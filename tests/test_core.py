"""Comprehensive security, E2EE v2, hardening, integration, and UI tests for DeskRemote."""

from __future__ import annotations

import hashlib
import io
import os
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

from PIL import Image

from deskremote.crypto.e2ee import (
    DPAPI_PREFIX,
    ROLE_GUEST,
    ROLE_HOST,
    AuthenticationError,
    DeviceIdentity,
    perform_client_handshake,
    perform_server_handshake,
)
from deskremote.crypto.spake2 import Spake2Error, Spake2Exchange
from deskremote.crypto.trust_store import TrustStatus, TrustStore
from deskremote.network.protocol import (
    FileChunkPacket,
    PacketType,
    ScreenFramePacket,
    recv_packet,
    send_file_chunk,
    send_json,
)
from deskremote.network.server import TemporarySessionServer, connect_to_session
from deskremote.network.session_code import (
    decode_session_code,
    encode_session_code,
    generate_pin,
    normalize_pin,
)
from deskremote.remote.guest_agent import GuestAgent
from deskremote.remote.screen import FrameCompositor
from deskremote.security.audit import SecurityAuditLogger
from deskremote.ui.icons import ICON_SPECS, export_svgs, render_vector_pil


def _socket_pair() -> tuple[socket.socket, socket.socket]:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    c = socket.create_connection(("127.0.0.1", port), timeout=5.0)
    s, _ = srv.accept()
    srv.close()
    return s, c


class TestSpake2(unittest.TestCase):
    def test_spake2_matching_pin_agrees_on_secret(self) -> None:
        a = Spake2Exchange("A", "K7M4P9Q2")
        b = Spake2Exchange("B", "K7M4P9Q2")
        ka = a.finish(b.start())
        kb = b.finish(a.start())
        self.assertEqual(len(ka), 33)
        self.assertEqual(ka, kb)

    def test_spake2_different_pin_diverges(self) -> None:
        a = Spake2Exchange("A", "K7M4P9Q2")
        b = Spake2Exchange("B", "XXXXYYYY")
        ka = a.finish(b.start())
        kb = b.finish(a.start())
        self.assertNotEqual(ka, kb)

    def test_spake2_rejects_invalid_curve_point(self) -> None:
        a = Spake2Exchange("A", "K7M4P9Q2")
        a.start()
        with self.assertRaises(Spake2Error):
            a.finish(b"\x04" + b"\x00" * 32)  # invalid prefix
        with self.assertRaises(Spake2Error):
            a.finish(b"\x02" + b"\xff" * 32)  # x >= p


class TestE2EECryptoV2(unittest.TestCase):
    def test_handshake_v2_and_aes_gcm_roundtrip(self) -> None:
        s_sock, c_sock = _socket_pair()
        id_s = DeviceIdentity.ephemeral()
        id_c = DeviceIdentity.ephemeral()
        pin = generate_pin()  # XXXX-XXXX
        self.assertEqual(len(normalize_pin(pin)), 8)
        res: dict = {}

        t = threading.Thread(
            target=lambda: res.setdefault(
                "s", perform_server_handshake(s_sock, id_s, pin, ROLE_HOST, "HostPC")
            )
        )
        t.start()
        # Client enters lowercase without hyphen -> normalization must succeed
        c_ch = perform_client_handshake(
            c_sock, id_c, pin.replace("-", "").lower(), ROLE_GUEST, "GuestPC"
        )
        t.join(timeout=8.0)
        s_ch = res["s"]

        try:
            self.assertEqual(c_ch.info.session_fingerprint, s_ch.info.session_fingerprint)
            self.assertEqual(s_ch.info.peer_id_pub, id_c.public_bytes)
            self.assertEqual(c_ch.info.peer_id_pub, id_s.public_bytes)

            c_ch.send_encrypted(b"secret-payload-v2")
            self.assertEqual(s_ch.recv_encrypted(), b"secret-payload-v2")
            s_ch.send_encrypted(b"secret-reply-v2")
            self.assertEqual(c_ch.recv_encrypted(), b"secret-reply-v2")
        finally:
            c_ch.close()
            s_ch.close()

    def test_wrong_pin_rejected(self) -> None:
        s_sock, c_sock = _socket_pair()
        id_s = DeviceIdentity.ephemeral()
        id_c = DeviceIdentity.ephemeral()
        srv_err: list[Exception] = []

        def srv_fn() -> None:
            try:
                perform_server_handshake(s_sock, id_s, "ABCD-2345", ROLE_HOST, "HostPC")
            except Exception as exc:
                srv_err.append(exc)
            finally:
                s_sock.close()

        t = threading.Thread(target=srv_fn)
        t.start()
        with self.assertRaises(AuthenticationError):
            perform_client_handshake(c_sock, id_c, "WXYZ-9999", ROLE_GUEST, "GuestPC")
        c_sock.close()
        t.join(timeout=8.0)
        self.assertEqual(len(srv_err), 1)

    def test_same_role_rejected(self) -> None:
        s_sock, c_sock = _socket_pair()
        id_s = DeviceIdentity.ephemeral()
        id_c = DeviceIdentity.ephemeral()
        srv_err: list[Exception] = []

        def srv_fn() -> None:
            try:
                perform_server_handshake(s_sock, id_s, "K7M4-P9Q2", ROLE_HOST, "Host1")
            except Exception as exc:
                srv_err.append(exc)
            finally:
                s_sock.close()

        t = threading.Thread(target=srv_fn)
        t.start()
        with self.assertRaises((AuthenticationError, ConnectionError)):
            perform_client_handshake(c_sock, id_c, "K7M4-P9Q2", ROLE_HOST, "Host2")
        c_sock.close()
        t.join(timeout=8.0)
        self.assertTrue(len(srv_err) == 1 and isinstance(srv_err[0], AuthenticationError))

    def test_tampered_ciphertext_rejected(self) -> None:
        s_sock, c_sock = _socket_pair()
        id_s = DeviceIdentity.ephemeral()
        id_c = DeviceIdentity.ephemeral()
        pin = "K7M4-P9Q2"
        res: dict = {}

        t = threading.Thread(
            target=lambda: res.setdefault(
                "s", perform_server_handshake(s_sock, id_s, pin, ROLE_HOST, "H")
            )
        )
        t.start()
        c_ch = perform_client_handshake(c_sock, id_c, pin, ROLE_GUEST, "G")
        t.join(timeout=8.0)
        s_ch = res["s"]

        try:
            c_sock.sendall(b"\x00\x00\x00\x20" + (b"\xAA" * 32))
            with self.assertRaises(AuthenticationError):
                s_ch.recv_encrypted()
        finally:
            c_ch.close()
            s_ch.close()

    def test_dpapi_identity_protection_and_migration(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            key_file = Path(td) / "id.key"
            ident1 = DeviceIdentity.load_or_create(key_file)
            raw_on_disk = key_file.read_bytes()
            if os.name == "nt":
                self.assertTrue(raw_on_disk.startswith(DPAPI_PREFIX))
            ident2 = DeviceIdentity.load_or_create(key_file)
            self.assertEqual(ident1.fingerprint, ident2.fingerprint)
            self.assertEqual(ident1.public_bytes, ident2.public_bytes)


class TestTrustStoreAndAudit(unittest.TestCase):
    def test_tofu_lifecycle_and_key_changed_alert(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = TrustStore(Path(td) / "known_peers.json")
            id1 = DeviceIdentity.ephemeral()
            id2 = DeviceIdentity.ephemeral()

            ev1 = store.evaluate("Oficina-PC", id1.fingerprint, id1.public_bytes)
            self.assertEqual(ev1.status, TrustStatus.NEW)

            store.trust_peer("Oficina-PC", id1.fingerprint, id1.public_bytes)
            ev2 = store.evaluate("Oficina-PC", id1.fingerprint, id1.public_bytes)
            self.assertEqual(ev2.status, TrustStatus.TRUSTED)

            # Different Ed25519 key claiming the same hostname -> KEY_CHANGED!
            ev3 = store.evaluate("Oficina-PC", id2.fingerprint, id2.public_bytes)
            self.assertEqual(ev3.status, TrustStatus.KEY_CHANGED)
            self.assertIsNotNone(ev3.existing_record)

            # Persist reload & revoke
            store_reloaded = TrustStore(Path(td) / "known_peers.json")
            self.assertEqual(len(store_reloaded.list_peers()), 1)
            self.assertTrue(store_reloaded.revoke_peer(id1.fingerprint))
            self.assertEqual(
                store_reloaded.evaluate("Oficina-PC", id1.fingerprint, id1.public_bytes).status,
                TrustStatus.NEW,
            )

    def test_persistent_audit_logger(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            log_path = Path(td) / "audit.log"
            logger = SecurityAuditLogger(log_path)
            logger.record("AUTH", "Prueba de evento de seguridad", level="WARNING")
            logger.close()
            text = log_path.read_text(encoding="utf-8")
            self.assertIn("[AUTH] Prueba de evento de seguridad", text)


class TestServerHardening(unittest.TestCase):
    def test_concurrent_handshake_resists_slow_dos_client(self) -> None:
        host_id = DeviceIdentity.ephemeral()
        guest_id = DeviceIdentity.ephemeral()
        connected = threading.Event()
        channels: list = []

        srv = TemporarySessionServer(
            identity=host_id,
            local_role=ROLE_HOST,
            on_connected=lambda ch: (channels.append(ch), connected.set()),
        )
        info = srv.start(tunnel_mode="lan")
        slow_sock = None
        try:
            # Attacker opens TCP socket and sends NOTHING (would stall a single-threaded accept loop)
            host, port = decode_session_code(info.session_code)
            slow_sock = socket.create_connection((host, port), timeout=3.0)

            # Legitimate Guest must still connect immediately without waiting for slow_sock timeout
            t0 = time.monotonic()
            gch = connect_to_session(info.session_code, info.pin, guest_id, ROLE_GUEST)
            elapsed = time.monotonic() - t0
            self.assertTrue(connected.wait(timeout=4.0))
            self.assertLess(elapsed, 4.0)
            gch.close()
        finally:
            if slow_sock:
                slow_sock.close()
            for c in channels:
                c.close()
            srv.stop()

    def test_rate_limit_rotates_pin_after_max_failures(self) -> None:
        host_id = DeviceIdentity.ephemeral()
        guest_id = DeviceIdentity.ephemeral()
        rotated = threading.Event()
        new_pins: list[str] = []

        srv = TemporarySessionServer(
            identity=host_id,
            local_role=ROLE_HOST,
            max_failures=3,
            on_pin_rotated=lambda np, _r: (new_pins.append(np), rotated.set()),
        )
        info = srv.start(tunnel_mode="lan")
        old_pin = info.pin
        try:
            for _ in range(3):
                with self.assertRaises((AuthenticationError, ConnectionError)):
                    connect_to_session(info.session_code, "BADP-9999", guest_id, ROLE_GUEST)

            self.assertTrue(rotated.wait(timeout=4.0))
            self.assertEqual(len(new_pins), 1)
            self.assertNotEqual(new_pins[0], old_pin)

            # Old PIN must fail now, new rotated PIN must succeed
            with self.assertRaises((AuthenticationError, ConnectionError)):
                connect_to_session(info.session_code, old_pin, guest_id, ROLE_GUEST)
            ok_ch = connect_to_session(info.session_code, new_pins[0], guest_id, ROLE_GUEST)
            ok_ch.close()
        finally:
            srv.stop()

    def test_approval_rejection_and_single_session(self) -> None:
        host_id = DeviceIdentity.ephemeral()
        guest_id = DeviceIdentity.ephemeral()
        accepted_list: list = []
        allow_flag = {"ok": False}

        srv = TemporarySessionServer(
            identity=host_id,
            local_role=ROLE_HOST,
            single_session=True,
            on_approve_peer=lambda _info, _ip: allow_flag["ok"],
            on_connected=lambda ch: accepted_list.append(ch),
        )
        info = srv.start(tunnel_mode="lan")
        try:
            # 1. Rejected by approval callback -> receives DISCONNECT and is NOT accepted
            gch1 = connect_to_session(info.session_code, info.pin, guest_id, ROLE_GUEST)
            ptype, payload = recv_packet(gch1)
            self.assertEqual(ptype, PacketType.DISCONNECT)
            self.assertIn("rechazada", payload.get("reason", "").lower())
            gch1.close()
            self.assertEqual(len(accepted_list), 0)

            # 2. Approved -> single-session locks out second connection
            allow_flag["ok"] = True
            gch2 = connect_to_session(info.session_code, info.pin, guest_id, ROLE_GUEST)
            time.sleep(0.25)
            self.assertEqual(len(accepted_list), 1)

            with self.assertRaises((ConnectionError, AuthenticationError, OSError)):
                connect_to_session(info.session_code, info.pin, guest_id, ROLE_GUEST, timeout=2.0)
            gch2.close()
        finally:
            for c in accepted_list:
                c.close()
            srv.stop()


class TestSessionCodeAndCompositor(unittest.TestCase):
    def test_session_codes_and_pin_format(self) -> None:
        code = encode_session_code("bore.pub", 41234)
        self.assertEqual(decode_session_code(code), ("bore.pub", 41234))
        self.assertEqual(decode_session_code("10.0.0.5:44000"), ("10.0.0.5", 44000))
        pin = generate_pin()
        self.assertRegex(pin, r"^[2-9A-HJ-NP-Z]{4}-[2-9A-HJ-NP-Z]{4}$")

    def test_full_then_delta_patch(self) -> None:
        comp = FrameCompositor()
        base = Image.new("RGB", (200, 100), (20, 30, 40))
        b1 = io.BytesIO()
        base.save(b1, format="PNG")
        out1 = comp.apply(ScreenFramePacket(1, True, 0, 0, 200, 100, 200, 100, b1.getvalue()))
        self.assertEqual(out1.getpixel((10, 10)), (20, 30, 40))

        patch = Image.new("RGB", (40, 30), (250, 10, 10))
        b2 = io.BytesIO()
        patch.save(b2, format="PNG")
        out2 = comp.apply(ScreenFramePacket(1, False, 50, 20, 40, 30, 200, 100, b2.getvalue()))
        self.assertEqual(out2.getpixel((60, 30)), (250, 10, 10))


class TestHostGuestIntegration(unittest.TestCase):
    def test_end_to_end_v2_and_file_hardening(self) -> None:
        host_id = DeviceIdentity.ephemeral()
        guest_id = DeviceIdentity.ephemeral()
        host_ch_box: list = []
        connected_ev = threading.Event()

        srv = TemporarySessionServer(
            identity=host_id,
            local_role=ROLE_HOST,
            local_name="HostTest",
            on_connected=lambda ch: (host_ch_box.append(ch), connected_ev.set()),
        )
        info = srv.start(tunnel_mode="lan")
        agent: GuestAgent | None = None
        try:
            guest_ch = connect_to_session(
                info.session_code, info.pin, guest_id, ROLE_GUEST, local_name="GuestTest"
            )
            self.assertTrue(connected_ev.wait(timeout=5.0))
            host_ch = host_ch_box[0]

            agent = GuestAgent(guest_ch)
            agent.start()

            # 1. SYS_INFO + SCREEN_FRAME
            got_sys, got_frame = False, False
            deadline = time.monotonic() + 8.0
            while time.monotonic() < deadline and not (got_sys and got_frame):
                ptype, payload = recv_packet(host_ch)
                if ptype == PacketType.SYS_INFO:
                    got_sys = True
                elif ptype == PacketType.SCREEN_FRAME:
                    self.assertGreater(len(payload.image_bytes), 100)
                    got_frame = True
            self.assertTrue(got_sys and got_frame)

            # 2. Remote Shell
            send_json(host_ch, PacketType.SHELL_REQ, {"exec_id": "e1", "command": "echo DeskRemoteV2"})
            got_shell = False
            deadline = time.monotonic() + 10.0
            while time.monotonic() < deadline and not got_shell:
                ptype, payload = recv_packet(host_ch)
                if ptype == PacketType.SHELL_RESP and payload.get("exec_id") == "e1":
                    self.assertIn("DeskRemoteV2", payload["stdout"])
                    got_shell = True
            self.assertTrue(got_shell)

            # 3. Overwrite protection + SHA-256 atomic upload + mid-transfer revocation
            with tempfile.TemporaryDirectory() as td:
                existing = Path(td) / "doc.bin"
                existing.write_bytes(b"ORIGINAL")

                sample = b"NEW-E2EE-CONTENT" * 512
                sha = hashlib.sha256(sample).hexdigest()

                # Attempt without overwrite -> must refuse with exists=True
                send_json(
                    host_ch,
                    PacketType.FILE_REQ,
                    {
                        "req_id": "u0",
                        "action": "upload_start",
                        "transfer_id": "tid00001",
                        "dest_dir": td,
                        "filename": "doc.bin",
                        "size": len(sample),
                        "sha256": sha,
                        "overwrite": False,
                    },
                )
                got_exists = False
                deadline = time.monotonic() + 6.0
                while time.monotonic() < deadline and not got_exists:
                    ptype, payload = recv_packet(host_ch)
                    if ptype == PacketType.FILE_RESP and payload.get("action") == "upload_ready":
                        self.assertFalse(payload["ok"])
                        self.assertTrue(payload.get("exists"))
                        got_exists = True
                self.assertTrue(got_exists)
                self.assertEqual(existing.read_bytes(), b"ORIGINAL")

                # Retry with overwrite=True -> succeeds atomically
                send_json(
                    host_ch,
                    PacketType.FILE_REQ,
                    {
                        "req_id": "u1",
                        "action": "upload_start",
                        "transfer_id": "tid00002",
                        "dest_dir": td,
                        "filename": "doc.bin",
                        "size": len(sample),
                        "sha256": sha,
                        "overwrite": True,
                    },
                )
                done = False
                deadline = time.monotonic() + 6.0
                while time.monotonic() < deadline and not done:
                    ptype, payload = recv_packet(host_ch)
                    if ptype == PacketType.FILE_RESP and payload.get("action") == "upload_ready":
                        self.assertTrue(payload["ok"])
                        send_file_chunk(host_ch, FileChunkPacket("tid00002", 0, 1, 0, sample))
                    elif ptype == PacketType.FILE_RESP and payload.get("action") == "upload_done":
                        self.assertTrue(payload["ok"])
                        self.assertEqual(payload["sha256"], sha)
                        done = True
                self.assertTrue(done)
                self.assertEqual(existing.read_bytes(), sample)

                # Mid-transfer permission revocation deletes .part cleanly
                send_json(
                    host_ch,
                    PacketType.FILE_REQ,
                    {
                        "req_id": "u2",
                        "action": "upload_start",
                        "transfer_id": "tid00003",
                        "dest_dir": td,
                        "filename": "revoked.bin",
                        "size": 200,
                        "sha256": "",
                        "overwrite": True,
                    },
                )
                revoked_ok = False
                deadline = time.monotonic() + 6.0
                while time.monotonic() < deadline and not revoked_ok:
                    ptype, payload = recv_packet(host_ch)
                    if ptype == PacketType.FILE_RESP and payload.get("action") == "upload_ready":
                        self.assertTrue(payload["ok"])
                        send_file_chunk(host_ch, FileChunkPacket("tid00003", 0, 2, 0, b"A" * 100))
                        # Revoke permission before chunk 1 arrives
                        agent.permissions.allow_files = False
                        send_file_chunk(host_ch, FileChunkPacket("tid00003", 1, 2, 0, b"B" * 100))
                    elif ptype == PacketType.FILE_RESP and payload.get("action") == "upload_done":
                        self.assertFalse(payload["ok"])
                        revoked_ok = True
                self.assertTrue(revoked_ok)
                self.assertFalse((Path(td) / "revoked.bin").exists())
                self.assertEqual(list(Path(td).glob("*.part")), [])
        finally:
            if agent:
                agent.stop("Fin test")
            if host_ch_box:
                host_ch_box[0].close()
            srv.stop()


class TestVectorIconsAndUI(unittest.TestCase):
    def test_all_vector_icons_render_and_export_svg(self) -> None:
        for name in ICON_SPECS:
            img = render_vector_pil(name, size=24, color="#F43F5E")
            self.assertEqual(img.size, (24, 24))
            self.assertEqual(img.mode, "RGBA")
        svg_dir = Path(__file__).resolve().parent.parent / "assets" / "icons"
        export_svgs(svg_dir)
        self.assertEqual(len(list(svg_dir.glob("*.svg"))), len(ICON_SPECS))

    def test_customtkinter_app_smoke(self) -> None:
        from deskremote.ui.app import DeskRemoteApp

        app = DeskRemoteApp()
        try:
            app.update_idletasks()
            for nav in ("guest", "direct", "security", "host"):
                app._select_nav(nav)
                app.update_idletasks()
            app._toggle_theme()
            app.update_idletasks()
            app._toggle_theme()
            app.update_idletasks()
        finally:
            app._on_app_close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
