"""Hardened Guest-side full-access session agent.

Security hardening over v1:
  - Per-chunk permission enforcement on uploads and downloads (immediate abort + cleanup).
  - Disk-space validation & file size ceiling (MAX_UPLOAD_FILE_BYTES) before accepting uploads.
  - Atomic .part staging files for uploads (prevents partial corruption / cleans up on cancel).
  - Explicit overwrite confirmation check (prevents silent overwriting of existing files).
  - Persistent SecurityAuditLogger integration for all sensitive remote operations.
"""

from __future__ import annotations

import base64
import getpass
import hashlib
import math
import os
import platform
import shutil
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import mss
import pyperclip

from deskremote.config import (
    FILE_CHUNK_SIZE,
    HEARTBEAT_INTERVAL,
    MAX_UPLOAD_FILE_BYTES,
    MIN_FREE_DISK_MARGIN,
)
from deskremote.crypto.e2ee import SecureChannel
from deskremote.network.protocol import (
    FileChunkPacket,
    PacketType,
    recv_packet,
    send_file_chunk,
    send_json,
    send_screen_frame,
)
from deskremote.remote.file_ops import (
    delete_path,
    list_directory,
    make_directory,
    open_remote_file,
    rename_path,
)
from deskremote.remote.input_ctrl import InputInjector
from deskremote.remote.screen import DeltaScreenCapturer, list_monitors
from deskremote.remote.shell_ops import (
    RemoteShellExecutor,
    collect_system_telemetry,
    kill_process,
    perform_system_action,
)
from deskremote.security.audit import get_audit_logger


@dataclass
class GuestPermissions:
    allow_screen: bool = True
    allow_input: bool = True
    allow_files: bool = True
    allow_shell: bool = True
    allow_clipboard: bool = True

    def to_dict(self) -> dict[str, bool]:
        return {
            "allow_screen": self.allow_screen,
            "allow_input": self.allow_input,
            "allow_files": self.allow_files,
            "allow_shell": self.allow_shell,
            "allow_clipboard": self.allow_clipboard,
        }


class GuestAgent:
    """Handles all encrypted Host requests on the Guest computer."""

    def __init__(
        self,
        channel: SecureChannel,
        permissions: GuestPermissions | None = None,
        on_audit: Callable[[str], None] | None = None,
        on_chat: Callable[[str, str], None] | None = None,
        on_disconnect: Callable[[str], None] | None = None,
    ) -> None:
        self.channel = channel
        self.permissions = permissions or GuestPermissions()
        self.on_audit = on_audit
        self.on_chat = on_chat
        self.on_disconnect = on_disconnect

        self._stop = threading.Event()
        self._capturer = DeltaScreenCapturer(monitor_idx=1, jpeg_quality=62, scale=0.85)
        self._injector = InputInjector()
        self._shell = RemoteShellExecutor()
        self._audit = get_audit_logger()
        self._target_fps = 20

        # Active incoming file uploads from Host: transfer_id -> dict
        self._uploads: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._threads: list[threading.Thread] = []

    def _log(self, text: str, category: str = "GUEST") -> None:
        self._audit.record(category, f"[{self.channel.info.peer_name}] {text}")
        if self.on_audit:
            self.on_audit(text)

    def start(self) -> None:
        self._log(
            f"Sesión iniciada con '{self.channel.info.peer_name}' "
            f"[FP:{self.channel.info.session_fingerprint}]",
            category="SESSION",
        )
        self._send_system_info()
        t_recv = threading.Thread(target=self._recv_loop, name="GuestRecv", daemon=True)
        t_screen = threading.Thread(target=self._screen_loop, name="GuestScreen", daemon=True)
        t_hb = threading.Thread(target=self._heartbeat_loop, name="GuestHB", daemon=True)
        self._threads = [t_recv, t_screen, t_hb]
        for t in self._threads:
            t.start()

    def stop(self, reason: str = "Sesión finalizada por el huésped.") -> None:
        if self._stop.is_set():
            return
        self._stop.set()
        self._log(reason, category="SESSION")
        try:
            send_json(self.channel, PacketType.DISCONNECT, {"reason": reason})
        except Exception:
            pass
        self._close_open_uploads(cleanup_partials=True)
        self.channel.close()
        if self.on_disconnect:
            self.on_disconnect(reason)

    def update_permissions(self) -> None:
        """Broadcast updated live permissions and abort in-flight uploads if revoked."""
        if not self.permissions.allow_files:
            self._close_open_uploads(cleanup_partials=True)
        try:
            send_json(self.channel, PacketType.PERMISSIONS, self.permissions.to_dict())
            self._log(f"Permisos actualizados: {self.permissions.to_dict()}", category="PERMS")
        except Exception:
            pass

    def send_chat(self, text: str) -> None:
        send_json(
            self.channel,
            PacketType.CHAT_MSG,
            {"sender": platform.node() or "Huésped", "text": text, "ts": time.strftime("%H:%M")},
        )

    def _send_system_info(self) -> None:
        monitors = [m.to_dict() for m in list_monitors()]
        info = {
            "hostname": platform.node(),
            "user": getpass.getuser(),
            "os": f"{platform.system()} {platform.release()}",
            "arch": platform.machine(),
            "monitors": monitors,
            "permissions": self.permissions.to_dict(),
            "cwd": self._shell.cwd,
        }
        send_json(self.channel, PacketType.SYS_INFO, info)

    def _heartbeat_loop(self) -> None:
        while not self._stop.is_set():
            time.sleep(HEARTBEAT_INTERVAL)
            if self._stop.is_set():
                break
            try:
                send_json(self.channel, PacketType.HEARTBEAT, {"ts": time.time()})
            except Exception:
                break

    def _screen_loop(self) -> None:
        while not self._stop.is_set():
            try:
                with mss.MSS() as sct:
                    while not self._stop.is_set():
                        t0 = time.monotonic()
                        if self.permissions.allow_screen:
                            pkt = self._capturer.capture_next(sct)
                            if pkt is not None:
                                send_screen_frame(self.channel, pkt)
                        frame_period = 1.0 / max(1, self._target_fps)
                        elapsed = time.monotonic() - t0
                        sleep_for = frame_period - elapsed
                        if sleep_for > 0:
                            self._stop.wait(timeout=sleep_for)
            except Exception as exc:
                if self._stop.is_set() or self.channel.is_closed:
                    break
                self._log(f"Reintentando captura de pantalla: {exc}")
                self._stop.wait(timeout=0.5)

    def _recv_loop(self) -> None:
        reason = "Conexión cerrada."
        try:
            while not self._stop.is_set():
                ptype, payload = recv_packet(self.channel)
                self._dispatch(ptype, payload)
        except Exception as exc:
            if not self._stop.is_set():
                reason = f"Desconectado: {exc}"
        finally:
            self._stop.set()
            self._close_open_uploads(cleanup_partials=True)
            self.channel.close()
            if self.on_disconnect:
                self.on_disconnect(reason)

    def _dispatch(self, ptype: PacketType, payload: Any) -> None:
        if ptype == PacketType.HEARTBEAT:
            return

        if ptype == PacketType.DISCONNECT:
            reason = payload.get("reason", "El anfitrión finalizó la sesión.")
            self._log(reason, category="SESSION")
            self._stop.set()
            return

        if ptype == PacketType.SCREEN_CONFIG:
            self._target_fps = max(1, min(30, int(payload.get("fps", self._target_fps))))
            self._capturer.configure(
                monitor_idx=payload.get("monitor_idx"),
                jpeg_quality=payload.get("jpeg_quality"),
                scale=payload.get("scale"),
                force_keyframe=bool(payload.get("force_keyframe", False)),
            )
            return

        if ptype == PacketType.INPUT_EVENT:
            if self.permissions.allow_input:
                self._injector.handle_event(payload, self._capturer.current_monitor_rect)
            return

        if ptype == PacketType.CLIPBOARD_SYNC:
            if not self.permissions.allow_clipboard:
                return
            action = payload.get("action")
            if action == "set":
                text = str(payload.get("text", ""))
                try:
                    pyperclip.copy(text)
                    self._log(f"Portapapeles recibido ({len(text)} caracteres).", category="CLIPBOARD")
                except Exception:
                    pass
            elif action == "get":
                try:
                    text = pyperclip.paste()
                except Exception:
                    text = ""
                send_json(
                    self.channel,
                    PacketType.CLIPBOARD_SYNC,
                    {"action": "data", "text": text},
                )
            return

        if ptype == PacketType.FILE_REQ:
            self._handle_file_req(payload)
            return

        if ptype == PacketType.FILE_CHUNK:
            self._handle_file_chunk(payload)
            return

        if ptype == PacketType.SHELL_REQ:
            self._handle_shell_req(payload)
            return

        if ptype == PacketType.PROC_REQ:
            self._handle_proc_req(payload)
            return

        if ptype == PacketType.SYS_ACTION:
            self._handle_sys_action(payload)
            return

        if ptype == PacketType.CHAT_MSG:
            sender = payload.get("sender", "Anfitrión")
            text = payload.get("text", "")
            if self.on_chat:
                self.on_chat(sender, text)
            return

    def _handle_file_req(self, req: dict[str, Any]) -> None:
        req_id = req.get("req_id", "")
        action = req.get("action", "")
        if not self.permissions.allow_files:
            send_json(
                self.channel,
                PacketType.FILE_RESP,
                {
                    "req_id": req_id,
                    "action": action,
                    "ok": False,
                    "error": "Acceso a archivos desactivado por el huésped.",
                },
            )
            return

        if action == "list":
            res = list_directory(req.get("path"))
            res.update({"req_id": req_id, "action": "list"})
            send_json(self.channel, PacketType.FILE_RESP, res)

        elif action == "mkdir":
            res = make_directory(req.get("path", ""), req.get("name", ""))
            res.update({"req_id": req_id, "action": "mkdir"})
            self._log(f"Carpeta creada: {req.get('name', '')}", category="FILE")
            send_json(self.channel, PacketType.FILE_RESP, res)

        elif action == "delete":
            res = delete_path(req.get("path", ""))
            res.update({"req_id": req_id, "action": "delete"})
            self._log(f"Elemento eliminado: {req.get('path', '')}", category="FILE")
            send_json(self.channel, PacketType.FILE_RESP, res)

        elif action == "rename":
            res = rename_path(req.get("path", ""), req.get("new_name", ""))
            res.update({"req_id": req_id, "action": "rename"})
            self._log(f"Renombrado: {req.get('path', '')} -> {req.get('new_name', '')}", category="FILE")
            send_json(self.channel, PacketType.FILE_RESP, res)

        elif action == "open":
            res = open_remote_file(req.get("path", ""))
            res.update({"req_id": req_id, "action": "open"})
            self._log(f"Abierto remotamente: {req.get('path', '')}", category="FILE")
            send_json(self.channel, PacketType.FILE_RESP, res)

        elif action == "upload_start":
            tid = str(req["transfer_id"])
            dest_dir = Path(req["dest_dir"])
            filename = Path(req["filename"]).name
            total_size = int(req.get("size", 0))
            overwrite = bool(req.get("overwrite", False))
            dest_path = dest_dir / filename

            if total_size < 0 or total_size > MAX_UPLOAD_FILE_BYTES:
                send_json(
                    self.channel,
                    PacketType.FILE_RESP,
                    {
                        "req_id": req_id,
                        "action": "upload_ready",
                        "transfer_id": tid,
                        "ok": False,
                        "error": f"El archivo excede el límite máximo permitido ({MAX_UPLOAD_FILE_BYTES // (1024**2)} MB).",
                    },
                )
                return

            # Check overwrite safety
            if dest_path.exists() and not overwrite:
                send_json(
                    self.channel,
                    PacketType.FILE_RESP,
                    {
                        "req_id": req_id,
                        "action": "upload_ready",
                        "transfer_id": tid,
                        "ok": False,
                        "exists": True,
                        "filename": filename,
                        "error": f"El archivo '{filename}' ya existe en el destino.",
                    },
                )
                return

            # Check available free disk space
            try:
                usage = shutil.disk_usage(dest_dir)
                if usage.free < (total_size + MIN_FREE_DISK_MARGIN):
                    send_json(
                        self.channel,
                        PacketType.FILE_RESP,
                        {
                            "req_id": req_id,
                            "action": "upload_ready",
                            "transfer_id": tid,
                            "ok": False,
                            "error": "Espacio insuficiente en disco en el equipo huésped.",
                        },
                    )
                    return
            except OSError:
                pass

            part_path = dest_dir / f".{filename}.{tid[:8]}.part"
            try:
                f = open(part_path, "wb")
                with self._lock:
                    self._uploads[tid] = {
                        "file": f,
                        "dest_path": dest_path,
                        "part_path": part_path,
                        "hasher": hashlib.sha256(),
                        "expected_sha256": req.get("sha256", ""),
                        "expected_size": total_size,
                        "written": 0,
                    }
                self._log(f"Recibiendo archivo del anfitrión: {dest_path}", category="FILE")
                send_json(
                    self.channel,
                    PacketType.FILE_RESP,
                    {"req_id": req_id, "action": "upload_ready", "transfer_id": tid, "ok": True},
                )
            except Exception as exc:
                send_json(
                    self.channel,
                    PacketType.FILE_RESP,
                    {"req_id": req_id, "action": "upload_ready", "transfer_id": tid, "ok": False, "error": str(exc)},
                )

        elif action == "download_start":
            tid = str(req["transfer_id"])
            src_path = Path(req["path"])
            threading.Thread(
                target=self._stream_file_to_host,
                args=(req_id, tid, src_path),
                name=f"FileDownload-{tid[:6]}",
                daemon=True,
            ).start()

    def _stream_file_to_host(self, req_id: str, tid: str, src_path: Path) -> None:
        if not src_path.is_file():
            send_json(
                self.channel,
                PacketType.FILE_RESP,
                {"req_id": req_id, "action": "download_meta", "transfer_id": tid, "ok": False, "error": "Archivo no encontrado."},
            )
            return

        try:
            size = src_path.stat().st_size
            total_chunks = max(1, math.ceil(size / FILE_CHUNK_SIZE))
            self._log(f"Enviando archivo al anfitrión: {src_path.name} ({size} bytes)", category="FILE")
            send_json(
                self.channel,
                PacketType.FILE_RESP,
                {
                    "req_id": req_id,
                    "action": "download_meta",
                    "transfer_id": tid,
                    "ok": True,
                    "filename": src_path.name,
                    "size": size,
                    "total_chunks": total_chunks,
                },
            )
            hasher = hashlib.sha256()
            with open(src_path, "rb") as f:
                if size == 0:
                    if not self.permissions.allow_files:
                        raise PermissionError("Permiso de archivos revocado durante la descarga.")
                    send_file_chunk(self.channel, FileChunkPacket(tid, 0, 1, 1, b""))
                else:
                    for idx in range(total_chunks):
                        if self._stop.is_set():
                            return
                        if not self.permissions.allow_files:
                            raise PermissionError("Permiso de archivos revocado durante la descarga.")
                        data = f.read(FILE_CHUNK_SIZE)
                        hasher.update(data)
                        send_file_chunk(
                            self.channel, FileChunkPacket(tid, idx, total_chunks, 1, data)
                        )
            send_json(
                self.channel,
                PacketType.FILE_RESP,
                {
                    "req_id": req_id,
                    "action": "download_done",
                    "transfer_id": tid,
                    "ok": True,
                    "sha256": hasher.hexdigest(),
                },
            )
        except Exception as exc:
            try:
                send_json(
                    self.channel,
                    PacketType.FILE_RESP,
                    {"req_id": req_id, "action": "download_done", "transfer_id": tid, "ok": False, "error": str(exc)},
                )
            except Exception:
                pass

    def _abort_upload(self, tid: str, error_msg: str) -> None:
        with self._lock:
            state = self._uploads.pop(tid, None)
        if state:
            try:
                state["file"].close()
            except Exception:
                pass
            try:
                if state["part_path"].exists():
                    state["part_path"].unlink()
            except OSError:
                pass
        try:
            send_json(
                self.channel,
                PacketType.FILE_RESP,
                {"action": "upload_done", "transfer_id": tid, "ok": False, "error": error_msg},
            )
        except Exception:
            pass

    def _handle_file_chunk(self, chunk: FileChunkPacket) -> None:
        if chunk.direction != 0:
            return
        # Re-verify live file permission on EVERY incoming chunk
        if not self.permissions.allow_files:
            self._abort_upload(
                chunk.transfer_id, "Subida cancelada: permiso de archivos revocado por el huésped."
            )
            return

        with self._lock:
            state = self._uploads.get(chunk.transfer_id)
        if not state:
            return

        try:
            if chunk.data:
                new_total = state["written"] + len(chunk.data)
                if new_total > MAX_UPLOAD_FILE_BYTES:
                    self._abort_upload(
                        chunk.transfer_id, "Subida cancelada: tamaño máximo excedido."
                    )
                    return
                state["file"].write(chunk.data)
                state["hasher"].update(chunk.data)
                state["written"] = new_total

            if chunk.chunk_idx + 1 >= chunk.total_chunks:
                state["file"].close()
                digest = state["hasher"].hexdigest()
                expected = state["expected_sha256"]
                ok = (not expected) or (digest == expected)
                with self._lock:
                    self._uploads.pop(chunk.transfer_id, None)
                if ok:
                    os.replace(state["part_path"], state["dest_path"])
                else:
                    try:
                        state["part_path"].unlink(missing_ok=True)
                    except OSError:
                        pass
                send_json(
                    self.channel,
                    PacketType.FILE_RESP,
                    {
                        "action": "upload_done",
                        "transfer_id": chunk.transfer_id,
                        "ok": ok,
                        "path": str(state["dest_path"]),
                        "sha256": digest,
                        "error": "" if ok else "Error de integridad SHA-256.",
                    },
                )
        except Exception as exc:
            self._abort_upload(chunk.transfer_id, str(exc))

    def _close_open_uploads(self, cleanup_partials: bool = True) -> None:
        with self._lock:
            items = list(self._uploads.values())
            self._uploads.clear()
        for st in items:
            try:
                st["file"].close()
            except Exception:
                pass
            if cleanup_partials:
                try:
                    if st["part_path"].exists():
                        st["part_path"].unlink()
                except OSError:
                    pass

    def _handle_shell_req(self, req: dict[str, Any]) -> None:
        exec_id = req.get("exec_id", "")
        cmd = str(req.get("command", ""))
        if not self.permissions.allow_shell:
            send_json(
                self.channel,
                PacketType.SHELL_RESP,
                {
                    "exec_id": exec_id,
                    "stdout": "",
                    "stderr": "Terminal remota desactivada por el huésped.\n",
                    "returncode": -1,
                    "cwd": self._shell.cwd,
                },
            )
            return

        self._log(f"Terminal remota: {cmd[:120]}", category="SHELL")

        def _run() -> None:
            res = self._shell.execute(cmd)
            res["exec_id"] = exec_id
            try:
                send_json(self.channel, PacketType.SHELL_RESP, res)
            except Exception:
                pass

        threading.Thread(target=_run, name="GuestShellExec", daemon=True).start()

    def _handle_proc_req(self, req: dict[str, Any]) -> None:
        action = req.get("action", "list")
        if action == "kill":
            if not self.permissions.allow_shell:
                send_json(
                    self.channel,
                    PacketType.PROC_RESP,
                    {"action": "kill", "ok": False, "error": "Permiso de sistema desactivado."},
                )
                return
            pid = int(req.get("pid", 0))
            res = kill_process(pid)
            res["action"] = "kill"
            self._log(f"Proceso finalizado remotamente: PID {pid}", category="SYSTEM")
            send_json(self.channel, PacketType.PROC_RESP, res)
        else:
            telemetry = collect_system_telemetry()
            telemetry["action"] = "list"
            send_json(self.channel, PacketType.PROC_RESP, telemetry)

    def _handle_sys_action(self, req: dict[str, Any]) -> None:
        action = str(req.get("action", ""))
        if action == "screenshot":
            try:
                png = self._capturer.capture_full_png()
                send_json(
                    self.channel,
                    PacketType.SYS_ACTION,
                    {
                        "action": "screenshot_data",
                        "ok": True,
                        "png_b64": base64.b64encode(png).decode("ascii"),
                    },
                )
                self._log("Captura PNG de alta calidad enviada al anfitrión.", category="SCREEN")
            except Exception as exc:
                send_json(
                    self.channel,
                    PacketType.SYS_ACTION,
                    {"action": "screenshot_data", "ok": False, "error": str(exc)},
                )
            return

        if not self.permissions.allow_shell:
            send_json(
                self.channel,
                PacketType.SYS_ACTION,
                {"action": action, "ok": False, "error": "Acciones de sistema desactivadas por el huésped."},
            )
            return

        self._log(f"Acción del sistema ejecutada: {action}", category="SYSTEM")
        res = perform_system_action(action)
        res["action"] = action
        send_json(self.channel, PacketType.SYS_ACTION, res)
