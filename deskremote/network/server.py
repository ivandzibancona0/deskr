"""Hardened Temporary Session Server (Host) and E2EE v2 Session Client.

Security hardening:
  - Concurrent handshake worker threads bounded by semaphore (anti-DoS).
  - Strict handshake timeout (8s) so slow/malicious clients never stall accept().
  - Consecutive failure tracking with automatic PIN rotation after MAX_AUTH_FAILURES.
  - Optional interactive approval callback before handing off an authenticated channel.
  - Single-session mode by default: automatically pauses accepting new connections
    once an approved peer connects (prevents unwanted parallel sessions).
"""

from __future__ import annotations

import platform
import socket
import threading
from dataclasses import dataclass
from typing import Callable

from deskremote.config import (
    BORE_CONTROL_PORT,
    BORE_DEFAULT_SERVER,
    DEFAULT_BIND_HOST,
    HANDSHAKE_TIMEOUT,
    MAX_AUTH_FAILURES,
    MAX_CONCURRENT_HANDSHAKES,
    PIN_LENGTH,
)
from deskremote.crypto.e2ee import (
    AuthenticationError,
    DeviceIdentity,
    SecureChannel,
    SessionInfo,
    perform_client_handshake,
    perform_server_handshake,
)
from deskremote.network.protocol import PacketType, send_json
from deskremote.network.session_code import (
    decode_session_code,
    encode_session_code,
    generate_pin,
)
from deskremote.network.tunnel import BaseTunnel, TunnelEndpoint, start_tunnel
from deskremote.security.audit import get_audit_logger


@dataclass
class ActiveServerInfo:
    """Published connection details for an active Host Temporary Server."""

    session_code: str
    lan_code: str
    pin: str
    local_port: int
    endpoint: TunnelEndpoint


class TemporarySessionServer:
    """Ephemeral TCP + WAN Tunnel server created by the Host for a session."""

    def __init__(
        self,
        identity: DeviceIdentity,
        local_role: int,
        local_name: str | None = None,
        on_connected: Callable[[SecureChannel], None] | None = None,
        on_approve_peer: Callable[[SessionInfo, str], bool] | None = None,
        on_auth_error: Callable[[str], None] | None = None,
        on_pin_rotated: Callable[[str, str], None] | None = None,
        on_status: Callable[[str], None] | None = None,
        single_session: bool = True,
        max_failures: int = MAX_AUTH_FAILURES,
    ) -> None:
        self.identity = identity
        self.local_role = local_role
        self.local_name = local_name or platform.node() or "DeskRemote-PC"
        self.on_connected = on_connected
        self.on_approve_peer = on_approve_peer
        self.on_auth_error = on_auth_error
        self.on_pin_rotated = on_pin_rotated
        self.on_status = on_status
        self.single_session = single_session
        self.max_failures = max(1, int(max_failures))

        self._server_sock: socket.socket | None = None
        self._tunnel: BaseTunnel | None = None
        self._stop_event = threading.Event()
        self._accept_thread: threading.Thread | None = None
        self._handshake_sem = threading.BoundedSemaphore(MAX_CONCURRENT_HANDSHAKES)
        self._state_lock = threading.Lock()
        self._failed_attempts = 0
        self._session_claimed = False
        self._audit = get_audit_logger()

        self.info: ActiveServerInfo | None = None
        self.pin: str = ""

    @property
    def is_running(self) -> bool:
        return self._server_sock is not None and not self._stop_event.is_set()

    @property
    def failed_attempts(self) -> int:
        with self._state_lock:
            return self._failed_attempts

    def rotate_pin(self, reason: str = "Rotación manual solicitada.") -> str:
        """Generate a fresh cryptographic PIN and reset the failure counter."""
        new_pin = generate_pin(PIN_LENGTH)
        with self._state_lock:
            self.pin = new_pin
            self._failed_attempts = 0
            if self.info is not None:
                self.info.pin = new_pin
        self._audit.record("SERVER", f"PIN rotado ({reason}).")
        if self.on_pin_rotated:
            self.on_pin_rotated(new_pin, reason)
        return new_pin

    def release_session_slot(self) -> None:
        """Allow accepting a new peer again after an active single-session ends."""
        with self._state_lock:
            self._session_claimed = False

    def start(
        self,
        tunnel_mode: str = "auto",
        bind_port: int = 0,
        custom_pin: str | None = None,
        custom_bore_host: str = BORE_DEFAULT_SERVER,
        custom_bore_port: int = BORE_CONTROL_PORT,
        custom_bore_secret: str | None = None,
    ) -> ActiveServerInfo:
        if self.is_running:
            raise RuntimeError("El servidor temporal ya está en ejecución.")

        self._stop_event.clear()
        with self._state_lock:
            self.pin = (custom_pin or generate_pin(PIN_LENGTH)).strip().upper()
            self._failed_attempts = 0
            self._session_claimed = False

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((DEFAULT_BIND_HOST, bind_port))
        srv.listen(8)
        srv.settimeout(1.0)
        local_port = srv.getsockname()[1]
        self._server_sock = srv

        try:
            self._tunnel = start_tunnel(
                local_port=local_port,
                mode=tunnel_mode,
                custom_bore_host=custom_bore_host,
                custom_bore_port=custom_bore_port,
                custom_bore_secret=custom_bore_secret,
                on_status=self.on_status,
            )
        except Exception:
            srv.close()
            self._server_sock = None
            raise

        ep = self._tunnel.endpoint
        session_code = encode_session_code(ep.public_host, ep.public_port)
        lan_code = f"{ep.lan_host}:{ep.lan_port}"
        self.info = ActiveServerInfo(
            session_code=session_code,
            lan_code=lan_code,
            pin=self.pin,
            local_port=local_port,
            endpoint=ep,
        )
        self._audit.record(
            "SERVER",
            f"Servidor temporal iniciado ({ep.strategy}) en {ep.public_host}:{ep.public_port} | LAN {lan_code}",
        )

        self._accept_thread = threading.Thread(
            target=self._accept_loop, name="TempServerAccept", daemon=True
        )
        self._accept_thread.start()
        return self.info

    def _accept_loop(self) -> None:
        assert self._server_sock is not None
        while not self._stop_event.is_set():
            try:
                client_sock, addr = self._server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            with self._state_lock:
                if self.single_session and self._session_claimed:
                    try:
                        client_sock.close()
                    except OSError:
                        pass
                    self._audit.record(
                        "SERVER",
                        f"Conexión adicional desde {addr[0]} rechazada (sesión única activa).",
                        level="WARNING",
                    )
                    continue

            if not self._handshake_sem.acquire(blocking=False):
                try:
                    client_sock.close()
                except OSError:
                    pass
                self._audit.record(
                    "SERVER",
                    f"Conexión desde {addr[0]} descartada (límite de handshakes concurrentes).",
                    level="WARNING",
                )
                continue

            threading.Thread(
                target=self._handle_client_handshake,
                args=(client_sock, addr[0]),
                name=f"Handshake-{addr[0]}",
                daemon=True,
            ).start()

    def _handle_client_handshake(self, client_sock: socket.socket, remote_ip: str) -> None:
        try:
            client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            client_sock.settimeout(HANDSHAKE_TIMEOUT)

            with self._state_lock:
                current_pin = self.pin

            if self.on_status:
                self.on_status(f"Verificando SPAKE2 + E2EE con {remote_ip}...")

            channel = perform_server_handshake(
                sock=client_sock,
                identity=self.identity,
                pin=current_pin,
                local_role=self.local_role,
                local_name=self.local_name,
            )
            client_sock.settimeout(None)

            # Interactive user approval (if configured)
            if self.on_approve_peer is not None:
                approved = False
                try:
                    approved = bool(self.on_approve_peer(channel.info, remote_ip))
                except Exception:
                    approved = False
                if not approved:
                    self._audit.record(
                        "AUTH",
                        f"Sesión rechazada por el usuario local: '{channel.info.peer_name}' ({channel.info.peer_fingerprint}) desde {remote_ip}",
                        level="WARNING",
                    )
                    try:
                        send_json(
                            channel,
                            PacketType.DISCONNECT,
                            {"reason": "Conexión rechazada por el usuario local."},
                        )
                    except Exception:
                        pass
                    channel.close()
                    if self.on_auth_error and not self._stop_event.is_set():
                        self.on_auth_error(
                            f"Conexión rechazada manualmente ({channel.info.peer_name})."
                        )
                    return

            # Claim single-session slot cleanly
            with self._state_lock:
                if self.single_session and self._session_claimed:
                    channel.close()
                    return
                self._failed_attempts = 0
                if self.single_session:
                    self._session_claimed = True

            self._audit.record(
                "SESSION",
                f"Sesión E2EE v2 aprobada con '{channel.info.peer_name}' "
                f"[ID:{channel.info.peer_fingerprint} | FP:{channel.info.session_fingerprint}] desde {remote_ip}",
            )
            if self.on_connected:
                self.on_connected(channel)

        except (AuthenticationError, Exception) as exc:
            try:
                client_sock.close()
            except OSError:
                pass
            if self._stop_event.is_set():
                return

            self._audit.record(
                "AUTH",
                f"Fallo de autenticación desde {remote_ip}: {exc}",
                level="WARNING",
            )
            rotate_needed = False
            attempts = 0
            with self._state_lock:
                self._failed_attempts += 1
                attempts = self._failed_attempts
                if self._failed_attempts >= self.max_failures:
                    rotate_needed = True

            if rotate_needed:
                self.rotate_pin(
                    f"Límite alcanzado ({attempts}/{self.max_failures} intentos fallidos)"
                )
            elif self.on_auth_error:
                self.on_auth_error(
                    f"Intento rechazado ({attempts}/{self.max_failures}): {exc}"
                )
        finally:
            self._handshake_sem.release()

    def stop(self) -> None:
        self._stop_event.set()
        if self._tunnel is not None:
            try:
                self._tunnel.stop()
            except Exception:
                pass
            self._tunnel = None
        if self._server_sock is not None:
            try:
                self._server_sock.close()
            except OSError:
                pass
            self._server_sock = None
        self.info = None
        self._audit.record("SERVER", "Servidor temporal detenido.")


def connect_to_session(
    code_or_address: str,
    pin: str,
    identity: DeviceIdentity,
    local_role: int,
    local_name: str | None = None,
    timeout: float = 12.0,
) -> SecureChannel:
    """Connect to a remote TemporarySessionServer and perform E2EE v2 handshake."""
    host, port = decode_session_code(code_or_address)
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.settimeout(HANDSHAKE_TIMEOUT + 4.0)
        channel = perform_client_handshake(
            sock=sock,
            identity=identity,
            pin=pin,
            local_role=local_role,
            local_name=local_name or platform.node() or "DeskRemote-PC",
        )
        sock.settimeout(None)
        return channel
    except Exception:
        try:
            sock.close()
        except OSError:
            pass
        raise
