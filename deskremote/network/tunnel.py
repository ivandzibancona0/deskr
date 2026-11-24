"""Multi-strategy WAN exposure engine for the Host Temporary Server.

Supports exposing a local ephemeral TCP port to the Internet without requiring
user accounts, router access, or external binaries:
  1. Pure-Python Bore TCP Tunnel client (ekzhang/bore protocol -> bore.pub:7835)
  2. Built-in OpenSSH Reverse Tunnel (Pinggy TCP / Serveo) with TOFU known_hosts
  3. Pure-Python UPnP IGD (SSDP + SOAP AddPortMapping) with reduced lease & atexit cleanup
  4. Direct LAN IPv4 exposure (for same-network / VPN ultra-low latency)
"""

from __future__ import annotations

import atexit
import hashlib
import hmac
import json
import os
import re
import shutil
import socket
import subprocess
import threading
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Callable

from deskremote.config import (
    BORE_CONTROL_PORT,
    BORE_DEFAULT_SERVER,
    SSH_KNOWN_HOSTS_FILE,
    UPNP_LEASE_SECONDS,
)


@dataclass
class TunnelEndpoint:
    """Describes how remote peers can reach the Host Temporary Server."""

    strategy: str  # "bore", "ssh_pinggy", "ssh_serveo", "upnp", "lan"
    public_host: str
    public_port: int
    lan_host: str
    lan_port: int
    is_internet: bool
    detail: str


def get_local_lan_ip() -> str:
    """Determine the primary LAN IPv4 address without sending network traffic."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "127.0.0.1"
    finally:
        sock.close()


def _pipe_sockets(src: socket.socket, dst: socket.socket) -> None:
    """Bidirectionally relay raw TCP bytes between two sockets until EOF."""
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


class BaseTunnel:
    """Abstract handle for an active temporary tunnel."""

    def __init__(self, endpoint: TunnelEndpoint) -> None:
        self.endpoint = endpoint
        self._stopped = threading.Event()

    def stop(self) -> None:
        self._stopped.set()


class LanTunnel(BaseTunnel):
    """Direct local network exposure (no external relay)."""

    @classmethod
    def start(cls, local_port: int) -> "LanTunnel":
        lan_ip = get_local_lan_ip()
        ep = TunnelEndpoint(
            strategy="lan",
            public_host=lan_ip,
            public_port=local_port,
            lan_host=lan_ip,
            lan_port=local_port,
            is_internet=False,
            detail=f"Red local directa ({lan_ip}:{local_port})",
        )
        return cls(ep)


class BoreTunnel(BaseTunnel):
    """Pure-Python client for the ekzhang/bore TCP tunnel protocol."""

    def __init__(
        self,
        endpoint: TunnelEndpoint,
        control_sock: socket.socket,
        server_host: str,
        server_port: int,
        local_port: int,
        secret: str | None = None,
    ) -> None:
        super().__init__(endpoint)
        self._control_sock = control_sock
        self._server_host = server_host
        self._server_port = server_port
        self._local_port = local_port
        self._secret = secret
        self._child_sockets: list[socket.socket] = []
        self._lock = threading.Lock()
        self._thread = threading.Thread(
            target=self._control_loop, name="BoreControlLoop", daemon=True
        )
        self._thread.start()

    @staticmethod
    def _send_json_nul(sock: socket.socket, obj: object) -> None:
        data = json.dumps(obj, separators=(",", ":")).encode("utf-8") + b"\x00"
        sock.sendall(data)

    @staticmethod
    def _recv_json_nul(sock: socket.socket, buf: bytearray) -> object:
        while True:
            nul_idx = buf.find(b"\x00")
            if nul_idx != -1:
                raw = bytes(buf[:nul_idx])
                del buf[: nul_idx + 1]
                if not raw:
                    continue
                return json.loads(raw.decode("utf-8"))
            chunk = sock.recv(4096)
            if not chunk:
                raise ConnectionError("El servidor Bore cerró la conexión de control.")
            buf.extend(chunk)
            if len(buf) > 16384:
                raise ValueError("Trama de control Bore demasiado grande.")

    @staticmethod
    def _compute_challenge_tag(secret: str, challenge_uuid: str) -> str:
        key = hashlib.sha256(secret.encode("utf-8")).digest()
        uuid_bytes = bytes.fromhex(challenge_uuid.replace("-", ""))
        return hmac.new(key, uuid_bytes, hashlib.sha256).hexdigest()

    @classmethod
    def start(
        cls,
        local_port: int,
        server_host: str = BORE_DEFAULT_SERVER,
        server_port: int = BORE_CONTROL_PORT,
        secret: str | None = None,
        timeout: float = 7.0,
    ) -> "BoreTunnel":
        sock = socket.create_connection((server_host, server_port), timeout=timeout)
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            buf = bytearray()

            cls._send_json_nul(sock, {"Hello": 0})
            msg = cls._recv_json_nul(sock, buf)

            if isinstance(msg, dict) and "Challenge" in msg:
                if not secret:
                    raise RuntimeError(
                        f"El servidor Bore {server_host} requiere una clave secreta."
                    )
                tag = cls._compute_challenge_tag(secret, msg["Challenge"])
                cls._send_json_nul(sock, {"Authenticate": tag})
                msg = cls._recv_json_nul(sock, buf)

            if isinstance(msg, dict) and "Error" in msg:
                raise RuntimeError(f"Error de Bore: {msg['Error']}")

            if not (isinstance(msg, dict) and "Hello" in msg):
                raise RuntimeError(f"Respuesta inesperada de Bore: {msg}")

            public_port = int(msg["Hello"])
            sock.settimeout(None)

            lan_ip = get_local_lan_ip()
            ep = TunnelEndpoint(
                strategy="bore",
                public_host=server_host,
                public_port=public_port,
                lan_host=lan_ip,
                lan_port=local_port,
                is_internet=True,
                detail=f"Túnel TCP Global ({server_host}:{public_port})",
            )
            tunnel = cls(ep, sock, server_host, server_port, local_port, secret)
            tunnel._initial_buf = buf
            return tunnel
        except Exception:
            sock.close()
            raise

    def _control_loop(self) -> None:
        buf = getattr(self, "_initial_buf", bytearray())
        self._control_sock.settimeout(2.0)
        while not self._stopped.is_set():
            try:
                msg = self._recv_json_nul(self._control_sock, buf)
            except socket.timeout:
                continue
            except Exception:
                break

            if msg == "Heartbeat":
                continue
            if isinstance(msg, dict) and "Connection" in msg:
                conn_uuid = str(msg["Connection"])
                threading.Thread(
                    target=self._handle_incoming,
                    args=(conn_uuid,),
                    name=f"BoreProxy-{conn_uuid[:8]}",
                    daemon=True,
                ).start()

    def _handle_incoming(self, conn_uuid: str) -> None:
        remote_sock: socket.socket | None = None
        local_sock: socket.socket | None = None
        try:
            remote_sock = socket.create_connection(
                (self._server_host, self._server_port), timeout=10.0
            )
            remote_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if self._secret:
                buf = bytearray()
                msg = self._recv_json_nul(remote_sock, buf)
                if isinstance(msg, dict) and "Challenge" in msg:
                    tag = self._compute_challenge_tag(self._secret, msg["Challenge"])
                    self._send_json_nul(remote_sock, {"Authenticate": tag})
            self._send_json_nul(remote_sock, {"Accept": conn_uuid})
            remote_sock.settimeout(None)

            local_sock = socket.create_connection(
                ("127.0.0.1", self._local_port), timeout=5.0
            )
            local_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            local_sock.settimeout(None)

            with self._lock:
                self._child_sockets.extend([remote_sock, local_sock])

            t1 = threading.Thread(
                target=_pipe_sockets, args=(remote_sock, local_sock), daemon=True
            )
            t2 = threading.Thread(
                target=_pipe_sockets, args=(local_sock, remote_sock), daemon=True
            )
            t1.start()
            t2.start()
            t1.join()
            t2.join()
        except Exception:
            pass
        finally:
            for s in (remote_sock, local_sock):
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass

    def stop(self) -> None:
        super().stop()
        try:
            self._control_sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self._control_sock.close()
        except OSError:
            pass
        with self._lock:
            for s in self._child_sockets:
                try:
                    s.close()
                except OSError:
                    pass
            self._child_sockets.clear()


class SshReverseTunnel(BaseTunnel):
    """Reverse TCP tunnel using system OpenSSH with dedicated TOFU known_hosts."""

    def __init__(self, endpoint: TunnelEndpoint, proc: subprocess.Popen) -> None:
        super().__init__(endpoint)
        self._proc = proc
        atexit.register(self.stop)

    @classmethod
    def start(
        cls,
        local_port: int,
        provider: str = "pinggy",
        timeout: float = 12.0,
    ) -> "SshReverseTunnel":
        ssh_bin = shutil.which("ssh")
        if not ssh_bin:
            raise RuntimeError("Cliente OpenSSH (ssh) no encontrado en el sistema.")

        # Persist SSH relay host keys (TOFU via accept-new) instead of disabling host verification
        try:
            SSH_KNOWN_HOSTS_FILE.parent.mkdir(parents=True, exist_ok=True)
            SSH_KNOWN_HOSTS_FILE.touch(exist_ok=True)
            known_hosts = str(SSH_KNOWN_HOSTS_FILE)
        except OSError:
            known_hosts = "NUL" if os.name == "nt" else "/dev/null"

        common = [
            ssh_bin,
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            f"UserKnownHostsFile={known_hosts}",
            "-o",
            "ServerAliveInterval=15",
            "-o",
            "ConnectTimeout=8",
            "-o",
            "ExitOnForwardFailure=yes",
            "-N" if provider == "serveo" else "-T",
        ]

        if provider == "pinggy":
            cmd = common + [
                "-p",
                "443",
                "-R",
                f"0:127.0.0.1:{local_port}",
                "tcp@a.pinggy.io",
            ]
            pattern = re.compile(r"tcp://([a-zA-Z0-9.\-]+):(\d+)")
            strategy_name = "ssh_pinggy"
        else:
            cmd = common + [
                "-R",
                f"0:127.0.0.1:{local_port}",
                "serveo.net",
            ]
            pattern = re.compile(
                r"Forwarding TCP connections from ([a-zA-Z0-9.\-]+):(\d+)"
            )
            strategy_name = "ssh_serveo"

        creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0

        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            creationflags=creationflags,
        )

        found: list[tuple[str, int]] = []
        done_event = threading.Event()
        collected: list[str] = []

        def _reader() -> None:
            assert proc.stdout is not None
            for line in proc.stdout:
                collected.append(line.strip())
                m = pattern.search(line)
                if m and not found:
                    found.append((m.group(1), int(m.group(2))))
                    done_event.set()
            done_event.set()

        threading.Thread(target=_reader, name="SshTunnelReader", daemon=True).start()
        done_event.wait(timeout=timeout)

        if not found:
            try:
                proc.terminate()
            except OSError:
                pass
            tail = " | ".join(collected[-3:]) if collected else "sin respuesta"
            raise RuntimeError(f"No se pudo abrir túnel SSH ({provider}): {tail}")

        pub_host, pub_port = found[0]
        lan_ip = get_local_lan_ip()
        ep = TunnelEndpoint(
            strategy=strategy_name,
            public_host=pub_host,
            public_port=pub_port,
            lan_host=lan_ip,
            lan_port=local_port,
            is_internet=True,
            detail=f"Túnel SSH Global ({pub_host}:{pub_port})",
        )
        return cls(ep, proc)

    def stop(self) -> None:
        if self._stopped.is_set():
            return
        super().stop()
        try:
            self._proc.terminate()
            self._proc.wait(timeout=2.0)
        except Exception:
            try:
                self._proc.kill()
            except Exception:
                pass


class UpnpTunnel(BaseTunnel):
    """Pure-Python UPnP IGD automatic port forwarding with reduced lease & atexit cleanup."""

    def __init__(
        self,
        endpoint: TunnelEndpoint,
        control_url: str,
        service_type: str,
        external_port: int,
    ) -> None:
        super().__init__(endpoint)
        self._control_url = control_url
        self._service_type = service_type
        self._external_port = external_port
        atexit.register(self.stop)

    @staticmethod
    def _soap_call(control_url: str, service_type: str, action: str, body_xml: str) -> str:
        envelope = (
            '<?xml version="1.0"?>'
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
            "<s:Body>"
            f'<u:{action} xmlns:u="{service_type}">{body_xml}</u:{action}>'
            "</s:Body></s:Envelope>"
        ).encode("utf-8")
        req = urllib.request.Request(
            control_url,
            data=envelope,
            headers={
                "Content-Type": 'text/xml; charset="utf-8"',
                "SOAPAction": f'"{service_type}#{action}"',
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=4.0) as resp:
            return resp.read().decode("utf-8", errors="replace")

    @classmethod
    def start(cls, local_port: int, timeout: float = 2.5) -> "UpnpTunnel":
        ssdp_req = (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            'MAN: "ssdp:discover"\r\n'
            "MX: 2\r\n"
            "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"
        ).encode("ascii")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(timeout)
        location: str | None = None
        try:
            sock.sendto(ssdp_req, ("239.255.255.250", 1900))
            data, _ = sock.recvfrom(4096)
            text = data.decode("utf-8", errors="replace")
            m = re.search(r"LOCATION:\s*(\S+)", text, re.IGNORECASE)
            if m:
                location = m.group(1).strip()
        finally:
            sock.close()

        if not location:
            raise RuntimeError("No se encontró un router compatible con UPnP en la red.")

        with urllib.request.urlopen(location, timeout=3.0) as resp:
            desc_xml = resp.read()

        root = ET.fromstring(desc_xml)
        control_url = None
        service_type = None
        for svc in root.iter():
            if svc.tag.endswith("service"):
                st = None
                cu = None
                for child in svc:
                    if child.tag.endswith("serviceType"):
                        st = child.text
                    elif child.tag.endswith("controlURL"):
                        cu = child.text
                if st and ("WANIPConnection" in st or "WANPPPConnection" in st) and cu:
                    service_type = st
                    control_url = urllib.parse.urljoin(location, cu)
                    break

        if not control_url or not service_type:
            raise RuntimeError("El router UPnP no expone WANIPConnection.")

        lan_ip = get_local_lan_ip()
        add_body = (
            "<NewRemoteHost></NewRemoteHost>"
            f"<NewExternalPort>{local_port}</NewExternalPort>"
            "<NewProtocol>TCP</NewProtocol>"
            f"<NewInternalPort>{local_port}</NewInternalPort>"
            f"<NewInternalClient>{lan_ip}</NewInternalClient>"
            "<NewEnabled>1</NewEnabled>"
            "<NewPortMappingDescription>DeskRemote Temporary</NewPortMappingDescription>"
            f"<NewLeaseDuration>{UPNP_LEASE_SECONDS}</NewLeaseDuration>"
        )
        cls._soap_call(control_url, service_type, "AddPortMapping", add_body)

        ip_resp = cls._soap_call(control_url, service_type, "GetExternalIPAddress", "")
        m_ip = re.search(r"<NewExternalIPAddress>([^<]+)</NewExternalIPAddress>", ip_resp)
        if not m_ip:
            raise RuntimeError("No se pudo obtener la IP pública del router UPnP.")
        pub_ip = m_ip.group(1).strip()

        ep = TunnelEndpoint(
            strategy="upnp",
            public_host=pub_ip,
            public_port=local_port,
            lan_host=lan_ip,
            lan_port=local_port,
            is_internet=True,
            detail=f"UPnP Router Directo ({pub_ip}:{local_port})",
        )
        return cls(ep, control_url, service_type, local_port)

    def stop(self) -> None:
        if self._stopped.is_set():
            return
        super().stop()
        try:
            del_body = (
                "<NewRemoteHost></NewRemoteHost>"
                f"<NewExternalPort>{self._external_port}</NewExternalPort>"
                "<NewProtocol>TCP</NewProtocol>"
            )
            self._soap_call(
                self._control_url, self._service_type, "DeletePortMapping", del_body
            )
        except Exception:
            pass


def start_tunnel(
    local_port: int,
    mode: str = "auto",
    custom_bore_host: str = BORE_DEFAULT_SERVER,
    custom_bore_port: int = BORE_CONTROL_PORT,
    custom_bore_secret: str | None = None,
    on_status: Callable[[str], None] | None = None,
) -> BaseTunnel:
    """Start a WAN/LAN tunnel according to the selected strategy."""

    def notify(msg: str) -> None:
        if on_status:
            on_status(msg)

    if mode == "lan":
        notify("Usando red local directa (LAN)...")
        return LanTunnel.start(local_port)

    if mode == "bore":
        notify(f"Conectando túnel TCP global ({custom_bore_host})...")
        return BoreTunnel.start(
            local_port, custom_bore_host, custom_bore_port, custom_bore_secret
        )

    if mode == "ssh_pinggy":
        notify("Abriendo túnel SSH inverso (Pinggy)...")
        return SshReverseTunnel.start(local_port, provider="pinggy")

    if mode == "ssh_serveo":
        notify("Abriendo túnel SSH inverso (Serveo)...")
        return SshReverseTunnel.start(local_port, provider="serveo")

    if mode == "upnp":
        notify("Buscando router UPnP...")
        return UpnpTunnel.start(local_port)

    strategies: list[tuple[str, Callable[[], BaseTunnel]]] = [
        (
            f"Túnel global Bore ({custom_bore_host})",
            lambda: BoreTunnel.start(
                local_port, custom_bore_host, custom_bore_port, custom_bore_secret
            ),
        ),
        (
            "Túnel global SSH (Pinggy)",
            lambda: SshReverseTunnel.start(local_port, provider="pinggy", timeout=10.0),
        ),
        (
            "Router UPnP automático",
            lambda: UpnpTunnel.start(local_port, timeout=2.0),
        ),
    ]

    for label, fn in strategies:
        notify(f"Estableciendo {label}...")
        try:
            return fn()
        except Exception:
            continue

    notify("Sin acceso a túnel WAN — iniciando en modo Red Local (LAN).")
    lan = LanTunnel.start(local_port)
    lan.endpoint.detail = (
        f"Solo Red Local ({lan.endpoint.lan_host}:{lan.endpoint.lan_port}) — "
        "túnel WAN no disponible"
    )
    return lan
