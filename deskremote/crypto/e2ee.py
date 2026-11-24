"""End-to-End Encryption (E2EE v2) engine for DeskRemote.

Hardened cryptographic design:
- Persistent device identity: Ed25519 keypair stored in ~/.deskremote/
  protected at rest via Windows DPAPI (CryptProtectData) on Windows and 0600 on POSIX.
- Password-Authenticated Key Exchange: RFC 9382 SPAKE2 over NIST P-256 combined
  with memory-hard scrypt (32 MiB), preventing offline PIN cracking even by an
  active MitM relay server.
- Hybrid Perfect Forward Secrecy: Ephemeral X25519 (ECDH) combined with SPAKE2
  shared point inside HKDF-SHA256 bound to the full handshake transcript hash.
- Strict Role & Identity Binding: Mutual Ed25519 signatures + mutual HMAC-SHA256
  transcript verification + strict complementary role enforcement (HOST <-> GUEST).
- Transport Cipher: AES-256-GCM (AEAD) with directional keys, 96-bit nonces
  (random prefix + 64-bit monotonic sequence counter) and AAD per packet.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import hashlib
import hmac
import os
import secrets
import socket
import struct
import threading
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from deskremote.config import (
    CONFIG_DIR,
    IDENTITY_KEY_FILE,
    MAX_PACKET_SIZE,
    PROTOCOL_VERSION,
)
from deskremote.crypto.spake2 import Spake2Error, Spake2Exchange
from deskremote.network.session_code import normalize_pin

ROLE_HOST = 1  # Anfitrión (Controlador)
ROLE_GUEST = 2  # Huésped (Equipo controlado)

HANDSHAKE_MAGIC = b"DRK2"
DPAPI_PREFIX = b"DRDPAPI1"


class CryptoError(Exception):
    """Base error for E2EE handshake or transport failures."""


class AuthenticationError(CryptoError):
    """Raised when PIN verification, SPAKE2, Ed25519 signature, role, or HMAC fails."""


# ----------------------------------------------------------------------
# Windows DPAPI Key Protection at Rest
# ----------------------------------------------------------------------


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", ctypes.wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_char)),
    ]


def _dpapi_protect(plaintext: bytes) -> bytes:
    if os.name != "nt":
        return plaintext
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    buf = ctypes.create_string_buffer(plaintext, len(plaintext))
    in_blob = _DataBlob(len(plaintext), buf)
    out_blob = _DataBlob()
    # CRYPTPROTECT_UI_FORBIDDEN = 0x1
    ok = crypt32.CryptProtectData(
        ctypes.byref(in_blob),
        "DeskRemote Ed25519 Identity",
        None,
        None,
        None,
        0x1,
        ctypes.byref(out_blob),
    )
    if not ok:
        raise OSError("Windows DPAPI CryptProtectData falló.")
    try:
        return DPAPI_PREFIX + ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)


def _dpapi_unprotect(blob: bytes) -> bytes:
    if not blob.startswith(DPAPI_PREFIX):
        return blob
    if os.name != "nt":
        raise CryptoError("Clave protegida con Windows DPAPI no legible en este SO.")
    payload = blob[len(DPAPI_PREFIX) :]
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    buf = ctypes.create_string_buffer(payload, len(payload))
    in_blob = _DataBlob(len(payload), buf)
    out_blob = _DataBlob()
    ok = crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None,
        None,
        None,
        None,
        0x1,
        ctypes.byref(out_blob),
    )
    if not ok:
        raise CryptoError("No se pudo descifrar la clave local con Windows DPAPI.")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)


# ----------------------------------------------------------------------
# Low-level Framing Helpers
# ----------------------------------------------------------------------


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes from a TCP socket or raise ConnectionError."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Conexión cerrada inesperadamente por el extremo remoto.")
        buf.extend(chunk)
    return bytes(buf)


def send_frame_raw(sock: socket.socket, payload: bytes) -> None:
    """Send a 4-byte length-prefixed raw frame."""
    header = struct.pack("!I", len(payload))
    sock.sendall(header + payload)


def recv_frame_raw(sock: socket.socket, max_len: int = MAX_PACKET_SIZE) -> bytes:
    """Receive a 4-byte length-prefixed raw frame."""
    header = recv_exact(sock, 4)
    (length,) = struct.unpack("!I", header)
    if length == 0 or length > max_len:
        raise CryptoError(f"Tamaño de trama inválido: {length} bytes")
    return recv_exact(sock, length)


def format_fingerprint(raw_hash: bytes, groups: int = 4) -> str:
    """Format a digest into readable uppercase hex groups (e.g. A3F8-91C2-4B0E-7D12)."""
    hex_str = raw_hash.hex().upper()
    parts = [hex_str[i * 4 : (i + 1) * 4] for i in range(groups)]
    return "-".join(parts)


class DeviceIdentity:
    """Persistent Ed25519 cryptographic identity protected at rest."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private = private_key
        self._public = private_key.public_key()
        self.public_bytes: bytes = self._public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.fingerprint: str = format_fingerprint(
            hashlib.sha256(self.public_bytes).digest(), groups=3
        )

    @classmethod
    def load_or_create(cls, key_path: Path = IDENTITY_KEY_FILE) -> "DeviceIdentity":
        try:
            if key_path.exists():
                stored = key_path.read_bytes()
                was_plaintext_on_win = (
                    os.name == "nt" and len(stored) == 32 and not stored.startswith(DPAPI_PREFIX)
                )
                raw = _dpapi_unprotect(stored)
                if len(raw) == 32:
                    ident = cls(Ed25519PrivateKey.from_private_bytes(raw))
                    # Auto-migrate legacy plaintext Windows key to DPAPI
                    if was_plaintext_on_win:
                        try:
                            key_path.write_bytes(_dpapi_protect(raw))
                        except OSError:
                            pass
                    return ident
        except (OSError, CryptoError, ValueError):
            pass

        private = Ed25519PrivateKey.generate()
        raw = private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        try:
            key_path.parent.mkdir(parents=True, exist_ok=True)
            data_to_store = _dpapi_protect(raw) if os.name == "nt" else raw
            key_path.write_bytes(data_to_store)
            if os.name != "nt":
                os.chmod(key_path, 0o600)
        except OSError:
            pass
        return cls(private)

    @classmethod
    def ephemeral(cls) -> "DeviceIdentity":
        """Create a transient Ed25519 identity (useful for testing)."""
        return cls(Ed25519PrivateKey.generate())

    def sign(self, data: bytes) -> bytes:
        return self._private.sign(data)


@dataclass(frozen=True)
class SessionInfo:
    """Verified cryptographic metadata of an established E2EE v2 session."""

    peer_name: str
    peer_role: int
    peer_fingerprint: str
    peer_id_pub: bytes
    session_fingerprint: str
    cipher_suite: str = "SPAKE2(P-256) + X25519 + Ed25519 + AES-256-GCM"


class SecureChannel:
    """Thread-safe AES-256-GCM authenticated encrypted channel over a TCP socket."""

    def __init__(
        self,
        sock: socket.socket,
        tx_key: bytes,
        rx_key: bytes,
        tx_nonce_prefix: bytes,
        rx_nonce_prefix: bytes,
        tx_dir_byte: bytes,
        rx_dir_byte: bytes,
        session_info: SessionInfo,
    ) -> None:
        self.sock = sock
        self._tx_cipher = AESGCM(tx_key)
        self._rx_cipher = AESGCM(rx_key)
        self._tx_prefix = tx_nonce_prefix
        self._rx_prefix = rx_nonce_prefix
        self._tx_dir = tx_dir_byte
        self._rx_dir = rx_dir_byte
        self.info = session_info

        self._tx_seq = 0
        self._rx_seq = 0
        self._tx_lock = threading.Lock()
        self._rx_lock = threading.Lock()
        self._closed = False

        self.bytes_sent = 0
        self.bytes_recv = 0

    @property
    def is_closed(self) -> bool:
        return self._closed

    def send_encrypted(self, plaintext: bytes) -> None:
        """Encrypt plaintext with AES-256-GCM and send length-prefixed ciphertext."""
        with self._tx_lock:
            if self._closed:
                raise ConnectionError("El canal cifrado está cerrado.")
            seq = self._tx_seq
            self._tx_seq += 1
            nonce = self._tx_prefix + struct.pack("!Q", seq)
            aad = self._tx_dir + struct.pack("!BQ", PROTOCOL_VERSION, seq)
            ciphertext = self._tx_cipher.encrypt(nonce, plaintext, aad)
            send_frame_raw(self.sock, ciphertext)
            self.bytes_sent += len(ciphertext) + 4

    def recv_encrypted(self) -> bytes:
        """Receive and decrypt the next AES-256-GCM packet, verifying sequence & tag."""
        with self._rx_lock:
            if self._closed:
                raise ConnectionError("El canal cifrado está cerrado.")
            ciphertext = recv_frame_raw(self.sock)
            self.bytes_recv += len(ciphertext) + 4
            seq = self._rx_seq
            self._rx_seq += 1
            nonce = self._rx_prefix + struct.pack("!Q", seq)
            aad = self._rx_dir + struct.pack("!BQ", PROTOCOL_VERSION, seq)
            try:
                return self._rx_cipher.decrypt(nonce, ciphertext, aad)
            except InvalidTag as exc:
                raise AuthenticationError(
                    "Integridad de paquete comprometida (fallo AES-256-GCM)."
                ) from exc

    def close(self) -> None:
        self._closed = True
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


def _validate_complementary_roles(local_role: int, peer_role: int) -> None:
    if peer_role not in (ROLE_HOST, ROLE_GUEST) or local_role not in (ROLE_HOST, ROLE_GUEST):
        raise AuthenticationError("Rol de sesión inválido.")
    if peer_role == local_role:
        raise AuthenticationError(
            "Incompatibilidad de roles: ambos extremos intentan actuar con el mismo rol."
        )


def _derive_session_keys_v2(
    spake2_shared: bytes,
    x25519_shared: bytes,
    client_nonce: bytes,
    server_nonce: bytes,
    transcript_hash: bytes,
) -> tuple[bytes, bytes, bytes, bytes, bytes]:
    """Derive directional AES-256 keys, nonce prefixes, and auth key via HKDF-SHA256."""
    ikm = spake2_shared + x25519_shared
    salt = client_nonce + server_nonce
    info = b"DeskRemote-v2-SPAKE2-E2EE:" + transcript_hash
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32 + 32 + 32 + 4 + 4,
        salt=salt,
        info=info,
    )
    material = hkdf.derive(ikm)
    return (
        material[0:32],   # s2c_key
        material[32:64],  # c2s_key
        material[64:96],  # auth_key
        material[96:100], # s2c_prefix
        material[100:104],# c2s_prefix
    )


def perform_client_handshake(
    sock: socket.socket,
    identity: DeviceIdentity,
    pin: str,
    local_role: int,
    local_name: str,
) -> SecureChannel:
    """Run the TCP-client side of the SPAKE2 + X25519 + Ed25519 E2EE v2 handshake."""
    norm_pin = normalize_pin(pin)
    if not norm_pin:
        raise AuthenticationError("El PIN de sesión no puede estar vacío.")

    spake = Spake2Exchange("A", norm_pin)
    spake_pub_a = spake.start()  # 33 bytes compressed P-256

    eph_priv = X25519PrivateKey.generate()
    eph_pub = eph_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    client_nonce = secrets.token_bytes(32)
    name_bytes = local_name.encode("utf-8")[:64]

    sig_payload = (
        b"DeskRemote-v2-Hello-C"
        + bytes([PROTOCOL_VERSION, local_role])
        + spake_pub_a
        + eph_pub
        + client_nonce
        + name_bytes
    )
    client_sig = identity.sign(sig_payload)

    hello_c = (
        HANDSHAKE_MAGIC
        + struct.pack("!BBH", PROTOCOL_VERSION, local_role, len(name_bytes))
        + spake_pub_a
        + eph_pub
        + identity.public_bytes
        + client_nonce
        + name_bytes
        + client_sig
    )
    send_frame_raw(sock, hello_c)

    # Receive HELLO_S
    hello_s = recv_frame_raw(sock, max_len=4096)
    min_len = 4 + 4 + 33 + 32 + 32 + 32 + 64 + 32
    if len(hello_s) < min_len or hello_s[:4] != HANDSHAKE_MAGIC:
        raise AuthenticationError("Respuesta HELLO v2 del servidor malformada.")

    ver, server_role, s_name_len = struct.unpack("!BBH", hello_s[4:8])
    if ver != PROTOCOL_VERSION:
        raise AuthenticationError(f"Versión de protocolo incompatible: {ver}")
    _validate_complementary_roles(local_role, server_role)

    offset = 8
    spake_pub_b = hello_s[offset : offset + 33]
    offset += 33
    server_eph_pub = hello_s[offset : offset + 32]
    offset += 32
    server_id_pub = hello_s[offset : offset + 32]
    offset += 32
    server_nonce = hello_s[offset : offset + 32]
    offset += 32
    server_name_bytes = hello_s[offset : offset + s_name_len]
    offset += s_name_len
    server_sig = hello_s[offset : offset + 64]
    offset += 64
    server_mac = hello_s[offset : offset + 32]
    if len(server_mac) != 32:
        raise AuthenticationError("HELLO v2 del servidor incompleto.")

    hello_s_core = hello_s[: 8 + 33 + 32 + 32 + 32 + s_name_len]
    transcript_hash = hashlib.sha256(hello_c + hello_s_core).digest()

    # Verify server Ed25519 signature over full transcript
    try:
        peer_id_key = Ed25519PublicKey.from_public_bytes(server_id_pub)
        peer_id_key.verify(server_sig, b"DeskRemote-v2-Hello-S" + transcript_hash)
    except (InvalidSignature, ValueError) as exc:
        raise AuthenticationError(
            "Firma criptográfica Ed25519 del servidor inválida (posible MitM)."
        ) from exc

    # Finish SPAKE2 + X25519
    try:
        spake_shared = spake.finish(spake_pub_b)
        x25519_shared = eph_priv.exchange(X25519PublicKey.from_public_bytes(server_eph_pub))
    except (Spake2Error, ValueError) as exc:
        raise AuthenticationError(f"Fallo en intercambio de claves: {exc}") from exc

    s2c_key, c2s_key, auth_key, s2c_prefix, c2s_prefix = _derive_session_keys_v2(
        spake_shared, x25519_shared, client_nonce, server_nonce, transcript_hash
    )

    expected_server_mac = hmac.new(
        auth_key, b"SERVER-AUTH-V2" + transcript_hash, hashlib.sha256
    ).digest()
    if not hmac.compare_digest(server_mac, expected_server_mac):
        raise AuthenticationError(
            "PIN incorrecto o intento de interceptación (fallo SPAKE2)."
        )

    # Send AUTH_C proof
    client_mac = hmac.new(
        auth_key, b"CLIENT-AUTH-V2" + transcript_hash, hashlib.sha256
    ).digest()
    send_frame_raw(sock, b"AUTH" + client_mac)

    session_fp = format_fingerprint(
        hashlib.sha256(b"FP-V2" + transcript_hash).digest(), groups=4
    )
    peer_fp = format_fingerprint(hashlib.sha256(server_id_pub).digest(), groups=3)

    info = SessionInfo(
        peer_name=server_name_bytes.decode("utf-8", errors="replace"),
        peer_role=server_role,
        peer_fingerprint=peer_fp,
        peer_id_pub=server_id_pub,
        session_fingerprint=session_fp,
    )
    return SecureChannel(
        sock=sock,
        tx_key=c2s_key,
        rx_key=s2c_key,
        tx_nonce_prefix=c2s_prefix,
        rx_nonce_prefix=s2c_prefix,
        tx_dir_byte=b"C",
        rx_dir_byte=b"S",
        session_info=info,
    )


def perform_server_handshake(
    sock: socket.socket,
    identity: DeviceIdentity,
    pin: str,
    local_role: int,
    local_name: str,
) -> SecureChannel:
    """Run the TCP-server side of the SPAKE2 + X25519 + Ed25519 E2EE v2 handshake."""
    norm_pin = normalize_pin(pin)
    if not norm_pin:
        raise AuthenticationError("PIN del servidor vacío.")

    hello_c = recv_frame_raw(sock, max_len=4096)
    min_len = 4 + 4 + 33 + 32 + 32 + 32 + 64
    if len(hello_c) < min_len or hello_c[:4] != HANDSHAKE_MAGIC:
        raise AuthenticationError("Mensaje HELLO v2 del cliente malformado.")

    ver, client_role, c_name_len = struct.unpack("!BBH", hello_c[4:8])
    if ver != PROTOCOL_VERSION:
        raise AuthenticationError(f"Versión de protocolo incompatible: {ver}")
    _validate_complementary_roles(local_role, client_role)

    offset = 8
    spake_pub_a = hello_c[offset : offset + 33]
    offset += 33
    client_eph_pub = hello_c[offset : offset + 32]
    offset += 32
    client_id_pub = hello_c[offset : offset + 32]
    offset += 32
    client_nonce = hello_c[offset : offset + 32]
    offset += 32
    client_name_bytes = hello_c[offset : offset + c_name_len]
    offset += c_name_len
    client_sig = hello_c[offset : offset + 64]
    if len(client_sig) != 64:
        raise AuthenticationError("HELLO v2 del cliente incompleto.")

    # Verify client Ed25519 signature
    sig_payload = (
        b"DeskRemote-v2-Hello-C"
        + bytes([ver, client_role])
        + spake_pub_a
        + client_eph_pub
        + client_nonce
        + client_name_bytes
    )
    try:
        peer_id_key = Ed25519PublicKey.from_public_bytes(client_id_pub)
        peer_id_key.verify(client_sig, sig_payload)
    except (InvalidSignature, ValueError) as exc:
        raise AuthenticationError(
            "Firma criptográfica Ed25519 del cliente inválida."
        ) from exc

    # Build server SPAKE2 + X25519 ephemeral keys
    spake = Spake2Exchange("B", norm_pin)
    spake_pub_b = spake.start()

    eph_priv = X25519PrivateKey.generate()
    eph_pub = eph_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    server_nonce = secrets.token_bytes(32)
    name_bytes = local_name.encode("utf-8")[:64]

    hello_s_core = (
        HANDSHAKE_MAGIC
        + struct.pack("!BBH", PROTOCOL_VERSION, local_role, len(name_bytes))
        + spake_pub_b
        + eph_pub
        + identity.public_bytes
        + server_nonce
        + name_bytes
    )
    transcript_hash = hashlib.sha256(hello_c + hello_s_core).digest()

    try:
        spake_shared = spake.finish(spake_pub_a)
        x25519_shared = eph_priv.exchange(X25519PublicKey.from_public_bytes(client_eph_pub))
    except (Spake2Error, ValueError) as exc:
        raise AuthenticationError(f"Punto criptográfico inválido del cliente: {exc}") from exc

    s2c_key, c2s_key, auth_key, s2c_prefix, c2s_prefix = _derive_session_keys_v2(
        spake_shared, x25519_shared, client_nonce, server_nonce, transcript_hash
    )

    server_sig = identity.sign(b"DeskRemote-v2-Hello-S" + transcript_hash)
    server_mac = hmac.new(
        auth_key, b"SERVER-AUTH-V2" + transcript_hash, hashlib.sha256
    ).digest()

    send_frame_raw(sock, hello_s_core + server_sig + server_mac)

    # Receive and verify AUTH_C
    auth_c = recv_frame_raw(sock, max_len=256)
    if len(auth_c) != 36 or auth_c[:4] != b"AUTH":
        raise AuthenticationError("Autenticación del cliente rechazada o malformada.")
    client_mac = auth_c[4:36]
    expected_client_mac = hmac.new(
        auth_key, b"CLIENT-AUTH-V2" + transcript_hash, hashlib.sha256
    ).digest()
    if not hmac.compare_digest(client_mac, expected_client_mac):
        raise AuthenticationError("PIN incorrecto en el extremo remoto.")

    session_fp = format_fingerprint(
        hashlib.sha256(b"FP-V2" + transcript_hash).digest(), groups=4
    )
    peer_fp = format_fingerprint(hashlib.sha256(client_id_pub).digest(), groups=3)

    info = SessionInfo(
        peer_name=client_name_bytes.decode("utf-8", errors="replace"),
        peer_role=client_role,
        peer_fingerprint=peer_fp,
        peer_id_pub=client_id_pub,
        session_fingerprint=session_fp,
    )
    return SecureChannel(
        sock=sock,
        tx_key=s2c_key,
        rx_key=c2s_key,
        tx_nonce_prefix=s2c_prefix,
        rx_nonce_prefix=c2s_prefix,
        tx_dir_byte=b"S",
        rx_dir_byte=b"C",
        session_info=info,
    )
