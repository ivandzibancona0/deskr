"""Compact shareable session codes and cryptographic session PIN generation.

Session code format:
  - Compact Base32 token: DR-XXXX-XXXX-...
  - Also accepts plain `host:port` (e.g. `bore.pub:41234` or `192.168.1.50:55000`)

Session PIN format:
  - Default 8 unambiguous uppercase alphanumeric chars grouped as XXXX-XXXX
    (~39.6 bits entropy, protected against offline attacks via SPAKE2 + scrypt).
"""

from __future__ import annotations

import base64
import secrets
import struct

from deskremote.config import PIN_LENGTH

# Unambiguous uppercase alphanumeric alphabet (excludes 0, O, 1, I, L)
PIN_ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"

# Known compact host aliases to keep session codes super short
HOST_TO_ALIAS = {
    "bore.pub": b"\x01",
}
ALIAS_TO_HOST = {v: k for k, v in HOST_TO_ALIAS.items()}


def normalize_pin(pin: str) -> str:
    """Normalize a user-entered PIN by removing whitespace/hyphens and uppercasing."""
    return pin.strip().upper().replace("-", "").replace(" ", "")


def generate_pin(length: int = PIN_LENGTH) -> str:
    """Generate a cryptographically secure session PIN (e.g. 'K7M4-P9Q2')."""
    raw = "".join(secrets.choice(PIN_ALPHABET) for _ in range(length))
    if length >= 8 and length % 4 == 0:
        return "-".join(raw[i : i + 4] for i in range(0, length, 4))
    return raw


def encode_session_code(host: str, port: int) -> str:
    """Encode a host & port into a compact readable DR-XXXX-... invitation code."""
    host_clean = host.strip().lower()
    if host_clean in HOST_TO_ALIAS:
        payload = HOST_TO_ALIAS[host_clean] + struct.pack("!H", port)
    else:
        host_bytes = host_clean.encode("utf-8")
        payload = b"\x00" + struct.pack("!H", port) + host_bytes

    b32 = base64.b32encode(payload).decode("ascii").rstrip("=")
    groups = [b32[i : i + 4] for i in range(0, len(b32), 4)]
    return "DR-" + "-".join(groups)


def decode_session_code(code: str) -> tuple[str, int]:
    """Decode either a DR-... session code or a direct 'host:port' string."""
    raw = code.strip()
    if not raw:
        raise ValueError("El código de sesión está vacío.")

    # Direct host:port format
    if ":" in raw and not raw.upper().startswith("DR-"):
        host_part, port_part = raw.rsplit(":", 1)
        host = host_part.strip("[] ")
        port = int(port_part.strip())
        if not host or not (1 <= port <= 65535):
            raise ValueError("Dirección host:puerto inválida.")
        return host, port

    # Compact DR-... format
    cleaned = raw.upper().replace(" ", "")
    if cleaned.startswith("DR-"):
        cleaned = cleaned[3:]
    cleaned = cleaned.replace("-", "")

    pad = (-len(cleaned)) % 8
    try:
        payload = base64.b32decode(cleaned + ("=" * pad))
    except Exception as exc:
        raise ValueError("Código de sesión DR inválido o corrupto.") from exc

    if len(payload) < 3:
        raise ValueError("Código de sesión demasiado corto.")

    tag = payload[0:1]
    (port,) = struct.unpack("!H", payload[1:3])
    if tag in ALIAS_TO_HOST:
        return ALIAS_TO_HOST[tag], port
    if tag == b"\x00":
        host = payload[3:].decode("utf-8")
        if not host:
            raise ValueError("Host vacío en el código de sesión.")
        return host, port
    raise ValueError("Formato de código de sesión desconocido.")
