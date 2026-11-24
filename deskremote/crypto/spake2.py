"""RFC 9382 SPAKE2 Password-Authenticated Key Exchange over NIST P-256.

Provides mathematical immunity against offline dictionary/brute-force attacks
on the session PIN, even if an active Man-in-the-Middle controls the public
tunnel/relay server (each online attempt yields at most one PIN guess).

Parameters follow RFC 9382 Section 4 (P-256 / secp256r1):
  - M = 02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f
  - N = 03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49
"""

from __future__ import annotations

import hashlib
import secrets

# NIST P-256 (secp256r1) curve parameters
_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_A = _P - 3
_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

# Official RFC 9382 P-256 compressed points M and N
_M_HEX = "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"
_N_HEX = "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"

Point = tuple[int, int] | None  # None represents point at infinity


class Spake2Error(ValueError):
    """Raised on invalid elliptic curve points or protocol errors."""


def _is_on_curve(pt: Point) -> bool:
    if pt is None:
        return False
    x, y = pt
    if not (0 <= x < _P and 0 <= y < _P):
        return False
    return (y * y - (x * x * x + _A * x + _B)) % _P == 0


def _point_neg(pt: Point) -> Point:
    if pt is None:
        return None
    return (pt[0], (-pt[1]) % _P)


def _point_add(p1: Point, p2: Point) -> Point:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % _P == 0:
            return None
        # Point doubling
        lam = ((3 * x1 * x1 + _A) * pow((2 * y1) % _P, -1, _P)) % _P
    else:
        lam = ((y2 - y1) * pow((x2 - x1) % _P, -1, _P)) % _P
    x3 = (lam * lam - x1 - x2) % _P
    y3 = (lam * (x1 - x3) - y1) % _P
    return (x3, y3)


def _scalar_mul(k: int, pt: Point) -> Point:
    k %= _N
    if k == 0 or pt is None:
        return None
    result: Point = None
    addend: Point = pt
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def encode_point(pt: Point) -> bytes:
    """Encode an affine P-256 point into 33-byte SEC1 compressed format."""
    if pt is None or not _is_on_curve(pt):
        raise Spake2Error("No se puede codificar un punto inválido de P-256.")
    x, y = pt
    prefix = b"\x02" if (y & 1) == 0 else b"\x03"
    return prefix + x.to_bytes(32, "big")


def decode_point(data: bytes) -> tuple[int, int]:
    """Decode and strictly validate a 33-byte SEC1 compressed P-256 point."""
    if len(data) != 33 or data[0] not in (2, 3):
        raise Spake2Error("Punto comprimido P-256 malformado.")
    x = int.from_bytes(data[1:], "big")
    if x >= _P:
        raise Spake2Error("Coordenada X fuera del campo P-256.")
    rhs = (pow(x, 3, _P) + _A * x + _B) % _P
    # P-256 prime satisfies p == 3 (mod 4), so sqrt(rhs) = rhs^((p+1)/4) mod p
    y = pow(rhs, (_P + 1) >> 2, _P)
    if (y * y) % _P != rhs:
        raise Spake2Error("El punto recibido no pertenece a la curva P-256.")
    if (y & 1) != (data[0] & 1):
        y = _P - y
    pt = (x, y)
    if not _is_on_curve(pt):
        raise Spake2Error("Validación de curva P-256 fallida.")
    return pt


_G: tuple[int, int] = (_GX, _GY)
_M: tuple[int, int] = decode_point(bytes.fromhex(_M_HEX))
_N_PT: tuple[int, int] = decode_point(bytes.fromhex(_N_HEX))


def pin_to_scalar(normalized_pin: str) -> int:
    """Derive a memory-hard SPAKE2 scalar w in [1, N-1] via scrypt."""
    pw = normalized_pin.encode("utf-8")
    # scrypt (32 MiB memory-hard) slows down both online and hypothetical offline attempts
    dk = hashlib.scrypt(
        pw,
        salt=b"DeskRemote-SPAKE2-P256-v2",
        n=1 << 15,
        r=8,
        p=1,
        maxmem=64 * 1024 * 1024,
        dklen=48,
    )
    return (int.from_bytes(dk, "big") % (_N - 1)) + 1


class Spake2Exchange:
    """One side (client='A' or server='B') of an RFC 9382 SPAKE2 exchange."""

    def __init__(self, side: str, normalized_pin: str) -> None:
        if side not in ("A", "B"):
            raise ValueError("side debe ser 'A' (cliente) o 'B' (servidor).")
        self.side = side
        self._w = pin_to_scalar(normalized_pin)
        self._ephemeral = secrets.randbelow(_N - 1) + 1
        self._public_bytes: bytes | None = None

    def start(self) -> bytes:
        """Return 33-byte blinded public element pA = x*G + w*M or pB = y*G + w*N."""
        if self._public_bytes is None:
            blind_base = _M if self.side == "A" else _N_PT
            pub = _point_add(
                _scalar_mul(self._ephemeral, _G),
                _scalar_mul(self._w, blind_base),
            )
            self._public_bytes = encode_point(pub)
        return self._public_bytes

    def finish(self, peer_public_bytes: bytes) -> bytes:
        """Validate peer point and return 33-byte shared secret point K."""
        peer_pt = decode_point(peer_public_bytes)
        peer_blind_base = _N_PT if self.side == "A" else _M
        unblinded = _point_add(peer_pt, _point_neg(_scalar_mul(self._w, peer_blind_base)))
        if unblinded is None:
            raise Spake2Error("Punto compartido degenerado (punto en el infinito).")
        shared_pt = _scalar_mul(self._ephemeral, unblinded)
        return encode_point(shared_pt)
