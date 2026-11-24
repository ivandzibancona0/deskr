"""Binary & JSON multiplexed packet protocol over SecureChannel."""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import Any

from deskremote.crypto.e2ee import SecureChannel


class PacketType(IntEnum):
    HEARTBEAT = 0x01
    SYS_INFO = 0x02

    # Screen streaming (raw binary header + compressed image bytes)
    SCREEN_FRAME = 0x10
    SCREEN_CONFIG = 0x11

    # Remote control input
    INPUT_EVENT = 0x20

    # Clipboard
    CLIPBOARD_SYNC = 0x30

    # File manager
    FILE_REQ = 0x40
    FILE_RESP = 0x41
    FILE_CHUNK = 0x42

    # Remote terminal & process telemetry
    SHELL_REQ = 0x50
    SHELL_RESP = 0x51
    PROC_REQ = 0x55
    PROC_RESP = 0x56

    # System power / lock / screenshot actions
    SYS_ACTION = 0x60

    # Encrypted chat & live permissions
    CHAT_MSG = 0x70
    PERMISSIONS = 0x75

    DISCONNECT = 0xFF


# Screen frame flags
FRAME_FLAG_FULL = 0x01
FRAME_FLAG_DELTA = 0x02

# Binary struct for SCREEN_FRAME header:
# monitor_idx(B), flags(B), x(H), y(H), w(H), h(H), full_w(H), full_h(H) = 14 bytes
SCREEN_HEADER_FMT = "!BBHHHHHH"
SCREEN_HEADER_SIZE = struct.calcsize(SCREEN_HEADER_FMT)

# Binary struct for FILE_CHUNK header:
# transfer_id(16s), chunk_idx(I), total_chunks(I), direction(B) = 25 bytes
# direction: 0 = host->guest (upload), 1 = guest->host (download)
FILE_CHUNK_FMT = "!16sIIB"
FILE_CHUNK_SIZE = struct.calcsize(FILE_CHUNK_FMT)


@dataclass
class ScreenFramePacket:
    monitor_idx: int
    is_full: bool
    x: int
    y: int
    w: int
    h: int
    full_w: int
    full_h: int
    image_bytes: bytes


@dataclass
class FileChunkPacket:
    transfer_id: str
    chunk_idx: int
    total_chunks: int
    direction: int
    data: bytes


def send_json(channel: SecureChannel, ptype: PacketType, data: dict[str, Any]) -> None:
    raw = json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    channel.send_encrypted(bytes([ptype]) + raw)


def send_screen_frame(channel: SecureChannel, frame: ScreenFramePacket) -> None:
    flags = FRAME_FLAG_FULL if frame.is_full else FRAME_FLAG_DELTA
    header = struct.pack(
        SCREEN_HEADER_FMT,
        frame.monitor_idx & 0xFF,
        flags,
        frame.x,
        frame.y,
        frame.w,
        frame.h,
        frame.full_w,
        frame.full_h,
    )
    channel.send_encrypted(bytes([PacketType.SCREEN_FRAME]) + header + frame.image_bytes)


def send_file_chunk(channel: SecureChannel, chunk: FileChunkPacket) -> None:
    tid_bytes = chunk.transfer_id.encode("ascii")[:16].ljust(16, b"\x00")
    header = struct.pack(
        FILE_CHUNK_FMT,
        tid_bytes,
        chunk.chunk_idx,
        chunk.total_chunks,
        chunk.direction & 0xFF,
    )
    channel.send_encrypted(bytes([PacketType.FILE_CHUNK]) + header + chunk.data)


def recv_packet(channel: SecureChannel) -> tuple[PacketType, Any]:
    """Receive and unpack the next encrypted packet from SecureChannel."""
    raw = channel.recv_encrypted()
    if not raw:
        raise ValueError("Paquete vacío recibido.")
    ptype = PacketType(raw[0])
    body = raw[1:]

    if ptype == PacketType.SCREEN_FRAME:
        mon, flags, x, y, w, h, full_w, full_h = struct.unpack(
            SCREEN_HEADER_FMT, body[:SCREEN_HEADER_SIZE]
        )
        return ptype, ScreenFramePacket(
            monitor_idx=mon,
            is_full=bool(flags & FRAME_FLAG_FULL),
            x=x,
            y=y,
            w=w,
            h=h,
            full_w=full_w,
            full_h=full_h,
            image_bytes=body[SCREEN_HEADER_SIZE:],
        )

    if ptype == PacketType.FILE_CHUNK:
        tid_bytes, idx, total, direction = struct.unpack(
            FILE_CHUNK_FMT, body[:FILE_CHUNK_SIZE]
        )
        tid = tid_bytes.rstrip(b"\x00").decode("ascii", errors="replace")
        return ptype, FileChunkPacket(
            transfer_id=tid,
            chunk_idx=idx,
            total_chunks=total,
            direction=direction,
            data=body[FILE_CHUNK_SIZE:],
        )

    if not body:
        return ptype, {}
    return ptype, json.loads(body.decode("utf-8"))
