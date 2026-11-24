"""High-performance screen capture and DeskRT-inspired delta dirty-rect engine."""

from __future__ import annotations

import io
import time
from dataclasses import dataclass

import mss
from PIL import Image, ImageChops, ImageDraw, ImageGrab

from deskremote.network.protocol import ScreenFramePacket


@dataclass
class MonitorInfo:
    index: int
    name: str
    left: int
    top: int
    width: int
    height: int

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "name": self.name,
            "left": self.left,
            "top": self.top,
            "width": self.width,
            "height": self.height,
        }


def list_monitors() -> list[MonitorInfo]:
    """Enumerate available displays via mss (index 0 = all monitors combined)."""
    monitors: list[MonitorInfo] = []
    with mss.MSS() as sct:
        for idx, mon in enumerate(sct.monitors):
            if idx == 0:
                name = f"Todos los monitores ({mon['width']}×{mon['height']})"
            else:
                name = f"Monitor {idx} ({mon['width']}×{mon['height']})"
            monitors.append(
                MonitorInfo(
                    index=idx,
                    name=name,
                    left=int(mon["left"]),
                    top=int(mon["top"]),
                    width=int(mon["width"]),
                    height=int(mon["height"]),
                )
            )
    return monitors


class DeltaScreenCapturer:
    """Captures screen frames and emits minimal dirty-rect delta updates.

    Inspired by AnyDesk's DeskRT:
      - Computes pixel difference against the previous frame in C (ImageChops).
      - Skips transmission completely when the screen is static (0 bytes sent).
      - Sends only the cropped changed bounding box when <65% of screen changed.
      - Emits periodic keyframes to guarantee visual consistency.
    """

    def __init__(
        self,
        monitor_idx: int = 1,
        jpeg_quality: int = 62,
        scale: float = 0.85,
        keyframe_interval: float = 8.0,
    ) -> None:
        self.monitor_idx = monitor_idx
        self.jpeg_quality = jpeg_quality
        self.scale = scale
        self.keyframe_interval = keyframe_interval

        self._prev_img: Image.Image | None = None
        self._last_keyframe_ts: float = 0.0
        self._force_keyframe: bool = True
        self._current_mon_rect: dict[str, int] = {
            "left": 0,
            "top": 0,
            "width": 1920,
            "height": 1080,
        }

    @property
    def current_monitor_rect(self) -> dict[str, int]:
        return dict(self._current_mon_rect)

    def configure(
        self,
        monitor_idx: int | None = None,
        jpeg_quality: int | None = None,
        scale: float | None = None,
        force_keyframe: bool = False,
    ) -> None:
        if monitor_idx is not None and monitor_idx != self.monitor_idx:
            self.monitor_idx = monitor_idx
            self._prev_img = None
            self._force_keyframe = True
        if jpeg_quality is not None:
            self.jpeg_quality = max(20, min(95, int(jpeg_quality)))
        if scale is not None:
            new_scale = max(0.35, min(1.0, float(scale)))
            if abs(new_scale - self.scale) > 0.01:
                self.scale = new_scale
                self._prev_img = None
                self._force_keyframe = True
        if force_keyframe:
            self._force_keyframe = True

    @staticmethod
    def _render_protected_frame(width: int, height: int, reason: str) -> Image.Image:
        """Render a clean fallback frame when Windows Secure Desktop / UAC blocks capture."""
        w = max(640, min(1280, width))
        h = max(360, min(720, height))
        img = Image.new("RGB", (w, h), (11, 15, 23))
        draw = ImageDraw.Draw(img)
        cx, cy = w // 2, h // 2
        draw.rounded_rectangle(
            [cx - 240, cy - 68, cx + 240, cy + 68],
            radius=16,
            fill=(21, 29, 46),
            outline=(51, 65, 85),
            width=2,
        )
        draw.text((cx - 190, cy - 36), "DeskRemote — Pantalla Protegida", fill=(248, 250, 252))
        draw.text(
            (cx - 190, cy - 6),
            "Escritorio seguro / UAC o sesion bloqueada.",
            fill=(148, 163, 184),
        )
        draw.text(
            (cx - 190, cy + 20),
            f"Reintentando captura automaticamente... ({reason[:38]})",
            fill=(100, 116, 139),
        )
        return img

    def capture_next(self, sct: mss.MSS) -> ScreenFramePacket | None:
        """Capture one frame and return a Full or Delta ScreenFramePacket (or None if unchanged)."""
        mon_count = len(sct.monitors)
        idx = self.monitor_idx if 0 <= self.monitor_idx < mon_count else (1 if mon_count > 1 else 0)
        mon = sct.monitors[idx]
        self._current_mon_rect = {
            "left": int(mon["left"]),
            "top": int(mon["top"]),
            "width": int(mon["width"]),
            "height": int(mon["height"]),
        }

        try:
            shot = sct.grab(mon)
            img = Image.frombytes("RGB", shot.size, shot.bgra, "raw", "BGRX")
        except Exception as primary_exc:
            # Fallback to fresh ImageGrab DC, then clean Secure-Desktop placeholder frame
            try:
                bbox = (
                    int(mon["left"]),
                    int(mon["top"]),
                    int(mon["left"] + mon["width"]),
                    int(mon["top"] + mon["height"]),
                )
                img = ImageGrab.grab(bbox=bbox, all_screens=True).convert("RGB")
            except Exception:
                img = self._render_protected_frame(
                    int(mon["width"]), int(mon["height"]), str(primary_exc)
                )

        if self.scale < 0.99:
            target_w = max(320, int(img.width * self.scale))
            target_h = max(180, int(img.height * self.scale))
            img = img.resize((target_w, target_h), Image.Resampling.BILINEAR)

        full_w, full_h = img.size
        now = time.monotonic()

        need_full = (
            self._force_keyframe
            or self._prev_img is None
            or self._prev_img.size != img.size
            or (now - self._last_keyframe_ts) >= self.keyframe_interval
        )

        if not need_full and self._prev_img is not None:
            diff = ImageChops.difference(self._prev_img, img)
            bbox = diff.getbbox()
            if bbox is None:
                return None

            x1, y1, x2, y2 = bbox
            # Add tiny 4px margin to prevent JPEG block-edge artifacts
            x1 = max(0, x1 - 4)
            y1 = max(0, y1 - 4)
            x2 = min(full_w, x2 + 4)
            y2 = min(full_h, y2 + 4)
            w = x2 - x1
            h = y2 - y1

            if (w * h) < (full_w * full_h * 0.65):
                region = img.crop((x1, y1, x2, y2))
                buf = io.BytesIO()
                region.save(buf, format="JPEG", quality=self.jpeg_quality, subsampling=2)
                self._prev_img = img
                return ScreenFramePacket(
                    monitor_idx=idx,
                    is_full=False,
                    x=x1,
                    y=y1,
                    w=w,
                    h=h,
                    full_w=full_w,
                    full_h=full_h,
                    image_bytes=buf.getvalue(),
                )

        # Send full keyframe
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=self.jpeg_quality, subsampling=2)
        self._prev_img = img
        self._last_keyframe_ts = now
        self._force_keyframe = False
        return ScreenFramePacket(
            monitor_idx=idx,
            is_full=True,
            x=0,
            y=0,
            w=full_w,
            h=full_h,
            full_w=full_w,
            full_h=full_h,
            image_bytes=buf.getvalue(),
        )

    def capture_full_png(self) -> bytes:
        """Capture an uncompressed lossless PNG screenshot of the active monitor."""
        with mss.MSS() as sct:
            idx = self.monitor_idx if 0 <= self.monitor_idx < len(sct.monitors) else 1
            shot = sct.grab(sct.monitors[idx])
            img = Image.frombytes("RGB", shot.size, shot.bgra, "raw", "BGRX")
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            return buf.getvalue()


class FrameCompositor:
    """Reconstructs full frames from Full + Delta ScreenFramePackets on the Host."""

    def __init__(self) -> None:
        self.canvas: Image.Image | None = None

    def apply(self, packet: ScreenFramePacket) -> Image.Image:
        patch = Image.open(io.BytesIO(packet.image_bytes))
        patch.load()
        if packet.is_full or self.canvas is None or self.canvas.size != (packet.full_w, packet.full_h):
            if packet.is_full:
                self.canvas = patch.convert("RGB")
            else:
                self.canvas = Image.new("RGB", (packet.full_w, packet.full_h), (0, 0, 0))
                self.canvas.paste(patch, (packet.x, packet.y))
        else:
            self.canvas.paste(patch, (packet.x, packet.y))
        return self.canvas
