"""Minimalist vector icon system (24x24 geometric primitives, 4x supersampled HiDPI).

Zero native DLL dependencies (no Cairo/GTK required on Windows) while delivering
razor-sharp, Lucide-style outline vector icons that adapt automatically to
CustomTkinter's Light and Dark themes. Also exports clean SVG files on demand.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import customtkinter as ctk
from PIL import Image, ImageDraw

# Declarative 24x24 minimalist vector icon definitions.
# Supported primitives:
#   ("line", x1, y1, x2, y2)
#   ("poly", [(x, y), ...], closed_bool)
#   ("rect", x1, y1, x2, y2, radius)
#   ("circle", cx, cy, r)
#   ("arc", x1, y1, x2, y2, start_deg, end_deg)
#   ("fill_circle", cx, cy, r)
ICON_SPECS: dict[str, list[tuple[Any, ...]]] = {
    "logo": [
        ("rect", 2.5, 4.0, 16.5, 14.5, 2.5),
        ("rect", 7.5, 9.5, 21.5, 20.0, 2.5),
        ("fill_circle", 14.5, 14.75, 1.5),
    ],
    "monitor": [
        ("rect", 2.5, 3.5, 21.5, 16.0, 2.0),
        ("line", 8.5, 20.5, 15.5, 20.5),
        ("line", 12.0, 16.0, 12.0, 20.5),
    ],
    "shield_lock": [
        ("poly", [(12.0, 2.5), (20.0, 5.8), (20.0, 11.8), (16.8, 17.5), (12.0, 21.5), (7.2, 17.5), (4.0, 11.8), (4.0, 5.8)], True),
        ("poly", [(9.0, 12.0), (11.2, 14.2), (15.5, 9.8)], False),
    ],
    "server": [
        ("rect", 3.0, 3.5, 21.0, 10.0, 2.0),
        ("rect", 3.0, 14.0, 21.0, 20.5, 2.0),
        ("fill_circle", 6.8, 6.75, 1.1),
        ("fill_circle", 6.8, 17.25, 1.1),
        ("line", 10.5, 6.75, 17.5, 6.75),
        ("line", 10.5, 17.25, 17.5, 17.25),
    ],
    "globe": [
        ("circle", 12.0, 12.0, 9.0),
        ("line", 3.0, 12.0, 21.0, 12.0),
        ("arc", 7.5, 3.0, 16.5, 21.0, 0, 360),
    ],
    "wifi": [
        ("arc", 2.5, 6.0, 21.5, 25.0, 225, 315),
        ("arc", 6.0, 10.0, 18.0, 22.0, 225, 315),
        ("arc", 9.2, 14.0, 14.8, 19.6, 225, 315),
        ("fill_circle", 12.0, 19.5, 1.3),
    ],
    "copy": [
        ("rect", 9.0, 9.0, 20.5, 20.5, 2.0),
        ("poly", [(15.0, 9.0), (15.0, 5.0), (5.0, 5.0), (5.0, 15.0), (9.0, 15.0)], False),
    ],
    "check": [
        ("poly", [(4.5, 12.5), (9.5, 17.5), (19.5, 6.5)], False),
    ],
    "play": [
        ("poly", [(6.5, 4.5), (19.5, 12.0), (6.5, 19.5)], True),
    ],
    "stop": [
        ("rect", 5.5, 5.5, 18.5, 18.5, 2.2),
    ],
    "link": [
        ("rect", 3.0, 8.5, 13.0, 15.5, 3.5),
        ("rect", 11.0, 8.5, 21.0, 15.5, 3.5),
    ],
    "folder": [
        ("poly", [(3.0, 6.0), (9.5, 6.0), (11.5, 8.5), (21.0, 8.5), (21.0, 19.0), (3.0, 19.0)], True),
    ],
    "file": [
        ("poly", [(6.0, 3.0), (14.5, 3.0), (18.5, 7.0), (18.5, 21.0), (6.0, 21.0)], True),
        ("poly", [(14.5, 3.0), (14.5, 7.0), (18.5, 7.0)], False),
    ],
    "upload": [
        ("line", 12.0, 15.5, 12.0, 4.5),
        ("poly", [(7.5, 9.0), (12.0, 4.5), (16.5, 9.0)], False),
        ("poly", [(4.0, 16.5), (4.0, 20.0), (20.0, 20.0), (20.0, 16.5)], False),
    ],
    "download": [
        ("line", 12.0, 4.5, 12.0, 15.5),
        ("poly", [(7.5, 11.0), (12.0, 15.5), (16.5, 11.0)], False),
        ("poly", [(4.0, 16.5), (4.0, 20.0), (20.0, 20.0), (20.0, 16.5)], False),
    ],
    "terminal": [
        ("rect", 2.5, 4.0, 21.5, 20.0, 2.2),
        ("poly", [(6.5, 9.5), (10.0, 12.5), (6.5, 15.5)], False),
        ("line", 12.0, 15.5, 17.5, 15.5),
    ],
    "clipboard": [
        ("rect", 5.0, 5.0, 19.0, 21.0, 2.0),
        ("rect", 8.5, 3.0, 15.5, 6.8, 1.2),
        ("line", 8.5, 11.5, 15.5, 11.5),
        ("line", 8.5, 15.5, 13.5, 15.5),
    ],
    "activity": [
        ("poly", [(2.5, 12.5), (6.5, 12.5), (9.2, 5.0), (14.2, 19.0), (17.2, 12.5), (21.5, 12.5)], False),
    ],
    "message": [
        ("poly", [(3.5, 4.5), (20.5, 4.5), (20.5, 16.5), (9.0, 16.5), (4.5, 20.5), (4.5, 16.5), (3.5, 16.5)], True),
    ],
    "settings": [
        ("circle", 12.0, 12.0, 3.5),
        ("circle", 12.0, 12.0, 7.8),
        ("line", 12.0, 2.2, 12.0, 4.2),
        ("line", 12.0, 19.8, 12.0, 21.8),
        ("line", 2.2, 12.0, 4.2, 12.0),
        ("line", 19.8, 12.0, 21.8, 12.0),
    ],
    "sun": [
        ("circle", 12.0, 12.0, 4.2),
        ("line", 12.0, 2.5, 12.0, 5.0),
        ("line", 12.0, 19.0, 12.0, 21.5),
        ("line", 2.5, 12.0, 5.0, 12.0),
        ("line", 19.0, 12.0, 21.5, 12.0),
        ("line", 5.2, 5.2, 7.0, 7.0),
        ("line", 17.0, 17.0, 18.8, 18.8),
        ("line", 18.8, 5.2, 17.0, 7.0),
        ("line", 7.0, 17.0, 5.2, 18.8),
    ],
    "moon": [
        ("arc", 4.0, 4.0, 20.0, 20.0, 40, 260),
        ("arc", 9.0, 3.0, 21.0, 15.0, 110, 260),
    ],
    "lock": [
        ("rect", 5.0, 10.5, 19.0, 20.5, 2.2),
        ("arc", 7.5, 3.5, 16.5, 13.5, 180, 360),
        ("line", 7.5, 8.5, 7.5, 10.5),
        ("line", 16.5, 8.5, 16.5, 10.5),
        ("fill_circle", 12.0, 15.5, 1.3),
    ],
    "camera": [
        ("rect", 2.5, 6.5, 21.5, 19.5, 2.5),
        ("poly", [(8.0, 6.5), (9.8, 4.0), (14.2, 4.0), (16.0, 6.5)], False),
        ("circle", 12.0, 13.0, 3.4),
    ],
    "power": [
        ("line", 12.0, 3.0, 12.0, 11.5),
        ("arc", 4.5, 5.0, 19.5, 20.0, -55, 235),
    ],
    "refresh": [
        ("arc", 4.0, 4.0, 20.0, 20.0, 35, 325),
        ("poly", [(16.5, 4.2), (19.8, 6.2), (17.2, 9.5)], False),
    ],
    "keyboard": [
        ("rect", 2.5, 5.5, 21.5, 18.5, 2.2),
        ("line", 6.0, 10.0, 8.0, 10.0),
        ("line", 11.0, 10.0, 13.0, 10.0),
        ("line", 16.0, 10.0, 18.0, 10.0),
        ("line", 7.5, 14.5, 16.5, 14.5),
    ],
    "trash": [
        ("line", 4.0, 6.5, 20.0, 6.5),
        ("rect", 9.0, 3.5, 15.0, 6.5, 1.0),
        ("poly", [(6.0, 6.5), (7.2, 20.5), (16.8, 20.5), (18.0, 6.5)], False),
        ("line", 10.2, 10.5, 10.2, 16.8),
        ("line", 13.8, 10.5, 13.8, 16.8),
    ],
    "arrow_up": [
        ("line", 12.0, 19.5, 12.0, 5.0),
        ("poly", [(6.5, 10.5), (12.0, 5.0), (17.5, 10.5)], False),
    ],
    "plus": [
        ("line", 12.0, 5.0, 12.0, 19.0),
        ("line", 5.0, 12.0, 19.0, 12.0),
    ],
    "user_check": [
        ("circle", 9.5, 8.0, 3.6),
        ("arc", 3.0, 14.0, 16.0, 25.0, 190, 350),
        ("poly", [(15.5, 12.0), (17.5, 14.2), (21.5, 9.8)], False),
    ],
}


def _hex_to_rgba(hex_color: str) -> tuple[int, int, int, int]:
    c = hex_color.lstrip("#")
    if len(c) == 6:
        return (int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16), 255)
    if len(c) == 8:
        return (int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16), int(c[6:8], 16))
    return (248, 250, 252, 255)


def render_vector_pil(
    name: str,
    size: int = 20,
    color: str = "#F8FAFC",
    stroke_width: float = 1.85,
) -> Image.Image:
    """Render a named minimalist vector icon to a crisp RGBA PIL Image (4x supersampled)."""
    scale = 4
    canvas_px = size * scale
    unit = canvas_px / 24.0
    width = max(2, int(round(stroke_width * unit)))
    rgba = _hex_to_rgba(color)

    img = Image.new("RGBA", (canvas_px, canvas_px), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    ops = ICON_SPECS.get(name, ICON_SPECS["monitor"])

    def pt(x: float, y: float) -> tuple[float, float]:
        return (x * unit, y * unit)

    def cap(x: float, y: float) -> None:
        r = width / 2.0
        cx, cy = x * unit, y * unit
        draw.ellipse((cx - r, cy - r, cx + r, cy + r), fill=rgba)

    for op in ops:
        kind = op[0]
        if kind == "line":
            _, x1, y1, x2, y2 = op
            draw.line([pt(x1, y1), pt(x2, y2)], fill=rgba, width=width)
            cap(x1, y1)
            cap(x2, y2)
        elif kind == "poly":
            _, points, closed = op
            scaled = [pt(x, y) for x, y in points]
            if closed and len(scaled) >= 3:
                scaled_loop = scaled + [scaled[0]]
                draw.line(scaled_loop, fill=rgba, width=width, joint="curve")
                for x, y in points:
                    cap(x, y)
            else:
                draw.line(scaled, fill=rgba, width=width, joint="curve")
                for x, y in points:
                    cap(x, y)
        elif kind == "rect":
            _, x1, y1, x2, y2, r = op
            draw.rounded_rectangle(
                [pt(x1, y1), pt(x2, y2)],
                radius=r * unit,
                outline=rgba,
                width=width,
            )
        elif kind == "circle":
            _, cx, cy, r = op
            draw.ellipse(
                [pt(cx - r, cy - r), pt(cx + r, cy + r)],
                outline=rgba,
                width=width,
            )
        elif kind == "fill_circle":
            _, cx, cy, r = op
            draw.ellipse([pt(cx - r, cy - r), pt(cx + r, cy + r)], fill=rgba)
        elif kind == "arc":
            _, x1, y1, x2, y2, start_deg, end_deg = op
            draw.arc(
                [pt(x1, y1), pt(x2, y2)],
                start=start_deg,
                end=end_deg,
                fill=rgba,
                width=width,
            )

    return img.resize((size, size), Image.Resampling.LANCZOS)


class IconLibrary:
    """Cached dual-theme CTkImage icon provider."""

    def __init__(self) -> None:
        self._cache: dict[tuple[str, int, str, str, float], ctk.CTkImage] = {}

    def get(
        self,
        name: str,
        size: int = 18,
        light_color: str = "#334155",
        dark_color: str = "#E2E8F0",
        stroke_width: float = 1.85,
    ) -> ctk.CTkImage:
        key = (name, size, light_color, dark_color, stroke_width)
        if key not in self._cache:
            light_img = render_vector_pil(name, size, light_color, stroke_width)
            dark_img = render_vector_pil(name, size, dark_color, stroke_width)
            self._cache[key] = ctk.CTkImage(
                light_image=light_img, dark_image=dark_img, size=(size, size)
            )
        return self._cache[key]

    def mono(
        self, name: str, size: int = 18, color: str = "#FFFFFF", stroke_width: float = 1.9
    ) -> ctk.CTkImage:
        return self.get(name, size=size, light_color=color, dark_color=color, stroke_width=stroke_width)


def export_svgs(output_dir: Path) -> None:
    """Export all geometric icon definitions as clean standalone SVG files."""
    output_dir.mkdir(parents=True, exist_ok=True)
    for name, ops in ICON_SPECS.items():
        elems: list[str] = []
        for op in ops:
            kind = op[0]
            if kind == "line":
                _, x1, y1, x2, y2 = op
                elems.append(f'  <line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}"/>')
            elif kind == "poly":
                _, pts, closed = op
                pstr = " ".join(f"{x},{y}" for x, y in pts)
                tag = "polygon" if closed else "polyline"
                elems.append(f'  <{tag} points="{pstr}"/>')
            elif kind == "rect":
                _, x1, y1, x2, y2, r = op
                elems.append(
                    f'  <rect x="{x1}" y="{y1}" width="{x2 - x1}" height="{y2 - y1}" rx="{r}"/>'
                )
            elif kind == "circle":
                _, cx, cy, r = op
                elems.append(f'  <circle cx="{cx}" cy="{cy}" r="{r}"/>')
            elif kind == "fill_circle":
                _, cx, cy, r = op
                elems.append(f'  <circle cx="{cx}" cy="{cy}" r="{r}" fill="currentColor" stroke="none"/>')
        svg = (
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" '
            'fill="none" stroke="currentColor" stroke-width="1.8" '
            'stroke-linecap="round" stroke-linejoin="round">\n'
            + "\n".join(elems)
            + "\n</svg>\n"
        )
        (output_dir / f"{name}.svg").write_text(svg, encoding="utf-8")
