"""Application configuration, constants, security limits, and design palette."""

from __future__ import annotations

import os
import sys
from pathlib import Path

APP_NAME = "DeskRemote"
APP_VERSION = "1.1.0"
PROTOCOL_VERSION = 2
APP_ICON_FILENAME = "DeskR.ico"


def get_app_icon_path() -> Path | None:
    """Resolve the bundled or project-root .ico icon path (works frozen and from source)."""
    candidates: list[Path] = []
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        meipass = Path(sys._MEIPASS)  # type: ignore[attr-defined]
        candidates.append(meipass / APP_ICON_FILENAME)
        candidates.extend(sorted(meipass.glob("*.ico")))
    root_dir = Path(__file__).resolve().parent.parent
    candidates.append(root_dir / APP_ICON_FILENAME)
    candidates.extend(sorted(root_dir.glob("*.ico")))
    for p in candidates:
        if p.is_file():
            return p
    return None

# Persistent identity, TOFU trust store, and security audit directory
CONFIG_DIR = Path.home() / ".deskremote"
IDENTITY_KEY_FILE = CONFIG_DIR / "identity_ed25519.key"
TRUST_STORE_FILE = CONFIG_DIR / "known_peers.json"
SSH_KNOWN_HOSTS_FILE = CONFIG_DIR / "tunnel_known_hosts"
AUDIT_LOG_DIR = CONFIG_DIR / "logs"
AUDIT_LOG_FILE = AUDIT_LOG_DIR / "audit.log"

# Networking & Security defaults
DEFAULT_BIND_HOST = "0.0.0.0"
DEFAULT_PORT = 0  # Ephemeral OS-assigned port
BORE_DEFAULT_SERVER = "bore.pub"
BORE_CONTROL_PORT = 7835
SOCKET_TIMEOUT = 15.0
HANDSHAKE_TIMEOUT = 8.0
HEARTBEAT_INTERVAL = 5.0
MAX_PACKET_SIZE = 32 * 1024 * 1024  # 32 MiB ceiling per encrypted frame
FILE_CHUNK_SIZE = 256 * 1024  # 256 KiB chunks for E2EE file transfers

# Hardening limits
PIN_LENGTH = 8  # 8 chars grouped as XXXX-XXXX (~39.6 bits + SPAKE2 + scrypt)
MAX_AUTH_FAILURES = 3  # Auto-rotate PIN after 3 consecutive failures
MAX_CONCURRENT_HANDSHAKES = 4  # Anti-DoS concurrency semaphore
MAX_UPLOAD_FILE_BYTES = 2 * 1024 * 1024 * 1024  # 2 GiB safety ceiling per upload
MIN_FREE_DISK_MARGIN = 64 * 1024 * 1024  # Keep at least 64 MiB free disk space
UPNP_LEASE_SECONDS = 1800  # 30-minute lease (reduced exposure on sudden crash)

# Screen streaming presets (quality, max_fps, scale_factor)
QUALITY_PRESETS: dict[str, dict[str, float | int]] = {
    "Baja (Ahorro)": {"jpeg_quality": 40, "fps": 12, "scale": 0.65},
    "Balanceada": {"jpeg_quality": 62, "fps": 20, "scale": 0.85},
    "Alta (Nítida)": {"jpeg_quality": 78, "fps": 24, "scale": 1.0},
    "Ultra": {"jpeg_quality": 90, "fps": 30, "scale": 1.0},
}

# Minimalist Dual-Theme Palette (Light, Dark) for CustomTkinter
COLORS = {
    "bg": ("#F4F6FA", "#0B0F17"),
    "sidebar": ("#FFFFFF", "#101622"),
    "surface": ("#FFFFFF", "#151D2E"),
    "surface_alt": ("#EEF2F7", "#1C263B"),
    "surface_hover": ("#E2E8F0", "#24314A"),
    "border": ("#D8E0EC", "#233046"),
    "text": ("#0F172A", "#F8FAFC"),
    "text_secondary": ("#475569", "#94A3B8"),
    "text_muted": ("#64748B", "#64748B"),
    "accent": ("#E11D48", "#F43F5E"),
    "accent_hover": ("#BE123C", "#E11D48"),
    "accent_soft": ("#FFE4E6", "#2E1420"),
    "success": ("#059669", "#10B981"),
    "success_soft": ("#D1FAE5", "#0E2A22"),
    "warning": ("#D97706", "#F59E0B"),
    "warning_soft": ("#FEF3C7", "#2B2210"),
    "danger": ("#DC2626", "#EF4444"),
    "danger_hover": ("#B91C1C", "#DC2626"),
    "info": ("#2563EB", "#3B82F6"),
    "info_soft": ("#DBEAFE", "#13223D"),
}

# Font family helper (clean modern typography on Windows/macOS/Linux)
FONT_FAMILY = "Segoe UI" if os.name == "nt" else "SF Pro Display"
MONO_FONT = "Cascadia Code" if os.name == "nt" else "Menlo"
