"""DeskRemote — Entry point (supports source execution and standalone PyInstaller .exe)."""

from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path

from deskremote.ui.app import DeskRemoteApp
from deskremote.ui.icons import export_svgs


def _configure_windows_shell() -> None:
    """Enable Per-Monitor HiDPI and bind Windows taskbar icon to DeskRemote."""
    if os.name != "nt":
        return
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("DeskRemote.App.1")
    except Exception:
        pass
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)  # Per-Monitor DPI Aware
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


def _run_smoke_test() -> int:
    """Verify all bundled dependencies and UI initialize cleanly (used by build_exe.py)."""
    import mss
    import psutil
    import pyperclip
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from pynput.keyboard import Controller as KbCtrl
    from pynput.mouse import Controller as MsCtrl

    from deskremote.crypto.spake2 import Spake2Exchange

    # Verify crypto, capture, input, and process subsystems instantiate cleanly
    a = Spake2Exchange("A", "TEST1234")
    b = Spake2Exchange("B", "TEST1234")
    assert a.finish(b.start()) == b.finish(a.start())
    _ = AESGCM.generate_key(bit_length=256)
    with mss.MSS() as sct:
        assert len(sct.monitors) >= 1
    _ = KbCtrl()
    _ = MsCtrl()
    _ = psutil.cpu_count()
    _ = pyperclip.paste

    app = DeskRemoteApp()
    try:
        app.update_idletasks()
        for nav in ("guest", "direct", "security", "host"):
            app._select_nav(nav)
            app.update_idletasks()
    finally:
        app._on_app_close()
    return 0


def main() -> None:
    _configure_windows_shell()

    if "--smoke-test" in sys.argv:
        sys.exit(_run_smoke_test())

    # Only export standalone SVG files when running from source (never beside the .exe)
    if not getattr(sys, "frozen", False):
        assets_icons = Path(__file__).resolve().parent / "assets" / "icons"
        if not assets_icons.exists():
            try:
                export_svgs(assets_icons)
            except OSError:
                pass

    app = DeskRemoteApp()
    app.mainloop()


if __name__ == "__main__":
    main()
