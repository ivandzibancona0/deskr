"""Persistent rotating security audit log (administrative & security events only).

Logs connection handshakes, auth rejections, TOFU alerts, permission toggles,
remote shell commands, file operations, process kills, and power actions.
Never logs screen frames or mouse/keyboard streams (zero performance impact).
"""

from __future__ import annotations

import logging
import os
import threading
from logging.handlers import RotatingFileHandler
from pathlib import Path

from deskremote.config import AUDIT_LOG_FILE


class SecurityAuditLogger:
    """Thread-safe rotating file logger for DeskRemote security events."""

    def __init__(self, log_path: Path = AUDIT_LOG_FILE) -> None:
        self.log_path = log_path
        self._lock = threading.Lock()
        self._logger = logging.getLogger(f"deskremote.audit.{id(self)}")
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False

        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            handler = RotatingFileHandler(
                self.log_path,
                maxBytes=5 * 1024 * 1024,
                backupCount=3,
                encoding="utf-8",
            )
            fmt = logging.Formatter(
                "%(asctime)s | %(levelname)-7s | %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S%z",
            )
            handler.setFormatter(fmt)
            self._logger.addHandler(handler)
            if os.name != "nt" and self.log_path.exists():
                os.chmod(self.log_path, 0o600)
        except OSError:
            pass

    def record(self, category: str, message: str, level: str = "INFO") -> None:
        line = f"[{category.upper()}] {message}"
        with self._lock:
            lvl = getattr(logging, level.upper(), logging.INFO)
            self._logger.log(lvl, line)

    def close(self) -> None:
        with self._lock:
            for h in list(self._logger.handlers):
                try:
                    h.close()
                except Exception:
                    pass
                self._logger.removeHandler(h)


_GLOBAL_AUDIT: SecurityAuditLogger | None = None
_AUDIT_INIT_LOCK = threading.Lock()


def get_audit_logger() -> SecurityAuditLogger:
    """Return the singleton persistent SecurityAuditLogger."""
    global _GLOBAL_AUDIT
    with _AUDIT_INIT_LOCK:
        if _GLOBAL_AUDIT is None:
            _GLOBAL_AUDIT = SecurityAuditLogger()
        return _GLOBAL_AUDIT
