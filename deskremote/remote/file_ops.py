"""Remote File Manager operations executed on the Guest system."""

from __future__ import annotations

import datetime
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import psutil


def get_quick_paths() -> dict[str, str]:
    """Return common user directories and mounted drives."""
    home = Path.home()
    quick: dict[str, str] = {"Usuario": str(home)}
    for label, sub in [
        ("Escritorio", home / "Desktop"),
        ("Documentos", home / "Documents"),
        ("Descargas", home / "Downloads"),
    ]:
        if sub.exists():
            quick[label] = str(sub)
    return quick


def list_drives() -> list[str]:
    """List available filesystem roots / drive letters."""
    drives: list[str] = []
    try:
        for part in psutil.disk_partitions(all=False):
            if part.mountpoint and part.mountpoint not in drives:
                drives.append(part.mountpoint)
    except Exception:
        pass
    if not drives:
        drives = ["C:\\"] if os.name == "nt" else ["/"]
    return drives


def list_directory(path_str: str | None = None) -> dict[str, Any]:
    """List files and folders inside the requested path."""
    target = Path(path_str).expanduser() if path_str else Path.home()
    try:
        target = target.resolve()
    except OSError:
        pass

    if not target.exists():
        return {"ok": False, "error": f"La ruta no existe: {target}"}
    if not target.is_dir():
        return {"ok": False, "error": f"No es una carpeta: {target}"}

    entries: list[dict[str, Any]] = []
    try:
        with os.scandir(target) as it:
            for entry in it:
                try:
                    stat = entry.stat(follow_symlinks=False)
                    is_dir = entry.is_dir(follow_symlinks=False)
                    mtime = datetime.datetime.fromtimestamp(stat.st_mtime).strftime(
                        "%Y-%m-%d %H:%M"
                    )
                    entries.append(
                        {
                            "name": entry.name,
                            "path": entry.path,
                            "is_dir": is_dir,
                            "size": 0 if is_dir else int(stat.st_size),
                            "modified": mtime,
                        }
                    )
                except OSError:
                    continue
    except PermissionError:
        return {"ok": False, "error": f"Permiso denegado en: {target}"}
    except OSError as exc:
        return {"ok": False, "error": str(exc)}

    entries.sort(key=lambda e: (not e["is_dir"], e["name"].lower()))
    parent = str(target.parent) if target.parent != target else str(target)
    return {
        "ok": True,
        "path": str(target),
        "parent": parent,
        "drives": list_drives(),
        "quick_paths": get_quick_paths(),
        "entries": entries,
    }


def make_directory(parent_path: str, folder_name: str) -> dict[str, Any]:
    try:
        new_dir = Path(parent_path) / folder_name.strip()
        new_dir.mkdir(parents=True, exist_ok=False)
        return {"ok": True, "path": str(new_dir)}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def delete_path(target_path: str) -> dict[str, Any]:
    try:
        p = Path(target_path)
        if not p.exists():
            return {"ok": False, "error": "Elemento no encontrado."}
        if p.is_dir():
            shutil.rmtree(p)
        else:
            p.unlink()
        return {"ok": True, "deleted": str(p)}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def rename_path(target_path: str, new_name: str) -> dict[str, Any]:
    try:
        p = Path(target_path)
        dst = p.parent / new_name.strip()
        p.rename(dst)
        return {"ok": True, "path": str(dst)}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def open_remote_file(target_path: str) -> dict[str, Any]:
    """Launch/open a file on the Guest OS with its default application."""
    try:
        p = Path(target_path)
        if not p.exists():
            return {"ok": False, "error": "Archivo no encontrado."}
        if os.name == "nt":
            os.startfile(str(p))  # type: ignore[attr-defined]
        else:
            opener = "open" if os.uname().sysname == "Darwin" else "xdg-open"
            subprocess.Popen([opener, str(p)])
        return {"ok": True, "opened": str(p)}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
