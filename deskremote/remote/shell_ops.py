"""Remote shell execution, system telemetry, process manager, and power actions."""

from __future__ import annotations

import ctypes
import os
import platform
import subprocess
import time
from pathlib import Path
from typing import Any

import psutil


class RemoteShellExecutor:
    """Stateful remote command executor preserving working directory across calls."""

    def __init__(self) -> None:
        self.cwd = str(Path.home())

    def execute(self, command: str, timeout: float = 30.0) -> dict[str, Any]:
        cmd = command.strip()
        if not cmd:
            return {"stdout": "", "stderr": "", "returncode": 0, "cwd": self.cwd}

        # Handle simple `cd <dir>` directly so cwd persists seamlessly
        if cmd.lower() == "cd" or cmd.lower().startswith("cd "):
            arg = cmd[2:].strip().strip('"').strip("'")
            target = Path.home() if not arg else Path(arg)
            if not target.is_absolute():
                target = Path(self.cwd) / target
            try:
                resolved = target.resolve()
                if resolved.is_dir():
                    self.cwd = str(resolved)
                    return {
                        "stdout": f"Directorio actual: {self.cwd}\n",
                        "stderr": "",
                        "returncode": 0,
                        "cwd": self.cwd,
                    }
                return {
                    "stdout": "",
                    "stderr": f"Directorio no encontrado: {target}\n",
                    "returncode": 1,
                    "cwd": self.cwd,
                }
            except Exception as exc:
                return {"stdout": "", "stderr": f"{exc}\n", "returncode": 1, "cwd": self.cwd}

        creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        try:
            if os.name == "nt":
                full_cmd = [
                    "powershell",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    cmd,
                ]
                proc = subprocess.run(
                    full_cmd,
                    cwd=self.cwd,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=timeout,
                    creationflags=creationflags,
                )
            else:
                proc = subprocess.run(
                    cmd,
                    shell=True,
                    cwd=self.cwd,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=timeout,
                )
            return {
                "stdout": proc.stdout[:120000],
                "stderr": proc.stderr[:40000],
                "returncode": proc.returncode,
                "cwd": self.cwd,
            }
        except subprocess.TimeoutExpired:
            return {
                "stdout": "",
                "stderr": f"Tiempo de espera agotado ({int(timeout)}s).\n",
                "returncode": -1,
                "cwd": self.cwd,
            }
        except Exception as exc:
            return {"stdout": "", "stderr": f"{exc}\n", "returncode": -1, "cwd": self.cwd}


def collect_system_telemetry(max_procs: int = 35) -> dict[str, Any]:
    """Gather CPU, RAM, Disk, and top active processes from the Guest machine."""
    vm = psutil.virtual_memory()
    disk_root = "C:\\" if os.name == "nt" else "/"
    try:
        disk = psutil.disk_usage(disk_root)
        disk_pct = round(disk.percent, 1)
        disk_used_gb = round(disk.used / (1024**3), 1)
        disk_total_gb = round(disk.total / (1024**3), 1)
    except Exception:
        disk_pct, disk_used_gb, disk_total_gb = 0.0, 0.0, 0.0

    procs: list[dict[str, Any]] = []
    for p in psutil.process_iter(["pid", "name", "memory_info", "status"]):
        try:
            info = p.info
            mem_mb = round((info["memory_info"].rss if info["memory_info"] else 0) / (1024**2), 1)
            procs.append(
                {
                    "pid": info["pid"],
                    "name": info["name"] or "?",
                    "mem_mb": mem_mb,
                    "status": info["status"] or "",
                }
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    procs.sort(key=lambda x: x["mem_mb"], reverse=True)

    return {
        "hostname": platform.node(),
        "os": f"{platform.system()} {platform.release()}",
        "cpu_percent": round(psutil.cpu_percent(interval=None), 1),
        "cpu_cores": psutil.cpu_count(logical=True) or 1,
        "ram_percent": round(vm.percent, 1),
        "ram_used_gb": round(vm.used / (1024**3), 2),
        "ram_total_gb": round(vm.total / (1024**3), 2),
        "disk_percent": disk_pct,
        "disk_used_gb": disk_used_gb,
        "disk_total_gb": disk_total_gb,
        "uptime_min": int((time.time() - psutil.boot_time()) // 60),
        "processes": procs[:max_procs],
    }


def kill_process(pid: int) -> dict[str, Any]:
    """Terminate a process by PID on the Guest machine."""
    if pid == os.getpid():
        return {"ok": False, "error": "No se puede finalizar el proceso propio de DeskRemote."}
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        proc.terminate()
        try:
            proc.wait(timeout=2.0)
        except psutil.TimeoutExpired:
            proc.kill()
        return {"ok": True, "pid": pid, "name": name}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def perform_system_action(action: str) -> dict[str, Any]:
    """Execute system-level actions (lock, restart, shutdown)."""
    try:
        if action == "lock":
            if os.name == "nt":
                ctypes.windll.user32.LockWorkStation()
                return {"ok": True, "message": "Estación de trabajo bloqueada."}
            return {"ok": False, "error": "Bloqueo directo solo disponible en Windows."}
        if action == "restart":
            if os.name == "nt":
                subprocess.Popen(["shutdown", "/r", "/t", "5"])
            else:
                subprocess.Popen(["shutdown", "-r", "+0"])
            return {"ok": True, "message": "Reinicio programado en 5 segundos."}
        if action == "shutdown":
            if os.name == "nt":
                subprocess.Popen(["shutdown", "/s", "/t", "5"])
            else:
                subprocess.Popen(["shutdown", "-h", "+0"])
            return {"ok": True, "message": "Apagado programado en 5 segundos."}
        return {"ok": False, "error": f"Acción desconocida: {action}"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
