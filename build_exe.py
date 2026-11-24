r"""Build script to compile DeskRemote into a single standalone Windows executable.

Produces ONE self-contained executable (`DeskRemote.exe`) directly in the project
root with Python, CustomTkinter, cryptography, pynput, mss, Pillow, psutil,
pyperclip, and DeskR.ico fully embedded — zero external folders or libraries needed.

Usage:
    .\.venv\Scripts\python.exe build_exe.py
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from deskremote.config import APP_ICON_FILENAME, APP_NAME, APP_VERSION

ROOT_DIR = Path(__file__).resolve().parent
ENTRY_SCRIPT = ROOT_DIR / "main.py"
OUTPUT_EXE = ROOT_DIR / f"{APP_NAME}.exe"


def _find_root_icon() -> Path:
    preferred = ROOT_DIR / APP_ICON_FILENAME
    if preferred.is_file():
        return preferred
    icos = sorted(ROOT_DIR.glob("*.ico"))
    if icos:
        return icos[0]
    raise FileNotFoundError(
        f"No se encontró ningún archivo .ico en la raíz del proyecto ({ROOT_DIR})."
    )


def _ensure_pyinstaller() -> None:
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print("[1/4] Instalando PyInstaller en el entorno actual...")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--upgrade", "pyinstaller"]
        )


def _write_windows_version_file(path: Path) -> None:
    parts = [int(p) for p in APP_VERSION.split(".")]
    while len(parts) < 4:
        parts.append(0)
    ver_tuple = tuple(parts[:4])
    ver_str = ".".join(str(p) for p in ver_tuple)

    content = f"""# UTF-8
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers={ver_tuple},
    prodvers={ver_tuple},
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo(
      [
        StringTable(
          '0C0A04B0',
          [
            StringStruct('CompanyName', 'DeskRemote'),
            StringStruct('FileDescription', 'DeskRemote — Escritorio Remoto Cifrado E2EE'),
            StringStruct('FileVersion', '{ver_str}'),
            StringStruct('InternalName', '{APP_NAME}'),
            StringStruct('OriginalFilename', '{APP_NAME}.exe'),
            StringStruct('ProductName', '{APP_NAME}'),
            StringStruct('ProductVersion', '{APP_VERSION}'),
          ]
        )
      ]
    ),
    VarFileInfo([VarStruct('Translation', [3082, 1200])])
  ]
)
"""
    path.write_text(content, encoding="utf-8")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest().upper()


def _verify_isolated_executable(exe_path: Path) -> None:
    """Copy the built .exe into a clean temp folder and run --smoke-test."""
    print("[4/4] Verificando ejecutable de forma aislada (sin Python ni dependencias externas)...")
    with tempfile.TemporaryDirectory(prefix="deskremote_verify_") as verify_dir:
        isolated_exe = Path(verify_dir) / exe_path.name
        shutil.copy2(exe_path, isolated_exe)

        env = os.environ.copy()
        env.pop("PYTHONPATH", None)
        env.pop("VIRTUAL_ENV", None)
        env.pop("PYTHONHOME", None)

        res = subprocess.run(
            [str(isolated_exe), "--smoke-test"],
            cwd=verify_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if res.returncode != 0:
            raise RuntimeError(
                f"La verificación aislada del .exe falló (código {res.returncode}):\n"
                f"STDOUT: {res.stdout}\nSTDERR: {res.stderr}"
            )

        # Ensure the executable did not leave stray folders/files beside itself
        remaining = [p.name for p in Path(verify_dir).iterdir()]
        if remaining != [exe_path.name]:
            raise RuntimeError(
                f"El ejecutable generó archivos adicionales junto a sí mismo: {remaining}"
            )


def build() -> None:
    if os.name != "nt":
        raise RuntimeError("Este script está diseñado para compilar ejecutables de Windows (.exe).")

    _ensure_pyinstaller()
    icon_path = _find_root_icon()
    print(f"[1/4] Usando icono: {icon_path.name} ({icon_path.stat().st_size:,} bytes)")

    with tempfile.TemporaryDirectory(prefix="deskremote_build_") as tmp:
        tmp_dir = Path(tmp)
        work_dir = tmp_dir / "work"
        dist_dir = tmp_dir / "dist"
        spec_dir = tmp_dir / "spec"
        ver_file = tmp_dir / "version_info.txt"
        _write_windows_version_file(ver_file)

        # PyInstaller --add-data syntax on Windows uses ';'
        add_data_icon = f"{icon_path};."

        # Bundle Python 3.15 abi3t compatibility shim (python3t.dll) + python3.dll
        # required by dual-ABI wheels such as cryptography 50+ on Python 3.15
        extra_binary_args: list[str] = []
        base_prefix = Path(sys.base_prefix)
        for dll_candidate in (
            base_prefix / "abi3t-compat" / "python3t.dll",
            base_prefix / "python3.dll",
            base_prefix / "vcruntime140.dll",
            base_prefix / "vcruntime140_1.dll",
        ):
            if dll_candidate.is_file():
                extra_binary_args.extend(["--add-binary", f"{dll_candidate};."])

        cmd = [
            sys.executable,
            "-m",
            "PyInstaller",
            "--onefile",
            "--windowed",
            "--clean",
            "--noconfirm",
            "--name",
            APP_NAME,
            "--icon",
            str(icon_path),
            "--version-file",
            str(ver_file),
            "--distpath",
            str(dist_dir),
            "--workpath",
            str(work_dir),
            "--specpath",
            str(spec_dir),
            "--add-data",
            add_data_icon,
            *extra_binary_args,
            # Full packages with data/binaries
            "--collect-all",
            "customtkinter",
            "--collect-all",
            "cryptography",
            "--collect-all",
            "psutil",
            # Submodules loaded dynamically at runtime
            "--collect-submodules",
            "pynput",
            "--collect-submodules",
            "mss",
            "--collect-submodules",
            "deskremote",
            # Explicit hidden imports for Windows backends & Tkinter/Pillow bridge
            "--hidden-import",
            "pynput.keyboard._win32",
            "--hidden-import",
            "pynput.mouse._win32",
            "--hidden-import",
            "_cffi_backend",
            "--hidden-import",
            "PIL._tkinter_finder",
            "--hidden-import",
            "PIL.ImageTk",
            "--hidden-import",
            "PIL.ImageGrab",
            "--hidden-import",
            "pyperclip",
            "--hidden-import",
            "darkdetect",
            # Exclude test frameworks to keep executable lean
            "--exclude-module",
            "pytest",
            "--exclude-module",
            "unittest",
            str(ENTRY_SCRIPT),
        ]

        print("[2/4] Compilando ejecutable único autocontenido con PyInstaller...")
        subprocess.check_call(cmd, cwd=str(ROOT_DIR))

        built_exe = dist_dir / f"{APP_NAME}.exe"
        if not built_exe.is_file():
            raise FileNotFoundError(f"PyInstaller no generó {built_exe}")

        print(f"[3/4] Colocando {OUTPUT_EXE.name} en la raíz y limpiando archivos temporales...")
        if OUTPUT_EXE.exists():
            OUTPUT_EXE.unlink()
        shutil.copy2(built_exe, OUTPUT_EXE)

    # All temporary build/work/spec/dist directories are now automatically removed!
    _verify_isolated_executable(OUTPUT_EXE)

    size_mb = OUTPUT_EXE.stat().st_size / (1024 * 1024)
    sha256 = _sha256_file(OUTPUT_EXE)
    print("\n" + "=" * 68)
    print(f"  COMPILACIÓN EXITOSA — {OUTPUT_EXE.name}")
    print("=" * 68)
    print(f"  Ruta   : {OUTPUT_EXE}")
    print(f"  Tamaño : {size_mb:.2f} MB (archivo único autocontenido)")
    print(f"  Icono  : {icon_path.name}")
    print(f"  SHA-256: {sha256}")
    print("=" * 68)


if __name__ == "__main__":
    build()
