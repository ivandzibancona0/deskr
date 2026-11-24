"""Host Remote Control Studio window (Full access to the connected Guest)."""

from __future__ import annotations

import base64
import hashlib
import math
import queue
import secrets
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog
from typing import Any, Callable

import customtkinter as ctk
import pyperclip
from PIL import Image, ImageTk

from deskremote.config import (
    COLORS,
    FILE_CHUNK_SIZE,
    FONT_FAMILY,
    MONO_FONT,
    QUALITY_PRESETS,
    get_app_icon_path,
)
from deskremote.crypto.e2ee import SecureChannel
from deskremote.network.protocol import (
    FileChunkPacket,
    PacketType,
    ScreenFramePacket,
    recv_packet,
    send_file_chunk,
    send_json,
)
from deskremote.remote.screen import FrameCompositor
from deskremote.ui.icons import IconLibrary


def _human_size(num_bytes: int) -> str:
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024.0:
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} TB"


class RemoteControlWindow(ctk.CTkToplevel):
    """Full-access minimalist control studio opened on the Host for an active Guest."""

    def __init__(
        self,
        master: ctk.CTk,
        channel: SecureChannel,
        icons: IconLibrary,
        on_closed: Callable[[], None] | None = None,
    ) -> None:
        super().__init__(master)
        self.channel = channel
        self.icons = icons
        self.on_closed = on_closed

        self.title(
            f"DeskRemote Studio — {channel.info.peer_name} "
            f"[{channel.info.session_fingerprint}]"
        )
        self.geometry("1260x780")
        self.minsize(980, 620)
        self.configure(fg_color=COLORS["bg"])
        ico = get_app_icon_path()
        if ico is not None:
            self.after(250, lambda p=str(ico): self._set_icon_safe(p))

        self._stop = threading.Event()
        self._compositor = FrameCompositor()
        self._ui_queue: queue.Queue[tuple[str, Any]] = queue.Queue()

        # Screen canvas rendering state
        self._tk_image: ImageTk.PhotoImage | None = None
        self._canvas_img_id: int | None = None
        self._render_rect: tuple[int, int, int, int] = (0, 0, 1, 1)  # x, y, w, h
        self._last_move_ts = 0.0
        self._frame_count = 0
        self._fps_ts = time.monotonic()
        self._current_fps = 0.0
        self._last_bytes_recv = 0
        self._last_frame_kind = "—"
        self._remote_res = "—"

        # Remote state
        self._monitors: list[dict[str, Any]] = []
        self._current_dir: str = ""
        self._selected_entry: dict[str, Any] | None = None
        self._downloads: dict[str, dict[str, Any]] = {}
        self._pending_uploads: dict[str, dict[str, Any]] = {}
        self._cmd_history: list[str] = []
        self._cmd_hist_idx = -1
        self._active_tab = "screen"

        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self.close_session)

        # Start encrypted receive worker
        self._recv_thread = threading.Thread(
            target=self._recv_loop, name="HostStudioRecv", daemon=True
        )
        self._recv_thread.start()

        # Poll UI queue smoothly at ~60Hz
        self.after(16, self._process_ui_queue)
        self.after(1000, self._update_stats_loop)

    def _set_icon_safe(self, ico_path: str) -> None:
        try:
            self.iconbitmap(ico_path)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # UI Construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        # Top minimalist toolbar
        topbar = ctk.CTkFrame(
            self,
            height=56,
            corner_radius=0,
            fg_color=COLORS["sidebar"],
            border_width=0,
        )
        topbar.pack(side="top", fill="x")
        topbar.pack_propagate(False)

        # Left: Peer Identity + E2EE Badge
        left = ctk.CTkFrame(topbar, fg_color="transparent")
        left.pack(side="left", padx=14, pady=8)

        ctk.CTkLabel(
            left,
            text="",
            image=self.icons.mono("shield_lock", 18, "#10B981"),
        ).pack(side="left", padx=(0, 8))

        id_stack = ctk.CTkFrame(left, fg_color="transparent")
        id_stack.pack(side="left")

        ctk.CTkLabel(
            id_stack,
            text=self.channel.info.peer_name,
            font=(FONT_FAMILY, 13, "bold"),
            text_color=COLORS["text"],
        ).pack(anchor="w")

        ctk.CTkLabel(
            id_stack,
            text=f"E2EE AES-256-GCM • {self.channel.info.session_fingerprint}",
            font=(MONO_FONT, 10),
            text_color=COLORS["success"],
        ).pack(anchor="w")

        # Center: Segmented Tab Bar
        tabs_frame = ctk.CTkFrame(
            topbar,
            fg_color=COLORS["surface_alt"],
            corner_radius=10,
            height=36,
        )
        tabs_frame.pack(side="left", padx=20, pady=10)

        self._tab_buttons: dict[str, ctk.CTkButton] = {}
        tab_defs = [
            ("screen", "Escritorio", "monitor"),
            ("files", "Archivos", "folder"),
            ("shell", "Terminal", "terminal"),
            ("system", "Sistema", "activity"),
            ("chat", "Chat", "message"),
        ]
        for key, label, icon_name in tab_defs:
            btn = ctk.CTkButton(
                tabs_frame,
                text=label,
                image=self.icons.get(icon_name, 15),
                compound="left",
                width=96,
                height=30,
                corner_radius=8,
                font=(FONT_FAMILY, 12, "bold"),
                fg_color="transparent",
                text_color=COLORS["text_secondary"],
                hover_color=COLORS["surface_hover"],
                command=lambda k=key: self._switch_tab(k),
            )
            btn.pack(side="left", padx=3, pady=3)
            self._tab_buttons[key] = btn

        # Right: Monitor, Quality, Quick Actions, Disconnect
        right = ctk.CTkFrame(topbar, fg_color="transparent")
        right.pack(side="right", padx=12, pady=8)

        self._monitor_var = ctk.StringVar(value="Monitor 1")
        self._monitor_menu = ctk.CTkOptionMenu(
            right,
            variable=self._monitor_var,
            values=["Monitor 1"],
            width=128,
            height=30,
            corner_radius=8,
            font=(FONT_FAMILY, 11),
            fg_color=COLORS["surface_alt"],
            button_color=COLORS["surface_hover"],
            button_hover_color=COLORS["border"],
            text_color=COLORS["text"],
            command=self._on_monitor_change,
        )
        self._monitor_menu.pack(side="left", padx=4)

        self._quality_var = ctk.StringVar(value="Balanceada")
        self._quality_menu = ctk.CTkOptionMenu(
            right,
            variable=self._quality_var,
            values=list(QUALITY_PRESETS.keys()),
            width=118,
            height=30,
            corner_radius=8,
            font=(FONT_FAMILY, 11),
            fg_color=COLORS["surface_alt"],
            button_color=COLORS["surface_hover"],
            button_hover_color=COLORS["border"],
            text_color=COLORS["text"],
            command=self._on_quality_change,
        )
        self._quality_menu.pack(side="left", padx=4)

        # Shortcuts dropdown button
        self._shortcut_var = ctk.StringVar(value="Atajos")
        shortcut_menu = ctk.CTkOptionMenu(
            right,
            variable=self._shortcut_var,
            values=[
                "Win (Inicio)",
                "Alt + Tab",
                "Ctrl + Shift + Esc",
                "Win + R (Ejecutar)",
                "Win + D (Escritorio)",
                "Win + E (Explorador)",
                "Alt + F4",
                "Bloquear PC (Win+L)",
            ],
            width=110,
            height=30,
            corner_radius=8,
            font=(FONT_FAMILY, 11),
            fg_color=COLORS["surface_alt"],
            button_color=COLORS["surface_hover"],
            text_color=COLORS["text"],
            command=self._on_shortcut_selected,
        )
        shortcut_menu.pack(side="left", padx=4)

        # Clipboard send/get & Screenshot
        ctk.CTkButton(
            right,
            text="",
            image=self.icons.get("clipboard", 16),
            width=32,
            height=30,
            corner_radius=8,
            fg_color=COLORS["surface_alt"],
            hover_color=COLORS["surface_hover"],
            command=self._open_clipboard_menu,
        ).pack(side="left", padx=3)

        ctk.CTkButton(
            right,
            text="",
            image=self.icons.get("camera", 16),
            width=32,
            height=30,
            corner_radius=8,
            fg_color=COLORS["surface_alt"],
            hover_color=COLORS["surface_hover"],
            command=self._request_screenshot,
        ).pack(side="left", padx=3)

        ctk.CTkButton(
            right,
            text="Salir",
            image=self.icons.mono("stop", 14, "#FFFFFF"),
            compound="left",
            width=74,
            height=30,
            corner_radius=8,
            font=(FONT_FAMILY, 12, "bold"),
            fg_color=COLORS["danger"],
            hover_color=COLORS["danger_hover"],
            command=self.close_session,
        ).pack(side="left", padx=(6, 0))

        # Divider
        ctk.CTkFrame(self, height=1, fg_color=COLORS["border"]).pack(fill="x")

        # Main workspace container
        self._body = ctk.CTkFrame(self, fg_color=COLORS["bg"], corner_radius=0)
        self._body.pack(fill="both", expand=True)

        self._views: dict[str, ctk.CTkFrame] = {
            "screen": self._build_screen_view(self._body),
            "files": self._build_files_view(self._body),
            "shell": self._build_shell_view(self._body),
            "system": self._build_system_view(self._body),
            "chat": self._build_chat_view(self._body),
        }

        # Bottom minimal telemetry bar
        status_bar = ctk.CTkFrame(
            self, height=28, corner_radius=0, fg_color=COLORS["sidebar"]
        )
        status_bar.pack(side="bottom", fill="x")
        status_bar.pack_propagate(False)

        self._status_left = ctk.CTkLabel(
            status_bar,
            text="Conectado • Esperando primer fotograma...",
            font=(FONT_FAMILY, 11),
            text_color=COLORS["text_secondary"],
        )
        self._status_left.pack(side="left", padx=12)

        self._status_right = ctk.CTkLabel(
            status_bar,
            text="0 FPS • 0 KB/s • E2EE Activo",
            font=(MONO_FONT, 10),
            text_color=COLORS["text_muted"],
        )
        self._status_right.pack(side="right", padx=12)

        self._switch_tab("screen")

    def _build_screen_view(self, parent: ctk.CTkFrame) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(parent, fg_color="#05070B", corner_radius=0)
        self._canvas = tk.Canvas(
            frame,
            bg="#05070B",
            highlightthickness=0,
            cursor="crosshair",
        )
        self._canvas.pack(fill="both", expand=True)

        # Mouse bindings
        self._canvas.bind("<Motion>", self._on_mouse_move)
        self._canvas.bind("<ButtonPress-1>", lambda e: self._on_mouse_btn(e, "left", True))
        self._canvas.bind("<ButtonRelease-1>", lambda e: self._on_mouse_btn(e, "left", False))
        self._canvas.bind("<Double-Button-1>", lambda e: self._on_mouse_dbl(e, "left"))
        self._canvas.bind("<ButtonPress-3>", lambda e: self._on_mouse_btn(e, "right", True))
        self._canvas.bind("<ButtonRelease-3>", lambda e: self._on_mouse_btn(e, "right", False))
        self._canvas.bind("<ButtonPress-2>", lambda e: self._on_mouse_btn(e, "middle", True))
        self._canvas.bind("<ButtonRelease-2>", lambda e: self._on_mouse_btn(e, "middle", False))
        self._canvas.bind("<MouseWheel>", self._on_mouse_wheel)
        self._canvas.bind("<Button-4>", lambda e: self._send_scroll(0, 3))
        self._canvas.bind("<Button-5>", lambda e: self._send_scroll(0, -3))

        # Keyboard bindings (when screen canvas has focus)
        self._canvas.bind("<KeyPress>", self._on_key_down)
        self._canvas.bind("<KeyRelease>", self._on_key_up)
        self._canvas.bind("<Configure>", self._on_canvas_resize)
        return frame

    def _build_files_view(self, parent: ctk.CTkFrame) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(parent, fg_color=COLORS["bg"], corner_radius=0)

        # Path & action toolbar
        bar = ctk.CTkFrame(frame, fg_color=COLORS["surface"], corner_radius=12)
        bar.pack(fill="x", padx=16, pady=(14, 8))

        ctk.CTkButton(
            bar,
            text="",
            image=self.icons.get("arrow_up", 16),
            width=36,
            height=34,
            corner_radius=8,
            fg_color=COLORS["surface_alt"],
            hover_color=COLORS["surface_hover"],
            command=self._files_go_up,
        ).pack(side="left", padx=(10, 4), pady=8)

        self._path_entry = ctk.CTkEntry(
            bar,
            placeholder_text="Ruta en el equipo huésped...",
            height=34,
            corner_radius=8,
            font=(MONO_FONT, 12),
            fg_color=COLORS["surface_alt"],
            border_color=COLORS["border"],
        )
        self._path_entry.pack(side="left", fill="x", expand=True, padx=4, pady=8)
        self._path_entry.bind("<Return>", lambda e: self._request_list_dir(self._path_entry.get()))

        ctk.CTkButton(
            bar,
            text="",
            image=self.icons.get("refresh", 15),
            width=36,
            height=34,
            corner_radius=8,
            fg_color=COLORS["surface_alt"],
            hover_color=COLORS["surface_hover"],
            command=lambda: self._request_list_dir(self._current_dir or None),
        ).pack(side="left", padx=4, pady=8)

        ctk.CTkButton(
            bar,
            text="Subir",
            image=self.icons.mono("upload", 15, "#FFFFFF"),
            compound="left",
            width=92,
            height=34,
            corner_radius=8,
            font=(FONT_FAMILY, 12, "bold"),
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            command=self._upload_file_to_guest,
        ).pack(side="left", padx=4, pady=8)

        ctk.CTkButton(
            bar,
            text="Descargar",
            image=self.icons.get("download", 15),
            compound="left",
            width=106,
            height=34,
            corner_radius=8,
            font=(FONT_FAMILY, 12),
            fg_color=COLORS["surface_alt"],
            hover_color=COLORS["surface_hover"],
            text_color=COLORS["text"],
            command=self._download_selected_file,
        ).pack(side="left", padx=4, pady=8)

        ctk.CTkButton(
            bar,
            text="Carpeta",
            image=self.icons.get("plus", 15),
            compound="left",
            width=90,
            height=34,
            corner_radius=8,
            font=(FONT_FAMILY, 12),
            fg_color=COLORS["surface_alt"],
            hover_color=COLORS["surface_hover"],
            text_color=COLORS["text"],
            command=self._create_remote_folder,
        ).pack(side="left", padx=4, pady=8)

        ctk.CTkButton(
            bar,
            text="",
            image=self.icons.mono("trash", 15, "#EF4444"),
            width=36,
            height=34,
            corner_radius=8,
            fg_color=COLORS["surface_alt"],
            hover_color=COLORS["surface_hover"],
            command=self._delete_selected_remote,
        ).pack(side="left", padx=(4, 10), pady=8)

        # Quick paths + drives strip
        self._quick_strip = ctk.CTkFrame(frame, fg_color="transparent")
        self._quick_strip.pack(fill="x", padx=16, pady=(0, 6))

        # Transfer progress bar
        self._transfer_label = ctk.CTkLabel(
            frame,
            text="",
            font=(FONT_FAMILY, 11),
            text_color=COLORS["text_secondary"],
        )
        self._transfer_label.pack(anchor="w", padx=20)

        # Directory listing
        self._file_list = ctk.CTkScrollableFrame(
            frame,
            fg_color=COLORS["surface"],
            corner_radius=12,
            border_width=1,
            border_color=COLORS["border"],
        )
        self._file_list.pack(fill="both", expand=True, padx=16, pady=(4, 14))
        self._file_rows: list[ctk.CTkFrame] = []
        return frame

    def _build_shell_view(self, parent: ctk.CTkFrame) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(parent, fg_color=COLORS["bg"], corner_radius=0)

        header = ctk.CTkFrame(frame, fg_color=COLORS["surface"], corner_radius=12)
        header.pack(fill="x", padx=16, pady=(14, 8))

        ctk.CTkLabel(
            header,
            text="Terminal Remota Cifrada (PowerShell / Bash en el Huésped)",
            image=self.icons.get("terminal", 17),
            compound="left",
            padx=8,
            font=(FONT_FAMILY, 13, "bold"),
            text_color=COLORS["text"],
        ).pack(side="left", padx=14, pady=10)

        self._shell_cwd_lbl = ctk.CTkLabel(
            header,
            text="cwd: —",
            font=(MONO_FONT, 11),
            text_color=COLORS["text_secondary"],
        )
        self._shell_cwd_lbl.pack(side="right", padx=14)

        self._shell_output = ctk.CTkTextbox(
            frame,
            font=(MONO_FONT, 12),
            fg_color="#090D14",
            text_color="#E2E8F0",
            corner_radius=12,
            border_width=1,
            border_color=COLORS["border"],
        )
        self._shell_output.pack(fill="both", expand=True, padx=16, pady=(0, 8))
        self._shell_output.insert(
            "end",
            "DeskRemote Terminal E2EE — Escribe cualquier comando para ejecutarlo en el sistema huésped.\n\n",
        )
        self._shell_output.configure(state="disabled")

        input_bar = ctk.CTkFrame(frame, fg_color=COLORS["surface"], corner_radius=12)
        input_bar.pack(fill="x", padx=16, pady=(0, 14))

        ctk.CTkLabel(
            input_bar,
            text="❯",
            font=(MONO_FONT, 15, "bold"),
            text_color=COLORS["accent"],
        ).pack(side="left", padx=(14, 6), pady=10)

        self._shell_entry = ctk.CTkEntry(
            input_bar,
            placeholder_text="Ej: whoami, ipconfig, dir, Get-Process...",
            height=36,
            corner_radius=8,
            font=(MONO_FONT, 12),
            fg_color=COLORS["surface_alt"],
            border_color=COLORS["border"],
        )
        self._shell_entry.pack(side="left", fill="x", expand=True, padx=4, pady=8)
        self._shell_entry.bind("<Return>", self._send_shell_command)
        self._shell_entry.bind("<Up>", self._shell_hist_prev)
        self._shell_entry.bind("<Down>", self._shell_hist_next)

        ctk.CTkButton(
            input_bar,
            text="Ejecutar",
            width=96,
            height=36,
            corner_radius=8,
            font=(FONT_FAMILY, 12, "bold"),
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            command=self._send_shell_command,
        ).pack(side="right", padx=10, pady=8)
        return frame

    def _build_system_view(self, parent: ctk.CTkFrame) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(parent, fg_color=COLORS["bg"], corner_radius=0)

        top = ctk.CTkFrame(frame, fg_color="transparent")
        top.pack(fill="x", padx=16, pady=(14, 10))

        # Metric cards
        self._cpu_lbl, self._cpu_bar = self._make_metric_card(top, "CPU")
        self._ram_lbl, self._ram_bar = self._make_metric_card(top, "Memoria RAM")
        self._disk_lbl, self._disk_bar = self._make_metric_card(top, "Disco Principal")

        # Power & System Control Strip
        ctrl = ctk.CTkFrame(frame, fg_color=COLORS["surface"], corner_radius=12)
        ctrl.pack(fill="x", padx=16, pady=(0, 10))

        ctk.CTkButton(
            ctrl,
            text="Actualizar Telemetría",
            image=self.icons.get("refresh", 15),
            compound="left",
            height=34,
            corner_radius=8,
            fg_color=COLORS["surface_alt"],
            hover_color=COLORS["surface_hover"],
            text_color=COLORS["text"],
            command=self._request_telemetry,
        ).pack(side="left", padx=10, pady=10)

        ctk.CTkButton(
            ctrl,
            text="Bloquear Pantalla",
            image=self.icons.get("lock", 15),
            compound="left",
            height=34,
            corner_radius=8,
            fg_color=COLORS["surface_alt"],
            hover_color=COLORS["surface_hover"],
            text_color=COLORS["text"],
            command=lambda: self._confirm_sys_action("lock", "bloquear la pantalla del huésped"),
        ).pack(side="left", padx=4, pady=10)

        ctk.CTkButton(
            ctrl,
            text="Reiniciar Huésped",
            image=self.icons.mono("power", 15, "#F59E0B"),
            compound="left",
            height=34,
            corner_radius=8,
            fg_color=COLORS["warning_soft"],
            hover_color=COLORS["surface_hover"],
            text_color=COLORS["warning"],
            command=lambda: self._confirm_sys_action("restart", "REINICIAR el equipo huésped"),
        ).pack(side="right", padx=6, pady=10)

        ctk.CTkButton(
            ctrl,
            text="Apagar Huésped",
            image=self.icons.mono("power", 15, "#FFFFFF"),
            compound="left",
            height=34,
            corner_radius=8,
            fg_color=COLORS["danger"],
            hover_color=COLORS["danger_hover"],
            command=lambda: self._confirm_sys_action("shutdown", "APAGAR el equipo huésped"),
        ).pack(side="right", padx=(6, 10), pady=10)

        # Processes list
        self._proc_list = ctk.CTkScrollableFrame(
            frame,
            label_text="Procesos Activos del Huésped (ordenados por memoria)",
            label_font=(FONT_FAMILY, 12, "bold"),
            fg_color=COLORS["surface"],
            corner_radius=12,
            border_width=1,
            border_color=COLORS["border"],
        )
        self._proc_list.pack(fill="both", expand=True, padx=16, pady=(0, 14))
        return frame

    def _make_metric_card(
        self, parent: ctk.CTkFrame, title: str
    ) -> tuple[ctk.CTkLabel, ctk.CTkProgressBar]:
        card = ctk.CTkFrame(
            parent,
            fg_color=COLORS["surface"],
            corner_radius=12,
            border_width=1,
            border_color=COLORS["border"],
        )
        card.pack(side="left", fill="x", expand=True, padx=6)
        ctk.CTkLabel(
            card, text=title, font=(FONT_FAMILY, 12), text_color=COLORS["text_secondary"]
        ).pack(anchor="w", padx=14, pady=(12, 2))
        val = ctk.CTkLabel(
            card, text="—", font=(FONT_FAMILY, 18, "bold"), text_color=COLORS["text"]
        )
        val.pack(anchor="w", padx=14, pady=(0, 6))
        bar = ctk.CTkProgressBar(
            card,
            height=6,
            corner_radius=4,
            progress_color=COLORS["accent"],
            fg_color=COLORS["surface_alt"],
        )
        bar.set(0)
        bar.pack(fill="x", padx=14, pady=(0, 12))
        return val, bar

    def _build_chat_view(self, parent: ctk.CTkFrame) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(parent, fg_color=COLORS["bg"], corner_radius=0)

        self._chat_box = ctk.CTkTextbox(
            frame,
            font=(FONT_FAMILY, 13),
            fg_color=COLORS["surface"],
            text_color=COLORS["text"],
            corner_radius=12,
            border_width=1,
            border_color=COLORS["border"],
        )
        self._chat_box.pack(fill="both", expand=True, padx=16, pady=(14, 8))
        self._chat_box.insert("end", "Chat cifrado de extremo a extremo (AES-256-GCM).\n\n")
        self._chat_box.configure(state="disabled")

        bar = ctk.CTkFrame(frame, fg_color=COLORS["surface"], corner_radius=12)
        bar.pack(fill="x", padx=16, pady=(0, 14))

        self._chat_entry = ctk.CTkEntry(
            bar,
            placeholder_text="Escribe un mensaje cifrado al huésped...",
            height=38,
            corner_radius=8,
            fg_color=COLORS["surface_alt"],
            border_color=COLORS["border"],
        )
        self._chat_entry.pack(side="left", fill="x", expand=True, padx=10, pady=8)
        self._chat_entry.bind("<Return>", self._send_chat)

        ctk.CTkButton(
            bar,
            text="Enviar",
            width=90,
            height=38,
            corner_radius=8,
            font=(FONT_FAMILY, 12, "bold"),
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            command=self._send_chat,
        ).pack(side="right", padx=(0, 10), pady=8)
        return frame

    # ------------------------------------------------------------------
    # Navigation & Toolbar Controls
    # ------------------------------------------------------------------

    def _switch_tab(self, tab_key: str) -> None:
        self._active_tab = tab_key
        for k, view in self._views.items():
            if k == tab_key:
                view.pack(fill="both", expand=True)
            else:
                view.pack_forget()

        for k, btn in self._tab_buttons.items():
            if k == tab_key:
                btn.configure(fg_color=COLORS["accent"], text_color="#FFFFFF")
            else:
                btn.configure(fg_color="transparent", text_color=COLORS["text_secondary"])

        if tab_key == "files" and not self._current_dir:
            self._request_list_dir(None)
        elif tab_key == "system":
            self._request_telemetry()
        elif tab_key == "screen":
            self._canvas.focus_set()

    def _on_monitor_change(self, label: str) -> None:
        idx = 1
        for m in self._monitors:
            if m["name"] == label:
                idx = m["index"]
                break
        self._safe_send_json(
            PacketType.SCREEN_CONFIG, {"monitor_idx": idx, "force_keyframe": True}
        )

    def _on_quality_change(self, preset_name: str) -> None:
        preset = QUALITY_PRESETS.get(preset_name)
        if not preset:
            return
        self._safe_send_json(
            PacketType.SCREEN_CONFIG,
            {
                "jpeg_quality": preset["jpeg_quality"],
                "fps": preset["fps"],
                "scale": preset["scale"],
                "force_keyframe": True,
            },
        )

    def _on_shortcut_selected(self, choice: str) -> None:
        mapping = {
            "Win (Inicio)": "win",
            "Alt + Tab": "alt_tab",
            "Ctrl + Shift + Esc": "ctrl_shift_esc",
            "Win + R (Ejecutar)": "win_r",
            "Win + D (Escritorio)": "win_d",
            "Win + E (Explorador)": "win_e",
            "Alt + F4": "alt_f4",
            "Bloquear PC (Win+L)": "win_l",
        }
        combo = mapping.get(choice)
        if combo:
            self._safe_send_json(PacketType.INPUT_EVENT, {"kind": "hotkey", "combo": combo})
        self._shortcut_var.set("Atajos")
        self._canvas.focus_set()

    def _open_clipboard_menu(self) -> None:
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(
            label="Enviar mi portapapeles al Huésped", command=self._push_clipboard
        )
        menu.add_command(
            label="Obtener portapapeles del Huésped", command=self._pull_clipboard
        )
        try:
            menu.tk_popup(self.winfo_pointerx(), self.winfo_pointery())
        finally:
            menu.grab_release()

    def _push_clipboard(self) -> None:
        try:
            text = pyperclip.paste()
        except Exception:
            text = ""
        self._safe_send_json(
            PacketType.CLIPBOARD_SYNC, {"action": "set", "text": text}
        )
        self._status_left.configure(text=f"Portapapeles enviado ({len(text)} caracteres).")

    def _pull_clipboard(self) -> None:
        self._safe_send_json(PacketType.CLIPBOARD_SYNC, {"action": "get"})

    def _request_screenshot(self) -> None:
        self._status_left.configure(text="Solicitando captura PNG sin pérdida...")
        self._safe_send_json(PacketType.SYS_ACTION, {"action": "screenshot"})

    # ------------------------------------------------------------------
    # Mouse & Keyboard Forwarding
    # ------------------------------------------------------------------

    def _canvas_to_norm(self, cx: int, cy: int) -> tuple[float, float] | None:
        rx, ry, rw, rh = self._render_rect
        if rw <= 1 or rh <= 1:
            return None
        nx = (cx - rx) / rw
        ny = (cy - ry) / rh
        if 0.0 <= nx <= 1.0 and 0.0 <= ny <= 1.0:
            return nx, ny
        return None

    def _on_mouse_move(self, event: tk.Event) -> None:
        now = time.monotonic()
        if now - self._last_move_ts < 0.022:  # ~45 Hz cap
            return
        coords = self._canvas_to_norm(event.x, event.y)
        if coords is None:
            return
        self._last_move_ts = now
        self._safe_send_json(
            PacketType.INPUT_EVENT,
            {"kind": "mouse_move", "nx": round(coords[0], 4), "ny": round(coords[1], 4)},
        )

    def _on_mouse_btn(self, event: tk.Event, button: str, down: bool) -> None:
        self._canvas.focus_set()
        coords = self._canvas_to_norm(event.x, event.y)
        if coords is None:
            return
        self._safe_send_json(
            PacketType.INPUT_EVENT,
            {
                "kind": "mouse_down" if down else "mouse_up",
                "button": button,
                "nx": round(coords[0], 4),
                "ny": round(coords[1], 4),
            },
        )

    def _on_mouse_dbl(self, event: tk.Event, button: str) -> None:
        coords = self._canvas_to_norm(event.x, event.y)
        if coords is None:
            return
        self._safe_send_json(
            PacketType.INPUT_EVENT,
            {
                "kind": "mouse_dblclick",
                "button": button,
                "nx": round(coords[0], 4),
                "ny": round(coords[1], 4),
            },
        )

    def _on_mouse_wheel(self, event: tk.Event) -> None:
        steps = int(event.delta / 120) if event.delta else 0
        if steps != 0:
            self._send_scroll(0, steps)

    def _send_scroll(self, dx: int, dy: int) -> None:
        self._safe_send_json(
            PacketType.INPUT_EVENT, {"kind": "mouse_scroll", "dx": dx, "dy": dy}
        )

    def _on_key_down(self, event: tk.Event) -> str:
        self._safe_send_json(
            PacketType.INPUT_EVENT,
            {"kind": "key_down", "keysym": event.keysym, "char": event.char},
        )
        return "break"

    def _on_key_up(self, event: tk.Event) -> str:
        self._safe_send_json(
            PacketType.INPUT_EVENT,
            {"kind": "key_up", "keysym": event.keysym, "char": event.char},
        )
        return "break"

    def _on_canvas_resize(self, _event: tk.Event) -> None:
        if self._compositor.canvas is not None:
            self._render_pil_to_canvas(self._compositor.canvas)

    def _render_pil_to_canvas(self, img: Image.Image) -> None:
        cw = max(1, self._canvas.winfo_width())
        ch = max(1, self._canvas.winfo_height())
        if cw < 10 or ch < 10:
            return

        iw, ih = img.size
        scale = min(cw / iw, ch / ih)
        nw = max(1, int(iw * scale))
        nh = max(1, int(ih * scale))
        ox = (cw - nw) // 2
        oy = (ch - nh) // 2
        self._render_rect = (ox, oy, nw, nh)

        resized = img if (nw == iw and nh == ih) else img.resize((nw, nh), Image.Resampling.BILINEAR)
        self._tk_image = ImageTk.PhotoImage(resized)
        if self._canvas_img_id is None:
            self._canvas_img_id = self._canvas.create_image(
                ox, oy, anchor="nw", image=self._tk_image
            )
        else:
            self._canvas.coords(self._canvas_img_id, ox, oy)
            self._canvas.itemconfig(self._canvas_img_id, image=self._tk_image)

    # ------------------------------------------------------------------
    # File Manager Operations
    # ------------------------------------------------------------------

    def _request_list_dir(self, path: str | None) -> None:
        self._safe_send_json(
            PacketType.FILE_REQ, {"req_id": secrets.token_hex(4), "action": "list", "path": path}
        )

    def _files_go_up(self) -> None:
        if self._current_dir:
            parent = str(Path(self._current_dir).parent)
            self._request_list_dir(parent)

    def _render_file_listing(self, data: dict[str, Any]) -> None:
        if not data.get("ok"):
            messagebox.showwarning("Archivos", data.get("error", "Error al listar."), parent=self)
            return

        self._current_dir = data["path"]
        self._selected_entry = None
        self._path_entry.delete(0, "end")
        self._path_entry.insert(0, self._current_dir)

        # Rebuild quick strip
        for w in self._quick_strip.winfo_children():
            w.destroy()
        for label, p in data.get("quick_paths", {}).items():
            ctk.CTkButton(
                self._quick_strip,
                text=label,
                height=26,
                width=74,
                corner_radius=6,
                font=(FONT_FAMILY, 11),
                fg_color=COLORS["surface"],
                hover_color=COLORS["surface_hover"],
                text_color=COLORS["text_secondary"],
                command=lambda path=p: self._request_list_dir(path),
            ).pack(side="left", padx=3)
        for drv in data.get("drives", []):
            ctk.CTkButton(
                self._quick_strip,
                text=drv,
                height=26,
                width=46,
                corner_radius=6,
                font=(MONO_FONT, 11, "bold"),
                fg_color=COLORS["surface_alt"],
                hover_color=COLORS["surface_hover"],
                text_color=COLORS["accent"],
                command=lambda path=drv: self._request_list_dir(path),
            ).pack(side="left", padx=3)

        # Rebuild file rows
        for w in self._file_list.winfo_children():
            w.destroy()
        self._file_rows.clear()

        entries = data.get("entries", [])
        if not entries:
            ctk.CTkLabel(
                self._file_list,
                text="Carpeta vacía.",
                font=(FONT_FAMILY, 12),
                text_color=COLORS["text_muted"],
            ).pack(pady=30)
            return

        for entry in entries[:400]:
            row = ctk.CTkFrame(
                self._file_list, fg_color="transparent", corner_radius=8, height=34
            )
            row.pack(fill="x", padx=4, pady=2)
            row.pack_propagate(False)
            self._file_rows.append(row)

            ico = self.icons.get(
                "folder" if entry["is_dir"] else "file",
                16,
                light_color="#E11D48" if entry["is_dir"] else "#475569",
                dark_color="#F43F5E" if entry["is_dir"] else "#94A3B8",
            )
            name_lbl = ctk.CTkLabel(
                row,
                text="  " + entry["name"],
                image=ico,
                compound="left",
                anchor="w",
                font=(FONT_FAMILY, 12, "bold" if entry["is_dir"] else "normal"),
                text_color=COLORS["text"],
            )
            name_lbl.pack(side="left", fill="x", expand=True, padx=10)

            size_txt = "Carpeta" if entry["is_dir"] else _human_size(entry["size"])
            ctk.CTkLabel(
                row,
                text=size_txt,
                width=90,
                anchor="e",
                font=(MONO_FONT, 11),
                text_color=COLORS["text_secondary"],
            ).pack(side="right", padx=10)

            ctk.CTkLabel(
                row,
                text=entry["modified"],
                width=125,
                anchor="e",
                font=(MONO_FONT, 11),
                text_color=COLORS["text_muted"],
            ).pack(side="right", padx=6)

            def _select(_e, item=entry, r=row):
                self._selected_entry = item
                for fr in self._file_rows:
                    fr.configure(fg_color="transparent")
                r.configure(fg_color=COLORS["surface_hover"])

            def _activate(_e, item=entry):
                if item["is_dir"]:
                    self._request_list_dir(item["path"])
                else:
                    self._safe_send_json(
                        PacketType.FILE_REQ,
                        {"req_id": secrets.token_hex(4), "action": "open", "path": item["path"]},
                    )

            for widget in (row, name_lbl):
                widget.bind("<Button-1>", _select)
                widget.bind("<Double-Button-1>", _activate)

    def _upload_file_to_guest(self) -> None:
        if not self._current_dir:
            return
        local_file = filedialog.askopenfilename(
            parent=self, title="Seleccionar archivo para subir al Huésped"
        )
        if not local_file:
            return
        src = Path(local_file)
        dest_dir = self._current_dir
        tid = secrets.token_hex(8)

        # Precompute SHA-256 in background then announce upload_start (overwrite=False)
        def _prep() -> None:
            h = hashlib.sha256()
            with open(src, "rb") as f:
                while chunk := f.read(FILE_CHUNK_SIZE):
                    h.update(chunk)
            digest = h.hexdigest()
            self._pending_uploads[tid] = {
                "src": src,
                "dest_dir": dest_dir,
                "sha256": digest,
            }
            self._safe_send_json(
                PacketType.FILE_REQ,
                {
                    "req_id": secrets.token_hex(4),
                    "action": "upload_start",
                    "transfer_id": tid,
                    "dest_dir": dest_dir,
                    "filename": src.name,
                    "size": src.stat().st_size,
                    "sha256": digest,
                    "overwrite": False,
                },
            )

        self._transfer_label.configure(text=f"Preparando subida cifrada: {src.name}...")
        threading.Thread(target=_prep, daemon=True).start()

    def _stream_upload_chunks(self, tid: str) -> None:
        meta = self._pending_uploads.pop(tid, None)
        if not meta:
            return
        src: Path = meta["src"]
        if not src.is_file():
            return

        def _worker() -> None:
            size = src.stat().st_size
            total = max(1, math.ceil(size / FILE_CHUNK_SIZE))
            with open(src, "rb") as f:
                if size == 0:
                    send_file_chunk(self.channel, FileChunkPacket(tid, 0, 1, 0, b""))
                else:
                    for idx in range(total):
                        if self._stop.is_set():
                            return
                        data = f.read(FILE_CHUNK_SIZE)
                        send_file_chunk(
                            self.channel, FileChunkPacket(tid, idx, total, 0, data)
                        )
                        pct = int(((idx + 1) / total) * 100)
                        self._ui_queue.put(
                            ("transfer_msg", f"Subiendo {src.name}: {pct}% (AES-256-GCM)")
                        )

        threading.Thread(target=_worker, daemon=True).start()

    def _download_selected_file(self) -> None:
        if not self._selected_entry or self._selected_entry["is_dir"]:
            messagebox.showinfo(
                "Descargar", "Selecciona primero un archivo (no una carpeta).", parent=self
            )
            return
        save_to = filedialog.asksaveasfilename(
            parent=self,
            title="Guardar archivo descargado",
            initialfile=self._selected_entry["name"],
        )
        if not save_to:
            return
        tid = secrets.token_hex(8)
        self._downloads[tid] = {
            "save_path": Path(save_to),
            "file": None,
            "hasher": hashlib.sha256(),
            "received": 0,
            "total": 1,
        }
        self._transfer_label.configure(
            text=f"Solicitando descarga cifrada: {self._selected_entry['name']}..."
        )
        self._safe_send_json(
            PacketType.FILE_REQ,
            {
                "req_id": secrets.token_hex(4),
                "action": "download_start",
                "transfer_id": tid,
                "path": self._selected_entry["path"],
            },
        )

    def _create_remote_folder(self) -> None:
        if not self._current_dir:
            return
        name = simpledialog.askstring("Nueva Carpeta", "Nombre de la carpeta:", parent=self)
        if name and name.strip():
            self._safe_send_json(
                PacketType.FILE_REQ,
                {
                    "req_id": secrets.token_hex(4),
                    "action": "mkdir",
                    "path": self._current_dir,
                    "name": name.strip(),
                },
            )

    def _delete_selected_remote(self) -> None:
        if not self._selected_entry:
            return
        name = self._selected_entry["name"]
        if messagebox.askyesno(
            "Eliminar", f"¿Eliminar permanentemente '{name}' en el equipo huésped?", parent=self
        ):
            self._safe_send_json(
                PacketType.FILE_REQ,
                {
                    "req_id": secrets.token_hex(4),
                    "action": "delete",
                    "path": self._selected_entry["path"],
                },
            )

    # ------------------------------------------------------------------
    # Remote Shell, System Telemetry & Chat
    # ------------------------------------------------------------------

    def _send_shell_command(self, _event=None) -> None:
        cmd = self._shell_entry.get().strip()
        if not cmd:
            return
        self._cmd_history.append(cmd)
        self._cmd_hist_idx = len(self._cmd_history)
        self._shell_entry.delete(0, "end")
        self._append_shell(f"❯ {cmd}\n")
        self._safe_send_json(
            PacketType.SHELL_REQ, {"exec_id": secrets.token_hex(4), "command": cmd}
        )

    def _shell_hist_prev(self, _event=None) -> str:
        if self._cmd_history and self._cmd_hist_idx > 0:
            self._cmd_hist_idx -= 1
            self._shell_entry.delete(0, "end")
            self._shell_entry.insert(0, self._cmd_history[self._cmd_hist_idx])
        return "break"

    def _shell_hist_next(self, _event=None) -> str:
        if self._cmd_history and self._cmd_hist_idx < len(self._cmd_history) - 1:
            self._cmd_hist_idx += 1
            self._shell_entry.delete(0, "end")
            self._shell_entry.insert(0, self._cmd_history[self._cmd_hist_idx])
        return "break"

    def _append_shell(self, text: str) -> None:
        self._shell_output.configure(state="normal")
        self._shell_output.insert("end", text)
        self._shell_output.see("end")
        self._shell_output.configure(state="disabled")

    def _request_telemetry(self) -> None:
        self._safe_send_json(PacketType.PROC_REQ, {"action": "list"})

    def _confirm_sys_action(self, action: str, desc: str) -> None:
        if messagebox.askyesno("Confirmar Acción", f"¿Deseas {desc}?", parent=self):
            self._safe_send_json(PacketType.SYS_ACTION, {"action": action})

    def _send_chat(self, _event=None) -> None:
        txt = self._chat_entry.get().strip()
        if not txt:
            return
        self._chat_entry.delete(0, "end")
        self._append_chat(f"Tú ({time.strftime('%H:%M')}): {txt}\n")
        self._safe_send_json(
            PacketType.CHAT_MSG,
            {"sender": "Anfitrión", "text": txt, "ts": time.strftime("%H:%M")},
        )

    def _append_chat(self, text: str) -> None:
        self._chat_box.configure(state="normal")
        self._chat_box.insert("end", text)
        self._chat_box.see("end")
        self._chat_box.configure(state="disabled")

    # ------------------------------------------------------------------
    # Network Receive Thread & UI Queue Pump
    # ------------------------------------------------------------------

    def _safe_send_json(self, ptype: PacketType, data: dict[str, Any]) -> None:
        if self._stop.is_set() or self.channel.is_closed:
            return
        try:
            send_json(self.channel, ptype, data)
        except Exception:
            pass

    def _recv_loop(self) -> None:
        reason = "Sesión finalizada."
        try:
            while not self._stop.is_set():
                ptype, payload = recv_packet(self.channel)
                if ptype == PacketType.SCREEN_FRAME:
                    # Composite off-UI thread to keep Tkinter responsive
                    img = self._compositor.apply(payload)
                    self._ui_queue.put(("frame", (img.copy(), payload)))
                elif ptype == PacketType.FILE_CHUNK:
                    self._handle_download_chunk(payload)
                elif ptype == PacketType.DISCONNECT:
                    reason = payload.get("reason", "El huésped cerró la sesión.")
                    break
                else:
                    self._ui_queue.put(("pkt", (ptype, payload)))
        except Exception as exc:
            if not self._stop.is_set():
                reason = f"Conexión interrumpida: {exc}"
        finally:
            self._ui_queue.put(("disconnected", reason))

    def _handle_download_chunk(self, chunk: FileChunkPacket) -> None:
        st = self._downloads.get(chunk.transfer_id)
        if not st:
            return
        try:
            if st["file"] is None:
                st["file"] = open(st["save_path"], "wb")
            if chunk.data:
                st["file"].write(chunk.data)
                st["hasher"].update(chunk.data)
            st["received"] = chunk.chunk_idx + 1
            st["total"] = max(1, chunk.total_chunks)
            pct = int((st["received"] / st["total"]) * 100)
            self._ui_queue.put(
                ("transfer_msg", f"Descargando {st['save_path'].name}: {pct}% (AES-256-GCM)")
            )
        except Exception as exc:
            self._ui_queue.put(("transfer_msg", f"Error escribiendo descarga: {exc}"))

    def _process_ui_queue(self) -> None:
        if self._stop.is_set():
            return
        latest_frame = None
        processed = 0
        while processed < 25:
            try:
                kind, data = self._ui_queue.get_nowait()
            except queue.Empty:
                break
            processed += 1

            if kind == "frame":
                latest_frame = data
            elif kind == "transfer_msg":
                self._transfer_label.configure(text=data)
            elif kind == "disconnected":
                self._handle_remote_disconnect(data)
                return
            elif kind == "pkt":
                ptype, payload = data
                self._handle_ui_packet(ptype, payload)

        if latest_frame is not None:
            img, pkt = latest_frame
            self._frame_count += 1
            self._last_frame_kind = "FULL" if pkt.is_full else f"DELTA {pkt.w}×{pkt.h}"
            self._remote_res = f"{pkt.full_w}×{pkt.full_h}"
            if self._active_tab == "screen":
                self._render_pil_to_canvas(img)

        if not self._stop.is_set():
            self.after(16, self._process_ui_queue)

    def _handle_ui_packet(self, ptype: PacketType, payload: dict[str, Any]) -> None:
        if ptype == PacketType.SYS_INFO:
            self._monitors = payload.get("monitors", [])
            if self._monitors:
                names = [m["name"] for m in self._monitors]
                self._monitor_menu.configure(values=names)
                default = names[1] if len(names) > 1 else names[0]
                self._monitor_var.set(default)
            cwd = payload.get("cwd", "")
            if cwd:
                self._shell_cwd_lbl.configure(text=f"cwd: {cwd}")
            self._status_left.configure(
                text=f"Controlando {payload.get('hostname', '?')} ({payload.get('os', '')}) • Usuario: {payload.get('user', '')}"
            )

        elif ptype == PacketType.CLIPBOARD_SYNC:
            if payload.get("action") == "data":
                txt = str(payload.get("text", ""))
                try:
                    pyperclip.copy(txt)
                    self._status_left.configure(
                        text=f"Portapapeles del huésped copiado ({len(txt)} caracteres)."
                    )
                except Exception:
                    pass

        elif ptype == PacketType.FILE_RESP:
            action = payload.get("action")
            if action == "list":
                self._render_file_listing(payload)
            elif action in ("mkdir", "delete", "rename"):
                if payload.get("ok"):
                    self._request_list_dir(self._current_dir)
                else:
                    messagebox.showerror("Error", payload.get("error", "Falló la operación."), parent=self)
            elif action == "open":
                if payload.get("ok"):
                    self._status_left.configure(text=f"Abierto en el huésped: {payload.get('opened')}")
            elif action == "upload_ready":
                tid = payload.get("transfer_id", "")
                if payload.get("ok"):
                    self._stream_upload_chunks(tid)
                elif payload.get("exists") and tid in self._pending_uploads:
                    fname = payload.get("filename", "el archivo")
                    if messagebox.askyesno(
                        "Archivo existente",
                        f"'{fname}' ya existe en el equipo huésped.\n¿Deseas sobrescribirlo?",
                        parent=self,
                    ):
                        meta = self._pending_uploads[tid]
                        src: Path = meta["src"]
                        self._safe_send_json(
                            PacketType.FILE_REQ,
                            {
                                "req_id": secrets.token_hex(4),
                                "action": "upload_start",
                                "transfer_id": tid,
                                "dest_dir": meta["dest_dir"],
                                "filename": src.name,
                                "size": src.stat().st_size,
                                "sha256": meta["sha256"],
                                "overwrite": True,
                            },
                        )
                    else:
                        self._pending_uploads.pop(tid, None)
                        self._transfer_label.configure(text="Subida cancelada por el usuario.")
                else:
                    self._pending_uploads.pop(tid, None)
                    self._transfer_label.configure(text=f"Subida rechazada: {payload.get('error')}")
            elif action == "upload_done":
                if payload.get("ok"):
                    self._transfer_label.configure(
                        text=f"Subida completada y verificada SHA-256: {payload.get('path')}"
                    )
                    self._request_list_dir(self._current_dir)
                else:
                    self._transfer_label.configure(text=f"Error de subida: {payload.get('error')}")
            elif action == "download_meta":
                if not payload.get("ok"):
                    self._downloads.pop(payload.get("transfer_id", ""), None)
                    self._transfer_label.configure(text=f"Descarga fallida: {payload.get('error')}")
            elif action == "download_done":
                tid = payload.get("transfer_id", "")
                st = self._downloads.pop(tid, None)
                if st and st.get("file"):
                    st["file"].close()
                if payload.get("ok") and st:
                    local_sha = st["hasher"].hexdigest()
                    remote_sha = payload.get("sha256", "")
                    verified = (not remote_sha) or (local_sha == remote_sha)
                    self._transfer_label.configure(
                        text=(
                            f"Descarga verificada SHA-256: {st['save_path']}"
                            if verified
                            else "Advertencia: hash SHA-256 no coincide."
                        )
                    )
                else:
                    self._transfer_label.configure(text=f"Error en descarga: {payload.get('error')}")

        elif ptype == PacketType.SHELL_RESP:
            out = payload.get("stdout", "")
            err = payload.get("stderr", "")
            if out:
                self._append_shell(out + ("" if out.endswith("\n") else "\n"))
            if err:
                self._append_shell(f"[stderr] {err}" + ("" if err.endswith("\n") else "\n"))
            self._append_shell("\n")
            if payload.get("cwd"):
                self._shell_cwd_lbl.configure(text=f"cwd: {payload['cwd']}")

        elif ptype == PacketType.PROC_RESP:
            if payload.get("action") == "kill":
                if payload.get("ok"):
                    self._status_left.configure(
                        text=f"Proceso finalizado: {payload.get('name')} (PID {payload.get('pid')})"
                    )
                    self._request_telemetry()
                else:
                    messagebox.showwarning("Procesos", payload.get("error", "No se pudo finalizar."), parent=self)
            else:
                self._render_telemetry(payload)

        elif ptype == PacketType.SYS_ACTION:
            if payload.get("action") == "screenshot_data":
                if payload.get("ok"):
                    save_to = filedialog.asksaveasfilename(
                        parent=self,
                        title="Guardar captura PNG del Huésped",
                        defaultextension=".png",
                        initialfile=f"captura_{time.strftime('%Y%m%d_%H%M%S')}.png",
                        filetypes=[("Imagen PNG", "*.png")],
                    )
                    if save_to:
                        Path(save_to).write_bytes(base64.b64decode(payload["png_b64"]))
                        self._status_left.configure(text=f"Captura guardada en: {save_to}")
                else:
                    messagebox.showerror("Captura", payload.get("error", "Error."), parent=self)
            else:
                msg = payload.get("message") or payload.get("error") or ""
                if msg:
                    self._status_left.configure(text=msg)

        elif ptype == PacketType.CHAT_MSG:
            self._append_chat(
                f"{payload.get('sender', 'Huésped')} ({payload.get('ts', '')}): {payload.get('text', '')}\n"
            )
            if self._active_tab != "chat":
                self._status_left.configure(
                    text=f"Nuevo mensaje de {payload.get('sender', 'Huésped')}: {payload.get('text', '')[:60]}"
                )

    def _render_telemetry(self, data: dict[str, Any]) -> None:
        cpu = float(data.get("cpu_percent", 0))
        ram = float(data.get("ram_percent", 0))
        disk = float(data.get("disk_percent", 0))
        self._cpu_lbl.configure(text=f"{cpu:.1f}% ({data.get('cpu_cores', 1)} hilos)")
        self._cpu_bar.set(min(1.0, cpu / 100.0))
        self._ram_lbl.configure(
            text=f"{ram:.1f}% ({data.get('ram_used_gb', 0)}/{data.get('ram_total_gb', 0)} GB)"
        )
        self._ram_bar.set(min(1.0, ram / 100.0))
        self._disk_lbl.configure(
            text=f"{disk:.1f}% ({data.get('disk_used_gb', 0)}/{data.get('disk_total_gb', 0)} GB)"
        )
        self._disk_bar.set(min(1.0, disk / 100.0))

        for w in self._proc_list.winfo_children():
            w.destroy()
        for p in data.get("processes", []):
            row = ctk.CTkFrame(self._proc_list, fg_color="transparent", height=32)
            row.pack(fill="x", padx=4, pady=2)
            row.pack_propagate(False)
            ctk.CTkLabel(
                row,
                text=f"{p['pid']:>6}   {p['name']}",
                anchor="w",
                font=(MONO_FONT, 11),
                text_color=COLORS["text"],
            ).pack(side="left", fill="x", expand=True, padx=8)
            ctk.CTkLabel(
                row,
                text=f"{p['mem_mb']:.1f} MB",
                width=85,
                anchor="e",
                font=(MONO_FONT, 11),
                text_color=COLORS["text_secondary"],
            ).pack(side="left", padx=8)
            ctk.CTkButton(
                row,
                text="Finalizar",
                width=74,
                height=24,
                corner_radius=6,
                font=(FONT_FAMILY, 11),
                fg_color=COLORS["surface_alt"],
                hover_color=COLORS["danger"],
                text_color=COLORS["text"],
                command=lambda pid=p["pid"]: self._safe_send_json(
                    PacketType.PROC_REQ, {"action": "kill", "pid": pid}
                ),
            ).pack(side="right", padx=6)

    def _update_stats_loop(self) -> None:
        if self._stop.is_set():
            return
        now = time.monotonic()
        dt = max(0.1, now - self._fps_ts)
        self._current_fps = self._frame_count / dt
        self._frame_count = 0
        self._fps_ts = now

        delta_bytes = max(0, self.channel.bytes_recv - self._last_bytes_recv)
        self._last_bytes_recv = self.channel.bytes_recv
        kbps = (delta_bytes / 1024.0) / dt

        self._status_right.configure(
            text=f"{self._remote_res} • {self._last_frame_kind} • {self._current_fps:.1f} FPS • {kbps:.1f} KB/s • AES-256-GCM"
        )
        self.after(1000, self._update_stats_loop)

    def _handle_remote_disconnect(self, reason: str) -> None:
        if self._stop.is_set():
            return
        self._stop.set()
        self.channel.close()
        try:
            messagebox.showinfo("Sesión Finalizada", reason, parent=self)
        except Exception:
            pass
        if self.on_closed:
            self.on_closed()
        try:
            self.destroy()
        except Exception:
            pass

    def close_session(self) -> None:
        if self._stop.is_set():
            return
        self._stop.set()
        try:
            send_json(
                self.channel,
                PacketType.DISCONNECT,
                {"reason": "El anfitrión finalizó la sesión."},
            )
        except Exception:
            pass
        self.channel.close()
        for st in self._downloads.values():
            if st.get("file"):
                try:
                    st["file"].close()
                except Exception:
                    pass
        if self.on_closed:
            self.on_closed()
        try:
            self.destroy()
        except Exception:
            pass
