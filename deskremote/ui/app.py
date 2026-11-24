"""Main DeskRemote minimalist modern application window (CustomTkinter) with Security v2 UI."""

from __future__ import annotations

import os
import platform
import subprocess
import threading
import time
from tkinter import messagebox

import customtkinter as ctk
import pyperclip

from deskremote.config import (
    APP_NAME,
    APP_VERSION,
    AUDIT_LOG_DIR,
    BORE_CONTROL_PORT,
    BORE_DEFAULT_SERVER,
    COLORS,
    FONT_FAMILY,
    MAX_AUTH_FAILURES,
    MONO_FONT,
    get_app_icon_path,
)
from deskremote.crypto.e2ee import (
    ROLE_GUEST,
    ROLE_HOST,
    DeviceIdentity,
    SecureChannel,
    SessionInfo,
)
from deskremote.crypto.trust_store import TrustEvaluation, TrustStatus, TrustStore
from deskremote.network.protocol import PacketType, send_json
from deskremote.network.server import (
    ActiveServerInfo,
    TemporarySessionServer,
    connect_to_session,
)
from deskremote.remote.guest_agent import GuestAgent, GuestPermissions
from deskremote.security.audit import get_audit_logger
from deskremote.ui.icons import IconLibrary
from deskremote.ui.remote_window import RemoteControlWindow

TUNNEL_OPTIONS: dict[str, str] = {
    "Automático Global (Recomendado)": "auto",
    "Túnel Global Bore (bore.pub)": "bore",
    "Túnel Global SSH (Pinggy)": "ssh_pinggy",
    "Túnel Global SSH (Serveo)": "ssh_serveo",
    "Router UPnP Automático": "upnp",
    "Solo Red Local (LAN)": "lan",
}


class SessionApprovalDialog(ctk.CTkToplevel):
    """Minimalist interactive confirmation dialog with TOFU identity verification."""

    def __init__(
        self,
        master: ctk.CTk,
        icons: IconLibrary,
        session_info: SessionInfo,
        trust_eval: TrustEvaluation,
        remote_ip: str,
        direction_label: str,
    ) -> None:
        super().__init__(master)
        self.title("Confirmación de Seguridad E2EE — DeskRemote")
        self.geometry("490x400")
        self.resizable(False, False)
        self.configure(fg_color=COLORS["bg"])
        self.transient(master)
        self.grab_set()

        self.approved = False
        self.remember_peer = trust_eval.status != TrustStatus.KEY_CHANGED

        # Status banner styling based on TOFU result
        if trust_eval.status == TrustStatus.TRUSTED:
            badge_text = "EQUIPO DE CONFIANZA VERIFICADO (TOFU)"
            badge_bg = COLORS["success_soft"]
            badge_fg = COLORS["success"]
            ico_color = "#10B981"
        elif trust_eval.status == TrustStatus.KEY_CHANGED:
            badge_text = "¡ALERTA! LA IDENTIDAD ED25519 DE ESTE EQUIPO CAMBIÓ"
            badge_bg = COLORS["accent_soft"]
            badge_fg = COLORS["danger"]
            ico_color = "#EF4444"
        else:
            badge_text = "NUEVO EQUIPO — PRIMERA CONEXIÓN"
            badge_bg = COLORS["info_soft"]
            badge_fg = COLORS["info"]
            ico_color = "#3B82F6"

        card = ctk.CTkFrame(
            self,
            fg_color=COLORS["surface"],
            corner_radius=16,
            border_width=1,
            border_color=COLORS["danger"]
            if trust_eval.status == TrustStatus.KEY_CHANGED
            else COLORS["border"],
        )
        card.pack(fill="both", expand=True, padx=18, pady=18)

        banner = ctk.CTkFrame(card, fg_color=badge_bg, corner_radius=10)
        banner.pack(fill="x", padx=18, pady=(18, 12))

        ctk.CTkLabel(
            banner,
            text=f"  {badge_text}",
            image=icons.mono("shield_lock", 17, ico_color),
            compound="left",
            font=(FONT_FAMILY, 11, "bold"),
            text_color=badge_fg,
        ).pack(anchor="w", padx=12, pady=10)

        ctk.CTkLabel(
            card,
            text=direction_label,
            font=(FONT_FAMILY, 13, "bold"),
            text_color=COLORS["text"],
        ).pack(anchor="w", padx=20, pady=(0, 8))

        # Verification details grid
        info_box = ctk.CTkFrame(
            card,
            fg_color=COLORS["surface_alt"],
            corner_radius=10,
            border_width=1,
            border_color=COLORS["border"],
        )
        info_box.pack(fill="x", padx=18, pady=(0, 12))

        rows = [
            ("Equipo remoto", f"{session_info.peer_name} ({remote_ip})"),
            ("Identidad Ed25519", session_info.peer_fingerprint),
            ("Huella de Sesión", session_info.session_fingerprint),
            ("Cifrado", "SPAKE2(P-256) + X25519 + AES-256-GCM"),
        ]
        if trust_eval.status == TrustStatus.KEY_CHANGED and trust_eval.existing_record:
            rows.insert(
                2,
                ("Clave anterior", trust_eval.existing_record.fingerprint),
            )

        for k, v in rows:
            r = ctk.CTkFrame(info_box, fg_color="transparent")
            r.pack(fill="x", padx=12, pady=4)
            ctk.CTkLabel(
                r,
                text=k,
                width=125,
                anchor="w",
                font=(FONT_FAMILY, 11, "bold"),
                text_color=COLORS["text_secondary"],
            ).pack(side="left")
            ctk.CTkLabel(
                r,
                text=v,
                anchor="w",
                font=(MONO_FONT, 11),
                text_color=COLORS["danger"]
                if k == "Clave anterior"
                else COLORS["text"],
            ).pack(side="left", fill="x", expand=True)

        self._remember_var = ctk.BooleanVar(value=self.remember_peer)
        ctk.CTkCheckBox(
            card,
            text="Recordar este equipo como confiable (TOFU)",
            variable=self._remember_var,
            font=(FONT_FAMILY, 12),
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
        ).pack(anchor="w", padx=20, pady=(2, 14))

        btn_row = ctk.CTkFrame(card, fg_color="transparent")
        btn_row.pack(fill="x", padx=18, pady=(0, 16))

        ctk.CTkButton(
            btn_row,
            text="Rechazar",
            height=40,
            corner_radius=10,
            font=(FONT_FAMILY, 13, "bold"),
            fg_color=COLORS["surface_alt"],
            hover_color=COLORS["danger"],
            text_color=COLORS["text"],
            command=self._reject,
        ).pack(side="left", fill="x", expand=True, padx=(0, 8))

        ctk.CTkButton(
            btn_row,
            text="Aceptar Conexión",
            height=40,
            corner_radius=10,
            font=(FONT_FAMILY, 13, "bold"),
            fg_color=COLORS["success"]
            if trust_eval.status != TrustStatus.KEY_CHANGED
            else COLORS["warning"],
            hover_color=COLORS["accent_hover"],
            text_color="#FFFFFF",
            command=self._accept,
        ).pack(side="right", fill="x", expand=True, padx=(8, 0))

        self.protocol("WM_DELETE_WINDOW", self._reject)
        self.focus_force()

    def _accept(self) -> None:
        self.approved = True
        self.remember_peer = bool(self._remember_var.get())
        self.destroy()

    def _reject(self) -> None:
        self.approved = False
        self.remember_peer = False
        self.destroy()


class DeskRemoteApp(ctk.CTk):
    """Unified AnyDesk-inspired minimalist desktop application (Hardened v2)."""

    def __init__(self) -> None:
        super().__init__()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.title(f"{APP_NAME} — Escritorio Remoto Cifrado E2EE")
        self.geometry("1060x700")
        self.minsize(940, 640)
        self.configure(fg_color=COLORS["bg"])
        self._apply_window_icon()

        self.identity = DeviceIdentity.load_or_create()
        self.trust_store = TrustStore()
        self.audit = get_audit_logger()
        self.icons = IconLibrary()
        self._is_dark = True

        # Active components
        self._host_server: TemporarySessionServer | None = None
        self._guest_server: TemporarySessionServer | None = None
        self._guest_agent: GuestAgent | None = None
        self._remote_windows: list[RemoteControlWindow] = []
        self._active_server_info: ActiveServerInfo | None = None

        # Custom bore settings
        self._custom_bore_host = BORE_DEFAULT_SERVER
        self._custom_bore_port = BORE_CONTROL_PORT
        self._custom_bore_secret: str | None = None

        self._build_layout()
        self.protocol("WM_DELETE_WINDOW", self._on_app_close)
        self._log_security(
            f"Identidad Ed25519 (DPAPI) cargada: {self.identity.fingerprint} ({platform.node()})"
        )

    def _apply_window_icon(self) -> None:
        """Apply DeskR.ico to window titlebar & taskbar (re-applied after CTk's delayed default)."""
        ico = get_app_icon_path()
        if ico is None or os.name != "nt":
            return

        def _set() -> None:
            try:
                self.iconbitmap(default=str(ico))
            except Exception:
                pass

        _set()
        self.after(250, _set)

    # ------------------------------------------------------------------
    # Main Layout (Minimalist Navigation Rail + Views)
    # ------------------------------------------------------------------

    def _build_layout(self) -> None:
        self._sidebar = ctk.CTkFrame(
            self, width=232, corner_radius=0, fg_color=COLORS["sidebar"]
        )
        self._sidebar.pack(side="left", fill="y")
        self._sidebar.pack_propagate(False)

        brand = ctk.CTkFrame(self._sidebar, fg_color="transparent")
        brand.pack(fill="x", padx=20, pady=(24, 20))

        ctk.CTkLabel(
            brand,
            text="",
            image=self.icons.mono("logo", 30, "#F43F5E", stroke_width=2.1),
        ).pack(side="left")

        brand_txt = ctk.CTkFrame(brand, fg_color="transparent")
        brand_txt.pack(side="left", padx=(10, 0))
        ctk.CTkLabel(
            brand_txt,
            text=APP_NAME,
            font=(FONT_FAMILY, 18, "bold"),
            text_color=COLORS["text"],
        ).pack(anchor="w")
        ctk.CTkLabel(
            brand_txt,
            text=f"E2EE v2 • v{APP_VERSION}",
            font=(FONT_FAMILY, 10),
            text_color=COLORS["text_muted"],
        ).pack(anchor="w")

        self._nav_buttons: dict[str, ctk.CTkButton] = {}
        nav_items = [
            ("host", "Anfitrión (Controlar)", "server"),
            ("guest", "Huésped (Dar Acceso)", "monitor"),
            ("direct", "Conexión Directa", "link"),
            ("security", "Seguridad y Red", "shield_lock"),
        ]
        for key, label, ico in nav_items:
            btn = ctk.CTkButton(
                self._sidebar,
                text=f"  {label}",
                image=self.icons.get(ico, 18),
                compound="left",
                anchor="w",
                height=42,
                corner_radius=10,
                font=(FONT_FAMILY, 13, "bold"),
                fg_color="transparent",
                text_color=COLORS["text_secondary"],
                hover_color=COLORS["surface_hover"],
                command=lambda k=key: self._select_nav(k),
            )
            btn.pack(fill="x", padx=14, pady=4)
            self._nav_buttons[key] = btn

        bottom = ctk.CTkFrame(self._sidebar, fg_color="transparent")
        bottom.pack(side="bottom", fill="x", padx=14, pady=16)

        id_card = ctk.CTkFrame(
            bottom,
            fg_color=COLORS["surface_alt"],
            corner_radius=10,
            border_width=1,
            border_color=COLORS["border"],
        )
        id_card.pack(fill="x", pady=(0, 10))

        ctk.CTkLabel(
            id_card,
            text="IDENTIDAD DEL EQUIPO",
            font=(FONT_FAMILY, 9, "bold"),
            text_color=COLORS["text_muted"],
        ).pack(anchor="w", padx=12, pady=(8, 1))

        ctk.CTkLabel(
            id_card,
            text=self.identity.fingerprint,
            font=(MONO_FONT, 11, "bold"),
            text_color=COLORS["text"],
        ).pack(anchor="w", padx=12, pady=(0, 8))

        self._theme_btn = ctk.CTkButton(
            bottom,
            text="  Modo Claro",
            image=self.icons.get("sun", 16),
            compound="left",
            anchor="w",
            height=36,
            corner_radius=9,
            font=(FONT_FAMILY, 12),
            fg_color=COLORS["surface_alt"],
            hover_color=COLORS["surface_hover"],
            text_color=COLORS["text"],
            command=self._toggle_theme,
        )
        self._theme_btn.pack(fill="x")

        ctk.CTkFrame(self, width=1, fg_color=COLORS["border"]).pack(side="left", fill="y")

        self._content = ctk.CTkFrame(self, fg_color=COLORS["bg"], corner_radius=0)
        self._content.pack(side="left", fill="both", expand=True)

        self._pages: dict[str, ctk.CTkFrame] = {
            "host": self._build_host_page(self._content),
            "guest": self._build_guest_page(self._content),
            "direct": self._build_direct_page(self._content),
            "security": self._build_security_page(self._content),
        }

        self._select_nav("host")

    # ------------------------------------------------------------------
    # Page 1: Anfitrión — Servidor Temporal & Control Total
    # ------------------------------------------------------------------

    def _build_host_page(self, parent: ctk.CTkFrame) -> ctk.CTkFrame:
        page = ctk.CTkFrame(parent, fg_color=COLORS["bg"], corner_radius=0)

        hdr = ctk.CTkFrame(page, fg_color="transparent")
        hdr.pack(fill="x", padx=30, pady=(26, 14))

        ctk.CTkLabel(
            hdr,
            text="Anfitrión — Servidor Temporal",
            font=(FONT_FAMILY, 24, "bold"),
            text_color=COLORS["text"],
        ).pack(anchor="w")

        ctk.CTkLabel(
            hdr,
            text="Crea un servidor efímero protegido con SPAKE2 + X25519 + AES-256-GCM y aprobación TOFU antes de cada sesión.",
            font=(FONT_FAMILY, 13),
            text_color=COLORS["text_secondary"],
            wraplength=700,
            justify="left",
        ).pack(anchor="w", pady=(4, 0))

        grid = ctk.CTkFrame(page, fg_color="transparent")
        grid.pack(fill="both", expand=True, padx=30, pady=(4, 24))
        grid.grid_columnconfigure(0, weight=1, uniform="col")
        grid.grid_columnconfigure(1, weight=1, uniform="col")
        grid.grid_rowconfigure(0, weight=1)

        left = ctk.CTkFrame(
            grid,
            fg_color=COLORS["surface"],
            corner_radius=16,
            border_width=1,
            border_color=COLORS["border"],
        )
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        ctk.CTkLabel(
            left,
            text="  Configuración del Servidor Temporal",
            image=self.icons.get("globe", 18),
            compound="left",
            font=(FONT_FAMILY, 15, "bold"),
            text_color=COLORS["text"],
        ).pack(anchor="w", padx=22, pady=(22, 12))

        ctk.CTkLabel(
            left,
            text="Alcance de red (WAN / Internet):",
            font=(FONT_FAMILY, 12),
            text_color=COLORS["text_secondary"],
        ).pack(anchor="w", padx=22, pady=(4, 6))

        self._tunnel_var = ctk.StringVar(value="Automático Global (Recomendado)")
        ctk.CTkOptionMenu(
            left,
            variable=self._tunnel_var,
            values=list(TUNNEL_OPTIONS.keys()),
            height=38,
            corner_radius=10,
            font=(FONT_FAMILY, 12),
            fg_color=COLORS["surface_alt"],
            button_color=COLORS["surface_hover"],
            button_hover_color=COLORS["border"],
            text_color=COLORS["text"],
        ).pack(fill="x", padx=22, pady=(0, 16))

        self._host_status_box = ctk.CTkFrame(
            left,
            fg_color=COLORS["surface_alt"],
            corner_radius=10,
            border_width=1,
            border_color=COLORS["border"],
        )
        self._host_status_box.pack(fill="x", padx=22, pady=(0, 18))

        self._host_status_lbl = ctk.CTkLabel(
            self._host_status_box,
            text="Servidor inactivo. Ningún puerto expuesto.",
            font=(FONT_FAMILY, 12),
            text_color=COLORS["text_secondary"],
            wraplength=290,
            justify="left",
        )
        self._host_status_lbl.pack(anchor="w", padx=14, pady=12)

        self._host_start_btn = ctk.CTkButton(
            left,
            text="  Iniciar Servidor Temporal",
            image=self.icons.mono("play", 16, "#FFFFFF"),
            compound="left",
            height=46,
            corner_radius=12,
            font=(FONT_FAMILY, 14, "bold"),
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            command=self._toggle_host_server,
        )
        self._host_start_btn.pack(fill="x", padx=22, pady=(0, 14))

        caps = ctk.CTkFrame(left, fg_color="transparent")
        caps.pack(fill="x", padx=22, pady=(6, 16))
        for txt in (
            "PAKE SPAKE2 (RFC 9382) + scrypt inmune a fuerza bruta offline",
            f"Auto-rotación de PIN tras {MAX_AUTH_FAILURES} intentos fallidos",
            "Confirmación interactiva con verificación TOFU de identidad",
            "Modo sesión única + auditoría persistente cifrada E2EE",
        ):
            ctk.CTkLabel(
                caps,
                text=f"  {txt}",
                image=self.icons.mono("check", 13, "#10B981"),
                compound="left",
                font=(FONT_FAMILY, 11),
                text_color=COLORS["text_secondary"],
            ).pack(anchor="w", pady=3)

        right = ctk.CTkFrame(
            grid,
            fg_color=COLORS["surface"],
            corner_radius=16,
            border_width=1,
            border_color=COLORS["border"],
        )
        right.grid(row=0, column=1, sticky="nsew", padx=(10, 0))

        ctk.CTkLabel(
            right,
            text="  Invitación de Sesión Cifrada",
            image=self.icons.mono("shield_lock", 18, "#10B981"),
            compound="left",
            font=(FONT_FAMILY, 15, "bold"),
            text_color=COLORS["text"],
        ).pack(anchor="w", padx=22, pady=(22, 6))

        ctk.CTkLabel(
            right,
            text="Comparte estos datos con el equipo Huésped:",
            font=(FONT_FAMILY, 12),
            text_color=COLORS["text_secondary"],
        ).pack(anchor="w", padx=22, pady=(0, 14))

        code_box = ctk.CTkFrame(
            right,
            fg_color=COLORS["surface_alt"],
            corner_radius=12,
            border_width=1,
            border_color=COLORS["border"],
        )
        code_box.pack(fill="x", padx=22, pady=(0, 12))

        ctk.CTkLabel(
            code_box,
            text="CÓDIGO DE SESIÓN (GLOBAL)",
            font=(FONT_FAMILY, 10, "bold"),
            text_color=COLORS["text_muted"],
        ).pack(anchor="w", padx=14, pady=(10, 2))

        code_row = ctk.CTkFrame(code_box, fg_color="transparent")
        code_row.pack(fill="x", padx=14, pady=(0, 12))

        self._host_code_lbl = ctk.CTkLabel(
            code_row,
            text="DR-••••-••••",
            font=(MONO_FONT, 20, "bold"),
            text_color=COLORS["text"],
        )
        self._host_code_lbl.pack(side="left")

        ctk.CTkButton(
            code_row,
            text="",
            image=self.icons.get("copy", 16),
            width=34,
            height=34,
            corner_radius=8,
            fg_color=COLORS["surface"],
            hover_color=COLORS["surface_hover"],
            command=self._copy_host_code,
        ).pack(side="right")

        pin_box = ctk.CTkFrame(
            right,
            fg_color=COLORS["surface_alt"],
            corner_radius=12,
            border_width=1,
            border_color=COLORS["border"],
        )
        pin_box.pack(fill="x", padx=22, pady=(0, 12))

        ctk.CTkLabel(
            pin_box,
            text="PIN CRIPTOGRÁFICO SPAKE2 (8 CARACTERES)",
            font=(FONT_FAMILY, 10, "bold"),
            text_color=COLORS["text_muted"],
        ).pack(anchor="w", padx=14, pady=(10, 2))

        pin_row = ctk.CTkFrame(pin_box, fg_color="transparent")
        pin_row.pack(fill="x", padx=14, pady=(0, 12))

        self._host_pin_lbl = ctk.CTkLabel(
            pin_row,
            text="••••-••••",
            font=(MONO_FONT, 21, "bold"),
            text_color=COLORS["accent"],
        )
        self._host_pin_lbl.pack(side="left")

        ctk.CTkButton(
            pin_row,
            text="",
            image=self.icons.get("copy", 16),
            width=34,
            height=34,
            corner_radius=8,
            fg_color=COLORS["surface"],
            hover_color=COLORS["surface_hover"],
            command=self._copy_host_pin,
        ).pack(side="right")

        self._rotate_pin_btn = ctk.CTkButton(
            pin_row,
            text="",
            image=self.icons.get("refresh", 15),
            width=34,
            height=34,
            corner_radius=8,
            fg_color=COLORS["surface"],
            hover_color=COLORS["surface_hover"],
            state="disabled",
            command=self._manual_rotate_pin,
        )
        self._rotate_pin_btn.pack(side="right", padx=(0, 6))

        self._host_lan_lbl = ctk.CTkLabel(
            right,
            text="Dirección LAN alternativa: —",
            font=(MONO_FONT, 11),
            text_color=COLORS["text_muted"],
        )
        self._host_lan_lbl.pack(anchor="w", padx=24, pady=(2, 12))

        self._copy_all_btn = ctk.CTkButton(
            right,
            text="  Copiar Invitación Completa",
            image=self.icons.get("copy", 16),
            compound="left",
            height=40,
            corner_radius=10,
            font=(FONT_FAMILY, 12, "bold"),
            fg_color=COLORS["surface_alt"],
            hover_color=COLORS["surface_hover"],
            text_color=COLORS["text"],
            state="disabled",
            command=self._copy_full_invite,
        )
        self._copy_all_btn.pack(fill="x", padx=22, pady=(0, 12))

        self._endpoint_badge = ctk.CTkLabel(
            right,
            text="El servidor se destruye automáticamente al detenerlo o cerrar la app.",
            font=(FONT_FAMILY, 11),
            text_color=COLORS["text_muted"],
            wraplength=310,
            justify="left",
        )
        self._endpoint_badge.pack(anchor="w", padx=22, pady=(4, 16))
        return page

    # ------------------------------------------------------------------
    # Page 2: Huésped — Compartir Este Equipo
    # ------------------------------------------------------------------

    def _build_guest_page(self, parent: ctk.CTkFrame) -> ctk.CTkFrame:
        page = ctk.CTkFrame(parent, fg_color=COLORS["bg"], corner_radius=0)

        hdr = ctk.CTkFrame(page, fg_color="transparent")
        hdr.pack(fill="x", padx=30, pady=(26, 14))

        ctk.CTkLabel(
            hdr,
            text="Huésped — Conceder Acceso Remoto",
            font=(FONT_FAMILY, 24, "bold"),
            text_color=COLORS["text"],
        ).pack(anchor="w")

        ctk.CTkLabel(
            hdr,
            text="Ingresa el Código y PIN generados por el Anfitrión. No necesitas abrir puertos ni configurar tu router.",
            font=(FONT_FAMILY, 13),
            text_color=COLORS["text_secondary"],
        ).pack(anchor="w", pady=(4, 0))

        grid = ctk.CTkFrame(page, fg_color="transparent")
        grid.pack(fill="both", expand=True, padx=30, pady=(4, 24))
        grid.grid_columnconfigure(0, weight=1, uniform="gcol")
        grid.grid_columnconfigure(1, weight=1, uniform="gcol")
        grid.grid_rowconfigure(0, weight=1)

        left = ctk.CTkFrame(
            grid,
            fg_color=COLORS["surface"],
            corner_radius=16,
            border_width=1,
            border_color=COLORS["border"],
        )
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        ctk.CTkLabel(
            left,
            text="  Unirse al Servidor del Anfitrión",
            image=self.icons.get("monitor", 18),
            compound="left",
            font=(FONT_FAMILY, 15, "bold"),
            text_color=COLORS["text"],
        ).pack(anchor="w", padx=22, pady=(22, 12))

        ctk.CTkLabel(
            left,
            text="Código de Sesión (DR-... o IP:puerto)",
            font=(FONT_FAMILY, 12),
            text_color=COLORS["text_secondary"],
        ).pack(anchor="w", padx=22)

        self._guest_code_entry = ctk.CTkEntry(
            left,
            placeholder_text="Ej: DR-AEUI-E  o  192.168.1.10:54321",
            height=40,
            corner_radius=10,
            font=(MONO_FONT, 13),
            fg_color=COLORS["surface_alt"],
            border_color=COLORS["border"],
        )
        self._guest_code_entry.pack(fill="x", padx=22, pady=(4, 12))

        ctk.CTkLabel(
            left,
            text="PIN Criptográfico (8 caracteres)",
            font=(FONT_FAMILY, 12),
            text_color=COLORS["text_secondary"],
        ).pack(anchor="w", padx=22)

        self._guest_pin_entry = ctk.CTkEntry(
            left,
            placeholder_text="Ej: K7M4-P9Q2",
            height=40,
            corner_radius=10,
            font=(MONO_FONT, 14, "bold"),
            fg_color=COLORS["surface_alt"],
            border_color=COLORS["border"],
        )
        self._guest_pin_entry.pack(fill="x", padx=22, pady=(4, 14))

        self._guest_connect_btn = ctk.CTkButton(
            left,
            text="  Conectar y Compartir Acceso Total",
            image=self.icons.mono("play", 15, "#FFFFFF"),
            compound="left",
            height=44,
            corner_radius=12,
            font=(FONT_FAMILY, 13, "bold"),
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            command=self._toggle_guest_connection,
        )
        self._guest_connect_btn.pack(fill="x", padx=22, pady=(0, 14))

        ctk.CTkLabel(
            left,
            text="PERMISOS EN VIVO (CONTROL TOTAL POR DEFECTO)",
            font=(FONT_FAMILY, 10, "bold"),
            text_color=COLORS["text_muted"],
        ).pack(anchor="w", padx=22, pady=(4, 6))

        self._perm_vars: dict[str, ctk.BooleanVar] = {}
        for key, label in [
            ("allow_screen", "Transmitir pantalla"),
            ("allow_input", "Control de ratón y teclado"),
            ("allow_files", "Gestor de archivos completo"),
            ("allow_shell", "Terminal remota y control del sistema"),
            ("allow_clipboard", "Sincronización de portapapeles"),
        ]:
            var = ctk.BooleanVar(value=True)
            self._perm_vars[key] = var
            ctk.CTkSwitch(
                left,
                text=label,
                variable=var,
                font=(FONT_FAMILY, 12),
                progress_color=COLORS["success"],
                command=self._sync_guest_permissions,
            ).pack(anchor="w", padx=22, pady=3)

        right = ctk.CTkFrame(
            grid,
            fg_color=COLORS["surface"],
            corner_radius=16,
            border_width=1,
            border_color=COLORS["border"],
        )
        right.grid(row=0, column=1, sticky="nsew", padx=(10, 0))

        self._guest_banner = ctk.CTkFrame(
            right,
            fg_color=COLORS["surface_alt"],
            corner_radius=12,
            border_width=1,
            border_color=COLORS["border"],
        )
        self._guest_banner.pack(fill="x", padx=18, pady=(18, 10))

        self._guest_status_lbl = ctk.CTkLabel(
            self._guest_banner,
            text="Sin sesión remota activa",
            font=(FONT_FAMILY, 13, "bold"),
            text_color=COLORS["text"],
        )
        self._guest_status_lbl.pack(anchor="w", padx=14, pady=(10, 2))

        self._guest_fp_lbl = ctk.CTkLabel(
            self._guest_banner,
            text="Huella de sesión E2EE: —",
            font=(MONO_FONT, 11),
            text_color=COLORS["text_muted"],
        )
        self._guest_fp_lbl.pack(anchor="w", padx=14, pady=(0, 10))

        ctk.CTkLabel(
            right,
            text="Registro de Auditoría y Chat E2EE",
            font=(FONT_FAMILY, 12, "bold"),
            text_color=COLORS["text_secondary"],
        ).pack(anchor="w", padx=18, pady=(2, 4))

        self._guest_log = ctk.CTkTextbox(
            right,
            font=(MONO_FONT, 11),
            fg_color=COLORS["surface_alt"],
            text_color=COLORS["text"],
            corner_radius=10,
            border_width=1,
            border_color=COLORS["border"],
        )
        self._guest_log.pack(fill="both", expand=True, padx=18, pady=(0, 8))
        self._guest_log.configure(state="disabled")

        chat_bar = ctk.CTkFrame(right, fg_color="transparent")
        chat_bar.pack(fill="x", padx=18, pady=(0, 14))

        self._guest_chat_entry = ctk.CTkEntry(
            chat_bar,
            placeholder_text="Responder al anfitrión...",
            height=34,
            corner_radius=8,
            fg_color=COLORS["surface_alt"],
            border_color=COLORS["border"],
        )
        self._guest_chat_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        self._guest_chat_entry.bind("<Return>", self._guest_send_chat)

        ctk.CTkButton(
            chat_bar,
            text="Enviar",
            width=74,
            height=34,
            corner_radius=8,
            font=(FONT_FAMILY, 12, "bold"),
            fg_color=COLORS["surface_hover"],
            hover_color=COLORS["accent"],
            text_color=COLORS["text"],
            command=self._guest_send_chat,
        ).pack(side="right")

        return page

    # ------------------------------------------------------------------
    # Page 3: Conexión Directa (Host -> Guest listening directly)
    # ------------------------------------------------------------------

    def _build_direct_page(self, parent: ctk.CTkFrame) -> ctk.CTkFrame:
        page = ctk.CTkFrame(parent, fg_color=COLORS["bg"], corner_radius=0)

        hdr = ctk.CTkFrame(page, fg_color="transparent")
        hdr.pack(fill="x", padx=30, pady=(26, 14))

        ctk.CTkLabel(
            hdr,
            text="Conexión Directa (Modo Clásico)",
            font=(FONT_FAMILY, 24, "bold"),
            text_color=COLORS["text"],
        ).pack(anchor="w")

        ctk.CTkLabel(
            hdr,
            text="Modo alternativo: el Huésped expone un servidor temporal con aprobación TOFU y el Anfitrión se conecta directamente.",
            font=(FONT_FAMILY, 13),
            text_color=COLORS["text_secondary"],
        ).pack(anchor="w", pady=(4, 0))

        grid = ctk.CTkFrame(page, fg_color="transparent")
        grid.pack(fill="x", padx=30, pady=10)
        grid.grid_columnconfigure(0, weight=1, uniform="dcol")
        grid.grid_columnconfigure(1, weight=1, uniform="dcol")

        c1 = ctk.CTkFrame(
            grid,
            fg_color=COLORS["surface"],
            corner_radius=16,
            border_width=1,
            border_color=COLORS["border"],
        )
        c1.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        ctk.CTkLabel(
            c1,
            text="  Conectar como Anfitrión",
            image=self.icons.get("link", 18),
            compound="left",
            font=(FONT_FAMILY, 15, "bold"),
            text_color=COLORS["text"],
        ).pack(anchor="w", padx=22, pady=(22, 12))

        self._direct_code = ctk.CTkEntry(
            c1,
            placeholder_text="Código DR-... o IP:puerto del Huésped",
            height=40,
            corner_radius=10,
            font=(MONO_FONT, 12),
            fg_color=COLORS["surface_alt"],
            border_color=COLORS["border"],
        )
        self._direct_code.pack(fill="x", padx=22, pady=(0, 10))

        self._direct_pin = ctk.CTkEntry(
            c1,
            placeholder_text="PIN E2EE (Ej: K7M4-P9Q2)",
            height=40,
            corner_radius=10,
            font=(MONO_FONT, 13, "bold"),
            fg_color=COLORS["surface_alt"],
            border_color=COLORS["border"],
        )
        self._direct_pin.pack(fill="x", padx=22, pady=(0, 14))

        self._direct_btn = ctk.CTkButton(
            c1,
            text="  Conectar y Controlar",
            image=self.icons.mono("play", 15, "#FFFFFF"),
            compound="left",
            height=42,
            corner_radius=10,
            font=(FONT_FAMILY, 13, "bold"),
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            command=self._direct_connect_as_host,
        )
        self._direct_btn.pack(fill="x", padx=22, pady=(0, 22))

        c2 = ctk.CTkFrame(
            grid,
            fg_color=COLORS["surface"],
            corner_radius=16,
            border_width=1,
            border_color=COLORS["border"],
        )
        c2.grid(row=0, column=1, sticky="nsew", padx=(10, 0))

        ctk.CTkLabel(
            c2,
            text="  Escuchar como Huésped",
            image=self.icons.get("server", 18),
            compound="left",
            font=(FONT_FAMILY, 15, "bold"),
            text_color=COLORS["text"],
        ).pack(anchor="w", padx=22, pady=(22, 10))

        ctk.CTkLabel(
            c2,
            text="Inicia un servidor temporal aquí para que un Anfitrión se conecte directamente a este equipo (requerirá tu aprobación).",
            font=(FONT_FAMILY, 12),
            text_color=COLORS["text_secondary"],
            wraplength=310,
            justify="left",
        ).pack(anchor="w", padx=22, pady=(0, 12))

        self._guest_srv_info = ctk.CTkLabel(
            c2,
            text="Código: —   |   PIN: —",
            font=(MONO_FONT, 12, "bold"),
            text_color=COLORS["text"],
        )
        self._guest_srv_info.pack(anchor="w", padx=22, pady=(0, 14))

        self._guest_listen_btn = ctk.CTkButton(
            c2,
            text="  Abrir Escucha Temporal",
            image=self.icons.get("wifi", 15),
            compound="left",
            height=42,
            corner_radius=10,
            font=(FONT_FAMILY, 13, "bold"),
            fg_color=COLORS["surface_alt"],
            hover_color=COLORS["surface_hover"],
            text_color=COLORS["text"],
            command=self._toggle_guest_listener,
        )
        self._guest_listen_btn.pack(fill="x", padx=22, pady=(0, 22))
        return page

    # ------------------------------------------------------------------
    # Page 4: Seguridad, TOFU, Criptografía y Red
    # ------------------------------------------------------------------

    def _build_security_page(self, parent: ctk.CTkFrame) -> ctk.CTkFrame:
        page = ctk.CTkFrame(parent, fg_color=COLORS["bg"], corner_radius=0)

        hdr = ctk.CTkFrame(page, fg_color="transparent")
        hdr.pack(fill="x", padx=30, pady=(22, 10))

        ctk.CTkLabel(
            hdr,
            text="Seguridad E2EE, Confianza (TOFU) y Red",
            font=(FONT_FAMILY, 22, "bold"),
            text_color=COLORS["text"],
        ).pack(side="left")

        ctk.CTkButton(
            hdr,
            text="  Abrir Logs de Auditoría",
            image=self.icons.get("folder", 15),
            compound="left",
            height=34,
            corner_radius=8,
            font=(FONT_FAMILY, 12),
            fg_color=COLORS["surface"],
            hover_color=COLORS["surface_hover"],
            text_color=COLORS["text"],
            command=self._open_audit_folder,
        ).pack(side="right")

        card = ctk.CTkFrame(
            page,
            fg_color=COLORS["surface"],
            corner_radius=14,
            border_width=1,
            border_color=COLORS["border"],
        )
        card.pack(fill="x", padx=30, pady=(0, 12))

        specs = [
            ("Suite Criptográfica", "SPAKE2 (P-256 RFC 9382) + scrypt + X25519 + Ed25519 + AES-256-GCM"),
            ("Identidad Ed25519 Local", f"{self.identity.fingerprint} (protegida con DPAPI en Windows)"),
            ("Anti-Fuerza Bruta", f"Auto-rotación tras {MAX_AUTH_FAILURES} fallos • Modo sesión única"),
        ]
        for k, v in specs:
            row = ctk.CTkFrame(card, fg_color="transparent")
            row.pack(fill="x", padx=18, pady=4)
            ctk.CTkLabel(
                row,
                text=k,
                width=185,
                anchor="w",
                font=(FONT_FAMILY, 12, "bold"),
                text_color=COLORS["text_secondary"],
            ).pack(side="left")
            ctk.CTkLabel(
                row,
                text=v,
                anchor="w",
                font=(MONO_FONT, 11),
                text_color=COLORS["text"],
            ).pack(side="left", fill="x", expand=True)

        bore_row = ctk.CTkFrame(card, fg_color="transparent")
        bore_row.pack(fill="x", padx=18, pady=(6, 14))

        self._bore_host_entry = ctk.CTkEntry(
            bore_row,
            placeholder_text="Servidor Bore (por defecto: bore.pub)",
            height=34,
            corner_radius=8,
            fg_color=COLORS["surface_alt"],
            border_color=COLORS["border"],
        )
        self._bore_host_entry.insert(0, BORE_DEFAULT_SERVER)
        self._bore_host_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))

        self._bore_secret_entry = ctk.CTkEntry(
            bore_row,
            placeholder_text="Secreto opcional (servidor propio)",
            show="•",
            height=34,
            width=210,
            corner_radius=8,
            fg_color=COLORS["surface_alt"],
            border_color=COLORS["border"],
        )
        self._bore_secret_entry.pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            bore_row,
            text="Aplicar",
            width=84,
            height=34,
            corner_radius=8,
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            command=self._apply_bore_settings,
        ).pack(side="right")

        # Bottom split: TOFU Trusted Peers + Security Log
        split = ctk.CTkFrame(page, fg_color="transparent")
        split.pack(fill="both", expand=True, padx=30, pady=(0, 20))
        split.grid_columnconfigure(0, weight=1, uniform="scol")
        split.grid_columnconfigure(1, weight=1, uniform="scol")
        split.grid_rowconfigure(0, weight=1)

        self._tofu_list = ctk.CTkScrollableFrame(
            split,
            label_text="Equipos de Confianza (TOFU)",
            label_font=(FONT_FAMILY, 12, "bold"),
            fg_color=COLORS["surface"],
            corner_radius=12,
            border_width=1,
            border_color=COLORS["border"],
        )
        self._tofu_list.grid(row=0, column=0, sticky="nsew", padx=(0, 8))

        self._sec_log = ctk.CTkTextbox(
            split,
            font=(MONO_FONT, 11),
            fg_color=COLORS["surface"],
            text_color=COLORS["text_secondary"],
            corner_radius=12,
            border_width=1,
            border_color=COLORS["border"],
        )
        self._sec_log.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        self._sec_log.configure(state="disabled")

        self._refresh_tofu_list()
        return page

    def _refresh_tofu_list(self) -> None:
        if not hasattr(self, "_tofu_list"):
            return
        for w in self._tofu_list.winfo_children():
            w.destroy()
        peers = self.trust_store.list_peers()
        if not peers:
            ctk.CTkLabel(
                self._tofu_list,
                text="Aún no hay equipos guardados en el almacén TOFU.",
                font=(FONT_FAMILY, 11),
                text_color=COLORS["text_muted"],
            ).pack(pady=18)
            return

        for rec in peers:
            row = ctk.CTkFrame(
                self._tofu_list, fg_color=COLORS["surface_alt"], corner_radius=8
            )
            row.pack(fill="x", padx=4, pady=3)
            txt = ctk.CTkFrame(row, fg_color="transparent")
            txt.pack(side="left", fill="x", expand=True, padx=10, pady=6)
            ctk.CTkLabel(
                txt,
                text=rec.peer_name,
                font=(FONT_FAMILY, 12, "bold"),
                text_color=COLORS["text"],
            ).pack(anchor="w")
            ctk.CTkLabel(
                txt,
                text=f"{rec.fingerprint} • {rec.last_seen}",
                font=(MONO_FONT, 10),
                text_color=COLORS["text_muted"],
            ).pack(anchor="w")
            ctk.CTkButton(
                row,
                text="Revocar",
                width=68,
                height=26,
                corner_radius=6,
                font=(FONT_FAMILY, 11),
                fg_color=COLORS["surface"],
                hover_color=COLORS["danger"],
                text_color=COLORS["text"],
                command=lambda fp=rec.fingerprint: self._revoke_trusted_peer(fp),
            ).pack(side="right", padx=8)

    def _revoke_trusted_peer(self, fingerprint: str) -> None:
        if self.trust_store.revoke_peer(fingerprint):
            self.audit.record("TOFU", f"Confianza revocada para identidad {fingerprint}")
            self._log_security(f"Confianza TOFU revocada: {fingerprint}")
            self._refresh_tofu_list()

    def _open_audit_folder(self) -> None:
        AUDIT_LOG_DIR.mkdir(parents=True, exist_ok=True)
        try:
            if os.name == "nt":
                os.startfile(str(AUDIT_LOG_DIR))  # type: ignore[attr-defined]
            else:
                opener = "open" if platform.system() == "Darwin" else "xdg-open"
                subprocess.Popen([opener, str(AUDIT_LOG_DIR)])
        except Exception as exc:
            messagebox.showinfo("Auditoría", f"Logs en: {AUDIT_LOG_DIR}\n({exc})")

    # ------------------------------------------------------------------
    # Interactive TOFU Approval Helper (Thread-safe)
    # ------------------------------------------------------------------

    def _prompt_peer_approval_blocking(
        self, session_info: SessionInfo, remote_ip: str, direction_label: str
    ) -> bool:
        """Called from a worker thread; displays modal on UI thread and waits."""
        eval_res = self.trust_store.evaluate(
            session_info.peer_name,
            session_info.peer_fingerprint,
            session_info.peer_id_pub,
        )
        done = threading.Event()
        result = {"approved": False, "remember": False}

        def _show() -> None:
            dlg = SessionApprovalDialog(
                self,
                icons=self.icons,
                session_info=session_info,
                trust_eval=eval_res,
                remote_ip=remote_ip,
                direction_label=direction_label,
            )
            self.wait_window(dlg)
            result["approved"] = dlg.approved
            result["remember"] = dlg.remember_peer
            done.set()

        self.after(0, _show)
        if not done.wait(timeout=60.0):
            return False

        if result["approved"]:
            if result["remember"]:
                self.trust_store.trust_peer(
                    session_info.peer_name,
                    session_info.peer_fingerprint,
                    session_info.peer_id_pub,
                )
            elif eval_res.status == TrustStatus.TRUSTED:
                self.trust_store.touch_peer(session_info.peer_fingerprint)
            self.after(0, self._refresh_tofu_list)
        return result["approved"]

    # ------------------------------------------------------------------
    # Navigation & Theme
    # ------------------------------------------------------------------

    def _select_nav(self, key: str) -> None:
        for k, page in self._pages.items():
            if k == key:
                page.pack(fill="both", expand=True)
            else:
                page.pack_forget()
        for k, btn in self._nav_buttons.items():
            if k == key:
                btn.configure(fg_color=COLORS["accent_soft"], text_color=COLORS["accent"])
            else:
                btn.configure(fg_color="transparent", text_color=COLORS["text_secondary"])
        if key == "security":
            self._refresh_tofu_list()

    def _toggle_theme(self) -> None:
        self._is_dark = not self._is_dark
        ctk.set_appearance_mode("dark" if self._is_dark else "light")
        self._theme_btn.configure(
            text="  Modo Claro" if self._is_dark else "  Modo Oscuro",
            image=self.icons.get("sun" if self._is_dark else "moon", 16),
        )

    def _apply_bore_settings(self) -> None:
        h = self._bore_host_entry.get().strip() or BORE_DEFAULT_SERVER
        s = self._bore_secret_entry.get().strip() or None
        self._custom_bore_host = h
        self._custom_bore_secret = s
        self._log_security(f"Servidor de túnel Bore actualizado: {h}")

    def _log_security(self, msg: str) -> None:
        stamp = time.strftime("%H:%M:%S")

        def _append() -> None:
            if not hasattr(self, "_sec_log"):
                return
            self._sec_log.configure(state="normal")
            self._sec_log.insert("end", f"[{stamp}] {msg}\n")
            self._sec_log.see("end")
            self._sec_log.configure(state="disabled")

        self.after(0, _append)

    # ------------------------------------------------------------------
    # Host Temporary Server Flow
    # ------------------------------------------------------------------

    def _toggle_host_server(self) -> None:
        if self._host_server and self._host_server.is_running:
            self._stop_host_server()
            return

        mode = TUNNEL_OPTIONS.get(self._tunnel_var.get(), "auto")
        self._host_start_btn.configure(state="disabled", text="  Iniciando servidor temporal...")
        self._host_status_lbl.configure(
            text="Creando servidor temporal y negociando túnel WAN...",
            text_color=COLORS["info"],
        )

        def _worker() -> None:
            srv = TemporarySessionServer(
                identity=self.identity,
                local_role=ROLE_HOST,
                on_approve_peer=lambda info, ip: self._prompt_peer_approval_blocking(
                    info, ip, "Un equipo Huésped solicita conectarse a tu Servidor Temporal:"
                ),
                on_connected=lambda ch: self.after(0, lambda: self._open_host_studio(ch)),
                on_auth_error=lambda err: self._on_host_auth_error(err),
                on_pin_rotated=lambda np, r: self.after(
                    0, lambda: self._on_host_pin_rotated(np, r)
                ),
                on_status=lambda st: self.after(
                    0, lambda: self._host_status_lbl.configure(text=st)
                ),
            )
            try:
                info = srv.start(
                    tunnel_mode=mode,
                    custom_bore_host=self._custom_bore_host,
                    custom_bore_port=self._custom_bore_port,
                    custom_bore_secret=self._custom_bore_secret,
                )
                self._host_server = srv
                self._active_server_info = info
                self.after(0, lambda: self._on_host_server_ready(info))
            except Exception as exc:
                self.after(0, lambda err=str(exc): self._on_host_server_failed(err))

        threading.Thread(target=_worker, name="HostServerStart", daemon=True).start()

    def _on_host_server_ready(self, info: ActiveServerInfo) -> None:
        self._host_code_lbl.configure(text=info.session_code)
        self._host_pin_lbl.configure(text=info.pin)
        self._host_lan_lbl.configure(text=f"Dirección LAN alternativa: {info.lan_code}")
        self._copy_all_btn.configure(state="normal")
        self._rotate_pin_btn.configure(state="normal")

        color = COLORS["success"] if info.endpoint.is_internet else COLORS["warning"]
        scope = "ACCESO GLOBAL ACTIVO" if info.endpoint.is_internet else "MODO RED LOCAL (LAN)"
        self._host_status_lbl.configure(
            text=f"{scope} — {info.endpoint.detail}\nEsperando conexión SPAKE2 + E2EE del Huésped...",
            text_color=color,
        )
        self._endpoint_badge.configure(
            text=f"Estrategia: {info.endpoint.strategy.upper()} • Sesión única • Puerto local: {info.local_port}"
        )
        self._host_start_btn.configure(
            state="normal",
            text="  Detener Servidor Temporal",
            image=self.icons.mono("stop", 15, "#FFFFFF"),
            fg_color=COLORS["danger"],
            hover_color=COLORS["danger_hover"],
        )
        self._log_security(
            f"Servidor temporal iniciado ({info.endpoint.strategy}): {info.session_code} | LAN {info.lan_code}"
        )

    def _on_host_pin_rotated(self, new_pin: str, reason: str) -> None:
        self._host_pin_lbl.configure(text=new_pin)
        self._host_status_lbl.configure(
            text=f"PIN rotado automáticamente ({reason}). Comparte el nuevo PIN.",
            text_color=COLORS["warning"],
        )
        self._log_security(f"PIN rotado: {reason}")

    def _manual_rotate_pin(self) -> None:
        if self._host_server and self._host_server.is_running:
            self._host_server.rotate_pin("Rotación manual por el anfitrión")

    def _on_host_server_failed(self, err: str) -> None:
        self._host_status_lbl.configure(
            text=f"No se pudo iniciar: {err}", text_color=COLORS["danger"]
        )
        self._host_start_btn.configure(
            state="normal",
            text="  Iniciar Servidor Temporal",
            image=self.icons.mono("play", 16, "#FFFFFF"),
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
        )
        self._log_security(f"Error iniciando servidor temporal: {err}")

    def _stop_host_server(self) -> None:
        if self._host_server:
            self._host_server.stop()
            self._host_server = None
        self._active_server_info = None
        self._host_code_lbl.configure(text="DR-••••-••••")
        self._host_pin_lbl.configure(text="••••-••••")
        self._host_lan_lbl.configure(text="Dirección LAN alternativa: —")
        self._copy_all_btn.configure(state="disabled")
        self._rotate_pin_btn.configure(state="disabled")
        self._host_status_lbl.configure(
            text="Servidor temporal detenido y destruido.",
            text_color=COLORS["text_secondary"],
        )
        self._host_start_btn.configure(
            state="normal",
            text="  Iniciar Servidor Temporal",
            image=self.icons.mono("play", 16, "#FFFFFF"),
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
        )
        self._log_security("Servidor temporal del anfitrión detenido.")

    def _on_host_auth_error(self, err: str) -> None:
        self._log_security(f"Conexión rechazada (seguridad E2EE): {err}")
        self.after(
            0,
            lambda: self._host_status_lbl.configure(text=err, text_color=COLORS["warning"]),
        )

    def _open_host_studio(self, channel: SecureChannel) -> None:
        self._log_security(
            f"Sesión E2EE v2 aprobada con '{channel.info.peer_name}' "
            f"[{channel.info.session_fingerprint}]"
        )
        self._host_status_lbl.configure(
            text=f"Conectado con {channel.info.peer_name} (E2EE Verificado • Sesión única).",
            text_color=COLORS["success"],
        )

        def _on_studio_closed() -> None:
            self._log_security(f"Sesión cerrada con '{channel.info.peer_name}'.")
            if self._host_server and self._host_server.is_running:
                self._host_server.release_session_slot()
                self._host_server.rotate_pin("Sesión anterior finalizada")

        win = RemoteControlWindow(
            self,
            channel=channel,
            icons=self.icons,
            on_closed=_on_studio_closed,
        )
        self._remote_windows.append(win)
        win.focus_force()

    def _copy_host_code(self) -> None:
        if self._active_server_info:
            pyperclip.copy(self._active_server_info.session_code)
            self._host_status_lbl.configure(text="Código de sesión copiado al portapapeles.")

    def _copy_host_pin(self) -> None:
        if self._active_server_info:
            pyperclip.copy(self._active_server_info.pin)
            self._host_status_lbl.configure(text="PIN criptográfico copiado al portapapeles.")

    def _copy_full_invite(self) -> None:
        if not self._active_server_info:
            return
        i = self._active_server_info
        text = (
            f"Invitación DeskRemote (E2EE v2)\n"
            f"Código de Sesión: {i.session_code}\n"
            f"PIN de Acceso: {i.pin}\n"
            f"Alternativa LAN: {i.lan_code}"
        )
        pyperclip.copy(text)
        self._host_status_lbl.configure(text="Invitación completa copiada al portapapeles.")

    # ------------------------------------------------------------------
    # Guest Outbound Connection Flow (with TOFU Approval)
    # ------------------------------------------------------------------

    def _toggle_guest_connection(self) -> None:
        if self._guest_agent is not None:
            self._guest_agent.stop("Acceso revocado por el usuario huésped.")
            self._guest_agent = None
            return

        code = self._guest_code_entry.get().strip()
        pin = self._guest_pin_entry.get().strip()
        if not code or not pin:
            messagebox.showwarning(
                "Datos requeridos",
                "Ingresa el Código de Sesión y el PIN proporcionados por el Anfitrión.",
            )
            return

        self._guest_connect_btn.configure(state="disabled", text="  Verificando SPAKE2 + E2EE...")
        self._guest_status_lbl.configure(
            text="Negociando SPAKE2 (P-256) + X25519...",
            text_color=COLORS["info"],
        )

        def _worker() -> None:
            try:
                channel = connect_to_session(
                    code_or_address=code,
                    pin=pin,
                    identity=self.identity,
                    local_role=ROLE_GUEST,
                )
                approved = self._prompt_peer_approval_blocking(
                    channel.info,
                    code,
                    "Confirma conceder acceso remoto a este equipo Anfitrión:",
                )
                if not approved:
                    try:
                        send_json(
                            channel,
                            PacketType.DISCONNECT,
                            {"reason": "El huésped rechazó la sesión tras revisar la identidad."},
                        )
                    except Exception:
                        pass
                    channel.close()
                    self.after(
                        0,
                        lambda: self._on_guest_connect_error(
                            "Conexión cancelada tras verificación de identidad."
                        ),
                    )
                    return
                self.after(0, lambda: self._start_guest_agent(channel))
            except Exception as exc:
                self.after(0, lambda err=str(exc): self._on_guest_connect_error(err))

        threading.Thread(target=_worker, name="GuestConnect", daemon=True).start()

    def _start_guest_agent(self, channel: SecureChannel) -> None:
        perms = GuestPermissions(**{k: v.get() for k, v in self._perm_vars.items()})
        self._guest_agent = GuestAgent(
            channel=channel,
            permissions=perms,
            on_audit=lambda m: self._append_guest_log(f"[AUDIT] {m}"),
            on_chat=lambda s, t: self._append_guest_log(f"[CHAT] {s}: {t}"),
            on_disconnect=lambda r: self.after(0, lambda: self._on_guest_disconnected(r)),
        )
        self._guest_agent.start()

        self._guest_status_lbl.configure(
            text=f"CONTROL ACTIVO POR: {channel.info.peer_name}",
            text_color=COLORS["success"],
        )
        self._guest_fp_lbl.configure(
            text=f"Huella E2EE verificada: {channel.info.session_fingerprint}",
            text_color=COLORS["success"],
        )
        self._guest_connect_btn.configure(
            state="normal",
            text="  Revocar Acceso y Desconectar",
            image=self.icons.mono("stop", 15, "#FFFFFF"),
            fg_color=COLORS["danger"],
            hover_color=COLORS["danger_hover"],
        )
        self._append_guest_log(
            f"Sesión E2EE v2 aprobada con '{channel.info.peer_name}' [{channel.info.session_fingerprint}]"
        )
        self._log_security(
            f"Modo Huésped activo con anfitrión '{channel.info.peer_name}' [{channel.info.session_fingerprint}]"
        )

    def _on_guest_connect_error(self, err: str) -> None:
        self._guest_status_lbl.configure(
            text=f"Error de conexión: {err}", text_color=COLORS["danger"]
        )
        self._guest_connect_btn.configure(
            state="normal",
            text="  Conectar y Compartir Acceso Total",
            image=self.icons.mono("play", 15, "#FFFFFF"),
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
        )
        self._append_guest_log(f"[ERROR] {err}")

    def _on_guest_disconnected(self, reason: str) -> None:
        self._guest_agent = None
        if self._guest_server and self._guest_server.is_running:
            self._guest_server.release_session_slot()
            self._guest_server.rotate_pin("Sesión anterior finalizada")
        self._guest_status_lbl.configure(
            text="Sin sesión remota activa", text_color=COLORS["text"]
        )
        self._guest_fp_lbl.configure(
            text="Huella de sesión E2EE: —", text_color=COLORS["text_muted"]
        )
        self._guest_connect_btn.configure(
            state="normal",
            text="  Conectar y Compartir Acceso Total",
            image=self.icons.mono("play", 15, "#FFFFFF"),
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
        )
        self._append_guest_log(f"[FIN] {reason}")

    def _sync_guest_permissions(self) -> None:
        if self._guest_agent is None:
            return
        for k, var in self._perm_vars.items():
            setattr(self._guest_agent.permissions, k, var.get())
        self._guest_agent.update_permissions()

    def _append_guest_log(self, line: str) -> None:
        stamp = time.strftime("%H:%M:%S")

        def _do() -> None:
            self._guest_log.configure(state="normal")
            self._guest_log.insert("end", f"[{stamp}] {line}\n")
            self._guest_log.see("end")
            self._guest_log.configure(state="disabled")

        self.after(0, _do)

    def _guest_send_chat(self, _event=None) -> None:
        txt = self._guest_chat_entry.get().strip()
        if not txt or self._guest_agent is None:
            return
        self._guest_chat_entry.delete(0, "end")
        self._guest_agent.send_chat(txt)
        self._append_guest_log(f"[CHAT] Tú: {txt}")

    # ------------------------------------------------------------------
    # Direct Mode Flows (with TOFU Approval)
    # ------------------------------------------------------------------

    def _direct_connect_as_host(self) -> None:
        code = self._direct_code.get().strip()
        pin = self._direct_pin.get().strip()
        if not code or not pin:
            messagebox.showwarning("Conexión Directa", "Ingresa código/dirección y PIN.")
            return
        self._direct_btn.configure(state="disabled", text="  Conectando...")

        def _worker() -> None:
            try:
                ch = connect_to_session(code, pin, self.identity, ROLE_HOST)
                approved = self._prompt_peer_approval_blocking(
                    ch.info, code, "Confirma iniciar control sobre este equipo Huésped:"
                )
                if not approved:
                    ch.close()
                    self.after(
                        0, lambda: self._on_direct_host_err("Conexión cancelada por el usuario.")
                    )
                    return
                self.after(0, lambda: self._on_direct_host_ok(ch))
            except Exception as exc:
                self.after(0, lambda e=str(exc): self._on_direct_host_err(e))

        threading.Thread(target=_worker, daemon=True).start()

    def _on_direct_host_ok(self, ch: SecureChannel) -> None:
        self._direct_btn.configure(state="normal", text="  Conectar y Controlar")
        self._open_host_studio(ch)

    def _on_direct_host_err(self, err: str) -> None:
        self._direct_btn.configure(state="normal", text="  Conectar y Controlar")
        messagebox.showerror("Error de conexión", err)

    def _toggle_guest_listener(self) -> None:
        if self._guest_server and self._guest_server.is_running:
            self._guest_server.stop()
            self._guest_server = None
            self._guest_srv_info.configure(text="Código: —   |   PIN: —")
            self._guest_listen_btn.configure(text="  Abrir Escucha Temporal")
            return

        self._guest_listen_btn.configure(state="disabled", text="  Iniciando escucha...")

        def _worker() -> None:
            srv = TemporarySessionServer(
                identity=self.identity,
                local_role=ROLE_GUEST,
                on_approve_peer=lambda info, ip: self._prompt_peer_approval_blocking(
                    info, ip, "Un equipo Anfitrión solicita control total sobre este equipo:"
                ),
                on_connected=lambda ch: self.after(0, lambda: self._on_direct_guest_accepted(ch)),
                on_auth_error=lambda err: self._log_security(f"Escucha Huésped rechazó intento: {err}"),
                on_pin_rotated=lambda np, r: self.after(
                    0,
                    lambda: self._guest_srv_info.configure(
                        text=f"Código: {srv.info.session_code if srv.info else '—'}   |   PIN: {np}"
                    ),
                ),
            )
            try:
                info = srv.start(tunnel_mode="auto")
                self._guest_server = srv
                self.after(
                    0,
                    lambda: (
                        self._guest_srv_info.configure(
                            text=f"Código: {info.session_code}   |   PIN: {info.pin}"
                        ),
                        self._guest_listen_btn.configure(
                            state="normal", text="  Detener Escucha Temporal"
                        ),
                    ),
                )
            except Exception as exc:
                self.after(
                    0,
                    lambda e=str(exc): (
                        self._guest_listen_btn.configure(
                            state="normal", text="  Abrir Escucha Temporal"
                        ),
                        messagebox.showerror("Error", e),
                    ),
                )

        threading.Thread(target=_worker, daemon=True).start()

    def _on_direct_guest_accepted(self, ch: SecureChannel) -> None:
        self._select_nav("guest")
        self._start_guest_agent(ch)

    # ------------------------------------------------------------------
    # Clean Shutdown
    # ------------------------------------------------------------------

    def _on_app_close(self) -> None:
        for w in list(self._remote_windows):
            try:
                w.close_session()
            except Exception:
                pass
        if self._guest_agent:
            try:
                self._guest_agent.stop("Aplicación cerrada.")
            except Exception:
                pass
        if self._host_server:
            self._host_server.stop()
        if self._guest_server:
            self._guest_server.stop()
        self.destroy()
