"""Remote mouse & keyboard input injection controller (Guest side)."""

from __future__ import annotations

import ctypes
import os
import time
from typing import Any

from pynput.keyboard import Controller as KeyboardController
from pynput.keyboard import Key
from pynput.mouse import Button
from pynput.mouse import Controller as MouseController

# Map Tkinter keysyms to pynput Key constants
KEYSYM_MAP: dict[str, Key] = {
    "Return": Key.enter,
    "KP_Enter": Key.enter,
    "BackSpace": Key.backspace,
    "Tab": Key.tab,
    "ISO_Left_Tab": Key.tab,
    "Escape": Key.esc,
    "space": Key.space,
    "Delete": Key.delete,
    "Insert": Key.insert,
    "Home": Key.home,
    "End": Key.end,
    "Prior": Key.page_up,
    "Next": Key.page_down,
    "Up": Key.up,
    "Down": Key.down,
    "Left": Key.left,
    "Right": Key.right,
    "Shift_L": Key.shift_l,
    "Shift_R": Key.shift_r,
    "Control_L": Key.ctrl_l,
    "Control_R": Key.ctrl_r,
    "Alt_L": Key.alt_l,
    "Alt_R": Key.alt_r,
    "Super_L": Key.cmd_l,
    "Super_R": Key.cmd_r,
    "Win_L": Key.cmd_l,
    "Win_R": Key.cmd_r,
    "Caps_Lock": Key.caps_lock,
    "Num_Lock": Key.num_lock,
    "Scroll_Lock": Key.scroll_lock,
    "Print": Key.print_screen,
    "Pause": Key.pause,
    "Menu": Key.menu,
    "F1": Key.f1,
    "F2": Key.f2,
    "F3": Key.f3,
    "F4": Key.f4,
    "F5": Key.f5,
    "F6": Key.f6,
    "F7": Key.f7,
    "F8": Key.f8,
    "F9": Key.f9,
    "F10": Key.f10,
    "F11": Key.f11,
    "F12": Key.f12,
}

BUTTON_MAP: dict[str, Button] = {
    "left": Button.left,
    "right": Button.right,
    "middle": Button.middle,
}

SHORTCUT_COMBOS: dict[str, list[Key | str]] = {
    "win": [Key.cmd],
    "alt_tab": [Key.alt, Key.tab],
    "alt_f4": [Key.alt, Key.f4],
    "ctrl_shift_esc": [Key.ctrl, Key.shift, Key.esc],
    "win_r": [Key.cmd, "r"],
    "win_d": [Key.cmd, "d"],
    "win_e": [Key.cmd, "e"],
    "ctrl_c": [Key.ctrl, "c"],
    "ctrl_v": [Key.ctrl, "v"],
    "ctrl_a": [Key.ctrl, "a"],
    "ctrl_z": [Key.ctrl, "z"],
}


class InputInjector:
    """Injects normalized mouse and keyboard events on the local OS."""

    def __init__(self) -> None:
        self._mouse = MouseController()
        self._keyboard = KeyboardController()

    @staticmethod
    def _to_abs_coords(
        nx: float, ny: float, monitor_rect: dict[str, int]
    ) -> tuple[int, int]:
        nx = max(0.0, min(1.0, float(nx)))
        ny = max(0.0, min(1.0, float(ny)))
        x = int(monitor_rect["left"] + nx * max(1, monitor_rect["width"] - 1))
        y = int(monitor_rect["top"] + ny * max(1, monitor_rect["height"] - 1))
        return x, y

    @staticmethod
    def _resolve_key(keysym: str, char: str) -> Key | str | None:
        if keysym in KEYSYM_MAP:
            return KEYSYM_MAP[keysym]
        if char and len(char) == 1 and ord(char) >= 32:
            return char
        if len(keysym) == 1:
            return keysym
        return None

    def handle_event(self, event: dict[str, Any], monitor_rect: dict[str, int]) -> None:
        kind = event.get("kind", "")

        if kind == "mouse_move":
            x, y = self._to_abs_coords(event["nx"], event["ny"], monitor_rect)
            self._mouse.position = (x, y)

        elif kind == "mouse_down":
            x, y = self._to_abs_coords(event["nx"], event["ny"], monitor_rect)
            self._mouse.position = (x, y)
            btn = BUTTON_MAP.get(event.get("button", "left"), Button.left)
            self._mouse.press(btn)

        elif kind == "mouse_up":
            x, y = self._to_abs_coords(event["nx"], event["ny"], monitor_rect)
            self._mouse.position = (x, y)
            btn = BUTTON_MAP.get(event.get("button", "left"), Button.left)
            self._mouse.release(btn)

        elif kind == "mouse_dblclick":
            x, y = self._to_abs_coords(event["nx"], event["ny"], monitor_rect)
            self._mouse.position = (x, y)
            btn = BUTTON_MAP.get(event.get("button", "left"), Button.left)
            self._mouse.click(btn, 2)

        elif kind == "mouse_scroll":
            dx = int(event.get("dx", 0))
            dy = int(event.get("dy", 0))
            self._mouse.scroll(dx, dy)

        elif kind == "key_down":
            key = self._resolve_key(event.get("keysym", ""), event.get("char", ""))
            if key is not None:
                try:
                    self._keyboard.press(key)
                except Exception:
                    pass

        elif kind == "key_up":
            key = self._resolve_key(event.get("keysym", ""), event.get("char", ""))
            if key is not None:
                try:
                    self._keyboard.release(key)
                except Exception:
                    pass

        elif kind == "type_text":
            text = str(event.get("text", ""))
            if text:
                self._keyboard.type(text)

        elif kind == "hotkey":
            combo_name = event.get("combo", "")
            if combo_name == "win_l" and os.name == "nt":
                try:
                    ctypes.windll.user32.LockWorkStation()
                    return
                except Exception:
                    pass
            keys = SHORTCUT_COMBOS.get(combo_name)
            if keys:
                self._press_combo(keys)

    def _press_combo(self, keys: list[Key | str]) -> None:
        pressed: list[Key | str] = []
        try:
            for k in keys:
                self._keyboard.press(k)
                pressed.append(k)
                time.sleep(0.02)
        finally:
            for k in reversed(pressed):
                try:
                    self._keyboard.release(k)
                except Exception:
                    pass
