"""Start vaultkit with Windows (in the tray), via the per-user Run key.

HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run is the standard per-user autostart
location: no admin rights, visible in Task Manager's Startup tab, removable there too.
Stdlib only (winreg). Every function is a safe no-op off Windows.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
VALUE = "vaultkit"
LEGACY_SHORTCUT = "vaultkit check.lnk"  # the cmd-window Startup shortcut from before the tray


def supported() -> bool:
    return os.name == "nt"


class _WinReg:
    """Thin wrapper so tests can swap in a fake registry."""

    def __init__(self) -> None:
        import winreg
        self.w = winreg

    def get(self) -> str | None:
        try:
            with self.w.OpenKey(self.w.HKEY_CURRENT_USER, RUN_KEY) as k:
                return self.w.QueryValueEx(k, VALUE)[0]
        except FileNotFoundError:
            return None

    def set(self, command: str) -> None:
        with self.w.CreateKey(self.w.HKEY_CURRENT_USER, RUN_KEY) as k:
            self.w.SetValueEx(k, VALUE, 0, self.w.REG_SZ, command)

    def delete(self) -> None:
        try:
            with self.w.OpenKey(self.w.HKEY_CURRENT_USER, RUN_KEY, 0, self.w.KEY_SET_VALUE) as k:
                self.w.DeleteValue(k, VALUE)
        except FileNotFoundError:
            pass


_registry = None


def registry():
    global _registry
    if _registry is None:
        _registry = _WinReg()
    return _registry


def pythonw() -> Path:
    """The interpreter that runs without a console window (pythonw.exe beside python.exe)."""
    exe = Path(sys.executable)
    if exe.name.lower() == "python.exe":
        windowless = exe.with_name("pythonw.exe")
        if windowless.exists():
            return windowless
    return exe


def command(launcher: Path) -> str:
    """pythonw (no console window) + launcher.py --tray (start hidden in the tray)."""
    return f'"{pythonw()}" "{Path(launcher).resolve()}" --tray'


def is_enabled() -> bool:
    return supported() and registry().get() is not None


def enable(launcher: Path) -> None:
    if not supported():
        return
    registry().set(command(launcher))
    remove_legacy_shortcut()


def disable() -> None:
    if supported():
        registry().delete()


def refresh(launcher: Path) -> None:
    """Keep the entry pointing at this install (e.g. after the folder was moved)."""
    if is_enabled() and registry().get() != command(launcher):
        registry().set(command(launcher))


def remove_legacy_shortcut() -> bool:
    """The tray does the daily check now; the old cmd-window shortcut would run it twice."""
    appdata = os.environ.get("APPDATA")
    if not appdata:
        return False
    lnk = Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup" / LEGACY_SHORTCUT
    if lnk.exists():
        lnk.unlink()
        return True
    return False
