"""Start-menu and project-folder shortcuts on Windows.

Created with PowerShell's WScript.Shell COM object (built into Windows, no extra packages).
Values are passed through environment variables, never spliced into the script, so paths
with spaces or quotes can't break it. Shortcuts are only rewritten when the install
location, interpreter or icon changed (recorded in shortcuts.json), so startup stays fast.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import autostart

NAME = "vaultkit.lnk"
FOLDER_NAME = "Open vaultkit.lnk"
DESCRIPTION = "Check your passwords for breaches and fix them"
_NO_WINDOW = {"creationflags": 0x08000000} if os.name == "nt" else {}

_PS = r"""
$s = (New-Object -ComObject WScript.Shell).CreateShortcut($env:VK_LNK)
$s.TargetPath = $env:VK_TARGET
$s.Arguments = $env:VK_ARGS
$s.WorkingDirectory = $env:VK_DIR
$s.IconLocation = $env:VK_ICON
$s.Description = $env:VK_DESC
$s.Save()
"""


def supported() -> bool:
    return os.name == "nt"


def data_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    d = Path(base) / "vaultkit"
    d.mkdir(parents=True, exist_ok=True)
    return d


def start_menu_dir() -> Path:
    return Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs"


def targets(app_dir: Path) -> list[Path]:
    """Start menu always; the project folder's 'Open vaultkit' when installed as <root>\\app."""
    out = [start_menu_dir() / NAME]
    if app_dir.name.lower() == "app":
        out.append(app_dir.parent / FOLDER_NAME)
    return out


def create(lnk: Path, target: Path, args: str, workdir: Path, icon: Path) -> None:
    env = dict(os.environ, VK_LNK=str(lnk), VK_TARGET=str(target), VK_ARGS=args,
               VK_DIR=str(workdir), VK_ICON=f"{icon},0", VK_DESC=DESCRIPTION)
    lnk.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", _PS],
                   env=env, check=True, capture_output=True, **_NO_WINDOW)


def ensure(app_dir: Path, icon: Path) -> list[Path]:
    """Create/refresh shortcuts if anything they point at changed. Returns what was written."""
    if not supported():
        return []
    app_dir = Path(app_dir).resolve()
    launcher = app_dir / "launcher.py"
    want = targets(app_dir)
    stamp = json.dumps({"app": str(app_dir), "python": str(autostart.pythonw()),
                        "icon": str(icon), "links": [str(p) for p in want]}, sort_keys=True)
    marker = data_dir() / "shortcuts.json"
    if marker.exists() and marker.read_text("utf-8") == stamp and all(p.exists() for p in want):
        return []
    for lnk in want:
        create(lnk, autostart.pythonw(), f'"{launcher}"', app_dir, icon)
    marker.write_text(stamp, "utf-8")
    return want


def remove_all(app_dir: Path) -> list[Path]:
    removed = []
    for lnk in targets(Path(app_dir).resolve()):
        if lnk.exists():
            lnk.unlink()
            removed.append(lnk)
    marker = data_dir() / "shortcuts.json"
    if marker.exists():
        marker.unlink()
    return removed
