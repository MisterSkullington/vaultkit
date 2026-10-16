"""Remove vaultkit's footprint from this PC. Never touches your vault.

  py -3.13 launcher.py --uninstall

Removes: Start with Windows, Start-menu and folder shortcuts, the saved master password,
app settings, update staging/backups/logs, the last check report.
Keeps:   your vault (and its folder), the app folder itself (delete it when this finishes),
         and your release signing key + update.json if this is the PC you publish from.
"""
from __future__ import annotations

import shutil
from pathlib import Path
from typing import Callable

import autostart
import secretstore
import shortcuts
import updater

KEEP = {"release-signing.key", "update.json"}  # publisher PC: losing these stops releases


def plan(app_dir: Path) -> list[str]:
    data = updater.data_dir()
    publisher = (data / "release-signing.key").exists()
    lines = ["Start with Windows (if on)", "Start-menu and folder shortcuts",
             "saved master password (if saved)", "app settings (theme, vault path, schedule)",
             f"update downloads, backups, logs and the last check report in {data}"]
    if not publisher:
        lines.append("this PC's update key (update.json)")
    return lines


def uninstall(app_dir: Path, confirm: Callable[[str], str] = input,
              clear_settings: Callable[[], None] | None = None) -> int:
    app_dir = Path(app_dir).resolve()
    data = updater.data_dir()
    publisher = (data / "release-signing.key").exists()
    print("This removes vaultkit's footprint from this PC:")
    for line in plan(app_dir):
        print(f"  - {line}")
    print("It does NOT touch your vault or KeePassXC.")
    if confirm("Type 'uninstall' to continue: ").strip().lower() != "uninstall":
        print("Nothing changed.")
        return 1

    autostart.disable()
    shortcuts.remove_all(app_dir)
    autostart.remove_legacy_shortcut()
    secretstore.forget()
    if clear_settings:
        clear_settings()
    for item in data.iterdir() if data.is_dir() else []:
        if publisher and item.name in KEEP:
            continue
        if item.suffix == ".kdbx":  # belt and braces: never delete a vault, wherever it is
            continue
        if item.is_dir():
            shutil.rmtree(item, ignore_errors=True)
        else:
            item.unlink(missing_ok=True)

    print("\nDone.")
    if publisher:
        print(f"Kept your release signing key and update.json in {data}: they're what let "
              "you publish updates. Delete that folder too if you'll never publish again.")
    print(f"Your vault was not touched. To finish, delete the app folder: {app_dir}")
    return 0
