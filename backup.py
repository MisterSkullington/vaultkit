"""Copies of the vault kept off this PC: OneDrive by default.

The .kdbx file is encrypted, so a copy is exactly as safe as the vault itself (master
password + Argon2id). vaultkit copies it when it has changed since the last copy, checks
the copy, and keeps the newest KEEP copies. OneDrive adds its own 30-day version history.

What's in OneDrive is never read back: with Files On-Demand, reading old copies would
download them all. The fingerprint of the last copy lives in %LOCALAPPDATA%\\vaultkit.
Stdlib only.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

KEEP = 30
FOLDER = "vaultkit backups"
_NAME = re.compile(r"^(?P<stem>.+)-(?P<stamp>\d{8}-\d{6})(?:-\d+)?\.kdbx$")
SIGNATURE = bytes.fromhex("03d9a29a67fb4bb5")  # KDBX file signature, little-endian


class BackupError(RuntimeError):
    pass


def onedrive_dir() -> Path | None:
    """The OneDrive folder Windows tells programs about, else <home>\\OneDrive."""
    for var in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial"):
        value = os.environ.get(var)
        if value and Path(value).is_dir():
            return Path(value)
    home = Path.home() / "OneDrive"
    return home if home.is_dir() else None


def default_target() -> Path | None:
    d = onedrive_dir()
    return d / FOLDER if d else None


def _state_path() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    d = Path(base) / "vaultkit"
    d.mkdir(parents=True, exist_ok=True)
    return d / "backup.json"


def _load_state() -> dict:
    try:
        data = json.loads(_state_path().read_text("utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_state(state: dict) -> None:
    path = _state_path()
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2), "utf-8")
    os.replace(tmp, path)


def copies(target: Path, stem: str) -> list[Path]:
    """This vault's copies in target, newest first. Other files are never touched."""
    try:
        found = [p for p in target.iterdir() if p.is_file()
                 and (m := _NAME.match(p.name)) and m["stem"] == stem]
    except OSError:
        return []
    return sorted(found, key=lambda p: p.name, reverse=True)


@dataclass(frozen=True)
class Status:
    target: Path | None
    last_at: datetime | None    # when the last copy was made
    last_path: Path | None
    up_to_date: bool            # the vault hasn't changed since that copy
    count: int


def status(vault: str | Path, target: Path | None) -> Status:
    vault = Path(vault)
    state = _load_state().get(str(vault.resolve()), {})
    last_at = None
    try:
        last_at = datetime.fromisoformat(state["at"]) if state.get("at") else None
    except ValueError:
        pass
    last_path = Path(state["path"]) if state.get("path") else None
    up_to_date = False
    if last_path is not None and target is not None and last_path.parent == target \
            and last_path.exists():
        try:
            up_to_date = _sha256(vault.read_bytes()) == state.get("sha256")
        except OSError:
            pass
    count = len(copies(target, vault.stem)) if target else 0
    return Status(target, last_at, last_path, up_to_date, count)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def backup(vault: str | Path, target: str | Path, keep: int = KEEP,
           now: datetime | None = None) -> Path | None:
    """Copy the vault into target if it changed since the last copy. Returns the new copy,
    or None if nothing changed. Raises BackupError if it can't be done safely."""
    vault, target = Path(vault), Path(target)
    try:
        data = vault.read_bytes()
    except OSError as e:
        raise BackupError(f"Can't read the vault: {e.strerror or e}.")
    if not data.startswith(SIGNATURE):
        raise BackupError(f"{vault.name} doesn't look like a KeePass vault, so it wasn't copied.")
    digest = _sha256(data)
    states = _load_state()
    key = str(vault.resolve())
    mine = states.get(key, {})
    last = Path(mine["path"]) if mine.get("path") else None
    if mine.get("sha256") == digest and last is not None and last.parent == target \
            and last.exists():
        return None  # unchanged since the last copy, and that copy is still there

    try:
        target.mkdir(parents=True, exist_ok=True)
        stamp = (now or datetime.now()).strftime("%Y%m%d-%H%M%S")
        dest, n = target / f"{vault.stem}-{stamp}.kdbx", 2
        while dest.exists():
            dest, n = target / f"{vault.stem}-{stamp}-{n}.kdbx", n + 1
        tmp = target / f".{dest.name}.partial"
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if _sha256(tmp.read_bytes()) != digest:
            tmp.unlink(missing_ok=True)
            raise BackupError("The copy didn't match the vault, so it was discarded.")
        os.replace(tmp, dest)
    except OSError as e:
        raise BackupError(f"Couldn't write to {target}: {e.strerror or e}.")

    states[key] = {"sha256": digest, "path": str(dest),
                   "at": (now or datetime.now()).isoformat(timespec="seconds")}
    _save_state(states)
    for old in copies(target, vault.stem)[keep:]:
        try:
            old.unlink()
        except OSError:
            pass  # in use or offline: tried again next time
    return dest
