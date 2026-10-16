#!/usr/bin/env python3
"""Find, install and set up KeePassXC the recommended way.

- find_cli(): KeePassXC wherever it's installed. Nothing needs to be on PATH.
- install_keepassxc(): the latest official Windows installer from KeePassXC's GitHub
  releases. Before it runs, its SHA-256 must match the release's .DIGEST file AND Windows
  must confirm it's signed by KeePassXC's code-signing company (DroidMonkey Apps, LLC).
  One Windows permission prompt; KeePassXC installs for all users.
- Settings: the recommended KeePassXC settings, changed only where they differ, only while
  KeePassXC is closed (it rewrites its settings file when it quits), with a backup first.
- Connector: what KeePassXC's own "Chrome" checkbox registers. Opera, Opera GX, Brave and
  Vivaldi read Chrome's registry key too.
- vault_info(): reads a .kdbx file's unencrypted header (no password needed): format, key
  derivation function and how much memory it uses.
- create_vault(): keepassxc-cli db-create. That can't choose Argon2id (it makes KDBX 3.1 with
  AES-KDF), so vault_info() plus a one-screen guide in KeePassXC finish the job.

Stdlib only: install.ps1 runs this with `python -I` before anything else is set up.
Run it directly:  python kpsetup.py check | install | apply   (see --help)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable

REPO = "keepassxreboot/keepassxc"
RELEASE_API = f"https://api.github.com/repos/{REPO}/releases/latest"
DOWNLOAD_PREFIX = f"https://github.com/{REPO}/releases/download/"
SIGNER = "DroidMonkey Apps, LLC"   # the certificate KeePassXC's Windows installers are signed with
MIN_VERSION = (2, 7, 0)
MAX_MSI_BYTES = 300 * 1024 * 1024
USER_AGENT = "vaultkit-setup"
EXTENSION_URL = ("https://chromewebstore.google.com/detail/keepassxc-browser/"
                 "oboonakemofpalcgghocfoadofidjkkk")
MIN_MEMORY_MIB = 256
_NO_WINDOW = {"creationflags": 0x08000000} if os.name == "nt" else {}  # CREATE_NO_WINDOW


class SetupError(RuntimeError):
    pass


def supported() -> bool:
    return os.name == "nt"


def data_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    d = Path(base) / "vaultkit"
    d.mkdir(parents=True, exist_ok=True)
    return d


# ---------------------------------------------------------------------------- registry
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
UNINSTALL_KEYS = (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                  r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")


class _WinReg:
    """HKCU values (name "" = the key's default value), plus a read of HKLM's uninstall list.
    A thin wrapper so tests can swap in a fake."""

    def __init__(self) -> None:
        import winreg
        self.w = winreg

    def get(self, key: str, name: str) -> str | None:
        try:
            with self.w.OpenKey(self.w.HKEY_CURRENT_USER, key) as k:
                return str(self.w.QueryValueEx(k, name)[0])
        except OSError:
            return None

    def set(self, key: str, name: str, value: str) -> None:
        with self.w.CreateKey(self.w.HKEY_CURRENT_USER, key) as k:
            self.w.SetValueEx(k, name, 0, self.w.REG_SZ, value)

    def delete(self, key: str, name: str) -> None:
        try:
            with self.w.OpenKey(self.w.HKEY_CURRENT_USER, key, 0, self.w.KEY_SET_VALUE) as k:
                self.w.DeleteValue(k, name)
        except OSError:
            pass

    def install_location(self) -> str | None:
        for root in UNINSTALL_KEYS:
            try:
                with self.w.OpenKey(self.w.HKEY_LOCAL_MACHINE, root) as k:
                    for i in range(self.w.QueryInfoKey(k)[0]):
                        try:
                            with self.w.OpenKey(k, self.w.EnumKey(k, i)) as app:
                                name = str(self.w.QueryValueEx(app, "DisplayName")[0])
                                if name.startswith("KeePassXC"):
                                    loc = str(self.w.QueryValueEx(app, "InstallLocation")[0])
                                    if loc:
                                        return loc
                        except OSError:
                            continue
            except OSError:
                continue
        return None


class _NoReg:
    def get(self, key: str, name: str) -> str | None:
        return None

    def set(self, key: str, name: str, value: str) -> None:
        raise SetupError("This part of the setup is for Windows.")

    def delete(self, key: str, name: str) -> None:
        pass

    def install_location(self) -> str | None:
        return None


_registry = None


def registry():
    global _registry
    if _registry is None:
        _registry = _WinReg() if supported() else _NoReg()
    return _registry


# ---------------------------------------------------------------------------- find
def _install_dirs() -> list[Path]:
    dirs = [Path(os.environ[v]) / "KeePassXC"
            for v in ("ProgramFiles", "ProgramW6432", "ProgramFiles(x86)") if os.environ.get(v)]
    if os.environ.get("LOCALAPPDATA"):
        dirs.append(Path(os.environ["LOCALAPPDATA"]) / "Programs" / "KeePassXC")
    loc = registry().install_location()
    if loc:
        dirs.append(Path(loc))
    return dirs


def find_cli() -> Path | None:
    """keepassxc-cli: on PATH, else in the usual install folders, else where Windows says."""
    hit = shutil.which("keepassxc-cli")
    if hit:
        return Path(hit)
    exe = "keepassxc-cli.exe" if os.name == "nt" else "keepassxc-cli"
    for d in _install_dirs():
        if (d / exe).is_file():
            return d / exe
    return None


def _cmd(cli) -> list[str]:
    """A CLI given as a path, or as a command prefix (tests: [python, fake_kpcli.py])."""
    return [str(c) for c in cli] if isinstance(cli, (list, tuple)) else [str(cli)]


def gui_exe(cli: Path) -> Path:
    return Path(cli).with_name("KeePassXC.exe" if os.name == "nt" else "keepassxc")


def cli_version(cli) -> tuple[int, ...] | None:
    try:
        out = subprocess.run(_cmd(cli) + ["--version"], capture_output=True, stdin=subprocess.DEVNULL,
                             timeout=60, **_NO_WINDOW).stdout.decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", out)
    return tuple(int(x) for x in m.groups()) if m else None


def version_text(v: tuple[int, ...] | None) -> str:
    return ".".join(map(str, v)) if v else "unknown"


# ---------------------------------------------------------------------------- download
def _open(url: str, timeout: float = 60):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    return urllib.request.urlopen(req, timeout=timeout)


def http_get(url: str, limit: int = 4 * 1024 * 1024) -> bytes:
    with _open(url) as r:
        data = r.read(limit + 1)
    if len(data) > limit:
        raise SetupError(f"Unexpectedly large response from {url}.")
    return data


def download(url: str, dest: Path, limit: int = MAX_MSI_BYTES) -> str:
    """Stream to dest (via a .part file); returns its SHA-256."""
    h, size = hashlib.sha256(), 0
    part = dest.with_name(dest.name + ".part")
    with _open(url, timeout=120) as r, open(part, "wb") as f:
        while chunk := r.read(1 << 20):
            size += len(chunk)
            if size > limit:
                f.close()
                part.unlink(missing_ok=True)
                raise SetupError("The download was unexpectedly large, so it was stopped.")
            h.update(chunk)
            f.write(chunk)
    os.replace(part, dest)
    return h.hexdigest()


@dataclass(frozen=True)
class Release:
    version: str
    msi_name: str
    msi_url: str
    digest_url: str


def latest_release(raw: bytes | None = None) -> Release:
    """KeePassXC's latest stable release and its Windows installer (from GitHub's API)."""
    try:
        data = json.loads(raw if raw is not None else http_get(RELEASE_API))
    except ValueError:
        raise SetupError("GitHub sent an unreadable answer about KeePassXC's latest release.")
    tag = str(data.get("tag_name", "")).lstrip("vV")
    if not re.fullmatch(r"\d+\.\d+\.\d+", tag):
        raise SetupError(f"Unexpected KeePassXC release name: {tag or 'none'}.")
    name = f"KeePassXC-{tag}-Win64.msi"
    assets = {a.get("name"): str(a.get("browser_download_url", ""))
              for a in data.get("assets", []) if isinstance(a, dict)}
    msi, digest = assets.get(name), assets.get(name + ".DIGEST")
    if not msi or not digest:
        raise SetupError(f"KeePassXC {tag} has no Windows installer with a checksum on GitHub yet.")
    for url in (msi, digest):
        if not url.startswith(DOWNLOAD_PREFIX):
            raise SetupError(f"Refusing a download from outside KeePassXC's releases: {url}")
    return Release(tag, name, msi, digest)


def parse_digest(text: str, name: str) -> str:
    """'<sha256>  <file name>' lines, as KeePassXC's release tool writes them."""
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip("*") == name \
                and re.fullmatch(r"[0-9a-fA-F]{64}", parts[0]):
            return parts[0].lower()
    raise SetupError("KeePassXC's checksum file doesn't list the installer.")


_SIGNATURE_PS = r"""
$s = Get-AuthenticodeSignature -LiteralPath $env:VK_FILE
$n = ''
if ($s.SignerCertificate) {
  $n = $s.SignerCertificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
}
[pscustomobject]@{ status = [string]$s.Status; signer = $n } | ConvertTo-Json -Compress
"""


def authenticode(path: Path) -> tuple[str, str]:
    """(status, signer name) from Windows' own signature check."""
    r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", _SIGNATURE_PS],
                       env=dict(os.environ, VK_FILE=str(path)), capture_output=True,
                       stdin=subprocess.DEVNULL, timeout=180, **_NO_WINDOW)
    try:
        d = json.loads(r.stdout.decode("utf-8", "replace").strip() or "{}")
    except ValueError:
        d = {}
    return str(d.get("status", "")), str(d.get("signer", ""))


def check_signature(path: Path) -> None:
    status, signer = authenticode(path)
    if status != "Valid" or signer != SIGNER:
        raise SetupError(
            f"STOPPED: the downloaded installer isn't signed by KeePassXC ({SIGNER}). Windows "
            f"says: {status or 'no signature'}, signed by {signer or 'nobody'}. Nothing was "
            "installed.")


_ELEVATE_PS = r"""
try {
  $p = Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" -ArgumentList $env:VK_ARGS -Verb RunAs -PassThru
} catch { exit 1223 }
$null = $p.Handle
$p.WaitForExit()
exit $p.ExitCode
"""
MSI_OK = (0, 1641, 3010)
MSI_MESSAGES = {
    1223: "You chose No on the Windows prompt, so KeePassXC wasn't installed.",
    1602: "The installation was cancelled.",
    1618: "Another installation is running. Wait for it to finish, then try again.",
    1925: "Installing KeePassXC needs an administrator account on this PC.",
}


def run_msi(msi: Path, log: Path, quiet: bool = False) -> int:
    """msiexec, elevated (one Windows prompt). KeePassXC starts with Windows afterwards,
    but doesn't open now."""
    ui = "/qn" if quiet else "/passive"
    args = (f'/i "{msi}" {ui} /norestart AUTOSTARTPROGRAM=1 LAUNCHAPPONEXIT=0 '
            f'/l*v "{log}"')
    r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
                        "Bypass", "-Command", _ELEVATE_PS],
                       env=dict(os.environ, VK_ARGS=args), capture_output=True,
                       stdin=subprocess.DEVNULL, **_NO_WINDOW)
    return r.returncode


def install_keepassxc(progress: Callable[[str], None] = print, quiet_ui: bool = False) -> Path:
    """Download, verify and install the latest KeePassXC. Returns keepassxc-cli's path."""
    if not supported():
        raise SetupError("Automatic install is for Windows. Get KeePassXC from keepassxc.org.")
    folder = data_dir() / "downloads"
    folder.mkdir(parents=True, exist_ok=True)
    try:
        rel = latest_release()
        msi = folder / rel.msi_name
        progress(f"Downloading KeePassXC {rel.version}…")
        want = parse_digest(http_get(rel.digest_url, 4096).decode("utf-8", "replace"),
                            rel.msi_name)
        got = download(rel.msi_url, msi)
    except (urllib.error.URLError, TimeoutError) as e:
        raise SetupError(f"Couldn't download KeePassXC. Check the internet connection and try "
                         f"again. ({getattr(e, 'reason', e)})")
    if got != want:
        msi.unlink(missing_ok=True)
        raise SetupError("STOPPED: the download doesn't match KeePassXC's published checksum. "
                         "Nothing was installed. Try again later.")
    progress("Checking the installer really comes from KeePassXC…")
    try:
        check_signature(msi)
    except SetupError:
        msi.unlink(missing_ok=True)
        raise
    progress("Installing. Windows will ask for permission: the publisher shown should be "
             f"{SIGNER}.")
    log = folder / f"KeePassXC-{rel.version}-install.log"
    code = run_msi(msi, log, quiet=quiet_ui)
    msi.unlink(missing_ok=True)
    if code not in MSI_OK:
        raise SetupError(MSI_MESSAGES.get(code, f"The KeePassXC installer stopped (code {code}). "
                                                f"Details: {log}"))
    cli = find_cli()
    if cli is None:
        raise SetupError("KeePassXC was installed, but vaultkit can't find it yet. Restart the "
                         "PC, then open vaultkit again.")
    progress(f"KeePassXC {rel.version} is installed.")
    return cli


# ---------------------------------------------------------------------------- settings
@dataclass(frozen=True)
class Setting:
    section: str
    key: str
    want: bool | int
    default: bool | int    # KeePassXC's own default (src/core/Config.cpp, 2.7.x)
    label: str
    at_most: bool = False  # numbers: a smaller (stricter) value is fine too
    local: bool = False    # kept in the per-PC settings file


SETTINGS = (
    Setting("General", "BackupBeforeSave", True, False, "Back up the vault before each save"),
    Setting("General", "AutoSaveAfterEveryChange", True, True, "Save after every change"),
    Setting("Security", "LockDatabaseIdle", True, True, "Lock when you're away"),
    Setting("Security", "LockDatabaseIdleSeconds", 300, 900, "Lock after 5 minutes",
            at_most=True),
    Setting("Security", "LockDatabaseScreenLock", True, True, "Lock when Windows locks"),
    Setting("Security", "ClearClipboard", True, True, "Clear copied passwords"),
    Setting("Security", "ClearClipboardTimeout", 10, 10, "...after 10 seconds", at_most=True),
    Setting("Security", "QuickUnlock", True, True, "Unlock with Windows Hello", local=True),
    Setting("GUI", "CheckForUpdates", True, True, "Check for KeePassXC updates"),
    Setting("GUI", "ShowTrayIcon", True, False, "Tray icon"),
    Setting("GUI", "MinimizeToTray", True, False, "Minimise to the tray"),
    Setting("GUI", "MinimizeOnStartup", True, False, "Start minimised"),
    Setting("Browser", "Enabled", True, False, "Browser integration"),
    Setting("Browser", "AlwaysAllowAccess", True, False,
            "Give logins to the browser without asking each time"),
)


def settings_paths() -> tuple[Path, Path]:
    """(roaming, local) keepassxc.ini, where KeePassXC 2.7 keeps them on Windows."""
    appdata = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
    local = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    roaming = os.environ.get("KPXC_CONFIG") or str(Path(appdata) / "KeePassXC" / "keepassxc.ini")
    local_ini = os.environ.get("KPXC_CONFIG_LOCAL") or str(Path(local) / "KeePassXC" / "keepassxc.ini")
    return Path(roaming), Path(local_ini)


class IniFile:
    """Qt-style INI, edited line by line so everything we don't touch stays byte-identical."""

    def __init__(self, text: str = "", nl: str | None = None) -> None:
        self.nl = nl or ("\r\n" if "\r\n" in text else "\n")
        self.lines = text.splitlines()

    @classmethod
    def load(cls, path: Path) -> "IniFile":
        try:
            with open(path, encoding="utf-8", errors="surrogateescape", newline="") as f:
                return cls(f.read())
        except FileNotFoundError:
            return cls("", nl="\r\n" if os.name == "nt" else "\n")  # as Qt writes it

    @staticmethod
    def _section(line: str) -> str | None:
        s = line.strip()
        return s[1:-1].strip() if len(s) > 1 and s[0] == "[" and s[-1] == "]" else None

    def _find(self, section: str, key: str) -> tuple[int | None, int | None]:
        cur, sec_at, key_at = None, None, None
        for i, line in enumerate(self.lines):
            name = self._section(line)
            if name is not None:
                cur = name
                if sec_at is None and name.lower() == section.lower():
                    sec_at = i
                continue
            if cur is None or cur.lower() != section.lower() or "=" not in line \
                    or line.lstrip().startswith((";", "#")):
                continue
            if key_at is None and line.split("=", 1)[0].strip().lower() == key.lower():
                key_at = i
        return sec_at, key_at

    def get(self, section: str, key: str) -> str | None:
        _, at = self._find(section, key)
        return None if at is None else self.lines[at].split("=", 1)[1].strip()

    def set(self, section: str, key: str, value: str) -> None:
        sec, at = self._find(section, key)
        if at is not None:
            self.lines[at] = f"{self.lines[at].split('=', 1)[0]}={value}"
            return
        if sec is None:
            while self.lines and not self.lines[-1].strip():
                self.lines.pop()
            if self.lines:
                self.lines.append("")
            self.lines += [f"[{section}]", f"{key}={value}"]
            return
        end = sec + 1
        while end < len(self.lines) and self._section(self.lines[end]) is None:
            end += 1
        while end > sec + 1 and not self.lines[end - 1].strip():
            end -= 1
        self.lines.insert(end, f"{key}={value}")

    def text(self) -> str:
        return self.nl.join(self.lines) + self.nl if self.lines else ""


def _parse(s: Setting, raw: str | None) -> bool | int | None:
    if raw is None:
        return s.default
    raw = raw.strip()
    if isinstance(s.want, bool):
        return raw.lower() in ("true", "1")
    try:
        return int(raw)
    except ValueError:
        return None


def _good(s: Setting, have: bool | int | None) -> bool:
    if isinstance(s.want, bool):
        return have is s.want
    if have is None:
        return False
    return 0 < have <= s.want if s.at_most else have == s.want


def _fmt(v: bool | int) -> str:
    return ("true" if v else "false") if isinstance(v, bool) else str(v)


@dataclass(frozen=True)
class SettingState:
    setting: Setting
    have: bool | int | None
    ok: bool


def audit_settings() -> list[SettingState]:
    roaming, local = settings_paths()
    files = {False: IniFile.load(roaming), True: IniFile.load(local)}
    out = []
    for s in SETTINGS:
        have = _parse(s, files[s.local].get(s.section, s.key))
        out.append(SettingState(s, have, _good(s, have)))
    return out


def settings_to_change() -> list[Setting]:
    return [st.setting for st in audit_settings() if not st.ok]


def keepassxc_running() -> bool:
    if not supported():
        return False
    try:
        out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq KeePassXC.exe", "/FO", "CSV", "/NH"],
                             capture_output=True, stdin=subprocess.DEVNULL, timeout=30,
                             **_NO_WINDOW).stdout.decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError):
        return False
    return "keepassxc.exe" in out.lower()


def _write_ini(path: Path, ini: IniFile) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        backup = path.with_name(f"{path.name}.before-vaultkit-{datetime.now():%Y%m%d-%H%M%S}")
        shutil.copy2(path, backup)
    tmp = path.with_name(path.name + ".vaultkit-tmp")
    with open(tmp, "w", encoding="utf-8", errors="surrogateescape", newline="") as f:
        f.write(ini.text())
    os.replace(tmp, path)


def apply_settings() -> list[Setting]:
    """Set every recommended setting that differs. Returns what changed."""
    todo = settings_to_change()
    if not todo:
        return []
    if keepassxc_running():
        raise SetupError("Close KeePassXC first (right-click its icon by the clock, then Quit). "
                         "It rewrites its settings when it quits, so changes made while it's "
                         "open would be lost.")
    roaming, local = settings_paths()
    for is_local, path in ((False, roaming), (True, local)):
        mine = [s for s in todo if s.local == is_local]
        if mine:
            ini = IniFile.load(path)
            for s in mine:
                ini.set(s.section, s.key, _fmt(s.want))
            _write_ini(path, ini)
    return todo


# ---------------------------------------------------------------------------- browsers
HOST = "org.keepassxc.keepassxc_browser"
CHROME_KEY = "Software\\Google\\Chrome\\NativeMessagingHosts\\" + HOST
ORIGINS = ("chrome-extension://pdffhmdngciaglkoonimfcmckehcpafo/",   # Edge add-ons store
           "chrome-extension://oboonakemofpalcgghocfoadofidjkkk/")   # Chrome Web Store


def manifest_path() -> Path:
    local = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    return Path(local) / "KeePassXC" / f"{HOST}_chrome.json"


def manifest(proxy: Path) -> dict:
    """Same content KeePassXC writes (src/browser/NativeMessageInstaller.cpp)."""
    return {"name": HOST, "description": "KeePassXC integration with native messaging support",
            "path": str(proxy), "type": "stdio", "allowed_origins": list(ORIGINS)}


def connector_problem() -> str | None:
    """None if Chrome-family browsers (Opera GX included) can reach KeePassXC; else why not."""
    where = registry().get(CHROME_KEY, "")
    if not where:
        return "Browsers aren't connected to KeePassXC yet."
    try:
        data = json.loads(Path(where).read_text("utf-8"))
    except (OSError, ValueError):
        return "The browser connection is broken (its settings file is missing)."
    if not Path(str(data.get("path", ""))).is_file():
        return "The browser connection points to a KeePassXC that isn't there any more."
    if not set(ORIGINS) <= set(data.get("allowed_origins") or []):
        return "The browser connection doesn't allow the KeePassXC-Browser extension."
    return None


def register_connector(cli: Path) -> Path:
    proxy = Path(cli).with_name("keepassxc-proxy.exe" if os.name == "nt" else "keepassxc-proxy")
    if not proxy.is_file():
        raise SetupError(f"KeePassXC's browser helper is missing ({proxy}). Reinstall KeePassXC.")
    path = manifest_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest(proxy), indent=4), "utf-8")
    registry().set(CHROME_KEY, "", str(path))
    return path


def keepassxc_autostarts() -> bool:
    return bool(registry().get(RUN_KEY, "KeePassXC"))


def enable_keepassxc_autostart(cli: Path) -> None:
    """The same Run entry KeePassXC's installer writes."""
    registry().set(RUN_KEY, "KeePassXC", f'"{gui_exe(cli)}"')


# ---------------------------------------------------------------------------- vault file
KDFS = {uuid.UUID("ef636ddf-8c29-444b-91f7-a9a403e30a0c"): "Argon2d",
        uuid.UUID("9e298b19-56db-4773-b23d-fc3ec6f0a1e6"): "Argon2id",
        uuid.UUID("7c02bb82-79a7-4ac0-927d-114a00648238"): "AES-KDF",
        uuid.UUID("c9d9f39a-628a-4460-bf74-0d08c18a4fea"): "AES-KDF"}
CIPHERS = {uuid.UUID("31c1f2e6-bf71-4350-be58-05216afc5aff"): "AES-256",
           uuid.UUID("d6038a2b-8b6f-4cb5-a524-339a31dbb59a"): "ChaCha20",
           uuid.UUID("ad68f29f-576f-4bb9-a36a-d47af965346c"): "Twofish"}
SIGNATURE = (0x9AA2D903, 0xB54BFB67)


@dataclass(frozen=True)
class VaultInfo:
    major: int
    minor: int
    kdf: str
    cipher: str
    memory: int | None = None        # bytes (Argon2)
    iterations: int | None = None    # Argon2
    parallelism: int | None = None   # Argon2
    rounds: int | None = None        # AES-KDF

    @property
    def format(self) -> str:
        return f"KDBX {self.major}.{self.minor}"

    @property
    def memory_mib(self) -> int:
        return (self.memory or 0) // (1024 * 1024)

    def problems(self) -> list[str]:
        out = []
        if self.major < 4:
            out.append(f"It uses the older {self.format} format.")
        if self.kdf != "Argon2id":
            out.append(f"It slows down password guessing with {self.kdf}; Argon2id is the "
                       "recommended choice.")
        if self.kdf.startswith("Argon2") and self.memory_mib < MIN_MEMORY_MIB:
            out.append(f"That uses {self.memory_mib} MiB of memory; {MIN_MEMORY_MIB} MiB makes "
                       "guessing on graphics cards much harder.")
        return out

    @property
    def ok(self) -> bool:
        return not self.problems()

    def summary(self) -> str:
        parts = [self.format, self.kdf]
        if self.kdf.startswith("Argon2"):
            parts.append(f"{self.memory_mib} MiB")
            if self.parallelism:
                parts.append(f"{self.parallelism} thread{'s' if self.parallelism != 1 else ''}")
        return ", ".join(parts)


def _variant_map(b: bytes) -> dict[str, object]:
    """KDBX 4 VariantDictionary: u16 version, then (type, name, value) items until type 0."""
    out: dict[str, object] = {}
    pos = 2
    while pos < len(b):
        kind = b[pos]
        pos += 1
        if kind == 0:
            break
        (n,) = struct.unpack_from("<I", b, pos)
        name = b[pos + 4:pos + 4 + n].decode("utf-8", "replace")
        pos += 4 + n
        (n,) = struct.unpack_from("<I", b, pos)
        v = b[pos + 4:pos + 4 + n]
        pos += 4 + n
        if len(v) != n:
            raise struct.error("short value")
        fmt = {0x04: "<I", 0x05: "<Q", 0x0C: "<i", 0x0D: "<q"}.get(kind)
        if fmt and len(v) == struct.calcsize(fmt):
            out[name] = struct.unpack(fmt, v)[0]
        elif kind == 0x08:
            out[name] = v != b"\x00"
        elif kind == 0x18:
            out[name] = v.decode("utf-8", "replace")
        else:
            out[name] = bytes(v)
    return out


def vault_info(path: str | Path) -> VaultInfo:
    """Format and key-derivation settings from the vault's header. No password needed."""
    try:
        with open(path, "rb") as f:
            head = f.read(1 << 20)
    except OSError as e:
        raise SetupError(f"Can't read the vault file: {e.strerror or e}.")
    try:
        if len(head) < 12 or struct.unpack_from("<II", head) != SIGNATURE:
            raise SetupError("That file isn't a KeePass vault (.kdbx).")
        (ver,) = struct.unpack_from("<I", head, 8)
        major, minor = ver >> 16, ver & 0xFFFF
        size_fmt = "<I" if major >= 4 else "<H"
        step = struct.calcsize(size_fmt)
        pos, fields = 12, {}
        while True:
            fid = head[pos]
            (n,) = struct.unpack_from(size_fmt, head, pos + 1)
            pos += 1 + step
            data = head[pos:pos + n]
            if len(data) != n:
                raise struct.error("short header field")
            pos += n
            if fid == 0:
                break
            fields[fid] = data
        cipher = CIPHERS.get(uuid.UUID(bytes=fields[2]), "unknown") if len(fields.get(2, b"")) == 16 \
            else "unknown"
        if major >= 4:
            params = _variant_map(fields.get(11, b""))
            raw = params.get("$UUID")
            kdf = KDFS.get(uuid.UUID(bytes=raw), "unknown") \
                if isinstance(raw, bytes) and len(raw) == 16 else "unknown"
            num = lambda k: params[k] if isinstance(params.get(k), int) else None  # noqa: E731
            return VaultInfo(major, minor, kdf, cipher, num("M"), num("I"), num("P"), num("R"))
        rounds = struct.unpack("<Q", fields[6])[0] if len(fields.get(6, b"")) == 8 else None
        return VaultInfo(major, minor, "AES-KDF", cipher, rounds=rounds)
    except (struct.error, IndexError):
        raise SetupError("The vault's header looks damaged or cut short.")


def strengthen_steps(cpus: int | None = None) -> list[str]:
    """The one-time KeePassXC screen that keepassxc-cli can't do for us."""
    threads = max(1, min(cpus or os.cpu_count() or 2, 8))
    return [
        "Open the vault in KeePassXC and unlock it.",
        "Menu Database > Database Security…, then the Encryption Settings tab, then Advanced.",
        "Key Derivation Function: Argon2id (KDBX 4).",
        f"Memory Usage: {MIN_MEMORY_MIB} MiB.  Parallelism: {threads} thread(s).",
        "Press the Benchmark button (it picks the rounds for a 1-second unlock), then OK.",
        "Save the vault (Ctrl+S), then come back here and press Check again.",
    ]


def create_vault(cli, path: str | Path, password: str, decryption_ms: int = 1000) -> None:
    """keepassxc-cli db-create with a password. Makes KDBX 3.1 + AES-KDF; see strengthen_steps."""
    path = Path(path)
    if path.exists():
        raise SetupError("A file with that name already exists. Choose another name or folder.")
    path.parent.mkdir(parents=True, exist_ok=True)
    secret = f"{password}\n{password}\n".encode("utf-8")
    r = subprocess.run(_cmd(cli) + ["db-create", "-q", "-p", "-t", str(decryption_ms), str(path)],
                       input=secret, capture_output=True, timeout=300, **_NO_WINDOW)
    del secret
    if r.returncode != 0 or not path.is_file():
        msg = (r.stderr or r.stdout).decode("utf-8", "replace").strip()
        raise SetupError(f"KeePassXC couldn't create the vault: {msg or 'no details given'}")


# ---------------------------------------------------------------------------- overview
@dataclass(frozen=True)
class Check:
    key: str
    title: str
    ok: bool | None      # None: nothing to check automatically, or can't check yet
    detail: str
    action: str = ""     # button label for the fix ("" = none)


def run_checks(db: str | None = None, cli: Path | None = None) -> list[Check]:
    """Everything the Setup page and `kpsetup.py check` show. Fast: no network, no unlock."""
    cli = cli or find_cli()
    ver = cli_version(cli) if cli else None
    out = []
    if cli is None:
        out.append(Check("keepassxc", "KeePassXC", False,
                         "Not installed. vaultkit needs it: it's where your passwords are kept.",
                         "Install KeePassXC"))
    elif ver is not None and ver < MIN_VERSION:
        out.append(Check("keepassxc", "KeePassXC", False,
                         f"Version {version_text(ver)} is too old; vaultkit needs "
                         f"{version_text(MIN_VERSION)} or newer.", "Update KeePassXC"))
    else:
        out.append(Check("keepassxc", "KeePassXC", True,
                         f"Version {version_text(ver)} installed." if ver else "Installed."))
    installed = cli is not None

    if not installed:
        out.append(Check("settings", "Recommended settings", None, "After KeePassXC is installed."))
    else:
        todo = settings_to_change()
        out.append(Check("settings", "Recommended settings", not todo,
                         "Backups, auto-lock, clipboard clearing and browser integration are on."
                         if not todo else f"{len(todo)} to change: "
                         + "; ".join(s.label for s in todo) + ".",
                         "" if not todo else "Apply recommended settings"))
    if supported():
        problem = connector_problem() if installed else None
        out.append(Check("connector", "Browser connection (Opera GX, Chrome)",
                         None if not installed else problem is None,
                         "After KeePassXC is installed." if not installed else
                         (problem or "Opera GX and Chrome can talk to KeePassXC."),
                         "Connect browsers" if installed and problem else ""))
        on = keepassxc_autostarts()
        out.append(Check("autostart", "KeePassXC starts with Windows",
                         None if not installed else on,
                         "After KeePassXC is installed." if not installed else
                         ("So auto-fill is ready as soon as you log in." if on else
                          "Auto-fill only works while KeePassXC is running."),
                         "Turn on" if installed and not on else ""))
    if db and Path(db).is_file():
        try:
            info = vault_info(db)
            out.append(Check("vault", "Vault security", info.ok,
                             f"{Path(db).name}: {info.summary()}." + ("" if info.ok else
                             f" Switching to Argon2id with {MIN_MEMORY_MIB} MiB makes the master "
                             "password far harder to crack."),
                             "" if info.ok else "Show me how"))
        except SetupError as e:
            out.append(Check("vault", "Vault security", False, str(e)))
    else:
        out.append(Check("vault", "Vault security", None,
                         "No vault chosen yet." if not db else f"Can't find {db}.",
                         "Create a vault"))
    out.append(Check("extension", "KeePassXC-Browser in Opera GX", None,
                     "Add it from the Chrome Web Store, then press Connect in it and give the "
                     "connection a name. vaultkit can't see whether that's done.",
                     "Open the extension page"))
    return out


# ---------------------------------------------------------------------------- command line
def _apply_all(cli: Path, ask: bool, yes: bool) -> int:
    rc = 0
    todo = settings_to_change()
    if todo:
        print("Recommended KeePassXC settings to change:")
        for s in todo:
            print(f"  - {s.label}")
        go = yes or not ask or input("Change these? [Y/n] ").strip().lower() in ("", "y", "yes")
        if go:
            try:
                apply_settings()
                print("Settings changed (the old file was backed up next to it).")
            except SetupError as e:
                print(e)
                rc = 1
    else:
        print("KeePassXC settings: already as recommended.")
    if supported():
        if connector_problem():
            print(f"Browser connection registered: {register_connector(cli)}")
        if not keepassxc_autostarts():
            enable_keepassxc_autostart(cli)
            print("KeePassXC will start with Windows.")
    print(f"\nLast step in Opera GX: add KeePassXC-Browser from {EXTENSION_URL}\n"
          "then click its icon, press Connect, and give the connection a name.")
    return rc


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="kpsetup", description="Install and set up KeePassXC "
                                "the way vaultkit recommends.")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="show what's set up and what isn't")
    c.add_argument("--db", help="also check this vault's encryption settings")
    i = sub.add_parser("install", help="install KeePassXC if needed, then apply the settings")
    i.add_argument("--yes", action="store_true", help="don't ask before changing settings")
    i.add_argument("--quiet-ui", action="store_true", help="no installer progress window")
    a = sub.add_parser("apply", help="apply the recommended settings and browser connection")
    a.add_argument("--yes", action="store_true")
    args = p.parse_args(argv)
    try:
        if args.cmd == "check":
            for ch in run_checks(args.db):
                mark = {True: "OK ", False: "!! ", None: "-- "}[ch.ok]
                print(f"{mark}{ch.title}: {ch.detail}")
            return 0
        cli = find_cli()
        fresh = False
        if args.cmd == "install":
            ver = cli_version(cli) if cli else None
            if cli is None or (ver is not None and ver < MIN_VERSION):
                cli = install_keepassxc(quiet_ui=args.quiet_ui)
                fresh = True
            else:
                print(f"KeePassXC {version_text(ver)} is already installed.")
        if cli is None:
            print("KeePassXC isn't installed. Run: python kpsetup.py install")
            return 1
        existing = settings_paths()[0].exists()
        return _apply_all(cli, ask=existing and not fresh, yes=args.yes)
    except (SetupError, OSError) as e:
        print(e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
