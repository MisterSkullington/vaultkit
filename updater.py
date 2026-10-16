"""Signed self-updates from GitHub Releases.

Threat model: a password tool that auto-updates must not trust GitHub with your vault. So:
  * Releases are Ed25519-signed with a key that lives only on your PC (tools/release.py).
  * The public key is pinned in %LOCALAPPDATA%\\vaultkit\\update.json, outside the app
    folder, so an update can never replace the key that judges it.
  * Signature is checked BEFORE the zip is parsed; every file is hash-checked against the
    signed manifest; file names are whitelisted (no path traversal); the version inside
    vaultkit.py must match the signed manifest; older or equal versions are refused.
  * Updates are staged, then applied at the next launch (launcher.py) after re-verifying,
    with a backup of the current version and `launcher.py --rollback`.
This protects against a compromised GitHub account or download channel. It does not (and
cannot) protect against malware already running as you, which could edit the app directly.

Network: only api.github.com / github.com, and only once a repo is configured.
Never imports vaultkit/app, so the launcher can update them before they're loaded.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import urllib.request
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Callable

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    HAVE_CRYPTO = True
except ImportError:  # updates simply stay off; the app still runs
    HAVE_CRYPTO = False

API = "https://api.github.com/repos/{repo}/releases/latest"
USER_AGENT = "vaultkit-updater"
MAX_DOWNLOAD = 25 * 1024 * 1024
KEEP_BACKUPS = 3
SUFFIXES = {".py", ".cmd", ".md", ".txt"}
SUBDIRS = ("tests", "tools")
_NAME_RE = re.compile(r"^(?:(?:tests|tools)/)?[A-Za-z0-9][A-Za-z0-9 _.\-]*\.(?:py|cmd|md|txt)$")
_VERSION_RE = re.compile(r'^__version__\s*=\s*"(\d+(?:\.\d+)*)"', re.M)
_ZIP_TIME = (2020, 1, 1, 0, 0, 0)  # fixed timestamps: identical source -> identical zip


class UpdateError(RuntimeError):
    pass


# ---------------------------------------------------------------------------- locations
def data_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    d = Path(base) / "vaultkit"
    d.mkdir(parents=True, exist_ok=True)
    return d


def trust_path() -> Path:
    return data_dir() / "update.json"


def stage_root() -> Path:
    return data_dir() / "updates"


def backup_root() -> Path:
    return data_dir() / "backups"


def hold_path() -> Path:
    return data_dir() / "update-hold.json"


def log(message: str) -> None:
    with open(data_dir() / "update.log", "a", encoding="utf-8") as f:
        f.write(f"{datetime.now():%Y-%m-%d %H:%M:%S}  {message}\n")


# ---------------------------------------------------------------------------- trust
@dataclass
class Trust:
    repo: str        # "owner/name"
    public_key: str  # 64 hex chars, Ed25519 raw public key


def load_trust() -> Trust | None:
    p = trust_path()
    if not p.exists():
        return None
    d = json.loads(p.read_text("utf-8"))
    repo, key = d.get("repo", ""), d.get("public_key", "")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise UpdateError("update.json has an invalid repo name")
    if not re.fullmatch(r"[0-9a-f]{64}", key):
        raise UpdateError("update.json has an invalid public key")
    return Trust(repo, key)


def save_trust(repo: str, public_key_hex: str) -> Path:
    p = trust_path()
    p.write_text(json.dumps({"repo": repo, "public_key": public_key_hex}, indent=2), "utf-8")
    load_trust()  # validate what we wrote
    return p


# ---------------------------------------------------------------------------- versions
def parse_version(s: str) -> tuple[int, ...]:
    s = s.strip().lstrip("vV")
    if not re.fullmatch(r"\d+(?:\.\d+)*", s):
        raise UpdateError(f"not a version number: {s!r}")
    return tuple(int(x) for x in s.split("."))


def installed_version(install_dir: Path) -> str:
    m = _VERSION_RE.search((Path(install_dir) / "vaultkit.py").read_text("utf-8"))
    if not m:
        raise UpdateError("can't read the installed version from vaultkit.py")
    return m.group(1)


# ---------------------------------------------------------------------------- packages
def collect(root: Path) -> dict[str, Path]:
    """The app's own files, by relative POSIX name. Anything else is never touched."""
    root = Path(root)
    found: dict[str, Path] = {}
    for p in sorted(root.iterdir()):
        if p.is_file() and p.suffix in SUFFIXES and _NAME_RE.match(p.name):
            found[p.name] = p
    for sub in SUBDIRS:
        d = root / sub
        if d.is_dir():
            for p in sorted(d.glob("*.py")):
                name = f"{sub}/{p.name}"
                if _NAME_RE.match(name):
                    found[name] = p
    return found


def build_package(source: Path, notes: str = "") -> tuple[str, bytes]:
    """Deterministic release zip with a manifest of SHA-256 hashes."""
    files = collect(source)
    if "vaultkit.py" not in files:
        raise UpdateError(f"{source} doesn't look like a vaultkit folder (no vaultkit.py)")
    version = installed_version(Path(source))
    blobs = {name: path.read_bytes() for name, path in files.items()}
    manifest = {"version": version, "notes": notes,
                "files": {n: hashlib.sha256(b).hexdigest() for n, b in blobs.items()}}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name in ["manifest.json", *sorted(blobs)]:
            info = zipfile.ZipInfo(name, _ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            data = (json.dumps(manifest, indent=2, sort_keys=True).encode()
                    if name == "manifest.json" else blobs[name])
            z.writestr(info, data)
    return version, buf.getvalue()


def verify(public_key_hex: str, data: bytes, signature: bytes) -> None:
    if not HAVE_CRYPTO:
        raise UpdateError("the 'cryptography' package isn't installed, so updates can't be "
                          "verified. Run: py -3.13 -m pip install -r requirements.txt")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex)).verify(signature, data)
    except InvalidSignature:
        raise UpdateError("the update's signature doesn't match your trusted key") from None


@dataclass
class Package:
    version: str
    files: dict[str, bytes]
    notes: str = ""


def read_package(zip_bytes: bytes, signature: bytes, public_key_hex: str) -> Package:
    verify(public_key_hex, zip_bytes, signature)  # nothing is parsed before this passes
    try:
        z = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except zipfile.BadZipFile:
        raise UpdateError("the update isn't a valid zip file") from None
    with z:
        try:
            manifest = json.loads(z.read("manifest.json"))
        except KeyError:
            raise UpdateError("the update has no manifest") from None
        version = str(manifest.get("version", ""))
        parse_version(version)
        listed = manifest.get("files")
        if not isinstance(listed, dict) or not listed:
            raise UpdateError("the update's manifest lists no files")
        files: dict[str, bytes] = {}
        for name, digest in listed.items():
            if not _NAME_RE.match(name) or ".." in PurePosixPath(name).parts:
                raise UpdateError(f"the update contains an unsafe file name: {name!r}")
            try:
                data = z.read(name)
            except KeyError:
                raise UpdateError(f"the update is missing {name}") from None
            if hashlib.sha256(data).hexdigest() != digest:
                raise UpdateError(f"{name} doesn't match the update's manifest")
            files[name] = data
    core = files.get("vaultkit.py")
    if core is None:
        raise UpdateError("the update is missing vaultkit.py")
    m = _VERSION_RE.search(core.decode("utf-8", "replace"))
    if not m or m.group(1) != version:
        raise UpdateError("the update's version label doesn't match its code")
    return Package(version, files, str(manifest.get("notes", "")))


# ---------------------------------------------------------------------------- GitHub
def http_get(url: str, accept: str = "application/vnd.github+json",
             limit: int = MAX_DOWNLOAD) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": accept})
    with urllib.request.urlopen(req, timeout=30) as r:
        data = r.read(limit + 1)
    if len(data) > limit:
        raise UpdateError("the update download is unexpectedly large")
    return data


@dataclass
class Staged:
    version: str
    notes: str
    path: Path


def staged() -> Staged | None:
    best: Staged | None = None
    root = stage_root()
    if not root.is_dir():
        return None
    for ready in root.glob("*/ready.json"):
        try:
            d = json.loads(ready.read_text("utf-8"))
            s = Staged(d["version"], d.get("notes", ""), ready.parent)
            if best is None or parse_version(s.version) > parse_version(best.version):
                best = s
        except (ValueError, KeyError, UpdateError):
            continue
    return best


def held_version() -> str | None:
    try:
        return json.loads(hold_path().read_text("utf-8")).get("version")
    except (OSError, ValueError):
        return None


def check_for_update(current: str, trust: Trust | None = None,
                     get: Callable[..., bytes] | None = None) -> Staged | None:
    """Download, verify and stage the latest release if it's newer. Returns what's staged."""
    trust = trust or load_trust()
    if trust is None:
        return None  # updates not set up: no network at all
    get = get or http_get
    release = json.loads(get(API.format(repo=trust.repo)))
    tag = str(release.get("tag_name", ""))
    version = tag.lstrip("vV")
    if parse_version(version) <= parse_version(current) or version == held_version():
        return None
    already = staged()
    if already and parse_version(already.version) >= parse_version(version):
        return already
    assets = {a.get("name"): a.get("browser_download_url") for a in release.get("assets", [])}
    zname = f"vaultkit-{version}.zip"
    if not assets.get(zname) or not assets.get(zname + ".sig"):
        raise UpdateError(f"release {tag} is missing {zname} or its signature")
    zip_bytes = get(assets[zname], "application/octet-stream")
    signature = get(assets[zname + ".sig"], "application/octet-stream", 1024)
    pkg = read_package(zip_bytes, signature, trust.public_key)
    if parse_version(pkg.version) <= parse_version(current):
        raise UpdateError(f"release {tag} contains an older version ({pkg.version})")

    shutil.rmtree(stage_root(), ignore_errors=True)  # only ever one staged update
    d = stage_root() / pkg.version
    d.mkdir(parents=True)
    (d / zname).write_bytes(zip_bytes)
    (d / (zname + ".sig")).write_bytes(signature)
    (d / "ready.json").write_text(json.dumps({"version": pkg.version, "notes": pkg.notes}), "utf-8")
    log(f"staged {pkg.version} from {trust.repo}")
    return Staged(pkg.version, pkg.notes, d)


# ---------------------------------------------------------------------------- install
def _copy_tree(files: dict[str, Path], dest: Path) -> None:
    for name, src in files.items():
        target = dest / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, target)


def backup(install_dir: Path, version: str) -> Path:
    dest = backup_root() / version
    shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True)
    _copy_tree(collect(install_dir), dest)
    backups = sorted((p for p in backup_root().iterdir() if p.is_dir()),
                     key=lambda p: p.stat().st_mtime, reverse=True)
    for old in backups[KEEP_BACKUPS:]:
        shutil.rmtree(old, ignore_errors=True)
    return dest


def apply_staged(install_dir: Path, current: str, trust: Trust | None = None) -> str | None:
    """Install the staged update (re-verified now). Returns the new version, or None."""
    s = staged()
    if s is None:
        return None
    if parse_version(s.version) <= parse_version(current) or s.version == held_version():
        shutil.rmtree(stage_root(), ignore_errors=True)
        return None
    trust = trust or load_trust()
    if trust is None:
        raise UpdateError("updates aren't set up on this PC (no update.json)")
    zname = f"vaultkit-{s.version}.zip"
    pkg = read_package((s.path / zname).read_bytes(), (s.path / (zname + ".sig")).read_bytes(),
                       trust.public_key)
    install_dir = Path(install_dir)
    backup(install_dir, current)
    for name, data in pkg.files.items():
        target = install_dir / name
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name(target.name + ".vkupdate")
        tmp.write_bytes(data)
        os.replace(tmp, target)  # each file swaps atomically
    shutil.rmtree(stage_root(), ignore_errors=True)
    log(f"installed {pkg.version} (backup of {current} kept)")
    return pkg.version


def rollback(install_dir: Path) -> str:
    """Restore the newest backup older than what's installed, and hold the bad version."""
    install_dir = Path(install_dir)
    current = installed_version(install_dir)
    candidates = []
    for d in (backup_root().iterdir() if backup_root().is_dir() else []):
        try:
            if parse_version(d.name) < parse_version(current):
                candidates.append(d)
        except UpdateError:
            continue
    if not candidates:
        raise UpdateError("there's no earlier version to go back to")
    target = max(candidates, key=lambda d: parse_version(d.name))
    _copy_tree(collect(target), install_dir)
    hold_path().write_text(json.dumps({"version": current}), "utf-8")
    shutil.rmtree(stage_root(), ignore_errors=True)
    log(f"rolled back {current} -> {target.name}; {current} won't be reinstalled")
    return target.name
