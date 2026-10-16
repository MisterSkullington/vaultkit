#!/usr/bin/env python3
"""Make and publish signed vaultkit releases. Run on your own PC.

  py -3.13 tools\\release.py init --repo OWNER/NAME   one time: signing key + trust this repo
  py -3.13 tools\\release.py publish                  sign this folder's code, upload a release
  py -3.13 tools\\release.py build                    sign into .\\dist without uploading
  py -3.13 tools\\release.py show-key                 print the public key (for other PCs)

The signing key is stored encrypted to your Windows login (DPAPI) and never leaves this PC.
Publishing uses the GitHub CLI (`gh auth login` once). Your installed app checks the repo,
verifies the signature against the pinned public key, and installs on its next start.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import secretstore  # noqa: E402
import updater  # noqa: E402

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:  # pragma: no cover
    sys.exit("Needs the 'cryptography' package: py -3.13 -m pip install -r requirements.txt")

RAW = serialization.Encoding.Raw


def key_path() -> Path:
    return updater.data_dir() / "release-signing.key"


def load_key(create: bool = False) -> Ed25519PrivateKey:
    p = key_path()
    if p.exists():
        return Ed25519PrivateKey.from_private_bytes(secretstore.unprotect(p.read_bytes()))
    if not create:
        sys.exit("No signing key on this PC yet. Run: py -3.13 tools\\release.py init --repo OWNER/NAME")
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(RAW, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    p.write_bytes(secretstore.protect(raw))
    return key


def public_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(RAW, serialization.PublicFormat.Raw).hex()


def cmd_init(a: argparse.Namespace) -> int:
    existed = key_path().exists()
    key = load_key(create=True)
    path = updater.save_trust(a.repo, public_hex(key))
    print(("Using the existing signing key." if existed else "Created a signing key.") +
          f" It's encrypted to your Windows login at:\n  {key_path()}")
    print(f"This PC now trusts signed releases from github.com/{a.repo}  ({path})")
    print("To update vaultkit on another PC, copy that update.json into the same folder there.")
    return 0


def build(notes: str, out: Path) -> tuple[str, Path, Path]:
    trust = updater.load_trust()
    key = load_key()
    pub = public_hex(key)
    if trust and trust.public_key != pub:
        sys.exit("This PC's signing key doesn't match the key in update.json, so the app would "
                 "reject this release. Run init again to re-pin.")
    version, blob = updater.build_package(ROOT, notes)
    sig = key.sign(blob)
    updater.read_package(blob, sig, pub)  # prove the app would accept it
    out.mkdir(parents=True, exist_ok=True)
    zpath = out / f"vaultkit-{version}.zip"
    spath = out / f"vaultkit-{version}.zip.sig"
    zpath.write_bytes(blob)
    spath.write_bytes(sig)
    return version, zpath, spath


def cmd_build(a: argparse.Namespace) -> int:
    version, z, s = build(a.notes, Path(a.out))
    print(f"Signed vaultkit {version}:\n  {z}\n  {s}")
    return 0


def cmd_publish(a: argparse.Namespace) -> int:
    trust = updater.load_trust()
    if trust is None:
        sys.exit("Run init first: py -3.13 tools\\release.py init --repo OWNER/NAME")
    gh = shutil.which("gh")
    if not gh:
        sys.exit("GitHub CLI not found. Install it (winget install GitHub.cli), "
                 "run `gh auth login`, then try again.")
    version, z, s = build(a.notes, Path(a.out))
    cmd = [gh, "release", "create", f"v{version}", str(z), str(s), "--repo", trust.repo,
           "--title", f"vaultkit {version}", "--notes", a.notes or f"vaultkit {version}"]
    print(f"Publishing vaultkit {version} to github.com/{trust.repo} …")
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print("gh couldn't create the release (see above). The signed files are in "
              f"{z.parent} if you want to upload them by hand.")
        return result.returncode
    print("Published. The app installs it the next time it starts after its daily check.")
    return 0


def cmd_show_key(a: argparse.Namespace) -> int:
    print(public_hex(load_key()))
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="release.py", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("init", help="create the signing key and trust a repo on this PC")
    i.add_argument("--repo", required=True, help="OWNER/NAME on GitHub")
    for name in ("build", "publish"):
        b = sub.add_parser(name)
        b.add_argument("--notes", default="", help="what changed (shown in the app)")
        b.add_argument("--out", default=str(ROOT / "dist"))
    sub.add_parser("show-key")
    a = p.parse_args(argv)
    return {"init": cmd_init, "build": cmd_build, "publish": cmd_publish,
            "show-key": cmd_show_key}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
