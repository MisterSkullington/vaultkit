"""Signed-update tests: the happy path, then every way an attacker might try to get in."""
import hashlib, io, json, os, sys, tempfile, unittest, zipfile
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import updater  # noqa: E402

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
except ImportError:  # pragma: no cover
    Ed25519PrivateKey = None

RAW = serialization.Encoding.Raw if Ed25519PrivateKey else None


def pub(k):
    return k.public_key().public_bytes(RAW, serialization.PublicFormat.Raw).hex()


def write_tree(root: Path, version: str, marker: str) -> None:
    (root / "tests").mkdir(parents=True, exist_ok=True)
    (root / "tools").mkdir(exist_ok=True)
    (root / "vaultkit.py").write_text(f'__version__ = "{version}"\nMARK = "{marker}"\n')
    (root / "app.py").write_text(f"# app {marker}\n")
    (root / "Open vaultkit.cmd").write_text("@echo off\r\n")
    (root / "tests" / "test_x.py").write_text(f"# test {marker}\n")
    (root / "tools" / "release.py").write_text(f"# tool {marker}\n")
    (root / "notes.docx").write_bytes(b"not part of the app")  # must never be packaged


def forge(manifest: dict, files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("manifest.json", json.dumps(manifest))
        for n, b in files.items():
            z.writestr(n, b)
    return buf.getvalue()


@unittest.skipIf(Ed25519PrivateKey is None, "cryptography not installed")
class Updates(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = Path(self.tmp.name)
        self.env = mock.patch.dict(os.environ, {"LOCALAPPDATA": str(t / "appdata")})
        self.env.start()
        self.key = Ed25519PrivateKey.generate()
        updater.save_trust("me/vaultkit", pub(self.key))
        self.src, self.inst = t / "src", t / "install"
        write_tree(self.src, "1.5.0", "new")
        write_tree(self.inst, "1.4.0", "old")
        self.calls = []
        self.serve(*updater.build_package(self.src, "Fix button"))

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def serve(self, version, blob, sig=None, tag=None, key=None):
        sig = sig if sig is not None else (key or self.key).sign(blob)
        tag = tag or f"v{version}"
        name = f"vaultkit-{tag.lstrip('v')}.zip"
        self.release = {"tag_name": tag, "assets": [
            {"name": name, "browser_download_url": f"https://dl/{name}"},
            {"name": name + ".sig", "browser_download_url": f"https://dl/{name}.sig"}]}
        self.files = {f"https://dl/{name}": blob, f"https://dl/{name}.sig": sig}

    def get(self, url, accept="", limit=0):
        self.calls.append(url)
        if url.startswith("https://api.github.com/"):
            self.assertEqual(url, "https://api.github.com/repos/me/vaultkit/releases/latest")
            return json.dumps(self.release).encode()
        return self.files[url]

    def check(self, current="1.4.0"):
        return updater.check_for_update(current, get=self.get)

    # -- happy path
    def test_stage_apply_backup_rollback(self):
        s = self.check()
        self.assertEqual((s.version, s.notes), ("1.5.0", "Fix button"))
        self.assertEqual(updater.apply_staged(self.inst, "1.4.0"), "1.5.0")
        self.assertEqual(updater.installed_version(self.inst), "1.5.0")
        self.assertIn('"new"', (self.inst / "vaultkit.py").read_text())
        self.assertIn("new", (self.inst / "tools" / "release.py").read_text())
        self.assertIsNone(updater.staged())
        self.assertTrue((updater.backup_root() / "1.4.0" / "vaultkit.py").exists())
        self.assertFalse((updater.backup_root() / "1.4.0" / "notes.docx").exists())

        self.assertEqual(updater.rollback(self.inst), "1.4.0")
        self.assertEqual(updater.installed_version(self.inst), "1.4.0")
        self.assertIsNone(self.check())  # the rolled-back version is held, not reinstalled
        write_tree(self.src, "1.5.1", "newer")
        self.serve(*updater.build_package(self.src))
        self.assertEqual(self.check().version, "1.5.1")  # a newer one still comes through

    def test_build_is_deterministic_and_excludes_other_files(self):
        v1, b1 = updater.build_package(self.src)
        v2, b2 = updater.build_package(self.src)
        self.assertEqual(b1, b2)
        names = zipfile.ZipFile(io.BytesIO(b1)).namelist()
        self.assertNotIn("notes.docx", names)
        self.assertIn("Open vaultkit.cmd", names)

    def test_no_trust_means_no_network(self):
        updater.trust_path().unlink()
        self.assertIsNone(self.check())
        self.assertEqual(self.calls, [])

    def test_same_or_older_tag_is_ignored(self):
        self.assertIsNone(self.check(current="1.5.0"))
        self.assertIsNone(self.check(current="2.0.0"))

    # -- attacks
    def test_tampered_download_rejected(self):
        v, blob = updater.build_package(self.src)
        sig = self.key.sign(blob)
        evil = bytearray(blob)
        evil[len(evil) // 2] ^= 0xFF
        self.serve(v, bytes(evil), sig=sig)
        with self.assertRaisesRegex(updater.UpdateError, "signature"):
            self.check()
        self.assertIsNone(updater.staged())

    def test_signed_with_another_key_rejected(self):
        self.serve(*updater.build_package(self.src), key=Ed25519PrivateKey.generate())
        with self.assertRaisesRegex(updater.UpdateError, "signature"):
            self.check()

    def test_path_traversal_rejected_even_if_signed(self):
        files = {"vaultkit.py": b'__version__ = "1.5.0"\n', "../evil.py": b"pwn"}
        manifest = {"version": "1.5.0",
                    "files": {n: hashlib.sha256(b).hexdigest() for n, b in files.items()}}
        self.serve("1.5.0", forge(manifest, files))
        with self.assertRaisesRegex(updater.UpdateError, "unsafe file name"):
            self.check()

    def test_version_label_must_match_code(self):
        files = {"vaultkit.py": b'__version__ = "1.3.0"\n'}
        manifest = {"version": "1.5.0",
                    "files": {n: hashlib.sha256(b).hexdigest() for n, b in files.items()}}
        self.serve("1.5.0", forge(manifest, files))
        with self.assertRaisesRegex(updater.UpdateError, "version label"):
            self.check()

    def test_signed_downgrade_under_newer_tag_rejected(self):
        write_tree(self.src, "1.3.0", "old-but-signed")
        _, blob = updater.build_package(self.src)
        self.serve("1.3.0", blob, tag="v1.6.0")
        with self.assertRaisesRegex(updater.UpdateError, "older version"):
            self.check()

    def test_file_hash_mismatch_rejected(self):
        files = {"vaultkit.py": b'__version__ = "1.5.0"\n', "app.py": b"swapped"}
        manifest = {"version": "1.5.0", "files": {
            "vaultkit.py": hashlib.sha256(files["vaultkit.py"]).hexdigest(),
            "app.py": hashlib.sha256(b"original").hexdigest()}}
        self.serve("1.5.0", forge(manifest, files))
        with self.assertRaisesRegex(updater.UpdateError, "doesn't match"):
            self.check()

    def test_staged_files_tampered_before_install(self):
        s = self.check()
        z = s.path / "vaultkit-1.5.0.zip"
        data = bytearray(z.read_bytes())
        data[-30] ^= 0x01
        z.write_bytes(bytes(data))
        with self.assertRaisesRegex(updater.UpdateError, "signature"):
            updater.apply_staged(self.inst, "1.4.0")
        self.assertEqual(updater.installed_version(self.inst), "1.4.0")  # untouched

    def test_malformed_trust_file(self):
        updater.trust_path().write_text(json.dumps({"repo": "me/x", "public_key": "zz"}))
        with self.assertRaises(updater.UpdateError):
            updater.load_trust()


@unittest.skipIf(Ed25519PrivateKey is None, "cryptography not installed")
class ReleaseTool(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = Path(self.tmp.name)
        self.patches = [mock.patch.dict(os.environ, {"LOCALAPPDATA": str(t / "appdata")})]
        import secretstore
        if not secretstore.supported():  # stand-in for DPAPI off Windows
            self.patches += [
                mock.patch.object(secretstore, "protect", lambda b: b"FAKE" + b[::-1]),
                mock.patch.object(secretstore, "unprotect", lambda b: b[4:][::-1])]
        for p in self.patches:
            p.start()
        import release
        self.release = release
        self.out = t / "dist"

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    def test_init_build_publish_roundtrip(self):
        r = self.release
        self.assertEqual(r.main(["init", "--repo", "me/vaultkit"]), 0)
        self.assertNotIn(b"PRIVATE", r.key_path().read_bytes())
        trust = updater.load_trust()
        self.assertEqual(trust.repo, "me/vaultkit")

        version, z, s = r.build("notes here", self.out)
        pkg = updater.read_package(z.read_bytes(), s.read_bytes(), trust.public_key)
        self.assertEqual(pkg.version, version)
        self.assertEqual(pkg.notes, "notes here")
        self.assertIn("launcher.py", pkg.files)
        self.assertIn("tools/release.py", pkg.files)

        with mock.patch.object(r.shutil, "which", return_value="gh"), \
             mock.patch.object(r.subprocess, "run") as run:
            run.return_value.returncode = 0
            self.assertEqual(r.main(["publish", "--out", str(self.out)]), 0)
        cmd = run.call_args[0][0]
        self.assertEqual(cmd[:4], ["gh", "release", "create", f"v{version}"])
        self.assertIn("--repo", cmd)
        self.assertEqual(cmd[cmd.index("--repo") + 1], "me/vaultkit")

    def test_init_twice_keeps_the_same_key(self):
        r = self.release
        r.main(["init", "--repo", "me/vaultkit"])
        first = updater.load_trust().public_key
        r.main(["init", "--repo", "me/vaultkit"])
        self.assertEqual(updater.load_trust().public_key, first)


if __name__ == "__main__":
    unittest.main()
