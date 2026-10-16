"""Tests that only mean something on real Windows: DPAPI, the registry, PowerShell shortcuts,
and install.ps1 under Windows PowerShell 5.1. Skipped elsewhere; run on every push by
.github/workflows/tests.yml. Safe to run on your own PC: nothing outside temp folders is
touched, and the registry test uses its own value name, never vaultkit's real one.
"""
import os, subprocess, sys, tempfile, unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import autostart  # noqa: E402
import secretstore  # noqa: E402
import shortcuts  # noqa: E402
import updater  # noqa: E402

WINDOWS = os.name == "nt"


@unittest.skipUnless(WINDOWS, "Windows only")
class RealDpapi(unittest.TestCase):
    def test_roundtrip_and_ciphertext_differs(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"LOCALAPPDATA": d}):
            path = secretstore.save("corr3ct-h0rse ünïcode")
            blob = path.read_bytes()
            self.assertNotIn("corr3ct".encode(), blob)
            self.assertEqual(secretstore.load(), "corr3ct-h0rse ünïcode")
            path.write_bytes(blob[:-1] + bytes([blob[-1] ^ 1]))  # tampered blob must not decrypt
            with self.assertRaises(secretstore.SecretStoreError):
                secretstore.load()


@unittest.skipUnless(WINDOWS, "Windows only")
class RealRegistry(unittest.TestCase):
    def test_enable_disable_under_a_test_name(self):
        with mock.patch.object(autostart, "VALUE", "vaultkit-ci-test"), \
             tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"APPDATA": d}):
            try:
                launcher = Path(d) / "app" / "launcher.py"
                autostart.enable(launcher)
                self.assertTrue(autostart.is_enabled())
                self.assertIn(str(launcher.resolve()), autostart.registry().get())
                self.assertTrue(autostart.registry().get().endswith("--tray"))
            finally:
                autostart.disable()
            self.assertFalse(autostart.is_enabled())


@unittest.skipUnless(WINDOWS, "Windows only")
class RealShortcut(unittest.TestCase):
    def test_powershell_writes_a_working_shortcut(self):
        with tempfile.TemporaryDirectory() as d:
            lnk = Path(d) / "sub dir" / "vaultkit test.lnk"   # spaces on purpose
            target = Path(sys.executable)
            shortcuts.create(lnk, target, '"C:\\some path\\launcher.py"', Path(d), Path(d) / "x.ico")
            self.assertTrue(lnk.exists())
            read = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 "$s=(New-Object -ComObject WScript.Shell).CreateShortcut($env:L); "
                 "$s.TargetPath; $s.Arguments; $s.WorkingDirectory"],
                env=dict(os.environ, L=str(lnk)), capture_output=True, text=True, check=True)
            got = read.stdout.splitlines()
            self.assertEqual(Path(got[0]).resolve(), target.resolve())
            self.assertEqual(got[1], '"C:\\some path\\launcher.py"')
            self.assertEqual(Path(got[2]).resolve(), Path(d).resolve())


@unittest.skipUnless(WINDOWS, "Windows only")
class RealInstaller(unittest.TestCase):
    """install.ps1 under Windows PowerShell 5.1 (`powershell`, not `pwsh`), offline mode."""

    def setUp(self):
        from cryptography.hazmat.primitives import serialization as s
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        self.tmp = tempfile.TemporaryDirectory()
        t = Path(self.tmp.name)
        key = Ed25519PrivateKey.generate()
        self.pub = key.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw).hex()
        version, blob = updater.build_package(ROOT, "ci")
        self.zip = t / f"vaultkit-{version}.zip"
        self.zip.write_bytes(blob)
        Path(f"{self.zip}.sig").write_bytes(key.sign(blob))
        bad = bytearray(blob)
        bad[100] ^= 1
        self.tampered = t / "tampered.zip"
        self.tampered.write_bytes(bytes(bad))
        Path(f"{self.tampered}.sig").write_bytes(key.sign(blob))

    def tearDown(self):
        self.tmp.cleanup()

    def install(self, name, zip_path):
        t = Path(self.tmp.name)
        env = dict(os.environ, LOCALAPPDATA=str(t / f"local-{name}"))
        root = t / f"home-{name}" / "vaultkit"
        r = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                            str(ROOT / "install.ps1"), "-PublicKey", self.pub,
                            "-ReleaseZip", str(zip_path), "-Root", str(root),
                            "-Python", sys.executable, "-SkipPrerequisites", "-NoLaunch"],
                           env=env, capture_output=True, text=True)
        return r, root, t / f"local-{name}" / "vaultkit"

    def test_good_release_installs_and_pins_the_key(self):
        r, root, data = self.install("good", self.zip)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue((root / "app" / "vaultkit.py").exists())
        self.assertTrue((root / "vault").is_dir())
        self.assertFalse((root / "app" / "manifest.json").exists())
        self.assertIn(self.pub, (data / "update.json").read_text())

    def test_tampered_release_installs_nothing(self):
        r, root, _ = self.install("bad", self.tampered)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("STOPPED", r.stdout)
        self.assertFalse((root / "app").exists())


if __name__ == "__main__":
    unittest.main()
