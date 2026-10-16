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
import kpsetup  # noqa: E402
import secretstore  # noqa: E402
import shortcuts  # noqa: E402
import updater  # noqa: E402
import vaultkit as vk  # noqa: E402

WINDOWS = os.name == "nt"
# The real KeePassXC install runs only on GitHub's throwaway Windows machines: it installs
# software for all users and registers the browser connection.
REAL_INSTALL = WINDOWS and os.environ.get("VAULTKIT_REAL_KEEPASSXC") == "1" \
    and os.environ.get("GITHUB_ACTIONS") == "true"


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


@unittest.skipUnless(WINDOWS, "Windows only")
class RealKpsetupWindows(unittest.TestCase):
    TEST_KEY = r"Software\vaultkit-ci-test\NativeMessagingHosts\org.keepassxc.keepassxc_browser"

    def tearDown(self):
        import winreg
        parts = self.TEST_KEY.split("\\")
        for n in range(len(parts), 1, -1):  # Software\vaultkit-ci-test\... deepest first
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, "\\".join(parts[:n]))
            except OSError:
                pass

    def test_registry_and_connector(self):
        reg = kpsetup._WinReg()
        self.assertIsNone(reg.get(self.TEST_KEY, ""))
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.dict(os.environ, {"LOCALAPPDATA": d}), \
             mock.patch.object(kpsetup, "CHROME_KEY", self.TEST_KEY):
            root = Path(d) / "KeePassXC-install"
            root.mkdir()
            for name in ("keepassxc-cli.exe", "keepassxc-proxy.exe"):
                (root / name).write_text("x")
            path = kpsetup.register_connector(root / "keepassxc-cli.exe")
            self.assertEqual(reg.get(self.TEST_KEY, ""), str(path))  # the key's default value
            self.assertIsNone(kpsetup.connector_problem())
        reg.install_location()  # reads HKLM's uninstall list without raising

    def test_windows_signature_check(self):
        notepad = Path(os.environ["SystemRoot"]) / "System32" / "notepad.exe"
        status, signer = kpsetup.authenticode(notepad)
        self.assertEqual(status, "Valid")
        self.assertIn("Microsoft", signer)
        with self.assertRaises(kpsetup.SetupError):  # validly signed, but not by KeePassXC
            kpsetup.check_signature(notepad)
        with tempfile.TemporaryDirectory() as d:
            fake = Path(d) / "KeePassXC-9.9.9-Win64.msi"
            fake.write_bytes(b"not an installer")
            self.assertNotEqual(kpsetup.authenticode(fake)[0], "Valid")

    def test_tasklist(self):
        self.assertIsInstance(kpsetup.keepassxc_running(), bool)


@unittest.skipUnless(REAL_INSTALL, "real install: GitHub Actions with VAULTKIT_REAL_KEEPASSXC=1")
class RealKeePassXC(unittest.TestCase):
    """Download, verify and install the real KeePassXC; set it up; create a vault; open it."""

    def test_install_setup_create_open(self):
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.dict(os.environ, {"APPDATA": str(Path(d) / "roaming"),
                                          "LOCALAPPDATA": str(Path(d) / "local")}):
            cli = kpsetup.install_keepassxc(progress=print, quiet_ui=True)
            ver = kpsetup.cli_version(cli)
            print(f"::notice title=KeePassXC installed::{kpsetup.version_text(ver)} at {cli}")
            self.assertGreaterEqual(ver, kpsetup.MIN_VERSION)
            self.assertTrue(kpsetup.gui_exe(cli).is_file())
            with mock.patch.object(kpsetup.shutil, "which", return_value=None):
                self.assertEqual(kpsetup.find_cli(), cli)  # no PATH needed

            changed = kpsetup.apply_settings()
            self.assertTrue(changed)
            self.assertEqual(kpsetup.settings_to_change(), [])

            vault = Path(d) / "vault" / "main.kdbx"
            kpsetup.create_vault(cli, vault, "maple river lantern orbit")
            info = kpsetup.vault_info(vault)
            print(f"::notice title=keepassxc-cli db-create made::{info.summary()} "
                  f"(cipher {info.cipher}, AES rounds {info.rounds})")
            self.assertIn(info.kdf, ("AES-KDF", "Argon2d", "Argon2id"))
            v = vk.Vault(db=str(vault), cli=str(cli))
            v.set_secret("maple river lantern orbit")
            v.verify()  # the real keepassxc-cli opens it with that password
            checks = {c.key: c for c in kpsetup.run_checks(str(vault), cli=cli)}
            self.assertTrue(checks["keepassxc"].ok)
            self.assertTrue(checks["settings"].ok)

    def test_python_installer_download_is_signed(self):
        r = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                            str(ROOT / "install.ps1"), "-PublicKey", "0" * 64,
                            "-Root", tempfile.mkdtemp(), "-CheckDownloadsOnly"],
                           capture_output=True, text=True, timeout=600)
        print(r.stdout, r.stderr)
        ok = [line for line in r.stdout.splitlines() if line.startswith("OK:")]
        if ok:
            print(f"::notice title=python.org installer::{ok[0]}")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("is signed by Python Software Foundation", r.stdout)


if __name__ == "__main__":
    unittest.main()
