"""1.9 app screens: Setup (install + recommended setup of KeePassXC) and Create a vault.
Headless; KeePassXC, the network and the registry are faked."""
import json, os, sys, tempfile, time, unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

try:
    from PySide6.QtWidgets import QApplication
except ImportError:  # pragma: no cover
    QApplication = None

import fake_hibp  # noqa: E402
import kpsetup  # noqa: E402
import vaultkit as vk  # noqa: E402
from test_kpsetup import FakeRegistry  # noqa: E402

FAKE = [sys.executable, str(HERE / "fake_kpcli.py")]
GOOD_PW = "maple river lantern orbit"


@unittest.skipIf(QApplication is None, "PySide6 not installed")
class SetupScreens(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as appmod
        cls.appmod = appmod
        cls.qapp = QApplication.instance() or QApplication([])
        appmod.apply_theme(cls.qapp, "mist")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.t = Path(self.tmp.name)
        self.state = self.t / "state.json"
        self.state.write_text(json.dumps({"master": "m4ster", "groups": [], "entries": {
            "Web/x": {"UserName": "me", "URL": "https://x.com", "Password": "uniq-Xq9!-long-1",
                      "Notes": ""}}}))
        self.cli_path = None  # what find_cli() answers: None = KeePassXC not installed
        self.reg = FakeRegistry()
        real_init, real_create = vk.Vault.__init__, kpsetup.create_vault
        self.pwned = set()

        def init(v, *a, **kw):
            real_init(v, *a, **kw)
            v.cli, v.cli_prefix_args = sys.executable, [FAKE[1]]

        def fetch_range(prefix):
            return "".join(f"{h[5:]}:42\n" for h in map(vk.sha1_hex, self.pwned) if h[:5] == prefix)

        self.patches = [
            mock.patch.dict(os.environ, {"FAKE_KP_STATE": str(self.state), "XDG_STATE_HOME": str(self.t),
                                         "LOCALAPPDATA": str(self.t / "local"),
                                         "APPDATA": str(self.t / "roaming")}),
            mock.patch.object(vk.Vault, "__init__", init),
            mock.patch.object(vk, "fetch_range", fetch_range),
            mock.patch.object(kpsetup, "find_cli", lambda: self.cli_path),
            mock.patch.object(kpsetup, "cli_version", lambda cli: (2, 7, 12)),
            mock.patch.object(kpsetup, "create_vault", lambda cli, path, pw: real_create(FAKE, path, pw)),
            mock.patch.object(kpsetup, "_registry", self.reg),
            mock.patch.object(kpsetup, "supported", lambda: True),
            mock.patch.object(kpsetup, "keepassxc_running", lambda: False),
            mock.patch.object(self.appmod.autostart, "supported", lambda: False),
            fake_hibp.patch([]),
        ]
        for p in self.patches:
            p.start()
        self.win = self.appmod.MainWindow(check_updates=False, background=False)
        self.win.settings.clear()
        self.win.idle.setInterval(10 * 60_000)
        self.win.show()
        self.win.unlock.refresh()

    def tearDown(self):
        self.win.quitting = True
        self.win.close()
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    def pump(self, until, timeout=45.0):
        end = time.time() + timeout
        while time.time() < end:
            self.qapp.processEvents()
            if until():
                return
            time.sleep(0.02)
        self.fail("timed out")

    def installed(self) -> Path:
        root = self.t / "Program Files" / "KeePassXC"
        root.mkdir(parents=True)
        for name in ("keepassxc-cli.exe", "keepassxc-proxy.exe", "KeePassXC.exe",
                     "keepassxc-cli", "keepassxc-proxy", "keepassxc"):
            (root / name).write_text("x")
        return root / ("keepassxc-cli.exe" if os.name == "nt" else "keepassxc-cli")

    def open_setup(self):
        s = self.win.setup
        s.checks = []
        self.win.show_setup()
        self.pump(lambda: s.checks and not s.busy and s.recheck.isEnabled())
        return s

    def row(self, key):
        return self.win.setup.row(key)

    # -- KeePassXC missing
    def test_missing_keepassxc_is_obvious_and_installs_from_setup(self):
        u = self.win.unlock
        self.assertTrue(u.kp_notice.isVisible())
        u.kp_button.click()
        self.assertIs(self.win.stack.currentWidget(), self.win.setup)
        self.pump(lambda: self.win.setup.checks)
        self.assertEqual(self.row("keepassxc").button.text(), "Install KeePassXC")
        self.assertFalse(self.row("settings").button.isVisible())

        progress = []
        self.win.setup.progress.message.connect(progress.append)

        def install(progress=print, quiet_ui=False):
            progress("Downloading KeePassXC 2.7.12…")
            self.cli_path = self.installed()
            return self.cli_path

        with mock.patch.object(kpsetup, "install_keepassxc", install):
            self.row("keepassxc").button.click()
            self.assertIn("Getting KeePassXC", self.win.setup.status.text())
            self.pump(lambda: self.win.setup.status.text() == "Done." and self.win.setup.checks
                      and self.win.setup.check("keepassxc").ok)
        self.assertEqual(progress, ["Downloading KeePassXC 2.7.12…"])
        checks = {c.key: c.ok for c in self.win.setup.checks}
        self.assertEqual((checks["settings"], checks["connector"], checks["autostart"]),
                         (True, True, True))  # recommended setup applied straight away
        self.assertIn("Enabled=true", kpsetup.settings_paths()[0].read_text())

        self.win.setup.back_requested.emit()
        self.assertIs(self.win.stack.currentWidget(), self.win.unlock)
        self.assertFalse(self.win.unlock.kp_notice.isVisible())

    def test_a_failed_install_says_why_and_changes_nothing(self):
        self.open_setup()
        boom = kpsetup.SetupError("You chose No on the Windows prompt, so KeePassXC wasn't installed.")
        with mock.patch.object(kpsetup, "install_keepassxc", mock.Mock(side_effect=boom)):
            self.row("keepassxc").button.click()
            self.pump(lambda: "You chose No" in self.win.setup.status.text()
                      and not self.win.setup.busy)
        self.assertEqual(self.win.setup.status.objectName(), "error")
        self.assertFalse(kpsetup.settings_paths()[0].exists())

    # -- installed, set up from the page
    def test_fix_buttons(self):
        self.cli_path = self.installed()
        s = self.open_setup()
        self.assertFalse(s.check("settings").ok)
        self.row("settings").button.click()
        self.pump(lambda: s.status.text() == "Done." and s.check("settings")
                  and s.check("settings").ok)
        self.row("connector").button.click()
        self.pump(lambda: s.check("connector") and s.check("connector").ok)
        self.row("autostart").button.click()
        self.pump(lambda: s.check("autostart") and s.check("autostart").ok)
        self.assertTrue(self.reg.get(kpsetup.RUN_KEY, "KeePassXC").endswith('KeePassXC.exe"')
                        or self.reg.get(kpsetup.RUN_KEY, "KeePassXC").endswith('keepassxc"'))
        opened = []
        with mock.patch.object(self.appmod, "open_link", opened.append):
            self.row("extension").button.click()
        self.assertEqual(opened, [kpsetup.EXTENSION_URL])

    def test_settings_wait_for_keepassxc_to_close(self):
        self.cli_path = self.installed()
        s = self.open_setup()
        with mock.patch.object(kpsetup, "keepassxc_running", lambda: True):
            self.row("settings").button.click()
            self.pump(lambda: "Close KeePassXC first" in s.status.text() and not s.busy)
        self.assertFalse(kpsetup.settings_paths()[0].exists())

    # -- a new vault
    def fill(self, pw=GOOD_PW, again=None, paper=True, path=None):
        c = self.win.create
        c.path.setText(str(path or self.t / "vault" / "main.kdbx"))
        c.pw.setText(pw)
        c.pw2.setText(pw if again is None else again)
        c.paper.setChecked(paper)
        c.go.click()

    def test_create_vault_then_guide_to_argon2id(self):
        self.cli_path = self.installed()
        self.win.unlock.create_link.click()
        c = self.win.create
        self.assertIs(self.win.stack.currentWidget(), c)
        for kwargs, error in (({"pw": "Summer2024!"}, "At least 12"),
                              ({"pw": "Summer2024!!!"}, "word with numbers"),
                              ({"again": "maple river lantern orbiT"}, "don't match"),
                              ({"paper": False}, "Write the master password down")):
            self.fill(**kwargs)
            self.assertIn(error, c.error.text())
        self.assertFalse((self.t / "vault").exists())

        self.pwned = {GOOD_PW}
        self.fill()
        self.pump(lambda: c.go.isEnabled() and c.error.isVisible())
        self.assertIn("known data breaches", c.error.text())
        self.assertEqual(c.pw.text(), "")  # never left on screen
        self.assertFalse((self.t / "vault" / "main.kdbx").exists())

        self.pwned = set()
        self.fill()
        s = self.win.setup
        self.pump(lambda: self.win.stack.currentWidget() is s and s.check("vault"))
        path = str(self.t / "vault" / "main.kdbx")
        self.assertTrue(Path(path).is_file())
        self.assertEqual(self.win.settings.value("db"), path)
        self.assertEqual(self.win.unlock.db.text(), path)
        self.assertIn("Your vault is created", s.status.text())
        vault = s.check("vault")
        self.assertFalse(vault.ok)
        self.assertIn("KDBX 3.1, AES-KDF", vault.detail)
        self.assertTrue(s.guide.isVisible())
        self.assertIn("Argon2id (KDBX 4)", s.guide_steps.text())

        # and it opens with the new master password
        v = vk.Vault(db=path)
        v.set_secret(GOOD_PW)
        v.verify()

    def test_lock_wipes_a_half_typed_master_password(self):
        self.cli_path = self.installed()
        self.win.show_create()
        self.win.create.pw.setText("half typed")
        self.win.lock()
        self.assertEqual(self.win.create.pw.text(), "")
        self.assertIs(self.win.stack.currentWidget(), self.win.unlock)

    def test_setup_from_the_dashboard_goes_back_to_it(self):
        self.cli_path = self.installed()
        self.win.unlock.db.setText("v.kdbx")
        self.win.unlock.pw.setText("m4ster")
        self.win.unlock.go.click()
        self.pump(lambda: self.win.dash.report is not None)
        self.win.setup_links[1].click()
        self.pump(lambda: self.win.setup.checks)
        self.win.setup.back_requested.emit()
        self.assertIs(self.win.stack.currentWidget(), self.win.dash)
        self.assertIsNotNone(self.win.dash.vault)


if __name__ == "__main__":
    unittest.main()
