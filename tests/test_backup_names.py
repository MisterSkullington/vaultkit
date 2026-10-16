"""1.10: vault backups (OneDrive) and giving entries that share a title their own names."""
import io, json, os, struct, sys, tempfile, time, unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
import backup  # noqa: E402
import fake_hibp  # noqa: E402
import kpsetup  # noqa: E402
import vaultkit as vk  # noqa: E402

try:
    from PySide6.QtWidgets import QApplication
except ImportError:  # pragma: no cover
    QApplication = None

FAKE = str(HERE / "fake_kpcli.py")
PWCMD = f'"{sys.executable}" -c "print(\'{{}}\')"'


def kdbx(extra: bytes = b"") -> bytes:
    return struct.pack("<III", *kpsetup.SIGNATURE, 0x00040001) + os.urandom(64) + extra


class Backups(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.t = Path(self.tmp.name)
        self.env = mock.patch.dict(os.environ, {"LOCALAPPDATA": str(self.t / "local")})
        self.env.start()
        self.vault = self.t / "vault" / "main.kdbx"
        self.vault.parent.mkdir()
        self.vault.write_bytes(kdbx())
        self.target = self.t / "OneDrive" / "vaultkit backups"

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def at(self, minutes):
        return datetime(2026, 10, 16, 7, 0) + timedelta(minutes=minutes)

    def test_copies_only_when_the_vault_changed(self):
        first = backup.backup(self.vault, self.target, now=self.at(0))
        self.assertEqual(first.name, "main-20261016-070000.kdbx")
        self.assertEqual(first.read_bytes(), self.vault.read_bytes())
        self.assertIsNone(backup.backup(self.vault, self.target, now=self.at(60)))  # unchanged
        st = backup.status(self.vault, self.target)
        self.assertTrue(st.up_to_date)
        self.assertEqual((st.count, st.last_at), (1, self.at(0)))

        self.vault.write_bytes(kdbx(b"new password"))  # KeePassXC saved a change
        self.assertFalse(backup.status(self.vault, self.target).up_to_date)
        second = backup.backup(self.vault, self.target, now=self.at(120))
        self.assertEqual(second.name, "main-20261016-090000.kdbx")
        self.assertEqual([p.name for p in self.target.iterdir() if p.name.startswith(".")], [])

    def test_keeps_the_newest_and_never_touches_other_files(self):
        self.target.mkdir(parents=True)
        (self.target / "my notes.txt").write_text("mine")
        (self.target / "other-20200101-000000.kdbx").write_bytes(kdbx())  # another vault's
        for i in range(5):
            self.vault.write_bytes(kdbx(bytes([i])))
            backup.backup(self.vault, self.target, keep=3, now=self.at(i))
        mine = [p.name for p in backup.copies(self.target, "main")]
        self.assertEqual(mine, ["main-20261016-070400.kdbx", "main-20261016-070300.kdbx",
                                "main-20261016-070200.kdbx"])
        self.assertTrue((self.target / "my notes.txt").exists())
        self.assertTrue((self.target / "other-20200101-000000.kdbx").exists())

    def test_same_second_and_a_deleted_copy(self):
        a = backup.backup(self.vault, self.target, now=self.at(0))
        self.vault.write_bytes(kdbx(b"x"))
        b = backup.backup(self.vault, self.target, now=self.at(0))
        self.assertEqual(b.name, "main-20261016-070000-2.kdbx")
        b.unlink()  # copy removed (by hand, or OneDrive): made again even though unchanged
        self.assertIsNotNone(backup.backup(self.vault, self.target, now=self.at(5)))
        self.assertTrue(a.exists())

    def test_refuses_what_isnt_a_vault(self):
        self.vault.write_bytes(b"half-written or not a vault")
        with self.assertRaises(backup.BackupError):
            backup.backup(self.vault, self.target)
        self.assertFalse(self.target.exists())
        with self.assertRaises(backup.BackupError):
            backup.backup(self.t / "missing.kdbx", self.target)

    def test_finds_onedrive(self):
        od = self.t / "OneDrive"
        od.mkdir()
        with mock.patch.dict(os.environ, {"OneDrive": str(od)}):
            self.assertEqual(backup.default_target(), od / "vaultkit backups")
        with mock.patch.dict(os.environ, {"OneDrive": "", "OneDriveConsumer": "",
                                          "OneDriveCommercial": ""}), \
             mock.patch.object(Path, "home", lambda: self.t / "nobody"):
            self.assertIsNone(backup.default_target())

    def test_command_line(self):
        out = io.StringIO()
        with redirect_stdout(out):
            rc = vk.main(["--db", str(self.vault), "backup", "--to", str(self.target)])
            vk.main(["--db", str(self.vault), "backup", "--to", str(self.target)])
        self.assertEqual(rc, 0)
        self.assertIn("Backed up to", out.getvalue())
        self.assertIn("No changes since the last backup", out.getvalue())


class SharedNames(unittest.TestCase):
    ENTRIES = {
        "Passwords/accounts.google.com": {"UserName": "jordan@example.com", "Password": "same-1"},
        "Passwords/accounts.google.com#2": {"UserName": "papa@example.com", "Password": "same-1"},
        "Passwords/accounts.google.com#3": {"UserName": "", "Password": "other-2"},
        "Passwords/panel.example.org": {"UserName": "me", "Password": "p-1"},
        "Passwords/panel.example.org#2": {"UserName": "me", "Password": "p-2"},
        "Passwords/solo.com": {"UserName": "me", "Password": "uniq-Solo-55!x"},
    }

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name, "state.json")
        entries = {k: dict(v, URL="", Notes="") for k, v in self.ENTRIES.items()}
        self.state.write_text(json.dumps({"master": "m4ster", "groups": [], "entries": entries}))
        self.env = mock.patch.dict(os.environ, {"FAKE_KP_STATE": str(self.state),
                                                "XDG_STATE_HOME": self.tmp.name,
                                                "LOCALAPPDATA": self.tmp.name})
        self.env.start()
        real_init = vk.Vault.__init__

        def init(v, *a, **kw):
            real_init(v, *a, **kw)
            v.cli, v.cli_prefix_args = sys.executable, [FAKE]

        self.init = mock.patch.object(vk.Vault, "__init__", init)
        self.init.start()

    def tearDown(self):
        self.init.stop()
        self.env.stop()
        self.tmp.cleanup()

    def entries(self):
        return json.loads(self.state.read_text())["entries"]

    def test_each_gets_its_own_name_and_nothing_else_changes(self):
        before = self.entries()
        out = io.StringIO()
        with redirect_stdout(out):
            rc = vk.main(["--db", "v.kdbx", "--password-cmd", PWCMD.format("m4ster"), "names"])
        self.assertEqual(rc, 0)
        after = self.entries()
        self.assertEqual(sorted(after), sorted([
            "Passwords/accounts.google.com (jordan@example.com)",
            "Passwords/accounts.google.com (papa@example.com)",
            "Passwords/accounts.google.com (no username)",
            "Passwords/panel.example.org (me)",
            "Passwords/panel.example.org (me) 2",
            "Passwords/solo.com"]))
        # same passwords, same order as before: only titles changed
        self.assertEqual([e["Password"] for e in after.values()],
                         [e["Password"] for e in before.values()])
        self.assertIn("accounts.google.com  ->  Passwords/accounts.google.com (papa@example.com)",
                      out.getvalue())
        _, dupes = vk.display_keys(vk.Vault(db="v.kdbx", password_cmd=PWCMD.format("m4ster"))
                                   .export_entries())
        self.assertEqual(dupes, [])
        with redirect_stdout(io.StringIO()) as again:
            vk.main(["--db", "v.kdbx", "--password-cmd", PWCMD.format("m4ster"), "names"])
        self.assertIn("already has its own name", again.getvalue())


@unittest.skipIf(QApplication is None, "PySide6 not installed")
class AppScreens(SharedNames):
    @classmethod
    def setUpClass(cls):
        import app as appmod
        cls.appmod = appmod
        cls.qapp = QApplication.instance() or QApplication([])
        appmod.apply_theme(cls.qapp, "mist")

    def setUp(self):
        super().setUp()
        self.patches = [fake_hibp.patch([]),
                        mock.patch.object(vk, "fetch_range", lambda p: ""),
                        mock.patch.object(kpsetup, "find_cli", lambda: None)]
        for p in self.patches:
            p.start()
        self.win = self.appmod.MainWindow(check_updates=False, background=False)
        self.win.settings.clear()
        self.win.idle.setInterval(10 * 60_000)
        self.win.show()

    def tearDown(self):
        self.win.quitting = True
        self.win.close()
        for p in self.patches:
            p.stop()
        super().tearDown()

    def pump(self, until, timeout=45.0):
        end = time.time() + timeout
        while time.time() < end:
            self.qapp.processEvents()
            if until():
                return
            time.sleep(0.02)
        self.fail("timed out")

    def test_double_click_a_shared_name_then_fix_reaches_them(self):
        u, d = self.win.unlock, self.win.dash
        u.db.setText("v.kdbx")
        u.pw.setText("m4ster")
        u.go.click()
        self.pump(lambda: d.report is not None)
        r = d.report
        self.assertEqual(r.samename, 2)
        row = next(i for i, issue in enumerate(r.issues) if " [user: " in issue.name)
        self.assertFalse(r.issues[row].fixable)
        d.report = r
        d.fix_row(row)  # a "[user: …]" row: renames its whole group
        self.pump(lambda: d.report is not None and d.report is not r
                  and "Renamed:" in d.sub.text())
        self.assertIn("accounts.google.com (papa@example.com)", d.sub.text())
        self.assertEqual(d.report.samename, 1)  # panel.example.org still shared
        same = next(i for i, issue in enumerate(d.report.issues) if issue.kind == "samename")
        before = d.report
        d.fix_row(same)
        self.pump(lambda: d.report is not None and d.report is not before
                  and d.report.samename == 0)
        self.assertTrue(all(i.fixable for i in d.report.issues))

    def test_backups_row_and_back_up_now(self):
        vault = Path(self.tmp.name, "main.kdbx")
        vault.write_bytes(kdbx())
        od = Path(self.tmp.name, "OneDrive")
        od.mkdir()
        self.win.settings.setValue("db", str(vault))
        with mock.patch.dict(os.environ, {"OneDrive": str(od)}):
            s = self.win.setup
            self.win.show_setup()
            self.pump(lambda: s.check("backup") is not None and not s.busy)
            self.assertEqual((s.check("backup").ok, s.check("backup").action),
                             (False, "Back up now"))
            s.row("backup").button.click()
            self.pump(lambda: s.status.text() == "Done." and s.check("backup")
                      and s.check("backup").ok)
            self.assertIn("1 kept in", s.check("backup").detail)
            self.assertEqual(len(backup.copies(od / "vaultkit backups", "main")), 1)

            self.win.settings.setValue("backups", False)
            self.win.setup.refresh()
            self.pump(lambda: s.check("backup").action == "Turn on")
            vault.write_bytes(kdbx(b"changed"))
            self.win.maybe_backup()   # off: nothing happens
            self.win.net.wait()
            self.assertEqual(len(backup.copies(od / "vaultkit backups", "main")), 1)
            self.win.settings.setValue("backups", True)
            self.win.maybe_backup()
            self.pump(lambda: len(backup.copies(od / "vaultkit backups", "main")) == 2)


if __name__ == "__main__":
    unittest.main()
