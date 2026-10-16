"""Headless GUI tests (QT_QPA_PLATFORM=offscreen). Skipped if PySide6 isn't installed."""
import json, os, sys, tempfile, time, unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

try:
    from PySide6.QtWidgets import QApplication
except ImportError:  # pragma: no cover
    QApplication = None

import vaultkit as vk  # noqa: E402

FAKE = str(HERE / "fake_kpcli.py")
SHOTS = os.environ.get("VAULTKIT_SHOTS")  # set to a folder to save screenshots


@unittest.skipIf(QApplication is None, "PySide6 not installed")
class AppFlow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as appmod
        cls.appmod = appmod
        cls.qapp = QApplication.instance() or QApplication([])
        appmod.apply_theme(cls.qapp)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name, "state.json")
        entries = {
            "Web/github": {"UserName": "me", "URL": "https://github.com", "Password": "P@ssw0rd", "Notes": ""},
            "Web/bank": {"UserName": "me", "URL": "https://bank", "Password": "P@ssw0rd", "Notes": ""},
            "Web/spotify": {"UserName": "me", "URL": "https://spotify.com", "Password": "hunter22x", "Notes": ""},
            "Web/steam": {"UserName": "me", "URL": "https://steam.com", "Password": "hunter22x", "Notes": ""},
        }
        for i in range(30):
            entries[f"Web/site{i:02d}"] = {"UserName": "me", "URL": f"https://s{i}.com",
                                           "Password": f"uniq-{i}-Xq9!", "Notes": ""}
        self.state.write_text(json.dumps({"master": "m4ster", "groups": [], "entries": entries}))
        breached = vk.sha1_hex("P@ssw0rd")
        real_init = vk.Vault.__init__

        def init(v, *a, **kw):
            real_init(v, *a, **kw)
            v.cli, v.cli_prefix_args = sys.executable, [FAKE]

        self.patches = [
            mock.patch.dict(os.environ, {"FAKE_KP_STATE": str(self.state),
                                         "XDG_STATE_HOME": self.tmp.name,
                                         "LOCALAPPDATA": self.tmp.name}),
            mock.patch.object(vk.Vault, "__init__", init),
            mock.patch.object(vk, "fetch_range",
                              lambda p: f"{breached[5:]}:6421042\n" if p == breached[:5] else ""),
        ]
        for p in self.patches:
            p.start()
        self.win = self.appmod.MainWindow(idle_minutes=0.02)  # ~1.2 s idle lock for the test
        self.win.settings.clear()
        self.win.resize(860, 640)
        self.win.show()

    def tearDown(self):
        self.win.close()
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    def pump(self, until, timeout=15.0):
        end = time.time() + timeout
        while time.time() < end:
            self.qapp.processEvents()
            if until():
                return
            time.sleep(0.02)
        self.fail("timed out waiting for UI")

    def shot(self, name):
        if SHOTS:
            Path(SHOTS).mkdir(parents=True, exist_ok=True)
            self.qapp.processEvents()
            self.win.grab().save(str(Path(SHOTS) / f"{name}.png"))

    def unlock(self, pw):
        u = self.win.unlock
        u.db.setText("v.kdbx")
        u.pw.setText(pw)
        u.go.click()

    def test_wrong_password_shows_plain_error(self):
        self.shot("1-unlock")
        self.unlock("nope")
        self.pump(lambda: self.win.unlock.error.isVisible())
        self.assertIn("doesn't open this vault", self.win.unlock.error.text())
        self.assertEqual(self.win.unlock.pw.text(), "")  # never left in the field
        self.shot("2-wrong-password")

    def test_unlock_check_and_report(self):
        self.unlock("m4ster")
        d = self.win.dash
        self.pump(lambda: d.report is not None)
        r = d.report
        self.assertEqual((r.scanned, r.breached, r.reused, r.safe), (34, 2, 2, 30))
        self.assertEqual(d.verdict.text(), "4 passwords need changing")
        self.assertEqual(d.table.rowCount(), 4)
        self.assertTrue(d.table.item(0, 1).text().startswith("Found in 6,421,042 known breaches. "
                                                              "Same password as 1 other entry."))
        self.assertTrue(Path(self.tmp.name, "vaultkit", "last-check.json").exists())
        self.shot("3-dashboard")

    def vault_entries(self):
        return json.loads(self.state.read_text())["entries"]

    def test_fix_flow_accept_reject_rules_skip(self):
        self.win.idle.setInterval(10 * 60_000)  # keep the idle lock out of this test
        opened = []
        mock.patch.object(self.appmod, "open_link", opened.append).start()
        self.unlock("m4ster")
        d, f = self.win.dash, self.win.fix
        self.pump(lambda: d.report is not None)
        self.assertTrue(d.fix_btn.isVisible())
        d.fix_btn.click()
        ready = lambda: f.secret.text() and f.accept_btn.isEnabled()

        # 1 of 4: Web/bank -> accepted
        self.pump(ready)
        self.assertEqual(f.title.text(), "Web/bank")
        self.assertEqual(f.progress.text(), "1 of 4")
        new_bank = f.secret.text()
        self.assertEqual(self.vault_entries()[vk.pending_path("Web/bank")]["Password"], new_bank)
        self.assertEqual(self.qapp.clipboard().text(), new_bank)  # copied automatically
        f.open_btn.click()
        self.shot("5-fix")
        f.accept_btn.click()

        # 2 of 4: Web/github -> rejected, then stricter rules
        self.pump(lambda: f.title.text() == "Web/github" and ready())
        self.assertEqual(self.vault_entries()["Web/bank"]["Password"], new_bank)
        self.assertNotIn(vk.pending_path("Web/bank"), self.vault_entries())
        f.reject_btn.click()
        self.pump(lambda: f.rules.isVisible() and f.save_rules_btn.isEnabled())
        self.assertFalse(f.accept_btn.isVisible())
        self.assertEqual(self.vault_entries()["Web/github"]["Password"], "P@ssw0rd")
        self.shot("6-rejected")
        f.length.setValue(20)
        f.no_symbols.setChecked(True)
        f.save_rules_btn.click()
        self.pump(lambda: f.accept_btn.isVisible() and ready() and len(f.secret.text()) == 20)
        self.assertTrue(f.secret.text().isalnum())
        self.assertIn("length: 20", self.vault_entries()["Web/github"]["Notes"])
        f.accept_btn.click()

        # 3 and 4: skip both
        self.pump(lambda: f.title.text() == "Web/spotify" and ready())
        f.skip_btn.click()
        self.pump(lambda: f.title.text() == "Web/steam" and ready())
        f.skip_btn.click()

        # back on the dashboard, re-checked
        self.pump(lambda: self.win.stack.currentWidget() is d and d.report is not None
                  and d.report.breached == 0)
        self.assertEqual(d.report.reused, 2)  # spotify + steam still share a password
        self.assertEqual(opened, ["https://bank/.well-known/change-password"])
        self.assertIn(vk.pending_path("Web/spotify"), self.vault_entries())  # skipped: kept for later
        self.assertEqual(self.qapp.clipboard().text(), "")  # clipboard wiped on finish
        self.shot("7-after-fix")

    def test_lock_during_fix_keeps_pending_and_wipes_screen(self):
        self.win.idle.setInterval(10 * 60_000)
        self.unlock("m4ster")
        d, f = self.win.dash, self.win.fix
        self.pump(lambda: d.report is not None)
        d.fix_row(0)
        self.pump(lambda: f.secret.text() and f.accept_btn.isEnabled())
        self.win.lock()
        self.assertEqual(f.secret.text(), "")
        self.assertEqual(self.qapp.clipboard().text(), "")
        self.assertIn(vk.pending_path("Web/bank"), self.vault_entries())  # safe to resume later

    def test_idle_lock_wipes_secret(self):
        self.unlock("m4ster")
        d = self.win.dash
        self.pump(lambda: d.report is not None)
        v = d.vault
        self.pump(lambda: self.win.stack.currentWidget() is self.win.unlock, timeout=10)
        self.assertIsNone(v._pw)
        self.assertIn("Locked after", self.win.unlock.error.text())
        self.shot("4-locked")


@unittest.skipIf(QApplication is None, "PySide6 not installed")
class UpdateBanner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as appmod
        cls.appmod = appmod
        cls.qapp = QApplication.instance() or QApplication([])

    def make(self, **kw):
        w = self.appmod.MainWindow(check_updates=False, **kw)
        w.show()
        self.qapp.processEvents()
        return w

    def test_ready_update_offers_restart(self):
        import updater
        w = self.make()
        w._update_staged(updater.Staged("9.9.9", "Fix button", Path(".")))
        self.assertTrue(w.banner.isVisible())
        self.assertIn("9.9.9", w.banner.text.text())
        self.assertIn("Fix button", w.banner.text.text())
        self.assertEqual(w.banner.action.text(), "Restart now")
        w.close()

    def test_rejected_update_warns(self):
        w = self.make()
        w._update_failed("the update's signature doesn't match your trusted key")
        self.assertTrue(w.banner.isVisible())
        self.assertEqual(w.banner.property("warn"), "true")
        self.assertFalse(w.banner.action.isVisible())
        w.close()

    def test_offline_stays_quiet(self):
        w = self.make()
        w._update_failed("Couldn't reach the breach database")
        self.assertFalse(w.banner.isVisible())
        w.close()

    def test_startup_note_after_update(self):
        w = self.make(startup_note="Updated to vaultkit 9.9.9.")
        self.assertTrue(w.banner.isVisible())
        self.assertEqual(w.banner.property("warn"), "false")
        w.close()


@unittest.skipIf(QApplication is None, "PySide6 not installed")
class ReportModel(unittest.TestCase):
    def test_all_safe(self):
        import app as appmod
        r = appmod.build_report([{"Path": "a"}], {}, [], [], 1)
        self.assertEqual((r.needs_changing, r.safe, r.issues), (0, 1, []))

    def test_breached_and_reused_merge_into_one_row(self):
        import app as appmod
        rows = [{"Path": p, "Last Modified": "2021-03-04T10:00:00"} for p in ("a", "b")]
        r = appmod.build_report(rows, {"a": 5}, [["a", "b"]], [], 2)
        self.assertEqual(len(r.issues), 2)
        self.assertEqual(r.issues[0].kind, "breached")
        self.assertEqual(r.issues[0].problem, "Found in 5 known breaches. Same password as 1 other entry.")
        self.assertEqual(r.issues[0].changed, "2021-03-04")
        self.assertEqual((r.breached, r.reused, r.safe), (1, 1, 0))


if __name__ == "__main__":
    unittest.main()
