"""M4 (tray, daily check, notifications, autostart, single instance) and themes. Headless."""
import json, os, subprocess, sys, tempfile, time, unittest
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

import autostart  # noqa: E402
import fake_hibp  # noqa: E402
import secretstore  # noqa: E402
import vaultkit as vk  # noqa: E402

FAKE = str(HERE / "fake_kpcli.py")


def fake_protect(b):
    return b"FAKE" + b[::-1]


def fake_unprotect(b):
    return b[4:][::-1]


class FakeTray:
    def __init__(self):
        self.messages = []

    def showMessage(self, title, body, *a):
        self.messages.append((title, body))

    def setIcon(self, *a): pass
    def setToolTip(self, *a): pass
    def hide(self): pass


@unittest.skipIf(QApplication is None, "PySide6 not installed")
class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as appmod
        cls.appmod = appmod
        cls.qapp = QApplication.instance() or QApplication([])
        appmod.apply_theme(cls.qapp, "mist")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = Path(self.tmp.name)
        self.state = t / "state.json"
        entries = {
            "Web/github": {"UserName": "me", "URL": "https://github.com", "Password": "P@ssw0rd", "Notes": ""},
            "Web/bank": {"UserName": "me", "URL": "https://bank", "Password": "uniq-Bank-77!", "Notes": ""},
        }
        self.state.write_text(json.dumps({"master": "m4ster", "groups": [], "entries": entries}))
        breached = vk.sha1_hex("P@ssw0rd")
        real_init = vk.Vault.__init__

        def init(v, *a, **kw):
            real_init(v, *a, **kw)
            v.cli, v.cli_prefix_args = sys.executable, [FAKE]

        self.patches = [
            mock.patch.dict(os.environ, {"FAKE_KP_STATE": str(self.state), "XDG_STATE_HOME": str(t),
                                         "LOCALAPPDATA": str(t), "APPDATA": str(t / "roaming")}),
            mock.patch.object(vk.Vault, "__init__", init),
            mock.patch.object(vk, "fetch_range",
                              lambda p: f"{breached[5:]}:99\n" if p == breached[:5] else ""),
            mock.patch.object(secretstore, "supported", lambda: True),
            mock.patch.object(secretstore, "protect", fake_protect),
            mock.patch.object(secretstore, "unprotect", fake_unprotect),
            fake_hibp.patch([]),
        ]
        for p in self.patches:
            p.start()
        self.win = self.appmod.MainWindow(check_updates=False, background=False)
        self.win.settings.clear()
        self.win.settings.setValue("db", "v.kdbx")
        self.win.tray = FakeTray()
        self.win.known_breached = set()

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

    @property
    def shown(self):
        return self.win.tray.messages


class DailyCheck(Base):
    def test_new_breach_then_weekly_reminder_then_quiet(self):
        secretstore.save("m4ster")
        self.assertTrue(self.win.check_due())
        self.win.maybe_daily_check()
        self.pump(lambda: self.shown)
        title, body = self.shown[0]
        self.assertEqual(title, "Password found in a breach")
        self.assertNotIn("github", body.lower())  # never names sites (lock-screen safe)
        self.assertFalse(self.win.check_due())
        self.assertTrue((Path(self.tmp.name) / "vaultkit" / "last-check.json").exists())

        self.win.run_check(explicit=False)  # same breach again: no alarm, one weekly nudge
        self.pump(lambda: len(self.shown) == 2)
        self.assertEqual(self.shown[1][0], "Passwords to change")
        self.win.run_check(explicit=False)  # within the week: silent
        self.pump(lambda: self.win.runner.pool.activeThreadCount() == 0)
        self.qapp.processEvents()
        time.sleep(0.3)
        self.qapp.processEvents()
        self.assertEqual(len(self.shown), 2)

    def test_explicit_check_always_reports(self):
        secretstore.save("m4ster")
        self.win.known_breached = {"Web/github"}  # nothing new
        self.win.run_check(explicit=True)
        self.pump(lambda: self.shown)
        self.assertEqual(self.shown[0], ("Check finished", "1 password needs changing."))

    def test_without_saved_password_reminds_once_a_day(self):
        self.win.maybe_daily_check()
        self.win.maybe_daily_check()
        self.assertEqual([t for t, _ in self.shown], ["Daily password check"])

    def test_stale_saved_password_warns_once(self):
        secretstore.save("old-master")
        self.win.run_check(explicit=False)
        self.pump(lambda: self.shown)
        self.assertEqual(self.shown[0][0], "Daily check couldn't unlock your vault")
        self.win.run_check(explicit=False)
        time.sleep(1.5)
        self.qapp.processEvents()
        self.assertEqual(len(self.shown), 1)
        self.assertTrue(self.win.check_due())  # still due: retried, not marked done

    def test_daily_check_can_be_turned_off(self):
        self.win.settings.setValue("daily_check", False)
        self.win.maybe_daily_check()
        self.assertEqual(self.shown, [])


class Window(Base):
    def test_close_locks_and_hides_to_tray(self):
        self.win.show()
        self.win.unlock.db.setText("v.kdbx")
        self.win.unlock.pw.setText("m4ster")
        self.win.unlock.go.click()
        self.pump(lambda: self.win.dash.report is not None)
        v = self.win.dash.vault
        self.win.close()
        self.assertFalse(self.win.isVisible())
        self.assertIsNone(v._pw)  # never in the tray with the vault open
        self.assertIs(self.win.stack.currentWidget(), self.win.unlock)
        self.assertEqual(self.shown[0][0], "vaultkit is still running")
        self.win.show_window()
        self.assertTrue(self.win.isVisible())

    def test_version_is_shown(self):
        v = vk.__version__
        self.assertEqual(self.win.windowTitle(), f"vaultkit {v}")
        self.assertEqual([l.text() for l in self.win.version_labels], [f"vaultkit {v}"] * 2)
        self.assertIs(self.win.version_labels[0].window(), self.win)  # actually on screen

    def test_icons_for_each_status(self):
        for status in (None, "ok", "warn", "bad"):
            self.assertFalse(self.appmod.make_icon(status).isNull())


class Themes(Base):
    def test_every_theme_applies_and_persists(self):
        for key, t in self.appmod.THEMES.items():
            self.win.set_theme(key)
            self.assertIs(self.appmod.T, t)
            self.assertIn(t.paper, self.qapp.styleSheet())
            self.assertEqual(self.win.settings.value("theme"), key)
            self.assertTrue(all(m.actions_by_key[key].isChecked() for m in self.win.theme_menus))
        self.win.set_theme("system")  # offscreen reports no dark preference
        self.assertEqual(self.appmod.T.key, "mist")

    def test_theme_switch_recolours_open_report(self):
        secretstore.save("m4ster")
        self.win.show()
        self.win.unlock.db.setText("v.kdbx")
        self.win.unlock.pw.setText("m4ster")
        self.win.unlock.go.click()
        self.pump(lambda: self.win.dash.report is not None)
        self.win.set_theme("slate")
        self.assertEqual(self.win.dash.report.issues[0].color, self.appmod.THEMES["slate"].breached)
        self.assertEqual(self.win.dash.table.rowCount(), 1)


SECOND_LAUNCH = """
import sys
sys.path.insert(0, sys.argv[1])
import app
app.INSTANCE_NAME = sys.argv[2]
from PySide6.QtCore import QCoreApplication
QCoreApplication([])
print(app.signal_running_instance(show=sys.argv[3] == "show"))
"""


@unittest.skipIf(QApplication is None, "PySide6 not installed")
class SingleInstance(unittest.TestCase):
    """A real second process, as when the user double-clicks the shortcut again."""

    def launch(self, qapp, name, mode):
        p = subprocess.Popen([sys.executable, "-c", SECOND_LAUNCH, str(HERE.parent), name, mode],
                             stdout=subprocess.PIPE, text=True)
        end = time.time() + 30
        while p.poll() is None and time.time() < end:
            qapp.processEvents()  # the first instance keeps running its event loop meanwhile
            time.sleep(0.01)
        out = p.communicate(timeout=5)[0].strip()
        for _ in range(20):
            qapp.processEvents()
            time.sleep(0.01)
        return out

    def test_second_launch_shows_the_first(self):
        import app as appmod
        qapp = QApplication.instance() or QApplication([])
        name = f"vaultkit-test-{os.getpid()}"
        with mock.patch.object(appmod, "INSTANCE_NAME", name):
            server = appmod.InstanceServer()
            shown = []
            server.show_requested.connect(lambda: shown.append(1))
            self.assertEqual(self.launch(qapp, name, "show"), "True")
            self.assertEqual(shown, [1])
            self.assertEqual(self.launch(qapp, name, "tray"), "True")  # tray start: stay hidden
            self.assertEqual(shown, [1])
            server.close()
            self.assertEqual(self.launch(qapp, name, "show"), "False")


class FakeRegistry:
    def __init__(self):
        self.value = None

    def get(self):
        return self.value

    def set(self, command):
        self.value = command

    def delete(self):
        self.value = None


class Autostart(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.reg = FakeRegistry()
        self.patches = [mock.patch.object(autostart, "supported", lambda: True),
                        mock.patch.object(autostart, "_registry", self.reg),
                        mock.patch.dict(os.environ, {"APPDATA": self.tmp.name})]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    def test_enable_disable_and_legacy_cleanup(self):
        startup = Path(self.tmp.name, "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
        startup.mkdir(parents=True)
        (startup / autostart.LEGACY_SHORTCUT).write_text("old")
        launcher = Path(self.tmp.name, "app", "launcher.py")
        autostart.enable(launcher)
        self.assertTrue(autostart.is_enabled())
        self.assertTrue(self.reg.value.endswith(f'"{launcher.resolve()}" --tray'))
        self.assertFalse((startup / autostart.LEGACY_SHORTCUT).exists())
        autostart.disable()
        self.assertFalse(autostart.is_enabled())

    def test_refresh_follows_a_moved_install(self):
        autostart.enable(Path(self.tmp.name, "old", "launcher.py"))
        new = Path(self.tmp.name, "new", "launcher.py")
        autostart.refresh(new)
        self.assertIn(str(new.resolve()), self.reg.value)


if __name__ == "__main__":
    unittest.main()
