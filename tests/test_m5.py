"""M5: icon file, shortcuts, uninstall."""
import io, os, struct, sys, tempfile, unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import autostart  # noqa: E402
import secretstore  # noqa: E402
import shortcuts  # noqa: E402
import uninstall  # noqa: E402
import updater  # noqa: E402

try:
    from PySide6.QtGui import QImage
    from PySide6.QtWidgets import QApplication
except ImportError:  # pragma: no cover
    QApplication = None


class Env(unittest.TestCase):
    """Temp APPDATA/LOCALAPPDATA, pretend Windows, fake shortcut writer + registry."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = Path(self.tmp.name)
        self.app_dir = t / "home" / "vaultkit" / "app"
        self.app_dir.mkdir(parents=True)
        self.written = []

        def fake_create(lnk, target, args, workdir, icon):
            self.written.append(Path(lnk))
            Path(lnk).parent.mkdir(parents=True, exist_ok=True)
            Path(lnk).write_text(f"{target} {args}")

        class Reg:
            value = "something"
            def get(s): return s.value
            def set(s, c): s.value = c
            def delete(s): s.value = None
        self.reg = Reg()
        self.patches = [
            mock.patch.dict(os.environ, {"APPDATA": str(t / "roaming"), "LOCALAPPDATA": str(t / "local")}),
            mock.patch.object(shortcuts, "supported", lambda: True),
            mock.patch.object(shortcuts, "create", fake_create),
            mock.patch.object(autostart, "supported", lambda: True),
            mock.patch.object(autostart, "_registry", self.reg),
            mock.patch.object(secretstore, "protect", lambda b: b"FAKE" + b[::-1]),
            mock.patch.object(secretstore, "unprotect", lambda b: b[4:][::-1]),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()


@unittest.skipIf(QApplication is None, "PySide6 not installed")
class Icon(unittest.TestCase):
    def test_ico_is_a_real_multisize_icon(self):
        import app as appmod
        QApplication.instance() or QApplication([])
        with tempfile.TemporaryDirectory() as d:
            data = appmod.write_ico(Path(d) / "vaultkit.ico").read_bytes()
        reserved, kind, count = struct.unpack_from("<HHH", data)
        self.assertEqual((reserved, kind, count), (0, 1, 6))
        sizes = []
        for i in range(count):
            w, h, _, _, planes, bpp, length, offset = struct.unpack_from("<BBBBHHII", data, 6 + 16 * i)
            img = QImage.fromData(data[offset:offset + length], "PNG")
            self.assertFalse(img.isNull())
            self.assertEqual(img.width(), w or 256)
            sizes.append(img.width())
        self.assertEqual(sizes, [16, 24, 32, 48, 64, 256])


class Shortcuts(Env):
    def test_creates_once_then_only_when_something_changed(self):
        icon = Path(self.tmp.name) / "vaultkit.ico"
        made = shortcuts.ensure(self.app_dir, icon)
        self.assertEqual({p.name for p in made}, {"vaultkit.lnk", "Open vaultkit.lnk"})
        self.assertTrue((self.app_dir.parent / "Open vaultkit.lnk").exists())
        self.assertIn("launcher.py", (shortcuts.start_menu_dir() / "vaultkit.lnk").read_text())
        self.assertEqual(shortcuts.ensure(self.app_dir, icon), [])  # nothing changed: no work

        moved = Path(self.tmp.name) / "elsewhere" / "vaultkit" / "app"
        moved.mkdir(parents=True)
        self.assertEqual(len(shortcuts.ensure(moved, icon)), 2)   # follows a moved install

        removed = shortcuts.remove_all(moved)
        self.assertEqual(len(removed), 2)
        self.assertFalse((shortcuts.start_menu_dir() / "vaultkit.lnk").exists())

    def test_no_folder_shortcut_outside_the_one_folder_layout(self):
        plain = Path(self.tmp.name) / "somewhere"
        plain.mkdir()
        self.assertEqual([p.name for p in shortcuts.ensure(plain, Path("x.ico"))], ["vaultkit.lnk"])


class Uninstall(Env):
    def populate(self, publisher: bool):
        d = updater.data_dir()
        secretstore.save("m4ster")
        (d / "update.json").write_text("{}")
        (d / "backups" / "1.5.0").mkdir(parents=True)
        (d / "updates").mkdir()
        (d / "last-check.json").write_text("{}")
        (d / "stray.kdbx").write_text("someone's vault")
        if publisher:
            (d / "release-signing.key").write_bytes(b"k")
        shortcuts.ensure(self.app_dir, Path("x.ico"))
        return d

    def run_uninstall(self, answer="uninstall"):
        cleared = []
        out = io.StringIO()
        with redirect_stdout(out):
            rc = uninstall.uninstall(self.app_dir, confirm=lambda _: answer,
                                     clear_settings=lambda: cleared.append(1))
        return rc, out.getvalue(), cleared

    def test_publisher_pc_keeps_signing_key_and_never_a_vault(self):
        d = self.populate(publisher=True)
        rc, out, cleared = self.run_uninstall()
        self.assertEqual(rc, 0)
        self.assertEqual(sorted(p.name for p in d.iterdir()),
                         ["release-signing.key", "stray.kdbx", "update.json"])
        self.assertFalse(secretstore.is_saved())
        self.assertIsNone(self.reg.value)  # Start with Windows off
        self.assertFalse((shortcuts.start_menu_dir() / "vaultkit.lnk").exists())
        self.assertEqual(cleared, [1])
        self.assertIn("Your vault was not touched", out)

    def test_other_pc_removes_update_key_too(self):
        d = self.populate(publisher=False)
        self.run_uninstall()
        self.assertEqual([p.name for p in d.iterdir()], ["stray.kdbx"])

    def test_declining_changes_nothing(self):
        d = self.populate(publisher=False)
        before = sorted(p.name for p in d.iterdir())
        rc, out, cleared = self.run_uninstall(answer="no")
        self.assertEqual(rc, 1)
        self.assertEqual(sorted(p.name for p in d.iterdir()), before)
        self.assertTrue(secretstore.is_saved())
        self.assertEqual(cleared, [])


@unittest.skipIf(QApplication is None, "PySide6 not installed")
class LauncherUninstall(unittest.TestCase):
    def test_refuses_while_the_app_is_running(self):
        import app as appmod
        import launcher
        out = io.StringIO()
        with mock.patch.object(sys, "argv", ["launcher.py", "--uninstall"]), \
             mock.patch.object(appmod, "signal_running_instance", lambda show: True), \
             redirect_stdout(out):
            rc = launcher.main()
        self.assertEqual(rc, 1)
        self.assertIn("still running", out.getvalue())


if __name__ == "__main__":
    unittest.main()
