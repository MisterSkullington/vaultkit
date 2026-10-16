"""kpsetup: finding, downloading, verifying, installing and configuring KeePassXC. Offline:
the network, Windows' signature check, msiexec and the registry are all faked here. The real
thing runs on GitHub's Windows machines (tests/test_windows.py, RealKeePassXC)."""
import hashlib, io, json, os, struct, sys, tempfile, unittest, uuid
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import kpsetup  # noqa: E402

FAKE = [sys.executable, str(HERE / "fake_kpcli.py")]


class FakeRegistry:
    def __init__(self):
        self.values = {}
        self.location = None

    def get(self, key, name):
        return self.values.get((key.lower(), name))

    def set(self, key, name, value):
        self.values[(key.lower(), name)] = value

    def delete(self, key, name):
        self.values.pop((key.lower(), name), None)

    def install_location(self):
        return self.location


class TempEnv(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.t = Path(self.tmp.name)
        self.reg = FakeRegistry()
        self.patches = [
            mock.patch.dict(os.environ, {"APPDATA": str(self.t / "roaming"),
                                         "LOCALAPPDATA": str(self.t / "local")}),
            mock.patch.object(kpsetup, "_registry", self.reg),
            mock.patch.object(kpsetup, "keepassxc_running", lambda: False),
        ]
        os.environ.pop("KPXC_CONFIG", None)
        os.environ.pop("KPXC_CONFIG_LOCAL", None)
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    def fake_install(self, root: Path) -> Path:
        """A KeePassXC folder with the files kpsetup looks for."""
        root.mkdir(parents=True, exist_ok=True)
        exe = ".exe" if os.name == "nt" else ""
        for name in (f"keepassxc-cli{exe}", f"keepassxc-proxy{exe}",
                     "KeePassXC.exe" if os.name == "nt" else "keepassxc"):
            (root / name).write_text("x")
        return root / f"keepassxc-cli{exe}"


# ---------------------------------------------------------------------------- settings file
class Ini(unittest.TestCase):
    QT = ("[General]\r\nConfigVersion=2\r\nBackupBeforeSave=false\r\n\r\n"
          "[Security]\r\nlockdatabaseidleseconds=900\r\n; a comment=1\r\n\r\n"
          "[Browser]\r\nCustomProxyLocation=C:/x y/z\r\n")

    def test_edits_only_what_it_must_and_keeps_line_endings(self):
        ini = kpsetup.IniFile(self.QT)
        self.assertEqual(ini.get("Security", "LockDatabaseIdleSeconds"), "900")  # any case
        self.assertIsNone(ini.get("Security", "a comment"))
        ini.set("Security", "LockDatabaseIdleSeconds", "300")
        ini.set("Security", "ClearClipboard", "true")             # new key, existing section
        ini.set("GUI", "ShowTrayIcon", "true")                    # new section
        out = ini.text()
        self.assertIn("lockdatabaseidleseconds=300\r\n", out)     # original spelling kept
        self.assertIn("lockdatabaseidleseconds=300\r\n; a comment=1\r\nClearClipboard=true\r\n\r\n"
                      "[Browser]", out)
        self.assertTrue(out.endswith("[GUI]\r\nShowTrayIcon=true\r\n"))
        self.assertIn("CustomProxyLocation=C:/x y/z\r\n", out)    # untouched
        self.assertNotIn("\n\n\n", out.replace("\r", ""))

    def test_new_file(self):
        ini = kpsetup.IniFile("", nl="\n")
        ini.set("General", "BackupBeforeSave", "true")
        ini.set("Security", "LockDatabaseIdleSeconds", "300")
        self.assertEqual(ini.text(), "[General]\nBackupBeforeSave=true\n\n[Security]\n"
                                     "LockDatabaseIdleSeconds=300\n")


class Settings(TempEnv):
    def roaming(self):
        return kpsetup.settings_paths()[0]

    def test_fresh_pc_gets_every_recommendation_and_keeps_stricter_choices(self):
        r, local = kpsetup.settings_paths()
        self.assertEqual(r, self.t / "roaming" / "KeePassXC" / "keepassxc.ini")
        self.assertEqual(local, self.t / "local" / "KeePassXC" / "keepassxc.ini")
        r.parent.mkdir(parents=True)
        r.write_text("[General]\nConfigVersion=2\n\n[Security]\nLockDatabaseIdleSeconds=120\n"
                     "ClearClipboardTimeout=30\n")
        todo = {s.key for s in kpsetup.settings_to_change()}
        self.assertEqual(todo, {"BackupBeforeSave", "ClearClipboardTimeout", "ShowTrayIcon",
                                "MinimizeToTray", "MinimizeOnStartup", "Enabled",
                                "AlwaysAllowAccess"})  # 120 s is stricter than 300: kept
        changed = kpsetup.apply_settings()
        self.assertEqual({s.key for s in changed}, todo)
        text = r.read_text()
        self.assertIn("ConfigVersion=2", text)
        self.assertIn("LockDatabaseIdleSeconds=120", text)
        self.assertIn("ClearClipboardTimeout=10", text)
        self.assertIn("[Browser]\nEnabled=true\nAlwaysAllowAccess=true", text)
        self.assertFalse(local.exists())  # QuickUnlock defaults to on: nothing to write
        backups = list(r.parent.glob("keepassxc.ini.before-vaultkit-*"))
        self.assertEqual(len(backups), 1)
        self.assertIn("ClearClipboardTimeout=30", backups[0].read_text())
        self.assertEqual(kpsetup.settings_to_change(), [])
        self.assertEqual(kpsetup.apply_settings(), [])  # second run: nothing, no new backup
        self.assertEqual(len(list(r.parent.glob("keepassxc.ini.before-vaultkit-*"))), 1)

    def test_local_file_and_no_file_at_all(self):
        local = kpsetup.settings_paths()[1]
        local.parent.mkdir(parents=True)
        local.write_text("[Security]\nQuickUnlock=false\n")
        kpsetup.apply_settings()
        self.assertIn("QuickUnlock=true", local.read_text())
        self.assertIn("BackupBeforeSave=true", self.roaming().read_text())

    def test_refuses_while_keepassxc_is_open(self):
        with mock.patch.object(kpsetup, "keepassxc_running", lambda: True):
            with self.assertRaises(kpsetup.SetupError) as e:
                kpsetup.apply_settings()
        self.assertIn("Close KeePassXC first", str(e.exception))
        self.assertFalse(self.roaming().exists())

    def test_every_setting_has_a_correct_default(self):
        # defaults as in KeePassXC 2.7.x src/core/Config.cpp; "want" differs only where we say
        differs = {s.key for s in kpsetup.SETTINGS if s.want != s.default}
        self.assertEqual(differs, {"BackupBeforeSave", "LockDatabaseIdleSeconds", "ShowTrayIcon",
                                   "MinimizeToTray", "MinimizeOnStartup", "Enabled",
                                   "AlwaysAllowAccess"})


# ---------------------------------------------------------------------------- download + install
def release_json(tag="2.7.12", url=kpsetup.DOWNLOAD_PREFIX, digest=True):
    name = f"KeePassXC-{tag}-Win64.msi"
    assets = [{"name": name, "browser_download_url": f"{url}{tag}/{name}"},
              {"name": f"KeePassXC-{tag}-Win64.zip", "browser_download_url": f"{url}{tag}/x.zip"}]
    if digest:
        assets.append({"name": name + ".DIGEST", "browser_download_url": f"{url}{tag}/{name}.DIGEST"})
    return json.dumps({"tag_name": tag, "assets": assets}).encode()


class Release(unittest.TestCase):
    def test_finds_the_windows_installer_and_its_checksum(self):
        r = kpsetup.latest_release(release_json())
        self.assertEqual((r.version, r.msi_name), ("2.7.12", "KeePassXC-2.7.12-Win64.msi"))
        self.assertTrue(r.digest_url.endswith(".msi.DIGEST"))

    def test_refuses_odd_releases(self):
        for raw in (release_json(digest=False), release_json(tag="nightly"),
                    release_json(url="https://evil.example/"), b"<html>"):
            with self.assertRaises(kpsetup.SetupError):
                kpsetup.latest_release(raw)

    def test_digest_file(self):
        h = "FEEE096C1D5D0D7BB7B36B18174818F7BAC889BE7668C550FF0E5EF9206EA9A5"
        name = "KeePassXC-2.7.12-Win64.msi"
        self.assertEqual(kpsetup.parse_digest(f"{h}  {name}\n", name), h.lower())
        self.assertEqual(kpsetup.parse_digest(f"{h} *{name}\n", name), h.lower())
        with self.assertRaises(kpsetup.SetupError):
            kpsetup.parse_digest(f"{h}  other.msi\n", name)


class Download(TempEnv):
    def test_streams_and_hashes_with_a_size_limit(self):
        data = os.urandom(3 << 20)
        dest = self.t / "f.msi"
        with mock.patch.object(kpsetup, "_open", lambda url, timeout=0: io.BytesIO(data)):
            self.assertEqual(kpsetup.download("u", dest), hashlib.sha256(data).hexdigest())
            self.assertEqual(dest.read_bytes(), data)
            with self.assertRaises(kpsetup.SetupError):
                kpsetup.download("u", self.t / "big.msi", limit=1 << 20)
        self.assertEqual(sorted(p.name for p in self.t.iterdir() if p.is_file()), ["f.msi"])


class Signature(unittest.TestCase):
    def test_only_a_valid_keepassxc_signature_passes(self):
        cases = {("Valid", "DroidMonkey Apps, LLC"): True, ("Valid", "Evil Corp"): False,
                 ("HashMismatch", "DroidMonkey Apps, LLC"): False, ("NotSigned", ""): False,
                 ("", ""): False}
        for answer, ok in cases.items():
            with mock.patch.object(kpsetup, "authenticode", lambda p, a=answer: a):
                if ok:
                    kpsetup.check_signature(Path("x"))
                else:
                    with self.assertRaises(kpsetup.SetupError) as e:
                        kpsetup.check_signature(Path("x"))
                    self.assertIn("STOPPED", str(e.exception))


class Install(TempEnv):
    BODY = b"pretend msi"

    def run_install(self, digest=None, signed=True, msi_code=0):
        calls = {"msi": []}
        cli = self.fake_install(self.t / "pf" / "KeePassXC")
        digest = digest or hashlib.sha256(self.BODY).hexdigest()

        def download(url, dest, limit=0):
            dest.write_bytes(self.BODY)
            return hashlib.sha256(self.BODY).hexdigest()

        def check(path):
            if not signed:
                raise kpsetup.SetupError("STOPPED: not signed")

        def run_msi(msi, log, quiet=False):
            calls["msi"].append((msi, msi.exists(), quiet))
            return msi_code

        progress = []
        with mock.patch.object(kpsetup, "supported", lambda: True), \
             mock.patch.object(kpsetup, "latest_release", lambda: kpsetup.Release(
                 "2.7.12", "KeePassXC-2.7.12-Win64.msi", "m", "d")), \
             mock.patch.object(kpsetup, "http_get",
                               lambda url, limit=0: f"{digest}  KeePassXC-2.7.12-Win64.msi\n".encode()), \
             mock.patch.object(kpsetup, "download", download), \
             mock.patch.object(kpsetup, "check_signature", check), \
             mock.patch.object(kpsetup, "run_msi", run_msi), \
             mock.patch.object(kpsetup, "find_cli", lambda: cli):
            try:
                result = kpsetup.install_keepassxc(progress=progress.append, quiet_ui=True)
            except kpsetup.SetupError as e:
                result = e
        msi = self.t / "local" / "vaultkit" / "downloads" / "KeePassXC-2.7.12-Win64.msi"
        return result, calls["msi"], msi, progress

    def test_verified_installer_runs_and_is_cleaned_up(self):
        result, runs, msi, progress = self.run_install()
        self.assertTrue(str(result).endswith("keepassxc-cli" + (".exe" if os.name == "nt" else "")))
        self.assertEqual(len(runs), 1)
        self.assertTrue(runs[0][1])           # it existed while msiexec ran
        self.assertTrue(runs[0][2])           # quiet as asked
        self.assertFalse(msi.exists())        # deleted afterwards
        self.assertTrue(any("DroidMonkey" in p for p in progress))  # what the UAC prompt shows

    def test_wrong_checksum_never_runs(self):
        result, runs, msi, _ = self.run_install(digest="0" * 64)
        self.assertIsInstance(result, kpsetup.SetupError)
        self.assertIn("checksum", str(result))
        self.assertEqual(runs, [])
        self.assertFalse(msi.exists())

    def test_bad_signature_never_runs(self):
        result, runs, msi, _ = self.run_install(signed=False)
        self.assertIsInstance(result, kpsetup.SetupError)
        self.assertEqual(runs, [])
        self.assertFalse(msi.exists())

    def test_saying_no_to_windows_is_explained(self):
        result, runs, _, _ = self.run_install(msi_code=1223)
        self.assertIn("You chose No", str(result))
        result, _, _, _ = self.run_install(msi_code=3010)  # installed, restart pending: fine
        self.assertNotIsInstance(result, kpsetup.SetupError)

    def test_not_on_windows(self):
        with mock.patch.object(kpsetup, "supported", lambda: False):
            with self.assertRaises(kpsetup.SetupError):
                kpsetup.install_keepassxc()


class Find(TempEnv):
    def test_found_without_path(self):
        cli = self.fake_install(self.t / "Program Files" / "KeePassXC")
        nowhere = {v: str(self.t / "none") for v in ("ProgramFiles", "ProgramW6432",
                                                     "ProgramFiles(x86)")}
        with mock.patch.object(kpsetup.shutil, "which", return_value=None), \
             mock.patch.dict(os.environ, dict(nowhere, ProgramFiles=str(self.t / "Program Files"))):
            self.assertEqual(kpsetup.find_cli(), cli)
        other = self.fake_install(self.t / "Elsewhere")
        self.reg.location = str(self.t / "Elsewhere")
        with mock.patch.object(kpsetup.shutil, "which", return_value=None), \
             mock.patch.dict(os.environ, nowhere):
            self.assertEqual(kpsetup.find_cli(), other)
            self.reg.location = None
            self.assertIsNone(kpsetup.find_cli())

    def test_version_from_the_cli(self):
        self.assertEqual(kpsetup.cli_version(FAKE), (2, 7, 12))
        self.assertIsNone(kpsetup.cli_version([str(self.t / "missing.exe")]))


# ---------------------------------------------------------------------------- browsers
class Connector(TempEnv):
    def test_register_like_keepassxc_does(self):
        cli = self.fake_install(self.t / "pf" / "KeePassXC")
        self.assertEqual(kpsetup.connector_problem(), "Browsers aren't connected to KeePassXC yet.")
        path = kpsetup.register_connector(cli)
        self.assertEqual(path, self.t / "local" / "KeePassXC" /
                         "org.keepassxc.keepassxc_browser_chrome.json")
        self.assertEqual(self.reg.get(kpsetup.CHROME_KEY, ""), str(path))
        data = json.loads(path.read_text())
        self.assertEqual(data["name"], "org.keepassxc.keepassxc_browser")
        self.assertEqual(data["type"], "stdio")
        self.assertTrue(data["path"].endswith("keepassxc-proxy" + (".exe" if os.name == "nt" else "")))
        self.assertIn("chrome-extension://oboonakemofpalcgghocfoadofidjkkk/", data["allowed_origins"])
        self.assertIsNone(kpsetup.connector_problem())
        Path(data["path"]).unlink()  # KeePassXC uninstalled or moved
        self.assertIn("isn't there any more", kpsetup.connector_problem())

    def test_missing_proxy_is_explained(self):
        cli = self.t / "nothing" / "keepassxc-cli.exe"
        with self.assertRaises(kpsetup.SetupError):
            kpsetup.register_connector(cli)

    def test_keepassxc_autostart(self):
        cli = self.fake_install(self.t / "pf" / "KeePassXC")
        self.assertFalse(kpsetup.keepassxc_autostarts())
        kpsetup.enable_keepassxc_autostart(cli)
        self.assertTrue(kpsetup.keepassxc_autostarts())
        self.assertEqual(self.reg.get(kpsetup.RUN_KEY, "KeePassXC"), f'"{kpsetup.gui_exe(cli)}"')


# ---------------------------------------------------------------------------- vault header
ARGON2ID = uuid.UUID("9e298b19-56db-4773-b23d-fc3ec6f0a1e6").bytes
ARGON2D = uuid.UUID("ef636ddf-8c29-444b-91f7-a9a403e30a0c").bytes
AES256 = uuid.UUID("31c1f2e6-bf71-4350-be58-05216afc5aff").bytes


def variant_map(items):
    out = struct.pack("<H", 0x0100)
    for kind, name, value in items:
        n = name.encode()
        out += bytes([kind]) + struct.pack("<I", len(n)) + n + struct.pack("<I", len(value)) + value
    return out + b"\x00"


def kdbx4(kdf=ARGON2ID, memory=256 << 20, minor=1):
    params = variant_map([(0x42, "$UUID", kdf), (0x05, "I", struct.pack("<Q", 10)),
                          (0x05, "M", struct.pack("<Q", memory)), (0x04, "P", struct.pack("<I", 4)),
                          (0x04, "V", struct.pack("<I", 0x13)), (0x42, "S", os.urandom(32))])
    head = struct.pack("<III", *kpsetup.SIGNATURE, (4 << 16) | minor)
    for fid, data in ((2, AES256), (3, b"\x01\x00\x00\x00"), (4, os.urandom(32)), (11, params),
                      (0, b"\r\n\r\n")):
        head += bytes([fid]) + struct.pack("<I", len(data)) + data
    return head + os.urandom(100)


class VaultHeader(TempEnv):
    def write(self, data: bytes) -> Path:
        p = self.t / "v.kdbx"
        p.write_bytes(data)
        return p

    def test_recommended_vault(self):
        info = kpsetup.vault_info(self.write(kdbx4()))
        self.assertEqual((info.format, info.kdf, info.memory_mib, info.parallelism, info.cipher),
                         ("KDBX 4.1", "Argon2id", 256, 4, "AES-256"))
        self.assertTrue(info.ok)
        self.assertEqual(info.summary(), "KDBX 4.1, Argon2id, 256 MiB, 4 threads")

    def test_keepassxc_default_and_cli_made_vaults_need_the_guide(self):
        info = kpsetup.vault_info(self.write(kdbx4(ARGON2D, 64 << 20, minor=0)))
        self.assertEqual(len(info.problems()), 2)  # Argon2d, and only 64 MiB
        p = self.t / "cli.kdbx"
        kpsetup.create_vault(FAKE, p, "maple river lantern orbit")
        info = kpsetup.vault_info(p)
        self.assertEqual((info.format, info.kdf, info.rounds), ("KDBX 3.1", "AES-KDF", 60000))
        self.assertIn("older KDBX 3.1 format", " ".join(info.problems()))

    def test_not_a_vault_or_damaged(self):
        for data in (b"", b"PK\x03\x04 zip file", kdbx4()[:40]):
            with self.assertRaises(kpsetup.SetupError):
                kpsetup.vault_info(self.write(data))
        with self.assertRaises(kpsetup.SetupError):
            kpsetup.vault_info(self.t / "missing.kdbx")

    def test_create_refuses_to_overwrite(self):
        p = self.write(b"keep me")
        with self.assertRaises(kpsetup.SetupError):
            kpsetup.create_vault(FAKE, p, "maple river lantern orbit")
        self.assertEqual(p.read_bytes(), b"keep me")

    def test_guide_names_the_real_keepassxc_menus(self):
        steps = " ".join(kpsetup.strengthen_steps(cpus=16))
        for words in ("Database Security", "Encryption Settings", "Advanced",
                      "Argon2id (KDBX 4)", "256 MiB", "8 thread(s)", "Benchmark"):
            self.assertIn(words, steps)


# ---------------------------------------------------------------------------- overview + CLI
class Overview(TempEnv):
    def test_nothing_installed(self):
        with mock.patch.object(kpsetup, "find_cli", lambda: None), \
             mock.patch.object(kpsetup, "supported", lambda: True):
            checks = {c.key: c for c in kpsetup.run_checks()}
        self.assertEqual((checks["keepassxc"].ok, checks["keepassxc"].action),
                         (False, "Install KeePassXC"))
        for key in ("settings", "connector", "autostart"):
            self.assertIsNone(checks[key].ok)
            self.assertEqual(checks[key].action, "")
        self.assertEqual(checks["vault"].action, "Create a vault")
        self.assertEqual(checks["extension"].action, "Open the extension page")

    def test_installed_and_partly_set_up(self):
        cli = self.fake_install(self.t / "pf" / "KeePassXC")
        vault = self.t / "main.kdbx"
        vault.write_bytes(kdbx4())
        with mock.patch.object(kpsetup, "cli_version", lambda c: (2, 7, 12)), \
             mock.patch.object(kpsetup, "supported", lambda: True):
            checks = {c.key: c for c in kpsetup.run_checks(str(vault), cli=cli)}
            self.assertTrue(checks["keepassxc"].ok)
            self.assertFalse(checks["settings"].ok)
            self.assertIn("7 to change", checks["settings"].detail)
            self.assertFalse(checks["connector"].ok)
            self.assertTrue(checks["vault"].ok)
            kpsetup.apply_settings()
            kpsetup.register_connector(cli)
            kpsetup.enable_keepassxc_autostart(cli)
            checks = {c.key: c for c in kpsetup.run_checks(str(vault), cli=cli)}
        self.assertTrue(all(checks[k].ok for k in ("keepassxc", "settings", "connector",
                                                   "autostart", "vault")))

    def test_too_old(self):
        cli = self.fake_install(self.t / "pf" / "KeePassXC")
        with mock.patch.object(kpsetup, "cli_version", lambda c: (2, 6, 6)):
            check = kpsetup.run_checks(cli=cli)[0]
        self.assertEqual((check.ok, check.action), (False, "Update KeePassXC"))

    def test_command_line(self):
        cli = self.fake_install(self.t / "pf" / "KeePassXC")
        out = io.StringIO()
        with mock.patch.object(kpsetup, "find_cli", lambda: cli), \
             mock.patch.object(kpsetup, "cli_version", lambda c: (2, 7, 12)), \
             mock.patch.object(kpsetup, "supported", lambda: True), redirect_stdout(out):
            self.assertEqual(kpsetup.main(["check"]), 0)
            self.assertEqual(kpsetup.main(["install"]), 0)  # already installed: just set up
        text = out.getvalue()
        self.assertIn("!! Recommended settings", text)
        self.assertIn("KeePassXC 2.7.12 is already installed.", text)
        self.assertIn("Browser connection registered", text)
        self.assertIn(kpsetup.EXTENSION_URL, text)
        self.assertEqual(kpsetup.settings_to_change(), [])


if __name__ == "__main__":
    unittest.main()
