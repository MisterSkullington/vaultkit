import hashlib, io, json, os, string, sys, tempfile, unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
import fake_hibp  # noqa: E402
import vaultkit as vk  # noqa: E402

FAKE = str(HERE / "fake_kpcli.py")
# cross-platform "print this password" command (no shell builtins like echo on Windows)
PWCMD = f'"{sys.executable}" -c "print(\'{{}}\')"'


class Generator(unittest.TestCase):
    def test_classes_and_length(self):
        for _ in range(200):
            pw = vk.generate_password(16, "!@#")
            self.assertEqual(len(pw), 16)
            for cls in (string.ascii_lowercase, string.ascii_uppercase, string.digits, "!@#"):
                self.assertTrue(any(c in cls for c in pw))
            self.assertTrue(set(pw) <= set(string.ascii_letters + string.digits + "!@#"))

    def test_no_symbols(self):
        self.assertTrue(vk.generate_password(64, "").isalnum())

    def test_too_short(self):
        with self.assertRaises(ValueError):
            vk.generate_password(3, "!")


class Profiles(unittest.TestCase):
    def test_roundtrip_preserves_user_notes(self):
        p = vk.Profile(length=64, symbols="", change_url="https://x/pw", twofa="totp")
        notes = vk.upsert_profile("security Q: blue", p)
        self.assertIn("security Q: blue", notes)
        self.assertEqual(vk.parse_profile(notes), p)
        p2 = vk.Profile(length=20)
        notes2 = vk.upsert_profile(notes, p2)
        self.assertEqual(notes2.count(vk.PROFILE_START), 1)
        self.assertEqual(vk.parse_profile(notes2), p2)

    def test_missing(self):
        self.assertIsNone(vk.parse_profile("just notes"))


class Pwned(unittest.TestCase):
    def test_p_at_ssw0rd_k_anonymity(self):
        full = hashlib.sha1(b"P@ssw0rd").hexdigest().upper()
        self.assertEqual(vk.sha1_hex("P@ssw0rd"), full)
        seen = []

        def fake_fetch(prefix):
            seen.append(prefix)
            # real suffix + a decoy + a padding row (count 0)
            return f"{full[5:]}:120000\r\n{'0' * 35}:3\r\n{'F' * 35}:0\r\n"

        hits = vk.pwned_counts({"Web/a": "P@ssw0rd", "Web/b": "P@ssw0rd"}, fetch=fake_fetch)
        self.assertEqual(seen, [full[:5]])              # one request, 5 chars only
        self.assertEqual(hits, {"Web/a": 120000, "Web/b": 120000})

    def test_clean_and_padding_ignored(self):
        h = vk.sha1_hex("unique-pw")
        hits = vk.pwned_counts({"x": "unique-pw"}, fetch=lambda p: f"{h[5:]}:0\n")
        self.assertEqual(hits, {})

    def test_reuse(self):
        self.assertEqual(vk.reused({"a": "1", "b": "1", "c": "2", "d": ""}), [["a", "b"]])


class Keys(unittest.TestCase):
    def test_duplicates_disambiguated_and_reported(self):
        rows = [{"Path": "a.com", "Username": "x", "Password": "1"},
                {"Path": "a.com", "Username": "y", "Password": "2"},
                {"Path": "b.com", "Username": "z", "Password": "3"}]
        pw, dupes = vk.keyed_passwords(rows)
        self.assertEqual(dupes, ["a.com"])
        self.assertEqual(set(pw), {"a.com [user: x]", "a.com [user: y]", "b.com"})

    def test_change_url(self):
        p = vk.Profile()
        self.assertEqual(vk.change_url_for(p, "https://www.github.com/login"),
                         "https://www.github.com/.well-known/change-password")
        self.assertEqual(vk.change_url_for(p, "spotify.com"),
                         "https://spotify.com/.well-known/change-password")
        self.assertEqual(vk.change_url_for(vk.Profile(change_url="https://x/pw"), "https://y"),
                         "https://x/pw")
        self.assertEqual(vk.change_url_for(p, ""), "")


class Shred(unittest.TestCase):
    def test_shred(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d, "Chrome Passwords.csv")
            f.write_text("name,url,username,password\nx,y,z,secret\n")
            self.assertEqual(vk.main(["shred", "-y", str(f)]), 0)
            self.assertEqual(list(Path(d).iterdir()), [])


class EndToEnd(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name, "state.json")
        self.state.write_text(json.dumps({"master": "m4ster", "groups": [], "entries": {
            "Web/github": {"UserName": "me", "URL": "https://github.com", "Password": "P@ssw0rd", "Notes": ""},
            "Web/bank": {"UserName": "me", "URL": "https://bank", "Password": "P@ssw0rd", "Notes": ""},
            "Recycle Bin/old": {"UserName": "", "URL": "", "Password": "ignored", "Notes": ""},
        }}))
        self.env = mock.patch.dict(os.environ, {"FAKE_KP_STATE": str(self.state),
                                                "XDG_STATE_HOME": self.tmp.name,
                                                "LOCALAPPDATA": self.tmp.name})
        self.env.start()
        self.hibp = fake_hibp.patch([fake_hibp.breach("github.com", "2020-01-01")])
        self.hibp.start()
        self.base = ["--db", "v.kdbx", "--password-cmd", PWCMD.format("m4ster")]
        self.cli = mock.patch.object(vk.shutil, "which", return_value=None)
        self.cli.start()

    def tearDown(self):
        self.env.stop(); self.cli.stop(); self.hibp.stop(); self.tmp.cleanup()

    def run_vk(self, *args):
        out = io.StringIO()
        with mock.patch.object(vk.Vault, "__init__", self._init), redirect_stdout(out):
            rc = vk.main(self.base + list(args))
        return rc, out.getvalue()

    _real_init = vk.Vault.__init__

    @staticmethod
    def _init(self, *args, **kwargs):  # real constructor, then point at the fake CLI
        EndToEnd._real_init(self, *args, **kwargs)
        self.cli, self.cli_prefix_args = sys.executable, [FAKE]

    def entries(self):
        return json.loads(self.state.read_text())["entries"]

    def test_wrong_master_fails_cleanly(self):
        self.base = ["--db", "v.kdbx", "--password-cmd", PWCMD.format("nope")]
        with mock.patch("sys.stderr", io.StringIO()):
            rc, _ = self.run_vk("profile", "Web/github")
        self.assertEqual(rc, 3)

    def test_check_flags_breach_and_reuse_skips_recycle_bin(self):
        h = vk.sha1_hex("P@ssw0rd")
        with mock.patch.object(vk, "fetch_range", lambda p: f"{h[5:]}:99\n"):
            rc, out = self.run_vk("check")
        self.assertEqual(rc, 2)
        self.assertIn("Web/github", out)
        self.assertNotIn("Recycle Bin", out)
        self.assertIn("Github had a breach in Jan 2020", out)
        self.assertIn("Only 8 characters long", out)
        self.assertIn("Health score: 0/100", out)   # both passwords breached
        report = json.loads(Path(self.tmp.name, "vaultkit", "last-check.json").read_text())
        self.assertNotIn("P@ssw0rd", json.dumps(report))  # no secrets in report
        history = json.loads(Path(self.tmp.name, "vaultkit", "history.json").read_text())
        self.assertEqual([(h["score"], h["breached"]) for h in history], [(0, 2)])

    def test_profile_then_rotate_commit(self):
        rc, out = self.run_vk("profile", "Web/github", "--length", "40", "--symbols", "none",
                              "--change-url", "https://github.com/settings/security", "--2fa", "totp")
        self.assertEqual(rc, 0)

        rc, out = self.run_vk("rotate", "start", "Web/github")
        self.assertEqual(rc, 0, out)
        e = self.entries()
        pend = e[vk.pending_path("Web/github")]["Password"]
        self.assertEqual(len(pend), 40)
        self.assertTrue(pend.isalnum())
        self.assertEqual(e["Web/github"]["Password"], "P@ssw0rd")  # original untouched
        self.assertIn("github.com/settings/security", out)

        rc, out = self.run_vk("rotate", "start", "Web/github")
        self.assertEqual(rc, 1)  # refuses a second pending rotation

        rc, _ = self.run_vk("rotate", "commit", "Web/github")
        self.assertEqual(rc, 0)
        e = self.entries()
        self.assertEqual(e["Web/github"]["Password"], pend)
        self.assertEqual(e["Web/github"]["History"], ["P@ssw0rd"])
        self.assertNotIn(vk.pending_path("Web/github"), e)

    def test_fix_walks_breached_commit_and_reject(self):
        h = vk.sha1_hex("P@ssw0rd")
        opened = []
        answers = iter(["c", "y", "n"])  # bank: copy again then accept; github: rejected
        with mock.patch.object(vk, "fetch_range", lambda p: f"{h[5:]}:99\n"), \
             mock.patch.object(vk, "open_url", opened.append), \
             mock.patch("builtins.input", lambda _: next(answers)):
            rc, out = self.run_vk("fix")
        self.assertEqual(rc, 0, out)
        e = self.entries()
        self.assertNotEqual(e["Web/bank"]["Password"], "P@ssw0rd")
        self.assertEqual(len(e["Web/bank"]["Password"]), 32)
        self.assertEqual(e["Web/github"]["Password"], "P@ssw0rd")
        self.assertFalse([k for k in e if k.startswith(vk.PENDING_GROUP)])
        self.assertEqual(opened, ["https://bank/.well-known/change-password",
                                  "https://github.com/.well-known/change-password"])
        self.assertIn("1 changed, 1 rejected", out)

    def test_fix_skip_keeps_pending_and_reuses_it(self):
        h = vk.sha1_hex("P@ssw0rd")
        with mock.patch.object(vk, "fetch_range", lambda p: f"{h[5:]}:99\n"), \
             mock.patch.object(vk, "open_url", lambda u: None), \
             mock.patch("builtins.input", lambda _: "s"):
            self.run_vk("fix", "Web/github")
        first = self.entries()[vk.pending_path("Web/github")]["Password"]
        with mock.patch.object(vk, "fetch_range", lambda p: f"{h[5:]}:99\n"), \
             mock.patch.object(vk, "open_url", lambda u: None), \
             mock.patch("builtins.input", lambda _: "y"):
            rc, out = self.run_vk("fix", "Web/github")
        self.assertIn("already saved", out)
        self.assertEqual(self.entries()["Web/github"]["Password"], first)

    def test_site_breach_clears_only_after_a_real_password_change(self):
        h = vk.sha1_hex("P@ssw0rd")
        with mock.patch.object(vk, "fetch_range", lambda p: f"{h[5:]}:99\n"):
            self.run_vk("profile", "Web/github", "--length", "40")   # an edit, not a change
            _, out = self.run_vk("check")
            self.assertIn("Github had a breach in Jan 2020", out)
            self.run_vk("rotate", "start", "Web/github")
            self.run_vk("rotate", "commit", "Web/github")
            notes = self.entries()["Web/github"]["Notes"]
            self.assertIn(f"changed: {vk.date.today().isoformat()}", notes)
            self.assertIn("length: 40", notes)  # rules kept
            _, out = self.run_vk("check")
        self.assertNotIn("Github had a breach", out)

    def test_rotate_abort_keeps_original(self):
        self.run_vk("rotate", "start", "Web/bank")
        rc, _ = self.run_vk("rotate", "abort", "Web/bank")
        self.assertEqual(rc, 0)
        self.assertEqual(self.entries()["Web/bank"]["Password"], "P@ssw0rd")


if __name__ == "__main__":
    unittest.main()
