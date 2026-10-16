"""1.8 checks: site-breach timeline (breaches.py), weak/similar passwords (strength.py),
health score and history. No network: the breach list comes from tests/fake_hibp.py."""
import json, os, sys, tempfile, unittest
from datetime import date, datetime, timedelta
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
import breaches  # noqa: E402
import fake_hibp  # noqa: E402
import strength  # noqa: E402
import vaultkit as vk  # noqa: E402

B = fake_hibp.breach


class TempDirs(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {"LOCALAPPDATA": self.tmp.name,
                                                "XDG_STATE_HOME": self.tmp.name})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()


class BreachList(TempDirs):
    def test_parse_keeps_only_real_site_breaches(self):
        raw = json.dumps([
            B("adobe.com", "2013-10-04"),
            B("nopw.com", "2019-01-01", passwords=False),
            B("fake.com", "2019-01-01", IsFabricated=True),
            B("spam.com", "2019-01-01", IsSpamList=True),
            B("gone.com", "2019-01-01", IsRetired=True),
            B("unverified.com", "2019-01-01", IsVerified=False),
            B("baddate.com", "someday"),
            B("", "2019-01-01"),
        ]).encode()
        got = {b.domain: b.passwords_leaked for b in breaches.parse(raw)}
        self.assertEqual(got, {"adobe.com": True, "nopw.com": False})

    def test_downloads_once_a_day_and_never_caches_junk(self):
        calls = []
        with fake_hibp.patch([B("adobe.com", "2013-10-04")], calls):
            self.assertEqual(len(breaches.load()), 1)
            breaches.load()
            self.assertEqual(len(calls), 1)  # second call within a day: from the cache
            breaches.load(now=datetime.now().timestamp() + 25 * 3600)
            self.assertEqual(len(calls), 2)  # a day later: fresh copy
        cache = Path(self.tmp.name, "vaultkit", "hibp-breaches.json")
        before = cache.read_bytes()
        with self.assertRaises(ValueError):
            breaches.load(get=lambda url: b"<html>rate limited</html>",
                          now=datetime.now().timestamp() + 50 * 3600)
        self.assertEqual(cache.read_bytes(), before)

    def test_host_of(self):
        self.assertEqual(breaches.host_of("HTTPS://WWW.Example.COM./login"), "example.com")
        self.assertEqual(breaches.host_of("accounts.adobe.com/signin"), "accounts.adobe.com")
        self.assertEqual(breaches.host_of(""), "")


class SiteTimeline(unittest.TestCase):
    LIST = [breaches.Breach("Adobe", "adobe.com", date(2013, 10, 4), True),
            breaches.Breach("Adobe", "adobe.com", date(2023, 5, 1), True),     # latest wins
            breaches.Breach("Adobe", "adobe.com", date(2024, 1, 1), False),    # no passwords
            breaches.Breach("Other", "other.com", date(2020, 1, 1), True)]

    @staticmethod
    def row(path, url, set_on=None, modified="2026-10-01"):
        prof = vk.Profile(changed=set_on or "")
        return {"Path": path, "URL": url, "Notes": f"my notes\n\n{prof.render()}",
                "Created": "2020-01-01T10:00:00Z", "Last Modified": f"{modified}T10:00:00Z"}

    def test_matching_and_dates(self):
        rows = [
            self.row("sub", "https://accounts.adobe.com/x"),                  # no date: unknown
            self.row("before", "https://www.adobe.com", "2022-06-01"),
            self.row("after", "adobe.com", "2024-02-01"),
            self.row("unrelated", "https://notadobe.com"),
            self.row("no-url", ""),
        ]
        found = breaches.match(rows, self.LIST, vk.password_set_on)
        self.assertEqual(set(found), {"sub", "before"})
        self.assertIsNone(found["sub"].changed)
        self.assertFalse(found["sub"].after_change)
        self.assertIn("Change this one if you haven't since then", found["sub"].text())
        self.assertEqual(found["before"].breach.breach_date, date(2023, 5, 1))
        self.assertTrue(found["before"].after_change)
        self.assertIn("after you last changed this one (Jun 2022)", found["before"].text())

    def test_other_edits_never_hide_a_breach(self):
        # Notes/URL/rules edited long after the breach, password never changed by vaultkit
        rows = [self.row("edited", "https://adobe.com", modified="2026-10-01")]
        self.assertIn("edited", breaches.match(rows, self.LIST, vk.password_set_on))
        self.assertIn("edited", breaches.match(rows, self.LIST))  # default: nothing is known


class PasswordDate(unittest.TestCase):
    def test_profile_keeps_the_date_through_rule_edits(self):
        notes = vk.upsert_profile("mine", vk.Profile(changed="2025-02-03"))
        self.assertEqual(vk.parse_profile(notes).changed, "2025-02-03")
        notes = vk.upsert_profile(notes, vk.Profile(length=20))      # rules saved from the app
        self.assertEqual(vk.parse_profile(notes).length, 20)
        self.assertEqual(vk.parse_profile(notes).changed, "2025-02-03")
        self.assertTrue(notes.startswith("mine"))
        self.assertEqual(vk.password_set_on({"Notes": notes}), date(2025, 2, 3))
        self.assertIsNone(vk.password_set_on({"Notes": "no block"}))
        self.assertNotIn("changed:", vk.Profile().render())


class Strength(unittest.TestCase):
    WEAK = ["password", "P@ssw0rd", "Summer2024!", "qwertyuiop12", "aaaaaaaaaaaa",
            "Tr0ub4dor&3", "Kangaroo!!77", "123456789012", "iloveyou2020", "Monkey1234!",
            "1234Football!", "abcdefgh1234", "Liverpool1999", "PASSWORD2023"]
    STRONG = ["correct horse battery staple", "xK9#mQ2$vL7!pR4&", "7gH!kd92-LmQz",
              "vT3nQ8wLp2Zr5Yx", "Gq7!rT2#bN9@"]

    def test_examples(self):
        for pw in self.WEAK:
            self.assertIsNotNone(strength.weakness(pw), pw)
        for pw in self.STRONG:
            self.assertIsNone(strength.weakness(pw), pw)
        self.assertIsNone(strength.weakness(""))

    def test_vaultkit_passwords_are_never_flagged(self):
        for i in range(3000):
            length = 12 + i % 53
            pw = vk.generate_password(length, "" if i % 3 == 0 else vk.DEFAULT_SYMBOLS)
            self.assertIsNone(strength.weakness(pw), pw)

    def test_similar_groups(self):
        groups = strength.similar_groups({"a": "Summer2023!", "b": "Summer2024!", "c": "S0mmer!",
                                          "d": "same-same", "e": "same-same", "f": "ab1"})
        self.assertEqual(groups, [["a", "b"]])  # identical-only pairs are reuse, not this


class Score(TempDirs):
    def result(self, scanned=10, **kw):
        return vk.ScanResult([], [], kw.pop("hits", {}), kw.pop("reuse", []), [], scanned, **kw)

    def test_worst_problem_per_entry_counts_once(self):
        site = breaches.SiteFinding(breaches.Breach("X", "x.com", date(2024, 1, 1), True),
                                    date(2023, 1, 1))
        r = self.result(hits={"a": 3}, reuse=[["a", "b"]], weak={"a": "short", "c": "short"},
                        old={"d": date(2019, 1, 1)}, sites={"e": site})
        self.assertEqual(r.problems(), {"a": "breached", "b": "reused", "c": "weak",
                                        "d": "old", "e": "breached"})
        self.assertEqual(r.score, round(100 * (1 - (1 + .6 + .6 + .2 + 1) / 10)))
        self.assertEqual(self.result(scanned=0).score, 100)

    def test_history_one_point_per_day_capped(self):
        path = Path(self.tmp.name, "vaultkit", "history.json")
        path.parent.mkdir(parents=True, exist_ok=True)
        old = [{"at": (datetime(2025, 1, 1) + timedelta(days=i)).isoformat(), "score": 50,
                "scanned": 1, "breached": 0, "at_risk": 1} for i in range(400)]
        path.write_text(json.dumps(old + ["junk", {"at": "x"}]))
        vk.record_history(self.result(hits={"a": 1}))
        vk.record_history(self.result())        # same day: replaces, doesn't add
        h = vk.load_history()
        self.assertEqual(len(h), 400)
        self.assertEqual(h[-1]["score"], 100)
        self.assertEqual(h[-2]["at"][:10], old[-1]["at"][:10])
        self.assertEqual(set(h[-1]), {"at", "score", "scanned", "breached", "at_risk"})  # no names
        path.write_text("{not json")
        self.assertEqual(vk.load_history(), [])


if __name__ == "__main__":
    unittest.main()
