import os, sys, tempfile, unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import secretstore  # noqa: E402
import vaultkit as vk  # noqa: E402

FAKE = str(HERE / "fake_kpcli.py")


def fake_protect(b: bytes) -> bytes:  # stand-in cipher for non-Windows test runs
    return b"FAKE" + bytes(x ^ 0x5A for x in b)


def fake_unprotect(b: bytes) -> bytes:
    assert b.startswith(b"FAKE")
    return bytes(x ^ 0x5A for x in b[4:])


class Store(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.patches = [mock.patch.dict(os.environ, {"LOCALAPPDATA": self.tmp.name})]
        if not secretstore.supported():
            self.patches += [mock.patch.object(secretstore, "protect", fake_protect),
                             mock.patch.object(secretstore, "unprotect", fake_unprotect)]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    def test_roundtrip_and_never_plaintext_on_disk(self):
        self.assertIsNone(secretstore.load())
        path = secretstore.save("corr3ct-h0rse ünïcode")
        self.assertNotIn(b"corr3ct", path.read_bytes())
        self.assertEqual(secretstore.load(), "corr3ct-h0rse ünïcode")
        self.assertTrue(secretstore.forget())
        self.assertFalse(secretstore.is_saved())
        self.assertFalse(secretstore.forget())

    def test_vault_uses_saved_password(self):
        secretstore.save("m4ster")
        v = vk.Vault(db="v.kdbx", use_saved_password=True)
        v.unlock()
        self.assertEqual(v._pw, "m4ster")
        v.lock()
        self.assertFalse(v.unlocked)

    def test_vault_without_saved_password_errors(self):
        v = vk.Vault(db="v.kdbx", use_saved_password=True)
        with self.assertRaises(vk.CliError):
            v.unlock()

    @unittest.skipIf(secretstore.supported(), "real DPAPI available")
    def test_non_windows_refuses_cleanly(self):
        for p in self.patches[1:]:
            p.stop()
        self.patches = self.patches[:1]
        with self.assertRaises(secretstore.SecretStoreError):
            secretstore.save("x")


if __name__ == "__main__":
    unittest.main()
