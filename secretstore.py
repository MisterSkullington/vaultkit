"""Opt-in storage of the master password for unattended checks, using Windows DPAPI.

DPAPI (CryptProtectData) encrypts with a key derived from your Windows login. Only your
Windows account on this PC can decrypt it — another user, another PC, or a copied disk
can't. Anyone (or any malware) running as *you* while you're logged in can, which is the
trade-off you opted into. Stdlib-only (ctypes); Windows-only by design.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# App-specific secondary entropy: another program calling DPAPI as you must also know this.
# Not a secret in the cryptographic sense, but it stops casual "decrypt every blob" sweeps.
_ENTROPY = b"vaultkit/master-password/v1"
_DESCRIPTION = "vaultkit master password"
CRYPTPROTECT_UI_FORBIDDEN = 0x1


class SecretStoreError(RuntimeError):
    pass


def supported() -> bool:
    return os.name == "nt"


def store_path() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    d = Path(base) / "vaultkit"
    d.mkdir(parents=True, exist_ok=True)
    return d / "master.dpapi"


if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    class _Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    _crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(_Blob), wintypes.LPCWSTR, ctypes.POINTER(_Blob),
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_Blob)]
    _crypt32.CryptProtectData.restype = wintypes.BOOL
    _crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(_Blob), ctypes.POINTER(wintypes.LPWSTR), ctypes.POINTER(_Blob),
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_Blob)]
    _crypt32.CryptUnprotectData.restype = wintypes.BOOL
    _kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    _kernel32.LocalFree.restype = ctypes.c_void_p

    def _in_blob(data: bytes) -> tuple[_Blob, ctypes.Array]:
        buf = ctypes.create_string_buffer(data, len(data))  # keep alive while in use
        return _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf

    def _take(out: _Blob) -> bytes:
        try:
            return ctypes.string_at(out.pbData, out.cbData)
        finally:
            _kernel32.LocalFree(ctypes.cast(out.pbData, ctypes.c_void_p))

    def protect(data: bytes) -> bytes:
        inp, _a = _in_blob(data)
        ent, _b = _in_blob(_ENTROPY)
        out = _Blob()
        if not _crypt32.CryptProtectData(ctypes.byref(inp), _DESCRIPTION, ctypes.byref(ent),
                                         None, None, CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out)):
            raise SecretStoreError(f"CryptProtectData failed: {ctypes.WinError(ctypes.get_last_error())}")
        return _take(out)

    def unprotect(blob: bytes) -> bytes:
        inp, _a = _in_blob(blob)
        ent, _b = _in_blob(_ENTROPY)
        out = _Blob()
        if not _crypt32.CryptUnprotectData(ctypes.byref(inp), None, ctypes.byref(ent),
                                           None, None, CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out)):
            raise SecretStoreError(f"CryptUnprotectData failed: {ctypes.WinError(ctypes.get_last_error())}")
        return _take(out)
else:
    def protect(data: bytes) -> bytes:
        raise SecretStoreError("Saved passwords use Windows DPAPI and are only available on Windows.")

    def unprotect(blob: bytes) -> bytes:
        raise SecretStoreError("Saved passwords use Windows DPAPI and are only available on Windows.")


def save(password: str) -> Path:
    blob = protect(password.encode("utf-8"))
    path = store_path()
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(blob)
    os.replace(tmp, path)  # atomic: never a half-written blob
    return path


def load() -> str | None:
    path = store_path()
    if not path.exists():
        return None
    return unprotect(path.read_bytes()).decode("utf-8")


def forget() -> bool:
    path = store_path()
    if path.exists():
        path.unlink()
        return True
    return False


def is_saved() -> bool:
    return store_path().exists()
