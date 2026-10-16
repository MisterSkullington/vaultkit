#!/usr/bin/env python3
"""vaultkit — local-only companion for a KeePassXC vault.

Commands
  check            Daily Pwned Passwords (k-anonymity) + reuse check over the whole vault.
  profile ENTRY    Read/set the per-site profile (length, symbols, change URL, 2FA).
  rotate start|commit|abort|list ENTRY
                   Pending-password rotation: the new password is saved in the vault
                   BEFORE you submit it on the site.
  fix [ENTRY...]   Walk breached/reused entries: save new password, open the
                   site's change page, confirm, commit.
  remember/forget  Save/delete the master password (Windows DPAPI) for unattended checks.
  shred FILE...    Overwrite + delete exported browser CSVs.

Design rules
  * Stdlib only. All vault I/O goes through the official `keepassxc-cli`; no third-party
    code parses the KDBX file.
  * Plaintext never touches disk: exports are read from the CLI's stdout into memory.
  * Only the first 5 hex chars of each SHA-1 hash leave the machine (HIBP range API).
"""
from __future__ import annotations

import argparse
import csv
import getpass
import hashlib
import io
import json
import os
import secrets
import shlex
import shutil
import string
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field, replace
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterable

__version__ = "1.8.0"
PENDING_GROUP = "vaultkit-pending"
SKIP_GROUPS = {"Recycle Bin"}
HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"
USER_AGENT = "vaultkit/1.0 (local password hygiene)"
# Conservative default: most sites accept these; quotes, backslash, <>, space often break forms.
DEFAULT_SYMBOLS = "!#$%&*+-=?@^_"
PROFILE_START, PROFILE_END = "--- vaultkit ---", "--- /vaultkit ---"
CLIP_SECONDS = 45
# GUI apps on Windows would flash a console window per keepassxc-cli call without this.
_NO_WINDOW = {"creationflags": 0x08000000} if os.name == "nt" else {}  # CREATE_NO_WINDOW
_DETACHED: list[subprocess.Popen] = []


# --------------------------------------------------------------------------- generation
def generate_password(length: int, symbols: str = DEFAULT_SYMBOLS) -> str:
    """CSPRNG password guaranteed to contain every character class in use.

    Rejection sampling (regenerate until all classes present) keeps the output uniformly
    distributed over valid passwords — unlike 'force one of each then shuffle', which
    biases position/class frequencies.
    """
    classes = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if symbols:
        classes.append("".join(dict.fromkeys(symbols)))  # de-dupe, keep order
    if length < len(classes):
        raise ValueError(f"length must be >= {len(classes)}")
    alphabet = "".join(classes)
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(c in cls for c in pw) for cls in classes):
            return pw


# --------------------------------------------------------------------------- profiles
@dataclass
class Profile:
    length: int = 32
    symbols: str = DEFAULT_SYMBOLS  # "" == alphanumeric only
    change_url: str = ""
    twofa: str = "none"  # totp | sms | webauthn | email | none
    changed: str = ""    # YYYY-MM-DD vaultkit last set this password ("" = never/unknown)

    def render(self) -> str:
        sym = self.symbols if self.symbols else "none"
        return "\n".join([
            PROFILE_START,
            f"length: {self.length}",
            f"symbols: {sym}",
            f"change_url: {self.change_url}",
            f"2fa: {self.twofa}",
            *([f"changed: {self.changed}"] if self.changed else []),
            PROFILE_END,
        ])


def parse_profile(notes: str) -> Profile | None:
    lines = notes.splitlines()
    try:
        start, end = lines.index(PROFILE_START), lines.index(PROFILE_END)
    except ValueError:
        return None
    p = Profile()
    for line in lines[start + 1:end]:
        key, _, val = line.partition(":")
        key, val = key.strip(), val.strip()
        if key == "length":
            p.length = int(val)
        elif key == "symbols":
            p.symbols = "" if val == "none" else val
        elif key == "change_url":
            p.change_url = val
        elif key == "2fa":
            p.twofa = val
        elif key == "changed":
            p.changed = val
    return p


def password_set_on(row: dict[str, str]) -> date | None:
    """When vaultkit last set this entry's password, if it ever did. KeePassXC's Last Modified
    can't tell us: it moves on ANY edit (notes, URL, rules), not just password changes."""
    prof = parse_profile(row.get("Notes", "") or "")
    return _day(prof.changed) if prof else None


def upsert_profile(notes: str, profile: Profile) -> str:
    """Replace the vaultkit block in Notes, preserving everything the user wrote (and the
    password date, unless `profile` sets a new one)."""
    if not profile.changed and (old := parse_profile(notes)) and old.changed:
        profile = replace(profile, changed=old.changed)
    lines = notes.splitlines()
    if PROFILE_START in lines and PROFILE_END in lines:
        s, e = lines.index(PROFILE_START), lines.index(PROFILE_END)
        lines = lines[:s] + lines[e + 1:]
    body = "\n".join(lines).strip()
    return f"{body}\n\n{profile.render()}" if body else profile.render()


# --------------------------------------------------------------------------- HIBP
def sha1_hex(pw: str) -> str:
    return hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()


def parse_range(body: str) -> dict[str, int]:
    """'SUFFIX:COUNT' lines -> {suffix: count}. Padding rows (count 0) are dropped."""
    out: dict[str, int] = {}
    for line in body.splitlines():
        suffix, _, count = line.strip().partition(":")
        if suffix and count and int(count) > 0:
            out[suffix.upper()] = int(count)
    return out


def fetch_range(prefix: str, retries: int = 3) -> str:
    """GET the 5-char prefix bucket. Add-Padding hides the real bucket size on the wire."""
    req = urllib.request.Request(
        HIBP_RANGE_URL.format(prefix=prefix),
        headers={"User-Agent": USER_AGENT, "Add-Padding": "true"},
    )
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            if e.code not in (429, 500, 502, 503, 504) or attempt == retries - 1:
                raise
        except urllib.error.URLError:
            if attempt == retries - 1:
                raise
        time.sleep(2 ** attempt)
    raise RuntimeError("unreachable")


def pwned_counts(passwords: dict[str, str],
                 fetch: Callable[[str], str] | None = None,
                 workers: int = 6) -> dict[str, int]:
    """{entry_path: password} -> {entry_path: breach_count} for breached entries only.

    One request per distinct prefix, not per entry; suffix match happens locally.
    """
    fetch = fetch or fetch_range
    by_hash: dict[str, list[str]] = {}
    for path, pw in passwords.items():
        if pw:
            by_hash.setdefault(sha1_hex(pw), []).append(path)
    prefixes = sorted({h[:5] for h in by_hash})
    with ThreadPoolExecutor(max_workers=workers) as ex:
        buckets = dict(zip(prefixes, ex.map(lambda p: parse_range(fetch(p)), prefixes)))
    hits: dict[str, int] = {}
    for h, paths in by_hash.items():
        count = buckets[h[:5]].get(h[5:], 0)
        if count:
            for path in paths:
                hits[path] = count
    return hits


def reused(passwords: dict[str, str]) -> list[list[str]]:
    groups: dict[str, list[str]] = {}
    for path, pw in passwords.items():
        if pw:
            groups.setdefault(sha1_hex(pw), []).append(path)
    return sorted((sorted(g) for g in groups.values() if len(g) > 1), key=len, reverse=True)


# --------------------------------------------------------------------------- keepassxc-cli
class CliError(RuntimeError):
    pass


@dataclass
class Vault:
    db: str
    key_file: str | None = None
    no_password: bool = False
    password_cmd: str | None = None
    cli: str = field(default_factory=lambda: shutil.which("keepassxc-cli") or "keepassxc-cli")
    cli_prefix_args: list[str] = field(default_factory=list)  # e.g. [script] when cli is python
    use_saved_password: bool = False  # Windows DPAPI store (secretstore.py), opt-in
    _pw: str | None = field(default=None, repr=False)

    # --- secret lifecycle (the GUI injects/wipes; the CLI prompts) ---
    def set_secret(self, password: str) -> None:
        self._pw = password

    def lock(self) -> None:
        """Drop our reference to the master password (CPython can't zero the string)."""
        self._pw = None

    @property
    def unlocked(self) -> bool:
        return self.no_password or self._pw is not None

    def verify(self) -> None:
        """Raise CliError unless the credentials open the database (one Argon2 unlock)."""
        self.run("ls", self.db)

    def unlock(self) -> None:
        if self.no_password or self._pw is not None:
            return
        if self.use_saved_password:
            import secretstore
            pw = secretstore.load()
            if pw is None:
                raise CliError("No saved master password. Run: vaultkit remember")
            self._pw = pw
            return
        if self.password_cmd:
            # Windows: CreateProcess parses the string itself; POSIX: split like a shell would.
            cmd = self.password_cmd if os.name == "nt" else shlex.split(self.password_cmd)
            out = subprocess.run(cmd, capture_output=True, text=True, check=True,
                                 **_NO_WINDOW).stdout
            self._pw = out.rstrip("\r\n")
        else:
            self._pw = getpass.getpass(f"Master password for {self.db}: ")

    def run(self, cmd: str, *args: str, extra_stdin: Iterable[str] = ()) -> str:
        self.unlock()
        flags = ["-q"]
        if self.key_file:
            flags += ["-k", self.key_file]
        if self.no_password:
            flags.append("--no-password")
        stdin = ([] if self.no_password else [self._pw or ""]) + list(extra_stdin)
        # Bytes, not text: text mode on Windows rewrites "\n" -> "\r\n" on the way in.
        proc = subprocess.run([self.cli, *self.cli_prefix_args, cmd, *flags, *args],
                              input=("\n".join(stdin) + "\n").encode("utf-8"),
                              capture_output=True, **_NO_WINDOW)
        out = proc.stdout.decode("utf-8", "replace").replace("\r\n", "\n")
        if proc.returncode != 0:
            err = proc.stderr.decode("utf-8", "replace").strip() or out.strip()
            hint = err or ("no message from keepassxc-cli — usually a wrong master password "
                           f"or key file. Check with: keepassxc-cli ls \"{self.db}\"")
            raise CliError(f"keepassxc-cli {cmd} failed (exit {proc.returncode}): {hint}")
        return out

    # NB: DB path goes right after flags; entry/group paths after that.
    def export_entries(self) -> list[dict[str, str]]:
        """Whole vault as rows, held in memory only. One Argon2 unlock instead of N."""
        out = self.run("export", "-f", "csv", self.db)
        rows = []
        for row in csv.DictReader(io.StringIO(out)):
            group = row.get("Group", "").split("/", 1)
            rel = group[1] if len(group) > 1 else ""
            if rel.split("/", 1)[0] in SKIP_GROUPS:
                continue
            row["Path"] = f"{rel}/{row['Title']}" if rel else row["Title"]
            rows.append(row)
        return rows

    def attr(self, entry: str, name: str) -> str:
        return self.run("show", "-s", "-a", name, self.db, entry).rstrip("\n")

    def set_notes(self, entry: str, notes: str) -> None:
        self.run("edit", "--notes", notes, self.db, entry)

    def set_password(self, entry: str, pw: str, notes: str | None = None) -> None:
        """New password (and optionally new notes) in one edit, so one unlock."""
        flags = ["--notes", notes] if notes is not None else []
        self.run("edit", *flags, "-p", self.db, entry, extra_stdin=[pw])

    def add(self, entry: str, pw: str, username: str = "", url: str = "", notes: str = "") -> None:
        args = ["-p"]
        if username:
            args += ["-u", username]
        if url:
            args += ["--url", url]
        if notes:
            args += ["--notes", notes]
        self.run("add", *args, self.db, entry, extra_stdin=[pw])

    def mkdir(self, group: str) -> None:
        try:
            self.run("mkdir", self.db, group)
        except CliError as e:
            if "already exists" not in str(e).lower():
                raise

    def rm(self, entry: str) -> None:
        self.run("rm", self.db, entry)  # moves to Recycle Bin — recoverable by design

    def exists(self, entry: str) -> bool:
        try:
            self.run("show", self.db, entry)
            return True
        except CliError:
            return False

    def ls(self, group: str) -> list[str]:
        try:
            return [l for l in self.run("ls", self.db, group).splitlines() if l and not l.endswith("/")]
        except CliError:
            return []

    def clip(self, entry: str, seconds: int = CLIP_SECONDS) -> None:
        # clip blocks until timeout clears the clipboard; run detached so we return now.
        self.unlock()
        flags = ["-q"] + (["-k", self.key_file] if self.key_file else []) + \
                (["--no-password"] if self.no_password else [])
        p = subprocess.Popen([self.cli, *self.cli_prefix_args, "clip", *flags, self.db, entry,
                              str(seconds)], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, **_NO_WINDOW)
        _DETACHED.append(p)
        if p.stdin:
            p.stdin.write((("" if self.no_password else (self._pw or "")) + "\n").encode("utf-8"))
            p.stdin.close()


def pending_path(entry: str) -> str:
    return f"{PENDING_GROUP}/{entry.replace('/', ' -- ')}"


# --------------------------------------------------------------------------- commands
def state_dir() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or (
        os.environ.get("LOCALAPPDATA") if os.name == "nt" else str(Path.home() / ".local/state"))
    d = Path(base) / "vaultkit"
    d.mkdir(parents=True, exist_ok=True)
    return d


def keyed_passwords(rows: list[dict[str, str]]) -> tuple[dict[str, str], list[str]]:
    """{display_key: password} plus the list of ambiguous (duplicate) entry paths.

    keepassxc-cli addresses entries by path, so two entries with the same title in the same
    group can't be targeted safely. They're still breach-checked (under a disambiguated
    display key) but never rotated automatically.
    """
    keys, dupes = display_keys(rows)
    return {k: r.get("Password", "") for k, r in zip(keys, rows)}, dupes


def display_keys(rows: list[dict[str, str]]) -> tuple[list[str], list[str]]:
    """One unique name per row (its path, disambiguated when a title repeats) + the repeats."""
    counts = Counter(r["Path"] for r in rows)
    dupes = sorted(p for p, n in counts.items() if n > 1)
    keys: list[str] = []
    seen: set[str] = set()
    for r in rows:
        key = r["Path"]
        if counts[key] > 1:
            base = f"{key} [user: {r.get('Username') or '?'}]"
            key, i = base, 1
            while key in seen:
                i += 1
                key = f"{base} #{i}"
        keys.append(key)
        seen.add(key)
    return keys, dupes


OLD_AFTER = timedelta(days=3 * 365)
# Weight of each problem in the health score: a breached password counts fully against it,
# an old one barely. An entry with several problems counts once, by its worst.
PENALTY = {"breached": 1.0, "sitebreach": 0.5, "reused": 0.6, "weak": 0.6, "similar": 0.4,
           "old": 0.2}


@dataclass
class ScanResult:
    rows: list[dict[str, str]]          # entries without their passwords
    keys: list[str]                     # display key per row, same order
    hits: dict[str, int]                # key -> times seen in breaches (the password itself)
    reuse: list[list[str]]
    dupes: list[str]
    scanned: int
    weak: dict[str, str] = field(default_factory=dict)       # key -> why
    similar: list[list[str]] = field(default_factory=list)
    old: dict[str, date] = field(default_factory=dict)       # key -> last changed
    sites: dict[str, object] = field(default_factory=dict)   # key -> breaches.SiteFinding
    sites_error: str = ""                                    # breach list unavailable

    def problems(self) -> dict[str, str]:
        """key -> its worst problem kind (as in PENALTY)."""
        worst: dict[str, str] = {}

        def add(key: str, kind: str) -> None:
            if key not in worst or PENALTY[kind] > PENALTY[worst[key]]:
                worst[key] = kind
        for k in self.hits:
            add(k, "breached")
        for k, f in self.sites.items():
            add(k, "breached" if f.after_change else "sitebreach")
        for group in self.reuse:
            for k in group:
                add(k, "reused")
        for k in self.weak:
            add(k, "weak")
        for group in self.similar:
            for k in group:
                add(k, "similar")
        for k in self.old:
            add(k, "old")
        return worst

    @property
    def score(self) -> int:
        if not self.scanned:
            return 100
        lost = sum(PENALTY[kind] for kind in self.problems().values())
        return max(0, min(100, round(100 * (1 - lost / self.scanned))))


def _day(stamp: str) -> date | None:
    try:
        return date.fromisoformat((stamp or "")[:10])
    except ValueError:
        return None


def scan_full(v: Vault, site_breaches: bool = True) -> ScanResult:
    """Every check in one vault read. Passwords exist only inside this function."""
    import breaches
    import strength
    rows = [r for r in v.export_entries() if not r["Path"].startswith(PENDING_GROUP + "/")]
    keys, dupes = display_keys(rows)
    pw = {k: r.get("Password", "") for k, r in zip(keys, rows)}
    hits = pwned_counts(pw)
    reuse = reused(pw)
    weak = {k: why for k, p in pw.items() if p and (why := strength.weakness(p))}
    similar = strength.similar_groups(pw)
    has_pw = {k for k, x in pw.items() if x}
    scanned = len(has_pw)
    for r in rows:  # drop secrets from the rows we keep around
        r.pop("Password", None)
    del pw

    today = date.today()
    old = {}
    for k, r in zip(keys, rows):
        # Last Modified >= the password's real date, so "edited 3+ years ago" is safe to say
        changed = password_set_on(r) or _day(r.get("Last Modified", ""))
        if k in has_pw and changed and today - changed >= OLD_AFTER:
            old[k] = changed
    sites, error = {}, ""
    if site_breaches:
        try:
            by_path = breaches.match(rows, breaches.load(), password_set_on)
            sites = {k: by_path[r["Path"]] for k, r in zip(keys, rows)
                     if r["Path"] in by_path and k in has_pw}
        except (OSError, ValueError, urllib.error.URLError) as e:
            error = f"the site breach list couldn't be downloaded ({e})"
    return ScanResult(rows, keys, hits, reuse, dupes, scanned, weak, similar, old, sites, error)


def scan(v: Vault) -> tuple[list[dict[str, str]], dict[str, int], list[list[str]], list[str], int]:
    """The breach + reuse part only (the older, smaller result `fix` builds on)."""
    r = scan_full(v, site_breaches=False)
    return r.rows, r.hits, r.reuse, r.dupes, r.scanned


def cmd_check(v: Vault, a: argparse.Namespace) -> int:
    res = scan_full(v)
    hits, reuse, dupes = res.hits, res.reuse, res.dupes

    print(f"vaultkit check — {datetime.now():%Y-%m-%d %H:%M} — {res.scanned} passwords scanned")
    print(f"Health score: {res.score}/100")
    if hits:
        print(f"\n✗ {len(hits)} entr{'y' if len(hits) == 1 else 'ies'} in Pwned Passwords:")
        for path, n in sorted(hits.items(), key=lambda kv: (-kv[1], kv[0])):
            print(f"  {n:>10,}×  {path}")
    else:
        print("\n✓ No vault passwords found in Pwned Passwords.")
    if res.sites:
        print(f"\n✗ {len(res.sites)} site(s) had a breach that may include your password:")
        for k, f in sorted(res.sites.items(), key=lambda kv: (not kv[1].after_change, kv[0])):
            print(f"   - {k}: {f.text()}")
    if reuse:
        print(f"\n! {len(reuse)} reused password group(s):")
        for g in reuse:
            print("   - " + ", ".join(g))
    if res.weak:
        print(f"\n! {len(res.weak)} weak password(s):")
        for k, why in sorted(res.weak.items()):
            print(f"   - {k}: {why}")
    if res.similar:
        print(f"\n! {len(res.similar)} group(s) of near-identical passwords:")
        for g in res.similar:
            print("   - " + ", ".join(g))
    if res.old:
        print(f"\n· {len(res.old)} password(s) unchanged for 3+ years:")
        for k, when in sorted(res.old.items(), key=lambda kv: kv[1]):
            print(f"   - {k} (since {when:%b %Y})")
    if dupes:
        print(f"\n? {len(dupes)} title(s) used by more than one entry (rename them so each is "
              "unique — fix skips these):")
        for d in dupes:
            print(f"   - {d}")
    if res.sites_error:
        print(f"\nNote: {res.sites_error}; that check was skipped.")
    if res.problems():
        print("\nTo change them: vaultkit fix")

    write_report(hits, reuse, dupes, site_breached(res))
    record_history(res)
    breached_now = hits or any(f.after_change for f in res.sites.values())
    return 2 if breached_now else (1 if res.problems() else 0)


def site_breached(res: ScanResult) -> list[str]:
    """Entries whose site was breached after their password was last changed."""
    return sorted(k for k, f in res.sites.items() if f.after_change)


def record_history(res: ScanResult) -> Path:
    """One point per day (the latest check wins): score and counts, never names or passwords."""
    path = state_dir() / "history.json"
    history = load_history()
    kinds = list(res.problems().values())
    point = {"at": datetime.now().isoformat(timespec="seconds"), "score": res.score,
             "scanned": res.scanned, "breached": kinds.count("breached"),
             "at_risk": len(kinds) - kinds.count("breached")}
    if history and str(history[-1].get("at", ""))[:10] == point["at"][:10]:
        history[-1] = point
    else:
        history.append(point)
    history = history[-400:]
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(history), "utf-8")
    os.replace(tmp, path)
    return path


def load_history() -> list[dict]:
    try:
        data = json.loads((state_dir() / "history.json").read_text("utf-8"))
    except (OSError, ValueError):
        return []
    return [h for h in data if isinstance(h, dict) and isinstance(h.get("score"), int)] \
        if isinstance(data, list) else []


def write_report(hits: dict[str, int], reuse: list[list[str]], dupes: list[str],
                 site_breached: list[str] = ()) -> Path:
    """Entry names + counts only — never secrets. Shared by the CLI and the app."""
    report = {"checked_at": datetime.now(timezone.utc).isoformat(),
              "breached": hits, "site_breached": list(site_breached),
              "reused": reuse, "duplicates": dupes}
    path = state_dir() / "last-check.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(report, f, indent=2)
    return path


def cmd_profile(v: Vault, a: argparse.Namespace) -> int:
    notes = v.attr(a.entry, "Notes")
    prof = parse_profile(notes) or Profile()
    changed = False
    for attr, val in (("length", a.length), ("change_url", a.change_url), ("twofa", a.twofa)):
        if val is not None:
            setattr(prof, attr, val)
            changed = True
    if a.symbols is not None:
        prof.symbols = "" if a.symbols == "none" else a.symbols
        changed = True
    if changed:
        generate_password(prof.length, prof.symbols)  # validate before writing
        v.set_notes(a.entry, upsert_profile(notes, prof))
    print(json.dumps(asdict(prof), indent=2))
    return 0


# --------------------------------------------------------------------------- rotation
open_url: Callable[[str], object] = webbrowser.open  # patched in tests


def change_url_for(prof: Profile, entry_url: str) -> str:
    """Profile URL > the site's /.well-known/change-password (W3C convention) > entry URL."""
    if prof.change_url:
        return prof.change_url
    if not entry_url:
        return ""
    u = entry_url if "://" in entry_url else f"https://{entry_url}"
    parts = urllib.parse.urlsplit(u)
    if parts.scheme in ("http", "https") and parts.netloc:
        return f"https://{parts.netloc}/.well-known/change-password"
    return entry_url


@dataclass
class SiteInfo:
    username: str
    url: str
    notes: str

    @property
    def profile(self) -> Profile:
        return parse_profile(self.notes) or Profile()


def site_info(v: Vault, entry: str, row: dict[str, str] | None = None) -> SiteInfo:
    if row:  # from an export we already have — saves three Argon2 unlocks
        return SiteInfo(row.get("Username", ""), row.get("URL", ""), row.get("Notes", ""))
    return SiteInfo(v.attr(entry, "UserName"), v.attr(entry, "URL"), v.attr(entry, "Notes"))


def start_rotation(v: Vault, entry: str, info: SiteInfo) -> str:
    """Generate and SAVE the new password before the site ever sees it."""
    pend = pending_path(entry)
    prof = info.profile
    v.mkdir(PENDING_GROUP)
    v.add(pend, generate_password(prof.length, prof.symbols),
          username=info.username, url=info.url,
          notes=f"pending_for: {entry}\ncreated: {datetime.now():%Y-%m-%d %H:%M}")
    return pend


def commit_rotation(v: Vault, entry: str) -> None:
    """Make the pending password the real one, and record today as its date."""
    pend = pending_path(entry)
    notes = v.attr(entry, "Notes")
    prof = parse_profile(notes) or Profile()
    prof.changed = date.today().isoformat()
    # old one stays in entry History
    v.set_password(entry, v.attr(pend, "Password"), notes=upsert_profile(notes, prof))
    v.rm(pend)


def abort_rotation(v: Vault, entry: str) -> None:
    v.rm(pending_path(entry))


def cmd_rotate(v: Vault, a: argparse.Namespace) -> int:
    if a.action == "list":
        items = v.ls(PENDING_GROUP)
        print("\n".join(items) if items else "No pending rotations.")
        return 0

    if a.action == "start":
        pend = pending_path(a.entry)
        if v.exists(pend):
            print(f"A rotation is already pending for {a.entry}. commit or abort it first.")
            return 1
        info = site_info(v, a.entry)
        start_rotation(v, a.entry, info)
        v.clip(pend)
        print(f"New password saved to '{pend}' and copied to clipboard for {CLIP_SECONDS}s.")
        print(f"Change it here: {change_url_for(info.profile, info.url) or '(no URL on entry)'}")
        if info.profile.twofa != "none":
            print(f"2FA on this account: {info.profile.twofa} — have it ready.")
        print("\nAfter the site accepts it, log out and back in with it, then run:\n"
              f"  vaultkit rotate commit {shlex.quote(a.entry)}\n"
              "If the site rejected it:\n"
              f"  vaultkit rotate abort {shlex.quote(a.entry)}")
        return 0

    if a.action == "commit":
        commit_rotation(v, a.entry)
        print(f"✓ {a.entry} updated. Old password is in the entry's History tab.")
        return 0

    if a.action == "abort":
        abort_rotation(v, a.entry)
        print(f"Pending password for {a.entry} moved to Recycle Bin. Original untouched.")
        return 0
    return 1


FIX_PROMPT = ("  [y] site accepted it AND I logged in with it   [n] site rejected it\n"
              "  [c] copy password again   [s] skip for now   [q] quit\n  > ")


def cmd_fix(v: Vault, a: argparse.Namespace) -> int:
    """Walk every entry with a problem (breached first): save new pw -> open change page ->
    confirm -> commit."""
    res = scan_full(v)
    rows, hits, reuse, dupes = res.rows, res.hits, res.reuse, res.dupes
    by_path = {r["Path"]: r for r in rows}
    dupe_set = set(dupes)

    if a.entries:
        targets = [(e, "requested") for e in a.entries]
    else:
        targets = [(p, f"breached {n:,}×") for p, n in sorted(hits.items(), key=lambda kv: (-kv[1], kv[0]))]
        seen = {p for p, _ in targets}

        def add(p: str, why: str) -> None:
            if p not in seen:
                targets.append((p, why))
                seen.add(p)
        for p, f in sorted(res.sites.items(), key=lambda kv: (not kv[1].after_change, kv[0])):
            add(p, f"site breach ({f.breach.title}, {f.breach.breach_date:%b %Y})")
        for group in reuse:
            for p in group:
                add(p, f"reused across {len(group)} entries")
        for p, why in sorted(res.weak.items()):
            add(p, "weak")
        for group in res.similar:
            for p in group:
                add(p, "near-identical to another")
        for p, when in sorted(res.old.items(), key=lambda kv: kv[1]):
            add(p, f"unchanged since {when:%b %Y}")
    skipped = [p for p, _ in targets if p not in by_path or p in dupe_set
               or p.startswith(PENDING_GROUP + "/")]
    targets = [(p, why) for p, why in targets if p not in skipped]

    if skipped:
        print("Skipping (duplicate title, pending entry, or not found — rename/check in KeePassXC):")
        for p in skipped:
            print(f"   - {p}")
    if not targets:
        print("Nothing to fix. ✓")
        return 0

    print(f"\n{len(targets)} password(s) to change. Each new password is saved in the vault "
          "before you use it, so quitting at any point is safe.\n"
          "Tip: save any unsaved changes in the KeePassXC window first.")
    done = rejected = 0
    for i, (entry, why) in enumerate(targets, 1):
        info = site_info(v, entry, by_path.get(entry))
        pend = pending_path(entry)
        print(f"\n[{i}/{len(targets)}] {entry} — {why}")
        if v.exists(pend):
            print("  Using the new password already saved from an earlier run.")
        else:
            start_rotation(v, entry, info)
            print("  New password generated and saved in the vault.")
        v.clip(pend)
        url = change_url_for(info.profile, info.url)
        if url:
            open_url(url)
            print(f"  Opened {url}")
        else:
            print("  No URL on this entry — open the site's password settings yourself.")
        print(f"  New password is on the clipboard for {CLIP_SECONDS}s "
              f"(or fill it from the '{pend}' entry in the extension).")
        if info.profile.twofa != "none":
            print(f"  This account uses {info.profile.twofa} 2FA — have it ready.")

        while True:
            ans = input(FIX_PROMPT).strip().lower()
            if ans == "y":
                commit_rotation(v, entry)
                done += 1
                print("  ✓ Saved. Old password kept in the entry's History.")
                break
            if ans == "n":
                abort_rotation(v, entry)
                rejected += 1
                print("  Discarded the new password; original unchanged. If the site needs "
                      "shorter/no symbols, set a profile: vaultkit profile "
                      f"{shlex.quote(entry)} --length 20 --symbols none")
                break
            if ans == "c":
                v.clip(pend)
                print(f"  Copied again ({CLIP_SECONDS}s).")
                continue
            if ans == "s":
                print("  Skipped. The new password stays saved; fix will reuse it next time.")
                break
            if ans == "q":
                print(f"\nStopped. {done} changed, {rejected} rejected. "
                      "Run vaultkit fix again to continue.")
                return 0
    print(f"\nDone: {done} changed, {rejected} rejected, "
          f"{len(targets) - done - rejected} skipped.")
    return 0


def cmd_remember(v: Vault, a: argparse.Namespace) -> int:
    import secretstore
    if not secretstore.supported():
        print("Saved passwords use Windows DPAPI and are only available on Windows.")
        return 1
    print("This saves your master password encrypted to your Windows login (DPAPI) so the\n"
          "daily check can run while you're away. Anything running as you can read it.")
    v.use_saved_password = False
    v.unlock()  # prompts
    v.verify()  # never store a wrong password
    print(f"Saved to {secretstore.save(v._pw or '')}. Undo any time with: vaultkit forget")
    return 0


def cmd_forget(_: Vault | None, a: argparse.Namespace) -> int:
    import secretstore
    print("Saved master password deleted." if secretstore.forget()
          else "No saved master password.")
    return 0


def shred_file(path: Path, passes: int = 1) -> None:
    """Overwrite with random bytes, fsync, truncate, rename, unlink.

    Effective on HDDs and non-journaled data. On SSDs/APFS/btrfs/cloud-synced folders,
    wear-levelling and copy-on-write mean old blocks may survive — the real fix is to
    export onto a RAM disk or an encrypted volume in the first place (see SETUP.md).
    """
    size = path.stat().st_size
    with open(path, "r+b", buffering=0) as f:
        for _ in range(passes):
            f.seek(0)
            left = size
            while left:
                n = min(1 << 20, left)
                f.write(os.urandom(n))
                left -= n
            os.fsync(f.fileno())
        f.truncate(0)
        os.fsync(f.fileno())
    tmp = path.with_name(secrets.token_hex(8))
    path.rename(tmp)
    tmp.unlink()


def cmd_shred(_: Vault | None, a: argparse.Namespace) -> int:
    files = [Path(f) for f in a.files]
    missing = [str(f) for f in files if not f.is_file()]
    if missing:
        print("Not files: " + ", ".join(missing), file=sys.stderr)
        return 1
    if not a.yes:
        print("About to irreversibly destroy:\n  " + "\n  ".join(map(str, files)))
        if input("Type 'shred' to continue: ").strip() != "shred":
            print("Aborted.")
            return 1
    for f in files:
        shred_file(f, a.passes)
        print(f"shredded {f}")
    return 0


# --------------------------------------------------------------------------- CLI
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="vaultkit", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"vaultkit {__version__}")
    p.add_argument("--db", default=os.environ.get("VAULTKIT_DB"), help="path to .kdbx (or $VAULTKIT_DB)")
    p.add_argument("--key-file", default=os.environ.get("VAULTKIT_KEYFILE"))
    p.add_argument("--no-password", action="store_true", help="key-file-only database")
    p.add_argument("--use-saved-password", action="store_true",
                   help="use the password saved with 'vaultkit remember' (Windows DPAPI)")
    p.add_argument("--password-cmd", default=os.environ.get("VAULTKIT_PASSWORD_CMD"),
                   help="command printing the master password (OS keychain) for unattended runs")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("check", help="Pwned Passwords + reuse check")

    pr = sub.add_parser("profile", help="show/set per-site profile")
    pr.add_argument("entry")
    pr.add_argument("--length", type=int)
    pr.add_argument("--symbols", help="allowed symbol set, or 'none'")
    pr.add_argument("--change-url")
    pr.add_argument("--2fa", dest="twofa", choices=["totp", "sms", "webauthn", "email", "none"])

    ro = sub.add_parser("rotate", help="pending-password rotation")
    ro.add_argument("action", choices=["start", "commit", "abort", "list"])
    ro.add_argument("entry", nargs="?")

    fx = sub.add_parser("fix", help="change breached/reused passwords one by one")
    fx.add_argument("entries", nargs="*", help="specific entry paths (default: all flagged)")

    sub.add_parser("remember", help="save master password for unattended checks (Windows)")
    sub.add_parser("forget", help="delete the saved master password")

    sh = sub.add_parser("shred", help="overwrite + delete files (exported CSVs)")
    sh.add_argument("files", nargs="+")
    sh.add_argument("--passes", type=int, default=1)
    sh.add_argument("-y", "--yes", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.cmd == "shred":
        return cmd_shred(None, a)
    if a.cmd == "forget":
        return cmd_forget(None, a)
    if not a.db:
        print("Set --db or VAULTKIT_DB.", file=sys.stderr)
        return 64
    if a.cmd == "rotate" and a.action != "list" and not a.entry:
        print("rotate start|commit|abort needs an ENTRY path.", file=sys.stderr)
        return 64
    v = Vault(db=a.db, key_file=a.key_file, no_password=a.no_password,
              password_cmd=a.password_cmd, use_saved_password=a.use_saved_password)
    try:
        return {"check": cmd_check, "profile": cmd_profile, "rotate": cmd_rotate,
                "fix": cmd_fix, "remember": cmd_remember}[a.cmd](v, a)
    except CliError as e:
        print(e, file=sys.stderr)
        return 3
    except urllib.error.URLError as e:
        print(f"Pwned Passwords API unreachable: {e}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    sys.exit(main())
