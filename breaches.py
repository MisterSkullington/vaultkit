"""Was a site in your vault breached AFTER you last changed its password?

Uses Have I Been Pwned's public list of every known breach (site, date, what leaked). The
whole list is downloaded at most once a day and matched on this PC, so HIBP never learns
which sites you have accounts with. No API key is needed for this endpoint.

Dates: only a password date vaultkit recorded itself counts (see vaultkit.password_set_on).
KeePassXC's "Last Modified" moves on any edit, so trusting it could hide a real warning.
Without a recorded date the password's age is unknown, and the finding says so.
"""
from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Callable

URL = "https://haveibeenpwned.com/api/v3/breaches"
USER_AGENT = "vaultkit-password-health (local app)"
CACHE_HOURS = 24
MAX_BYTES = 20 * 1024 * 1024


def data_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    d = Path(base) / "vaultkit"
    d.mkdir(parents=True, exist_ok=True)
    return d


def http_get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,
                                               "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        data = r.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("breach list unexpectedly large")
    return data


@dataclass(frozen=True)
class Breach:
    title: str
    domain: str
    breach_date: date
    passwords_leaked: bool


def parse(raw: bytes) -> list[Breach]:
    out = []
    for b in json.loads(raw):
        domain = (b.get("Domain") or "").strip().lower()
        if not domain or b.get("IsFabricated") or b.get("IsSpamList") or b.get("IsRetired"):
            continue  # no site to match, or not a real breach of that site
        if b.get("IsVerified") is False:
            continue
        try:
            when = date.fromisoformat(str(b.get("BreachDate", ""))[:10])
        except ValueError:
            continue
        classes = [c.lower() for c in b.get("DataClasses") or []]
        out.append(Breach(str(b.get("Title") or domain), domain, when, "passwords" in classes))
    return out


def load(get: Callable[[str], bytes] | None = None, now: float | None = None) -> list[Breach]:
    """The breach list, from a cache younger than a day, else freshly downloaded."""
    cache = data_dir() / "hibp-breaches.json"
    now = time.time() if now is None else now
    if cache.exists() and now - cache.stat().st_mtime < CACHE_HOURS * 3600:
        return parse(cache.read_bytes())
    raw = (get or http_get)(URL)
    breaches = parse(raw)  # validate before caching
    tmp = cache.with_suffix(".tmp")
    tmp.write_bytes(raw)
    os.replace(tmp, cache)
    return breaches


def host_of(url: str) -> str:
    if not url:
        return ""
    u = url if "://" in url else f"https://{url}"
    host = (urllib.parse.urlsplit(u).hostname or "").lower().rstrip(".")
    return host[4:] if host.startswith("www.") else host


@dataclass(frozen=True)
class SiteFinding:
    breach: Breach
    changed: date | None   # when the password was set; None = unknown

    @property
    def after_change(self) -> bool:
        return self.changed is not None and self.breach.breach_date >= self.changed

    def text(self) -> str:
        when = self.breach.breach_date.strftime("%b %Y")
        if self.changed is None:
            return (f"{self.breach.title} had a breach in {when} that exposed passwords. "
                    "Change this one if you haven't since then.")
        return (f"{self.breach.title} had a breach in {when} that exposed passwords, after you "
                f"last changed this one ({self.changed.strftime('%b %Y')}).")


def match(rows: list[dict[str, str]], breaches: list[Breach],
          password_set: Callable[[dict[str, str]], date | None] = lambda row: None,
          ) -> dict[str, SiteFinding]:
    """{entry path: the most recent password-exposing breach of its site that may matter}.
    A breach matters unless the password is known to have been set after it."""
    by_domain: dict[str, Breach] = {}
    for b in breaches:
        if b.passwords_leaked:
            cur = by_domain.get(b.domain)
            if cur is None or b.breach_date > cur.breach_date:
                by_domain[b.domain] = b
    out: dict[str, SiteFinding] = {}
    for r in rows:
        host = host_of(r.get("URL", ""))
        if not host:
            continue
        parts = host.split(".")
        breach = None
        for i in range(len(parts) - 1):  # accounts.adobe.com -> adobe.com
            breach = by_domain.get(".".join(parts[i:]))
            if breach:
                break
        if breach is None:
            continue
        finding = SiteFinding(breach, password_set(r))
        if finding.changed is None or finding.after_change:
            out[r["Path"]] = finding
    return out
