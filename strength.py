"""Rough, transparent password-strength checks. Stdlib only; passwords stay in memory.

Not a full cracker model (like zxcvbn): it catches the patterns attackers try first and
explains each finding in plain words. A random 32-character password from vaultkit passes
every rule with a wide margin.
"""
from __future__ import annotations

import math
import re
import string

MIN_LENGTH = 10
MIN_BITS = 60
SEQUENCES = ("abcdefghijklmnopqrstuvwxyz", "0123456789",
             "qwertyuiop", "asdfghjkl", "zxcvbnm", "1qaz2wsx3edc")
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t",
                       "@": "a", "$": "s", "!": "i"})
# A "word" = lowercase, Capitalised or ALL CAPS, up to 12 letters. Random letters flip case
# constantly, so they don't match and generated passwords aren't flagged.
_WORD = r"(?:[A-Z]?[a-z]{2,11}|[A-Z]{3,12})"
_WORD_THEN_NUMBER = re.compile(_WORD + r"[0-9]{1,4}[^A-Za-z0-9]{0,3}")
_NUMBER_THEN_WORD = re.compile(r"[^A-Za-z0-9]{0,3}[0-9]{1,4}" + _WORD + r"[^A-Za-z0-9]{0,3}")
_YEAR = re.compile(r"(19[4-9][0-9]|20[0-4][0-9])")


def bits(pw: str) -> float:
    """Upper-bound entropy from length and the character sets used."""
    pool = 0
    if any(c in string.ascii_lowercase for c in pw):
        pool += 26
    if any(c in string.ascii_uppercase for c in pw):
        pool += 26
    if any(c in string.digits for c in pw):
        pool += 10
    if any(not c.isalnum() for c in pw):
        pool += 33
    return len(pw) * math.log2(pool) if pool else 0.0


def _sequence_run(pw: str) -> int:
    """Longest run of keyboard or alphabet order (forwards or backwards)."""
    low = pw.lower()
    best = 0
    for seq in SEQUENCES:
        for s in (seq, seq[::-1]):
            for n in range(len(low), 3, -1):
                if n <= best:
                    break
                if any(low[i:i + n] in s for i in range(len(low) - n + 1)):
                    best = n
                    break
    return best


def _disguised_word(pw: str) -> bool:
    """One short word, capitalised or with leetspeak swaps, plus a few extras at the edges."""
    edges = string.digits + string.punctuation + " "
    core = pw.strip(edges)
    plain = core.lower().translate(_LEET)
    if not (4 <= len(plain) <= 12 and plain.isalpha() and len(core) * 10 >= len(pw) * 6):
        return False
    letters = "".join(c for c in core if c.isalpha())
    word_case = letters.islower() or letters.isupper() or (letters[:1].isupper() and letters[1:].islower())
    if not word_case:
        return False  # random letters flip case; a word doesn't
    swapped = plain != core.lower()
    capitalised = core[0].isupper() and core[1:].islower()
    return swapped or capitalised


def weakness(pw: str) -> str | None:
    """Why this password is weak, in one sentence, or None if it looks fine."""
    if not pw:
        return None
    if len(pw) < MIN_LENGTH:
        return f"Only {len(pw)} characters long. Use at least {MIN_LENGTH}, ideally many more."
    if len(set(pw)) <= 3:
        return "Uses only a few different characters."
    run = _sequence_run(pw)
    if run >= 4 and run * 2 >= len(pw):
        return "Mostly a keyboard or alphabet sequence (like qwerty or 1234)."
    if _WORD_THEN_NUMBER.fullmatch(pw) or _NUMBER_THEN_WORD.fullmatch(pw):
        return "A word with numbers added (like Summer2024!) is one of the first things attackers try."
    if _disguised_word(pw):
        return ("Looks like one word with a few changes (like Kangaroo!!77 or Tr0ub4dor&3). "
                "Attackers try capitals, swapped letters and added symbols automatically.")
    if _YEAR.search(pw) and len(pw) < 14 and bits(pw) < 90:
        return "Contains a year and is fairly short, which makes it easier to guess."
    b = bits(pw)
    if b < MIN_BITS:
        return f"Too predictable for its length (about {b:.0f} bits; aim for {MIN_BITS}+)."
    return None


def stem(pw: str) -> str:
    """The 'core' of a password: lower-cased, leetspeak undone, edge digits/symbols removed."""
    core = pw.lower().strip(string.digits + string.punctuation + " ")
    return core.translate(_LEET)  # undo swaps only after the edge digits are gone


def similar_groups(passwords: dict[str, str]) -> list[list[str]]:
    """Entries whose passwords share a core but aren't identical (Summer2023! / Summer2024!)."""
    by_stem: dict[str, list[str]] = {}
    for key, pw in passwords.items():
        s = stem(pw) if pw else ""
        if len(s) >= 4:
            by_stem.setdefault(s, []).append(key)
    groups = []
    for keys in by_stem.values():
        if len(keys) > 1 and len({passwords[k] for k in keys}) > 1:
            groups.append(sorted(keys))
    return sorted(groups, key=len, reverse=True)
