"""
ASCII-only rendering for printed output.

Requirement: printed sheets must be English/ASCII only.

Two different rules apply, because the two kinds of text have different
failure modes:

  * Labels (title, url, username, notes) - readability wins. Cyrillic and
    Greek are transliterated, accents are stripped, anything else becomes '?'.
    A slightly anglicised site name is harmless.

  * Passwords - correctness wins. A password must be transcribable character
    for character. We never transliterate one. If it is pure printable ASCII
    it is printed verbatim; otherwise every non-ASCII character is printed as
    an explicit \\uXXXX escape and the row is flagged, so you know the paper
    copy needs the escape decoded rather than typed literally.
"""
from __future__ import annotations

import unicodedata
import string

PRINTABLE = set(string.printable[:95])  # space .. '~'

# Russian/Ukrainian/Belarusian/Serbian coverage, BGN/PCGN-ish.
_CYRILLIC = {
    "а": "a", "б": "b", "в": "v", "г": "g", "ґ": "g", "д": "d", "е": "e",
    "ё": "yo", "є": "ye", "ж": "zh", "з": "z", "и": "i", "і": "i", "ї": "yi",
    "й": "y", "к": "k", "л": "l", "м": "m", "н": "n", "о": "o", "п": "p",
    "р": "r", "с": "s", "т": "t", "у": "u", "ў": "w", "ф": "f", "х": "kh",
    "ц": "ts", "ч": "ch", "ш": "sh", "щ": "shch", "ъ": "", "ы": "y", "ь": "",
    "э": "e", "ю": "yu", "я": "ya", "ђ": "dj", "ј": "j", "љ": "lj",
    "њ": "nj", "ћ": "c", "џ": "dz",
}

_EXTRA = {
    "ß": "ss", "æ": "ae", "œ": "oe", "ø": "o", "å": "aa", "đ": "d", "ł": "l",
    "þ": "th", "ð": "d", "–": "-", "—": "-", "‑": "-", "„": '"', "“": '"',
    "”": '"', "‘": "'", "’": "'", "«": '"', "»": '"', "…": "...",
    " ": " ", "№": "No.", "€": "EUR", "£": "GBP", "¥": "JPY", "₽": "RUB",
    "•": "-", "→": "->", "×": "x",
}


def to_ascii(text, placeholder="?"):
    """Transliterate arbitrary text down to printable ASCII (labels only)."""
    if not text:
        return ""
    out = []
    for ch in text:
        if ch in PRINTABLE:
            out.append(ch)
            continue
        if ch == "\t":
            out.append(" ")
            continue
        lower = ch.lower()
        mapped = _CYRILLIC.get(lower) or _EXTRA.get(lower)
        if mapped is not None:
            out.append(mapped.upper() if ch.isupper() and mapped else mapped)
            continue
        decomposed = unicodedata.normalize("NFKD", ch)
        stripped = "".join(c for c in decomposed if not unicodedata.combining(c))
        stripped = "".join(c if c in PRINTABLE else "" for c in stripped)
        out.append(stripped if stripped else placeholder)
    return "".join(out)


def ascii_password(password):
    """
    Return (rendered, needs_escape).

    `rendered` is always pure ASCII. When `needs_escape` is True the sheet must
    show the legend explaining that \\uXXXX sequences are escapes.
    """
    if not password:
        return "", False
    if all(ch in PRINTABLE for ch in password):
        return password, False
    out = []
    for ch in password:
        if ch in PRINTABLE:
            out.append(ch)
        else:
            code = ord(ch)
            out.append("\\u%04X" % code if code <= 0xFFFF else "\\U%08X" % code)
    return "".join(out), True


def group_chars(text, size=4, sep=" "):
    """Visual grouping aid for hand transcription (thin space by default)."""
    if size <= 0 or len(text) <= size:
        return text
    return sep.join(text[i:i + size] for i in range(0, len(text), size))


def shorten(text, limit):
    """Middle-ellipsis so both ends of a long URL stay readable."""
    if limit <= 3 or len(text) <= limit:
        return text
    head = (limit - 3) // 2
    tail = limit - 3 - head
    return text[:head] + "..." + (text[-tail:] if tail else "")


AMBIGUITY_LEGEND = (
    "Reading guide: 0 (zero) is narrow, O (letter) is round - "
    "l (lower L), 1 (one), I (capital i) - "
    "5/S, 8/B, 2/Z, 6/G, 9/g, rn/m. "
    "Passwords are printed in a monospaced face with slashed zeros."
)
