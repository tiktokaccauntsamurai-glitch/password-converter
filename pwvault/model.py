"""
Core data model: one password entry, plus the normalisation rules used for
deduplication and for verifying an export against what was selected.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict

# The six fields Apple Passwords carries; this is our internal superset too.
FIELDS = ("title", "url", "username", "password", "notes", "otpauth")


def strip_www(host: str) -> str:
    host = host.lower().strip()
    return host[4:] if host.startswith("www.") else host


def domain_of(url: str) -> str:
    """
    Best-effort registrable host of a URL, without pulling in urllib
    (the whole urllib package is blocked by the network kill switch).
    """
    if not url:
        return ""
    u = url.strip()
    if "://" in u:
        u = u.split("://", 1)[1]
    # strip credentials, path, query, fragment
    u = u.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in u:
        u = u.rsplit("@", 1)[1]
    # strip port
    if ":" in u and not u.startswith("["):
        u = u.split(":", 1)[0]
    return strip_www(u)


def normalise_url(url: str) -> str:
    """Key used for grouping: scheme-less, www-less, path-less host."""
    return domain_of(url) or (url or "").strip().lower()


def password_checksum(password: str) -> str:
    """
    Two-character transcription check code printed next to a password.

    Purpose: after typing a password by hand from paper you can ask the app
    (Tools > Check code) whether what you typed produces the same two chars.
    It is a typo detector, NOT a security feature - it leaks ~10 bits about
    the password, which is why it is optional and off for A4 sheets by default.
    """
    if not password:
        return "--"
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"  # no 0/O/1/I
    return alphabet[digest[0] % 32] + alphabet[digest[1] % 32]


@dataclass
class Record:
    title: str = ""
    url: str = ""
    username: str = ""
    password: str = ""
    notes: str = ""
    otpauth: str = ""

    # provenance
    source_file: str = ""
    source_format: str = ""

    # derived / UI state
    category: str = "OTHER"
    selected_export: bool = True
    selected_print: bool = True
    merged_from: list = field(default_factory=list)
    conflict: bool = False
    incomplete: bool = False

    # ---------------------------------------------------------------- keys
    @property
    def group_key(self) -> tuple:
        """Identity used to merge duplicates across browsers."""
        return (normalise_url(self.url), self.username.strip().lower())

    @property
    def uid(self) -> str:
        """Stable id for the UI; derived from content, contains no secret."""
        raw = "|".join((normalise_url(self.url), self.username.lower(),
                        hashlib.sha256(self.password.encode()).hexdigest()[:16]))
        return hashlib.sha256(raw.encode()).hexdigest()[:12]

    @property
    def display_title(self) -> str:
        return self.title or domain_of(self.url) or self.url or "(no title)"

    def payload(self) -> tuple:
        """Field tuple used when verifying a written export file."""
        return tuple(getattr(self, f).strip() for f in FIELDS)

    def payload_subset(self, fields) -> tuple:
        return tuple(getattr(self, f).strip() for f in fields)

    def as_dict(self) -> dict:
        return asdict(self)

    def redacted(self) -> dict:
        """Loggable form: never contains the password."""
        d = {k: v for k, v in self.as_dict().items() if k != "password"}
        d["password_len"] = len(self.password)
        d["password_check"] = password_checksum(self.password)
        return d
