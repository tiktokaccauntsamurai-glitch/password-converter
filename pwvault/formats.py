"""
CSV dialects of the password managers we interoperate with.

Verified against vendor documentation (September 2026):

  Chrome / Google Password Manager
      export header : name,url,username,password,note
      import needs  : url, username, password  (order-insensitive, extra
                      columns tolerated)
      docs          : https://support.google.com/chrome/answer/13068232

  Firefox (about:logins -> Export Logins)
      export header : "url","username","password","httpRealm",
                      "formActionOrigin","guid","timeCreated",
                      "timeLastUsed","timePasswordChanged"
      import needs  : url, username, password
      docs          : https://support.mozilla.org/kb/export-login-data-firefox

  Apple Passwords (macOS/iOS, File > Export All Passwords)
      header        : Title,URL,Username,Password,Notes,OTPAuth
      requirements  : UTF-8 without BOM, comma delimiter, CRLF line endings

  pwvault
      full-fidelity internal format, keeps every field plus provenance.

`carried` lists the fields that survive a round trip through that format; the
export verifier only compares those, and the UI warns before you shred sources
using a lossy format.
"""
from __future__ import annotations

import csv
import os
import time
import secrets

from .model import Record, FIELDS, domain_of
from .security import open_private

# --------------------------------------------------------------------------
# reading
# --------------------------------------------------------------------------

ENCODINGS = ("utf-8-sig", "utf-8", "cp1252", "cp1251", "latin-1")

# alias -> internal field, for the tolerant "generic" reader
ALIASES = {
    "title": "title", "name": "title", "item name": "title", "account": "title",
    "site": "title", "website name": "title",
    "url": "url", "website": "url", "login_uri": "url", "uri": "url",
    "web site": "url", "hostname": "url", "origin": "url", "website url": "url",
    "username": "username", "user": "username", "login": "username",
    "login_username": "username", "user name": "username", "email": "username",
    "e-mail": "username", "account name": "username",
    "password": "password", "login_password": "password", "pass": "password",
    "notes": "notes", "note": "notes", "comment": "notes", "comments": "notes",
    "otpauth": "otpauth", "otp": "otpauth", "totp": "otpauth",
    "login_totp": "otpauth", "two-factor secret": "otpauth", "verification code": "otpauth",
}


def _norm_header(name):
    return (name or "").strip().lstrip("﻿").lower()


def detect_format(fieldnames):
    """Identify the source dialect from a CSV header row."""
    if not fieldnames:
        return "unknown"
    fields = {_norm_header(f) for f in fieldnames}
    if {"url", "username", "password"} <= fields and "httprealm" in fields:
        return "firefox"
    if {"name", "url", "username", "password"} <= fields:
        return "chrome"
    if {"title", "url", "username", "password"} <= fields and "otpauth" in fields:
        return "apple"
    if {"title", "url", "username", "password"} <= fields:
        return "apple"
    if {"url", "username", "password"} <= fields:
        return "chrome"  # bare Google-style minimum
    if fields & {"login_uri", "login_username", "login_password"}:
        return "bitwarden"
    return "generic"


def _decode_rows(path):
    """Yield (fieldnames, list-of-dicts) trying several encodings."""
    last_error = None
    for enc in ENCODINGS:
        try:
            with open(path, "r", newline="", encoding=enc) as fh:
                reader = csv.DictReader(fh)
                rows = list(reader)
                return reader.fieldnames or [], rows, enc
        except (UnicodeDecodeError, UnicodeError) as exc:
            last_error = exc
            continue
    raise ValueError("cannot decode %s: %s" % (os.path.basename(path), last_error))


def read_csv(path):
    """
    Read any supported CSV into Records.
    Returns (records, info) where info describes what was detected.
    """
    fieldnames, rows, encoding = _decode_rows(path)
    fmt = detect_format(fieldnames)
    records = []
    skipped = 0

    for raw in rows:
        row = {}
        for key, value in raw.items():
            if key is None:
                continue
            row[_norm_header(key)] = (value or "").strip()

        rec = Record(source_file=path, source_format=fmt)
        if fmt == "firefox":
            rec.url = row.get("url", "")
            rec.username = row.get("username", "")
            rec.password = row.get("password", "")
            rec.title = domain_of(rec.url)
            realm = row.get("httprealm", "")
            rec.notes = ("HTTP realm: %s" % realm) if realm and realm != "null" else ""
        elif fmt == "chrome":
            rec.title = row.get("name", "") or domain_of(row.get("url", ""))
            rec.url = row.get("url", "")
            rec.username = row.get("username", "")
            rec.password = row.get("password", "")
            rec.notes = row.get("note", "") or row.get("notes", "")
        elif fmt == "apple":
            rec.title = row.get("title", "")
            rec.url = row.get("url", "")
            rec.username = row.get("username", "")
            rec.password = row.get("password", "")
            rec.notes = row.get("notes", "")
            rec.otpauth = row.get("otpauth", "")
        else:  # generic / bitwarden / unknown
            for header, value in row.items():
                target = ALIASES.get(header)
                if target and not getattr(rec, target):
                    setattr(rec, target, value)
            if not rec.title:
                rec.title = domain_of(rec.url)

        # A row with neither a locator nor a secret carries no information.
        if not (rec.url or rec.username) or not rec.password:
            if not any((rec.url, rec.username, rec.password)):
                skipped += 1
                continue
            rec.incomplete = True

        records.append(rec)

    info = {
        "path": path,
        "format": fmt,
        "encoding": encoding,
        "header": list(fieldnames),
        "rows": len(rows),
        "parsed": len(records),
        "skipped_empty": skipped,
    }
    return records, info


# --------------------------------------------------------------------------
# writing
# --------------------------------------------------------------------------

def _guid():
    """RFC-4122-shaped random id without importing uuid (keeps deps minimal)."""
    h = secrets.token_hex(16)
    return "{%s-%s-4%s-a%s-%s}" % (h[0:8], h[8:12], h[13:16], h[17:20], h[20:32])


def _ms_now():
    return str(int(time.time() * 1000))


def _write(path, header, rows):
    with open_private(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh, lineterminator="\r\n", quoting=csv.QUOTE_MINIMAL)
        writer.writerow(header)
        writer.writerows(rows)
    return path


def write_apple(path, records):
    header = ["Title", "URL", "Username", "Password", "Notes", "OTPAuth"]
    rows = [[r.title, r.url, r.username, r.password, r.notes, r.otpauth]
            for r in records]
    return _write(path, header, rows)


def write_chrome(path, records):
    header = ["name", "url", "username", "password", "note"]
    rows = [[r.display_title, r.url, r.username, r.password, r.notes]
            for r in records]
    return _write(path, header, rows)


def write_firefox(path, records):
    header = ["url", "username", "password", "httpRealm", "formActionOrigin",
              "guid", "timeCreated", "timeLastUsed", "timePasswordChanged"]
    now = _ms_now()
    rows = []
    for r in records:
        url = r.url
        if url and "://" not in url:
            url = "https://" + url
        origin = url.split("/")[0] + "//" + domain_of(url) if "://" in url else url
        rows.append([url, r.username, r.password, "", origin,
                     _guid(), now, now, now])
    return _write(path, header, rows)


def write_vault(path, records):
    """Full-fidelity backup: nothing is dropped, ever."""
    header = list(FIELDS) + ["category", "source_format", "source_file"]
    rows = [[r.title, r.url, r.username, r.password, r.notes, r.otpauth,
             r.category, r.source_format, os.path.basename(r.source_file)]
            for r in records]
    return _write(path, header, rows)


# --------------------------------------------------------------------------
# format registry
# --------------------------------------------------------------------------

class Spec:
    def __init__(self, key, label, writer, carried, filename, note=""):
        self.key = key
        self.label = label
        self.writer = writer
        self.carried = carried          # fields that survive the round trip
        self.filename = filename
        self.note = note

    @property
    def lossy_fields(self):
        return [f for f in FIELDS if f not in self.carried]

    @property
    def lossless(self):
        return not self.lossy_fields


WRITE_FORMATS = {
    "apple": Spec(
        "apple", "Apple Passwords (macOS / iOS)", write_apple,
        ("title", "url", "username", "password", "notes", "otpauth"),
        "apple_passwords.csv",
        "Lossless. File > Import Passwords from File in the Passwords app.",
    ),
    "chrome": Spec(
        "chrome", "Chrome / Google Password Manager", write_chrome,
        ("title", "url", "username", "password", "notes"),
        "chrome_passwords.csv",
        "Drops 2FA (OTPAuth). Import at passwords.google.com > Settings.",
    ),
    "firefox": Spec(
        "firefox", "Firefox (about:logins)", write_firefox,
        ("url", "username", "password"),
        "firefox_logins.csv",
        "Firefox stores no title/notes/2FA. about:logins > Import from a File.",
    ),
    "vault": Spec(
        "vault", "pwvault full backup (all fields)", write_vault,
        ("title", "url", "username", "password", "notes", "otpauth"),
        "pwvault_full_backup.csv",
        "Keeps everything including category and provenance. Recommended "
        "before shredding the import folder.",
    ),
}

WRITE_ORDER = ["apple", "chrome", "firefox", "vault"]
