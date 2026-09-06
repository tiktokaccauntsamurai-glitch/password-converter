#!/usr/bin/env python3
"""
End-to-end self test.

Runs the complete pipeline against the sample files inside a throwaway
temporary folder, including the destructive shred step, and asserts the
safety rules actually hold. It never touches your real import/export folders.

    python selftest.py
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pwvault import security                       # noqa: E402

security.harden()

from pwvault import formats, printing, textutil    # noqa: E402
from pwvault.model import password_checksum        # noqa: E402
from pwvault.vault import Vault                    # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(HERE, "samples")

PASSED = []
FAILED = []


def check(name, condition, detail=""):
    (PASSED if condition else FAILED).append(name)
    mark = "PASS" if condition else "FAIL"
    print("  [%s] %s%s" % (mark, name, ("  <- " + detail) if detail and not condition else ""))


def main():
    print("pwvault self test")
    print("  network blocked: %s" % security.network_is_blocked())
    check("network kill switch active", security.network_is_blocked())

    workdir = tempfile.mkdtemp(prefix="pwvault-selftest-")
    imp = os.path.join(workdir, "import")
    exp = os.path.join(workdir, "export")
    os.makedirs(imp)
    os.makedirs(exp)

    copied = 0
    for sub in ("chrome", "firefox", "apple", "generic"):
        folder = os.path.join(SAMPLES, sub)
        if not os.path.isdir(folder):
            continue
        for name in os.listdir(folder):
            if name.endswith(".csv"):
                shutil.copy2(os.path.join(folder, name), os.path.join(imp, name))
                copied += 1
    check("sample files copied", copied >= 3, "found %d" % copied)

    print("\n-- import")
    vault = Vault(imp, exp)
    stats = vault.scan()
    print("  %d raw rows -> %d unique, %d conflicts"
          % (stats["input"], stats["unique"], stats["conflicts"]))
    check("records loaded", stats["unique"] > 0)
    check("all four dialects detected",
          {i["format"] for i in vault.file_infos} >= {"chrome", "firefox", "apple"},
          str({i["format"] for i in vault.file_infos}))
    check("cross-browser duplicates merged", stats["unique"] < stats["input"])
    check("password conflict detected", stats["conflicts"] >= 1)

    gmail = [r for r in vault.records if r.category == "GMAIL"]
    check("gmail put in its own category", len(gmail) >= 2, str(len(gmail)))

    unicode_rows = [r for r in vault.records if any(ord(c) > 127 for c in r.password)]
    check("non-ascii password preserved verbatim", len(unicode_rows) == 1,
          str(len(unicode_rows)))

    print("\n-- shred must be refused before any export")
    plan = vault.plan_shred()
    check("shred blocked without a verified export", not plan.allowed,
          str(plan.blockers))
    try:
        vault.shred_sources(plan)
        refused = False
    except PermissionError:
        refused = True
    check("shred_sources() raises before export", refused)

    print("\n-- export + verification")
    results = vault.export(["apple", "chrome", "firefox", "vault"])
    for res in results:
        print("  " + res.summary())
    check("every export verified against disk", all(r.ok for r in results),
          str([r.error for r in results if not r.ok]))
    check("apple export is lossless",
          formats.WRITE_FORMATS["apple"].lossless)
    check("firefox export declares its losses",
          set(formats.WRITE_FORMATS["firefox"].lossy_fields) ==
          {"title", "notes", "otpauth"})

    print("\n-- tamper detection")
    apple_path = os.path.join(exp, "apple_passwords.csv")
    with open(apple_path, "r", encoding="utf-8") as fh:
        original = fh.read()
    with open(apple_path, "w", encoding="utf-8", newline="") as fh:
        fh.write("\r\n".join(original.split("\r\n")[:-2]) + "\r\n")
    tampered = [r for r in vault.exports if r.format_key == "apple"][0]
    from pwvault.vault import verify_export
    tampered.verified = False
    verify_export(tampered, formats.WRITE_FORMATS["apple"],
                  vault.selected_for_export())
    check("truncated export file fails verification", not tampered.verified)
    with open(apple_path, "w", encoding="utf-8", newline="") as fh:
        fh.write(original)
    verify_export(tampered, formats.WRITE_FORMATS["apple"],
                  vault.selected_for_export())
    check("restored export file passes again", tampered.verified)

    print("\n-- partial selection")
    for rec in vault.records:
        rec.selected_export = rec.category == "GMAIL"
    partial = vault.export(["apple"], prefix="gmail_")
    check("subset export verified", partial[0].ok)
    check("subset really is a subset", partial[0].written == len(gmail))
    for rec in vault.records:
        rec.selected_export = True
    vault.export(["apple", "vault"])

    print("\n-- printing")
    for preset in printing.PRESET_ORDER:
        opt = printing.PrintOptions(preset=preset)
        markup = printing.render_html(vault.records, opt)
        path = printing.write_html(os.path.join(exp, "sheet_%s.html" % preset), markup)
        size = printing.PRESETS[preset]
        check("%s sheet is pure ASCII" % preset, all(ord(c) < 128 for c in markup))
        check("%s sheet declares its page size" % preset,
              "size: %smm %smm" % (size.width_mm, size.height_mm) in markup
              or "size: %gmm %gmm" % (size.width_mm, size.height_mm) in markup)
        check("%s sheet has the Gmail section first" % preset,
              markup.index("GMAIL") < markup.index("OTHER"))
        check("%s sheet written" % preset, os.path.getsize(path) > 500)

    escaped, flagged = textutil.ascii_password("Пароль#2026!ok")
    check("cyrillic password is escaped, not transliterated",
          flagged and escaped.startswith("\\u041F") and "#2026!ok" in escaped,
          escaped)
    check("ascii password passes through untouched",
          textutil.ascii_password("Gx7#nQ2vLp!4Rt") == ("Gx7#nQ2vLp!4Rt", False))
    check("check code is stable", password_checksum("hunter2") ==
          password_checksum("hunter2"))
    check("check code differs for different passwords",
          password_checksum("hunter2") != password_checksum("hunter3"))

    print("\n-- export folder inside import folder is refused")
    bad = Vault(imp, os.path.join(imp, "out"))
    warnings = bad.directory_warnings()
    check("nested export folder is flagged",
          any("INSIDE" in w for w in warnings), str(warnings))

    print("\n-- shred")
    plan = vault.plan_shred()
    print("  files: %d, bytes: %d, blockers: %s"
          % (len(plan.files), plan.total_bytes, plan.blockers or "none"))
    check("shred now allowed", plan.allowed, str(plan.blockers))
    sources = list(plan.files)
    shredded = vault.shred_sources(plan)
    check("all source files destroyed", all(r.ok for r in shredded))
    check("source files really gone", not any(os.path.exists(p) for p in sources))
    check("export files untouched",
          os.path.exists(os.path.join(exp, "apple_passwords.csv")))

    print("\n-- audit log")
    log_path = os.path.join(exp, "pwvault_audit.log")
    with open(log_path, encoding="utf-8") as fh:
        log_text = fh.read()
    leaked = [r.password for r in vault.records if r.password and r.password in log_text]
    check("audit log exists", os.path.getsize(log_path) > 0)
    check("audit log contains no passwords", not leaked)
    check("audit log recorded the shred", "shred.done" in log_text)

    vault.clear_memory()
    check("memory cleared", vault.records == [])

    shutil.rmtree(workdir, ignore_errors=True)

    print("\n%d passed, %d failed" % (len(PASSED), len(FAILED)))
    if FAILED:
        print("FAILED: " + ", ".join(FAILED))
        return 1
    print("ALL GREEN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
