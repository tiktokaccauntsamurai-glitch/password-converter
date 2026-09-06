"""
Command line interface - the same pipeline as the GUI, for scripting and for
machines without Tk.

    python -m pwvault --cli --list
    python -m pwvault --cli --export apple,vault --print a6
    python -m pwvault --cli --export vault --shred        # destructive
"""
from __future__ import annotations

import argparse
import os
import sys

from . import categories, formats, printing, security
from .model import password_checksum
from .vault import Vault

DEFAULT_IMPORT = "import"
DEFAULT_EXPORT = "export"


def _echo(line):
    print("  " + line)


def build_parser():
    p = argparse.ArgumentParser(
        prog="pwvault --cli",
        description="Offline password import / export / print manager.")
    p.add_argument("--import-dir", default=DEFAULT_IMPORT,
                   help="folder scanned for browser CSV exports (default: ./import)")
    p.add_argument("--export-dir", default=DEFAULT_EXPORT,
                   help="folder written to (default: ./export)")
    p.add_argument("--list", action="store_true", help="list what was found and exit")
    p.add_argument("--only", default="",
                   help="comma-separated categories to keep (e.g. GMAIL,FINANCE)")
    p.add_argument("--exclude", default="",
                   help="comma-separated categories to drop")
    p.add_argument("--export", default="",
                   help="formats to write: %s" % ",".join(formats.WRITE_ORDER))
    p.add_argument("--print", dest="print_preset", default="",
                   help="build a print sheet: %s" % ",".join(printing.PRESET_ORDER))
    p.add_argument("--pdf", action="store_true",
                   help="also render the sheet to PDF with headless Chromium")
    p.add_argument("--no-checksum", action="store_true",
                   help="omit the 2-char transcription check code")
    p.add_argument("--page-break-per-category", action="store_true")
    p.add_argument("--keep-conflicts", action="store_true",
                   help="keep every variant of a conflicting password as its own row")
    p.add_argument("--shred", action="store_true",
                   help="DESTROY the source files after a verified export")
    p.add_argument("--force", action="store_true",
                   help="with --shred: accept lossy export / discarded records")
    p.add_argument("--yes", action="store_true", help="skip the interactive prompt")
    p.add_argument("--check", metavar="PASSWORD",
                   help="print the 2-char check code for a password and exit")
    return p


def _filter(records, only, exclude):
    keep_only = {c.strip().upper() for c in only.split(",") if c.strip()}
    drop = {c.strip().upper() for c in exclude.split(",") if c.strip()}
    for rec in records:
        wanted = True
        if keep_only and rec.category not in keep_only:
            wanted = False
        if rec.category in drop:
            wanted = False
        rec.selected_export = wanted
        rec.selected_print = wanted


def run(argv=None):
    args = build_parser().parse_args(argv)

    if args.check:
        print(password_checksum(args.check))
        return 0

    env = security.environment_report()
    print("pwvault - offline mode | python %s | %s | network blocked: %s"
          % (env["python"], env["platform"], env["network_blocked"]))

    vault = Vault(args.import_dir, args.export_dir, log_echo=_echo)
    for warning in vault.directory_warnings():
        print("WARNING: %s" % warning)

    if not os.path.isdir(vault.import_dir):
        print("Import folder does not exist: %s" % vault.import_dir)
        return 2

    stats = vault.scan(keep_conflict_variants=args.keep_conflicts)
    for err in vault.load_errors:
        print("ERROR: %s" % err)
    if not vault.records:
        print("No password records found in %s" % vault.import_dir)
        return 2

    print("\nLoaded %d rows from %d file(s) -> %d unique (%d conflicts, "
          "%d incomplete)" % (stats["input"], len(vault.file_infos),
                              stats["unique"], stats["conflicts"],
                              stats["incomplete"]))
    for info in vault.file_infos:
        print("  %-38s %-8s %-10s %d rows"
              % (os.path.basename(info["path"]), info["format"],
                 info["encoding"], info["parsed"]))

    _filter(vault.records, args.only, args.exclude)

    print("\nBy category:")
    for cat, label, items in categories.group_by_category(vault.records):
        chosen = sum(1 for r in items if r.selected_export)
        print("  %-24s %3d entries (%d selected)" % (label, len(items), chosen))

    if args.list:
        print("\nEntries (passwords hidden):")
        for rec in vault.records:
            print("  [%s] %-30s %-30s pw=%d chars chk=%s%s"
                  % ("x" if rec.selected_export else " ",
                     rec.display_title[:30], rec.username[:30],
                     len(rec.password), password_checksum(rec.password),
                     "  CONFLICT" if rec.conflict else ""))
        return 0

    exit_code = 0

    if args.export:
        keys = [k.strip() for k in args.export.split(",") if k.strip()]
        print("\nExporting %d record(s)..." % len(vault.selected_for_export()))
        for res in vault.export(keys):
            print("  " + res.summary())
            if res.missing or res.extra:
                for row in res.missing[:5]:
                    print("    missing: %s" % row)
                for row in res.extra[:5]:
                    print("    unexpected: %s" % row)
            if not res.ok:
                exit_code = 1

    if args.print_preset:
        opt = printing.PrintOptions(
            preset=args.print_preset,
            show_checksum=not args.no_checksum,
            page_break_per_category=args.page_break_per_category,
        )
        chosen = vault.selected_for_print()
        markup = printing.render_html(chosen, opt)
        os.makedirs(vault.export_dir, exist_ok=True)
        html_path = os.path.join(vault.export_dir,
                                 "print_%s.html" % args.print_preset)
        printing.write_html(html_path, markup)
        security.lock_down_path(html_path)
        vault.log("print.sheet", preset=args.print_preset, records=len(chosen),
                  file=os.path.basename(html_path))
        print("\nPrint sheet: %s  (%d entries)" % (html_path, len(chosen)))
        if args.pdf:
            pdf_path = html_path[:-5] + ".pdf"
            ok, msg = printing.html_to_pdf(html_path, pdf_path)
            print("  PDF: %s" % msg if ok else "  PDF failed: %s" % msg)

    if args.shred:
        plan = vault.plan_shred()
        print("\nShred plan: %d file(s), %d bytes"
              % (len(plan.files), plan.total_bytes))
        print("  verified exports : %s" % (", ".join(plan.verified_formats) or "none"))
        print("  records exported : %d" % plan.exported)
        print("  records DISCARDED: %d" % plan.discarded)
        for blocker in plan.blockers:
            print("  BLOCKER: %s" % blocker)
        if plan.blockers and not args.force:
            print("  -> refusing to shred. Fix the blockers or pass --force.")
            return 1
        if not args.yes:
            answer = input("  Type SHRED to destroy the source files: ").strip()
            if answer != "SHRED":
                print("  aborted.")
                return 1
        for res in vault.shred_sources(plan, force=args.force):
            print("  %s" % res)

    print("\nReminders:")
    for risk in security.unmitigated_risks():
        print("  - %s" % risk)
    return exit_code


def main(argv=None):
    try:
        return run(argv)
    except KeyboardInterrupt:
        print("\ninterrupted")
        return 130
    except PermissionError as exc:
        print("REFUSED: %s" % exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
