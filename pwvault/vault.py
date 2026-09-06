"""
The pipeline: import folder -> merge -> select -> export -> verify -> shred.

The one rule that governs the whole module: **nothing in the import folder is
destroyed until an export file has been written, read back from disk, and
compared field-by-field against what was selected.** Verification is done on
the file as it now exists on disk, not on the in-memory data that produced it.
"""
from __future__ import annotations

import os
from collections import Counter
from dataclasses import dataclass, field

from . import categories, formats, shred as shred_mod, security
from .audit import AuditLog
from .model import Record, normalise_url, FIELDS

CSV_SUFFIXES = (".csv", ".txt", ".tsv")


# --------------------------------------------------------------------------
# results
# --------------------------------------------------------------------------

@dataclass
class ExportResult:
    format_key: str
    path: str = ""
    written: int = 0
    verified: bool = False
    lossless: bool = False
    dropped_fields: list = field(default_factory=list)
    missing: list = field(default_factory=list)   # selected but not in the file
    extra: list = field(default_factory=list)     # in the file but not selected
    error: str = ""

    @property
    def ok(self):
        return self.verified and not self.error

    def summary(self):
        if self.error:
            return "%s: FAILED - %s" % (self.format_key, self.error)
        state = "verified" if self.verified else "NOT VERIFIED"
        loss = "" if self.lossless else " (drops: %s)" % ", ".join(self.dropped_fields)
        return "%s -> %s | %d records | %s%s" % (
            self.format_key, os.path.basename(self.path), self.written, state, loss)


@dataclass
class ShredPlan:
    files: list = field(default_factory=list)
    total_bytes: int = 0
    exported: int = 0
    discarded: int = 0
    verified_formats: list = field(default_factory=list)
    has_lossless: bool = False
    blockers: list = field(default_factory=list)

    @property
    def allowed(self):
        return not self.blockers and bool(self.files)


# --------------------------------------------------------------------------
# vault
# --------------------------------------------------------------------------

class Vault:
    def __init__(self, import_dir="", export_dir="", log_echo=None):
        self.import_dir = os.path.abspath(import_dir) if import_dir else ""
        self.export_dir = os.path.abspath(export_dir) if export_dir else ""
        self.records = []
        self.file_infos = []
        self.load_errors = []
        self.exports = []          # ExportResult from this session
        self.audit = None
        self._log_echo = log_echo
        if self.export_dir:
            self._init_audit()

    # ------------------------------------------------------------ plumbing
    def _init_audit(self):
        try:
            os.makedirs(self.export_dir, exist_ok=True)
            security.lock_down_path(self.export_dir)
            self.audit = AuditLog(self.export_dir, echo=self._log_echo)
        except Exception as exc:
            self.load_errors.append("audit log unavailable: %s" % exc)

    def log(self, event, **fields):
        if self.audit:
            return self.audit.write(event, **fields)
        if self._log_echo:
            self._log_echo("%s %s" % (event, fields))
        return ""

    def set_dirs(self, import_dir, export_dir):
        self.import_dir = os.path.abspath(import_dir) if import_dir else ""
        self.export_dir = os.path.abspath(export_dir) if export_dir else ""
        self._init_audit()

    # -------------------------------------------------------------- checks
    def directory_warnings(self):
        warns = []
        for name, path in (("import", self.import_dir), ("export", self.export_dir)):
            if not path:
                continue
            msg = security.cloud_sync_warning(path)
            if msg:
                warns.append("%s folder: %s" % (name, msg))
        if self.import_dir and self.export_dir:
            imp = os.path.normcase(self.import_dir)
            exp = os.path.normcase(self.export_dir)
            if exp == imp:
                warns.append("Export folder must be different from the import "
                             "folder - shredding would destroy your export.")
            elif exp.startswith(imp + os.sep):
                warns.append("Export folder is INSIDE the import folder - "
                             "shredding would destroy your export.")
        return warns

    # -------------------------------------------------------------- import
    def discover(self, directory=None):
        directory = directory or self.import_dir
        if not directory or not os.path.isdir(directory):
            return []
        found = []
        for name in sorted(os.listdir(directory)):
            path = os.path.join(directory, name)
            if not os.path.isfile(path):
                continue
            if name.lower().endswith(CSV_SUFFIXES) and not name.startswith("."):
                found.append(path)
        return found

    def scan(self, directory=None, keep_conflict_variants=False):
        """Load every CSV in the import folder and merge duplicates."""
        directory = directory or self.import_dir
        self.records = []
        self.file_infos = []
        self.load_errors = []

        raw = []
        for path in self.discover(directory):
            try:
                recs, info = formats.read_csv(path)
            except Exception as exc:
                self.load_errors.append("%s: %s" % (os.path.basename(path), exc))
                self.log("import.error", file=os.path.basename(path), error=str(exc))
                continue
            raw.extend(recs)
            self.file_infos.append(info)
            self.log("import.file", file=os.path.basename(path),
                     format=info["format"], encoding=info["encoding"],
                     rows=info["rows"], parsed=info["parsed"])

        merged, stats = merge_records(raw, keep_conflict_variants)
        categories.apply_categories(merged)
        for rec in merged:
            security.register_secret(rec.password)
        self.records = merged
        self.log("import.done", files=len(self.file_infos), raw=len(raw),
                 unique=len(merged), conflicts=stats["conflicts"],
                 incomplete=stats["incomplete"])
        return stats

    # ---------------------------------------------------------- selections
    def selected_for_export(self):
        return [r for r in self.records if r.selected_export]

    def selected_for_print(self):
        return [r for r in self.records if r.selected_print]

    def stats(self):
        by_cat = Counter(r.category for r in self.records)
        return {
            "total": len(self.records),
            "export_selected": sum(1 for r in self.records if r.selected_export),
            "print_selected": sum(1 for r in self.records if r.selected_print),
            "conflicts": sum(1 for r in self.records if r.conflict),
            "incomplete": sum(1 for r in self.records if r.incomplete),
            "categories": dict(by_cat),
            "source_files": len(self.file_infos),
        }

    # -------------------------------------------------------------- export
    def export(self, format_keys, directory=None, prefix=""):
        """Write one file per requested format and verify each of them."""
        directory = directory or self.export_dir
        if not directory:
            raise ValueError("no export folder set")
        os.makedirs(directory, exist_ok=True)
        security.lock_down_path(directory)

        selected = self.selected_for_export()
        results = []
        for key in format_keys:
            spec = formats.WRITE_FORMATS.get(key)
            res = ExportResult(format_key=key)
            if spec is None:
                res.error = "unknown format"
                results.append(res)
                continue
            if not selected:
                res.error = "nothing selected for export"
                results.append(res)
                continue
            res.lossless = spec.lossless
            res.dropped_fields = list(spec.lossy_fields)
            path = os.path.join(directory, (prefix + spec.filename) if prefix
                                else spec.filename)
            try:
                spec.writer(path, selected)
                security.lock_down_path(path)
                res.path = path
                res.written = len(selected)
                verify_export(res, spec, selected)
            except Exception as exc:
                res.error = "%s: %s" % (type(exc).__name__, exc)
            results.append(res)
            self.log("export", format=key, file=os.path.basename(res.path or "-"),
                     records=res.written, verified=res.verified,
                     lossless=res.lossless, error=res.error or "-",
                     missing=len(res.missing), extra=len(res.extra))

        self.exports = [r for r in results]
        return results

    # -------------------------------------------------------------- shred
    def plan_shred(self):
        plan = ShredPlan()
        plan.files = [i["path"] for i in self.file_infos
                      if os.path.isfile(i["path"])]
        plan.total_bytes = sum(os.path.getsize(p) for p in plan.files)
        plan.exported = sum(1 for r in self.records if r.selected_export)
        plan.discarded = len(self.records) - plan.exported

        good = [e for e in self.exports if e.ok]
        plan.verified_formats = [e.format_key for e in good]
        plan.has_lossless = any(e.lossless for e in good)

        if not plan.files:
            plan.blockers.append("No source files loaded in this session.")
        if not good:
            plan.blockers.append(
                "No verified export in this session. Export and let "
                "verification pass first.")
        elif not plan.has_lossless:
            plan.blockers.append(
                "Only lossy exports were verified (%s). Add the Apple or "
                "pwvault-backup format so no field is lost, or accept the loss "
                "explicitly." % ", ".join(plan.verified_formats))
        for exp in good:
            exp_dir = os.path.normcase(os.path.dirname(os.path.abspath(exp.path)))
            for src in plan.files:
                src_dir = os.path.normcase(os.path.dirname(os.path.abspath(src)))
                if exp_dir == src_dir:
                    plan.blockers.append(
                        "Export file %s sits in the import folder - it would be "
                        "shredded too. Choose a different export folder."
                        % os.path.basename(exp.path))
                    break
        plan.blockers = list(dict.fromkeys(plan.blockers))
        return plan

    def shred_sources(self, plan=None, force=False, passes=3):
        """
        Destroy the source files. `force=True` overrides the soft blockers
        (lossy-only export, discarded records) but never the hard ones
        (no verified export at all, export inside the import folder).
        """
        plan = plan or self.plan_shred()
        hard = [b for b in plan.blockers
                if b.startswith("No verified export")
                or "would be shredded too" in b
                or b.startswith("No source files")]
        if hard:
            raise PermissionError("shred refused: " + " ".join(hard))
        if plan.blockers and not force:
            raise PermissionError("shred refused: " + " ".join(plan.blockers))

        results = shred_mod.shred_paths(plan.files, passes=passes)
        for res in results:
            self.log("shred", file=os.path.basename(res.path), bytes=res.size,
                     passes=res.passes, ok=res.ok, error=res.error or "-")
        self.file_infos = [i for i in self.file_infos
                           if os.path.isfile(i["path"])]
        self.log("shred.done", requested=len(results),
                 succeeded=sum(1 for r in results if r.ok),
                 discarded_records=plan.discarded)
        return results

    def clear_memory(self):
        """Drop every reference to plaintext we hold."""
        passwords = [r.password for r in self.records]
        for rec in self.records:
            rec.password = ""
            rec.otpauth = ""
        shred_mod.wipe_string_list(passwords)
        self.records = []
        security.forget_secrets()
        self.log("session.cleared")


# --------------------------------------------------------------------------
# merging
# --------------------------------------------------------------------------

def merge_records(records, keep_conflict_variants=False):
    """
    Collapse duplicates coming from several browsers.

    Identity = (host without www, lowercased username). When the same identity
    carries different passwords we either keep the longest one and flag the
    record, or - with `keep_conflict_variants` - keep every variant as its own
    row so nothing is silently thrown away.
    """
    groups = {}
    for rec in records:
        groups.setdefault(rec.group_key, []).append(rec)

    merged = []
    conflicts = 0
    for _key, group in groups.items():
        distinct = {}
        for rec in group:
            distinct.setdefault(rec.password, []).append(rec)

        if len(distinct) > 1:
            conflicts += 1
            if keep_conflict_variants:
                for _pw, variants in distinct.items():
                    out = _fuse(variants)
                    out.conflict = True
                    merged.append(out)
                continue
            best_pw = max(distinct, key=lambda p: (len(p), p))
            out = _fuse(distinct[best_pw])
            out.conflict = True
            out.merged_from = [
                {"source": os.path.basename(r.source_file),
                 "format": r.source_format,
                 "password_len": len(r.password)}
                for pw, rs in distinct.items() if pw != best_pw for r in rs
            ]
            merged.append(out)
        else:
            merged.append(_fuse(group))

    incomplete = 0
    for rec in merged:
        if not rec.password or not (rec.url or rec.username):
            rec.incomplete = True
            incomplete += 1

    merged.sort(key=lambda r: (r.display_title.lower(), r.username.lower()))
    return merged, {"input": len(records), "unique": len(merged),
                    "conflicts": conflicts, "incomplete": incomplete}


def _fuse(group):
    """Combine identical-password duplicates, preferring the richest fields."""
    base = max(group, key=lambda r: sum(bool(getattr(r, f)) for f in FIELDS))
    out = Record(
        title=_first(group, "title") or base.title,
        url=_longest(group, "url"),
        username=base.username,
        password=base.password,
        notes="; ".join(sorted({r.notes for r in group if r.notes})),
        otpauth=_first(group, "otpauth"),
        source_file=base.source_file,
        source_format=", ".join(sorted({r.source_format for r in group})),
    )
    out.merged_from = [{"source": os.path.basename(r.source_file),
                        "format": r.source_format} for r in group]
    return out


def _first(group, field_name):
    for rec in group:
        value = getattr(rec, field_name)
        if value:
            return value
    return ""


def _longest(group, field_name):
    return max((getattr(r, field_name) for r in group), key=len, default="")


# --------------------------------------------------------------------------
# verification
# --------------------------------------------------------------------------

def _key_for(spec, rec, from_file):
    """
    Comparable tuple over the fields this format actually carries.
    URLs are compared by host because Firefox's writer must add a scheme.
    """
    values = []
    for field_name in spec.carried:
        value = getattr(rec, field_name, "").strip()
        if field_name == "url":
            value = normalise_url(value)
        elif field_name == "title" and not from_file and spec.key == "chrome":
            value = rec.display_title.strip()
        values.append(value)
    return tuple(values)


def verify_export(result, spec, selected):
    """
    Read the file back off disk and compare it with the selection.
    Sets result.verified / .missing / .extra / .error in place.
    """
    if not os.path.isfile(result.path):
        result.error = "export file not found after writing"
        return result
    try:
        reloaded, _info = formats.read_csv(result.path)
    except Exception as exc:
        result.error = "cannot re-read export: %s" % exc
        return result

    want = Counter(_key_for(spec, r, False) for r in selected)
    got = Counter(_key_for(spec, r, True) for r in reloaded)

    missing = want - got
    extra = got - want
    result.missing = [_redact(k, spec) for k in missing.elements()]
    result.extra = [_redact(k, spec) for k in extra.elements()]
    result.verified = not missing and not extra
    if not result.verified and not result.error:
        result.error = "verification mismatch: %d missing, %d unexpected" % (
            len(result.missing), len(result.extra))
    return result


def _redact(key_tuple, spec):
    """Turn a comparison key into something safe to show or log."""
    out = {}
    for name, value in zip(spec.carried, key_tuple):
        out[name] = "<%d chars>" % len(value) if name in ("password", "otpauth") \
            else value
    return out
