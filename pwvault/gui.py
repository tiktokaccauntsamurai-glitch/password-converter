"""
Tkinter desktop UI. Standard library only, so it runs on Windows and macOS
with a stock Python and no installer.

Two independent tick columns, as required:
    EXP - goes into the export files (and therefore survives the shred)
    PRN - goes onto the printed sheet
You can print a subset of what you migrate, or migrate a subset of what you
print; they never affect each other.
"""
from __future__ import annotations

import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from . import categories, formats, printing, security
from .model import password_checksum
from .vault import Vault

TICK_ON = "[x]"
TICK_OFF = "[ ]"
MASK = "*" * 10

COLUMNS = [
    ("exp", "EXP", 44, "center"),
    ("prn", "PRN", 44, "center"),
    ("cat", "Category", 92, "w"),
    ("title", "Site", 190, "w"),
    ("user", "Username", 200, "w"),
    ("pw", "Password", 190, "w"),
    ("chk", "Chk", 40, "center"),
    ("src", "Source", 130, "w"),
    ("flag", "!", 34, "center"),
]


class App(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=6)
        self.master = master
        self.grid(row=0, column=0, sticky="nsew")
        master.rowconfigure(0, weight=1)
        master.columnconfigure(0, weight=1)

        root = os.getcwd()
        if getattr(sys, "frozen", False):
            # a bundled app (.app from Finder) starts with cwd "/", so keep
            # the working folders in the home dir - not in iCloud-synced
            # ~/Documents or ~/Desktop
            root = os.path.join(os.path.expanduser("~"), "pwvault")
            os.makedirs(os.path.join(root, "import"), mode=0o700, exist_ok=True)
        self.var_import = tk.StringVar(value=os.path.join(root, "import"))
        self.var_export = tk.StringVar(value=os.path.join(root, "export"))
        self.var_search = tk.StringVar()
        self.var_reveal = tk.BooleanVar(value=False)
        self.var_keep_conflicts = tk.BooleanVar(value=False)
        self.var_status = tk.StringVar(value="Ready. Choose folders, then Scan.")
        self.var_autolock = tk.IntVar(value=10)

        self.vault = Vault(self.var_import.get(), self.var_export.get(),
                           log_echo=self._log_line)
        self.rows = {}          # tree iid -> Record
        self.sort_state = ("title", False)
        self._lock_job = None

        self._build()
        self._reset_autolock()
        self._refresh_warnings()

    # ================================================================ layout
    def _build(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        self._build_toolbar()
        self._build_warnings()
        self._build_middle()
        self._build_tabs()
        self._build_statusbar()

        self.master.bind_all("<Key>", self._activity, add="+")
        self.master.bind_all("<Button>", self._activity, add="+")

    def _build_toolbar(self):
        bar = ttk.LabelFrame(self, text="Folders", padding=6)
        bar.grid(row=0, column=0, sticky="ew")
        bar.columnconfigure(1, weight=1)

        ttk.Label(bar, text="Import from:").grid(row=0, column=0, sticky="w")
        ttk.Entry(bar, textvariable=self.var_import).grid(
            row=0, column=1, sticky="ew", padx=4)
        ttk.Button(bar, text="Browse...", width=11,
                   command=self._pick_import).grid(row=0, column=2)
        ttk.Button(bar, text="Open", width=7,
                   command=lambda: self._reveal_folder(self.var_import.get())
                   ).grid(row=0, column=3, padx=(4, 0))

        ttk.Label(bar, text="Export to:").grid(row=1, column=0, sticky="w", pady=(4, 0))
        ttk.Entry(bar, textvariable=self.var_export).grid(
            row=1, column=1, sticky="ew", padx=4, pady=(4, 0))
        ttk.Button(bar, text="Browse...", width=11,
                   command=self._pick_export).grid(row=1, column=2, pady=(4, 0))
        ttk.Button(bar, text="Open", width=7,
                   command=lambda: self._reveal_folder(self.var_export.get())
                   ).grid(row=1, column=3, padx=(4, 0), pady=(4, 0))

        actions = ttk.Frame(bar)
        actions.grid(row=2, column=0, columnspan=4, sticky="w", pady=(6, 0))
        ttk.Button(actions, text="Scan import folder",
                   command=self.scan).pack(side="left")
        ttk.Checkbutton(actions, text="keep every variant of conflicting passwords",
                        variable=self.var_keep_conflicts).pack(side="left", padx=8)
        ttk.Button(actions, text="Clear session (wipe memory)",
                   command=self.clear_session).pack(side="left", padx=4)

    def _build_warnings(self):
        self.warn_frame = ttk.Frame(self)
        self.warn_frame.grid(row=1, column=0, sticky="ew", pady=(4, 0))
        self.warn_frame.columnconfigure(0, weight=1)
        self.warn_label = tk.Label(self.warn_frame, text="", anchor="w",
                                   justify="left", bg="#ffe9a8", fg="#4a3600",
                                   padx=8, pady=4, wraplength=1000)

    def _build_middle(self):
        pane = ttk.Panedwindow(self, orient="horizontal")
        pane.grid(row=2, column=0, sticky="nsew", pady=6)

        # ---- left: filters
        left = ttk.Frame(pane, padding=(0, 0, 6, 0))
        left.rowconfigure(3, weight=1)
        ttk.Label(left, text="Search").grid(row=0, column=0, sticky="w")
        entry = ttk.Entry(left, textvariable=self.var_search, width=26)
        entry.grid(row=1, column=0, sticky="ew", pady=(0, 6))
        entry.bind("<KeyRelease>", lambda _e: self.refresh_tree())

        ttk.Label(left, text="Categories (click to filter)").grid(
            row=2, column=0, sticky="w")
        self.cat_list = tk.Listbox(left, selectmode="extended", height=14, width=32,
                                   exportselection=False, activestyle="none")
        self.cat_list.grid(row=3, column=0, sticky="nsew")
        self.cat_list.bind("<<ListboxSelect>>", lambda _e: self.refresh_tree())
        ttk.Button(left, text="Show all categories",
                   command=self._clear_cat_filter).grid(row=4, column=0,
                                                        sticky="ew", pady=(4, 8))

        for label, column in (("EXPORT ticks", "exp"), ("PRINT ticks", "prn")):
            box = ttk.LabelFrame(left, text=label, padding=4)
            box.grid(row=5 if column == "exp" else 6, column=0,
                     sticky="ew", pady=(0, 6))
            box.columnconfigure((0, 1, 2), weight=1)
            ttk.Button(box, text="All", width=6,
                       command=lambda c=column: self._bulk(c, True)).grid(row=0, column=0)
            ttk.Button(box, text="None", width=6,
                       command=lambda c=column: self._bulk(c, False)).grid(row=0, column=1)
            ttk.Button(box, text="Invert", width=6,
                       command=lambda c=column: self._bulk(c, None)).grid(row=0, column=2)
            ttk.Label(box, text="applies to visible rows",
                      font=("TkDefaultFont", 8)).grid(row=1, column=0, columnspan=3,
                                                      sticky="w", pady=(2, 0))
        pane.add(left, weight=0)

        # ---- right: table
        right = ttk.Frame(pane)
        right.rowconfigure(1, weight=1)
        right.columnconfigure(0, weight=1)

        top = ttk.Frame(right)
        top.grid(row=0, column=0, sticky="ew", pady=(0, 4))
        ttk.Checkbutton(top, text="Show passwords", variable=self.var_reveal,
                        command=self.refresh_tree).pack(side="left")
        ttk.Label(top, text="   Click EXP / PRN to tick.  Space = export tick, "
                            "Shift+Space = print tick.").pack(side="left")

        self.tree = ttk.Treeview(right, columns=[c[0] for c in COLUMNS],
                                 show="headings", selectmode="extended")
        for key, heading, width, anchor in COLUMNS:
            self.tree.heading(key, text=heading,
                              command=lambda k=key: self._sort_by(k))
            self.tree.column(key, width=width, anchor=anchor,
                             stretch=key in ("title", "user", "pw", "src"))
        self.tree.grid(row=1, column=0, sticky="nsew")
        self.tree.tag_configure("conflict", background="#fff2cc")
        self.tree.tag_configure("incomplete", background="#ffe0e0")

        vsb = ttk.Scrollbar(right, orient="vertical", command=self.tree.yview)
        vsb.grid(row=1, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=vsb.set)

        self.tree.bind("<Button-1>", self._on_click)
        self.tree.bind("<space>", lambda _e: self._toggle_selected("exp"))
        self.tree.bind("<Shift-space>", lambda _e: self._toggle_selected("prn"))
        pane.add(right, weight=1)

    def _build_tabs(self):
        nb = ttk.Notebook(self)
        nb.grid(row=3, column=0, sticky="ew")
        self._tab_export(nb)
        self._tab_print(nb)
        self._tab_shred(nb)
        self._tab_log(nb)
        self._tab_security(nb)

    # ------------------------------------------------------------ export tab
    def _tab_export(self, nb):
        tab = ttk.Frame(nb, padding=8)
        nb.add(tab, text="1. Export")
        tab.columnconfigure(1, weight=1)

        box = ttk.LabelFrame(tab, text="Write these formats", padding=6)
        box.grid(row=0, column=0, sticky="nw")
        self.fmt_vars = {}
        for i, key in enumerate(formats.WRITE_ORDER):
            spec = formats.WRITE_FORMATS[key]
            var = tk.BooleanVar(value=key in ("apple", "vault"))
            self.fmt_vars[key] = var
            ttk.Checkbutton(box, text=spec.label, variable=var).grid(
                row=i, column=0, sticky="w")
            ttk.Label(box, text=spec.note, font=("TkDefaultFont", 8),
                      foreground="#555").grid(row=i, column=1, sticky="w", padx=(8, 0))

        side = ttk.Frame(tab)
        side.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        side.columnconfigure(0, weight=1)
        side.rowconfigure(1, weight=1)
        ttk.Button(side, text="Export selected  ->  verify against disk",
                   command=self.do_export).grid(row=0, column=0, sticky="ew")
        self.export_out = tk.Text(side, height=7, wrap="word")
        self.export_out.grid(row=1, column=0, sticky="nsew", pady=(6, 0))
        self.export_out.configure(state="disabled")

    # ------------------------------------------------------------- print tab
    def _tab_print(self, nb):
        tab = ttk.Frame(nb, padding=8)
        nb.add(tab, text="2. Print")
        tab.columnconfigure(2, weight=1)

        self.var_preset = tk.StringVar(value="a4")
        paper = ttk.LabelFrame(tab, text="Paper", padding=6)
        paper.grid(row=0, column=0, sticky="nw")
        for i, key in enumerate(printing.PRESET_ORDER):
            ttk.Radiobutton(paper, text=printing.PRESETS[key].label,
                            value=key, variable=self.var_preset).grid(
                row=i, column=0, sticky="w")

        self.print_opts = {
            "show_checksum": tk.BooleanVar(value=True),
            "show_url": tk.BooleanVar(value=True),
            "show_notes": tk.BooleanVar(value=False),
            "group_password": tk.BooleanVar(value=False),
            "page_break_per_category": tk.BooleanVar(value=False),
            "show_legend": tk.BooleanVar(value=True),
            "fold_marks": tk.BooleanVar(value=False),
        }
        labels = {
            "show_checksum": "2-char typo check code",
            "show_url": "show URL",
            "show_notes": "show notes",
            "group_password": "group password in 4s (visual only)",
            "page_break_per_category": "new page per category",
            "show_legend": "reading guide",
            "fold_marks": "cut line at the bottom",
        }
        opts = ttk.LabelFrame(tab, text="Options", padding=6)
        opts.grid(row=0, column=1, sticky="nw", padx=(10, 0))
        for i, (key, var) in enumerate(self.print_opts.items()):
            ttk.Checkbutton(opts, text=labels[key], variable=var).grid(
                row=i, column=0, sticky="w")

        right = ttk.Frame(tab)
        right.grid(row=0, column=2, sticky="nsew", padx=(10, 0))
        right.columnconfigure(1, weight=1)
        right.rowconfigure(3, weight=1)

        ttk.Label(right, text="Sheet title").grid(row=0, column=0, sticky="w")
        self.var_sheet_title = tk.StringVar(value="Password sheet")
        ttk.Entry(right, textvariable=self.var_sheet_title).grid(
            row=0, column=1, sticky="ew", padx=(6, 0))

        ttk.Label(right, text="Font scale").grid(row=1, column=0, sticky="w", pady=(4, 0))
        self.var_scale = tk.DoubleVar(value=1.0)
        ttk.Spinbox(right, from_=0.7, to=1.6, increment=0.05, width=6,
                    textvariable=self.var_scale).grid(row=1, column=1, sticky="w",
                                                      padx=(6, 0), pady=(4, 0))

        buttons = ttk.Frame(right)
        buttons.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        ttk.Button(buttons, text="Build sheet",
                   command=self.do_print).pack(side="left")
        ttk.Button(buttons, text="Open in browser (Ctrl+P)",
                   command=self.open_sheet).pack(side="left", padx=4)
        ttk.Button(buttons, text="Save exact-size PDF",
                   command=self.do_pdf).pack(side="left")

        self.print_out = tk.Text(right, height=5, wrap="word")
        self.print_out.grid(row=3, column=0, columnspan=2, sticky="nsew", pady=(6, 0))
        self.print_out.configure(state="disabled")
        self.sheet_path = ""

    # ------------------------------------------------------------- shred tab
    def _tab_shred(self, nb):
        tab = ttk.Frame(nb, padding=8)
        nb.add(tab, text="3. Shred import")
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)

        head = ttk.Frame(tab)
        head.grid(row=0, column=0, sticky="ew")
        ttk.Button(head, text="Check what would be destroyed",
                   command=self.refresh_shred_plan).pack(side="left")
        self.var_shred_ack = tk.BooleanVar(value=False)
        ttk.Checkbutton(head, text="I have a verified export and accept the loss",
                        variable=self.var_shred_ack).pack(side="left", padx=10)
        ttk.Label(head, text="type SHRED:").pack(side="left")
        self.var_shred_word = tk.StringVar()
        ttk.Entry(head, textvariable=self.var_shred_word, width=10).pack(side="left", padx=4)
        ttk.Button(head, text="Destroy source files",
                   command=self.do_shred).pack(side="left")

        self.shred_out = tk.Text(tab, height=8, wrap="word")
        self.shred_out.grid(row=1, column=0, sticky="nsew", pady=(6, 0))
        self.shred_out.configure(state="disabled")

    # --------------------------------------------------------------- log tab
    def _tab_log(self, nb):
        tab = ttk.Frame(nb, padding=8)
        nb.add(tab, text="Log")
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(0, weight=1)
        self.log_out = tk.Text(tab, height=9, wrap="none")
        self.log_out.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(tab, orient="vertical", command=self.log_out.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.log_out.configure(yscrollcommand=scroll.set, state="disabled")

    # ---------------------------------------------------------- security tab
    def _tab_security(self, nb):
        tab = ttk.Frame(nb, padding=8)
        nb.add(tab, text="Security")
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)

        row = ttk.Frame(tab)
        row.grid(row=0, column=0, sticky="ew")
        ttk.Label(row, text="Auto-clear memory after").pack(side="left")
        ttk.Spinbox(row, from_=1, to=120, width=5, textvariable=self.var_autolock,
                    command=self._reset_autolock).pack(side="left", padx=4)
        ttk.Label(row, text="minutes of inactivity").pack(side="left")

        text = tk.Text(tab, height=11, wrap="word")
        text.grid(row=1, column=0, sticky="nsew", pady=(6, 0))
        env = security.environment_report()
        lines = ["Environment"]
        for key, value in env.items():
            lines.append("   %-22s %s" % (key, value))
        lines.append("")
        lines.append("What this program does NOT protect you from:")
        for risk in security.unmitigated_risks():
            lines.append("   - " + risk)
        text.insert("1.0", "\n".join(lines))
        text.configure(state="disabled")

    def _build_statusbar(self):
        bar = ttk.Frame(self)
        bar.grid(row=4, column=0, sticky="ew", pady=(4, 0))
        bar.columnconfigure(0, weight=1)
        ttk.Label(bar, textvariable=self.var_status, anchor="w").grid(
            row=0, column=0, sticky="ew")

    # ============================================================== helpers
    def _log_line(self, line):
        try:
            self.log_out.configure(state="normal")
            self.log_out.insert("end", line + "\n")
            self.log_out.see("end")
            self.log_out.configure(state="disabled")
        except Exception:
            pass

    @staticmethod
    def _set_text(widget, content):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", content)
        widget.configure(state="disabled")

    def _status(self, message):
        self.var_status.set(message)
        self.update_idletasks()

    def _pick_import(self):
        path = filedialog.askdirectory(title="Folder holding the browser CSV exports",
                                       initialdir=self.var_import.get() or os.getcwd())
        if path:
            self.var_import.set(path)
            self._refresh_warnings()

    def _pick_export(self):
        path = filedialog.askdirectory(title="Folder to write the results into",
                                       initialdir=self.var_export.get() or os.getcwd())
        if path:
            self.var_export.set(path)
            self._refresh_warnings()

    def _reveal_folder(self, path):
        if not path:
            return
        os.makedirs(path, exist_ok=True)
        try:
            if sys.platform == "darwin":
                import subprocess
                subprocess.Popen(["open", path])
            elif os.name == "nt":
                os.startfile(path)          # noqa: S606 - local folder only
            else:
                import subprocess
                subprocess.Popen(["xdg-open", path])
        except Exception as exc:
            messagebox.showerror("Cannot open folder", str(exc))

    def _refresh_warnings(self):
        self.vault.set_dirs(self.var_import.get(), self.var_export.get())
        warnings = self.vault.directory_warnings()
        if warnings:
            self.warn_label.configure(text="\n".join("! " + w for w in warnings))
            self.warn_label.grid(row=0, column=0, sticky="ew")
        else:
            self.warn_label.grid_forget()

    # ------------------------------------------------------------- autolock
    def _activity(self, _event=None):
        self._reset_autolock()

    def _reset_autolock(self):
        if self._lock_job is not None:
            try:
                self.after_cancel(self._lock_job)
            except Exception:
                pass
        minutes = max(1, int(self.var_autolock.get() or 10))
        self._lock_job = self.after(minutes * 60_000, self._autolock)

    def _autolock(self):
        if not self.vault.records:
            self._reset_autolock()
            return
        self.clear_session(silent=True)
        self._status("Session auto-cleared after inactivity. Scan again to reload.")
        messagebox.showinfo("Auto-cleared",
                            "No activity for %d minutes, so the loaded passwords "
                            "were dropped from memory.\n\nThe files on disk are "
                            "untouched - press Scan to reload."
                            % int(self.var_autolock.get()))

    # ================================================================ actions
    def scan(self):
        self._refresh_warnings()
        import_dir = self.var_import.get()
        if not os.path.isdir(import_dir):
            messagebox.showerror("No such folder", import_dir)
            return
        self._status("Scanning %s ..." % import_dir)
        stats = self.vault.scan(keep_conflict_variants=self.var_keep_conflicts.get())
        if self.vault.load_errors:
            messagebox.showwarning("Some files could not be read",
                                   "\n".join(self.vault.load_errors))
        self._refresh_categories()
        self.refresh_tree()
        self._status(
            "%d file(s) -> %d rows -> %d unique entries | %d conflict(s), "
            "%d incomplete"
            % (len(self.vault.file_infos), stats["input"], stats["unique"],
               stats["conflicts"], stats["incomplete"]))
        if not self.vault.records:
            messagebox.showinfo(
                "Nothing found",
                "No password rows in %s.\n\nDrop your Chrome / Firefox / Apple "
                "CSV exports there, or copy the files from the samples folder "
                "to try it out." % import_dir)

    def clear_session(self, silent=False):
        self.vault.clear_memory()
        self.rows.clear()
        self.tree.delete(*self.tree.get_children())
        self.cat_list.delete(0, "end")
        self._set_text(self.export_out, "")
        self._set_text(self.shred_out, "")
        if not silent:
            self._status("Session cleared. Nothing is loaded.")

    def _refresh_categories(self):
        self.cat_list.delete(0, "end")
        counts = {}
        for rec in self.vault.records:
            counts[rec.category] = counts.get(rec.category, 0) + 1
        self._cat_keys = sorted(counts, key=categories.sort_key)
        for cat in self._cat_keys:
            self.cat_list.insert("end", "%-25s %3d" % (categories.label(cat),
                                                       counts[cat]))

    def _clear_cat_filter(self):
        self.cat_list.selection_clear(0, "end")
        self.refresh_tree()

    def _visible_records(self):
        needle = self.var_search.get().strip().lower()
        chosen = {self._cat_keys[i] for i in self.cat_list.curselection()} \
            if getattr(self, "_cat_keys", None) else set()
        out = []
        for rec in self.vault.records:
            if chosen and rec.category not in chosen:
                continue
            if needle:
                hay = " ".join((rec.title, rec.url, rec.username,
                                rec.notes, rec.category)).lower()
                if needle not in hay:
                    continue
            out.append(rec)
        return out

    def refresh_tree(self):
        self.tree.delete(*self.tree.get_children())
        self.rows.clear()
        key, reverse = self.sort_state
        getter = {
            "exp": lambda r: not r.selected_export,
            "prn": lambda r: not r.selected_print,
            "cat": lambda r: (categories.sort_key(r.category), r.display_title.lower()),
            "title": lambda r: r.display_title.lower(),
            "user": lambda r: r.username.lower(),
            "pw": lambda r: len(r.password),
            "chk": lambda r: password_checksum(r.password),
            "src": lambda r: r.source_format,
            "flag": lambda r: (not r.conflict, not r.incomplete),
        }.get(key, lambda r: r.display_title.lower())

        records = sorted(self._visible_records(), key=getter, reverse=reverse)
        reveal = self.var_reveal.get()
        for rec in records:
            tags = []
            if rec.conflict:
                tags.append("conflict")
            if rec.incomplete:
                tags.append("incomplete")
            flag = ("C" if rec.conflict else "") + ("?" if rec.incomplete else "")
            iid = self.tree.insert("", "end", values=(
                TICK_ON if rec.selected_export else TICK_OFF,
                TICK_ON if rec.selected_print else TICK_OFF,
                rec.category,
                rec.display_title,
                rec.username,
                rec.password if reveal else MASK,
                password_checksum(rec.password),
                rec.source_format,
                flag,
            ), tags=tags)
            self.rows[iid] = rec
        self._update_counts()

    def _update_counts(self):
        stats = self.vault.stats()
        self._status("%d entries | %d ticked for EXPORT | %d ticked for PRINT | "
                     "%d shown"
                     % (stats["total"], stats["export_selected"],
                        stats["print_selected"], len(self.rows)))

    def _sort_by(self, column):
        key, reverse = self.sort_state
        self.sort_state = (column, not reverse if key == column else False)
        self.refresh_tree()

    def _on_click(self, event):
        if self.tree.identify_region(event.x, event.y) != "cell":
            return
        column = self.tree.identify_column(event.x)
        index = int(column[1:]) - 1
        if index < 0 or index >= len(COLUMNS):
            return
        key = COLUMNS[index][0]
        if key not in ("exp", "prn"):
            return
        iid = self.tree.identify_row(event.y)
        rec = self.rows.get(iid)
        if rec is None:
            return
        self._flip(rec, key)
        self._redraw_row(iid, rec)
        self._update_counts()
        return "break"

    @staticmethod
    def _flip(rec, key, value=None):
        attr = "selected_export" if key == "exp" else "selected_print"
        setattr(rec, attr, (not getattr(rec, attr)) if value is None else value)

    def _redraw_row(self, iid, rec):
        self.tree.set(iid, "exp", TICK_ON if rec.selected_export else TICK_OFF)
        self.tree.set(iid, "prn", TICK_ON if rec.selected_print else TICK_OFF)

    def _toggle_selected(self, key):
        for iid in self.tree.selection():
            rec = self.rows.get(iid)
            if rec is not None:
                self._flip(rec, key)
                self._redraw_row(iid, rec)
        self._update_counts()
        return "break"

    def _bulk(self, key, value):
        for iid, rec in self.rows.items():
            self._flip(rec, key, value)
            self._redraw_row(iid, rec)
        self._update_counts()

    # ------------------------------------------------------------ export
    def do_export(self):
        keys = [k for k, v in self.fmt_vars.items() if v.get()]
        if not keys:
            messagebox.showinfo("Pick a format", "Tick at least one export format.")
            return
        if not self.vault.selected_for_export():
            messagebox.showinfo("Nothing ticked",
                                "No entry is ticked in the EXP column.")
            return
        self._refresh_warnings()
        self._status("Exporting and verifying...")
        try:
            results = self.vault.export(keys)
        except Exception as exc:
            messagebox.showerror("Export failed", str(exc))
            return

        lines = []
        for res in results:
            lines.append(res.summary())
            for row in res.missing[:5]:
                lines.append("      missing from file: %s" % row)
            for row in res.extra[:5]:
                lines.append("      unexpected in file: %s" % row)
        good = [r for r in results if r.ok]
        lines.append("")
        lines.append("%d of %d file(s) verified byte-for-byte against the "
                     "selection." % (len(good), len(results)))
        self._set_text(self.export_out, "\n".join(lines))
        self._status("Export finished: %d/%d verified." % (len(good), len(results)))
        self.refresh_shred_plan()

    # ------------------------------------------------------------- print
    def _print_options(self):
        opt = printing.PrintOptions(preset=self.var_preset.get())
        for key, var in self.print_opts.items():
            setattr(opt, key, bool(var.get()))
        opt.title = self.var_sheet_title.get() or "Password sheet"
        try:
            opt.font_scale = float(self.var_scale.get())
        except Exception:
            opt.font_scale = 1.0
        return opt

    def do_print(self):
        chosen = self.vault.selected_for_print()
        if not chosen:
            messagebox.showinfo("Nothing ticked",
                                "No entry is ticked in the PRN column.")
            return
        opt = self._print_options()
        markup = printing.render_html(chosen, opt)
        export_dir = self.var_export.get()
        os.makedirs(export_dir, exist_ok=True)
        path = os.path.join(export_dir, "print_%s.html" % opt.preset)
        printing.write_html(path, markup)
        security.lock_down_path(path)
        self.sheet_path = path
        self.vault.log("print.sheet", preset=opt.preset, records=len(chosen),
                       file=os.path.basename(path))
        preset = printing.PRESETS[opt.preset]
        self._set_text(self.print_out,
                       "Sheet written:\n  %s\n\n%d entries, %d categories, "
                       "page %g x %g mm.\n\nOpen it in the browser and press "
                       "Ctrl/Cmd+P. Set margins to 'Default' and scale to 100%%; "
                       "the page size is already baked into the file. For an "
                       "exact %g x %g mm page use 'Save exact-size PDF'."
                       % (path, len(chosen),
                          len(categories.group_by_category(chosen)),
                          preset.width_mm, preset.height_mm,
                          preset.width_mm, preset.height_mm))
        self._status("Print sheet built: %s" % os.path.basename(path))

    def open_sheet(self):
        if not self.sheet_path or not os.path.exists(self.sheet_path):
            self.do_print()
        if self.sheet_path:
            printing.open_in_browser(self.sheet_path)

    def do_pdf(self):
        if not self.sheet_path or not os.path.exists(self.sheet_path):
            self.do_print()
        if not self.sheet_path:
            return
        pdf_path = self.sheet_path[:-5] + ".pdf"
        self._status("Rendering PDF with headless Chromium...")
        ok, message = printing.html_to_pdf(self.sheet_path, pdf_path)
        self.vault.log("print.pdf", ok=ok, file=os.path.basename(pdf_path))
        self._set_text(self.print_out,
                       ("PDF written:\n  %s" % message) if ok
                       else ("PDF not created.\n%s" % message))
        self._status("PDF ready." if ok else "PDF failed.")

    # ------------------------------------------------------------- shred
    def refresh_shred_plan(self):
        plan = self.vault.plan_shred()
        lines = [
            "Files that would be destroyed: %d (%d bytes)"
            % (len(plan.files), plan.total_bytes),
        ]
        for path in plan.files:
            lines.append("    %s" % path)
        lines += [
            "",
            "Verified exports this session : %s"
            % (", ".join(plan.verified_formats) or "none"),
            "Entries carried into export   : %d" % plan.exported,
            "Entries NOT exported (lost)   : %d" % plan.discarded,
        ]
        if plan.blockers:
            lines.append("")
            lines.append("BLOCKERS:")
            for blocker in plan.blockers:
                lines.append("    - " + blocker)
        else:
            lines.append("")
            lines.append("No blockers. Tick the acknowledgement, type SHRED, "
                         "and the source files will be overwritten and deleted.")
        self._set_text(self.shred_out, "\n".join(lines))
        return plan

    def do_shred(self):
        plan = self.refresh_shred_plan()
        if not plan.files:
            messagebox.showinfo("Nothing to shred", "No source files are loaded.")
            return
        if self.var_shred_word.get().strip() != "SHRED":
            messagebox.showwarning("Confirmation missing",
                                   "Type SHRED in the box to confirm.")
            return
        if not self.var_shred_ack.get():
            messagebox.showwarning("Confirmation missing",
                                   "Tick the acknowledgement first.")
            return
        detail = ("%d file(s) will be overwritten and deleted.\n\n"
                  "%d entries were exported and verified.\n"
                  "%d entries were NOT exported and will be lost.\n\n"
                  "This cannot be undone. Continue?"
                  % (len(plan.files), plan.exported, plan.discarded))
        if not messagebox.askyesno("Destroy source files?", detail, icon="warning"):
            return
        try:
            results = self.vault.shred_sources(plan, force=True)
        except PermissionError as exc:
            messagebox.showerror("Refused", str(exc))
            return
        ok = sum(1 for r in results if r.ok)
        self._set_text(self.shred_out,
                       "\n".join(["%s" % r for r in results] +
                                 ["", "%d of %d file(s) destroyed." % (ok, len(results)),
                                  "",
                                  "Reminder: on an SSD this is best effort. "
                                  "Full-disk encryption is what actually protects "
                                  "already-deleted blocks."]))
        self.var_shred_word.set("")
        self.var_shred_ack.set(False)
        self._status("Shredded %d of %d source file(s)." % (ok, len(results)))


def main():
    root = tk.Tk()
    root.title("pwvault - offline password import / export / print")
    root.geometry("1180x780")
    root.minsize(940, 640)
    try:
        style = ttk.Style(root)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        elif "aqua" in style.theme_names():
            style.theme_use("aqua")
        style.configure("Treeview", rowheight=21)
    except Exception:
        pass
    app = App(root)

    def on_close():
        try:
            app.vault.clear_memory()
        finally:
            root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()
    return 0
