"""
Print sheet generation.

Output is a single self-contained HTML file with an exact `@page` size, so the
browser's print dialog is already set to the right paper. No external CSS, no
web fonts, no scripts - the file works with the machine offline and cannot
call anything home.

Paper presets
    a4        210 x 297 mm   dense reference sheet, 2 columns of data
    a6        105 x 148 mm   pocket card
    notebook   90 x 170 mm   the custom notebook page (9 cm wide, 17 cm tall)

Type sizes were chosen as "as small as still comfortably readable":
6.4-8.2 pt for labels, monospaced with slashed zeros for the secrets, which is
what actually decides legibility when you transcribe by hand.
"""
from __future__ import annotations

import html
import os
import shutil
import subprocess
import time
from dataclasses import dataclass

from . import categories
from .model import password_checksum, domain_of
from .security import open_private
from .textutil import to_ascii, ascii_password, group_chars, shorten, AMBIGUITY_LEGEND


@dataclass
class PagePreset:
    key: str
    label: str
    width_mm: float
    height_mm: float
    margin_mm: float
    base_pt: float          # label text
    mono_pt: float          # password text
    heading_pt: float
    layout: str             # "wide" (A4) or "narrow" (A6 / notebook)
    url_chars: int          # truncation budget for URLs
    title_chars: int
    user_chars: int


PRESETS = {
    "a4": PagePreset("a4", "A4  210 x 297 mm", 210, 297, 10,
                     7.8, 8.2, 10.5, "wide", 46, 34, 34),
    "a6": PagePreset("a6", "A6  105 x 148 mm", 105, 148, 6,
                     6.6, 7.0, 8.6, "narrow", 30, 26, 26),
    "notebook": PagePreset("notebook", "Notebook  90 x 170 mm (9 x 17 cm)",
                           90, 170, 5,
                           6.4, 6.9, 8.2, "narrow", 26, 24, 24),
}

PRESET_ORDER = ["a4", "a6", "notebook"]


@dataclass
class PrintOptions:
    preset: str = "a4"
    show_checksum: bool = True
    group_password: bool = False     # visual 4-char grouping
    show_url: bool = True
    show_notes: bool = False
    page_break_per_category: bool = False
    show_legend: bool = True
    show_totals: bool = True
    title: str = "Password sheet"
    font_scale: float = 1.0          # 0.8 .. 1.4 user zoom
    fold_marks: bool = False         # cut/fold guides for the notebook page


# --------------------------------------------------------------------------
# HTML
# --------------------------------------------------------------------------

MONO_STACK = ("'DejaVu Sans Mono','Menlo','Consolas','Liberation Mono',"
              "'Courier New',monospace")
SANS_STACK = ("'Helvetica Neue',Helvetica,Arial,'Liberation Sans',sans-serif")


def _esc(text):
    return html.escape(text, quote=True)


def _css(preset, opt):
    s = max(0.7, min(1.6, opt.font_scale))
    base = preset.base_pt * s
    mono = preset.mono_pt * s
    head = preset.heading_pt * s
    narrow = preset.layout == "narrow"
    return f"""
@page {{
  size: {preset.width_mm}mm {preset.height_mm}mm;
  margin: {preset.margin_mm}mm;
}}
* {{ box-sizing: border-box; }}
html, body {{
  margin: 0; padding: 0; background: #fff; color: #000;
  font-family: {SANS_STACK};
  font-size: {base:.2f}pt; line-height: 1.22;
  -webkit-print-color-adjust: exact; print-color-adjust: exact;
}}
.sheet {{ width: 100%; }}
h1.doc {{
  font-size: {head * 1.15:.2f}pt; margin: 0 0 1.5mm 0;
  letter-spacing: .3px; text-transform: uppercase;
}}
.meta {{ font-size: {base * 0.82:.2f}pt; color: #333; margin-bottom: 2mm; }}
.legend {{
  font-size: {base * 0.78:.2f}pt; color: #222; border: .3pt solid #999;
  padding: 1mm 1.5mm; margin: 0 0 2.5mm 0; border-radius: 1mm;
}}
h2.cat {{
  font-size: {head:.2f}pt; margin: 2.5mm 0 1mm 0; padding: .6mm 1.2mm;
  background: #000; color: #fff; letter-spacing: .4px;
  text-transform: uppercase; break-after: avoid; page-break-after: avoid;
}}
h2.cat .count {{ float: right; font-weight: normal; }}
table {{
  width: 100%; border-collapse: collapse; table-layout: fixed;
  margin-bottom: 1.5mm;
}}
thead {{ display: table-header-group; }}
th {{
  font-size: {base * 0.78:.2f}pt; text-align: left; text-transform: uppercase;
  letter-spacing: .3px; border-bottom: .5pt solid #000; padding: .5mm .8mm;
}}
td {{
  padding: .55mm .8mm; border-bottom: .3pt dotted #999;
  vertical-align: top; word-break: break-all; overflow-wrap: anywhere;
}}
tr {{ break-inside: avoid; page-break-inside: avoid; }}
tbody tr:nth-child(even) {{ background: #f2f2f2; }}
.idx {{ color: #555; font-size: {base * 0.8:.2f}pt; text-align: right; }}
.title {{ font-weight: 700; }}
.url {{ color: #333; font-size: {base * 0.85:.2f}pt; }}
.user {{ font-family: {MONO_STACK}; font-size: {mono * 0.95:.2f}pt; }}
.pw {{
  font-family: {MONO_STACK}; font-size: {mono:.2f}pt; font-weight: 700;
  letter-spacing: .2px; font-variant-numeric: slashed-zero;
  font-feature-settings: "zero" 1, "ss01" 1;
}}
.chk {{
  font-family: {MONO_STACK}; font-size: {base * 0.78:.2f}pt; color: #444;
  text-align: center; white-space: nowrap;
}}
.notes {{ color: #333; font-size: {base * 0.8:.2f}pt; font-style: italic; }}
.flag {{ font-weight: 700; }}
.box {{
  display: inline-block; width: {2.6 if narrow else 3.0}mm;
  height: {2.6 if narrow else 3.0}mm;
  border: .4pt solid #000; margin-right: .8mm; vertical-align: -.2mm;
}}
.brk {{ break-before: page; page-break-before: always; }}
.foot {{
  margin-top: 3mm; border-top: .4pt solid #000; padding-top: 1mm;
  font-size: {base * 0.75:.2f}pt; color: #222;
}}
.cutline {{
  border-top: .4pt dashed #666; margin: 2mm 0 0 0; height: 0;
}}
"""


def _cols(preset, opt):
    """Column widths per layout."""
    # Widths are percentages only and always sum to 100: with
    # `table-layout: fixed`, mixing mm and % overflows the page and silently
    # clips the last column.
    if preset.layout == "wide":
        cols = [("idx", "#", "4%")]
        if opt.show_url and opt.show_checksum:
            cols += [("site", "Site / login", "32%"), ("url", "URL", "26%"),
                     ("pw", "Password", "32%"), ("chk", "Chk", "6%")]
        elif opt.show_url:
            cols += [("site", "Site / login", "36%"), ("url", "URL", "27%"),
                     ("pw", "Password", "33%")]
        elif opt.show_checksum:
            cols += [("site", "Site / login", "50%"), ("pw", "Password", "40%"),
                     ("chk", "Chk", "6%")]
        else:
            cols += [("site", "Site / login", "54%"), ("pw", "Password", "42%")]
        return cols
    if opt.show_checksum:
        return [("idx", "#", "6%"), ("site", "Site / login", "46%"),
                ("pw", "Password", "41%"), ("chk", "Chk", "7%")]
    return [("idx", "#", "6%"), ("site", "Site / login", "50%"),
            ("pw", "Password", "44%")]


def _render_rows(items, preset, opt, start_index, escaped_flag):
    rows = []
    idx = start_index
    for rec in items:
        idx += 1
        title = to_ascii(rec.display_title) or domain_of(rec.url) or "(no title)"
        title = shorten(title, preset.title_chars)
        user = shorten(to_ascii(rec.username) or "-", preset.user_chars)
        # The scheme costs 8 characters and tells the reader nothing they need
        # while typing, so it only survives when it is not https.
        url_text = to_ascii(rec.url)
        if url_text.lower().startswith("https://"):
            url_text = url_text[8:]
        url = shorten(url_text.rstrip("/"), preset.url_chars)
        pw_text, needs_escape = ascii_password(rec.password)
        if needs_escape:
            escaped_flag[0] = True
        if opt.group_password and not needs_escape:
            pw_text = group_chars(pw_text, 4, "\u2009")
        chk = password_checksum(rec.password)

        site_cell = ('<span class="box"></span><span class="title">%s</span>'
                     '<br><span class="user">%s</span>'
                     % (_esc(title), _esc(user)))
        if preset.layout == "narrow" and opt.show_url and url:
            site_cell += '<br><span class="url">%s</span>' % _esc(url)
        if opt.show_notes and rec.notes:
            site_cell += ('<br><span class="notes">%s</span>'
                          % _esc(shorten(to_ascii(rec.notes), 60)))

        cells = ['<td class="idx">%d</td>' % idx, "<td>%s</td>" % site_cell]
        if preset.layout == "wide" and opt.show_url:
            cells.append('<td class="url">%s</td>' % _esc(url))
        flag = '<span class="flag">*</span> ' if needs_escape else ""
        cells.append('<td class="pw">%s%s</td>' % (flag, _esc(pw_text)))
        if opt.show_checksum:
            cells.append('<td class="chk">%s</td>' % _esc(chk))
        rows.append("<tr>%s</tr>" % "".join(cells))
    return rows, idx


def render_html(records, opt=None):
    """Build the complete printable document. Pure ASCII output."""
    opt = opt or PrintOptions()
    preset = PRESETS.get(opt.preset, PRESETS["a4"])
    cols = _cols(preset, opt)
    groups = categories.group_by_category(records)
    escaped_flag = [False]

    colgroup = "".join('<col style="width:%s">' % w for _k, _l, w in cols)
    header = "".join("<th>%s</th>" % _esc(lbl) for _k, lbl, _w in cols)
    # On a 90 or 105 mm page a repeated column header costs more room than it
    # earns - the black category bar already tells you where you are.
    show_head = preset.layout == "wide"

    sections = []
    index = 0
    for pos, (_cat, label, items) in enumerate(groups):
        rows, index = _render_rows(items, preset, opt, index, escaped_flag)
        brk = " brk" if (opt.page_break_per_category and pos > 0) else ""
        thead = "<thead><tr>%s</tr></thead>" % header if show_head else ""
        sections.append(
            '<section class="cat-block%s">'
            '<h2 class="cat">%s<span class="count">%d</span></h2>'
            '<table><colgroup>%s</colgroup>%s<tbody>%s</tbody></table></section>'
            % (brk, _esc(to_ascii(label)), len(items), colgroup, thead,
               "".join(rows))
        )

    stamp = time.strftime("%Y-%m-%d %H:%M")
    meta_bits = ["%d entries" % len(records),
                 "%d categories" % len(groups),
                 preset.label, stamp]
    meta = " &middot; ".join(_esc(to_ascii(b)) for b in meta_bits)

    legend = ""
    if opt.show_legend:
        text = AMBIGUITY_LEGEND
        if opt.show_checksum:
            text += (" 'Chk' is a 2-character typo check code for the password, "
                     "not part of it.")
        if opt.group_password:
            text += " Spaces inside passwords are visual grouping only."
        if escaped_flag[0]:
            text += (" Rows marked * contain non-ASCII characters printed as "
                     "\\uXXXX escapes - decode them, do not type them literally.")
        legend = '<div class="legend">%s</div>' % _esc(to_ascii(text))

    footer = ""
    if opt.show_totals:
        footer = ('<div class="foot">Handle as a secret document. '
                  'Store it where you would store cash. Destroy by shredding '
                  'or burning, never in normal waste. Generated offline by '
                  'pwvault - no network access was used.</div>')
    if opt.fold_marks:
        footer += '<div class="cutline"></div>'

    return (
        "<!DOCTYPE html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="robots" content="noindex,nofollow,noarchive">'
        "<title>%s</title><style>%s</style></head><body><div class=\"sheet\">"
        '<h1 class="doc">%s</h1><div class="meta">%s</div>%s%s%s'
        "</div></body></html>"
        % (_esc(to_ascii(opt.title)), _css(preset, opt),
           _esc(to_ascii(opt.title)), meta, legend, "".join(sections), footer)
    )


# --------------------------------------------------------------------------
# output
# --------------------------------------------------------------------------

def write_html(path, markup):
    with open_private(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(markup)
    return path


def open_in_browser(path):
    """
    Hand a local file to the default browser for Ctrl/Cmd+P.
    `webbrowser` shells out to the OS; it opens no socket of its own.
    """
    import webbrowser
    url = "file:///" + os.path.abspath(path).replace("\\", "/")
    return webbrowser.open(url)


_CHROME_CANDIDATES = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
]


def find_chromium():
    for name in ("chrome", "google-chrome", "chromium", "msedge"):
        found = shutil.which(name)
        if found:
            return found
    for path in _CHROME_CANDIDATES:
        if os.path.exists(path):
            return path
    return None


def html_to_pdf(html_path, pdf_path, timeout=90):
    """
    Render to PDF with headless Chromium so the custom 90x170 mm page size is
    honoured exactly (print dialogs often clamp to the printer's paper list).
    Returns (ok, message). Runs with networking disabled on the child too.
    """
    binary = find_chromium()
    if not binary:
        return False, ("No Chrome/Edge/Chromium found. Use 'Open in browser' "
                       "and print from there, or save as PDF in that dialog.")
    src = "file:///" + os.path.abspath(html_path).replace("\\", "/")
    cmd = [
        binary, "--headless=new", "--disable-gpu", "--no-first-run",
        "--no-default-browser-check", "--disable-extensions",
        "--disable-sync", "--disable-background-networking",
        "--disable-component-update", "--no-pings", "--incognito",
        "--host-resolver-rules=MAP * ~NOTFOUND",
        "--no-sandbox" if os.name == "nt" else "--disable-dev-shm-usage",
        "--print-to-pdf-no-header",
        "--print-to-pdf=%s" % os.path.abspath(pdf_path),
        src,
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception as exc:
        return False, "PDF render failed: %s: %s" % (type(exc).__name__, exc)
    if os.path.exists(pdf_path) and os.path.getsize(pdf_path) > 0:
        try:
            os.chmod(pdf_path, 0o600)
        except Exception:
            pass
        return True, os.path.abspath(pdf_path)
    return False, "Chromium exited rc=%s: %s" % (res.returncode,
                                                 (res.stderr or "")[-400:])
