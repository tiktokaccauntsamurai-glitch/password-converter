# PyInstaller spec for the macOS .app (universal2: Apple Silicon + Intel).
# Built by .github/workflows/build-macos.yml; on a Mac it also runs locally
# from the project root:
#     pip install pyinstaller
#     pyinstaller --noconfirm release/pwvault_macos.spec
# Needs a universal2 python.org Python - it bundles Tk and both architectures.
import os
import re

ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))

with open(os.path.join(ROOT, "pwvault", "__init__.py"), encoding="utf-8") as fh:
    VERSION = re.search(r'__version__ = "([^"]+)"', fh.read()).group(1)

a = Analysis(
    [os.path.join(ROOT, "run.py")],
    pathex=[ROOT],
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="pwvault",
    console=False,
    target_arch="universal2",
    codesign_identity=None,     # ad-hoc signature, no Apple developer account
)

coll = COLLECT(exe, a.binaries, a.datas, name="pwvault")

app = BUNDLE(
    coll,
    name="pwvault.app",
    bundle_identifier="io.github.tiktokaccauntsamurai-glitch.pwvault",
    version=VERSION,
    info_plist={
        "CFBundleDisplayName": "pwvault",
        "CFBundleShortVersionString": VERSION,
        "LSMinimumSystemVersion": "11.0",
        "NSHighResolutionCapable": True,
    },
)
