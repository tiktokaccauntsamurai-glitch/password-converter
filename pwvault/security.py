"""
Runtime hardening / isolation layer.

Threat model (long version in PROJECT.md):
  T1  exfiltration of plaintext secrets over the network by this process
  T2  supply-chain code execution via third-party packages
  T3  secrets leaking into logs, tracebacks, crash dumps
  T4  secrets left readable by other local accounts (file permissions)
  T5  secrets silently replicated by a cloud-sync client (OneDrive/iCloud/...)
  T6  secrets surviving on disk after the user believes they were deleted
  T7  shoulder-surfing / unattended screen

Everything here is best effort and honest: where the platform cannot give a
real guarantee (see `unmitigated_risks()`) we say so instead of pretending.
"""
from __future__ import annotations

import io
import os
import sys
import platform
import subprocess

# --------------------------------------------------------------------------
# T1 - network kill switch
# --------------------------------------------------------------------------

_NETWORK_MODULES = {
    "socket", "ssl", "urllib", "http", "httplib", "ftplib", "smtplib",
    "poplib", "imaplib", "telnetlib", "xmlrpc", "asyncio", "socketserver",
    "requests", "urllib3", "httpx", "aiohttp", "websockets", "paramiko",
    "boto3", "botocore", "grpc", "pycurl",
}

_network_blocked = False


class NetworkBlocked(PermissionError):
    """Raised whenever the process tries to touch the network."""


class _NetworkImportBlocker:
    """Meta-path finder that refuses to import networking modules."""

    def find_module(self, fullname, path=None):  # legacy API, harmless
        return self.find_spec(fullname, path)

    def find_spec(self, fullname, path=None, target=None):
        root = fullname.split(".")[0]
        if root in _NETWORK_MODULES:
            raise NetworkBlocked(
                "pwvault runs fully offline: import of %r is blocked. "
                "If you see this, something tried to phone home." % fullname
            )
        return None


def block_network() -> None:
    """Make outbound networking impossible for the rest of the process."""
    global _network_blocked
    if _network_blocked:
        return

    # 1. Import `socket` ourselves and gut it. Parts of the stdlib (e.g.
    #    platform.uname() -> node name) legitimately import socket, so removing
    #    the module would break them; removing its *ability to connect* does
    #    not. Because it is now in sys.modules, the import blocker below never
    #    sees those internal imports, and they get the disarmed module.
    def _deny(*_a, **_kw):
        raise NetworkBlocked("network access is disabled in pwvault")

    try:
        import socket as sock_mod
    except Exception:
        sock_mod = None
    if sock_mod is not None:
        for name in ("socket", "SocketIO", "create_connection", "socketpair",
                     "getaddrinfo", "gethostbyname", "gethostbyname_ex",
                     "create_server", "fromfd", "dup"):
            if hasattr(sock_mod, name):
                try:
                    setattr(sock_mod, name, _deny)
                except Exception:
                    pass

    # 2. refuse future imports of anything that could talk to a network
    sys.meta_path.insert(0, _NetworkImportBlocker())
    _network_blocked = True


def network_is_blocked() -> bool:
    return _network_blocked


# --------------------------------------------------------------------------
# T3 - keep secrets out of tracebacks and core dumps
# --------------------------------------------------------------------------

_SCRUB_MARK = "<redacted-by-pwvault>"
_registered_secrets = []


def register_secret(value):
    """Remember a value so it can be scrubbed out of any crash output."""
    if value and len(value) >= 4 and value not in _registered_secrets:
        _registered_secrets.append(value)


def forget_secrets():
    del _registered_secrets[:]


def scrub(text):
    """Replace every known secret inside `text`."""
    if not text:
        return text
    for secret in _registered_secrets:
        if secret in text:
            text = text.replace(secret, _SCRUB_MARK)
    return text


def _scrubbing_excepthook(exc_type, exc, tb):
    import traceback
    rendered = "".join(traceback.format_exception(exc_type, exc, tb))
    sys.stderr.write(scrub(rendered))


def install_excepthook():
    sys.excepthook = _scrubbing_excepthook
    if hasattr(sys, "unraisablehook"):
        _prev = sys.unraisablehook

        def _hook(unraisable):
            try:
                sys.stderr.write(scrub("unraisable: %r\n" % (unraisable.exc_value,)))
            except Exception:
                _prev(unraisable)

        sys.unraisablehook = _hook


def disable_core_dumps():
    """Stop the OS from writing a core file that would contain the passwords."""
    try:
        import resource  # POSIX only
    except ImportError:
        return False  # Windows: no core files by default
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        return True
    except Exception:
        return False


def disable_bytecode_cache():
    """No .pyc noise next to the data folders."""
    sys.dont_write_bytecode = True


# --------------------------------------------------------------------------
# T4 - private-by-default files and folders
# --------------------------------------------------------------------------

IS_WINDOWS = os.name == "nt"


def set_private_umask():
    if not IS_WINDOWS:
        try:
            os.umask(0o077)
        except Exception:
            pass


def lock_down_path(path):
    """
    Restrict `path` (file or directory) to the current user only.
    Returns a short description of what was actually applied.
    """
    if not os.path.exists(path):
        return "missing"
    if not IS_WINDOWS:
        try:
            mode = 0o700 if os.path.isdir(path) else 0o600
            os.chmod(path, mode)
            return "chmod %o" % mode
        except Exception as exc:
            return "chmod failed: %s" % exc

    user = os.environ.get("USERNAME") or ""
    if not user:
        return "acl skipped (no USERNAME)"
    domain = os.environ.get("USERDOMAIN") or ""
    principal = "%s\\%s" % (domain, user) if domain else user

    # Inheritance flags (OI)(CI) are only valid on a directory. Applying them
    # to a file makes icacls fail *after* /inheritance:r has already stripped
    # the inherited ACEs, leaving a file nobody can open. Keep them apart.
    grant = "%s:(OI)(CI)F" % principal if os.path.isdir(path) else "%s:F" % principal
    try:
        res = subprocess.run(["icacls", path, "/inheritance:r", "/grant:r", grant],
                             capture_output=True, text=True, timeout=30)
        if res.returncode == 0:
            return "icacls: owner-only"
        # Never leave the object unreachable: put inheritance back.
        subprocess.run(["icacls", path, "/inheritance:e"],
                       capture_output=True, text=True, timeout=30)
        return "icacls failed rc=%s (inheritance restored)" % res.returncode
    except Exception as exc:
        return "icacls error: %s" % exc


def open_private(path, mode="w", **kwargs):
    """
    open() replacement that creates the file with 0600 from the very first byte
    (no window in which another local user could read it).
    """
    if "r" in mode and "+" not in mode:
        return io.open(path, mode, **kwargs)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if IS_WINDOWS and "b" in mode:
        flags |= getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, 0o600)
    return io.open(fd, mode, **kwargs)


# --------------------------------------------------------------------------
# T5 - cloud-sync detection
# --------------------------------------------------------------------------

_CLOUD_MARKERS = (
    "onedrive", "dropbox", "google drive", "googledrive", "gdrive",
    "icloud drive", "com~apple~clouddocs", "mobile documents",
    "yandexdisk", "yandex.disk", "mega", "pcloud", "box sync",
    "nextcloud", "owncloud", "creative cloud",
)


def cloud_sync_warning(path):
    """Return a warning string if `path` looks like it lives in a synced folder."""
    low = os.path.abspath(path).replace("\\", "/").lower()
    for marker in _CLOUD_MARKERS:
        if marker in low:
            return ("Folder looks like it is inside a cloud-sync location (%r). "
                    "Plaintext passwords placed here can be uploaded "
                    "automatically. Use a local-only folder instead." % marker)
    return None


# --------------------------------------------------------------------------
# environment facts the UI shows the user
# --------------------------------------------------------------------------

_CORE_DISABLED = False


def unmitigated_risks():
    """
    Things this program genuinely cannot fix. Shown in the UI and written to
    the audit log so the user is never given a false sense of safety.
    """
    risks = [
        "Browser CSV exports are PLAINTEXT. Anything that can read your user "
        "account can read them while they exist on disk.",
        "Python cannot reliably wipe secrets out of RAM (strings are immutable "
        "and may be copied by the interpreter). Reboot after a session if this "
        "matters to you.",
        "If the OS swaps or hibernates, plaintext can reach the page file. "
        "Full-disk encryption (BitLocker / FileVault) is the real mitigation.",
        "On SSDs, overwriting a file does not guarantee the old flash blocks are "
        "gone (wear levelling). Shredding here is best effort; full-disk "
        "encryption is what actually protects deleted data.",
        "Anything you print exists on paper and possibly in the printer spool. "
        "Prefer a directly attached printer, never a shared or cloud queue.",
    ]
    if not _network_blocked:
        risks.insert(0, "Network kill switch is NOT active in this process.")
    return risks


def environment_report():
    return {
        "python": sys.version.split()[0],
        "platform": "%s %s" % (platform.system(), platform.release()),
        "machine": platform.machine(),
        "network_blocked": _network_blocked,
        "bytecode_cache_off": bool(sys.dont_write_bytecode),
        "core_dumps_disabled": _CORE_DISABLED,
    }


def harden():
    """Apply every mitigation that is safe to apply unconditionally."""
    global _CORE_DISABLED
    disable_bytecode_cache()
    set_private_umask()
    _CORE_DISABLED = disable_core_dumps()
    install_excepthook()
    block_network()
    return environment_report()
