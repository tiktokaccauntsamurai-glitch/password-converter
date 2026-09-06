"""
Append-only audit log.

Invariant enforced by `_SECRET_KEYS` + `scrub()`: a password, an OTP secret or
any registered secret can never reach this file. The log records *what
happened* (counts, file names, verification verdicts, shred results) so that a
destructive step is always traceable, and nothing more.
"""
from __future__ import annotations

import os
import time

from . import security

LOG_NAME = "pwvault_audit.log"

_SECRET_KEYS = ("password", "otpauth", "secret", "token", "pin")


class AuditLog:
    def __init__(self, directory, echo=None):
        self.directory = directory
        self.path = os.path.join(directory, LOG_NAME)
        self.echo = echo            # optional callable(str) for the UI
        self._ensure()

    def _ensure(self):
        try:
            os.makedirs(self.directory, exist_ok=True)
            if not os.path.exists(self.path):
                with security.open_private(self.path, "w", encoding="utf-8") as fh:
                    fh.write("# pwvault audit log - contains no secrets\n")
            security.lock_down_path(self.path)
        except Exception:
            pass

    @staticmethod
    def _safe(value):
        text = security.scrub(str(value))
        return text.replace("\n", " ").replace("\r", " ")

    def write(self, event, **fields):
        parts = ["%s" % time.strftime("%Y-%m-%dT%H:%M:%S"), event]
        for key, value in fields.items():
            if any(s in key.lower() for s in _SECRET_KEYS):
                value = "<omitted>"
            parts.append("%s=%s" % (key, self._safe(value)))
        line = " | ".join(parts)
        try:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except Exception:
            pass
        if self.echo:
            try:
                self.echo(line)
            except Exception:
                pass
        return line
