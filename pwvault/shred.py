"""
Best-effort secure deletion of plaintext CSV files.

Honesty first: on modern SSDs, overwriting a file in place does NOT reliably
destroy the previous contents. Wear levelling means the controller usually
writes your overwrite to a *different* physical block and leaves the old one
readable by forensic tooling until it is garbage-collected. NIST SP 800-88r1
therefore does not recommend software overwrite as a sanitisation method for
flash media.

What this module actually buys you:
  * the data is gone from the filesystem's point of view
  * it is gone from any snapshot/undelete tool that works at the file layer
  * on spinning rust (HDD, USB stick with no FTL remapping) the overwrite is
    genuinely effective
  * the filename itself - often revealing - is randomised before unlink

What actually protects you on an SSD is full-disk encryption (BitLocker /
FileVault): once the volume key is gone, leftover blocks are ciphertext.
The UI repeats this; see security.unmitigated_risks().
"""
from __future__ import annotations

import os
import secrets
import string

CHUNK = 1 << 16  # 64 KiB


class ShredResult:
    def __init__(self, path):
        self.path = path
        self.size = 0
        self.passes = 0
        self.renamed_to = ""
        self.ok = False
        self.error = ""

    def __repr__(self):
        state = "ok" if self.ok else "FAILED: %s" % self.error
        return "<shred %s (%d bytes, %d passes) %s>" % (
            os.path.basename(self.path), self.size, self.passes, state)


def _overwrite(fh, size, pattern):
    """pattern=None -> cryptographically random bytes."""
    fh.seek(0)
    remaining = size
    while remaining > 0:
        n = min(CHUNK, remaining)
        block = secrets.token_bytes(n) if pattern is None else pattern * n
        fh.write(block)
        remaining -= n
    fh.flush()
    os.fsync(fh.fileno())


def shred_file(path, passes=3, rename_rounds=3):
    """
    Overwrite, truncate, rename and unlink a single file.
    Never raises: inspect the returned ShredResult.
    """
    result = ShredResult(path)
    try:
        if not os.path.isfile(path):
            result.error = "not a regular file"
            return result
        result.size = os.path.getsize(path)

        patterns = [None, b"\xff", b"\x00"][:max(1, passes)]
        with open(path, "r+b", buffering=0) as fh:
            for pattern in patterns:
                _overwrite(fh, result.size, pattern)
                result.passes += 1
            fh.seek(0)
            fh.truncate(0)
            fh.flush()
            os.fsync(fh.fileno())

        # Randomise the name so the directory entry leaks nothing either.
        directory = os.path.dirname(os.path.abspath(path))
        current = path
        alphabet = string.ascii_lowercase + string.digits
        for _ in range(rename_rounds):
            name = "".join(secrets.choice(alphabet) for _ in range(16))
            target = os.path.join(directory, name)
            if os.path.exists(target):
                continue
            os.rename(current, target)
            current = target
        result.renamed_to = os.path.basename(current)

        os.remove(current)
        result.ok = True
    except Exception as exc:                      # noqa: BLE001 - reported, not raised
        result.error = "%s: %s" % (type(exc).__name__, exc)
    return result


def shred_paths(paths, passes=3):
    return [shred_file(p, passes=passes) for p in paths]


def wipe_string_list(values):
    """
    Overwrite the *containers* holding secrets and drop the references.

    CPython cannot zero an immutable str in place, so this only removes our
    own references and makes the objects collectable sooner. It is a hygiene
    measure, not a guarantee - stated plainly in the docs and in the UI.
    """
    for i in range(len(values)):
        values[i] = "\x00" * len(values[i] or "")
    del values[:]
