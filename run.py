#!/usr/bin/env python3
"""Convenience launcher: `python run.py` from anywhere inside the project."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pwvault.__main__ import main  # noqa: E402  (hardening runs on import)

if __name__ == "__main__":
    sys.exit(main())
