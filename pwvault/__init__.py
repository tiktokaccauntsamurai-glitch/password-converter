"""
pwvault - offline, cross-platform password import/export/print manager.

Design rules (enforced in code, see pwvault.security):
  * zero third-party dependencies  -> no supply-chain surface
  * no network access at runtime   -> no exfiltration possible
  * plaintext secrets never leave the working folders you choose
  * every export is read back and byte-verified before any source is destroyed

Entry point:  python -m pwvault
"""

__all__ = ["__version__", "APP_NAME"]

__version__ = "1.0.0"
APP_NAME = "pwvault"
