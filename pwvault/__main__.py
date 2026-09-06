"""
Entry point.

    python -m pwvault              GUI
    python -m pwvault --cli ...    command line

Hardening is applied before anything else is imported, so the network kill
switch is in place for the whole lifetime of the process.
"""
import sys

from . import security

security.harden()


def main():
    argv = sys.argv[1:]
    if "--cli" in argv:
        argv.remove("--cli")
        from .cli import main as cli_main
        return cli_main(argv)
    if argv and argv[0] in ("-h", "--help"):
        print(__doc__)
        from .cli import build_parser
        build_parser().print_help()
        return 0
    try:
        from .gui import main as gui_main
    except Exception as exc:                       # Tk missing or no display
        print("Cannot start the GUI (%s: %s)." % (type(exc).__name__, exc))
        print("Falling back to the command line. Try: python -m pwvault --cli --list")
        from .cli import main as cli_main
        return cli_main(argv)
    return gui_main()


if __name__ == "__main__":
    sys.exit(main())
