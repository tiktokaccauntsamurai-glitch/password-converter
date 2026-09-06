#!/bin/bash
# pwvault launcher for macOS - double-click this file in Finder.
# If macOS refuses to run it: right-click > Open, or run
#     chmod +x run_macos.command
cd "$(dirname "$0")" || exit 1

PY=""
for candidate in python3 /usr/local/bin/python3 /opt/homebrew/bin/python3 \
                 /usr/bin/python3; do
    if command -v "$candidate" >/dev/null 2>&1; then PY="$candidate"; break; fi
done

if [ -z "$PY" ]; then
    echo "Python 3.9+ was not found."
    echo "Install it from https://www.python.org/downloads/macos/ and try again."
    read -r -p "Press Enter to close..."
    exit 1
fi

if ! "$PY" -c "import tkinter" >/dev/null 2>&1; then
    echo "This Python has no Tk support, so the window cannot open."
    echo "Use the python.org installer (it bundles Tk), or run the CLI:"
    echo "    $PY -m pwvault --cli --list"
    read -r -p "Press Enter to close..."
    exit 1
fi

"$PY" -m pwvault "$@"
status=$?
[ $status -ne 0 ] && read -r -p "Exited with status $status. Press Enter to close..."
exit $status
