#!/bin/sh
# macOS Finder (after chmod +x) or Linux/macOS terminal: sh Aegis.command
set -eu
cd "$(dirname "$0")"
if [ -x .venv/bin/python ]; then
    exec .venv/bin/python aegis.py "$@"
fi
if command -v python3 >/dev/null 2>&1; then
    if [ "$(uname -s)" = Darwin ] && [ "$(command -v python3)" = /usr/bin/python3 ]; then
        printf '%s\n' 'Use a reviewed Python 3.11+ installation; Aegis will not invoke the Apple developer-tools bootstrap. See QUICKSTART.md.' >&2
        exit 1
    fi
    exec python3 aegis.py "$@"
fi
printf '%s\n' 'Install a reviewed local Python 3.11+ runtime first. See QUICKSTART.md.' >&2
exit 1
