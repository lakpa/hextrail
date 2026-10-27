#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
if [ -f .tools/activate.sh ]; then
  source .tools/activate.sh
fi
if [ -x .tools/python/bin/python ]; then
  hextrail_python=.tools/python/bin/python
else
  if ! command -v python3 >/dev/null 2>&1; then
    echo "Install Python 3.10 or newer, then run: bash run.sh"
    exit 1
  fi
  python3 -c 'import sys; assert sys.version_info >= (3, 10), "Python 3.10 or newer is required"'
  if [ ! -x .venv/bin/python ]; then
    python3 -m venv .venv
  fi
  hextrail_python=.venv/bin/python
fi
if ! "$hextrail_python" -c 'from importlib.metadata import version; assert version("capstone")=="5.0.9"; assert version("pyelftools")=="0.33"; assert version("PySide6-Essentials")=="6.12.0"' >/dev/null 2>&1; then
  echo "Installing the desktop and analysis dependencies (first run)…"
  "$hextrail_python" -m pip install --disable-pip-version-check -r requirements.txt
fi
exec "$hextrail_python" -m hextrail "$@"
