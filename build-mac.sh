#!/bin/sh
# One-shot macOS build: venv + Python deps + iperf3 from source + PyInstaller .app
# Usage: ./build-mac.sh [--console] [--onedir]     (see MACOS.md)
set -e
cd "$(dirname "$0")"

if ! xcode-select -p >/dev/null 2>&1; then
  echo "The Xcode Command Line Tools are missing. Run:  xcode-select --install   then re-run this script."
  exit 1
fi

PY="${PYTHON:-python3}"
if [ ! -x .venv/bin/python ]; then
  echo "Creating .venv with $PY ..."
  "$PY" -m venv .venv
fi
# shellcheck disable=SC1091
. .venv/bin/activate
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r requirements.txt pillow

ARCH="$(uname -m)"
case "$ARCH" in arm64|aarch64) TAG=mac-arm64 ;; *) TAG=mac-x86_64 ;; esac
if [ ! -x "bin/$TAG/iperf3" ]; then
  echo "Compiling iperf3 for $TAG ..."
  python fetch-helpers.py mac
fi
if [ ! -f assets/manuf.z ]; then
  echo "assets/manuf.z is missing (MAC vendor names). Fetching ..."
  python fetch-helpers.py manuf || echo "WARNING: vendor table not fetched; makers will be blank"
fi
if [ ! -f assets/linktest.icns ]; then
  python tools/make_icon.py
fi

python build.py "$@"
