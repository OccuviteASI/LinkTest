"""Zip the LinkTest source tree for moving it to another machine (e.g. a Mac to build on).

    python tools/pack_source.py            -> dist/LinkTest-src-<version>.zip

Includes everything needed to build: code, ui/, assets/ (icons + vendor table), the
build/fetch scripts, docs and the bin/*/LICENSE.txt notes. Leaves out built binaries
(dist/, bin/*/iperf3*, DLLs), caches and editor state.
"""
from __future__ import annotations

import os
import re
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKIP_DIRS = {"dist", "__pycache__", ".git", ".venv", "venv", ".claude", "build", "tools/fake", "tools/fake-build"}
SKIP_SUFFIX = (".pyc", ".pyo", ".zip", ".exe", ".dll", ".log")


def version() -> str:
    src = open(os.path.join(ROOT, "linktest.py"), encoding="utf-8").read()
    m = re.search(r'^VERSION\s*=\s*"([^"]+)"', src, re.M)
    return m.group(1) if m else "0.0.0"


def wanted(rel: str) -> bool:
    parts = rel.replace("\\", "/").split("/")
    for i in range(1, len(parts)):
        if "/".join(parts[:i]) in SKIP_DIRS or parts[i - 1] in SKIP_DIRS:
            return False
    if rel.endswith(SKIP_SUFFIX):
        return False
    if parts[0] == "bin" and len(parts) == 3 and parts[2] != "LICENSE.txt":
        return False  # binaries are rebuilt per platform by fetch-helpers.py
    return True


def main() -> int:
    ver = version()
    out_dir = os.path.join(ROOT, "dist")
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, f"LinkTest-src-{ver}.zip")
    n = 0
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for dirpath, dirnames, filenames in os.walk(ROOT):
            rel_dir = os.path.relpath(dirpath, ROOT).replace("\\", "/")
            dirnames[:] = [d for d in dirnames if wanted((rel_dir + "/" + d).lstrip("./") + "/x")]
            for fn in filenames:
                rel = (rel_dir + "/" + fn).lstrip("./") if rel_dir != "." else fn
                if not wanted(rel):
                    continue
                info = zipfile.ZipInfo.from_file(os.path.join(dirpath, fn), "LinkTest/" + rel)
                if fn.endswith(".sh"):
                    info.external_attr = (0o100755 << 16)   # keep build-mac.sh executable when unzipped on the Mac
                with open(os.path.join(dirpath, fn), "rb") as f:
                    z.writestr(info, f.read(), compress_type=zipfile.ZIP_DEFLATED)
                n += 1
    print(f"wrote {out} ({os.path.getsize(out) // 1024} KB, {n} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
