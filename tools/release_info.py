"""Release files for the GitHub release workflow (.github/workflows/release.yml).

    python tools/release_info.py --version
        prints VERSION from linktest.py
    python tools/release_info.py --write --asset win64=LinkTest-win64.exe --commit <sha>
        writes release.json (what copies of LinkTest read to update themselves, see
        selfupdate.py), notes.md (the release text: this version's CHANGELOG section) and
        SHA256SUMS.txt
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HISTORY = 15   # versions of changes carried in release.json, for copies that skipped several


def version() -> str:
    src = open(os.path.join(ROOT, "linktest.py"), encoding="utf-8").read()
    return re.search(r'^VERSION\s*=\s*"([^"]+)"', src, re.M).group(1)


def changelog_sections() -> list[tuple[str, str]]:
    """[(version, markdown body)] newest first."""
    text = open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8").read()
    parts = re.split(r"^## (\S+)[^\n]*\n", text, flags=re.M)
    return [(parts[i], parts[i + 1].strip()) for i in range(1, len(parts) - 1, 2)]


def bullets(body: str) -> list[str]:
    """One line per top-level bullet: its first sentence, without markdown emphasis."""
    out, cur = [], None
    for line in body.splitlines():
        if line.startswith("- "):
            if cur is not None:
                out.append(cur)
            cur = line[2:].strip()
        elif cur is not None and line.startswith("  ") and not line.strip().startswith("- "):
            cur += " " + line.strip()
        elif cur is not None and not line.strip():
            out.append(cur)
            cur = None
    if cur is not None:
        out.append(cur)
    clean = []
    for b in out:
        b = re.sub(r"\*\*|`", "", b)
        m = re.match(r"(.{20,}?[.:])(\s|$)", b)
        b = m.group(1).rstrip(":") if m else b
        clean.append(b if len(b) <= 160 else b[:157].rstrip() + "…")
    return clean


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write(assets: dict[str, str], commit: str) -> None:
    ver = version()
    sections = changelog_sections()
    mine = dict(sections).get(ver, "")
    info = {"version": ver, "commit": commit, "changes": bullets(mine),
            "history": [{"version": v, "changes": bullets(b)} for v, b in sections[:HISTORY]],
            "assets": {}}
    sums = []
    for tag, path in assets.items():
        digest = sha256(path)
        info["assets"][tag] = {"name": os.path.basename(path), "sha256": digest, "size": os.path.getsize(path)}
        sums.append(f"{digest}  {os.path.basename(path)}")
    with open("release.json", "w", encoding="utf-8") as f:
        json.dump(info, f, indent=2)
    with open("SHA256SUMS.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(sums) + "\n")
    with open("notes.md", "w", encoding="utf-8") as f:
        f.write((mine or f"LinkTest {ver}") + "\n\n---\nCopies of LinkTest update themselves from this release "
                "(Settings > Updates). To install by hand, download LinkTest-win64.exe and run it.\n")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", action="store_true")
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--asset", action="append", default=[], help="tag=path")
    ap.add_argument("--commit", default="")
    a = ap.parse_args(argv)
    if a.version:
        print(version())
        return 0
    if a.write:
        write(dict(x.split("=", 1) for x in a.asset), a.commit)
        return 0
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
