"""Fetch the third-party pieces that build.py bundles into LinkTest.

    python fetch-helpers.py                 # everything this machine can use
    python fetch-helpers.py win64 manuf     # a subset
    python fetch-helpers.py mac             # on a Mac: compile iperf3 from the pinned source

Targets and where they land (all verified against the SHA-256 pins below):
  win64         bin/win64/iperf3.exe + cygwin1.dll   github.com/ar51an/iperf3-win-builds
  linux-x86_64  bin/linux-x86_64/iperf3 (static)     github.com/userdocs/iperf3-static
  mac           bin/mac-<arch>/iperf3 (built here)   github.com/esnet/iperf source tarball, compiled with
                                                     the Xcode command line tools (macOS only)
  manuf         assets/manuf.z (MAC vendor table)    wireshark.org 'manuf' (GPL-2 data)

Run once per checkout; bin/ contents are git-ignored, assets/manuf.z is
committed. Nothing here runs at LinkTest runtime; the shipped app never
downloads anything. When refreshing the vendor table, download, then paste
the new sha256 the script prints (the Wireshark file changes weekly, so its
pin is expected to go stale; re-pin deliberately, never auto-accept).
"""
from __future__ import annotations

import hashlib
import io
import os
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import zipfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
IPERF_VERSION = "3.21"

HELPERS = {
    "win64": {
        "url": f"https://github.com/ar51an/iperf3-win-builds/releases/download/{IPERF_VERSION}/iperf-{IPERF_VERSION}-win64.zip",
        "sha256": "9b73b7e0e0326347b5f4ac4f6a1fc34fe60a5966e5fd172c7bfcd0e1cc93e709",
        "kind": "zip",
        "dest": "bin/win64",
        "files": ["iperf3.exe", "cygwin1.dll"],
    },
    "linux-x86_64": {
        "url": f"https://github.com/userdocs/iperf3-static/releases/download/{IPERF_VERSION}/iperf3-amd64",
        "sha256": "201cbaed73d4e4da72c44c9aee895a2d58c75f1d1a4d721137f4888f6b7f5016",
        "kind": "bin",
        "dest": "bin/linux-x86_64",
        "files": ["iperf3"],
    },
    "mac": {
        "url": f"https://github.com/esnet/iperf/releases/download/{IPERF_VERSION}/iperf-{IPERF_VERSION}.tar.gz",
        "sha256": "656e4405ebd620121de7ceca3eaf43a88f79ea1b857d041a6a0b1314801acdd8",
        "kind": "source",
        "dest": "bin/mac-ARCH",   # ARCH is replaced with arm64 or x86_64 at run time
        "files": ["iperf3"],
    },
    "manuf": {
        "url": "https://www.wireshark.org/download/automated/data/manuf",
        "sha256": "48fe530bcc7a513727d027e984afda73c823a82fd4dce79bafdae6103542fbb0",
        "kind": "manuf",
        "dest": "assets",
        "files": ["manuf.z"],
    },
}


def download(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "LinkTest-fetch"})
    with urllib.request.urlopen(req, timeout=120) as r:
        total = int(r.headers.get("Content-Length") or 0)
        buf = io.BytesIO()
        while True:
            chunk = r.read(1 << 16)
            if not chunk:
                break
            buf.write(chunk)
            if total:
                sys.stdout.write(f"\r  {buf.tell() * 100 // total:3d}%")
                sys.stdout.flush()
        sys.stdout.write("\r" + " " * 8 + "\r")
    return buf.getvalue()


def verify(name: str, data: bytes, pinned: str) -> None:
    got = hashlib.sha256(data).hexdigest()
    if pinned.startswith("REPLACE"):
        print(f"  NOTE: no pin for {name} yet. sha256 = {got}")
        print("        paste it into HELPERS in fetch-helpers.py once you trust this file.")
        return
    if got != pinned:
        sys.exit(f"  sha256 mismatch for {name}:\n    expected {pinned}\n    got      {got}\n"
                 "  Refusing to unpack. (For 'manuf' the upstream file changes weekly: inspect, then re-pin.)")
    print("  sha256 ok")


def write_manuf(data: bytes, dest: str) -> None:
    """Trim Wireshark's manuf to 'prefix<TAB>short name' lines and zlib-compress it."""
    lines = []
    for raw in data.decode("utf-8", "replace").splitlines():
        if not raw or raw.startswith("#"):
            continue
        parts = raw.split("\t")
        if len(parts) < 2:
            continue
        prefix = parts[0].strip().upper()
        short = parts[1].strip()
        if not prefix or not short:
            continue
        lines.append(f"{prefix}\t{short}")
    blob = zlib.compress("\n".join(lines).encode("utf-8"), 9)
    with open(os.path.join(dest, "manuf.z"), "wb") as f:
        f.write(blob)
    with open(os.path.join(dest, "manuf.txt"), "w", encoding="utf-8") as f:
        f.write(f"Wireshark manuf MAC vendor table, fetched {time.strftime('%Y-%m-%d')}\n"
                f"source: {HELPERS['manuf']['url']}\nentries: {len(lines)}\n"
                "licence: GPL-2.0 (data file; attribution in THIRD-PARTY-LICENSES.txt)\n")
    print(f"  wrote assets/manuf.z ({len(blob) // 1024} KB, {len(lines)} entries)")


def mac_arch() -> str:
    m = platform.machine().lower()
    return "arm64" if m in ("arm64", "aarch64") else "x86_64"


def build_iperf_from_source(data: bytes, dest: str) -> None:
    """macOS: compile iperf3 with the Xcode command line tools (clang). No OpenSSL, so the
    binary depends on nothing but libSystem and runs on any Mac of the same architecture."""
    if sys.platform != "darwin":
        print("  skipped: compiling the macOS iperf3 only works on a Mac")
        return
    if subprocess.run(["xcode-select", "-p"], capture_output=True).returncode != 0:
        sys.exit("  the Xcode command line tools are missing. Run:  xcode-select --install   and try again.")
    with tempfile.TemporaryDirectory(prefix="linktest-iperf-") as tmp:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            tf.extractall(tmp, filter="data")
        src = os.path.join(tmp, f"iperf-{IPERF_VERSION}")
        env = dict(os.environ, MACOSX_DEPLOYMENT_TARGET=os.environ.get("MACOSX_DEPLOYMENT_TARGET", "12.0"))
        steps = [["./configure", "--disable-shared", "--enable-static", "--without-openssl", "--disable-profiling"],
                 ["make", "-j4"]]
        for step in steps:
            print("  " + " ".join(step))
            r = subprocess.run(step, cwd=src, env=env, capture_output=True, text=True)
            if r.returncode != 0:
                sys.exit("  build failed:\n" + (r.stderr or r.stdout)[-2000:])
        built = os.path.join(src, "src", "iperf3")
        if not os.path.isfile(built):
            sys.exit("  build produced no src/iperf3")
        target = os.path.join(dest, "iperf3")
        shutil.copy2(built, target)
        subprocess.run(["strip", target], capture_output=True)
        subprocess.run(["codesign", "--force", "--sign", "-", target], capture_output=True)
        os.chmod(target, 0o755)
        lic = os.path.join(src, "LICENSE")
        with open(os.path.join(dest, "LICENSE.txt"), "w", encoding="utf-8") as f:
            f.write(f"iperf3 {IPERF_VERSION} for macOS ({mac_arch()}), compiled from the official source tarball\n"
                    f"  {HELPERS['mac']['url']}\n  built without OpenSSL; links only against the macOS system library.\n\n")
            if os.path.isfile(lic):
                f.write(open(lic, encoding="utf-8", errors="replace").read())
        print(f"  wrote {os.path.relpath(target, HERE)} ({os.path.getsize(target) // 1024} KB)")


def install(tag: str, spec: dict) -> None:
    dest = os.path.join(HERE, spec["dest"].replace("ARCH", mac_arch()))
    if spec["kind"] == "source" and sys.platform != "darwin":
        print(f"{tag}: skipped (only built on a Mac)")
        return
    os.makedirs(dest, exist_ok=True)
    print(f"{tag}: {spec['url']}")
    data = download(spec["url"])
    verify(tag, data, spec["sha256"])
    if spec["kind"] == "source":
        build_iperf_from_source(data, dest)
    elif spec["kind"] == "zip":
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            names = {os.path.basename(i.filename).lower(): i for i in z.infolist() if not i.is_dir()}
            for want in spec["files"]:
                info = names.get(want.lower())
                if not info:
                    sys.exit(f"  {want} not found in archive (has: {sorted(names)})")
                with z.open(info) as src, open(os.path.join(dest, want), "wb") as dst:
                    dst.write(src.read())
                print(f"  wrote {spec['dest']}/{want} ({info.file_size // 1024} KB)")
    elif spec["kind"] == "bin":
        target = os.path.join(dest, spec["files"][0])
        with open(target, "wb") as f:
            f.write(data)
        os.chmod(target, os.stat(target).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        print(f"  wrote {spec['dest']}/{spec['files'][0]} ({len(data) // 1024} KB)")
    elif spec["kind"] == "manuf":
        write_manuf(data, dest)
        return
    # Smoke-test iperf3 when this machine can run it.
    exe = os.path.join(dest, spec["files"][0])
    runnable = {"win64": os.name == "nt", "linux-x86_64": sys.platform.startswith("linux"), "mac": sys.platform == "darwin"}.get(tag, False)
    if runnable:
        try:
            out = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=15)
            first = (out.stdout or out.stderr).strip().splitlines()[0]
            print(f"  runs: {first}")
            if IPERF_VERSION not in first:
                sys.exit("  unexpected version string")
        except (OSError, subprocess.TimeoutExpired, IndexError) as e:
            sys.exit(f"  binary does not run: {e}")


def main(argv: list[str]) -> int:
    tags = argv or [t for t in HELPERS if HELPERS[t]["kind"] != "source" or sys.platform == "darwin"]
    for tag in tags:
        if tag not in HELPERS:
            sys.exit(f"unknown helper {tag}; choose from {', '.join(HELPERS)}")
        install(tag, HELPERS[tag])
    print("done")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
