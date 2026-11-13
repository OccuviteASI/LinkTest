"""Build a single-file LinkTest executable for the platform this script runs on.

    python build.py              Windows -> dist/win64/LinkTest.exe
                                 Linux   -> dist/linux-x86_64/LinkTest
                                 macOS   -> dist/mac-<arch>/LinkTest.app (+ a zip for transfer)
    python build.py --wsl        from Windows: run the Linux build inside WSL too
    python build.py --console    keep a console window (Windows debugging)
    python build.py --onedir     folder build instead of one file (faster start)

PyInstaller cannot cross-compile, so each platform builds its own binary. The
bundled iperf3 comes from bin/<tag>/ (see fetch-iperf3.py); the build refuses
to run without it because the whole point of the app is that nothing has to be
downloaded later.
"""
from __future__ import annotations

import os
import re
import json
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import iperf_runner as ir  # noqa: E402

NAME = "LinkTest"
WINDOWS = sys.platform == "win32"
LINUX = sys.platform.startswith("linux")
MAC = sys.platform == "darwin"
TAG = ir.plat_tag()
BUNDLE_ID = "com.asirobots.linktest"
DIST = os.path.join(HERE, "dist", TAG)
# Scratch outside the tree: sync clients (OneDrive) lock PyInstaller work files.
WORK = os.path.join(os.environ.get("TEMP") or os.environ.get("TMPDIR") or "/tmp", "linktest-build", TAG)
SEP = ";" if WINDOWS else ":"
WSL_VENV = "/opt/linktestbuild"

REQUIRED_BIN = {
    "win64": ["iperf3.exe", "cygwin1.dll", "LICENSE.txt"],
    "linux-x86_64": ["iperf3", "LICENSE.txt"],
    "mac-arm64": ["iperf3", "LICENSE.txt"],
    "mac-x86_64": ["iperf3", "LICENSE.txt"],
}


def version() -> str:
    src = open(os.path.join(HERE, "linktest.py"), encoding="utf-8").read()
    m = re.search(r'^VERSION\s*=\s*"([^"]+)"', src, re.M)
    return m.group(1) if m else "0.0.0"


def check_binaries() -> list[str]:
    bin_dir = os.path.join(HERE, "bin", TAG)
    need = REQUIRED_BIN.get(TAG)
    if need is None:
        sys.exit(f"build: no iperf3 bundle defined for platform '{TAG}' (add it to fetch-iperf3.py)")
    missing = [n for n in need if not os.path.isfile(os.path.join(bin_dir, n))]
    if missing:
        fetch_tag = "mac" if MAC else TAG
        sys.exit(f"build: bin/{TAG}/ is missing {', '.join(missing)} -- run: python fetch-helpers.py {fetch_tag}")
    paths = [os.path.join(bin_dir, n) for n in need]
    if LINUX or MAC:
        os.chmod(paths[0], 0o755)
    return paths


def check_python_deps() -> None:
    try:
        import webview  # noqa: F401
    except ImportError:
        sys.exit("build: pywebview is not installed in this Python -- pip install -r requirements.txt")
    if not MAC:
        import importlib.util
        # find_spec, not import: pystray connects to the display when imported on Linux
        if not all(importlib.util.find_spec(m) for m in ("pystray", "PIL")):
            print("WARNING: pystray / Pillow missing -- this build will have no tray icon. pip install -r requirements.txt")
    if LINUX:
        try:
            import PySide6.QtWebEngineWidgets  # noqa: F401
        except ImportError:
            sys.exit("build: PySide6 (with QtWebEngine) is missing -- pip install -r requirements.txt")
    if MAC:
        try:
            import AppKit, WebKit, objc  # noqa: F401
        except ImportError:
            sys.exit("build: PyObjC (AppKit/WebKit) is missing -- pip install -r requirements.txt")
        try:
            import CoreWLAN  # noqa: F401
        except ImportError:
            print("WARNING: pyobjc-framework-CoreWLAN is missing -- the Wi-Fi tab will fall back to system_profiler (slow, no BSSIDs)")


def git_info() -> dict:
    """Commit and branch of this source folder (empty when it is not a git checkout)."""
    def run(*args):
        try:
            r = subprocess.run(["git", *args], cwd=HERE, capture_output=True, text=True, timeout=30)
            return r.stdout.strip() if r.returncode == 0 else ""
        except (OSError, subprocess.SubprocessError):
            return ""
    return {"commit": run("rev-parse", "HEAD"), "branch": run("rev-parse", "--abbrev-ref", "HEAD"),
            "dirty": bool(run("status", "--porcelain", "--untracked-files=no"))}


def exe_in_use(path: str) -> bool:
    """Windows keeps a running exe open; opening it for writing then fails (checked before a
    two-minute PyInstaller run that would only fail at the very end)."""
    if not os.path.exists(path):
        return False
    try:
        with open(path, "r+b"):
            return False
    except PermissionError:
        return True
    except OSError:
        return False


def write_build_info(ver: str) -> str:
    """build_info.json, bundled into the executable: which commit it is and where its source and
    build Python live, so "Update LinkTest" can pull, rebuild and replace it (updater.py)."""
    info = {"version": ver, **git_info(), "source": HERE, "python": sys.executable, "tag": TAG,
            "built": time.strftime("%Y-%m-%dT%H:%M:%S")}
    path = os.path.join(WORK, "build_info.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(info, f, indent=2)
    return path


def pyinstaller_cmd(console: bool, onedir: bool, binaries: list[str]) -> list[str]:
    cmd = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
           "--onedir" if onedir else "--onefile",
           "--name", NAME, "--distpath", DIST, "--workpath", WORK, "--specpath", WORK,
           "--paths", HERE,
           "--add-data", os.path.join(HERE, "ui") + SEP + "ui",
           "--add-data", os.path.join(HERE, "CHANGELOG.md") + SEP + ".",
           "--add-data", os.path.join(WORK, "build_info.json") + SEP + ".",
           "--hidden-import", "pcaplogs", "--hidden-import", "pcapproto", "--hidden-import", "zeek_tables",
           "--hidden-import", "tray", "--hidden-import", "PIL.Image", "--hidden-import", "PIL.ImageDraw",
           "--exclude-module", "tkinter", "--exclude-module", "unittest",
           "--exclude-module", "webview.platforms.cef", "--exclude-module", "webview.platforms.android",
           "--exclude-module", "webview.platforms.mshtml"]
    if not MAC:
        cmd += ["--exclude-module", "webview.platforms.cocoa"]
    for b in binaries:
        cmd += ["--add-binary" if not b.endswith(".txt") else "--add-data", b + SEP + "bin"]
    for asset in ("linktest.png", "manuf.z", "manuf.txt"):
        ap = os.path.join(HERE, "assets", asset)
        if os.path.isfile(ap):
            cmd += ["--add-data", ap + SEP + "assets"]
        elif asset == "manuf.z":
            print("WARNING: assets/manuf.z missing -- MAC vendor names will be blank. Run: python fetch-helpers.py manuf")
    if WINDOWS:
        ico = os.path.join(HERE, "assets", "linktest.ico")
        if os.path.isfile(ico):
            cmd += ["--icon", ico, "--add-data", ico + SEP + "assets"]
        if not console:
            cmd.append("--noconsole")
        cmd += ["--hidden-import", "pystray._win32"]
        cmd += ["--hidden-import", "webview.platforms.winforms", "--hidden-import", "webview.platforms.edgechromium",
                "--hidden-import", "webview.platforms.win32", "--hidden-import", "clr",
                "--exclude-module", "webview.platforms.qt", "--exclude-module", "webview.platforms.gtk"]
    elif MAC:
        icns = os.path.join(HERE, "assets", "linktest.icns")
        if os.path.isfile(icns):
            cmd += ["--icon", icns]
        if not console:
            cmd.append("--windowed")           # makes the .app bundle
        cmd += ["--osx-bundle-identifier", BUNDLE_ID,
                "--hidden-import", "webview.platforms.cocoa", "--hidden-import", "objc",
                "--hidden-import", "AppKit", "--hidden-import", "Foundation", "--hidden-import", "WebKit",
                "--hidden-import", "Security", "--hidden-import", "PyObjCTools.AppHelper",
                "--exclude-module", "webview.platforms.qt", "--exclude-module", "webview.platforms.gtk",
                "--exclude-module", "webview.platforms.winforms", "--exclude-module", "webview.platforms.edgechromium",
                "--exclude-module", "PySide6", "--exclude-module", "PyQt5", "--exclude-module", "PyQt6"]
        for opt in ("UniformTypeIdentifiers", "CoreWLAN"):
            try:
                __import__(opt)
                cmd += ["--hidden-import", opt]
            except ImportError:
                pass
    else:
        cmd += ["--hidden-import", "webview.platforms.qt", "--hidden-import", "qtpy",
                "--hidden-import", "PySide6.QtWebEngineWidgets", "--hidden-import", "PySide6.QtWebEngineCore",
                "--hidden-import", "PySide6.QtWebChannel", "--hidden-import", "PySide6.QtNetwork",
                "--hidden-import", "PySide6.QtPrintSupport",
                "--exclude-module", "webview.platforms.gtk", "--exclude-module", "webview.platforms.winforms",
                "--exclude-module", "webview.platforms.edgechromium",
                "--hidden-import", "pystray._xorg"]
    cmd.append(os.path.join(HERE, "linktest.py"))
    return cmd


def build_here(console: bool, onedir: bool) -> int:
    ver = version()
    check_python_deps()
    print(f"Build Python: {sys.executable}")
    binaries = check_binaries()
    os.makedirs(DIST, exist_ok=True)
    os.makedirs(WORK, exist_ok=True)
    info_path = write_build_info(ver)
    out = os.path.join(DIST, NAME + (".exe" if WINDOWS else ""))
    if onedir:
        out = os.path.join(DIST, NAME, NAME + (".exe" if WINDOWS else ""))
    app_bundle = os.path.join(DIST, NAME + ".app") if MAC and not console else None
    if app_bundle:
        out = os.path.join(app_bundle, "Contents", "MacOS", NAME)
        shutil.rmtree(app_bundle, ignore_errors=True)
    if WINDOWS and exe_in_use(out):
        sys.exit(f"build: {out} is in use -- LinkTest is still running (it may be hidden in the tray by the clock).\n"
                 "       Quit it from the tray icon (right-click > Quit LinkTest) or run: taskkill /IM LinkTest.exe /F\n"
                 "       then build again.")
    before = os.path.getmtime(out) if os.path.exists(out) else 0
    print(f"Building {NAME} {ver} for {TAG} ({'onedir' if onedir else 'onefile'}) ...")
    t0 = time.time()
    code = subprocess.call(pyinstaller_cmd(console, onedir, binaries), cwd=HERE)
    if code != 0:
        sys.exit(f"PyInstaller exited {code} -- build FAILED (anything in dist/ is stale)")
    if not os.path.exists(out):
        sys.exit("build produced no binary at " + out)
    if os.path.getmtime(out) <= before:
        sys.exit("binary was not rewritten -- build FAILED, dist/ holds a stale build")
    if not WINDOWS:
        os.chmod(out, 0o755)
    if app_bundle:
        finish_mac_bundle(app_bundle, ver)
    with open(os.path.join(DIST, "VERSION.txt"), "w", encoding="utf-8") as f:
        f.write(ver + "\n")
    shutil.copyfile(info_path, os.path.join(DIST, "build.json"))   # what updater.py compares with
    write_update_launcher()
    with open(os.path.join(HERE, "bin", TAG, "LICENSE.txt"), encoding="utf-8") as src, \
            open(os.path.join(DIST, "THIRD-PARTY-LICENSES.txt"), "w", encoding="utf-8") as dst:
        dst.write(src.read())
        dst.write("\nMAC address vendor table -- Wireshark 'manuf' file\n"
                  "  https://www.wireshark.org/download/automated/data/manuf\n"
                  "  Copyright the Wireshark authors; GNU General Public License v2 (data file).\n"
                  "  Bundled as assets/manuf.z (prefix + short vendor name only); see assets/manuf.txt for the fetch date.\n")
    size = os.path.getsize(out) / 1e6
    print(f"Done in {time.time() - t0:.0f}s: {out} ({size:.0f} MB)")
    if app_bundle:
        zip_path = os.path.join(DIST, f"{NAME}-{ver}-{TAG}.zip")
        if os.path.exists(zip_path):
            os.remove(zip_path)
        # ditto keeps the bundle's attributes and signature intact, unlike a plain zip
        if subprocess.call(["ditto", "-c", "-k", "--keepParent", app_bundle, zip_path]) == 0:
            print(f"App bundle: {app_bundle}\nZip for sharing: {zip_path}")
    return 0


def write_update_launcher() -> None:
    """'Update LinkTest' next to the executable: the same update as the tray menu, in a console."""
    if WINDOWS:
        with open(os.path.join(DIST, "Update LinkTest.cmd"), "w", encoding="utf-8", newline="\r\n") as f:
            f.write("@echo off\nrem Pulls the latest LinkTest, rebuilds it and restarts it.\n"
                    f'"{sys.executable}" "{os.path.join(HERE, "updater.py")}" %*\npause\n')
    else:
        path = os.path.join(DIST, "update-linktest.sh")
        with open(path, "w", encoding="utf-8") as f:
            f.write("#!/usr/bin/env sh\n# Pulls the latest LinkTest, rebuilds it and restarts it.\n"
                    f'exec "{sys.executable}" "{os.path.join(HERE, "updater.py")}" "$@"\n')
        os.chmod(path, 0o755)


def finish_mac_bundle(app: str, ver: str) -> None:
    """Add the usage-description keys macOS wants, then ad-hoc sign the whole bundle."""
    import plistlib
    plist = os.path.join(app, "Contents", "Info.plist")
    with open(plist, "rb") as f:
        info = plistlib.load(f)
    info.update({
        "CFBundleShortVersionString": ver, "CFBundleVersion": ver,
        "CFBundleDisplayName": NAME, "LSMinimumSystemVersion": "12.0",
        "NSHighResolutionCapable": True,
        "NSLocationUsageDescription": "Wi-Fi scanning needs Location Services to show network names (macOS requirement).",
        "NSLocationWhenInUseUsageDescription": "Wi-Fi scanning needs Location Services to show network names (macOS requirement).",
        "NSLocalNetworkUsageDescription": "LinkTest tests and scans the devices on your local network.",
        "NSAppTransportSecurity": {"NSAllowsLocalNetworking": True},
    })
    with open(plist, "wb") as f:
        plistlib.dump(info, f)
    # Ad-hoc signature: lets the app run locally after "Open anyway"; use a Developer ID for distribution.
    r = subprocess.run(["codesign", "--force", "--deep", "--sign", "-", app], capture_output=True, text=True)
    if r.returncode != 0:
        print("WARNING: codesign failed: " + (r.stderr or "").strip())


def build_in_wsl(extra_args: list[str]) -> int:
    """From Windows: run this script inside WSL (Ubuntu) with the /opt/linktestbuild venv."""
    if not WINDOWS:
        sys.exit("--wsl only makes sense on Windows")
    drive, rest = os.path.splitdrive(HERE)
    src = "/mnt/" + drive[0].lower() + rest.replace("\\", "/")
    stage = "/tmp/linktest-src"
    py = f"{WSL_VENV}/bin/python"
    script = (
        f"set -e; test -x {py} || {{ echo 'missing {WSL_VENV}: python3 -m venv {WSL_VENV} && "
        f"{WSL_VENV}/bin/pip install -r requirements.txt'; exit 2; }}; "
        f"mkdir -p {stage}; rsync -a --delete --exclude dist --exclude build --exclude __pycache__ "
        f"--exclude tools/fake --exclude tools/fake-build --exclude .git '{src}/' {stage}/; "
        f"cd {stage}; {py} build.py {' '.join(extra_args)}; "
        f"mkdir -p '{src}/dist'; rm -rf '{src}/dist/linux-x86_64'; cp -r {stage}/dist/linux-x86_64 '{src}/dist/'; "
        f"ls -la '{src}/dist/linux-x86_64'"
    )
    print("Running the Linux build inside WSL ...")
    return subprocess.call(["wsl", "-e", "bash", "-lc", script])


def main() -> int:
    args = sys.argv[1:]
    console = "--console" in args
    onedir = "--onedir" in args
    if "--wsl" in args:
        code = build_in_wsl([a for a in args if a not in ("--wsl", "--console")])
        if code:
            return code
        if "--linux-only" in args:
            return 0
    return build_here(console, onedir)


if __name__ == "__main__":
    sys.exit(main())
