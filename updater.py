#!/usr/bin/env python3
"""Update LinkTest: pull the latest code from GitHub, rebuild the executable and restart it.

    tray menu / Settings > Update LinkTest (runs this through update_gui.py: a progress window)
    "Update LinkTest.cmd" next to LinkTest.exe, or: python updater.py

Steps:
  1. git fetch the branch this source folder is on and fast-forward to it
     (local edits are never discarded; a branch that has its own commits is left alone)
  2. stop if nothing changed and the executable is already this build
  3. update the build packages when requirements.txt changed (pip)
  4. close the running LinkTest (PyInstaller cannot overwrite a running exe)
  5. build (build.py) and copy the new executable over the one that asked for the update
  6. start LinkTest again if it was running; on a failed build the old one is started again

Options:
  --check         only report whether an update is available (--json for the app)
  --force         rebuild even if nothing changed
  --no-restart    do not start LinkTest again afterwards
  --exe PATH      the executable to replace (default: dist/<platform>/LinkTest[.exe])
  --have COMMIT   the commit that executable was built from (default: read from build.json)
  --pid N --port N  the running LinkTest to close first (default: from its instance.json)
  --source        LinkTest runs from source (python linktest.py): pull and restart, no build
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
IS_WINDOWS = sys.platform == "win32"
IS_MAC = sys.platform == "darwin"
EXE_NAME = "LinkTest.exe" if IS_WINDOWS else "LinkTest"
LOCK_FILE = os.path.join(ROOT, "dist", "update.lock")
LOCK_STALE = 2 * 3600            # no update takes this long: the lock was left by a crash
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def log(msg: str) -> None:
    print(f"[update] {msg}", flush=True)


class UpdateError(RuntimeError):
    pass


def plat_tag() -> str:
    import iperf_runner
    return iperf_runner.plat_tag()


def dist_dir() -> str:
    return os.path.join(ROOT, "dist", plat_tag())


def built_exe() -> str:
    if IS_MAC:
        return os.path.join(dist_dir(), "LinkTest.app")
    return os.path.join(dist_dir(), EXE_NAME)


# ---------------------------------------------------------------------- git
def git(*args: str, check: bool = True, timeout: int = 120) -> str:
    try:
        r = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, timeout=timeout,
                           creationflags=NO_WINDOW)
    except FileNotFoundError as exc:
        raise UpdateError("git is not installed or not on PATH (install Git for Windows from git-scm.com)") from exc
    except subprocess.TimeoutExpired as exc:
        raise UpdateError(f"git {args[0]} took too long (no network?)") from exc
    if check and r.returncode != 0:
        raise UpdateError(f"git {' '.join(args)} failed: {(r.stderr or r.stdout).strip()}")
    return r.stdout.strip()


def tracking() -> tuple[str, str, str]:
    """(local branch, remote, remote branch) this checkout follows."""
    if not os.path.isdir(os.path.join(ROOT, ".git")):
        raise UpdateError(f"{ROOT} is not a git checkout, so it cannot be updated "
                          "(clone it with: git clone https://github.com/OccuviteASI/LinkTest.git)")
    branch = git("rev-parse", "--abbrev-ref", "HEAD")
    if branch == "HEAD":
        raise UpdateError("the source folder is not on a branch (detached HEAD); run: git checkout main")
    remote = git("config", f"branch.{branch}.remote", check=False) or "origin"
    merge = git("config", f"branch.{branch}.merge", check=False)
    return branch, remote, merge.removeprefix("refs/heads/") if merge else branch


def fetch() -> tuple[str, str]:
    """Fetch the followed branch; returns (local branch, 'remote/branch')."""
    branch, remote, rbranch = tracking()
    url = git("remote", "get-url", remote, check=False) or remote
    log(f"checking {url} ({rbranch}) for updates")
    git("fetch", "--quiet", remote, rbranch)
    return branch, f"{remote}/{rbranch}"


def counts(upstream: str) -> tuple[int, int]:
    """(commits behind, commits ahead) of upstream."""
    out = git("rev-list", "--left-right", "--count", f"HEAD...{upstream}")
    ahead, behind = (int(x) for x in out.split())
    return behind, ahead


def dirty() -> bool:
    return bool(git("status", "--porcelain", "--untracked-files=no"))


def check(have: str | None) -> dict:
    """What an update would bring, without changing anything."""
    branch, upstream = fetch()
    behind, ahead = counts(upstream)
    head = git("rev-parse", "HEAD")
    latest = git("rev-parse", upstream)
    changes = git("log", "--format=%h %s", "-n", "15", f"HEAD..{upstream}").splitlines() if behind else []
    version = _version_at(upstream)
    have = have or installed_build()
    rebuild = bool(have) and not latest.startswith(have[:7]) and not have.startswith(latest[:7])
    problem = ""
    if ahead and behind:
        problem = f"this source folder has {ahead} commit(s) that are not on GitHub; merge them by hand first"
    elif behind and dirty():
        problem = "the source folder has local edits; commit or undo them (git stash) first"
    return {"branch": branch, "upstream": upstream, "behind": behind, "ahead": ahead, "head": head[:7],
            "latest": latest[:7], "have": (have or "")[:7], "latestVersion": version, "changes": changes,
            "available": bool(behind) or rebuild, "problem": problem}


def _version_at(ref: str) -> str:
    import re
    src = git("show", f"{ref}:linktest.py", check=False)
    m = re.search(r'^VERSION\s*=\s*"([^"]+)"', src, re.M)
    return m.group(1) if m else ""


def pull() -> tuple[str, str]:
    """Fast-forward to the followed branch. Returns (old commit, new commit)."""
    old = git("rev-parse", "HEAD")
    _, upstream = fetch()
    behind, ahead = counts(upstream)
    if behind and ahead:
        raise UpdateError(f"the source folder has {ahead} commit(s) that are not on GitHub; merge them by hand")
    if behind and dirty():
        raise UpdateError("the source folder has local edits; commit or undo them (git stash) and update again")
    if behind:
        git("merge", "--ff-only", "--quiet", upstream)
    new = git("rev-parse", "HEAD")
    if new != old:
        log(f"updated {old[:7]} -> {new[:7]} ({behind} new commit(s))")
    else:
        log(f"source is already up to date ({new[:7]})")
    return old, new


# --------------------------------------------------------------- executable
def installed_build(exe: str | None = None) -> str:
    """The commit the default build in dist/ was made from ('' if unknown)."""
    if exe and os.path.normcase(os.path.abspath(exe)) != os.path.normcase(os.path.abspath(built_exe())):
        return ""
    try:
        with open(os.path.join(dist_dir(), "build.json"), encoding="utf-8") as f:
            return str(json.load(f).get("commit") or "")
    except (OSError, ValueError):
        return ""


def same_build(have: str, head: str) -> bool:
    return bool(have) and (head.startswith(have[:7]) or have.startswith(head[:7]))


def requirements_changed(old: str, new: str) -> bool:
    if old == new:
        return False
    return "requirements.txt" in git("diff", "--name-only", old, new, check=False).splitlines()


def deps_missing() -> bool:
    import importlib.util
    mods = ["webview", "PyInstaller"] + ([] if IS_MAC else ["pystray", "PIL"])
    return not all(importlib.util.find_spec(m) for m in mods)


def install_deps() -> None:
    log("installing build packages (pip install -r requirements.txt)")
    r = subprocess.run([sys.executable, "-m", "pip", "install", "--disable-pip-version-check", "-q",
                        "-r", os.path.join(ROOT, "requirements.txt")], cwd=ROOT, creationflags=NO_WINDOW)
    if r.returncode != 0:
        raise UpdateError("pip could not install the build packages (see the lines above)")


# ----------------------------------------------------------------- running app
def _state_dir() -> str:
    from linktest import state_dir   # same folder logic as the app
    return state_dir()


def running_instance() -> tuple[int | None, int | None]:
    """(pid, port) of the LinkTest that is running now, from its instance.json."""
    try:
        with open(os.path.join(_state_dir(), "instance.json"), encoding="utf-8") as f:
            info = json.load(f)
        return int(info.get("pid") or 0) or None, int(info.get("port") or 0) or None
    except (OSError, ValueError, TypeError, ImportError):
        return None, None


def pid_alive(pid: int) -> bool:
    if IS_WINDOWS:
        import ctypes
        k32 = ctypes.windll.kernel32
        h = k32.OpenProcess(0x00100000 | 0x1000, False, pid)   # SYNCHRONIZE | QUERY_LIMITED_INFORMATION
        if not h:
            return False
        try:
            return k32.WaitForSingleObject(h, 0) == 0x102       # WAIT_TIMEOUT: still running
        finally:
            k32.CloseHandle(h)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    try:   # a zombie (our own child that already exited) counts as gone
        with open(f"/proc/{pid}/stat") as f:
            return f.read().split(") ", 1)[1][:1] != "Z"
    except (OSError, IndexError):
        return True


def stop_app(pid: int | None, port: int | None) -> bool:
    """Ask the running LinkTest to quit (it stops captures and saves state), kill it if it will not."""
    if not pid or not pid_alive(pid):
        return False
    log(f"closing the running LinkTest (pid {pid}) so it can be replaced")
    if port:
        try:
            req = urllib.request.Request(f"http://127.0.0.1:{port}/api/quit", data=b"{}", method="POST",
                                         headers={"Content-Type": "application/json", "X-LinkTest": "update"})
            urllib.request.urlopen(req, timeout=5).read()
        except Exception:
            pass
    for _ in range(40):
        if not pid_alive(pid):
            break
        time.sleep(0.5)
    else:
        log("LinkTest did not close by itself; ending it")
        if IS_WINDOWS:
            subprocess.run(["taskkill", "/PID", str(pid), "/F", "/T"], capture_output=True, creationflags=NO_WINDOW)
        else:
            try:
                os.kill(pid, 9)
            except ProcessLookupError:
                pass
        for _ in range(20):
            if not pid_alive(pid):
                break
            time.sleep(0.5)
    time.sleep(1.5 if IS_WINDOWS else 0.2)   # one-file exes: let the bootloader exit and Windows release the file
    return True


def app_env() -> dict:
    """Our environment minus PyInstaller bootloader leftovers (when started by a frozen LinkTest):
    a LinkTest started with another one's _PYI_* variables refuses to run."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("_PYI") and k != "_MEIPASS2"}
    env["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
    return env


START_LOG = os.path.join(ROOT, "dist", "update-start.log")


def start_app(cmd: list[str], old_pid: int | None = None) -> bool:
    """Start LinkTest and wait until it answers; its output goes to dist/update-start.log."""
    log("starting " + " ".join(cmd))
    os.makedirs(os.path.dirname(START_LOG), exist_ok=True)
    out = open(START_LOG, "wb")
    quiet = dict(env=app_env(), stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
                 cwd=os.path.dirname(cmd[-1]) if len(cmd) > 1 else os.path.dirname(cmd[0]) or None)
    try:
        if IS_WINDOWS:
            flags = 0x00000008 | 0x00000200   # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
            proc = subprocess.Popen(cmd, creationflags=flags, **quiet)
        elif IS_MAC and cmd[0].endswith(".app"):
            proc = subprocess.Popen(["open", "-n", cmd[0]], **quiet)
        else:
            proc = subprocess.Popen(cmd, start_new_session=True, **quiet)
    finally:
        out.close()
    for _ in range(90):
        time.sleep(0.5)
        pid, port = running_instance()
        if pid and pid != old_pid and port and _answers(port):
            return True
        if proc.poll() is not None and not (IS_MAC and cmd[0].endswith(".app")):
            break
    try:
        with open(START_LOG, encoding="utf-8", errors="replace") as f:
            tail = [ln.rstrip() for ln in f.readlines()[-8:] if ln.strip()]
    except OSError:
        tail = []
    for ln in tail:
        log("  " + ln)
    log(f"WARNING: LinkTest did not come back after the update; start it by hand (its output: {START_LOG})")
    return False


def _answers(port: int) -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/ping", timeout=2) as r:
            return json.loads(r.read().decode()).get("app") == "LinkTest"
    except Exception:
        return False


def install(src: str, dest: str) -> None:
    """Copy the new build over the old executable (retrying while Windows still holds the file)."""
    log(f"installing the new version to {dest}")
    last = None
    for _ in range(20):
        try:
            if os.path.isdir(src):        # macOS .app bundle
                tmp = dest + ".new"
                shutil.rmtree(tmp, ignore_errors=True)
                shutil.copytree(src, tmp, symlinks=True)
                shutil.rmtree(dest, ignore_errors=True)
                os.replace(tmp, dest)
            else:
                tmp = dest + ".new"
                shutil.copy2(src, tmp)
                os.replace(tmp, dest)
            return
        except OSError as exc:
            last = exc
            time.sleep(0.5)
    raise UpdateError(f"could not replace {dest}: {last}")


# --------------------------------------------------------------------- lock
def acquire_lock() -> bool:
    os.makedirs(os.path.dirname(LOCK_FILE), exist_ok=True)
    for _ in range(2):
        try:
            fd = os.open(LOCK_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            try:
                if time.time() - os.path.getmtime(LOCK_FILE) < LOCK_STALE:
                    return False
                os.remove(LOCK_FILE)
            except FileNotFoundError:
                pass
            continue
        with os.fdopen(fd, "w") as f:
            f.write(str(os.getpid()))
        return True
    return False


def release_lock() -> None:
    try:
        os.remove(LOCK_FILE)
    except FileNotFoundError:
        pass


# --------------------------------------------------------------------- main
def run_update(a: argparse.Namespace) -> int:
    try:
        old, head = pull()
    except UpdateError as exc:
        log(f"UPDATE FAILED: {exc}")
        return 1
    pid, port = a.pid, a.port
    if not pid:
        pid, port = running_instance()

    if a.source:
        if old == head and not a.force:
            log(f"LinkTest is already build {head[:7]}: nothing to do")
            return 0
        was = stop_app(pid, port)
        if was and not a.no_restart:
            start_app([sys.executable, os.path.join(ROOT, "linktest.py")], pid)
        log(f"UPDATE OK: LinkTest is now build {head[:7]}")
        return 0

    target = os.path.abspath(a.exe) if a.exe else built_exe()
    have = a.have or installed_build(target)
    if same_build(have, head) and not a.force and os.path.exists(target):
        log(f"LinkTest is already build {head[:7]}: nothing to do")
        return 0
    log(f"installed build: {have[:7] if have else 'unknown'}; building {head[:7]}")
    try:
        if requirements_changed(old, head) or deps_missing():
            install_deps()
    except UpdateError as exc:
        log(f"UPDATE FAILED: {exc}")
        return 1

    was = stop_app(pid, port)
    restart = [target]
    log("building LinkTest (a minute or two)")
    code = subprocess.call([sys.executable, os.path.join(ROOT, "build.py")], cwd=ROOT, creationflags=NO_WINDOW)
    built = built_exe()
    ok = code == 0 and os.path.exists(built) and same_build(installed_build(built), head)
    if ok and os.path.normcase(target) != os.path.normcase(os.path.abspath(built)):
        try:
            install(built, target)
        except UpdateError as exc:
            log(f"UPDATE FAILED: {exc}")
            ok = False
            code = code or 1
    if not ok:
        log("UPDATE FAILED: the build did not succeed (see the messages above); LinkTest keeps the previous version")
        if was and os.path.exists(target) and not a.no_restart:
            start_app(restart, pid)
        return code or 1
    if was and not a.no_restart and not start_app(restart, pid):
        log(f"UPDATE FAILED: LinkTest {head[:7]} was built and installed but did not start (see the lines above)")
        return 4
    log(f"UPDATE OK: LinkTest is now build {head[:7]} ({_version_at('HEAD') or '?'})")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--no-restart", action="store_true")
    ap.add_argument("--exe")
    ap.add_argument("--have")
    ap.add_argument("--pid", type=int)
    ap.add_argument("--port", type=int)
    ap.add_argument("--source", action="store_true")
    a = ap.parse_args(argv)

    if a.check:
        try:
            info = check(a.have)
        except UpdateError as exc:
            info = {"error": str(exc)}
        if a.json:
            print(json.dumps(info))
        else:
            for k, v in info.items():
                print(f"{k}: {v}")
        return 0 if "error" not in info else 1

    if not acquire_lock():
        log(f"UPDATE FAILED: another update is already running (if it is not, delete {LOCK_FILE})")
        return 3
    try:
        return run_update(a)
    finally:
        release_lock()


if __name__ == "__main__":
    sys.exit(main())
