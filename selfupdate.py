"""Updates for copies of LinkTest that have no source folder: the newest GitHub release.

The release workflow (.github/workflows/release.yml) builds LinkTest on GitHub for every new
VERSION on main and publishes, next to the executable, a small release.json:

    {"version": "0.13.5", "commit": "...", "changes": ["...", ...],
     "assets": {"win64": {"name": "LinkTest-win64.exe", "sha256": "...", "size": 17000000}}}

Everything is fetched from github.com/<repo>/releases/latest/download/<name>, which is a plain
download (no API call), so a whole office checking every 30 minutes stays far from GitHub's
API limits. The executable is checked against the SHA-256 in release.json before it is used.

Swapping a running executable: Windows will not overwrite a running .exe but lets it be
renamed, so the running one becomes LinkTest.exe.old, the download takes its name, and the
next start deletes the .old file. Linux replaces the file in place.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import urllib.request

REPO = "OccuviteASI/LinkTest"
# LINKTEST_UPDATE_URL points a test at a local copy of the release files
LATEST = os.environ.get("LINKTEST_UPDATE_URL") or f"https://github.com/{REPO}/releases/latest/download/"
PAGE = f"https://github.com/{REPO}/releases/latest"
IS_WIN = sys.platform == "win32"


class UpdateError(RuntimeError):
    pass


def vtuple(v: str) -> tuple:
    out = []
    for part in str(v or "").lstrip("v").split("."):
        num = "".join(ch for ch in part if ch.isdigit())
        out.append(int(num) if num else 0)
    return tuple(out)


def _get(url: str, timeout: float = 30):
    req = urllib.request.Request(url, headers={"User-Agent": "LinkTest-updater", "Cache-Control": "no-cache"})
    return urllib.request.urlopen(req, timeout=timeout)


def check(current: str, tag: str) -> dict:
    """What the latest release offers this platform; never raises for network trouble."""
    try:
        with _get(LATEST + "release.json", timeout=20) as r:
            rel = json.loads(r.read().decode("utf-8"))
    except Exception as e:   # offline, proxy, no release yet ...
        code = getattr(e, "code", None)
        if code == 404:
            return {"error": "There is no LinkTest release on GitHub yet."}
        return {"error": f"Could not reach GitHub ({e})."}
    latest = str(rel.get("version") or "")
    asset = (rel.get("assets") or {}).get(tag)
    # Everything since the version this copy has (several releases may have been skipped)
    changes = []
    newer = [h for h in (rel.get("history") or []) if vtuple(h.get("version")) > vtuple(current)]
    for h in newer:
        for c in h.get("changes") or []:
            changes.append(f"{h['version']}: {c}" if len(newer) > 1 else str(c))
    if not changes:
        changes = [str(c) for c in (rel.get("changes") or [])]
    info = {"mode": "release", "latestVersion": latest, "latest": (rel.get("commit") or "")[:7],
            "changes": changes[:20], "behind": len(newer), "page": PAGE,
            "available": vtuple(latest) > vtuple(current), "problem": ""}
    if info["available"] and not asset:
        info["problem"] = f"the {latest} release has no ready-made LinkTest for this system ({tag})"
    if asset:
        info["asset"] = {"name": str(asset.get("name") or ""), "sha256": str(asset.get("sha256") or "").lower(),
                         "size": int(asset.get("size") or 0)}
    return info


def download(info: dict, exe: str, progress=None) -> str:
    """Download the new executable next to `exe` and verify it. Returns its path (exe + '.new')."""
    asset = info.get("asset") or {}
    if not asset.get("name") or len(asset.get("sha256", "")) != 64:
        raise UpdateError("the release does not say which file to download")
    new = exe + ".new"
    part = new + ".part"
    try:
        fh = open(part, "wb")
    except OSError as e:
        raise UpdateError(f"LinkTest cannot write next to itself in {os.path.dirname(exe)} ({e.strerror}). "
                          f"Move LinkTest to a folder of your own (for example Documents) and update again, "
                          f"or download the new version from {PAGE}") from e
    h = hashlib.sha256()
    done = 0
    try:
        with fh, _get(LATEST + asset["name"], timeout=60) as r:
            total = int(r.headers.get("Content-Length") or asset.get("size") or 0)
            while True:
                chunk = r.read(256 * 1024)
                if not chunk:
                    break
                fh.write(chunk)
                h.update(chunk)
                done += len(chunk)
                if progress:
                    progress(done, total)
    except Exception as e:
        _remove(part)
        if isinstance(e, UpdateError):
            raise
        raise UpdateError(f"the download stopped ({e})") from e
    if h.hexdigest() != asset["sha256"]:
        _remove(part)
        raise UpdateError("the downloaded file is damaged (its SHA-256 does not match the release); try again")
    _remove(new)
    os.replace(part, new)
    if not IS_WIN:
        os.chmod(new, 0o755)
    return new


def install(exe: str, new: str) -> None:
    """Put `new` in place of the running `exe`."""
    if IS_WIN:
        old = exe + ".old"
        _remove(old)
        try:
            os.replace(exe, old)          # a running exe can be renamed, not overwritten
        except OSError as e:
            raise UpdateError(f"Windows would not let LinkTest move its old file aside ({e.strerror})") from e
        try:
            os.replace(new, exe)
        except OSError as e:
            os.replace(old, exe)          # put the old one back
            raise UpdateError(f"could not put the new version in place ({e.strerror})") from e
    else:
        os.replace(new, exe)


def cleanup(exe: str) -> None:
    """Remove what an earlier update left behind (the old exe once it has exited)."""
    for suffix in (".old", ".new.part"):
        _remove(exe + suffix)


def _remove(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass
