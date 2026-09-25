"""LinkTest - a friendly window around iperf3.

Run `python linktest.py`. It starts a tiny local web server on 127.0.0.1 and
shows the UI in its own native window (pywebview: WebView2 on Windows, Qt on
Linux). The app exits when the last window closes. `--browser` opens a normal
browser tab instead (no third-party packages needed), `--no-open` just serves.
All the iperf3 work is in iperf_runner.py; the bundled iperf3 lives in bin/.
"""
from __future__ import annotations

import argparse
import base64
import json
import mimetypes
import os
import platform
import re
import socket
import sys
import threading
import time
import urllib.request
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import iperf_runner as ir
import nettools as nt
import pcaptool as pc
import wifiscan as ws

APP_NAME = "LinkTest"
VERSION = "0.10.0"
IS_WIN = os.name == "nt"
IS_LINUX = sys.platform.startswith("linux")
IS_MAC = sys.platform == "darwin"
WINDOW_SIZE = (1160, 940)
WINDOW_MIN = (820, 600)
HEARTBEAT_GRACE = 90  # browser mode only: seconds without a heartbeat before closing


def resource_dir() -> str:
    """Where ui/ and assets/ live (PyInstaller unpacks data files under sys._MEIPASS)."""
    return ir.resource_dir()


def state_dir() -> str:
    if IS_WIN:
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        d = os.path.join(base, APP_NAME)
    elif sys.platform == "darwin":
        d = os.path.expanduser(f"~/Library/Application Support/{APP_NAME}")
    else:
        d = os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"),
                         APP_NAME.lower())
    os.makedirs(d, exist_ok=True)
    return d


def downloads_dir() -> str:
    d = os.path.join(os.path.expanduser("~"), "Downloads")
    return d if os.path.isdir(d) else os.path.expanduser("~")


def read_json(path: str, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def write_json(path: str, data) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1)
    os.replace(tmp, path)


# ----------------------------------------------------------------------------
# Application state shared by all request handlers
# ----------------------------------------------------------------------------
class App:
    def __init__(self, windowed: bool):
        self.state_dir = state_dir()
        self.settings_path = os.path.join(self.state_dir, "settings.json")
        self.history_path = os.path.join(self.state_dir, "history.json")
        self.settings = read_json(self.settings_path, {})
        self.history = read_json(self.history_path, [])
        if not isinstance(self.history, list):
            self.history = []
        self.lock = threading.Lock()
        self.runner = ir.Runner()
        self.runner.on_result = self._on_result
        self.windowed = windowed
        self.windows: list = []          # live pywebview windows
        self.url = ""
        self.last_heartbeat = None
        self.server: ThreadingHTTPServer | None = None
        self.started = time.time()
        self._shutting_down = False
        self._iperf_cache = None
        self._iperf_cache_key = None
        self._firewall = None
        self._firewall_checked = False
        # Network tools
        self.pinger = nt.make_pinger()
        self.netinfo = nt.NetInfo()
        self.vendors = nt.MacVendors()
        self.dns = nt.DnsClient(self.netinfo)
        self.scanner = nt.Scanner(self.pinger, self.netinfo, self.dns, self.vendors)
        self.monitor = nt.PingMonitor(self.pinger, os.path.join(self.state_dir, "pings"),
                                      self.settings, self.save_settings, dns=self.dns)
        self.capture = pc.CaptureSession(self.state_dir, VERSION, self.settings, self.save_settings, self.netinfo,
                                         os.path.abspath(__file__))
        self.wifi = ws.WifiScanner(self.vendors)

    # -- iperf3 discovery ----------------------------------------------------
    def iperf_info(self, refresh: bool = False) -> dict:
        custom = self.settings.get("iperfPath") or None
        path = ir.find_iperf(self.state_dir, custom)
        key = (path, os.path.getmtime(path) if path else None)
        if not refresh and self._iperf_cache and self._iperf_cache_key == key:
            return self._iperf_cache
        info = {"found": False, "path": path, "version": None, "features": {},
                "searched": ir.candidate_paths(self.state_dir, custom), "customPath": custom,
                "bundled": ir.bundled_iperf_path()}
        if path:
            problem = ir.companions_ok(path)
            ver = None if problem else ir.iperf_version(path)
            if ver:
                info.update(found=True, version=ver[0], features=ir.features_for(ver[1]))
            else:
                info["error"] = problem or "iperf3 was found but would not start."
        self._iperf_cache, self._iperf_cache_key = info, key
        return info

    def firewall_backend(self) -> str | None:
        if not self._firewall_checked:
            self._firewall = ir.firewall_backend()
            self._firewall_checked = True
        return self._firewall

    # -- persistence ---------------------------------------------------------
    def save_settings(self):
        write_json(self.settings_path, self.settings)

    def save_history(self):
        write_json(self.history_path, self.history[-300:])

    def _on_result(self, summary: dict):
        """Runner callback: store a finished test in history."""
        intervals = []
        for e in reversed(self.runner.since(0)):
            if e["type"] == "start":
                break
            if e["type"] == "interval" and not e.get("omitted"):
                intervals.append({k: e.get(k) for k in
                                  ("t0", "t1", "bps", "bytes", "retransmits", "jitter_ms",
                                   "lost_packets", "packets", "lost_percent", "reverse")
                                  if e.get(k) is not None})
        intervals.reverse()
        entry = {
            "id": uuid.uuid4().hex[:12], "ts": time.time(),
            "mode": self.runner.mode, "opts": self.runner.opts, "cmd": self.runner.cmd,
            "summary": summary, "intervals": intervals,
            "iperfVersion": (self._iperf_cache or {}).get("version"),
            "host": socket.gethostname(),
        }
        with self.lock:
            self.history.append(entry)
            self.save_history()

    # -- native window helpers -------------------------------------------------
    def on_window_closed(self, win):
        try:
            self.windows.remove(win)
        except ValueError:
            pass

    def request_new_window(self) -> bool:
        if not self.windowed or not self.url:
            return False
        open_native_window(self, self.url)
        return True

    def _save_dialog(self, name: str) -> str | None:
        import webview  # available whenever windowed
        win = self.windows[-1] if self.windows else None
        if win is None:
            raise RuntimeError("No window is open.")
        ext = os.path.splitext(name)[1].lower()
        types = {".csv": ("CSV files (*.csv)", "All files (*.*)"),
                 ".json": ("JSON files (*.json)", "All files (*.*)"),
                 ".txt": ("Text files (*.txt)", "All files (*.*)"),
                 ".pcapng": ("Capture files (*.pcapng)", "All files (*.*)"),
                 ".log": ("Zeek logs (*.log)", "All files (*.*)"),
                 ".zip": ("Zip archives (*.zip)", "All files (*.*)")}.get(ext, ("All files (*.*)",))
        res = win.create_file_dialog(webview.FileDialog.SAVE, directory=downloads_dir(),
                                     save_filename=name, file_types=types)
        if not res:
            return None
        path = res[0] if isinstance(res, (list, tuple)) else str(res)
        return path or None

    def export_file(self, name: str, text: str) -> str | None:
        """Native Save dialog on the newest window; returns the written path or None."""
        path = self._save_dialog(name)
        if not path:
            return None
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(text)
        return path

    def export_path(self, name: str, src: str) -> str | None:
        """Native Save dialog, then copy an existing file there."""
        import shutil
        path = self._save_dialog(name)
        if not path:
            return None
        shutil.copyfile(src, path)
        return path

    def open_dialog(self, file_types: tuple) -> str | None:
        import webview
        win = self.windows[-1] if self.windows else None
        if win is None:
            raise RuntimeError("No window is open.")
        res = win.create_file_dialog(webview.FileDialog.OPEN, directory=downloads_dir(), allow_multiple=False,
                                     file_types=file_types)
        if not res:
            return None
        path = res[0] if isinstance(res, (list, tuple)) else str(res)
        return path or None

    # -- lifecycle -----------------------------------------------------------
    def heartbeat(self):
        self.last_heartbeat = time.time()

    def shutdown(self):
        if self._shutting_down:
            return
        self._shutting_down = True
        self.stop_tools()
        srv = self.server
        if srv:
            threading.Thread(target=srv.shutdown, daemon=True).start()
        threading.Timer(2.0, lambda: os._exit(0)).start()

    def stop_tools(self):
        for fn in (self.runner.stop, self.scanner.stop, self.capture.stop, self.wifi.stop, self.monitor.stop_all):
            try:
                fn()
            except Exception:
                pass

    def watch(self):
        """Browser mode only: close the app when the tab has gone away for a while."""
        while not self._shutting_down:
            time.sleep(2)
            if self.runner.running():
                continue
            if self.last_heartbeat and time.time() - self.last_heartbeat > HEARTBEAT_GRACE:
                self.shutdown()
                return


# ----------------------------------------------------------------------------
# HTTP handler
# ----------------------------------------------------------------------------
_NAME_RE = re.compile(r"[A-Za-z0-9._ -]{1,120}")


class Handler(BaseHTTPRequestHandler):
    app: App = None  # type: ignore[assignment]
    server_version = f"{APP_NAME}/{VERSION}"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # quiet unless --verbose
        if getattr(self.server, "verbose", False):
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    # -- helpers -------------------------------------------------------------
    def _json(self, obj, status=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0:
            return {}
        try:
            data = json.loads(self.rfile.read(n).decode("utf-8"))
        except ValueError:
            return {}
        return data if isinstance(data, dict) else {}

    def _static(self, rel: str):
        root = os.path.join(resource_dir(), "ui")
        path = os.path.normpath(os.path.join(root, rel.lstrip("/")))
        if not path.startswith(os.path.normpath(root)) or not os.path.isfile(path):
            self.send_error(404)
            return
        ctype = mimetypes.guess_type(path)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript", "application/json"):
            ctype += "; charset=utf-8"
        with open(path, "rb") as f:
            body = f.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _status(self) -> dict:
        app = self.app
        return {
            "app": {"name": APP_NAME, "version": VERSION, "platform": platform.system(),
                    "stateDir": app.state_dir, "windowed": app.windowed, "isWindows": IS_WIN,
                    "isLinux": IS_LINUX, "isMac": IS_MAC, "firewall": app.firewall_backend()},
            "iperf": app.iperf_info(),
            "net": ir.local_addresses(),
            "runner": app.runner.state(),
            "tools": {"pinger": getattr(app.pinger, "name", None), "scanRunning": app.scanner.running(),
                      "pingTargets": len(app.monitor.targets), "hopWorkers": app.monitor.hop_workers,
                      "vendors": app.vendors.available, "captureRunning": app.capture.running()},
        }

    # -- routes --------------------------------------------------------------
    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        p = u.path
        app = self.app
        if p == "/" or p == "/index.html":
            return self._static("index.html")
        if p.startswith("/ui/"):
            return self._static(p[4:])
        if p == "/api/ping":
            return self._json({"app": APP_NAME, "version": VERSION})
        if p == "/api/status":
            return self._json(self._status())
        if p == "/api/events":
            try:
                since = int(q.get("since", ["0"])[0])
            except ValueError:
                since = 0
            return self._json({"events": app.runner.since(since), "seq": app.runner.seq,
                               "running": app.runner.running()})
        if p == "/api/settings":
            return self._json({"settings": app.settings})
        if p == "/api/history":
            with app.lock:
                hist = list(reversed(app.history))
            return self._json({"history": hist})
        # -- network tools --
        try:
            if p == "/api/net/info":
                if q.get("refresh"):
                    app.netinfo.refresh()
                return self._json({"interfaces": app.netinfo.interfaces(), "dnsServers": app.netinfo.dns_servers(),
                                   "default": app.netinfo.default_scan_range(),
                                   "pinger": getattr(app.pinger, "name", None),
                                   "defaultPorts": [{"port": k, "name": v} for k, v in nt.DEFAULT_PORTS.items()],
                                   "portPresets": nt.port_presets(),
                                   "portNames": nt.PORT_NAMES})
            if p == "/api/scan/events":
                since = int(q.get("since", ["0"])[0] or 0)
                return self._json({"events": app.scanner.log.since(since), "seq": app.scanner.log.seq,
                                   "running": app.scanner.running()})
            if p == "/api/scan/state":
                return self._json(app.scanner.state())
            if p == "/api/scan/csv":
                return self._json({"name": f"LinkTest-scan-{time.strftime('%Y-%m-%d-%H-%M')}.csv", "text": app.scanner.csv()})
            if p == "/api/pings/targets":
                n = int(q.get("recent", ["2000"])[0] or 2000)
                return self._json({"targets": [{**t.stats(hop_samples=True), "recent": t.recent(n)} for t in
                                               app.monitor.sorted_targets()],
                                   "seq": app.monitor.log.seq, "outageThreshold": app.monitor.outage_threshold,
                                   "retentionDays": app.monitor.retention_days})
            if p == "/api/pings/samples":
                since = int(q.get("since", ["0"])[0] or 0)
                return self._json({"events": app.monitor.log.since(since), "seq": app.monitor.log.seq,
                                   "stats": app.monitor.snapshot()})
            if p == "/api/pings/history":
                return self._json(app.monitor.history(q.get("id", [""])[0], float(q.get("hours", ["1"])[0])))
            if p == "/api/pings/csv":
                tid = q.get("id", [""])[0]
                days = int(q.get("days", ["1"])[0] or 1)
                t = app.monitor.get(tid)
                safe = re.sub(r"[^A-Za-z0-9._-]+", "-", t.label or t.host)[:40]
                return self._json({"name": f"LinkTest-ping-{safe}-{time.strftime('%Y-%m-%d')}.csv",
                                   "text": app.monitor.csv_export(tid, days)})
            if p == "/api/dns/servers":
                return self._json({**app.dns.servers(), "custom": app.settings.get("dnsCustomServers") or []})
            if p == "/api/arp":
                with app.scanner.lock:
                    hosts = dict(app.scanner.hosts)
                rep = nt.arp_report(app.netinfo, app.vendors, hosts)
                rep["commands"] = nt.arp_command_templates()
                rep["isAdmin"] = nt._is_admin()
                return self._json(rep)
            # -- wi-fi --
            if p == "/api/wifi/state":
                if q.get("start"):
                    app.wifi.start()
                return self._json(app.wifi.state())
            if p == "/api/wifi/history":
                ids = [b.strip().lower() for b in q.get("bssid", [""])[0].split(",") if b.strip()][:12]
                return self._json({"history": app.wifi.history_for(ids)})
            if p == "/api/wifi/csv":
                return self._json({"name": f"LinkTest-wifi-{time.strftime('%Y-%m-%d-%H-%M')}.csv", "text": app.wifi.csv()})
            if p == "/api/changelog":
                path = os.path.join(resource_dir(), "CHANGELOG.md")
                try:
                    with open(path, encoding="utf-8") as f:
                        text = f.read()
                except OSError:
                    text = "Release notes are not available in this build."
                return self._json({"version": VERSION, "markdown": text})
            # -- packet capture --
            if p == "/api/pcap/interfaces":
                return self._json({"interfaces": app.capture.interfaces(), "engines": app.capture.engine_info(),
                                   "last": app.settings.get("captureOpts") or {}})
            if p == "/api/pcap/status":
                since = int(q.get("since", ["0"])[0] or 0)
                return self._json({"events": app.capture.log.since(since), "state": app.capture.state()})
            if p == "/api/pcap/list":
                return self._json({"captures": app.capture.list(), "wireshark": bool(pc.find_wireshark())})
            if p == "/api/pcap/stats":
                return self._json(app.capture.stats(q.get("id", [""])[0]))
            if p == "/api/pcap/packets":
                g = lambda k, d="": q.get(k, [d])[0]
                return self._json(app.capture.packets(g("id"), proto=g("proto"), host=g("host"), port=g("port") or None, q=g("q"),
                                                      conn=g("conn"), offset=max(0, int(g("offset", "0") or 0)),
                                                      limit=max(1, min(500, int(g("limit", "500") or 500)))))
            if p == "/api/pcap/analysis":
                return self._json(app.capture.analysis(q.get("id", [""])[0]))
            if p == "/api/pcap/log":
                g = lambda k, d="": q.get(k, [d])[0]
                return self._json(app.capture.log_rows(g("id"), g("log", "conn"), q=g("q"), uid=g("uid"), sort=g("sort"),
                                                       desc=g("desc") == "1", offset=max(0, int(g("offset", "0") or 0)),
                                                       limit=max(1, min(1000, int(g("limit", "200") or 200)))))
            if p == "/api/pcap/log-text":
                g = lambda k, d="": q.get(k, [d])[0]
                cid, log, fmt = g("id"), g("log", "conn"), g("fmt", "zeek")
                e = app.capture.entry(cid)
                safe = re.sub(r"[^A-Za-z0-9._-]+", "-", e.get("name") or cid)[:50]
                ext = "json" if fmt == "json" else "log"
                return self._json({"name": f"{safe}-{log}.{ext}", "text": app.capture.log_text(cid, log, fmt)})
            if p == "/api/pcap/packet":
                return self._json(app.capture.packet(q.get("id", [""])[0], int(q.get("n", ["0"])[0] or 0)))
            if p == "/api/pcap/csv":
                g = lambda k, d="": q.get(k, [d])[0]
                cid = g("id")
                e = app.capture.entry(cid)
                safe = re.sub(r"[^A-Za-z0-9._-]+", "-", e.get("name") or cid)[:50]
                return self._json({"name": f"{safe}.csv", "text": app.capture.csv(cid, proto=g("proto"), host=g("host"), port=g("port") or None,
                                                                                  q=g("q"), conn=g("conn"))})
        except ValueError as e:
            return self._json({"error": str(e)}, 400)
        except Exception as e:
            return self._json({"error": f"Unexpected problem: {e}"}, 500)
        self.send_error(404)

    def do_POST(self):
        p = urlparse(self.path).path
        app = self.app
        body = self._body()
        try:
            if p == "/api/heartbeat":
                app.heartbeat()
                return self._json({"ok": True})
            if p == "/api/start":
                info = app.iperf_info()
                if not info["found"]:
                    return self._json({"error": "iperf3 could not be started. See the setup box at the top."}, 400)
                opts = body.get("opts") or {}
                app.runner.start(info["path"], opts, info["features"], retry=body.get("retry"))
                app.settings["lastOpts"] = opts
                host = str(opts.get("host", "")).strip()
                if opts.get("mode", "client") == "client" and host and not body.get("skipRecent"):
                    # skipRecent: the UI sets it for the built-in public servers so they stay out of the Recent chips
                    recent = [h for h in (app.settings.get("recentHosts") or []) if h.lower() != host.lower()]
                    app.settings["recentHosts"] = ([host] + recent)[:5]
                app.save_settings()
                return self._json({"ok": True, "cmd": app.runner.cmd})
            if p == "/api/stop":
                return self._json({"ok": True, "stopped": app.runner.stop()})
            if p == "/api/preview":
                info = app.iperf_info()
                exe = info["path"] or ir.EXE
                try:
                    args = ir.build_args(body.get("opts") or {}, info.get("features") or
                                         ir.features_for((3, 17, 0)))
                except ValueError as e:
                    return self._json({"error": str(e)})
                return self._json({"cmd": ir.quote_cmd([os.path.basename(exe)] + args)})
            if p == "/api/settings":
                patch = body.get("patch") or {}
                app.settings.update(patch)
                app.save_settings()
                return self._json({"settings": app.settings})
            if p == "/api/history/delete":
                hid = body.get("id")
                with app.lock:
                    app.history = [h for h in app.history if h.get("id") != hid]
                    app.save_history()
                return self._json({"ok": True})
            if p == "/api/history/rename":
                hid = body.get("id")
                label = str(body.get("label") or "").strip()[:80]
                with app.lock:
                    for h in app.history:
                        if h.get("id") == hid:
                            if label:
                                h["label"] = label
                            else:
                                h.pop("label", None)
                            break
                    else:
                        return self._json({"error": "That test no longer exists."}, 404)
                    app.save_history()
                return self._json({"ok": True, "label": label})
            if p == "/api/history/clear":
                with app.lock:
                    app.history = []
                    app.save_history()
                return self._json({"ok": True})
            if p == "/api/iperf/path":
                path = str(body.get("path") or "").strip().strip('"')
                if path and os.path.isdir(path):
                    path = os.path.join(path, ir.EXE)
                if not path or not os.path.isfile(path):
                    return self._json({"error": "That file does not exist."}, 400)
                if not ir.iperf_version(path):
                    return self._json({"error": "That file does not look like a working iperf3."}, 400)
                app.settings["iperfPath"] = path
                app.save_settings()
                return self._json({"ok": True, "iperf": app.iperf_info(refresh=True)})
            if p == "/api/iperf/forget":
                app.settings.pop("iperfPath", None)
                app.save_settings()
                return self._json({"ok": True, "iperf": app.iperf_info(refresh=True)})
            if p == "/api/firewall":
                try:
                    port = int(body.get("port") or 5201)
                except ValueError:
                    port = 5201
                return self._json({"ok": True, "result": ir.add_firewall_rules(port)})
            if p == "/api/window":
                return self._json({"ok": app.request_new_window()})
            if p == "/api/export":
                name = str(body.get("name") or "").strip()
                text = body.get("text")
                if not _NAME_RE.fullmatch(name) or not isinstance(text, str):
                    return self._json({"error": "Bad export request."}, 400)
                if len(text) > 50_000_000:
                    return self._json({"error": "That report is too large to save."}, 400)
                if not app.windowed:
                    return self._json({"error": "not-windowed"}, 400)
                path = app.export_file(name, text)
                if path is None:
                    return self._json({"ok": False, "cancelled": True})
                return self._json({"ok": True, "path": path})
            # -- network tools --
            if p == "/api/scan/start":
                res = app.scanner.start(body)
                app.settings.update(scanRange=body.get("range", ""), scanPorts=app.scanner.opts["ports"],
                                    scanOpts={k: app.scanner.opts[k] for k in ("timeoutMs", "retries", "resolveNames", "portsOnSilent")})
                app.save_settings()
                return self._json({"ok": True, **res})
            if p == "/api/scan/stop":
                return self._json({"ok": True, "stopped": app.scanner.stop()})
            if p == "/api/pings/add":
                return self._json({"ok": True, "target": app.monitor.add(body)})
            if p == "/api/pings/remove":
                app.monitor.remove(str(body.get("id", "")), delete_files=bool(body.get("deleteFiles", True)))
                return self._json({"ok": True})
            if p == "/api/pings/pause":
                return self._json({"ok": True, "target": app.monitor.pause(str(body.get("id", "")), bool(body.get("paused", True)))})
            if p == "/api/pings/update":
                return self._json({"ok": True, "target": app.monitor.update(str(body.get("id", "")), body)})
            if p == "/api/pings/clear":
                return self._json({"ok": True, "target": app.monitor.clear(str(body.get("id", "")))})
            if p == "/api/pings/reorder":
                ids = body.get("ids")
                if not isinstance(ids, list):
                    return self._json({"error": "Bad reorder request."}, 400)
                return self._json({"ok": True, "targets": app.monitor.reorder(ids)})
            if p == "/api/arp/cmd":
                return self._json(nt.arp_command(str(body.get("action", "")), body.get("ip"), body.get("mac"), app.netinfo))
            if p == "/api/arp/lookup":
                with app.scanner.lock:
                    hosts = dict(app.scanner.hosts)
                return self._json({"ok": True, **nt.arp_lookup(str(body.get("q", "")), app.netinfo, app.vendors, app.pinger, app.dns, hosts)})
            # -- wi-fi --
            if p == "/api/wifi/start":
                app.wifi.start()
                return self._json({"ok": True, "running": app.wifi.running(), "error": app.wifi.error or app.wifi.backend_error})
            if p == "/api/wifi/stop":
                app.wifi.stop()
                return self._json({"ok": True})
            if p == "/api/wifi/rescan":
                app.wifi.rescan()
                return self._json({"ok": True})
            # -- packet capture --
            if p == "/api/pcap/start":
                return self._json({"ok": True, **app.capture.start(body)})
            if p == "/api/pcap/stop":
                return self._json({"ok": True, "stopped": app.capture.stop()})
            if p == "/api/pcap/open":
                if body.get("path"):
                    e = app.capture.open_external(str(body["path"]))
                else:
                    e = app.capture.entry(str(body.get("id", "")))
                return self._json({"ok": True, "capture": app.capture.stats(e["id"])})
            if p == "/api/pcap/rename":
                return self._json({"ok": True, "capture": app.capture.rename(str(body.get("id", "")), str(body.get("name", "")))})
            if p == "/api/pcap/delete":
                app.capture.delete(str(body.get("id", "")))
                return self._json({"ok": True})
            if p == "/api/pcap/wireshark":
                return self._json({"ok": app.capture.open_in_wireshark(str(body.get("id", "")))})
            if p == "/api/pcap/import":
                if not app.windowed:
                    return self._json({"error": "not-windowed"}, 400)
                path = app.open_dialog(("Capture files (*.pcapng;*.pcap;*.cap)", "All files (*.*)"))
                if not path:
                    return self._json({"ok": False, "cancelled": True})
                e = app.capture.open_external(path)
                return self._json({"ok": True, "capture": app.capture.stats(e["id"])})
            if p == "/api/pcap/export":
                cid = str(body.get("id", ""))
                e = app.capture.entry(cid)
                if not app.windowed:
                    return self._json({"error": "not-windowed", "path": app.capture.path_for(cid)}, 400)
                safe = re.sub(r"[^A-Za-z0-9._ -]+", "-", e.get("name") or cid)[:60]
                path = app.export_path(safe + ".pcapng", app.capture.path_for(cid))
                if path is None:
                    return self._json({"ok": False, "cancelled": True})
                return self._json({"ok": True, "path": path})
            if p == "/api/pcap/analyze":
                return self._json({"ok": True, **app.capture.analyze(str(body.get("id", "")), bool(body.get("force")))})
            if p == "/api/pcap/logs-export":
                cid = str(body.get("id", ""))
                fmt = "json" if body.get("format") == "json" else "zeek"
                e = app.capture.entry(cid)
                zpath = app.capture.logs_zip(cid, fmt)
                safe = re.sub(r"[^A-Za-z0-9._ -]+", "-", e.get("name") or cid)[:60]
                name = f"{safe}-{'zeek' if fmt == 'zeek' else 'json'}-logs.zip"
                if not app.windowed:
                    with open(zpath, "rb") as f:
                        data = base64.b64encode(f.read()).decode()
                    return self._json({"ok": True, "name": name, "b64": data, "path": zpath})
                path = app.export_path(name, zpath)
                if path is None:
                    return self._json({"ok": False, "cancelled": True})
                return self._json({"ok": True, "path": path})
            if p == "/api/pings/collapse":
                return self._json({"ok": True, "targets": app.monitor.set_collapsed_all(bool(body.get("collapsed", True)))})
            if p == "/api/dns/lookup":
                servers = body.get("servers")
                if servers is not None and not isinstance(servers, list):
                    servers = None
                if servers:
                    servers = [str(s).strip() for s in servers if str(s).strip()][:6]
                res = app.dns.lookup(str(body.get("name", "")), str(body.get("type") or "A"), servers or None)
                app.settings["dnsLastType"] = str(body.get("type") or "A")
                custom = body.get("custom")
                if isinstance(custom, list):
                    app.settings["dnsCustomServers"] = [str(s).strip() for s in custom if str(s).strip()][:10]
                app.save_settings()
                return self._json({"ok": True, **res})
            if p == "/api/quit":
                self._json({"ok": True})
                app.shutdown()
                return
        except ValueError as e:
            return self._json({"error": str(e)}, 400)
        except RuntimeError as e:
            return self._json({"error": str(e)}, 400)
        except Exception as e:  # keep the UI informed rather than dropping the socket
            return self._json({"error": f"Unexpected problem: {e}"}, 500)
        self.send_error(404)


class QuietServer(ThreadingHTTPServer):
    """ThreadingHTTPServer that does not print a traceback when a client aborts a request."""
    daemon_threads = True
    verbose = False

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionAbortedError, ConnectionResetError, BrokenPipeError)):
            return
        super().handle_error(request, client_address)


# ----------------------------------------------------------------------------
# Native window (pywebview)
# ----------------------------------------------------------------------------
def gui_backend() -> str | None:
    if IS_WIN:
        return "edgechromium"
    if IS_LINUX:
        return "qt"
    if IS_MAC:
        return "cocoa"
    return None


def webview_storage_dir(sd: str) -> str:
    d = os.path.join(sd, "webview")
    os.makedirs(d, exist_ok=True)
    return d


def icon_path() -> str | None:
    name = "linktest.ico" if IS_WIN else "linktest.png"
    p = os.path.join(resource_dir(), "assets", name)
    return p if os.path.isfile(p) else None


def _saved_geometry(app: App) -> dict:
    """Validated {width, height, x, y, maximized} from settings, or the defaults."""
    g = app.settings.get("window") if isinstance(app.settings.get("window"), dict) else {}
    out = {"width": WINDOW_SIZE[0], "height": WINDOW_SIZE[1], "x": None, "y": None,
           "maximized": bool(g.get("maximized"))}
    try:
        w, h = int(g.get("width") or 0), int(g.get("height") or 0)
        if WINDOW_MIN[0] <= w <= 6000 and WINDOW_MIN[1] <= h <= 6000:
            out["width"], out["height"] = w, h
        if g.get("x") is not None and g.get("y") is not None:
            x, y = int(g["x"]), int(g["y"])
            if -20000 < x < 20000 and -20000 < y < 20000:
                out["x"], out["y"] = x, y
    except (TypeError, ValueError):
        pass
    return out


def _wire_geometry_saving(app: App, win):
    """Remember size/position/maximised state so the next launch reopens the same way."""
    state = {"timer": None, "maximized": False}

    def save_now():
        try:
            g = dict(app.settings.get("window") or {})
            if not state["maximized"]:
                w, h, x, y = win.width, win.height, win.x, win.y
                if w >= WINDOW_MIN[0] // 2 and h >= WINDOW_MIN[1] // 2:
                    g.update({"width": int(w), "height": int(h), "x": int(x), "y": int(y)})
            g["maximized"] = state["maximized"]
            app.settings["window"] = g
            app.save_settings()
        except Exception:
            pass

    def schedule(*_a):
        t = state["timer"]
        if t:
            t.cancel()
        state["timer"] = threading.Timer(0.5, save_now)
        state["timer"].daemon = True
        state["timer"].start()

    def on_max():
        state["maximized"] = True
        schedule()

    def on_restore():
        state["maximized"] = False
        schedule()

    def on_closing():
        t = state["timer"]
        if t:
            t.cancel()
        save_now()

    win.events.resized += schedule
    win.events.moved += schedule
    win.events.maximized += on_max
    win.events.restored += on_restore
    win.events.closing += on_closing
    return state


def open_native_window(app: App, url: str):
    import webview
    geo = _saved_geometry(app)
    extra = bool(app.windows)  # a second window: offset so it does not hide the first
    kw = dict(width=geo["width"], height=geo["height"])
    if geo["x"] is not None:
        kw["x"] = geo["x"] + (40 if extra else 0)
        kw["y"] = geo["y"] + (40 if extra else 0)
    win = webview.create_window(APP_NAME, url, min_size=WINDOW_MIN, text_select=True, zoomable=False,
                                background_color="#f3f5f9", **kw)
    win.events.closed += lambda: app.on_window_closed(win)
    state = _wire_geometry_saving(app, win)

    def on_shown():
        # Pull the window back if the saved spot is on a monitor that is no longer there.
        try:
            x, y = win.x, win.y
            if IS_WIN:
                import ctypes
                import ctypes.wintypes as wt
                # MONITOR_DEFAULTTONULL: 0 when the point is on no monitor
                on_screen = bool(ctypes.windll.user32.MonitorFromPoint(wt.POINT(x + 40, y + 40), 0))
                if not on_screen:
                    win.move(60, 60)
            else:
                # webview.screens is a proxy that always looks callable; iterating it gives the list
                screens = list(webview.screens)
                if screens and not any(s.x - 10 <= x + 40 <= s.x + s.width and s.y - 10 <= y + 40 <= s.y + s.height for s in screens):
                    p = screens[0]
                    win.move(p.x + 60, p.y + 60)
        except Exception as e:
            if sys.stderr:
                print(f"window position check failed: {e!r}", file=sys.stderr)
        if geo["maximized"] and not extra:
            try:
                state["maximized"] = True
                win.maximize()
            except Exception:
                pass
    win.events.shown += on_shown
    app.windows.append(win)
    return win


def run_windowed(app: App, url: str, sd: str, verbose: bool) -> bool:
    """Show the UI in a native window; returns False if pywebview is unavailable.

    Blocks until the last window is closed.
    """
    try:
        import webview
    except ImportError:
        return False
    if IS_LINUX and hasattr(os, "geteuid") and os.geteuid() == 0:
        # Chromium refuses to sandbox as root (e.g. a WSL shell); QtWebEngine needs this.
        os.environ.setdefault("QTWEBENGINE_DISABLE_SANDBOX", "1")
    webview.settings["ALLOW_DOWNLOADS"] = False        # exports go through /api/export
    webview.settings["OPEN_EXTERNAL_LINKS_IN_BROWSER"] = True
    open_native_window(app, url)
    webview.start(gui=gui_backend(), private_mode=False, storage_path=webview_storage_dir(sd),
                  icon=icon_path(), debug=verbose)
    return True


def request_window(port: int) -> bool:
    """Ask an already-running LinkTest to open another window."""
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{port}/api/window", data=b"{}",
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=3) as r:
            return bool(json.loads(r.read().decode()).get("ok"))
    except Exception:
        return False


def existing_instance(sd: str) -> int | None:
    info = read_json(os.path.join(sd, "instance.json"), None)
    if not isinstance(info, dict) or not info.get("port"):
        return None
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{info['port']}/api/ping", timeout=1.5) as r:
            if json.loads(r.read().decode()).get("app") == APP_NAME:
                return int(info["port"])
    except Exception:
        return None
    return None


# ----------------------------------------------------------------------------
def main(argv=None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    if "--capture-helper" in raw:
        # Packet-capture helper mode (may be running elevated). No UI, no server.
        return pc.capture_helper_main(raw)
    if raw and raw[0] == "--zeek-logs":
        # Command line: write Zeek-style logs for a capture file and exit.
        import pcaplogs
        return pcaplogs.cli_main(raw[1:])
    ap = argparse.ArgumentParser(description="LinkTest - friendly iperf3")
    ap.add_argument("--port", type=int, default=0, help="local UI port (default: pick a free one)")
    ap.add_argument("--browser", action="store_true",
                    help="open in the default browser instead of a native window")
    ap.add_argument("--no-open", action="store_true", help="just run the server; print the URL")
    ap.add_argument("--verbose", action="store_true", help="log HTTP requests / enable devtools")
    ns = ap.parse_args(argv)

    sd = state_dir()
    if not ns.no_open:
        port = existing_instance(sd)
        if port:
            # Already running: show another window on the same instance.
            url = f"http://127.0.0.1:{port}/"
            if ns.browser or not request_window(port):
                webbrowser.open(url)
            return 0

    windowed = not (ns.browser or ns.no_open)
    app = App(windowed=windowed)
    Handler.app = app
    server = QuietServer(("127.0.0.1", ns.port), Handler)
    server.verbose = ns.verbose
    app.server = server
    port = server.server_address[1]
    url = f"http://127.0.0.1:{port}/"
    app.url = url
    instance_file = os.path.join(sd, "instance.json")
    write_json(instance_file, {"port": port, "pid": os.getpid()})
    print(f"{APP_NAME} {VERSION} at {url}  (state: {sd})")

    def cleanup():
        app.stop_tools()
        try:
            os.remove(instance_file)
        except OSError:
            pass

    if not windowed:
        if ns.browser:
            webbrowser.open(url)
            threading.Thread(target=app.watch, daemon=True).start()
        try:
            server.serve_forever(poll_interval=0.5)
        except KeyboardInterrupt:
            pass
        finally:
            cleanup()
        return 0

    # Native window: the HTTP server runs on a thread, pywebview owns the main thread.
    st = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.5}, daemon=True)
    st.start()
    try:
        if not run_windowed(app, url, sd, ns.verbose):
            print("pywebview is not installed; opening the default browser instead "
                  "(pip install -r requirements.txt for the native window).")
            app.windowed = False
            webbrowser.open(url)
            threading.Thread(target=app.watch, daemon=True).start()
            while st.is_alive():
                st.join(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        cleanup()
        try:
            server.shutdown()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
