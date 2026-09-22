"""iperf3 process management for LinkTest.

Everything that touches the real iperf3 binary lives here: locating it,
reading its version, turning the GUI's option dictionary into a command line,
running it, and turning its output (streamed JSON or classic text) into
normalised events the UI can draw.
"""
from __future__ import annotations

import json
import os
import platform
import re
import shlex
import shutil
import socket
import subprocess
import sys
import threading
import time

IS_WIN = os.name == "nt"
IS_LINUX = sys.platform.startswith("linux")
IS_MAC = sys.platform == "darwin"
EXE = "iperf3.exe" if IS_WIN else "iperf3"
CREATE_NO_WINDOW = 0x08000000 if IS_WIN else 0


# ----------------------------------------------------------------------------
# Locating iperf3
# ----------------------------------------------------------------------------
def app_dir() -> str:
    """Folder holding the executable (frozen) or this source file."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def resource_dir() -> str:
    """Where bundled data lives: PyInstaller's unpack dir when frozen, else the source dir."""
    return getattr(sys, "_MEIPASS", None) or os.path.dirname(os.path.abspath(__file__))


def plat_tag() -> str:
    """Name of the bin/<tag> folder for this platform (matches fetch-iperf3.py / build.py)."""
    if IS_WIN:
        return "win64"
    machine = platform.machine().lower() or "unknown"
    if machine in ("amd64", "x64"):
        machine = "x86_64"
    if IS_MAC:
        return f"mac-{'arm64' if machine in ('arm64', 'aarch64') else 'x86_64'}"
    return f"{'linux' if IS_LINUX else sys.platform}-{machine}"


def bundled_bin_dir() -> str:
    """Folder that holds the iperf3 shipped with LinkTest."""
    if getattr(sys, "frozen", False):
        return os.path.join(resource_dir(), "bin")
    return os.path.join(app_dir(), "bin", plat_tag())


def bundled_iperf_path() -> str | None:
    p = os.path.join(bundled_bin_dir(), EXE)
    return p if os.path.isfile(p) else None


def ensure_executable(path: str) -> None:
    """PyInstaller/zip extraction can drop the exec bit; put it back on POSIX."""
    if IS_WIN or os.access(path, os.X_OK):
        return
    try:
        os.chmod(path, os.stat(path).st_mode | 0o755)
    except OSError:
        pass


def companions_ok(path: str) -> str | None:
    """Return a problem description if a Windows iperf3.exe lacks cygwin1.dll beside it."""
    if IS_WIN and not os.path.isfile(os.path.join(os.path.dirname(path), "cygwin1.dll")):
        return "cygwin1.dll is missing next to iperf3.exe"
    return None


def candidate_paths(state_dir: str, custom: str | None) -> list[str]:
    cands: list[str] = []
    if custom:
        cands.append(custom)
    cands.append(os.path.join(bundled_bin_dir(), EXE))
    cands.append(os.path.join(app_dir(), "bin", EXE))
    cands.append(os.path.join(state_dir, "bin", EXE))
    found = shutil.which("iperf3")
    if found:
        cands.append(found)
    if IS_WIN:
        for base in (os.environ.get("ProgramFiles", r"C:\Program Files"),
                     os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
                     r"C:\iperf3", r"C:\iperf", r"C:\Tools\iperf3"):
            cands.append(os.path.join(base, "iperf3", EXE))
            cands.append(os.path.join(base, EXE))
    else:
        for p in ("/usr/bin/iperf3", "/usr/local/bin/iperf3", "/opt/homebrew/bin/iperf3"):
            cands.append(p)
    seen, out = set(), []
    for c in cands:
        n = os.path.normcase(os.path.abspath(c))
        if n not in seen:
            seen.add(n)
            out.append(c)
    return out


def find_iperf(state_dir: str, custom: str | None) -> str | None:
    for c in candidate_paths(state_dir, custom):
        if os.path.isfile(c):
            ensure_executable(c)
            if os.access(c, os.X_OK):
                return c
    return None


_VER_RE = re.compile(r"iperf\s+(\d+)\.(\d+)(?:\.(\d+))?")


def iperf_version(path: str) -> tuple[str, tuple[int, int, int]] | None:
    """Return ('3.21', (3,21,0)) or None if the binary does not run."""
    try:
        out = subprocess.run([path, "--version"], capture_output=True, text=True,
                             timeout=10, creationflags=CREATE_NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (out.stdout or "") + (out.stderr or "")
    m = _VER_RE.search(text)
    if not m:
        return None
    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)
    return (f"{major}.{minor}" + (f".{patch}" if patch else ""), (major, minor, patch))


def features_for(ver: tuple[int, int, int]) -> dict:
    return {
        "jsonStream": ver >= (3, 17, 0),
        "bidir": ver >= (3, 7, 0),
        "dscp": ver >= (3, 2, 0),
        "connectTimeout": ver >= (3, 2, 0),
        "extraData": ver >= (3, 6, 0),
        "idleTimeout": ver >= (3, 11, 0),
        "dontFragment": ver >= (3, 15, 0),
    }


# ----------------------------------------------------------------------------
# Command line construction
# ----------------------------------------------------------------------------
_UNIT_RE = re.compile(
    r"^\s*(\d+(?:\.\d+)?)\s*([kKmMgGtT])?(?:i?[bB](?:it|yte)?s?)?(?:/s(?:ec)?|ps)?\s*$")


def norm_size(v, allow_zero=False) -> str | None:
    """Turn '100M', '100 Mbps', '2.5 g', '0' into iperf's n[KMGT] format."""
    if v is None:
        return None
    s = str(v).strip()
    if not s:
        return None
    m = _UNIT_RE.match(s)
    if not m:
        raise ValueError(f"'{v}' is not a number I understand (try 100M or 2.5G).")
    num, unit = m.group(1), (m.group(2) or "").upper()
    if float(num) == 0:
        return "0" if allow_zero else None
    if "." in num:
        scale = {"": 1, "K": 1_000, "M": 1_000_000, "G": 1_000_000_000,
                 "T": 1_000_000_000_000}[unit]
        return str(int(float(num) * scale))
    return f"{num}{unit}"


def _int(v, name, lo=None, hi=None):
    if v is None or str(v).strip() == "":
        return None
    try:
        n = int(float(str(v).strip()))
    except ValueError:
        raise ValueError(f"{name} must be a whole number.")
    if lo is not None and n < lo:
        raise ValueError(f"{name} must be at least {lo}.")
    if hi is not None and n > hi:
        raise ValueError(f"{name} must be at most {hi}.")
    return n


def _fmt_num(x: float) -> str:
    return str(int(x)) if x == int(x) else repr(x)


def build_args(opts: dict, features: dict) -> list[str]:
    """Translate the GUI option dictionary into iperf3 arguments (without exe)."""
    mode = opts.get("mode", "client")
    a: list[str] = []
    port = _int(opts.get("port"), "Port", 1, 65535)
    if port and port != 5201:
        a += ["-p", str(port)]
    interval = str(opts.get("interval", 1)).strip()
    try:
        iv = float(interval) if interval else 1.0
    except ValueError:
        raise ValueError("Report interval must be a number of seconds.")
    if iv <= 0:
        iv = 1.0
    a += ["-i", _fmt_num(iv)]
    ipver = str(opts.get("ipver", "auto"))
    if ipver == "4":
        a.append("-4")
    elif ipver == "6":
        a.append("-6")
    bind = str(opts.get("bind", "")).strip()
    if bind:
        a += ["-B", bind]
    if features.get("jsonStream"):
        a.append("--json-stream")
    else:
        a.append("--forceflush")

    if mode == "server":
        a.append("-s")
        if opts.get("oneOff"):
            a.append("-1")
        it = _int(opts.get("idleTimeout"), "Idle timeout", 1)
        if it and features.get("idleTimeout"):
            a += ["--idle-timeout", str(it)]
        lim = norm_size(opts.get("serverBitrateLimit"))
        if lim:
            a += ["--server-bitrate-limit", lim]
    else:
        host = str(opts.get("host", "")).strip()
        if not host:
            raise ValueError("Enter the address of the computer to test against.")
        a += ["-c", host]
        proto = opts.get("protocol", "tcp")
        if proto == "udp":
            a.append("-u")
        direction = opts.get("direction", "upload")
        if direction == "download":
            a.append("-R")
        elif direction == "both":
            if not features.get("bidir"):
                raise ValueError("Your iperf3 is older than 3.7 and cannot test both directions at once.")
            a.append("--bidir")
        amount = opts.get("amount", "time")
        if amount == "bytes":
            n = norm_size(opts.get("bytes"))
            if not n:
                raise ValueError("Enter how much data to send (for example 500M).")
            a += ["-n", n]
        elif amount == "blocks":
            k = norm_size(opts.get("blocks"))
            if not k:
                raise ValueError("Enter how many blocks to send.")
            a += ["-k", k]
        else:
            t = _int(opts.get("duration", 10), "Duration", 1, 86400) or 10
            a += ["-t", str(t)]
        par = _int(opts.get("parallel"), "Connections at once", 1, 128)
        if par and par > 1:
            a += ["-P", str(par)]
        br = norm_size(opts.get("bitrate"), allow_zero=True)
        if br is not None and not (proto != "udp" and br == "0"):
            a += ["-b", br]
        om = _int(opts.get("omit"), "Warm-up seconds", 0, 60)
        if om:
            a += ["-O", str(om)]
        w = norm_size(opts.get("window"))
        if w:
            a += ["-w", w]
        mss = _int(opts.get("mss"), "Segment size", 88, 65535)
        if mss and proto != "udp":
            a += ["-M", str(mss)]
        if opts.get("nodelay") and proto != "udp":
            a.append("-N")
        ln = norm_size(opts.get("length"))
        if ln:
            a += ["-l", ln]
        cport = _int(opts.get("cport"), "Client port", 1, 65535)
        if cport:
            a += ["--cport", str(cport)]
        ct = _int(opts.get("connectTimeout"), "Connect timeout", 1)
        if ct and features.get("connectTimeout"):
            a += ["--connect-timeout", str(ct * 1000)]
        dscp = str(opts.get("dscp", "")).strip()
        if dscp and features.get("dscp"):
            a += ["--dscp", dscp]
        tos = str(opts.get("tos", "")).strip()
        if tos and not dscp:
            a += ["-S", tos]
        if opts.get("zerocopy"):
            a.append("-Z")
        cc = str(opts.get("congestion", "")).strip()
        if cc and platform.system() in ("Linux", "FreeBSD"):
            a += ["-C", cc]
        if opts.get("getServerOutput"):
            a.append("--get-server-output")
        if opts.get("repeatingPayload"):
            a.append("--repeating-payload")
        if opts.get("dontFragment") and proto == "udp" and features.get("dontFragment"):
            a.append("--dont-fragment")
        if opts.get("udp64") and proto == "udp":
            a.append("--udp-counters-64bit")
        title = str(opts.get("title", "")).strip()
        if title:
            a += ["-T", title]
    extra = str(opts.get("extraArgs", "")).strip()
    if extra:
        a += shlex.split(extra, posix=not IS_WIN)
    return a


def quote_cmd(parts: list[str]) -> str:
    if IS_WIN:
        return subprocess.list2cmdline(parts)
    return " ".join(shlex.quote(p) for p in parts)


# ----------------------------------------------------------------------------
# Friendly error text
# ----------------------------------------------------------------------------
_FRIENDLY = [
    (r"unable to connect to server.*(refused|timed out|timeout|unreachable|No route)",
     "Couldn't reach the other computer. Check the address, make sure LinkTest is in "
     "'Be the test target' mode over there, and that its firewall allows the port."),
    (r"unable to connect to server",
     "Couldn't connect to the other computer. Check the address and port."),
    (r"the server is busy running a test",
     "The other computer is busy with another test right now. Try again in a moment."),
    (r"Address already in use|unable to start listener",
     "That port is already in use on this computer. Close the other program using it "
     "or pick a different port on both ends."),
    (r"control socket has closed unexpectedly|connection reset|Broken pipe|"
     r"unable to receive control message",
     "The connection dropped part-way through. The other side may have stopped, "
     "or the network is unstable."),
    (r"the client has unexpectedly closed the connection",
     "The other computer stopped the test early."),
    (r"parameter.*(exchange|failed)",
     "The two sides could not agree on test settings. Make sure both computers run "
     "a similar iperf3 version."),
    (r"test authorization failed|authorization",
     "The other computer requires a username and password for tests."),
    (r"unrecognized option|invalid option|unknown option",
     "Your iperf3 does not understand one of the advanced options selected. "
     "Try clearing Advanced options or updating iperf3."),
    (r"Name or service not known|getaddrinfo|Temporary failure in name resolution|"
     r"nodename nor servname|No such host|unknown host",
     "That address could not be found. Check the spelling, or use the IP address "
     "shown on the other computer."),
    (r"the server has terminated|interrupt", "The test was stopped."),
    (r"Permission denied", "Permission denied. Ports below 1024 need administrator rights."),
]


def friendly_error(msg: str) -> str:
    for pat, text in _FRIENDLY:
        if re.search(pat, msg, re.I):
            return text
    return "iperf3 reported a problem: " + msg.strip()


# ----------------------------------------------------------------------------
# Output parsing
# ----------------------------------------------------------------------------
def _sum_block(s: dict | None) -> dict | None:
    if not s:
        return None
    out = {
        "start": s.get("start"), "end": s.get("end"), "seconds": s.get("seconds"),
        "bytes": s.get("bytes"), "bps": s.get("bits_per_second"),
    }
    for k in ("retransmits", "jitter_ms", "lost_packets", "packets", "lost_percent",
              "omitted", "sender"):
        if k in s:
            out[k] = s[k]
    return out


def _udp_of(src: dict | None) -> dict | None:
    if src and (src.get("jitter_ms") is not None or src.get("lost_packets") is not None):
        return {"jitter_ms": src.get("jitter_ms"), "lost": src.get("lost_packets"),
                "packets": src.get("packets"), "lostPct": src.get("lost_percent")}
    return None


def normalise_end(data: dict) -> dict:
    """Reduce iperf3's end block into what the UI shows."""
    sent = _sum_block(data.get("sum_sent"))
    recv = _sum_block(data.get("sum_received"))
    plain = _sum_block(data.get("sum"))  # UDP puts totals here
    rsent = _sum_block(data.get("sum_sent_bidir_reverse"))
    rrecv = _sum_block(data.get("sum_received_bidir_reverse"))
    rplain = _sum_block(data.get("sum_bidir_reverse"))
    cpu = data.get("cpu_utilization_percent") or {}
    udp = _udp_of(plain or recv or sent)
    rudp = _udp_of(rplain or rrecv or rsent)
    if plain and not recv and not sent:
        if plain.get("sender"):
            sent = plain
        else:
            recv = plain
    if rplain and not rrecv and not rsent:
        if rplain.get("sender"):
            rsent = rplain
        else:
            rrecv = rplain
    return {
        "sent": sent, "received": recv, "udp": udp,
        "reverse": ({"sent": rsent, "received": rrecv, "udp": rudp}
                    if (rsent or rrecv or rplain) else None),
        "cpu": ({"local": cpu.get("host_total"), "remote": cpu.get("remote_total")}
                if cpu else None),
        "streams": len(data.get("streams") or []),
        "serverOutput": data.get("server_output_text"),
    }


def normalise_interval(data: dict) -> dict:
    s = data.get("sum") or {}
    streams = data.get("streams") or []
    if not s and len(streams) == 1:
        s = streams[0]
    out = {
        "t0": s.get("start"), "t1": s.get("end"), "bytes": s.get("bytes"),
        "bps": s.get("bits_per_second"),
        "omitted": bool(s.get("omitted")), "sender": s.get("sender"),
    }
    for k in ("retransmits", "jitter_ms", "lost_packets", "packets", "lost_percent"):
        if k in s:
            out[k] = s[k]
    if streams and len(streams) > 1:
        out["perStream"] = [st.get("bits_per_second") for st in streams]
    r = data.get("sum_bidir_reverse")
    if r:
        out["reverse"] = {"bps": r.get("bits_per_second"), "bytes": r.get("bytes"),
                          "retransmits": r.get("retransmits"), "jitter_ms": r.get("jitter_ms"),
                          "lost_packets": r.get("lost_packets"), "packets": r.get("packets"),
                          "lost_percent": r.get("lost_percent")}
    return out


def normalise_start(data: dict) -> dict:
    ts = data.get("test_start") or {}
    con = data.get("connecting_to") or data.get("accepted_connection") or {}
    return {
        "host": con.get("host"), "port": con.get("port"),
        "protocol": ts.get("protocol"), "streams": ts.get("num_streams"),
        "reverse": bool(ts.get("reverse")), "duration": ts.get("duration"),
        "bytes": ts.get("bytes"), "blocks": ts.get("blocks"), "bidir": bool(ts.get("bidir")),
        "version": data.get("version"), "system": data.get("system_info"),
        "timestamp": (data.get("timestamp") or {}).get("time"),
        "tcpMss": data.get("tcp_mss_default") or data.get("tcp_mss"),
        "sndbuf": data.get("sock_bufsize") or data.get("sndbuf_actual"),
    }


# Classic text output (iperf3 < 3.17 fallback) --------------------------------
_TXT_IV = re.compile(
    r"^\[\s*(?P<id>SUM|\d+)\]\s+(?P<t0>[\d.]+)-(?P<t1>[\d.]+)\s+sec\s+"
    r"(?P<bytes>[\d.]+)\s+(?P<bu>[KMGT]?)Bytes\s+(?P<rate>[\d.]+)\s+(?P<ru>[KMGT]?)bits/sec"
    r"(?P<rest>.*)$")
_MULT = {"": 1, "K": 1e3, "M": 1e6, "G": 1e9, "T": 1e12}
_UDP_REST = re.compile(r"(?P<jit>[\d.]+)\s+ms\s+(?P<lost>\d+)/(?P<pk>\d+)\s+\((?P<pct>[\d.e+-]+)%\)")
_TCP_REST = re.compile(r"^\s+(?P<retr>\d+)(?:\s+(?P<cwnd>[\d.]+\s+[KMGT]?Bytes))?")


def parse_text_line(line: str, state: dict):
    """Return a list of (kind, payload) events from one line of classic output."""
    m = _TXT_IV.match(line)
    if not m:
        low = line.lower()
        if low.startswith("iperf3: "):
            msg = line.split(":", 1)[1].strip()
            msg = re.sub(r"^error\s*-\s*", "", msg)
            return [("error", msg)]
        if line.startswith("Connecting to host"):
            mm = re.match(r"Connecting to host (\S+), port (\d+)", line)
            if mm:
                return [("start", {"host": mm.group(1), "port": int(mm.group(2))})]
        if line.startswith("Accepted connection from"):
            mm = re.match(r"Accepted connection from (\S+), port (\d+)", line)
            if mm:
                return [("start", {"host": mm.group(1), "port": int(mm.group(2))})]
        if line.startswith("- - - -"):
            state["in_end"] = True
        return []
    rest = m.group("rest")
    is_end = state.get("in_end") or "sender" in rest or "receiver" in rest
    ent = {
        "t0": float(m.group("t0")), "t1": float(m.group("t1")),
        "bytes": float(m.group("bytes")) * _MULT[m.group("bu")],
        "bps": float(m.group("rate")) * _MULT[m.group("ru")],
        "omitted": "(omitted)" in rest,
    }
    u = _UDP_REST.search(rest)
    if u:
        ent.update(jitter_ms=float(u.group("jit")), lost_packets=int(u.group("lost")),
                   packets=int(u.group("pk")), lost_percent=float(u.group("pct")))
    else:
        t = _TCP_REST.match(rest)
        if t and t.group("retr") is not None:
            ent["retransmits"] = int(t.group("retr"))
    sid = m.group("id")
    if sid == "SUM":
        state["has_sum"] = True
    elif state.get("has_sum") and not is_end:
        return []  # per-stream line of a parallel run; the SUM line carries the total
    if is_end:
        who = "sent" if "sender" in rest else ("received" if "receiver" in rest else None)
        if who is None:
            return []
        end = state.setdefault("end", {})
        if sid == "SUM" or not end.get(who):
            end[who] = {"bytes": ent["bytes"], "bps": ent["bps"],
                        "seconds": ent["t1"] - ent["t0"],
                        "retransmits": ent.get("retransmits"), "jitter_ms": ent.get("jitter_ms"),
                        "lost_packets": ent.get("lost_packets"), "packets": ent.get("packets"),
                        "lost_percent": ent.get("lost_percent")}
        return []
    return [("interval", ent)]


def finish_text_end(state: dict) -> dict | None:
    end = state.get("end")
    if not end:
        return None
    sent, recv = end.get("sent"), end.get("received")
    return {"sent": sent, "received": recv, "udp": _udp_of(recv or sent), "reverse": None,
            "cpu": None, "streams": 0, "serverOutput": None}


# ----------------------------------------------------------------------------
# The runner
# ----------------------------------------------------------------------------
class Runner:
    """Owns at most one iperf3 process and an append-only list of events."""

    def __init__(self):
        self.lock = threading.Lock()
        self.events: list[dict] = []
        self.seq = 0
        self.proc: subprocess.Popen | None = None
        self.mode = None
        self.cmd = None
        self.started_at = None
        self.opts = None
        self.on_result = None  # callback(summary dict) for history
        self._thread = None
        self._stop_requested = False
        # auto-retry (public servers): {"every": s, "maxSeconds": s, "ports": [..]} or None
        self.retry: dict | None = None
        self._retry_pending = False
        self._retry_wake = threading.Event()
        self._attempt = 0
        self._exe: str | None = None
        self._features: dict = {}

    # -- events --------------------------------------------------------------
    def push(self, ev: dict):
        with self.lock:
            self.seq += 1
            ev["seq"] = self.seq
            ev["ts"] = time.time()
            self.events.append(ev)
            if len(self.events) > 5000:
                del self.events[:1000]

    def since(self, seq: int) -> list[dict]:
        with self.lock:
            return [e for e in self.events if e["seq"] > seq]

    def running(self) -> bool:
        return self._retry_pending or (self.proc is not None and self.proc.poll() is None)

    def state(self) -> dict:
        return {"running": self.running(), "mode": self.mode, "cmd": self.cmd,
                "startedAt": self.started_at, "opts": self.opts, "seq": self.seq}

    # -- lifecycle -----------------------------------------------------------
    def start(self, exe: str, opts: dict, features: dict, retry: dict | None = None):
        if self.running():
            raise RuntimeError("A test is already running. Stop it first.")
        args = build_args(opts, features)
        cmd = [exe] + args
        self.mode = opts.get("mode", "client")
        self.opts = opts
        self.cmd = quote_cmd(cmd)
        self.started_at = time.time()
        self._stop_requested = False
        self._exe, self._features = exe, features
        self.retry = retry if (isinstance(retry, dict) and self.mode == "client") else None
        self._attempt = 1
        self._retry_pending = False
        self._retry_wake.clear()
        with self.lock:
            self.events.clear()
        self.push({"type": "state", **self.state()})
        self.push({"type": "log", "line": "$ " + self.cmd})
        kwargs = dict(stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                      text=True, encoding="utf-8", errors="replace", bufsize=1,
                      creationflags=CREATE_NO_WINDOW)
        try:
            self.proc = subprocess.Popen(cmd, **kwargs)
        except OSError as e:
            self.push({"type": "error", "message": str(e),
                       "friendly": f"Could not start iperf3: {e}"})
            self.push({"type": "exit", "code": -1})
            self.proc = None
            raise
        self._thread = threading.Thread(target=self._run,
                                        args=(bool(features.get("jsonStream")),), daemon=True)
        self._thread.start()

    def stop(self):
        p = self.proc
        if self._retry_pending:
            # Waiting between attempts: no process to kill, just end the loop.
            self._stop_requested = True
            self._retry_wake.set()
            return True
        if not p or p.poll() is not None:
            return False
        self._stop_requested = True
        self._retry_wake.set()
        if IS_WIN:
            # Kill the whole tree so a wrapper/launcher cannot leave iperf3 running.
            try:
                subprocess.run(["taskkill", "/PID", str(p.pid), "/T", "/F"],
                               capture_output=True, timeout=10, creationflags=CREATE_NO_WINDOW)
            except (OSError, subprocess.TimeoutExpired):
                pass
        try:
            p.terminate()
        except OSError:
            pass
        try:
            p.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                p.kill()
            except OSError:
                pass
        return True

    # -- output pump ---------------------------------------------------------
    # "busy" is what most servers say; some builds instead drop the control connection of a
    # second client. Either way the test never started (checked by the caller: no data flowed).
    RETRYABLE = re.compile(r"the server is busy running a test|unable to connect to server|"
                           r"control socket has closed unexpectedly|unable to receive control message|"
                           r"connection reset", re.I)

    def _run(self, json_stream: bool):
        """Pump one attempt; for public servers, retry while the server is busy."""
        code = -1
        while True:
            code, got_end, saw_data, last_error = self._pump_once(self.proc, json_stream)
            r = self.retry
            if (r and not self._stop_requested and not got_end and not saw_data and last_error
                    and self.RETRYABLE.search(last_error)):
                every = max(1.0, float(r.get("every") or 3))
                max_s = float(r.get("maxSeconds") or 120)
                if time.time() - (self.started_at or time.time()) + every > max_s:
                    mins = max(1, round(max_s / 60))
                    self.push({"type": "error", "message": last_error,
                               "friendly": f"The server was still busy after {mins} minute{'s' if mins != 1 else ''} of trying. "
                                           "Pick another public server or try later."})
                    break
                self._attempt += 1
                cur = int(self.opts.get("port") or 5201)
                port = self._next_port(cur)
                busy = "busy" in last_error.lower()
                why = "The server is busy" if busy else "The server did not accept the connection"
                where = f" on port {port}" if port != cur else ""
                self._retry_pending = True
                self.push({"type": "retry", "attempt": self._attempt, "inSeconds": every, "port": port,
                           "friendly": f"{why}. Trying again in {every:g} s{where} (attempt {self._attempt})…"})
                self._retry_wake.wait(every)
                self._retry_pending = False
                if self._stop_requested:
                    break
                if port != cur:
                    self.opts = dict(self.opts, port=port)
                cmd = [self._exe] + build_args(self.opts, self._features)
                self.cmd = quote_cmd(cmd)
                self.push({"type": "state", **self.state()})
                self.push({"type": "log", "line": "$ " + self.cmd})
                try:
                    self.proc = subprocess.Popen(
                        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                        text=True, encoding="utf-8", errors="replace", bufsize=1, creationflags=CREATE_NO_WINDOW)
                except OSError as e:
                    self.push({"type": "error", "message": str(e), "friendly": f"Could not start iperf3: {e}"})
                    break
                continue
            break
        self.push({"type": "exit", "code": code, "stopped": self._stop_requested})

    def _next_port(self, current: int) -> int:
        ports = [int(p) for p in (self.retry or {}).get("ports") or [] if str(p).isdigit()]
        if not ports:
            return current
        if current in ports:
            return ports[(ports.index(current) + 1) % len(ports)]
        return ports[0]

    def _pump_once(self, p, json_stream: bool):
        """Read one iperf3 process to completion. Returns (code, got_end, saw_data, last_error)."""
        text_state: dict = {}
        current_start = None
        got_end = False
        saw_data = False
        last_error: str | None = None
        assert p and p.stdout
        for raw in p.stdout:
            line = raw.rstrip("\r\n")
            if not line.strip():
                continue
            self.push({"type": "log", "line": line})
            obj = None
            if line.lstrip().startswith("{"):
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    obj = None
            if isinstance(obj, dict):
                ev = obj.get("event")
                data = obj.get("data")
                if ev == "start" and isinstance(data, dict):
                    current_start = normalise_start(data)
                    got_end = False
                    self.push({"type": "start", "info": current_start})
                elif ev == "interval" and isinstance(data, dict):
                    saw_data = True
                    self.push({"type": "interval", **normalise_interval(data)})
                elif ev == "end" and isinstance(data, dict):
                    # After an error iperf3 emits {"event":"end","data":{}}; that is not a result.
                    if any(data.get(k) for k in ("sum_sent", "sum_received", "sum", "streams")):
                        got_end = True
                        self._emit_end(normalise_end(data), current_start)
                elif ev == "error":
                    msg = data if isinstance(data, str) else json.dumps(data)
                    last_error = msg
                    self.push({"type": "error", "message": msg, "friendly": friendly_error(msg)})
                elif ev in ("server_output_text", "server_output_json"):
                    self.push({"type": "serverOutput",
                               "text": data if isinstance(data, str) else json.dumps(data, indent=1)})
                elif "error" in obj and not ev:
                    msg = str(obj["error"])
                    last_error = msg
                    self.push({"type": "error", "message": msg, "friendly": friendly_error(msg)})
                elif isinstance(obj.get("end"), dict):
                    # A whole --json document; handle it for completeness.
                    if isinstance(obj.get("start"), dict):
                        current_start = normalise_start(obj["start"])
                        self.push({"type": "start", "info": current_start})
                    for iv in obj.get("intervals") or []:
                        self.push({"type": "interval", **normalise_interval(iv)})
                    got_end = True
                    self._emit_end(normalise_end(obj["end"]), current_start)
                continue
            # classic text
            for kind, payload in parse_text_line(line, text_state):
                if kind == "interval":
                    saw_data = True
                    self.push({"type": "interval", **payload})
                elif kind == "start":
                    current_start = payload
                    text_state = {}
                    got_end = False
                    self.push({"type": "start", "info": payload})
                elif kind == "error":
                    last_error = str(payload)
                    self.push({"type": "error", "message": payload,
                               "friendly": friendly_error(payload)})
            if text_state.get("end") and "receiver" in line and not got_end:
                summary = finish_text_end(text_state)
                if summary:
                    got_end = True
                    self._emit_end(summary, current_start)
                    text_state = {}
        code = p.wait()
        if not json_stream and not got_end and text_state.get("end"):
            summary = finish_text_end(text_state)
            if summary:
                got_end = True
                self._emit_end(summary, current_start)
        return code, got_end, saw_data, last_error

    def _emit_end(self, summary: dict, start: dict | None):
        summary = dict(summary)
        summary["start"] = start
        self.push({"type": "end", "summary": summary})
        if self.on_result:
            try:
                self.on_result(summary)
            except Exception:
                pass


# ----------------------------------------------------------------------------
# Local network information
# ----------------------------------------------------------------------------
def local_addresses() -> dict:
    """IPv4 addresses of this machine, with the one that reaches the default route first."""
    primary = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # UDP connect sends nothing; it just picks a route
        primary = s.getsockname()[0]
        s.close()
    except OSError:
        pass
    addrs: list[str] = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip not in addrs and not ip.startswith("127."):
                addrs.append(ip)
    except OSError:
        pass
    if primary:
        if primary in addrs:
            addrs.remove(primary)
        addrs.insert(0, primary)
    return {"hostname": socket.gethostname(), "primary": primary, "addresses": addrs}


def _run(cmd: list[str], timeout: float = 15) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              creationflags=CREATE_NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired):
        return None


def firewall_backend() -> str | None:
    """Which firewall LinkTest knows how to open: 'windows', 'firewalld', 'ufw' or None.

    macOS returns None on purpose: its application firewall asks the user itself the first
    time LinkTest listens for a test, so there is nothing for a button to do.
    """
    if IS_WIN:
        return "windows"
    if not IS_LINUX:
        return None
    if shutil.which("firewall-cmd"):
        r = _run(["firewall-cmd", "--state"], timeout=10)
        if r is not None and r.returncode == 0:
            return "firewalld"
    if shutil.which("ufw"):
        return "ufw"
    return None


def _win_rule_name(port: int) -> str:
    return f"LinkTest iperf3 {port}"


def parse_ufw_status(text: str, port: int) -> bool:
    """True when `ufw status` output allows both <port>/tcp and <port>/udp (or plain <port>)."""
    tcp = udp = False
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2 or "ALLOW" not in line.upper():
            continue
        rule = parts[0]
        if rule == str(port):
            tcp = udp = True
        elif rule == f"{port}/tcp":
            tcp = True
        elif rule == f"{port}/udp":
            udp = True
    return tcp and udp


def parse_firewalld_ports(text: str, port: int) -> bool:
    ports = set(text.split())
    return f"{port}/tcp" in ports and f"{port}/udp" in ports


def firewall_rule_exists(port: int, backend: str | None = None) -> bool | None:
    """True/False when the check could run, None when it could not (e.g. not root)."""
    backend = backend or firewall_backend()
    if backend == "windows":
        r = _run(["netsh", "advfirewall", "firewall", "show", "rule", f"name={_win_rule_name(port)}"])
        if r is None:
            return None
        return r.returncode == 0 and "Rule Name" in (r.stdout or "")
    if backend == "ufw":
        r = _run(["ufw", "status"])
        if r is None or r.returncode != 0:
            return None
        return parse_ufw_status(r.stdout or "", port)
    if backend == "firewalld":
        r = _run(["firewall-cmd", "--list-ports"])
        if r is None or r.returncode != 0:
            return None
        return parse_firewalld_ports(r.stdout or "", port)
    return None


def firewall_commands(port: int, backend: str) -> list[list[str]]:
    if backend == "ufw":
        return [["ufw", "allow", f"{port}/tcp"], ["ufw", "allow", f"{port}/udp"]]
    if backend == "firewalld":
        return [["firewall-cmd", "--permanent", f"--add-port={port}/tcp"],
                ["firewall-cmd", "--permanent", f"--add-port={port}/udp"],
                ["firewall-cmd", "--reload"]]
    if backend == "windows":
        return [["netsh", "advfirewall", "firewall", "add", "rule", f"name={_win_rule_name(port)}",
                 "dir=in", "action=allow", f"protocol={proto}", f"localport={port}"]
                for proto in ("TCP", "UDP")]
    return []


def sudo_lines(port: int, backend: str) -> list[str]:
    return ["sudo " + shlex.join(c) for c in firewall_commands(port, backend)]


def add_firewall_rules(port: int) -> dict:
    """Open inbound TCP+UDP on `port` with an elevation prompt.

    Returns {"backend", "status": added|already|manual|unsupported, "commands", "message"}.
    Raises RuntimeError when the user cancels or the OS refuses.
    """
    backend = firewall_backend()
    res = {"backend": backend, "status": "unsupported", "commands": [], "message": ""}
    if backend is None:
        res["message"] = ("No supported firewall tool was found (LinkTest knows ufw and firewalld). "
                          "If a firewall is active, allow TCP and UDP port %d manually." % port)
        return res
    if firewall_rule_exists(port, backend):
        res.update(status="already", message="The firewall already allows this port.")
        return res
    if backend == "windows":
        inner = " & ".join(
            f'netsh advfirewall firewall add rule name="{_win_rule_name(port)}" dir=in action=allow '
            f"protocol={proto} localport={port}" for proto in ("TCP", "UDP"))
        # Start-Process -Verb RunAs triggers the standard Windows administrator prompt.
        script = ("Start-Process -Verb RunAs -Wait -WindowStyle Hidden -FilePath cmd.exe "
                  "-ArgumentList @('/c', $env:LT_FW_CMD)")
        env = dict(os.environ, LT_FW_CMD=inner)
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                           capture_output=True, text=True, timeout=180, env=env,
                           creationflags=CREATE_NO_WINDOW)
        if firewall_rule_exists(port, backend):
            res.update(status="added", message="Done. Other computers can now reach this one.")
            return res
        err = (r.stderr or "").strip()
        if "cancel" in err.lower():
            raise RuntimeError("The administrator prompt was cancelled.")
        raise RuntimeError(err.splitlines()[0] if err else "Windows did not confirm the firewall rule.")
    # Linux: one polkit prompt for all commands; otherwise hand the user the sudo lines.
    cmds = firewall_commands(port, backend)
    res["commands"] = sudo_lines(port, backend)
    has_display = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
    if shutil.which("pkexec") and has_display:
        joined = " && ".join(shlex.join(c) for c in cmds)
        r = _run(["pkexec", "sh", "-c", joined], timeout=180)
        if r is not None:
            if r.returncode in (126, 127):
                raise RuntimeError("The authorisation prompt was cancelled.")
            exists = firewall_rule_exists(port, backend)
            if exists or (exists is None and r.returncode == 0):
                res.update(status="added", message="Done. Other computers can now reach this one.")
                return res
            if r.returncode != 0:
                err = (r.stderr or r.stdout or "").strip().splitlines()
                res.update(status="manual",
                           message="The firewall tool reported: %s. Run these in a terminal instead:"
                                   % (err[-1] if err else "an error"))
                return res
    res.update(status="manual",
               message="LinkTest cannot ask for permission here. Run these in a terminal:")
    return res
