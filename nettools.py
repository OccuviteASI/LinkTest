"""Network tools for LinkTest: ping backends, network info, scanner, ping
monitor, traceroute, DNS client and MAC vendor lookup.

Everything here is standard library only and works without administrator or
root rights:
  * Windows pings through the IP Helper API (iphlpapi.IcmpSendEcho, ctypes).
  * Linux pings through unprivileged ICMP datagram sockets, falling back to
    the system `ping` command when the kernel refuses them.
  * DNS is a small pure-Python client (UDP, TCP on truncation).
Long-running jobs publish seq-numbered events through EventLog, which the
UI polls (same contract as iperf_runner.Runner).
"""
from __future__ import annotations

import collections
import concurrent.futures
import csv
import functools
import ipaddress
import os
import queue
import random
import re
import select
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zlib
from dataclasses import dataclass, field

IS_WIN = os.name == "nt"
IS_LINUX = sys.platform.startswith("linux")
IS_MAC = sys.platform == "darwin"
CREATE_NO_WINDOW = 0x08000000 if IS_WIN else 0


def resource_dir() -> str:
    return getattr(sys, "_MEIPASS", None) or os.path.dirname(os.path.abspath(__file__))


def _run(cmd: list[str], timeout: float = 10, env=None) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env,
                              creationflags=CREATE_NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired):
        return None


# ----------------------------------------------------------------------------
# Event log (seq-numbered, polled by the UI)
# ----------------------------------------------------------------------------
class EventLog:
    def __init__(self, keep: int = 6000):
        self.lock = threading.Lock()
        self.events: list[dict] = []
        self.seq = 0
        self.keep = keep

    def push(self, ev: dict) -> None:
        with self.lock:
            self.seq += 1
            ev["seq"] = self.seq
            ev["ts"] = time.time()
            self.events.append(ev)
            if len(self.events) > self.keep:
                del self.events[: self.keep // 5]

    def since(self, seq: int) -> list[dict]:
        with self.lock:
            return [e for e in self.events if e["seq"] > seq]

    def clear(self) -> None:
        with self.lock:
            self.events.clear()


# ----------------------------------------------------------------------------
# Pinging
# ----------------------------------------------------------------------------
@dataclass
class PingResult:
    status: str                 # ok | timeout | ttl_expired | unreachable | error | no_backend
    rtt_ms: float | None = None
    responder: str | None = None
    ttl: int | None = None
    detail: str = ""


def is_ipv4(s: str) -> bool:
    try:
        ipaddress.IPv4Address(s)
        return True
    except ValueError:
        return False


def resolve4(host: str) -> str:
    """Return the IPv4 address for a host name or address; ValueError with a friendly message."""
    host = (host or "").strip()
    if not host:
        raise ValueError("Enter an address or name.")
    if is_ipv4(host):
        return host
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror:
        try:
            socket.getaddrinfo(host, None, socket.AF_INET6, socket.SOCK_STREAM)
            raise ValueError(f"'{host}' only has an IPv6 address, which the ping tools do not support yet.")
        except socket.gaierror:
            raise ValueError(f"'{host}' could not be found. Check the spelling or use its IP address.")
    return infos[0][4][0]


class WinIcmpPinger:
    """ICMP echo through iphlpapi (no admin needed). One handle per thread."""
    name = "iphlpapi"
    max_parallel = 256

    def __init__(self):
        import ctypes
        import ctypes.wintypes as wt
        self.ct = ctypes
        self.dll = ctypes.WinDLL("iphlpapi", use_last_error=True)

        class IP_OPTION_INFORMATION(ctypes.Structure):
            _fields_ = [("Ttl", ctypes.c_ubyte), ("Tos", ctypes.c_ubyte), ("Flags", ctypes.c_ubyte),
                        ("OptionsSize", ctypes.c_ubyte), ("OptionsData", ctypes.c_void_p)]

        class ICMP_ECHO_REPLY(ctypes.Structure):
            _fields_ = [("Address", ctypes.c_uint32), ("Status", ctypes.c_ulong),
                        ("RoundTripTime", ctypes.c_ulong), ("DataSize", ctypes.c_ushort),
                        ("Reserved", ctypes.c_ushort), ("Data", ctypes.c_void_p),
                        ("Options", IP_OPTION_INFORMATION)]

        self.OPT = IP_OPTION_INFORMATION
        self.REPLY = ICMP_ECHO_REPLY
        self.dll.IcmpCreateFile.restype = wt.HANDLE
        self.dll.IcmpSendEcho.argtypes = [wt.HANDLE, ctypes.c_uint32, ctypes.c_void_p, wt.WORD,
                                          ctypes.POINTER(IP_OPTION_INFORMATION), ctypes.c_void_p,
                                          wt.DWORD, wt.DWORD]
        self.dll.IcmpSendEcho.restype = wt.DWORD
        self.dll.IcmpCloseHandle.argtypes = [wt.HANDLE]
        self._tls = threading.local()

    def _handle(self):
        h = getattr(self._tls, "h", None)
        if h is None:
            h = self.dll.IcmpCreateFile()
            self._tls.h = h
        return h

    def ping(self, ip: str, timeout_ms: int = 1000, ttl: int = 128, size: int = 32) -> PingResult:
        ct = self.ct
        payload = (b"LinkTest" * 8)[:max(1, min(size, 1400))]
        dest = struct.unpack("<I", socket.inet_aton(ip))[0]
        opt = self.OPT(ttl, 0, 0, 0, None)
        n = ct.sizeof(self.REPLY) + len(payload) + 8
        buf = ct.create_string_buffer(n)
        t0 = time.perf_counter()
        ok = self.dll.IcmpSendEcho(self._handle(), dest, payload, len(payload), ct.byref(opt), buf, n, timeout_ms)
        dt = (time.perf_counter() - t0) * 1000
        rep = self.REPLY.from_buffer(buf)
        status = rep.Status if ok else (ct.get_last_error() or rep.Status)
        responder = socket.inet_ntoa(struct.pack("<I", rep.Address)) if rep.Address else None
        if status == 0:
            return PingResult("ok", dt, responder or ip, rep.Options.Ttl)
        if status == 11013:
            return PingResult("ttl_expired", dt, responder)
        if status == 11010:
            return PingResult("timeout", None, None)
        if status in (11002, 11003, 11004, 11005):
            return PingResult("unreachable", dt, responder, detail=f"status {status}")
        return PingResult("error", None, None, detail=f"status {status}")


class LinuxDgramPinger:
    """ICMP echo through unprivileged datagram sockets (needs ping_group_range)."""
    name = "icmp-dgram"
    max_parallel = 256
    IP_RECVERR = 11
    MSG_ERRQUEUE = 0x2000

    def __init__(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)  # PermissionError if denied
        s.close()
        self._seq = random.randint(0, 0xFFFF)
        self._lock = threading.Lock()

    @staticmethod
    def _csum(b: bytes) -> int:
        if len(b) % 2:
            b += b"\0"
        s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)
        return (~s) & 0xFFFF

    def ping(self, ip: str, timeout_ms: int = 1000, ttl: int = 64, size: int = 32) -> PingResult:
        with self._lock:
            self._seq = (self._seq + 1) & 0xFFFF
            seq = self._seq
        token = os.urandom(4) + (b"LinkTest" * 8)[:max(4, min(size, 1400)) - 4]
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
        except PermissionError:
            return PingResult("no_backend", detail="ICMP sockets are not permitted for this user")
        try:
            s.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
            s.setsockopt(socket.SOL_IP, self.IP_RECVERR, 1)
            hdr = struct.pack("!BBHHH", 8, 0, 0, 0, seq)
            pkt = struct.pack("!BBHHH", 8, 0, self._csum(hdr + token), 0, seq) + token
            deadline = time.perf_counter() + timeout_ms / 1000
            t0 = time.perf_counter()
            s.sendto(pkt, (ip, 0))
            while True:
                remaining = deadline - time.perf_counter()
                if remaining <= 0:
                    return PingResult("timeout")
                s.settimeout(remaining)
                try:
                    data, addr = s.recvfrom(1500)
                except socket.timeout:
                    return PingResult("timeout")
                except OSError:
                    rtt = (time.perf_counter() - t0) * 1000
                    try:
                        _d, anc, _f, _a = s.recvmsg(1500, 512, self.MSG_ERRQUEUE)
                    except OSError as e:
                        return PingResult("error", None, None, detail=str(e))
                    for lvl, typ, cd in anc:
                        if lvl == socket.SOL_IP and typ == self.IP_RECVERR and len(cd) >= 16:
                            _errno, origin, etype, ecode = struct.unpack_from("=IBBB", cd, 0)
                            offender = None
                            if len(cd) >= 24 and cd[16] == 2:
                                offender = socket.inet_ntoa(cd[20:24])
                            if origin == 2 and etype == 11:
                                return PingResult("ttl_expired", rtt, offender)
                            if origin == 2 and etype == 3:
                                return PingResult("unreachable", rtt, offender, detail=f"code {ecode}")
                    return PingResult("error", None, None, detail="socket error")
                rtt = (time.perf_counter() - t0) * 1000
                if len(data) >= 8 and data[0] == 0 and struct.unpack("!H", data[6:8])[0] == seq and data[8:] == token:
                    return PingResult("ok", rtt, addr[0], None)
                # stray datagram: keep waiting until the deadline
        finally:
            s.close()


class LinuxPingCliPinger:
    """Fallback: the system `ping` binary, one process per probe."""
    name = "ping-cli"
    max_parallel = 32
    _RE_TIME = re.compile(r"time=([\d.]+) ms")
    _RE_TTL = re.compile(r"^From (\S+).*Time to live exceeded", re.M)
    _RE_TTLVAL = re.compile(r"ttl=(\d+)")

    def __init__(self):
        self.exe = shutil.which("ping")
        if not self.exe:
            raise RuntimeError("no ping binary")

    def _args(self, ip: str, timeout_ms: int, ttl: int, size: int, secs: int) -> list[str]:
        # iputils ping: -W = seconds to wait, -t = TTL
        return [self.exe, "-n", "-c", "1", "-W", str(secs), "-t", str(ttl), "-s", str(max(8, size)), ip]

    def ping(self, ip: str, timeout_ms: int = 1000, ttl: int = 64, size: int = 32) -> PingResult:
        secs = max(1, int(-(-timeout_ms // 1000)))
        env = dict(os.environ, LC_ALL="C")
        t0 = time.perf_counter()
        r = _run(self._args(ip, timeout_ms, ttl, size, secs), timeout=secs + 4, env=env)
        dt = (time.perf_counter() - t0) * 1000
        if r is None:
            return PingResult("error", detail="ping did not run")
        out = (r.stdout or "") + (r.stderr or "")
        m = self._RE_TIME.search(out)
        if r.returncode == 0 and m:
            tm = self._RE_TTLVAL.search(out)
            return PingResult("ok", float(m.group(1)), ip, int(tm.group(1)) if tm else None)
        m = self._RE_TTL.search(out)
        if m:
            return PingResult("ttl_expired", dt, m.group(1))
        if "Destination Host Unreachable" in out or "Destination Net Unreachable" in out:
            return PingResult("unreachable", dt, None)
        if r.returncode == 2:
            return PingResult("error", detail=out.strip().splitlines()[-1] if out.strip() else "ping error")
        return PingResult("timeout")


class MacPingCliPinger(LinuxPingCliPinger):
    """macOS/BSD ping: -W is milliseconds per reply, -m is the TTL, -t an overall deadline (s)."""
    name = "ping-cli"
    _RE_TTL = re.compile(r"^\d+ bytes from (\S+?):? Time to live exceeded", re.M)

    def _args(self, ip: str, timeout_ms: int, ttl: int, size: int, secs: int) -> list[str]:
        return [self.exe, "-n", "-c", "1", "-W", str(int(timeout_ms)), "-t", str(secs + 1), "-m", str(ttl),
                "-s", str(max(8, size)), ip]


def make_pinger():
    """Pick the best available backend for this machine (None if nothing works)."""
    if IS_WIN:
        try:
            return WinIcmpPinger()
        except OSError:
            return None
    if IS_MAC:
        # macOS allows unprivileged ICMP datagram sockets but does not hand back TTL-exceeded
        # errors the way Linux does, so the system ping (setuid) does the work there.
        try:
            return MacPingCliPinger()
        except RuntimeError:
            return None
    try:
        return LinuxDgramPinger()
    except (PermissionError, OSError):
        pass
    try:
        return LinuxPingCliPinger()
    except RuntimeError:
        return None


# ----------------------------------------------------------------------------
# Network information (interfaces, DNS servers, ARP)
# ----------------------------------------------------------------------------
class NetInfo:
    CACHE_S = 60

    def __init__(self):
        self._lock = threading.Lock()
        self._if = None
        self._if_t = 0.0
        self._dns = None
        self._dns_t = 0.0

    def refresh(self) -> None:
        with self._lock:
            self._if = None
            self._dns = None

    # -- interfaces ------------------------------------------------------------
    def interfaces(self) -> list[dict]:
        with self._lock:
            if self._if is not None and time.time() - self._if_t < self.CACHE_S:
                return self._if
        try:
            if IS_WIN:
                ifs = self._win_adapters()
            elif IS_MAC:
                ifs = self._mac_addrs()
            else:
                ifs = self._linux_addrs()
        except Exception:
            ifs = []
        if not ifs:
            ifs = self._fallback_iface()
        primary = _primary_ip()
        for i in ifs:
            i["primary"] = (i["ip"] == primary)
            try:
                net = ipaddress.IPv4Network(f"{i['ip']}/{i['prefix']}", strict=False)
                i["fullNetwork"] = str(net)
                if net.prefixlen < 20:
                    net = ipaddress.IPv4Network(f"{i['ip']}/24", strict=False)
                    i["narrowed"] = True
                i["network"] = str(net)
            except ValueError:
                i["network"] = None
        ifs.sort(key=lambda i: (not i["primary"], i["name"]))
        with self._lock:
            self._if, self._if_t = ifs, time.time()
        return ifs

    @staticmethod
    def _fallback_iface() -> list[dict]:
        ip = _primary_ip()
        if not ip:
            return []
        net = ipaddress.IPv4Network(f"{ip}/24", strict=False)
        return [{"name": "Network", "ip": ip, "prefix": 24, "mask": str(net.netmask), "gateway": None,
                 "mac": None, "primary": True, "assumed": True}]

    def _win_adapters(self) -> list[dict]:
        import ctypes
        import ctypes.wintypes as wt

        class IP_ADDRESS_STRING(ctypes.Structure):
            _fields_ = [("String", ctypes.c_char * 16)]

        class IP_ADDR_STRING(ctypes.Structure):
            pass
        IP_ADDR_STRING._fields_ = [("Next", ctypes.POINTER(IP_ADDR_STRING)), ("IpAddress", IP_ADDRESS_STRING),
                                   ("IpMask", IP_ADDRESS_STRING), ("Context", wt.DWORD)]

        class IP_ADAPTER_INFO(ctypes.Structure):
            pass
        IP_ADAPTER_INFO._fields_ = [
            ("Next", ctypes.POINTER(IP_ADAPTER_INFO)), ("ComboIndex", wt.DWORD),
            ("AdapterName", ctypes.c_char * 260), ("Description", ctypes.c_char * 132),
            ("AddressLength", wt.UINT), ("Address", ctypes.c_ubyte * 8), ("Index", wt.DWORD),
            ("Type", wt.UINT), ("DhcpEnabled", wt.UINT), ("CurrentIpAddress", ctypes.POINTER(IP_ADDR_STRING)),
            ("IpAddressList", IP_ADDR_STRING), ("GatewayList", IP_ADDR_STRING), ("DhcpServer", IP_ADDR_STRING),
            ("HaveWins", wt.BOOL), ("PrimaryWinsServer", IP_ADDR_STRING), ("SecondaryWinsServer", IP_ADDR_STRING),
            ("LeaseObtained", ctypes.c_int64), ("LeaseExpires", ctypes.c_int64)]
        dll = ctypes.WinDLL("iphlpapi")
        size = wt.ULONG(0)
        dll.GetAdaptersInfo(None, ctypes.byref(size))
        buf = ctypes.create_string_buffer(max(size.value, ctypes.sizeof(IP_ADAPTER_INFO)))
        if dll.GetAdaptersInfo(buf, ctypes.byref(size)) != 0:
            return []
        out = []
        p = ctypes.cast(buf, ctypes.POINTER(IP_ADAPTER_INFO))
        while p:
            a = p.contents
            if a.Type not in (24,):  # skip loopback
                mac = ":".join(f"{a.Address[i]:02X}" for i in range(a.AddressLength)) if a.AddressLength else None
                gw = a.GatewayList.IpAddress.String.decode(errors="replace").strip("\0") or None
                if gw == "0.0.0.0":
                    gw = None
                q = ctypes.pointer(a.IpAddressList)
                while q:
                    ip = q.contents.IpAddress.String.decode(errors="replace").strip("\0")
                    mask = q.contents.IpMask.String.decode(errors="replace").strip("\0")
                    if ip and ip != "0.0.0.0" and not ip.startswith("169.254."):
                        try:
                            prefix = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
                        except ValueError:
                            prefix = 24
                        out.append({"name": a.Description.decode("mbcs", errors="replace").strip("\0"),
                                    "ip": ip, "prefix": prefix, "mask": mask, "gateway": gw, "mac": mac,
                                    "kind": {6: "ethernet", 71: "wifi"}.get(a.Type, "other"), "index": a.Index})
                    q = q.contents.Next
            p = a.Next
        return out

    @staticmethod
    def _linux_addrs() -> list[dict]:
        r = _run(["ip", "-o", "-4", "addr", "show"])
        out = []
        if not r or r.returncode != 0:
            return out
        gw = None
        rr = _run(["ip", "-4", "route", "show", "default"])
        if rr and rr.returncode == 0:
            m = re.search(r"default via (\S+)", rr.stdout or "")
            gw = m.group(1) if m else None
        for line in (r.stdout or "").splitlines():
            m = re.match(r"\d+:\s+(\S+)\s+inet\s+(\S+)/(\d+).*?scope\s+(\S+)", line)
            if not m:
                continue
            dev, ip, prefix, scope = m.groups()
            if dev == "lo" or scope == "host" or ip.startswith("169.254."):
                continue
            mac = None
            try:
                with open(f"/sys/class/net/{dev}/address") as f:
                    mac = f.read().strip().upper() or None
            except OSError:
                pass
            net = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
            out.append({"name": dev, "ip": ip, "prefix": int(prefix), "mask": str(net.netmask), "gateway": gw,
                        "mac": mac, "kind": "wifi" if dev.startswith(("wl", "wlan")) else "ethernet"})
        return out

    @staticmethod
    def _mac_addrs() -> list[dict]:
        """macOS: ifconfig for addresses, route for the gateway, networksetup for friendly port names."""
        r = _run(["ifconfig", "-a"])
        if not r or r.returncode != 0:
            return []
        gw = gwdev = None
        rr = _run(["route", "-n", "get", "default"])
        if rr and rr.returncode == 0:
            m = re.search(r"gateway:\s*(\S+)", rr.stdout or "")
            gw = m.group(1) if m else None
            m = re.search(r"interface:\s*(\S+)", rr.stdout or "")
            gwdev = m.group(1) if m else None
        ports: dict[str, str] = {}
        rp = _run(["networksetup", "-listallhardwareports"])
        if rp and rp.returncode == 0:
            for m in re.finditer(r"Hardware Port:\s*(.+)\r?\nDevice:\s*(\S+)", rp.stdout or ""):
                ports[m.group(2)] = m.group(1).strip()
        out = []
        for block in re.split(r"\n(?=\S)", r.stdout or ""):
            m = re.match(r"([A-Za-z0-9.]+):\s+flags=", block)
            if not m:
                continue
            dev = m.group(1)
            if dev.startswith(("lo", "utun", "awdl", "llw", "gif", "stf", "anpi", "ap", "ipsec", "pktap")):
                continue
            mm = re.search(r"\bether\s+([0-9a-fA-F:]+)", block)
            mac = _pad_mac(mm.group(1)) if mm else None
            for im in re.finditer(r"\binet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+0x([0-9a-fA-F]{8})", block):
                ip, hexmask = im.groups()
                if ip.startswith("169.254."):
                    continue
                prefix = bin(int(hexmask, 16)).count("1")
                net = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
                port = ports.get(dev, "")
                kind = "wifi" if ("wi-fi" in port.lower() or "airport" in port.lower()) else "ethernet"
                out.append({"name": f"{port} ({dev})" if port else dev, "dev": dev, "ip": ip, "prefix": prefix,
                            "mask": str(net.netmask), "gateway": gw if gwdev in (None, dev) else None, "mac": mac, "kind": kind})
        return out

    # -- DNS servers -------------------------------------------------------------
    def dns_servers(self) -> list[str]:
        with self._lock:
            if self._dns is not None and time.time() - self._dns_t < self.CACHE_S:
                return self._dns
        servers: list[str] = []
        try:
            if IS_WIN:
                servers = self._win_dns()
                if not servers:
                    servers = self._win_dns_ps()
            else:
                with open("/etc/resolv.conf", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 2 and parts[0] == "nameserver":
                            servers.append(parts[1])
        except Exception:
            servers = []
        servers = [s for s in dict.fromkeys(servers) if s and s != "0.0.0.0"]
        with self._lock:
            self._dns, self._dns_t = servers, time.time()
        return servers

    @staticmethod
    def _win_dns() -> list[str]:
        import ctypes
        import ctypes.wintypes as wt

        class IP_ADDRESS_STRING(ctypes.Structure):
            _fields_ = [("String", ctypes.c_char * 16)]

        class IP_ADDR_STRING(ctypes.Structure):
            pass
        IP_ADDR_STRING._fields_ = [("Next", ctypes.POINTER(IP_ADDR_STRING)), ("IpAddress", IP_ADDRESS_STRING),
                                   ("IpMask", IP_ADDRESS_STRING), ("Context", wt.DWORD)]

        class FIXED_INFO(ctypes.Structure):
            _fields_ = [("HostName", ctypes.c_char * 132), ("DomainName", ctypes.c_char * 132),
                        ("CurrentDnsServer", ctypes.POINTER(IP_ADDR_STRING)), ("DnsServerList", IP_ADDR_STRING),
                        ("NodeType", wt.UINT), ("ScopeId", ctypes.c_char * 260), ("EnableRouting", wt.UINT),
                        ("EnableProxy", wt.UINT), ("EnableDns", wt.UINT)]
        dll = ctypes.WinDLL("iphlpapi")
        size = wt.ULONG(0)
        dll.GetNetworkParams(None, ctypes.byref(size))
        buf = ctypes.create_string_buffer(max(size.value, ctypes.sizeof(FIXED_INFO)))
        if dll.GetNetworkParams(buf, ctypes.byref(size)) != 0:
            return []
        fi = ctypes.cast(buf, ctypes.POINTER(FIXED_INFO)).contents
        out = []
        q = ctypes.pointer(fi.DnsServerList)
        while q:
            ip = q.contents.IpAddress.String.decode(errors="replace").strip("\0")
            if ip:
                out.append(ip)
            q = q.contents.Next
        return out

    @staticmethod
    def _win_dns_ps() -> list[str]:
        r = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                  "(Get-DnsClientServerAddress -AddressFamily IPv4 | Select -Expand ServerAddresses) -join ','"],
                 timeout=15)
        if not r or r.returncode != 0:
            return []
        return [s.strip() for s in (r.stdout or "").split(",") if s.strip()]

    # -- ARP table -----------------------------------------------------------------
    def arp_table(self) -> dict[str, str]:
        return {r["ip"]: r["mac"] for r in self.arp_rows()}

    def arp_rows(self) -> list[dict]:
        """Every neighbour this computer knows: {ip, mac, kind, iface}."""
        try:
            rows = self._win_arp_rows() if IS_WIN else self._mac_arp_rows() if IS_MAC else self._linux_arp_rows()
        except Exception:
            return []
        if IS_WIN:
            names = {i.get("index"): i["name"] for i in self.interfaces() if i.get("index") is not None}
            for r in rows:
                r["iface"] = names.get(r.pop("ifindex", None), "")
        return rows

    @staticmethod
    def _win_arp_rows() -> list[dict]:
        import ctypes
        import ctypes.wintypes as wt

        class MIB_IPNETROW(ctypes.Structure):
            _fields_ = [("dwIndex", wt.DWORD), ("dwPhysAddrLen", wt.DWORD), ("bPhysAddr", ctypes.c_ubyte * 8),
                        ("dwAddr", wt.DWORD), ("dwType", wt.DWORD)]
        dll = ctypes.WinDLL("iphlpapi")
        size = wt.ULONG(0)
        dll.GetIpNetTable(None, ctypes.byref(size), False)
        buf = ctypes.create_string_buffer(max(size.value, 4))
        if dll.GetIpNetTable(buf, ctypes.byref(size), False) != 0:
            return []
        n = struct.unpack_from("<I", buf, 0)[0]
        rows = (MIB_IPNETROW * n).from_buffer(buf, 4)
        out = []
        for r in rows:
            if r.dwType == 2 or r.dwPhysAddrLen != 6:
                continue
            mac = ":".join(f"{b:02X}" for b in r.bPhysAddr[:6])
            if mac in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
                continue
            ip = socket.inet_ntoa(struct.pack("<I", r.dwAddr))
            if ip.startswith("224.") or ip.startswith("239.") or ip.endswith(".255"):
                continue
            out.append({"ip": ip, "mac": mac, "kind": {3: "dynamic", 4: "static"}.get(r.dwType, "other"), "ifindex": r.dwIndex})
        return out

    @staticmethod
    def _mac_arp_rows() -> list[dict]:
        r = _run(["arp", "-an"])
        out = []
        for line in ((r.stdout or "").splitlines() if r else []):
            m = re.match(r"\S+\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+(\S+)\s+on\s+(\S+)(.*)", line)
            if not m:
                continue
            ip, mac, dev, rest = m.groups()
            if mac.startswith("("):
                continue  # (incomplete)
            mac = _pad_mac(mac)
            if mac == "FF:FF:FF:FF:FF:FF" or ip.startswith(("224.", "239.")) or ip.endswith(".255"):
                continue
            out.append({"ip": ip, "mac": mac, "kind": "static" if "permanent" in rest else "dynamic", "iface": dev})
        return out

    @staticmethod
    def _linux_arp_rows() -> list[dict]:
        out = []
        try:
            with open("/proc/net/arp") as f:
                next(f, None)
                for line in f:
                    parts = line.split()
                    if len(parts) >= 6 and parts[3] != "00:00:00:00:00:00":
                        flags = int(parts[2], 16)
                        if not flags & 0x2:
                            continue
                        out.append({"ip": parts[0], "mac": parts[3].upper(), "kind": "static" if flags & 0x4 else "dynamic", "iface": parts[5]})
        except OSError:
            pass
        return out

    # -- default scan range ----------------------------------------------------------
    def default_scan_range(self) -> dict:
        ifs = self.interfaces()
        if not ifs:
            return {"range": "192.168.1.0/24", "note": "No network address was found; edit the range."}
        i = ifs[0]
        net = ipaddress.IPv4Network(f"{i['ip']}/{i['prefix']}", strict=False)
        note = ""
        if net.prefixlen < 20:
            net = ipaddress.IPv4Network(f"{i['ip']}/24", strict=False)
            note = f"Your network ({i['ip']}/{i['prefix']}) is very large, so the range was narrowed to the nearest 256 addresses."
        elif i.get("assumed"):
            note = "The network size could not be read, so a /24 (256 addresses) around your address is assumed."
        return {"range": str(net), "note": note, "interface": i}


def _primary_ip() -> str | None:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return None


# ----------------------------------------------------------------------------
# Target parsing
# ----------------------------------------------------------------------------
MAX_HOSTS = 4096


def parse_targets(text: str) -> list[str]:
    """CIDR, 'a.b.c.1-254', 'a.b.c.d-e.f.g.h', single IPs; comma/space/newline separated."""
    hosts: list[str] = []
    seen = set()

    def add(ip: str):
        if ip not in seen:
            seen.add(ip)
            hosts.append(ip)
            if len(hosts) > MAX_HOSTS:
                raise ValueError(f"That is more than {MAX_HOSTS} addresses. The scanner stops at {MAX_HOSTS}; "
                                 "try a smaller range such as a /20 or a /24.")

    for part in re.split(r"[\s,;]+", (text or "").strip()):
        if not part:
            continue
        if "/" in part:
            try:
                net = ipaddress.IPv4Network(part, strict=False)
            except ValueError:
                raise ValueError(f"'{part}' is not a valid network. Try something like 192.168.1.0/24.")
            if net.num_addresses > MAX_HOSTS + 2:
                raise ValueError(f"{part} has {net.num_addresses} addresses; the scanner stops at {MAX_HOSTS}. "
                                 "Try a /20 or smaller.")
            it = net.hosts() if net.prefixlen <= 30 else net
            for ip in it:
                add(str(ip))
        elif "-" in part:
            a, b = part.split("-", 1)
            if not is_ipv4(a):
                raise ValueError(f"'{a}' is not a valid address.")
            if is_ipv4(b):
                start, end = int(ipaddress.IPv4Address(a)), int(ipaddress.IPv4Address(b))
            elif b.isdigit() and 0 <= int(b) <= 255:
                start = int(ipaddress.IPv4Address(a))
                end = (start & ~0xFF) | int(b)
            else:
                raise ValueError(f"'{part}' is not a valid range. Try 192.168.1.1-254.")
            if end < start:
                raise ValueError(f"'{part}' runs backwards.")
            if end - start + 1 > MAX_HOSTS:
                raise ValueError(f"'{part}' covers {end - start + 1} addresses; the scanner stops at {MAX_HOSTS}.")
            for n in range(start, end + 1):
                add(str(ipaddress.IPv4Address(n)))
        elif is_ipv4(part):
            add(part)
        else:
            raise ValueError(f"'{part}' is not an IP address or range. Names can be looked up in the DNS tab.")
    if not hosts:
        raise ValueError("Enter an address range to scan, for example 192.168.1.0/24.")
    return hosts


DEFAULT_PORTS: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 135: "RPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB", 548: "AFP", 554: "RTSP", 587: "Mail submission",
    631: "Printing (IPP)", 993: "IMAPS", 995: "POP3S", 1433: "SQL Server", 1883: "MQTT", 3306: "MySQL",
    3389: "Remote Desktop", 5000: "UPnP / Flask", 5201: "iperf3", 5900: "VNC", 8080: "HTTP alt",
    8443: "HTTPS alt", 9100: "Printer (raw)",
}
PORT_NAMES = dict(DEFAULT_PORTS)
PORT_NAMES.update({20: "FTP data", 67: "DHCP", 69: "TFTP", 88: "Kerberos", 111: "RPC (portmap)", 123: "NTP",
                   161: "SNMP", 389: "LDAP", 636: "LDAPS", 902: "VMware", 1080: "SOCKS", 1521: "Oracle",
                   2049: "NFS", 2375: "Docker", 3000: "Dev server", 3268: "AD Global Catalog", 5060: "SIP",
                   5353: "mDNS", 5432: "PostgreSQL", 5601: "Kibana", 5672: "AMQP", 6379: "Redis",
                   8000: "HTTP dev", 8006: "Proxmox", 8123: "Home Assistant", 8888: "HTTP alt",
                   9000: "HTTP alt", 9090: "Prometheus", 9200: "Elasticsearch", 27017: "MongoDB",
                   32400: "Plex"})

# Quick-select port presets (the UI offers Basic / Standard / Thorough).
BASIC_PORTS: list[int] = [21, 22, 23, 53, 80, 443, 445, 3389, 8080]
_THOROUGH_EXTRA = list(range(5900, 5911)) + list(range(8000, 8011)) + list(range(8080, 8091)) + [10000, 49152]
THOROUGH_PORTS: list[int] = sorted(set(range(1, 1025)) | set(PORT_NAMES) | set(_THOROUGH_EXTRA))


def ports_to_text(ports: list[int]) -> str:
    """Compact 'a-b, c, d-e' text for a sorted port list (what the ports field shows)."""
    out, i = [], 0
    ports = sorted(set(ports))
    while i < len(ports):
        j = i
        while j + 1 < len(ports) and ports[j + 1] == ports[j] + 1:
            j += 1
        out.append(str(ports[i]) if j == i else f"{ports[i]}-{ports[j]}" if j - i > 1 else f"{ports[i]}, {ports[j]}")
        i = j + 1
    return ", ".join(out)


def port_presets() -> dict:
    return {"basic": {"ports": BASIC_PORTS, "text": ports_to_text(BASIC_PORTS), "count": len(BASIC_PORTS)},
            "standard": {"ports": list(DEFAULT_PORTS), "text": ports_to_text(list(DEFAULT_PORTS)), "count": len(DEFAULT_PORTS)},
            "thorough": {"ports": THOROUGH_PORTS, "text": ports_to_text(THOROUGH_PORTS), "count": len(THOROUGH_PORTS)}}


def parse_ports(text) -> list[int]:
    if isinstance(text, list):
        vals = [int(x) for x in text]
    else:
        vals = []
        for part in re.split(r"[\s,;]+", str(text or "").strip()):
            if not part:
                continue
            if "-" in part:
                a, b = part.split("-", 1)
                if not (a.isdigit() and b.isdigit()):
                    raise ValueError(f"'{part}' is not a valid port range.")
                a, b = int(a), int(b)
                if b - a > 2048:
                    raise ValueError("Port ranges are limited to 2048 ports at a time.")
                vals.extend(range(a, b + 1))
            elif part.isdigit():
                vals.append(int(part))
            else:
                raise ValueError(f"'{part}' is not a port number.")
    out = sorted({p for p in vals if 1 <= p <= 65535})
    if len(out) > 2048:
        raise ValueError("Please keep the port list to 2048 ports or fewer.")
    return out


PROBE_CHUNK = 256
_REFUSED = {111, 61, 10061}  # ECONNREFUSED (Linux, BSD/macOS), WSAECONNREFUSED
_PENDING = {115, 36, 10035, 10036}  # EINPROGRESS, EINPROGRESS (BSD), WSAEWOULDBLOCK, WSAEINPROGRESS


def tcp_probe(ip: str, ports: list[int], timeout_ms: int = 500) -> dict[int, str]:
    """Connect to all ports at once. Returns {port: "open" | "refused" | "timeout" | "error"}.

    "refused" means a real host answered with a reset: proof of life even when it drops pings.
    """
    out: dict[int, str] = {}
    if not ports:
        return out
    if len(ports) > PROBE_CHUNK:  # never hold more than PROBE_CHUNK sockets per host at once
        for i in range(0, len(ports), PROBE_CHUNK):
            out.update(tcp_probe(ip, ports[i:i + PROBE_CHUNK], timeout_ms))
        return out
    socks: dict[socket.socket, int] = {}
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(False)
        try:
            err = s.connect_ex((ip, port))
        except OSError:
            s.close()
            out[port] = "error"
            continue
        if err == 0:
            out[port] = "open"
            s.close()
            continue
        if err in _REFUSED:
            out[port] = "refused"
            s.close()
            continue
        if err not in _PENDING and err != 0:
            out[port] = "error"
            s.close()
            continue
        socks[s] = port
    deadline = time.perf_counter() + timeout_ms / 1000
    try:
        while socks:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                break
            try:
                _r, w, x = select.select([], list(socks), list(socks), remaining)
            except (OSError, ValueError):
                break
            for s in set(w) | set(x):
                port = socks.pop(s, None)
                if port is None:
                    continue
                try:
                    code = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                except OSError:
                    code = -1
                out[port] = "open" if code == 0 else "refused" if code in _REFUSED else "error"
                s.close()
    finally:
        for s, port in socks.items():
            out.setdefault(port, "timeout")
            try:
                s.close()
            except OSError:
                pass
    return out


def tcp_open_ports(ip: str, ports: list[int], timeout_ms: int = 500) -> list[int]:
    return [p for p, st in tcp_probe(ip, ports, timeout_ms).items() if st == "open"]


# ----------------------------------------------------------------------------
# MAC vendors
# ----------------------------------------------------------------------------
class MacVendors:
    def __init__(self):
        self._loaded = False
        self._lock = threading.Lock()
        self._m24: dict[str, str] = {}
        self._m28: dict[str, str] = {}
        self._m36: dict[str, str] = {}

    def _load(self):
        with self._lock:
            if self._loaded:
                return
            self._loaded = True
            path = os.path.join(resource_dir(), "assets", "manuf.z")
            try:
                with open(path, "rb") as f:
                    text = zlib.decompress(f.read()).decode("utf-8", "replace")
            except (OSError, zlib.error):
                return
            for line in text.split("\n"):
                if "\t" not in line:
                    continue
                prefix, name = line.split("\t", 1)
                if "/" in prefix:
                    p, bits = prefix.split("/")
                    hexs = p.replace(":", "")
                    if bits == "28":
                        self._m28[hexs[:7]] = name
                    elif bits == "36":
                        self._m36[hexs[:9]] = name
                else:
                    self._m24[prefix.replace(":", "")[:6]] = name

    def lookup(self, mac: str | None) -> str | None:
        if not mac:
            return None
        self._load()
        h = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
        if len(h) < 6:
            return None
        return self._m36.get(h[:9]) or self._m28.get(h[:7]) or self._m24.get(h[:6])

    @property
    def available(self) -> bool:
        self._load()
        return bool(self._m24)

    def lookup_smart(self, mac: str | None, siblings=()) -> str | None:
        """Vendor lookup that also handles private (randomised) addresses.

        Tries the address itself, then the same address with the 'locally administered' bit
        cleared, then any sibling MAC that differs only in the first byte. Guesses get a '?'.
        """
        v = self.lookup(mac)
        if v or not mac:
            return v
        h = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
        if len(h) != 12:
            return None
        first = int(h[:2], 16)
        if first & 0x02:
            alt = f"{first & ~0x02:02X}" + h[2:]
            v = self.lookup(alt)
            if v:
                return v + "?"
            for s in siblings:
                hs = re.sub(r"[^0-9A-Fa-f]", "", s or "").upper()
                if len(hs) == 12 and hs[2:] == h[2:] and hs != h and not int(hs[:2], 16) & 0x02:
                    vv = self.lookup(hs)
                    if vv:
                        return vv + "?"
        return None


def _pad_mac(text: str) -> str:
    """BSD tools print single-digit octets (0:1c:42:...); normalise to AA:BB:CC:DD:EE:FF."""
    return ":".join(p.zfill(2) for p in text.strip().split(":")).upper()


def normalise_mac(text: str) -> str | None:
    h = re.sub(r"[^0-9A-Fa-f]", "", text or "")
    if len(h) != 12:
        return None
    return ":".join(h[i:i + 2].upper() for i in range(0, 12, 2))


def mac_kind(mac: str) -> dict:
    """Plain-language classification of a MAC address."""
    h = re.sub(r"[^0-9A-Fa-f]", "", mac or "").upper()
    if len(h) != 12:
        return {"kind": "invalid", "text": "Not a valid hardware address."}
    if h == "F" * 12:
        return {"kind": "broadcast", "text": "Broadcast address: means every device on the network."}
    first = int(h[:2], 16)
    if first & 0x01:
        return {"kind": "multicast", "text": "Multicast (group) address, not a single device."}
    if first & 0x02:
        return {"kind": "private", "text": "Private (randomised) address: phones, laptops and some access points make these up "
                                             "for privacy, so the maker cannot be read from it reliably."}
    return {"kind": "global", "text": "Factory-assigned address; the first half identifies the maker."}


def arp_report(netinfo: NetInfo, vendors: MacVendors, scan_hosts: dict | None = None) -> dict:
    rows = netinfo.arp_rows()
    scan_hosts = scan_hosts or {}
    macs = [r["mac"] for r in rows]
    by_mac: dict[str, list[str]] = {}
    for r in rows:
        r["vendor"] = vendors.lookup_smart(r["mac"], macs)
        r["macKind"] = mac_kind(r["mac"])["kind"]
        sh = scan_hosts.get(r["ip"])
        r["hostname"] = sh.get("hostname") if sh else None
        r["inScan"] = bool(sh and sh.get("alive"))
        by_mac.setdefault(r["mac"], []).append(r["ip"])
    conflicts = []
    for mac, ips in by_mac.items():
        if len(ips) > 1:
            conflicts.append({"kind": "mac", "mac": mac, "ips": sorted(ips),
                              "text": f"{mac} answers for {len(ips)} addresses ({', '.join(sorted(ips)[:4])}{'…' if len(ips) > 4 else ''}). "
                                      "Usually a router or a device with several addresses; if unexpected, it can be spoofing."})
    for ip, sh in scan_hosts.items():
        smac = sh.get("mac")
        amac = next((r["mac"] for r in rows if r["ip"] == ip), None)
        if smac and amac and smac.upper() != amac.upper():
            conflicts.append({"kind": "ip", "ip": ip, "macs": [smac, amac],
                              "text": f"{ip} was seen with two different hardware addresses ({smac} and {amac}): two devices may be fighting over one IP."})
    rows.sort(key=lambda r: tuple(int(p) for p in r["ip"].split(".")) if is_ipv4(r["ip"]) else (999,))
    return {"rows": rows, "conflicts": conflicts, "count": len(rows)}


def arp_lookup(q: str, netinfo: NetInfo, vendors: MacVendors, pinger, dns: "DnsClient", scan_hosts: dict | None = None) -> dict:
    q = (q or "").strip()
    if not q:
        raise ValueError("Enter a hardware (MAC) address or an IP address.")
    scan_hosts = scan_hosts or {}
    mac = normalise_mac(q)
    if mac and not is_ipv4(q):
        rows = netinfo.arp_rows()
        kind = mac_kind(mac)
        ips = sorted({r["ip"] for r in rows if r["mac"] == mac} | {ip for ip, h in scan_hosts.items() if (h.get("mac") or "").upper() == mac})
        names = {ip: (scan_hosts.get(ip) or {}).get("hostname") for ip in ips}
        return {"type": "mac", "mac": mac, "vendor": vendors.lookup_smart(mac, [r["mac"] for r in rows]), **kind,
                "ips": [{"ip": ip, "hostname": names.get(ip)} for ip in ips],
                "summary": (f"Belongs to {', '.join(ips)}" if ips else "Not currently seen on this network (no address maps to it).")}
    if not is_ipv4(q):
        try:
            q = resolve4(q)
        except ValueError as e:
            raise ValueError(str(e))
    ip = q
    ping = pinger.ping(ip, 1000) if pinger else None
    rows = netinfo.arp_rows()
    row = next((r for r in rows if r["ip"] == ip), None)
    own = next((i for i in netinfo.interfaces() if i["ip"] == ip), None)
    mac = own["mac"] if own else (row["mac"] if row else (scan_hosts.get(ip) or {}).get("mac"))
    vendor = vendors.lookup_smart(mac, [r["mac"] for r in rows]) if mac else None
    name = (scan_hosts.get(ip) or {}).get("hostname") or (dns.ptr(ip, timeout=1.0) if dns else None)
    on_link = mac is not None
    return {"type": "ip", "ip": ip, "mac": mac, "vendor": vendor, "hostname": name, "iface": (row or {}).get("iface") or (own or {}).get("name"),
            "kind": (row or {}).get("kind"), "macKind": mac_kind(mac)["kind"] if mac else None, "own": bool(own),
            "answersPing": bool(ping and ping.status == "ok"), "rttMs": round(ping.rtt_ms, 1) if ping and ping.rtt_ms is not None else None,
            "summary": ("This computer's own address." if own else
                        f"On your local network as {mac}" if on_link else
                        ("Answers pings but is not on your local network (reached through the router), so it has no hardware address here." if ping and ping.status == "ok"
                         else "No hardware address known and no reply to a ping: the device is off, blocking pings, or on another network."))}


# ----------------------------------------------------------------------------
# DNS client
# ----------------------------------------------------------------------------
class DnsClient:
    TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33,
             "CAA": 257, "OPT": 41}
    TYPE_NAMES = {v: k for k, v in TYPES.items()}
    RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
    ALL_COMMON = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]
    PRESETS = [("Cloudflare", "1.1.1.1"), ("Google", "8.8.8.8"), ("Quad9", "9.9.9.9")]

    def __init__(self, netinfo: NetInfo):
        self.netinfo = netinfo

    # -- wire format ---------------------------------------------------------------
    @staticmethod
    def _encode_name(name: str) -> bytes:
        name = name.rstrip(".")
        if not name:
            return b"\0"
        out = b""
        for label in name.split("."):
            lb = label.encode("idna") if not label.isascii() else label.encode()
            if not 0 < len(lb) < 64:
                raise ValueError(f"'{label}' is not a valid part of a name.")
            out += bytes([len(lb)]) + lb
        return out + b"\0"

    def build_query(self, name: str, qtype: int, edns: bool = True) -> tuple[int, bytes]:
        qid = random.randint(0, 0xFFFF)
        hdr = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 1 if edns else 0)
        q = self._encode_name(name) + struct.pack("!HH", qtype, 1)
        opt = b"\0" + struct.pack("!HHIH", 41, 1232, 0, 0) if edns else b""
        return qid, hdr + q + opt

    @staticmethod
    def read_name(msg: bytes, off: int) -> tuple[str, int]:
        labels = []
        jumps = 0
        end = None
        while True:
            if off >= len(msg):
                raise ValueError("truncated name")
            ln = msg[off]
            if ln & 0xC0 == 0xC0:
                ptr = struct.unpack_from("!H", msg, off)[0] & 0x3FFF
                if end is None:
                    end = off + 2
                off = ptr
                jumps += 1
                if jumps > 64:
                    raise ValueError("name loop")
                continue
            off += 1
            if ln == 0:
                break
            labels.append(msg[off:off + ln].decode("idna", "replace") if False else msg[off:off + ln].decode("ascii", "replace"))
            off += ln
        return ".".join(labels), (end if end is not None else off)

    def _rdata(self, msg: bytes, rtype: int, off: int, ln: int) -> str:
        d = msg[off:off + ln]
        try:
            if rtype == 1 and ln == 4:
                return socket.inet_ntoa(d)
            if rtype == 28 and ln == 16:
                return socket.inet_ntop(socket.AF_INET6, d)
            if rtype in (2, 5, 12):
                return self.read_name(msg, off)[0]
            if rtype == 15:
                pref = struct.unpack_from("!H", msg, off)[0]
                return f"{pref} {self.read_name(msg, off + 2)[0]}"
            if rtype == 16:
                parts, p = [], 0
                while p < ln:
                    sl = d[p]
                    parts.append(d[p + 1:p + 1 + sl].decode("utf-8", "replace"))
                    p += 1 + sl
                return "".join(parts)
            if rtype == 6:
                mname, p = self.read_name(msg, off)
                rname, p = self.read_name(msg, p)
                serial, refresh, retry, expire, minimum = struct.unpack_from("!IIIII", msg, p)
                return f"{mname} {rname} serial {serial} refresh {refresh} retry {retry} expire {expire} min {minimum}"
            if rtype == 33:
                pri, wt_, port = struct.unpack_from("!HHH", msg, off)
                return f"{pri} {wt_} {port} {self.read_name(msg, off + 6)[0]}"
            if rtype == 257:
                flags, tl = d[0], d[1]
                return f"{flags} {d[2:2 + tl].decode('ascii', 'replace')} {d[2 + tl:].decode('utf-8', 'replace')}"
        except (struct.error, ValueError, IndexError):
            pass
        return d.hex()

    def parse(self, msg: bytes) -> dict:
        qid, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", msg, 0)
        off = 12
        questions = []
        for _ in range(qd):
            name, off = self.read_name(msg, off)
            qt, qc = struct.unpack_from("!HH", msg, off)
            off += 4
            questions.append({"name": name, "type": self.TYPE_NAMES.get(qt, str(qt))})

        def section(count):
            nonlocal off
            out = []
            for _ in range(count):
                name, off = self.read_name(msg, off)
                rtype, rclass, ttl, rdlen = struct.unpack_from("!HHIH", msg, off)
                off += 10
                if rtype != 41:
                    out.append({"name": name, "type": self.TYPE_NAMES.get(rtype, str(rtype)), "ttl": ttl,
                                "data": self._rdata(msg, rtype, off, rdlen)})
                off += rdlen
            return out
        answers = section(an)
        authority = section(ns)
        additional = section(ar)
        rcode = flags & 0xF
        return {"id": qid, "rcode": rcode, "rcodeText": self.RCODES.get(rcode, str(rcode)),
                "flags": {"aa": bool(flags & 0x0400), "tc": bool(flags & 0x0200), "rd": bool(flags & 0x0100),
                          "ra": bool(flags & 0x0080), "ad": bool(flags & 0x0020)},
                "question": questions, "answers": answers, "authority": authority, "additional": additional}

    # -- transport ---------------------------------------------------------------------
    def query(self, server: str, name: str, qtype: str, timeout: float = 2.0) -> dict:
        t = self.TYPES.get(qtype.upper())
        if not t:
            raise ValueError(f"Unknown record type {qtype}.")
        qid, pkt = self.build_query(name, t)
        t0 = time.perf_counter()
        result = {"server": server, "name": name, "type": qtype.upper(), "transport": "udp"}
        family = socket.AF_INET6 if ":" in server else socket.AF_INET
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(pkt, (server, 53))
                deadline = time.perf_counter() + timeout
                while True:
                    remaining = deadline - time.perf_counter()
                    if remaining <= 0:
                        raise socket.timeout()
                    s.settimeout(remaining)
                    data, _ = s.recvfrom(4096)
                    if len(data) >= 2 and struct.unpack_from("!H", data, 0)[0] == qid:
                        break
            parsed = self.parse(data)
            if parsed["flags"]["tc"]:
                result["transport"] = "tcp"
                with socket.create_connection((server, 53), timeout=timeout) as c:
                    c.settimeout(timeout)
                    c.sendall(struct.pack("!H", len(pkt)) + pkt)
                    hdr = self._recv_exact(c, 2)
                    ln = struct.unpack("!H", hdr)[0]
                    data = self._recv_exact(c, ln)
                parsed = self.parse(data)
        except socket.timeout:
            result.update(error=f"No answer from {server} within {timeout:g} s.", ms=round((time.perf_counter() - t0) * 1000, 1))
            return result
        except (OSError, ValueError, struct.error) as e:
            result.update(error=f"Could not query {server}: {e}", ms=round((time.perf_counter() - t0) * 1000, 1))
            return result
        result["ms"] = round((time.perf_counter() - t0) * 1000, 1)
        result.update(parsed)
        return result

    @staticmethod
    def _recv_exact(c: socket.socket, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = c.recv(n - len(buf))
            if not chunk:
                raise OSError("connection closed")
            buf += chunk
        return buf

    @staticmethod
    def ptr_name(ip: str) -> str:
        addr = ipaddress.ip_address(ip)
        return addr.reverse_pointer

    def ptr(self, ip: str, server: str | None = None, timeout: float = 1.5) -> str | None:
        """Reverse lookup with a bounded timeout; None if unknown."""
        servers = [server] if server else self.netinfo.dns_servers()
        if not servers:
            try:
                return socket.gethostbyaddr(ip)[0]
            except (OSError, socket.herror):
                return None
        try:
            r = self.query(servers[0], self.ptr_name(ip), "PTR", timeout)
        except ValueError:
            return None
        for a in r.get("answers", []):
            if a["type"] == "PTR":
                return a["data"].rstrip(".")
        return None

    def servers(self) -> dict:
        return {"system": self.netinfo.dns_servers(), "presets": [{"name": n, "ip": ip} for n, ip in self.PRESETS]}

    def lookup(self, name: str, qtype: str = "A", servers: list[str] | None = None, timeout: float = 2.0) -> dict:
        name = (name or "").strip().rstrip(".")
        if not name:
            raise ValueError("Enter a name to look up, for example example.com.")
        is_ip = False
        try:
            ipaddress.ip_address(name)
            is_ip = True
        except ValueError:
            pass
        if is_ip:
            qname, types = self.ptr_name(name), ["PTR"]
        else:
            qname = name
            types = self.ALL_COMMON if qtype.upper() == "ALL" else [qtype.upper()]
        if not servers:
            servers = self.netinfo.dns_servers()
            if not servers:
                servers = [self.PRESETS[0][1]]
                note = "No system DNS server was found, so Cloudflare (1.1.1.1) was used."
            else:
                note = ""
        else:
            note = ""
        jobs = [(srv, t) for srv in servers for t in types]
        results: dict[str, list[dict]] = {srv: [] for srv in servers}
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, len(jobs))) as ex:
            futs = {ex.submit(self.query, srv, qname, t, timeout): (srv, t) for srv, t in jobs}
            for f in concurrent.futures.as_completed(futs):
                srv, t = futs[f]
                try:
                    results[srv].append(f.result())
                except Exception as e:  # keep one bad server from hiding the others
                    results[srv].append({"server": srv, "name": qname, "type": t, "error": str(e)})
        for srv in results:
            results[srv].sort(key=lambda r: types.index(r["type"]) if r.get("type") in types else 99)
        return {"name": name, "qname": qname, "types": types, "servers": servers, "results": results, "note": note}


# ----------------------------------------------------------------------------
# Scanner
# ----------------------------------------------------------------------------
class Scanner:
    def __init__(self, pinger, netinfo: NetInfo, dns: DnsClient, vendors: MacVendors):
        self.pinger = pinger
        self.netinfo = netinfo
        self.dns = dns
        self.vendors = vendors
        self.log = EventLog()
        self.lock = threading.Lock()
        self.hosts: dict[str, dict] = {}
        self.opts: dict = {}
        self.total = 0
        self.done = 0
        self.alive = 0
        self.intercepted: set[int] = set()   # ports a middlebox answers for every address (DNS interception etc.)
        self.started_at = None
        self.finished_at = None
        self._thread = None
        self._cancel = threading.Event()
        self._executor = None

    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def state(self) -> dict:
        with self.lock:
            return {"running": self.running(), "total": self.total, "done": self.done, "alive": self.alive,
                    "opts": self.opts, "startedAt": self.started_at, "finishedAt": self.finished_at,
                    "seq": self.log.seq, "hosts": sorted(self.hosts.values(), key=lambda h: h["n"]),
                    "backend": getattr(self.pinger, "name", None), "intercepted": sorted(self.intercepted),
                    "dupMacs": self._dup_macs()}

    def start(self, opts: dict) -> dict:
        if self.running():
            raise RuntimeError("A scan is already running. Stop it first.")
        if self.pinger is None:
            raise RuntimeError("No way to send pings was found on this computer.")
        targets = parse_targets(opts.get("range", ""))
        ports = parse_ports(opts.get("ports", list(DEFAULT_PORTS)))
        timeout_ms = int(opts.get("timeoutMs") or 1000)
        timeout_ms = max(200, min(timeout_ms, 5000))
        tcp_timeout = int(opts.get("tcpTimeoutMs") or min(timeout_ms, 600))
        conc = min(int(opts.get("concurrency") or 128), getattr(self.pinger, "max_parallel", 128), 256)
        if ports:  # keep the total number of half-open sockets around 2048 (Windows ephemeral ports)
            conc = max(4, min(conc, 2048 // min(len(ports), PROBE_CHUNK)))
        chunks = -(-len(ports) // PROBE_CHUNK) if ports else 0
        self.opts = {"range": opts.get("range", ""), "ports": ports, "timeoutMs": timeout_ms,
                     "tcpTimeoutMs": tcp_timeout, "retries": int(opts.get("retries", 1)),
                     "resolveNames": bool(opts.get("resolveNames", True)),
                     "portsOnSilent": bool(opts.get("portsOnSilent", True)), "concurrency": conc}
        with self.lock:
            self.hosts = {}
            self.intercepted = set()
            self.total, self.done, self.alive = len(targets), 0, 0
            self.started_at, self.finished_at = time.time(), None
        self.log.clear()
        self._cancel.clear()
        est = len(targets) / conc * (timeout_ms / 1000 * (1 + self.opts["retries"]) + chunks * tcp_timeout / 1000 + 0.3)
        self.log.push({"type": "start", "total": len(targets), "ports": ports, "estimateS": round(est, 1),
                       "range": self.opts["range"]})
        self._thread = threading.Thread(target=self._manage, args=(targets,), daemon=True)
        self._thread.start()
        return {"total": len(targets), "estimateS": round(est, 1)}

    def stop(self) -> bool:
        if not self.running():
            return False
        self._cancel.set()
        ex = self._executor
        if ex:
            ex.shutdown(wait=False, cancel_futures=True)
        return True

    # -- interception detection --------------------------------------------------------
    def _canary_check(self, targets: list[str]) -> None:
        """Probe the port list at three addresses spread through the range before the scan.
        A port that accepts connections on most of them is being answered by the network
        (typically the gateway intercepting DNS), not by devices."""
        ports = self.opts["ports"]
        n = len(targets)
        if not ports or n < 8:
            return
        idx = sorted({min(13, n - 1), min(n // 2 + 7, n - 1), n - 1})
        canaries = [targets[i] for i in idx]
        hits: dict[int, int] = {}
        for ip in canaries:
            if self._cancel.is_set():
                return
            for p, st in tcp_probe(ip, ports, self.opts["tcpTimeoutMs"]).items():
                if st == "open":
                    hits[p] = hits.get(p, 0) + 1
        need = 2 if len(canaries) >= 3 else len(canaries)
        found = sorted(p for p, c in hits.items() if c >= need)
        if found:
            with self.lock:
                self.intercepted.update(found)
            self.log.push({"type": "intercept", "ports": found, "canaries": canaries, "phase": "start"})

    def _posthoc_check(self) -> None:
        """Safety net: a port open on almost every scanned address is intercepted too."""
        with self.lock:
            hosts = list(self.hosts.values())
            known = set(self.intercepted)
        if len(hosts) < 10:
            return
        counts: dict[int, int] = {}
        for h in hosts:
            for p in h.get("ports") or []:
                counts[p] = counts.get(p, 0) + 1
        new = sorted(p for p, c in counts.items() if p not in known and c >= 10 and c >= 0.8 * len(hosts))
        if not new:
            return
        with self.lock:
            self.intercepted.update(new)
        self.log.push({"type": "intercept", "ports": sorted(self.intercepted), "phase": "end"})
        for h in hosts:
            if any(p in new for p in h.get("ports") or []):
                self._evaluate(h)
                self.log.push({"type": "detail", **self._detail(h)})

    def _evaluate(self, host: dict) -> None:
        """Decide alive/status from every piece of evidence; keeps self.alive in step."""
        inter = [p for p in host.get("ports") or [] if p in self.intercepted]
        real_open = [p for p in host.get("ports") or [] if p not in self.intercepted]
        if host.get("pingOk"):
            alive, status = True, "ok"
        elif host.get("mac"):
            alive, status = True, "arp"
        elif real_open:
            alive, status = True, "tcp"
        elif host.get("refused"):
            alive, status = True, "refused"
        elif inter:
            alive, status = False, "intercepted"
        else:
            alive, status = False, host.get("pingStatus") or "timeout"
        with self.lock:
            if alive != host.get("alive", False):
                self.alive += 1 if alive else -1
            host["alive"], host["status"] = alive, status
            host["interceptedPorts"], host["phantom"] = inter, (not alive and bool(inter))

    @staticmethod
    def _detail(host: dict) -> dict:
        return {"ip": host["ip"], "alive": host["alive"], "status": host["status"], "ports": host["ports"],
                "hostname": host.get("hostname"), "interceptedPorts": host.get("interceptedPorts") or [],
                "phantom": bool(host.get("phantom")), "refused": bool(host.get("refused"))}

    def _manage(self, targets: list[str]):
        opts = self.opts
        last_progress = 0.0
        self._canary_check(targets)
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=opts["concurrency"])
        try:
            futures = [self._executor.submit(self._probe, i, ip) for i, ip in enumerate(targets)]
            for f in concurrent.futures.as_completed(futures):
                if self._cancel.is_set():
                    break
                try:
                    f.result()
                except Exception:
                    pass
                now = time.time()
                if now - last_progress > 0.25:
                    last_progress = now
                    with self.lock:
                        self.log.push({"type": "progress", "done": self.done, "total": self.total, "alive": self.alive})
        finally:
            self._executor.shutdown(wait=False, cancel_futures=True)
            self._executor = None
        if not self._cancel.is_set():
            self._posthoc_check()
        # ARP entries appear as a side effect of the pings; read them now.
        arp = self.netinfo.arp_table()
        with self.lock:
            for ip, h in self.hosts.items():
                mac = arp.get(ip)
                if mac and not h.get("mac"):
                    h["mac"] = mac
                    h["vendor"] = self.vendors.lookup(mac)
                    if not h["alive"]:
                        h["alive"] = True
                        h["status"] = "arp"
                        self.alive += 1
            self.finished_at = time.time()
            elapsed = self.finished_at - (self.started_at or self.finished_at)
            macs = {ip: {"mac": h["mac"], "vendor": h.get("vendor")} for ip, h in self.hosts.items() if h.get("mac")}
            dups = self._dup_macs()
        self.log.push({"type": "arp", "hosts": macs, "dupMacs": dups})
        self.log.push({"type": "done", "cancelled": self._cancel.is_set(), "elapsed": round(elapsed, 1),
                       "alive": self.alive, "done": self.done, "total": self.total, "dupMacs": dups})

    def _dup_macs(self) -> dict:
        """{mac: [ips]} for hardware addresses seen on more than one answering address (call with the lock held)."""
        by: dict[str, list[str]] = {}
        for ip, h in self.hosts.items():
            m = (h.get("mac") or "").upper()
            if not m or m == "FF:FF:FF:FF:FF:FF" or int(m[:2], 16) & 1:
                continue
            by.setdefault(m, []).append(ip)
        return {m: sorted(ips, key=lambda x: tuple(int(p) for p in x.split("."))) for m, ips in by.items() if len(ips) > 1}

    def _probe(self, n: int, ip: str):
        if self._cancel.is_set():
            return
        o = self.opts
        r = self.pinger.ping(ip, o["timeoutMs"])
        tries = 0
        while r.status == "timeout" and tries < o["retries"] and not self._cancel.is_set():
            tries += 1
            r = self.pinger.ping(ip, o["timeoutMs"])
        alive = r.status == "ok"
        host = {"n": n, "ip": ip, "alive": alive, "rtt": round(r.rtt_ms, 2) if r.rtt_ms is not None else None,
                "status": r.status, "ports": [], "hostname": None, "mac": None, "vendor": None,
                "pingOk": alive, "pingStatus": r.status, "refused": False, "interceptedPorts": [], "phantom": False}
        with self.lock:
            self.hosts[ip] = host
            if alive:
                self.alive += 1
        self.log.push({"type": "host", **{k: host[k] for k in ("ip", "alive", "rtt", "status", "n")}})
        if self._cancel.is_set():
            with self.lock:
                self.done += 1
            return
        if (alive or o["portsOnSilent"]) and o["ports"]:
            res = tcp_probe(ip, o["ports"], o["tcpTimeoutMs"])
            host["ports"] = [p for p in o["ports"] if res.get(p) == "open"]
            host["refused"] = any(st == "refused" for st in res.values())
            self._evaluate(host)
        if host["alive"] and o["resolveNames"] and not self._cancel.is_set():
            host["hostname"] = self.dns.ptr(ip)
        with self.lock:
            self.done += 1
        self.log.push({"type": "detail", **self._detail(host)})

    def csv(self) -> str:
        import io
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow(["ip", "alive", "hostname", "mac", "vendor", "rtt_ms", "status", "open_ports", "note"])
        with self.lock:
            rows = sorted(self.hosts.values(), key=lambda h: h["n"])
            dups = self._dup_macs()
        for h in rows:
            inter = h.get("interceptedPorts") or []
            shared = dups.get((h.get("mac") or "").upper())
            note = (f"same hardware address as {', '.join(ip for ip in shared if ip != h['ip'])}; " if shared else "") + ("only answered on intercepted port(s) " + " ".join(map(str, inter)) + "; probably no device") if h.get("phantom") else \
                   ("port(s) " + " ".join(map(str, inter)) + " intercepted by the network") if inter else \
                   ("no ping reply but refused a connection" if h.get("status") == "refused" else "")
            w.writerow([h["ip"], "yes" if h["alive"] else "no", h.get("hostname") or "", h.get("mac") or "",
                        h.get("vendor") or "", h["rtt"] if h["rtt"] is not None else "", h["status"],
                        " ".join(str(p) for p in h["ports"]), note])
        return buf.getvalue()


# ----------------------------------------------------------------------------
# Ping monitor (PingPlotter-style: end-to-end ping + per-hop route probes)
# ----------------------------------------------------------------------------
@dataclass
class Hop:
    n: int
    ip: str | None = None
    name: str | None = None
    dest: bool = False
    sent: int = 0
    received: int = 0
    min: float | None = None
    max: float | None = None
    sum: float = 0.0
    last: float | None = None
    changes: int = 0
    silent_run: int = 0
    ok_run: int = 0            # probes at this TTL answered as the destination (route got shorter)
    stale: bool = False
    flapping: bool = False
    cand_ip: str | None = None
    cand_n: int = 0
    seen: dict = field(default_factory=dict)             # ip -> last round seen
    samples: collections.deque = field(default_factory=lambda: collections.deque(maxlen=120))

    def add(self, ts: float, rtt: float | None) -> None:
        self.sent += 1
        self.samples.append((ts, rtt))
        if rtt is None:
            self.silent_run += 1
            if self.silent_run >= 10 and self.ip:
                self.stale = True
        else:
            self.silent_run = 0
            self.stale = False
            self.received += 1
            self.last = rtt
            self.sum += rtt
            self.min = rtt if self.min is None else min(self.min, rtt)
            self.max = rtt if self.max is None else max(self.max, rtt)

    def reset(self) -> None:
        self.sent = self.received = 0
        self.min = self.max = self.last = None
        self.sum = 0.0
        self.silent_run = self.ok_run = 0
        self.stale = False
        self.samples.clear()

    def stats(self) -> dict:
        loss = (1 - self.received / self.sent) * 100 if self.sent else 0.0
        return {"n": self.n, "ip": self.ip, "name": self.name, "dest": self.dest, "sent": self.sent,
                "recv": self.received, "lossPct": round(loss, 1),
                "avg": round(self.sum / self.received, 2) if self.received else None,
                "min": round(self.min, 2) if self.min is not None else None,
                "max": round(self.max, 2) if self.max is not None else None,
                "cur": round(self.last, 2) if self.last is not None else None,
                "changes": self.changes, "stale": self.stale, "flapping": self.flapping,
                "addresses": len(self.seen)}

    def recent(self) -> list:
        return [[round(ts, 3), (round(r, 2) if r is not None else None)] for ts, r in self.samples]


# ----------------------------------------------------------------------------
# Service checks (Uptime-Robot style): TCP port and web page, next to ICMP ping
# ----------------------------------------------------------------------------
CheckResult = collections.namedtuple("CheckResult", "status rtt_ms detail code")


def parse_watch_target(text: str, kind: str = "auto", port=None) -> dict:
    """Turn what the user typed into {kind, host, port, url}.

    'https://example.com/health'  -> http check on that URL (host = example.com)
    'fileserver:445' / '10.0.0.5:3389' -> tcp check on that port
    anything else -> ping (unless kind/port say otherwise)
    """
    text = (text or "").strip()
    kind = (kind or "auto").lower()
    if re.match(r"^https?://", text, re.I):
        u = urllib.parse.urlsplit(text)
        if not u.hostname:
            raise ValueError("That web address has no host name.")
        return {"kind": "http", "host": u.hostname, "port": u.port or (443 if u.scheme == "https" else 80), "url": text}
    if kind == "http":
        url = text if re.match(r"^https?://", text, re.I) else ("https://" + text if (port in (None, "", 443)) else f"http://{text}:{port}")
        return parse_watch_target(url, "http")
    m = re.match(r"^([^\s:/]+):(\d{1,5})$", text)
    if m and kind in ("auto", "tcp"):
        return {"kind": "tcp", "host": m.group(1), "port": int(m.group(2)), "url": None}
    if kind == "tcp" or (port not in (None, "") and kind == "auto"):
        p = int(port or 0)
        if not 1 <= p <= 65535:
            raise ValueError("Enter a port number between 1 and 65535 for a port check.")
        return {"kind": "tcp", "host": text, "port": p, "url": None}
    return {"kind": "ping", "host": text, "port": None, "url": None}


def tcp_check(ip: str, port: int, timeout_ms: int) -> CheckResult:
    """One TCP connect: ok (with connect time) / refused / timeout / error."""
    t0 = time.perf_counter()
    try:
        with socket.create_connection((ip, port), timeout=max(0.1, timeout_ms / 1000)):
            return CheckResult("ok", (time.perf_counter() - t0) * 1000, f"port {port} accepted the connection", None)
    except socket.timeout:
        return CheckResult("timeout", None, f"no answer on port {port}", None)
    except ConnectionRefusedError:
        return CheckResult("refused", None, f"port {port} refused the connection (nothing listening)", None)
    except OSError as e:
        code = getattr(e, "winerror", None) or getattr(e, "errno", None)
        if code in _REFUSED:
            return CheckResult("refused", None, f"port {port} refused the connection (nothing listening)", None)
        return CheckResult("error", None, str(e), None)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_HTTP_OPENER = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl.create_default_context()))
_HTTP_OPENER.addheaders = [("User-Agent", "LinkTest uptime check"), ("Accept", "*/*")]


def http_check(url: str, timeout_ms: int, ip: str | None = None) -> CheckResult:
    """GET the page; 2xx/3xx = ok (time to first byte), 4xx/5xx = http_error, else timeout/error.

    Redirects are followed (up to urllib's limit). A certificate problem is reported as an
    error with a plain-language detail because the site is effectively down for users.
    """
    t0 = time.perf_counter()
    try:
        req = urllib.request.Request(url, method="GET")
        with _HTTP_OPENER.open(req, timeout=max(0.2, timeout_ms / 1000)) as r:
            rtt = (time.perf_counter() - t0) * 1000
            r.read(4096)
            code = r.status
            return CheckResult("ok", rtt, f"HTTP {code} {r.reason}".strip(), code)
    except urllib.error.HTTPError as e:
        rtt = (time.perf_counter() - t0) * 1000
        return CheckResult("http_error", None, f"HTTP {e.code} {e.reason}".strip(), e.code)
    except urllib.error.URLError as e:
        reason = e.reason
        if isinstance(reason, socket.timeout) or "timed out" in str(reason).lower():
            return CheckResult("timeout", None, "the web server did not answer in time", None)
        if isinstance(reason, ssl.SSLError) or "certificate" in str(reason).lower() or "ssl" in str(reason).lower():
            return CheckResult("error", None, "certificate problem: " + str(reason)[:120], None)
        if isinstance(reason, ConnectionRefusedError) or getattr(reason, "errno", None) in _REFUSED or getattr(reason, "winerror", None) in _REFUSED:
            return CheckResult("refused", None, "the server refused the connection (nothing listening on that port)", None)
        return CheckResult("error", None, str(reason)[:160], None)
    except (socket.timeout, TimeoutError):
        return CheckResult("timeout", None, "the web server did not answer in time", None)
    except Exception as e:  # noqa: BLE001
        return CheckResult("error", None, str(e)[:160], None)


class Target:
    MAX_SAMPLES = 20000

    def __init__(self, spec: dict):
        self.id = spec.get("id") or uuid.uuid4().hex[:8]
        parsed = parse_watch_target(str(spec.get("host", "")), str(spec.get("kind") or "auto"), spec.get("port"))
        self.kind = parsed["kind"]                  # ping | tcp | http
        self.host = parsed["host"]
        self.port = parsed["port"]
        self.url = spec.get("url") or parsed["url"]
        self.label = str(spec.get("label", "") or "").strip()[:60]
        default_interval = 1.0 if self.kind == "ping" else 30.0
        self.interval = float(spec.get("interval") or default_interval)
        self.interval = max(0.2, min(self.interval, 3600.0))
        max_to = 5000 if self.kind == "ping" else 15000
        self.timeout_ms = int(spec.get("timeoutMs") or min(1000 if self.kind == "ping" else 5000, int(self.interval * 1000)))
        self.timeout_ms = max(100, min(self.timeout_ms, int(self.interval * 1000), max_to))
        self.last_detail: str | None = None
        self.last_code = None
        self.paused = bool(spec.get("paused", False))
        self.muted = bool(spec.get("muted", False))
        self.hops_on = bool(spec.get("hopsOn", True))
        self.collapsed = bool(spec.get("collapsed", False))
        self.order = int(spec.get("order") or 0)
        self.created = float(spec.get("created") or time.time())
        self.ip: str | None = None
        self.resolve_error: str | None = None
        self.samples: collections.deque = collections.deque(maxlen=self.MAX_SAMPLES)  # (ts, rtt|None, status)
        self.lock = threading.Lock()
        # route
        self.route: list[Hop] = []
        self.route_version = 0
        self.route_changes = 0
        self.route_state = "off" if not self.hops_on else "pending"
        self.last_discovery = 0.0
        self._hop_round = 0
        self._last_hop_round = 0.0
        self._hop_pending = 0
        self._hop_futures: list = []
        self._discovering = False
        self._disc_delay = 0.0
        self.reset_stats()
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self._writer: _DayCsv | None = None
        self._last_resolve = 0.0

    def reset_stats(self):
        self.sent = 0
        self.received = 0
        self.min = None
        self.max = None
        self.sum = 0.0
        self.last = None
        self.last_status = "idle"
        self.jitter = 0.0
        self._prev_rtt = None
        self.consecutive_fail = 0
        self.outages: list[dict] = []
        self.state = "paused" if self.paused else "starting"
        for h in self.route:
            h.reset()

    def spec(self) -> dict:
        return {"id": self.id, "host": self.host, "kind": self.kind, "port": self.port, "url": self.url,
                "label": self.label, "interval": self.interval,
                "timeoutMs": self.timeout_ms, "paused": self.paused, "muted": self.muted,
                "hopsOn": self.hops_on, "collapsed": self.collapsed, "order": self.order, "created": self.created}

    def key(self) -> str:
        return self.url.lower() if self.kind == "http" and self.url else f"{self.host.lower()}:{self.port}" if self.kind == "tcp" else self.host.lower()

    def display(self) -> str:
        return self.url if self.kind == "http" and self.url else f"{self.host}:{self.port}" if self.kind == "tcp" else self.host

    def stats(self, hop_samples: bool = False) -> dict:
        with self.lock:
            loss = (1 - self.received / self.sent) * 100 if self.sent else 0.0
            route = []
            for h in self.route:
                hs = h.stats()
                if hop_samples:
                    hs["recent"] = h.recent()
                route.append(hs)
            return {**self.spec(), "ip": self.ip, "resolveError": self.resolve_error, "state": self.state,
                    "sent": self.sent, "received": self.received, "lossPct": round(loss, 2),
                    "min": round(self.min, 2) if self.min is not None else None,
                    "max": round(self.max, 2) if self.max is not None else None,
                    "avg": round(self.sum / self.received, 2) if self.received else None,
                    "last": round(self.last, 2) if self.last is not None else None, "lastStatus": self.last_status,
                    "lastDetail": self.last_detail, "lastCode": self.last_code, "display": self.display(),
                    "uptimePct": round(100 - loss, 2) if self.sent else None,
                    "jitter": round(self.jitter, 2), "consecutiveFail": self.consecutive_fail,
                    "outages": self.outages[-50:], "samples": len(self.samples),
                    "routeVersion": self.route_version, "routeChanges": self.route_changes,
                    "routeState": self.route_state, "lastDiscovery": self.last_discovery, "route": route}

    def recent(self, n: int = 600) -> list:
        with self.lock:
            items = list(self.samples)[-n:]
        return [[round(ts, 3), (round(r, 2) if r is not None else None), st] for ts, r, st in items]


class _DayCsv:
    """Buffered writer for pings/<id>/<YYYY-MM-DD>.csv with date rotation."""

    def __init__(self, folder: str):
        self.folder = folder
        self.rows: list[list] = []
        self.last_flush = time.time()
        self.lock = threading.Lock()

    def add(self, ts: float, rtt, status: str):
        with self.lock:
            self.rows.append([f"{ts:.3f}", "" if rtt is None else f"{rtt:.2f}", status])
            if len(self.rows) >= 20 or time.time() - self.last_flush > 5:
                self._flush_locked()

    def flush(self):
        with self.lock:
            self._flush_locked()

    def _flush_locked(self):
        if not self.rows:
            self.last_flush = time.time()
            return
        try:
            os.makedirs(self.folder, exist_ok=True)
            by_day: dict[str, list] = {}
            for row in self.rows:
                day = time.strftime("%Y-%m-%d", time.localtime(float(row[0])))
                by_day.setdefault(day, []).append(row)
            for day, rows in by_day.items():
                path = os.path.join(self.folder, f"{day}.csv")
                new = not os.path.exists(path)
                with open(path, "a", encoding="utf-8", newline="") as f:
                    w = csv.writer(f, lineterminator="\n")
                    if new:
                        w.writerow(["ts", "rtt_ms", "status"])
                    w.writerows(rows)
        except OSError:
            pass
        self.rows = []
        self.last_flush = time.time()


class PingMonitor:
    OUTAGE_THRESHOLD = 3
    MAX_TARGETS = 50
    HOP_WORKERS = 64
    HOP_TIMEOUT_MS = 1000
    DISCOVERY_EVERY = 300.0
    DISCOVERY_BATCH = 8
    MAX_HOPS = 30
    SILENT_BACKOFF_AFTER = 5
    SILENT_BACKOFF_EVERY = 5
    FLAP_WINDOW = 20

    def __init__(self, pinger, base_dir: str, settings: dict, save_settings, dns: "DnsClient | None" = None):
        self.pinger = pinger
        self.dns = dns
        self.base_dir = base_dir
        self.settings = settings
        self.save_settings = save_settings
        self.log = EventLog(keep=20000)
        self.targets: dict[str, Target] = {}
        self.lock = threading.Lock()
        self.retention_days = int(settings.get("pingRetentionDays") or 30)
        self.outage_threshold = int(settings.get("pingOutageThreshold") or self.OUTAGE_THRESHOLD)
        self._pool: concurrent.futures.ThreadPoolExecutor | None = None
        self._pool_lock = threading.Lock()
        self._ptr_cache: dict[str, tuple[str | None, float]] = {}
        self._ptr_q: "queue.Queue[tuple[str, str]]" = queue.Queue()
        self._ptr_inflight: set[str] = set()
        self._ptr_thread: threading.Thread | None = None
        self._cli = getattr(pinger, "name", "") == "ping-cli"
        os.makedirs(base_dir, exist_ok=True)
        for idx, spec in enumerate(settings.get("pingTargets") or []):
            try:
                t = Target(spec)
                if "order" not in spec:
                    t.order = idx
                t._disc_delay = idx * 0.3
                self._add(t, persist=False, load_history=True)
            except Exception:
                pass
        threading.Thread(target=self.prune, daemon=True).start()

    # -- pool / helpers ------------------------------------------------------------
    def _pool_get(self) -> concurrent.futures.ThreadPoolExecutor:
        with self._pool_lock:
            if self._pool is None:
                workers = 16 if self._cli else min(self.HOP_WORKERS, getattr(self.pinger, "max_parallel", 64))
                self._pool = concurrent.futures.ThreadPoolExecutor(max_workers=workers, thread_name_prefix="hop")
            return self._pool

    @property
    def hop_workers(self) -> int:
        return 16 if self._cli else min(self.HOP_WORKERS, getattr(self.pinger, "max_parallel", 64))

    def _hop_interval(self, t: Target) -> float:
        return max(t.interval, 5.0 if self._cli else 1.0)

    def _hop_timeout(self, t: Target) -> int:
        return min(t.timeout_ms, self.HOP_TIMEOUT_MS)

    # -- management ----------------------------------------------------------------
    def _persist(self):
        self.settings["pingTargets"] = [t.spec() for t in self.targets.values()]
        try:
            self.save_settings()
        except Exception:
            pass

    def add(self, spec: dict) -> dict:
        host = str(spec.get("host", "")).strip()
        if not host:
            raise ValueError("Enter an address or name to watch.")
        if len(self.targets) >= self.MAX_TARGETS:
            raise ValueError(f"You can watch up to {self.MAX_TARGETS} addresses at a time.")
        probe = Target(spec)  # parses kind/host/port/url and validates
        for t in self.targets.values():
            if t.key() == probe.key():
                raise ValueError(f"{probe.display()} is already being watched.")
        resolve4(probe.host)  # immediate feedback; the thread re-resolves later anyway
        t = probe
        t.order = max([x.order for x in self.targets.values()] + [-1]) + 1
        self._add(t, persist=True, load_history=False)
        return t.stats()

    def sorted_targets(self) -> list[Target]:
        return sorted(self.targets.values(), key=lambda t: (t.order, t.created))

    def reorder(self, ids: list) -> list[dict]:
        """Apply a new display order (ids first, then anything not mentioned in its old order)."""
        known = [str(i) for i in ids if str(i) in self.targets]
        rest = [t.id for t in self.sorted_targets() if t.id not in known]
        for i, tid in enumerate(known + rest):
            self.targets[tid].order = i
        self._persist()
        return self.snapshot()

    def _add(self, t: Target, persist: bool, load_history: bool):
        with self.lock:
            self.targets[t.id] = t
        t._writer = _DayCsv(os.path.join(self.base_dir, t.id))
        if load_history:
            self._load_recent(t)
        if not t.paused:
            self._start_thread(t)
        if persist:
            self._persist()

    def _start_thread(self, t: Target):
        if t._thread and t._thread.is_alive():
            return
        t._stop.clear()
        t.state = "starting"
        t._thread = threading.Thread(target=self._loop, args=(t,), daemon=True, name=f"ping-{t.id}")
        t._thread.start()

    def get(self, tid: str) -> Target:
        t = self.targets.get(tid)
        if not t:
            raise ValueError("That address is no longer being watched.")
        return t

    def _cancel_hops(self, t: Target):
        for f in t._hop_futures:
            f.cancel()
        t._hop_futures = []
        t._hop_pending = 0

    def remove(self, tid: str, delete_files: bool = True) -> None:
        t = self.get(tid)
        t._stop.set()
        t._wake.set()
        self._cancel_hops(t)
        if t._thread:
            t._thread.join(timeout=3)
        if t._writer:
            t._writer.flush()
        with self.lock:
            self.targets.pop(tid, None)
        if delete_files:
            shutil.rmtree(os.path.join(self.base_dir, tid), ignore_errors=True)
        self._persist()
        self.log.push({"type": "removed", "id": tid})

    def pause(self, tid: str, paused: bool) -> dict:
        t = self.get(tid)
        t.paused = paused
        if paused:
            t._stop.set()
            t._wake.set()
            self._cancel_hops(t)
            with t.lock:
                t.state = "paused"
        else:
            self._start_thread(t)
        self._persist()
        return t.stats()

    def update(self, tid: str, patch: dict) -> dict:
        t = self.get(tid)
        restart = False
        if "label" in patch:
            t.label = str(patch["label"] or "").strip()[:60]
        if "muted" in patch:
            t.muted = bool(patch["muted"])
        if "collapsed" in patch:
            t.collapsed = bool(patch["collapsed"])
        if "hopsOn" in patch:
            on = bool(patch["hopsOn"])
            if on != t.hops_on:
                t.hops_on = on
                if not on:
                    self._cancel_hops(t)
                    with t.lock:
                        t.route_state = "off"
                else:
                    with t.lock:
                        t.route_state = "ok" if t.route else "pending"
                    t._wake.set()
        if "interval" in patch and patch["interval"]:
            t.interval = max(0.2, min(float(patch["interval"]), 3600.0))
            t.timeout_ms = min(t.timeout_ms, int(t.interval * 1000))
            restart = True
        if "timeoutMs" in patch and patch["timeoutMs"]:
            t.timeout_ms = max(100, min(int(patch["timeoutMs"]), int(t.interval * 1000), 5000))
        if "host" in patch and str(patch["host"]).strip() and str(patch["host"]).strip() != t.host:
            resolve4(str(patch["host"]).strip())
            t.host = str(patch["host"]).strip()
            t.ip = None
            with t.lock:
                t.route = []
                t.route_version += 1
            restart = True
        if restart and not t.paused:
            t._wake.set()
        self._persist()
        return t.stats()

    def set_collapsed_all(self, collapsed: bool) -> list[dict]:
        for t in self.targets.values():
            t.collapsed = collapsed
        self._persist()
        return self.snapshot()

    def clear(self, tid: str) -> dict:
        t = self.get(tid)
        with t.lock:
            t.reset_stats()
            t.samples.clear()
            if not t.paused:
                t.state = "starting"
        return t.stats()

    def stop_all(self):
        for t in list(self.targets.values()):
            t._stop.set()
            t._wake.set()
            self._cancel_hops(t)
        for t in list(self.targets.values()):
            if t._thread:
                t._thread.join(timeout=2)
            if t._writer:
                t._writer.flush()
        with self._pool_lock:
            if self._pool:
                self._pool.shutdown(wait=False, cancel_futures=True)
                self._pool = None

    # -- the loop ---------------------------------------------------------------------
    def _loop(self, t: Target):
        if t._disc_delay:
            t._wake.wait(t._disc_delay)
            t._wake.clear()
        next_t = time.time()
        while not t._stop.is_set():
            now = time.time()
            if now - next_t > 5 * t.interval:
                # Machine slept or we fell far behind: resync and mark a gap rather than faking an outage.
                self._record(t, now, None, "gap")
                next_t = now
            if now < next_t:
                t._wake.wait(next_t - now)
                t._wake.clear()
                if t._stop.is_set():
                    break
                if time.time() < next_t:  # woken early by an update; recompute
                    next_t = time.time()
                    continue
            next_t += t.interval
            if not t.ip or time.time() - t._last_resolve > 300 or (t.consecutive_fail >= 5 and time.time() - t._last_resolve > 30):
                try:
                    new_ip = resolve4(t.host)
                    if t.ip and new_ip != t.ip:
                        with t.lock:
                            t.route = []
                            t.route_version += 1
                    t.ip = new_ip
                    t.resolve_error = None
                except ValueError as e:
                    if not t.ip:
                        t.resolve_error = str(e)
                        self._record(t, time.time(), None, "unresolved")
                        t._last_resolve = time.time()
                        continue
                t._last_resolve = time.time()
            if t.kind == "tcp":
                c = tcp_check(t.ip, int(t.port), t.timeout_ms)
                t.last_detail, t.last_code = c.detail, None
                self._record(t, time.time(), c.rtt_ms, c.status)
            elif t.kind == "http":
                c = http_check(t.url, t.timeout_ms)
                t.last_detail, t.last_code = c.detail, c.code
                self._record(t, time.time(), c.rtt_ms, c.status)
            else:
                if self.pinger is None:
                    self._record(t, time.time(), None, "error")
                    continue
                r = self.pinger.ping(t.ip, t.timeout_ms)
                ts = time.time()
                if r.status == "ok":
                    self._record(t, ts, r.rtt_ms, "ok")
                elif r.status == "timeout":
                    self._record(t, ts, None, "timeout")
                elif r.status == "unreachable":
                    self._record(t, ts, None, "unreachable")
                else:
                    self._record(t, ts, None, "error")
            # route probes
            if t.hops_on and not t._stop.is_set():
                now = time.time()
                if not t._discovering and (not t.route or now - t.last_discovery > self.DISCOVERY_EVERY):
                    self._maybe_discover(t, "start" if not t.route else "periodic")
                elif not t._discovering and t.route and t._hop_pending == 0 and now - t._last_hop_round >= self._hop_interval(t):
                    self._submit_hop_round(t, now)
        with t.lock:
            if t.paused:
                t.state = "paused"

    def _record(self, t: Target, ts: float, rtt, status: str):
        events = []
        rediscover = False
        with t.lock:
            t.samples.append((ts, rtt, status))
            t.last_status = status
            if status == "gap":
                pass
            elif status == "ok":
                t.sent += 1
                t.received += 1
                t.last = rtt
                t.sum += rtt
                t.min = rtt if t.min is None else min(t.min, rtt)
                t.max = rtt if t.max is None else max(t.max, rtt)
                if t._prev_rtt is not None:
                    t.jitter += (abs(rtt - t._prev_rtt) - t.jitter) / 16
                t._prev_rtt = rtt
                if t.consecutive_fail >= self.outage_threshold and t.outages and t.outages[-1].get("end") is None:
                    o = t.outages[-1]
                    o["end"] = ts
                    o["duration"] = round(ts - o["start"], 1)
                    events.append({"type": "recovery", "id": t.id, "host": t.display(), "label": t.label,
                                   "duration": o["duration"], "muted": t.muted})
                t.consecutive_fail = 0
                t.state = "up"
            else:
                t.sent += 1
                t.consecutive_fail += 1
                if t.consecutive_fail == self.outage_threshold:
                    start = t.samples[-self.outage_threshold][0] if len(t.samples) >= self.outage_threshold else ts
                    t.outages.append({"start": start, "end": None, "count": self.outage_threshold})
                    events.append({"type": "outage", "id": t.id, "host": t.display(), "label": t.label, "muted": t.muted,
                                   "detail": t.last_detail})
                    rediscover = True
                elif t.consecutive_fail > self.outage_threshold and t.outages:
                    t.outages[-1]["count"] = t.consecutive_fail
                t.state = "down" if t.consecutive_fail >= self.outage_threshold else ("unresolved" if status == "unresolved" else "up")
            # the destination row of the route is the end-to-end sample
            if status in ("ok", "timeout", "unreachable", "error", "refused", "http_error") and t.route and t.route[-1].dest:
                t.route[-1].add(ts, rtt if status == "ok" else None)
        if t._writer:
            t._writer.add(ts, rtt, status)
        self.log.push({"type": "sample", "id": t.id, "t": round(ts, 3), "rtt": round(rtt, 2) if rtt is not None else None,
                       "status": status})
        for e in events:
            self.log.push(e)
        if rediscover and t.hops_on and t.route:
            n = len(t.route)
            self._maybe_discover(t, "outage", max(1, n - 2), min(self.MAX_HOPS, n + 8))

    # -- route discovery ---------------------------------------------------------------
    def _maybe_discover(self, t: Target, reason: str, ttl_from: int = 1, ttl_to: int | None = None):
        if t._discovering or t.paused or not t.hops_on or self.pinger is None or not t.ip or t._stop.is_set():
            return
        t._discovering = True
        th = threading.Thread(target=self._discover, args=(t, reason, ttl_from, ttl_to or self.MAX_HOPS), daemon=True,
                              name=f"disc-{t.id}")
        th.start()

    def _discover(self, t: Target, reason: str, ttl_from: int, ttl_to: int):
        try:
            with t.lock:
                if not t.route:
                    t.route_state = "discovering"
            ip = t.ip
            timeout = self._hop_timeout(t)
            pool = self._pool_get()
            found: dict[int, PingResult] = {}
            dest_ttl = None
            ttl = ttl_from
            while ttl <= ttl_to and not t._stop.is_set():
                batch = list(range(ttl, min(ttl + self.DISCOVERY_BATCH, ttl_to) + 1))
                futs = {n: pool.submit(self.pinger.ping, ip, timeout, n) for n in batch}
                for n in batch:
                    try:
                        found[n] = futs[n].result(timeout=timeout / 1000 + 5)
                    except Exception:
                        found[n] = PingResult("error")
                for n in batch:
                    r = found[n]
                    if r.status == "ok" or (r.status == "unreachable" and r.responder == ip):
                        dest_ttl = n
                        break
                if dest_ttl:
                    break
                # trailing silence: stop when the last 8 probed TTLs were all silent and something answered before
                tail = [found[n] for n in sorted(found)[-self.DISCOVERY_BATCH:]]
                answered_any = any(r.responder for r in found.values())
                if len(tail) >= self.DISCOVERY_BATCH and all(not r.responder for r in tail) and (answered_any or ttl >= 16):
                    break
                ttl += self.DISCOVERY_BATCH
            if t._stop.is_set():
                return
            ts = time.time()
            # Build the new hop list for the probed range.
            if dest_ttl:
                last_n = dest_ttl
            else:
                responders = [n for n, r in found.items() if r.responder]
                last_n = (max(responders) + 1) if responders else min(ttl_to, ttl_from + 1)
            with t.lock:
                old = {h.n: h for h in t.route}
                before = [(h.n, h.ip, h.dest) for h in t.route]
                new_route: list[Hop] = [h for h in t.route if h.n < ttl_from and not h.dest]
                for n in range(ttl_from, last_n + 1):
                    r = found.get(n)
                    is_dest = dest_ttl is not None and n == dest_ttl
                    resp = (ip if is_dest else (r.responder if r and r.status in ("ttl_expired", "unreachable") else None))
                    prev = old.get(n)
                    if prev and (prev.ip == resp or (prev.dest and is_dest)):
                        hop = prev
                        hop.dest = is_dest
                        if is_dest:
                            hop.ip = ip
                    else:
                        hop = Hop(n=n, ip=resp, dest=is_dest)
                        if resp:
                            hop.seen[resp] = t._hop_round
                    if r is not None and not is_dest:
                        hop.add(ts, r.rtt_ms if r.status in ("ttl_expired", "unreachable") else None)
                    new_route.append(hop)
                if dest_ttl is None:
                    # keep any previously known destination row so its stats survive a partial rediscovery
                    prev_dest = next((h for h in t.route if h.dest), None)
                    if prev_dest and reason != "start":
                        prev_dest.n = last_n + 1
                        new_route.append(prev_dest)
                new_route.sort(key=lambda h: h.n)
                t.route = new_route
                t.route_state = "ok" if dest_ttl else "partial"
                t.last_discovery = time.time()
                after = [(h.n, h.ip, h.dest) for h in t.route]
                changed = before != after
                if changed:
                    t.route_version += 1
                    if before and reason != "start":
                        t.route_changes += 1
            if changed:
                self.log.push({"type": "route", "id": t.id, "version": t.route_version, "host": t.host, "label": t.label,
                               "detail": "route found" if not before else "route changed", "reason": reason})
            for h in t.route:
                if h.ip and not h.name:
                    self._request_name(t, h.ip)
        finally:
            t._discovering = False
            t._last_hop_round = time.time()

    # -- per-round hop probes -------------------------------------------------------------
    def _submit_hop_round(self, t: Target, now: float):
        t._hop_round += 1
        rnd = t._hop_round
        with t.lock:
            todo = [h for h in t.route if not h.dest and
                    (h.silent_run < self.SILENT_BACKOFF_AFTER or rnd % self.SILENT_BACKOFF_EVERY == 0)]
        t._last_hop_round = now
        if not todo or not t.ip:
            return
        results: dict[int, float | None] = {}
        t._hop_pending = len(todo)
        t._hop_futures = []
        pool = self._pool_get()
        timeout = self._hop_timeout(t)
        for h in todo:
            fut = pool.submit(self.pinger.ping, t.ip, timeout, h.n)
            fut.add_done_callback(functools.partial(self._hop_done, t, h.n, rnd, results))
            t._hop_futures.append(fut)

    def _hop_done(self, t: Target, n: int, rnd: int, results: dict, fut):
        if t._stop.is_set():
            t._hop_pending = max(0, t._hop_pending - 1)
            return
        try:
            r = fut.result()
        except Exception:
            r = PingResult("error")
        ts = time.time()
        shorten = False
        with t.lock:
            hop = next((h for h in t.route if h.n == n), None)
            if hop is not None:
                if r.status == "ok":
                    # The destination answered at this TTL: the route got shorter.
                    hop.ok_run += 1
                    hop.add(ts, r.rtt_ms)
                    if hop.ok_run >= 2:
                        shorten = True
                else:
                    hop.ok_run = 0
                    rtt = r.rtt_ms if r.status in ("ttl_expired", "unreachable") else None
                    hop.add(ts, rtt)
                    if r.responder and r.status in ("ttl_expired", "unreachable"):
                        self._note_responder(t, hop, r.responder, rnd)
                results[n] = round(hop.last, 2) if (r.status in ("ok", "ttl_expired", "unreachable") and r.rtt_ms is not None) else None
            t._hop_pending -= 1
            done = t._hop_pending <= 0
        if done:
            t._hop_pending = 0
            self.log.push({"type": "hops", "id": t.id, "t": round(ts, 3),
                           "hops": [[k, results[k]] for k in sorted(results)]})
        if shorten and not t._discovering:
            self._maybe_discover(t, "shorter", 1, min(self.MAX_HOPS, n + 2))

    def _note_responder(self, t: Target, hop: Hop, ip: str, rnd: int):
        """Called with t.lock held. Debounced route-change detection for one hop."""
        hop.seen[ip] = rnd
        for k in [k for k, v in hop.seen.items() if rnd - v > self.FLAP_WINDOW]:
            del hop.seen[k]
        hop.flapping = len(hop.seen) >= 2
        if hop.ip is None:
            hop.ip = ip
            hop.cand_ip, hop.cand_n = None, 0
            t.route_version += 1
            self._request_name(t, ip)
            return
        if ip == hop.ip:
            hop.cand_ip, hop.cand_n = None, 0
            return
        if ip == hop.cand_ip:
            hop.cand_n += 1
        else:
            hop.cand_ip, hop.cand_n = ip, 1
        if hop.cand_n >= 2:
            hop.ip = ip
            hop.name = None
            hop.cand_ip, hop.cand_n = None, 0
            t.route_version += 1
            if not hop.flapping:
                hop.changes += 1
                t.route_changes += 1
                self.log.push({"type": "route", "id": t.id, "version": t.route_version, "host": t.host, "label": t.label,
                               "detail": f"hop {hop.n} is now {ip}", "reason": "change"})
            self._request_name(t, ip)

    # -- reverse names -----------------------------------------------------------------------
    def _request_name(self, t: Target, ip: str):
        cached = self._ptr_cache.get(ip)
        if cached and (cached[0] or time.time() - cached[1] < 3600):
            for h in t.route:
                if h.ip == ip and not h.name:
                    h.name = cached[0]
            return
        if ip in self._ptr_inflight:
            return
        self._ptr_inflight.add(ip)
        self._ptr_q.put((t.id, ip))
        if self._ptr_thread is None or not self._ptr_thread.is_alive():
            self._ptr_thread = threading.Thread(target=self._ptr_worker, daemon=True, name="ptr")
            self._ptr_thread.start()

    def _ptr_worker(self):
        while True:
            try:
                tid, ip = self._ptr_q.get(timeout=60)
            except queue.Empty:
                return
            name = None
            try:
                if self.dns is not None:
                    name = self.dns.ptr(ip, timeout=1.0)
                else:
                    name = socket.gethostbyaddr(ip)[0]
            except Exception:
                name = None
            self._ptr_cache[ip] = (name, time.time())
            self._ptr_inflight.discard(ip)
            changed = False
            for t in list(self.targets.values()):
                with t.lock:
                    for h in t.route:
                        if h.ip == ip and h.name != name and name:
                            h.name = name
                            changed = True
                    if changed:
                        t.route_version += 1
                changed = False

    # -- history on disk ------------------------------------------------------------------
    def _load_recent(self, t: Target):
        """Refill the in-memory window from today's and yesterday's files."""
        rows = []
        for d in (1, 0):
            day = time.strftime("%Y-%m-%d", time.localtime(time.time() - d * 86400))
            rows.extend(self._read_day(t.id, day))
        for ts, rtt, status in rows[-Target.MAX_SAMPLES:]:
            t.samples.append((ts, rtt, status))

    def _read_day(self, tid: str, day: str) -> list[tuple]:
        path = os.path.join(self.base_dir, tid, f"{day}.csv")
        out = []
        try:
            with open(path, encoding="utf-8", newline="") as f:
                rd = csv.reader(f)
                next(rd, None)
                for row in rd:
                    if len(row) < 3:
                        continue
                    try:
                        out.append((float(row[0]), float(row[1]) if row[1] else None, row[2]))
                    except ValueError:
                        continue
        except OSError:
            pass
        return out

    def history(self, tid: str, hours: float) -> dict:
        t = self.get(tid)
        hours = max(0.05, min(float(hours), 24 * 31))
        now = time.time()
        start = now - hours * 3600
        days = set()
        d = start
        while d <= now + 86400:
            days.add(time.strftime("%Y-%m-%d", time.localtime(d)))
            d += 86400
        rows = []
        for day in sorted(days):
            rows.extend(self._read_day(tid, day))
        rows = [r for r in rows if r[0] >= start]
        flushed_until = rows[-1][0] if rows else 0
        with t.lock:
            rows.extend(s for s in t.samples if s[0] > flushed_until and s[0] >= start)
        rows.sort(key=lambda r: r[0])
        buckets = 1200
        if len(rows) <= buckets:
            return {"id": tid, "hours": hours, "points": [[round(ts, 3), rtt, st] for ts, rtt, st in rows], "raw": True}
        width = hours * 3600 / buckets
        out = []
        cur = None
        for ts, rtt, st in rows:
            b = int((ts - start) / width)
            if cur is None or cur["b"] != b:
                if cur:
                    out.append(cur)
                cur = {"b": b, "t": start + (b + 0.5) * width, "min": None, "max": None, "sum": 0.0, "n": 0, "lost": 0, "gap": 0}
            if st == "gap":
                cur["gap"] += 1
            elif rtt is None:
                cur["lost"] += 1
            else:
                cur["n"] += 1
                cur["sum"] += rtt
                cur["min"] = rtt if cur["min"] is None else min(cur["min"], rtt)
                cur["max"] = rtt if cur["max"] is None else max(cur["max"], rtt)
        if cur:
            out.append(cur)
        points = [[round(c["t"], 1), (round(c["sum"] / c["n"], 2) if c["n"] else None),
                   ("gap" if c["gap"] and not c["n"] and not c["lost"] else ("timeout" if c["lost"] and not c["n"] else "ok")),
                   round(c["min"], 2) if c["min"] is not None else None, round(c["max"], 2) if c["max"] is not None else None,
                   c["lost"], c["n"]] for c in out]
        return {"id": tid, "hours": hours, "points": points, "raw": False}

    def csv_export(self, tid: str, days: int) -> str:
        t = self.get(tid)
        import io
        buf = io.StringIO()
        buf.write("ts,rtt_ms,status,time_local\n")
        for d in range(int(days) - 1, -1, -1):
            day = time.strftime("%Y-%m-%d", time.localtime(time.time() - d * 86400))
            for ts, rtt, st in self._read_day(tid, day):
                buf.write(f"{ts:.3f},{'' if rtt is None else f'{rtt:.2f}'},{st},{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))}\n")
        with t.lock:
            route = [h.stats() for h in t.route]
        if route:
            buf.write("\n# Route at export time\nhop,address,name,avg_ms,min_ms,max_ms,loss_pct,sent\n")
            for h in route:
                buf.write(f"{h['n']},{h['ip'] or ''},{h['name'] or ''},{h['avg'] if h['avg'] is not None else ''},"
                          f"{h['min'] if h['min'] is not None else ''},{h['max'] if h['max'] is not None else ''},{h['lossPct']},{h['sent']}\n")
        return buf.getvalue()

    def prune(self):
        cutoff = time.time() - self.retention_days * 86400
        try:
            for tid in os.listdir(self.base_dir):
                folder = os.path.join(self.base_dir, tid)
                if not os.path.isdir(folder):
                    continue
                if tid not in self.targets:
                    shutil.rmtree(folder, ignore_errors=True)
                    continue
                for name in os.listdir(folder):
                    m = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})\.csv", name)
                    if not m:
                        continue
                    day_ts = time.mktime((int(m[1]), int(m[2]), int(m[3]), 23, 59, 59, 0, 0, -1))
                    if day_ts < cutoff:
                        try:
                            os.remove(os.path.join(folder, name))
                        except OSError:
                            pass
        except OSError:
            pass

    def snapshot(self) -> list[dict]:
        return [t.stats() for t in self.sorted_targets()]


# ----------------------------------------------------------------------------
# ARP commands (the same commands a technician would type; admin ones elevate)
# ----------------------------------------------------------------------------
_CNW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
ARP_ADMIN_ACTIONS = ("flush", "delete", "add")


def _is_admin() -> bool:
    if IS_WIN:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def arp_command_templates() -> dict:
    """Command lines shown in the UI for this OS; {ip}, {mac}, {dev} are filled in."""
    if IS_WIN:
        return {"show": "arp -a", "neighbors": "netsh interface ip show neighbors",
                "flush": "arp -d *", "delete": "arp -d {ip}", "add": "arp -s {ip} {mac}"}
    if IS_MAC:
        return {"show": "arp -an", "neighbors": "arp -al",
                "flush": "sudo arp -d -a", "delete": "sudo arp -d {ip}", "add": "sudo arp -s {ip} {mac}"}
    return {"show": "ip neigh show", "neighbors": "ip -s neigh show",
            "flush": "sudo ip neigh flush all", "delete": "sudo ip neigh del {ip} dev {dev}",
            "add": "sudo ip neigh replace {ip} lladdr {mac} dev {dev} nud permanent"}


def _iface_for_ip(netinfo: "NetInfo | None", ip: str) -> str:
    if not netinfo:
        return "eth0"
    try:
        a = ipaddress.IPv4Address(ip)
        for i in netinfo.interfaces():
            net = i.get("fullNetwork") or i.get("network")
            if net and a in ipaddress.IPv4Network(net, strict=False):
                return i.get("dev") or i["name"]
        prim = [i for i in netinfo.interfaces() if i.get("primary")]
        return (prim[0].get("dev") or prim[0]["name"]) if prim else "eth0"
    except (ValueError, KeyError, IndexError):
        return "eth0"


def _run_admin_windows(inner: str, timeout: int = 180) -> tuple[int, str]:
    """Run a cmd.exe line elevated (UAC prompt) and capture its output through a temp file."""
    import tempfile
    fd, out_path = tempfile.mkstemp(prefix="linktest-arp-", suffix=".txt")
    os.close(fd)
    cmd_line = f'{inner} > "{out_path}" 2>&1'
    script = ("Start-Process -Verb RunAs -Wait -WindowStyle Hidden -FilePath cmd.exe "
              "-ArgumentList @('/c', $env:LT_ARP_CMD)")
    env = dict(os.environ, LT_ARP_CMD=cmd_line)
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                           capture_output=True, text=True, timeout=timeout, env=env, creationflags=_CNW)
        err = (r.stderr or "").strip()
        if "cancel" in err.lower():
            raise RuntimeError("The administrator prompt was cancelled.")
        try:
            with open(out_path, "r", encoding="mbcs", errors="replace") as f:
                out = f.read()
        except OSError:
            out = ""
        if r.returncode != 0 and not out and err:
            raise RuntimeError(err.splitlines()[0])
        return 0, out
    finally:
        try:
            os.remove(out_path)
        except OSError:
            pass


def _run_admin_mac(cmd: str, timeout: int = 180) -> tuple[int, str]:
    """Run a shell line as administrator through the standard macOS password dialog."""
    esc = cmd.replace("\\", "\\\\").replace('"', '\\"')
    script = f'do shell script "{esc} 2>&1" with administrator privileges'
    r = subprocess.run(["osascript", "-e", script], capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0:
        err = (r.stderr or "").strip()
        if "-128" in err or "cancel" in err.lower():
            raise RuntimeError("The administrator prompt was cancelled.")
        raise RuntimeError(err.splitlines()[-1] if err else "macOS did not run the command.")
    return 0, r.stdout


def arp_command(action: str, ip: str | None = None, mac: str | None = None, netinfo: "NetInfo | None" = None) -> dict:
    action = (action or "").strip()
    tpl = arp_command_templates()
    if action not in tpl:
        raise ValueError("Unknown ARP command.")
    ip = (ip or "").strip(); mac = (mac or "").strip(); dev = ""
    if action in ("delete", "add"):
        if not is_ipv4(ip):
            raise ValueError("Enter a valid IPv4 address, e.g. 192.168.1.20.")
        dev = _iface_for_ip(netinfo, ip)
    if action == "add":
        m = normalise_mac(mac)
        if not m:
            raise ValueError("Enter a hardware (MAC) address, e.g. aa-bb-cc-dd-ee-ff.")
        mac = m.replace(":", "-").lower() if IS_WIN else m.lower()
    cmd = tpl[action].format(ip=ip, mac=mac, dev=dev)
    admin = action in ARP_ADMIN_ACTIONS
    res = {"ok": True, "action": action, "cmd": cmd, "elevated": admin, "status": "ran", "output": ""}
    if IS_WIN:
        if admin and not _is_admin():
            _, out = _run_admin_windows(cmd)
        else:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, encoding="mbcs", errors="replace",
                               timeout=30, creationflags=_CNW)
            out = (r.stdout or "") + (r.stderr or "")
        res["output"] = out.strip() or ("Done." if admin else "(no output)")
        return res
    # macOS / Linux
    plain = cmd.replace("sudo ", "", 1)
    if admin and not _is_admin() and IS_MAC:
        _, out = _run_admin_mac(plain)
        res["output"] = out.strip() or "Done."
        return res
    if admin and not _is_admin():
        has_display = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
        if shutil.which("pkexec") and has_display:
            r = subprocess.run(["pkexec", "sh", "-c", plain], capture_output=True, text=True, timeout=180)
            if r.returncode in (126, 127):
                raise RuntimeError("The authorisation prompt was cancelled.")
            res["output"] = ((r.stdout or "") + (r.stderr or "")).strip() or "Done."
            return res
        res.update(status="manual", output=f"Run this in a terminal:\n{cmd}")
        return res
    r = subprocess.run(plain, shell=True, capture_output=True, text=True, timeout=30)
    res["output"] = ((r.stdout or "") + (r.stderr or "")).strip() or ("Done." if admin else "(no output)")
    return res
