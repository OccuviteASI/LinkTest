"""Packet capture for LinkTest.

Pieces (all standard library):
  * PcapngWriter / PcapReader   - write .pcapng, read .pcap/.pcapng incrementally (tail a growing file)
  * Dissector                   - per-packet one-line summaries in plain language + a detail view
  * SimpleFilter                - the "what to capture" builder: host / port / protocol -> BPF or Python match
  * engines                     - Npcap (Windows, ctypes), raw socket (Windows, admin), AF_PACKET (Linux, root)
  * capture_helper_main         - the helper process that actually captures (runs elevated when needed)
  * CaptureSession              - starts/stops the helper, tails the file, keeps summaries and stats,
                                  manages the saved-captures index and the viewer queries
"""
from __future__ import annotations

import collections
import ipaddress
import base64
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import uuid

IS_WIN = os.name == "nt"
IS_LINUX = sys.platform.startswith("linux")
IS_MAC = sys.platform == "darwin"
CREATE_NO_WINDOW = 0x08000000 if IS_WIN else 0

LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
MAX_SUMMARIES = 200_000
NPCAP_DIR = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Npcap")


def is_admin() -> bool:
    if IS_WIN:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


# ----------------------------------------------------------------------------
# pcapng writer
# ----------------------------------------------------------------------------
def _opt(code: int, data: bytes) -> bytes:
    return struct.pack("<HH", code, len(data)) + data + b"\0" * ((-len(data)) % 4)


def _block(btype: int, body: bytes) -> bytes:
    tl = 12 + len(body)
    return struct.pack("<II", btype, tl) + body + struct.pack("<I", tl)


class PcapngWriter:
    def __init__(self, path: str, linktype: int, if_name: str, if_desc: str = "", app: str = "LinkTest"):
        self.path = path
        self.f = open(path, "wb")
        shb = _block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + _opt(4, app.encode()) + _opt(0, b""))
        idb = _block(1, struct.pack("<HHI", linktype, 0, 65535) + _opt(2, if_name.encode("utf-8", "replace"))
                     + (_opt(3, if_desc.encode("utf-8", "replace")) if if_desc else b"") + _opt(9, b"\x06") + _opt(0, b""))
        self.f.write(shb + idb)
        self.f.flush()
        self.size = len(shb) + len(idb)
        self.packets = 0
        self.bytes = 0
        self._buf = bytearray()
        self._last_flush = time.time()

    def write(self, ts_us: int, data: bytes, orig_len: int | None = None) -> None:
        orig = orig_len if orig_len is not None else len(data)
        body = struct.pack("<IIIII", 0, (ts_us >> 32) & 0xFFFFFFFF, ts_us & 0xFFFFFFFF, len(data), orig) + data
        body += b"\0" * ((-len(data)) % 4)
        blk = _block(6, body)
        self._buf += blk
        self.packets += 1
        self.bytes += len(data)
        self.size += len(blk)
        if len(self._buf) >= 65536 or time.time() - self._last_flush > 0.25:
            self.flush()

    def flush(self) -> None:
        if self._buf:
            self.f.write(self._buf)
            self._buf.clear()
        self.f.flush()
        self._last_flush = time.time()

    def close(self) -> None:
        try:
            self.flush()
        finally:
            self.f.close()


# ----------------------------------------------------------------------------
# pcap / pcapng reader (incremental)
# ----------------------------------------------------------------------------
class PcapReader:
    """Reads complete blocks only, so it can follow a file that is still being written.

    read_new() -> list of (ts_seconds, data_offset, caplen, orig_len, linktype).
    """

    def __init__(self, path: str):
        self.path = path
        self.pos = 0
        self.fmt: str | None = None
        self.endian = "<"
        self.interfaces: list[dict] = []
        self.linktype: int | None = None
        self.snaplen = 65535
        self.pcap_ns = False
        self.packets = 0

    def _detect(self, f, size: int) -> bool:
        if size < 24:
            return False
        f.seek(0)
        head = f.read(24)
        magic = head[:4]
        if magic == b"\xd4\xc3\xb2\xa1" or magic == b"\xa1\xb2\xc3\xd4" or magic == b"\x4d\x3c\xb2\xa1" or magic == b"\xa1\xb2\x3c\x4d":
            self.fmt = "pcap"
            self.endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
            self.pcap_ns = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
            _m, _maj, _min, _tz, _sig, snaplen, linktype = struct.unpack(self.endian + "IHHiIII", head)
            self.snaplen = snaplen
            self.linktype = linktype
            self.interfaces = [{"linktype": linktype, "tsresol": 6, "name": ""}]
            self.pos = 24
            return True
        if struct.unpack("<I", magic)[0] == 0x0A0D0D0A:
            bom = struct.unpack("<I", head[8:12])[0]
            self.endian = "<" if bom == 0x1A2B3C4D else ">"
            self.fmt = "pcapng"
            return True
        raise ValueError("This is not a capture file (.pcap or .pcapng).")

    def read_new(self) -> list[tuple]:
        out: list[tuple] = []
        try:
            size = os.path.getsize(self.path)
        except OSError:
            return out
        if size <= self.pos:
            return out
        with open(self.path, "rb") as f:
            if self.fmt is None and not self._detect(f, size):
                return out
            if self.fmt == "pcap":
                while self.pos + 16 <= size:
                    f.seek(self.pos)
                    sec, sub, caplen, olen = struct.unpack(self.endian + "IIII", f.read(16))
                    if self.pos + 16 + caplen > size:
                        break
                    ts = sec + sub / (1e9 if self.pcap_ns else 1e6)
                    out.append((ts, self.pos + 16, caplen, olen, self.linktype))
                    self.pos += 16 + caplen
                    self.packets += 1
                return out
            # pcapng
            while self.pos + 12 <= size:
                f.seek(self.pos)
                hdr = f.read(8)
                btype, tl = struct.unpack(self.endian + "II", hdr)
                if btype == 0x0A0D0D0A:
                    # new section: byte order may change
                    bom_raw = f.read(4)
                    bom = struct.unpack("<I", bom_raw)[0]
                    self.endian = "<" if bom == 0x1A2B3C4D else ">"
                    btype, tl = struct.unpack(self.endian + "II", hdr)
                    self.interfaces = []
                if tl < 12 or tl % 4:
                    raise ValueError("Corrupt capture file.")
                if self.pos + tl > size:
                    break
                f.seek(self.pos + 8)
                body = f.read(tl - 12)
                if btype == 1 and len(body) >= 8:
                    linktype, _res, snaplen = struct.unpack(self.endian + "HHI", body[:8])
                    iface = {"linktype": linktype, "tsresol": 6, "name": "", "snaplen": snaplen}
                    p = 8
                    while p + 4 <= len(body):
                        code, ln = struct.unpack(self.endian + "HH", body[p:p + 4])
                        val = body[p + 4:p + 4 + ln]
                        if code == 0:
                            break
                        if code == 2:
                            iface["name"] = val.decode("utf-8", "replace").strip("\0")
                        elif code == 9 and val:
                            b = val[0]
                            iface["tsresol"] = b & 0x7F
                            iface["tsbase2"] = bool(b & 0x80)
                        p += 4 + ln + ((-ln) % 4)
                    self.interfaces.append(iface)
                    if self.linktype is None:
                        self.linktype = linktype
                elif btype == 6 and len(body) >= 20:
                    ifid, tsh, tsl, caplen, olen = struct.unpack(self.endian + "IIIII", body[:20])
                    iface = self.interfaces[ifid] if ifid < len(self.interfaces) else {"linktype": self.linktype or 1, "tsresol": 6}
                    raw_ts = (tsh << 32) | tsl
                    ts = raw_ts / (2 ** iface["tsresol"] if iface.get("tsbase2") else 10 ** iface["tsresol"])
                    out.append((ts, self.pos + 8 + 20, caplen, olen, iface["linktype"]))
                    self.packets += 1
                elif btype == 2 and len(body) >= 20:  # obsolete Packet Block
                    ifid, _drops, tsh, tsl, caplen, olen = struct.unpack(self.endian + "HHIIII", body[:20])
                    iface = self.interfaces[ifid] if ifid < len(self.interfaces) else {"linktype": self.linktype or 1, "tsresol": 6}
                    ts = ((tsh << 32) | tsl) / 10 ** iface["tsresol"]
                    out.append((ts, self.pos + 8 + 20, caplen, olen, iface["linktype"]))
                    self.packets += 1
                elif btype == 3 and len(body) >= 4:  # Simple Packet Block
                    olen = struct.unpack(self.endian + "I", body[:4])[0]
                    iface = self.interfaces[0] if self.interfaces else {"linktype": self.linktype or 1}
                    caplen = min(olen, iface.get("snaplen", 65535), len(body) - 4)
                    out.append((0.0, self.pos + 8 + 4, caplen, olen, iface["linktype"]))
                    self.packets += 1
                self.pos += tl
        return out

    def read_packet(self, offset: int, caplen: int) -> bytes:
        with open(self.path, "rb") as f:
            f.seek(offset)
            return f.read(caplen)


# ----------------------------------------------------------------------------
# Dissector
# ----------------------------------------------------------------------------
ETH_IPV4, ETH_IPV6, ETH_ARP, ETH_VLAN = 0x0800, 0x86DD, 0x0806, 0x8100
PROTO_BUCKET = {
    "DNS": "dns", "mDNS": "dns", "LLMNR": "dns", "HTTP": "web", "TLS": "web", "QUIC": "web",
    "ICMP": "icmp", "ICMPv6": "icmp", "ARP": "arp", "TCP": "tcp", "UDP": "udp",
    "DHCP": "udp", "NTP": "udp", "SSDP": "udp", "NBNS": "udp", "iperf3": "tcp",
}
DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY"}
DHCP_TYPES = {1: "Discover (looking for a DHCP server)", 2: "Offer (server offers an address)", 3: "Request (device asks for the address)",
              4: "Decline", 5: "Ack (address confirmed)", 6: "Nak (address refused)", 7: "Release", 8: "Inform"}
ICMP_UNREACH = {0: "network unreachable", 1: "host unreachable", 2: "protocol unreachable", 3: "port unreachable",
                4: "fragmentation needed", 13: "blocked by a firewall/filter"}
TLS_HS = {1: "Client Hello", 2: "Server Hello", 11: "Certificate", 16: "Client Key Exchange", 20: "Finished"}


def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b[:6])


def _ip4(b: bytes) -> str:
    return socket.inet_ntoa(b[:4])


def _ip6(b: bytes) -> str:
    try:
        return socket.inet_ntop(socket.AF_INET6, b[:16])
    except (OSError, ValueError):
        return b[:16].hex()


def _dns_name(msg: bytes, off: int, depth: int = 0) -> tuple[str, int]:
    labels = []
    end = None
    jumps = 0
    while off < len(msg):
        ln = msg[off]
        if ln & 0xC0 == 0xC0:
            if off + 1 >= len(msg):
                break
            ptr = struct.unpack_from("!H", msg, off)[0] & 0x3FFF
            if end is None:
                end = off + 2
            off = ptr
            jumps += 1
            if jumps > 32:
                break
            continue
        off += 1
        if ln == 0:
            break
        labels.append(msg[off:off + ln].decode("ascii", "replace"))
        off += ln
    return ".".join(labels), (end if end is not None else off)


class Dissector:
    def __init__(self, linktype: int = LINKTYPE_ETHERNET):
        self.linktype = linktype

    # -- layer parsing -------------------------------------------------------------
    def parse(self, data: bytes, linktype: int | None = None) -> dict:
        lt = self.linktype if linktype is None else linktype
        ctx: dict = {"len": len(data)}
        off = 0
        etype = None
        if lt == LINKTYPE_ETHERNET:
            if len(data) < 14:
                return ctx
            ctx["eth"] = {"dst": _mac(data[0:6]), "src": _mac(data[6:12])}
            etype = struct.unpack_from("!H", data, 12)[0]
            off = 14
            if etype == ETH_VLAN and len(data) >= 18:
                ctx["vlan"] = struct.unpack_from("!H", data, 14)[0] & 0x0FFF
                etype = struct.unpack_from("!H", data, 16)[0]
                off = 18
        elif lt == LINKTYPE_NULL:
            if len(data) < 4:
                return ctx
            af = struct.unpack_from("<I", data, 0)[0]
            etype = ETH_IPV4 if af == 2 else ETH_IPV6 if af in (23, 24, 28, 30) else None
            off = 4
        elif lt == LINKTYPE_RAW:
            v = data[0] >> 4 if data else 0
            etype = ETH_IPV4 if v == 4 else ETH_IPV6 if v == 6 else None
        else:
            return ctx
        ctx["etype"] = etype
        if etype == ETH_ARP:
            self._arp(data, off, ctx)
        elif etype == ETH_IPV4:
            self._ip4(data, off, ctx)
        elif etype == ETH_IPV6:
            self._ip6(data, off, ctx)
        return ctx

    def _arp(self, d: bytes, off: int, ctx: dict):
        if len(d) < off + 28:
            return
        op = struct.unpack_from("!H", d, off + 6)[0]
        ctx["arp"] = {"op": op, "smac": _mac(d[off + 8:off + 14]), "sip": _ip4(d[off + 14:off + 18]),
                      "tmac": _mac(d[off + 18:off + 24]), "tip": _ip4(d[off + 24:off + 28])}

    def _ip4(self, d: bytes, off: int, ctx: dict):
        if len(d) < off + 20:
            return
        vihl = d[off]
        ihl = (vihl & 0x0F) * 4
        total, ident, frag, ttl, proto = struct.unpack_from("!HHHBB", d, off + 2)
        ctx["ip"] = {"ver": 4, "src": _ip4(d[off + 12:off + 16]), "dst": _ip4(d[off + 16:off + 20]), "proto": proto, "ttl": ttl,
                     "len": total, "id": ident, "df": bool(frag & 0x4000), "mf": bool(frag & 0x2000), "offset": frag & 0x1FFF}
        if ctx["ip"]["offset"]:
            ctx["fragment"] = True
            return
        self._l4(d, off + ihl, proto, ctx)

    def _ip6(self, d: bytes, off: int, ctx: dict):
        if len(d) < off + 40:
            return
        plen, nh, hlim = struct.unpack_from("!HBB", d, off + 4)
        ctx["ip"] = {"ver": 6, "src": _ip6(d[off + 8:off + 24]), "dst": _ip6(d[off + 24:off + 40]), "proto": nh, "ttl": hlim, "len": plen}
        p = off + 40
        # skip common extension headers
        while nh in (0, 43, 60) and len(d) >= p + 8:
            nh_next = d[p]
            hl = (d[p + 1] + 1) * 8
            p += hl
            nh = nh_next
        ctx["ip"]["proto"] = nh
        self._l4(d, p, nh, ctx)

    def _l4(self, d: bytes, off: int, proto: int, ctx: dict):
        if proto == 6 and len(d) >= off + 20:
            sport, dport, seq, ack, doff_flags, win = struct.unpack_from("!HHIIHH", d, off)
            doff = (doff_flags >> 12) * 4
            flags = doff_flags & 0x1FF
            payload = d[off + doff:] if len(d) >= off + doff else b""
            ctx["tcp"] = {"sport": sport, "dport": dport, "seq": seq, "ack": ack, "flags": flags, "win": win, "payload": payload}
            self._app(ctx, sport, dport, payload, "tcp")
        elif proto == 17 and len(d) >= off + 8:
            sport, dport, ln = struct.unpack_from("!HHH", d, off)
            payload = d[off + 8:]
            ctx["udp"] = {"sport": sport, "dport": dport, "len": ln, "payload": payload}
            self._app(ctx, sport, dport, payload, "udp")
        elif proto == 1 and len(d) >= off + 4:
            t, c = d[off], d[off + 1]
            ctx["icmp"] = {"type": t, "code": c, "seq": struct.unpack_from("!H", d, off + 6)[0] if t in (0, 8) and len(d) >= off + 8 else None}
        elif proto == 58 and len(d) >= off + 4:
            ctx["icmp6"] = {"type": d[off], "code": d[off + 1]}

    def _app(self, ctx: dict, sport: int, dport: int, payload: bytes, l4: str):
        app = None
        try:
            if 53 in (sport, dport) or 5353 in (sport, dport) or 5355 in (sport, dport):
                app = self._dns(payload, "DNS" if 53 in (sport, dport) else ("mDNS" if 5353 in (sport, dport) else "LLMNR"), l4)
            elif l4 == "udp" and (67 in (sport, dport) or 68 in (sport, dport)):
                app = self._dhcp(payload)
            elif l4 == "udp" and 123 in (sport, dport) and len(payload) >= 48:
                mode = payload[0] & 7
                app = {"name": "NTP", "info": "Time sync: " + ("request to a time server" if mode == 3 else "reply from a time server" if mode == 4 else f"mode {mode}")}
            elif l4 == "udp" and 1900 in (sport, dport):
                line = payload.split(b"\r\n", 1)[0].decode("ascii", "replace")
                app = {"name": "SSDP", "info": f"Device discovery: {line[:60]}"}
            elif l4 == "udp" and 137 in (sport, dport):
                app = {"name": "NBNS", "info": "Windows computer-name lookup (NetBIOS)"}
            elif l4 == "udp" and 443 in (sport, dport):
                app = {"name": "QUIC", "info": "Encrypted web traffic (QUIC)"}
            elif l4 == "tcp" and payload:
                if 443 in (sport, dport) or (payload[0] in (20, 21, 22, 23) and len(payload) >= 5 and payload[1] == 3):
                    app = self._tls(payload)
                elif re.match(rb"^(GET|POST|PUT|HEAD|DELETE|OPTIONS|PATCH|CONNECT) \S+ HTTP/\d", payload[:120]):
                    line = payload.split(b"\r\n", 1)[0].decode("ascii", "replace")
                    m = re.search(rb"\r\nHost:\s*([^\r\n]+)", payload[:2000], re.I)
                    host = m.group(1).decode("ascii", "replace") if m else ""
                    parts = line.split(" ")
                    app = {"name": "HTTP", "info": f"Web request: {parts[0]} {parts[1][:80] if len(parts) > 1 else ''}" + (f" (site {host})" if host else ""), "rows": [["Request", line]]}
                elif payload.startswith(b"HTTP/"):
                    line = payload.split(b"\r\n", 1)[0].decode("ascii", "replace")
                    app = {"name": "HTTP", "info": f"Web reply: {line.split(' ', 1)[1] if ' ' in line else line}", "rows": [["Status", line]]}
                elif 5201 in (sport, dport):
                    app = {"name": "iperf3", "info": f"iperf3 speed-test data ({len(payload)} bytes)"}
            elif l4 == "udp" and 5201 in (sport, dport):
                app = {"name": "iperf3", "info": f"iperf3 speed-test data ({len(payload)} bytes)"}
        except Exception:
            app = None
        if app:
            ctx["app"] = app

    def _dns(self, p: bytes, label: str, l4: str) -> dict | None:
        if len(p) < 12:
            return None
        qid, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", p, 0)
        qr = bool(flags & 0x8000)
        rcode = flags & 0xF
        off = 12
        qname, qtype = "", 0
        if qd:
            qname, off = _dns_name(p, off)
            if off + 4 <= len(p):
                qtype = struct.unpack_from("!H", p, off)[0]
                off += 4
        tname = DNS_TYPES.get(qtype, str(qtype))
        answers = []
        for _ in range(min(an, 10)):
            if off >= len(p):
                break
            _n, off = _dns_name(p, off)
            if off + 10 > len(p):
                break
            rtype, _cls, _ttl, rdlen = struct.unpack_from("!HHIH", p, off)
            off += 10
            rd = p[off:off + rdlen]
            if rtype == 1 and rdlen == 4:
                answers.append(_ip4(rd))
            elif rtype == 28 and rdlen == 16:
                answers.append(_ip6(rd))
            elif rtype in (5, 12, 2):
                answers.append(_dns_name(p, off)[0])
            off += rdlen
        what = {"A": "the address", "AAAA": "the IPv6 address", "MX": "the mail servers", "PTR": "the name", "TXT": "the text records",
                "SRV": "the service location", "CNAME": "the alias", "NS": "the name servers", "HTTPS": "the HTTPS details"}.get(tname, f"the {tname} record")
        if not qr:
            info = f"Question: what is {what} of {qname}?"
        elif rcode == 3:
            info = f"Answer: {qname} does not exist (NXDOMAIN)"
        elif rcode:
            info = f"Answer: error {rcode} for {qname}"
        elif answers:
            info = f"Answer: {qname} is {answers[0]}" + (f" (+{an - 1} more)" if an > 1 else "")
        else:
            info = f"Answer for {qname}: {an} record{'s' if an != 1 else ''}"
        return {"name": label, "info": info, "rows": [["Name", qname], ["Type", tname], ["Answers", ", ".join(answers) or str(an)], ["ID", f"0x{qid:04x}"]]}

    def _dhcp(self, p: bytes) -> dict | None:
        if len(p) < 240 or p[236:240] != b"\x63\x82\x53\x63":
            return {"name": "DHCP", "info": "Address assignment (DHCP)"}
        op = p[0]
        yiaddr = _ip4(p[16:20])
        chaddr = _mac(p[28:34])
        off = 240
        mtype, hostname, req = None, "", ""
        while off + 2 <= len(p):
            code = p[off]
            if code == 255:
                break
            if code == 0:
                off += 1
                continue
            ln = p[off + 1]
            val = p[off + 2:off + 2 + ln]
            if code == 53 and val:
                mtype = val[0]
            elif code == 12:
                hostname = val.decode("utf-8", "replace")
            elif code == 50 and len(val) == 4:
                req = _ip4(val)
            off += 2 + ln
        kind = DHCP_TYPES.get(mtype or 0, "message")
        extra = f" for {hostname}" if hostname else ""
        addr = yiaddr if yiaddr != "0.0.0.0" else req
        return {"name": "DHCP", "info": f"Address assignment: {kind}{extra}" + (f", address {addr}" if addr and addr != '0.0.0.0' else ""),
                "rows": [["Message", kind], ["Device", chaddr], ["Host name", hostname], ["Address", addr]]}

    def _tls(self, p: bytes) -> dict | None:
        if len(p) < 5:
            return None
        rtype = p[0]
        ver = f"{p[1]}.{p[2]}"
        if rtype == 22 and len(p) >= 9:
            hs = p[5]
            name = TLS_HS.get(hs, f"handshake {hs}")
            sni = ""
            if hs == 1:
                sni = self._sni(p)
            info = f"Secure connection starting: {name}" + (f" to {sni}" if sni else "")
            return {"name": "TLS", "info": info, "rows": [["Handshake", name], ["Server name", sni], ["Record version", ver]]}
        if rtype == 23:
            return {"name": "TLS", "info": f"Encrypted data ({len(p) - 5} bytes)"}
        if rtype == 21:
            return {"name": "TLS", "info": "Secure connection alert"}
        if rtype == 20:
            return {"name": "TLS", "info": "Secure connection: cipher change"}
        return None

    @staticmethod
    def _sni(p: bytes) -> str:
        try:
            off = 5 + 4  # record header + handshake header
            off += 2 + 32  # version + random
            sid = p[off]
            off += 1 + sid
            cs = struct.unpack_from("!H", p, off)[0]
            off += 2 + cs
            cm = p[off]
            off += 1 + cm
            ext_len = struct.unpack_from("!H", p, off)[0]
            off += 2
            end = off + ext_len
            while off + 4 <= end and off + 4 <= len(p):
                et, el = struct.unpack_from("!HH", p, off)
                off += 4
                if et == 0 and off + 5 <= len(p):
                    nl = struct.unpack_from("!H", p, off + 3)[0]
                    return p[off + 5:off + 5 + nl].decode("ascii", "replace")
                off += el
        except (struct.error, IndexError):
            pass
        return ""

    # -- summaries -------------------------------------------------------------------
    def summary(self, n: int, ts: float, data: bytes, linktype: int | None = None) -> dict:
        c = self.parse(data, linktype)
        s = {"n": n, "ts": round(ts, 6), "len": len(data), "src": "", "dst": "", "proto": "Other", "info": "", "sport": None, "dport": None, "flags": ""}
        ip = c.get("ip")
        if "arp" in c:
            a = c["arp"]
            s.update(src=a["sip"], dst=a["tip"], proto="ARP")
            s["info"] = f"Who has {a['tip']}? Tell {a['sip']}" if a["op"] == 1 else f"{a['sip']} is at {a['smac']}" if a["op"] == 2 else f"ARP operation {a['op']}"
        elif ip:
            s.update(src=ip["src"], dst=ip["dst"], proto="IPv4" if ip["ver"] == 4 else "IPv6")
            if c.get("fragment"):
                s["info"] = "Part of a larger (fragmented) packet"
            app = c.get("app")
            if "tcp" in c:
                t = c["tcp"]
                s.update(sport=t["sport"], dport=t["dport"], proto="TCP", flags=self._flags(t["flags"]))
                if app:
                    s["proto"] = app["name"]
                    s["info"] = app["info"]
                else:
                    s["info"] = self._tcp_info(t, ip)
            elif "udp" in c:
                u = c["udp"]
                s.update(sport=u["sport"], dport=u["dport"], proto="UDP")
                s["info"] = app["info"] if app else f"Data {u['sport']} → {u['dport']} ({len(u['payload'])} bytes)"
                if app:
                    s["proto"] = app["name"]
            elif "icmp" in c:
                i = c["icmp"]
                s["proto"] = "ICMP"
                s["info"] = self._icmp_info(i)
            elif "icmp6" in c:
                i = c["icmp6"]
                s["proto"] = "ICMPv6"
                s["info"] = {128: "Ping request", 129: "Ping reply", 133: "Router solicitation", 134: "Router advertisement",
                             135: "Neighbour solicitation (who has this address?)", 136: "Neighbour advertisement", 1: "Destination unreachable",
                             3: "Time exceeded"}.get(i["type"], f"ICMPv6 type {i['type']}")
            elif not s["info"]:
                s["info"] = f"IP protocol {ip['proto']}"
        elif "eth" in c:
            e = c["eth"]
            s.update(src=e["src"], dst=e["dst"], proto="Other", info=f"Ethernet type 0x{c.get('etype') or 0:04x}")
        else:
            s["info"] = "Unrecognised packet"
        if c.get("vlan") is not None:
            s["vlan"] = c["vlan"]
        s["bucket"] = PROTO_BUCKET.get(s["proto"], "other")
        if s["sport"] is not None:
            a, b = (s["src"], s["sport"]), (s["dst"], s["dport"])
            lo, hi = sorted([a, b])
            s["conv"] = f"{lo[0]}:{lo[1]} ↔ {hi[0]}:{hi[1]}"
        else:
            lo, hi = sorted([s["src"], s["dst"]])
            s["conv"] = f"{lo} ↔ {hi}" if lo else ""
        return s

    @staticmethod
    def _flags(f: int) -> str:
        names = []
        for bit, nm in ((0x02, "SYN"), (0x10, "ACK"), (0x01, "FIN"), (0x04, "RST"), (0x08, "PSH"), (0x20, "URG")):
            if f & bit:
                names.append(nm)
        return ",".join(names)

    @staticmethod
    def _tcp_info(t: dict, ip: dict) -> str:
        f = t["flags"]
        plen = len(t["payload"])
        where = f"{ip['src']}:{t['sport']} → {ip['dst']}:{t['dport']}"
        if f & 0x04:
            return f"Connection reset (RST) {where}"
        if f & 0x02 and f & 0x10:
            return f"Connection accepted (SYN, ACK) {where}"
        if f & 0x02:
            return f"Start of a connection (SYN) {where}"
        if f & 0x01:
            return f"Connection closing (FIN) {where}"
        if plen:
            return f"Data: {plen} bytes {where}"
        return f"Acknowledgement {where}"

    @staticmethod
    def _icmp_info(i: dict) -> str:
        t, c = i["type"], i["code"]
        if t == 8:
            return "Ping request" + (f" (seq {i['seq']})" if i.get("seq") is not None else "")
        if t == 0:
            return "Ping reply" + (f" (seq {i['seq']})" if i.get("seq") is not None else "")
        if t == 3:
            return f"Destination unreachable: {ICMP_UNREACH.get(c, f'code {c}')}"
        if t == 11:
            return "Time exceeded (a router dropped the packet: traceroute or routing loop)"
        if t == 5:
            return "Redirect (a router suggests a better path)"
        return f"ICMP type {t} code {c}"

    # -- detail -----------------------------------------------------------------------
    def detail(self, data: bytes, linktype: int | None = None) -> dict:
        c = self.parse(data, linktype)
        secs = []
        secs.append({"title": "Frame", "rows": [["Captured length", f"{len(data)} bytes", "How much of the packet was recorded"]]})
        if "eth" in c:
            rows = [["From (hardware address)", c["eth"]["src"], "The MAC address of the sender on this network segment"],
                    ["To (hardware address)", c["eth"]["dst"], "ff:ff:ff:ff:ff:ff means everyone (broadcast)"],
                    ["Type", f"0x{c.get('etype') or 0:04x}", {ETH_IPV4: "IPv4", ETH_IPV6: "IPv6", ETH_ARP: "ARP"}.get(c.get("etype"), "")]]
            if c.get("vlan") is not None:
                rows.append(["VLAN", str(c["vlan"]), "Virtual network tag"])
            secs.append({"title": "Ethernet", "rows": rows})
        if "arp" in c:
            a = c["arp"]
            secs.append({"title": "ARP (who has which address)", "rows": [["Operation", "request" if a["op"] == 1 else "reply" if a["op"] == 2 else str(a["op"]), ""],
                                                                         ["Sender", f"{a['sip']} ({a['smac']})", ""], ["Target", f"{a['tip']} ({a['tmac']})", ""]]})
        ip = c.get("ip")
        if ip:
            rows = [["From", ip["src"], ""], ["To", ip["dst"], ""], ["Time to live" if ip["ver"] == 4 else "Hop limit", str(ip["ttl"]), "Hops left before routers discard the packet"],
                    ["Protocol", {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6", 2: "IGMP", 47: "GRE", 50: "ESP"}.get(ip["proto"], str(ip["proto"])), ""],
                    ["Length", f"{ip['len']} bytes", ""]]
            if ip["ver"] == 4:
                rows.append(["Fragmentation", ("don't fragment" if ip["df"] else "allowed") + (", more fragments follow" if ip["mf"] else ""), ""])
            secs.append({"title": f"IPv{ip['ver']}", "rows": rows})
        if "tcp" in c:
            t = c["tcp"]
            secs.append({"title": "TCP (reliable connection)", "rows": [["From port", str(t["sport"]), _port_note(t["sport"])], ["To port", str(t["dport"]), _port_note(t["dport"])],
                                                                        ["Flags", self._flags(t["flags"]) or "none", "SYN starts, FIN ends, RST aborts, ACK confirms, PSH pushes data"],
                                                                        ["Sequence", str(t["seq"]), ""], ["Acknowledgement", str(t["ack"]), ""], ["Window", str(t["win"]), "How much the receiver can take right now"],
                                                                        ["Data", f"{len(t['payload'])} bytes", ""]]})
        if "udp" in c:
            u = c["udp"]
            secs.append({"title": "UDP (quick messages)", "rows": [["From port", str(u["sport"]), _port_note(u["sport"])], ["To port", str(u["dport"]), _port_note(u["dport"])],
                                                                   ["Data", f"{len(u['payload'])} bytes", ""]]})
        if "icmp" in c:
            i = c["icmp"]
            secs.append({"title": "ICMP (control messages)", "rows": [["Type / code", f"{i['type']} / {i['code']}", self._icmp_info(i)]]})
        if "icmp6" in c:
            i = c["icmp6"]
            secs.append({"title": "ICMPv6", "rows": [["Type / code", f"{i['type']} / {i['code']}", ""]]})
        app = c.get("app")
        if app:
            rows = [[k, v, ""] for k, v in app.get("rows", []) if v]
            rows.insert(0, ["Summary", app["info"], ""])
            secs.append({"title": app["name"], "rows": rows})
        return {"sections": secs, "hex": self.hexdump(data)}

    @staticmethod
    def hexdump(data: bytes, limit: int = 4096) -> str:
        lines = []
        for i in range(0, min(len(data), limit), 16):
            chunk = data[i:i + 16]
            hx = " ".join(f"{b:02x}" for b in chunk)
            asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{i:06x}  {hx:<47}  {asc}")
        if len(data) > limit:
            lines.append(f"... {len(data) - limit} more bytes")
        return "\n".join(lines)


def _port_note(port: int) -> str:
    from nettools import PORT_NAMES  # local import to avoid a cycle at module load
    return PORT_NAMES.get(port, "")


# ----------------------------------------------------------------------------
# Simple filter (what to capture)
# ----------------------------------------------------------------------------
class SimpleFilter:
    PROTOS = {"any": "everything", "tcp": "TCP connections", "udp": "UDP messages", "icmp": "pings (ICMP)", "arp": "ARP",
              "dns": "DNS lookups", "web": "web traffic (HTTP/HTTPS)"}

    def __init__(self, host: str = "", port=None, proto: str = "any"):
        self.host = (host or "").strip()
        self.ip = None
        if self.host:
            try:
                ipaddress.ip_address(self.host)
                self.ip = self.host
            except ValueError:
                try:
                    self.ip = socket.getaddrinfo(self.host, None, socket.AF_INET)[0][4][0]
                except socket.gaierror:
                    raise ValueError(f"'{self.host}' could not be found. Use an IP address or a name that resolves.")
        self.port = None
        if port not in (None, "", 0, "0"):
            try:
                self.port = int(port)
            except ValueError:
                raise ValueError("Port must be a number.")
            if not 1 <= self.port <= 65535:
                raise ValueError("Port must be between 1 and 65535.")
        self.proto = (proto or "any").lower()
        if self.proto not in self.PROTOS:
            raise ValueError("Unknown protocol choice.")

    def to_dict(self) -> dict:
        return {"host": self.host, "ip": self.ip, "port": self.port, "proto": self.proto}

    def describe(self) -> str:
        parts = [self.PROTOS[self.proto].capitalize()]
        if self.ip:
            parts.append(f"to or from {self.host}")
        if self.port:
            parts.append(f"on port {self.port}")
        return " ".join(parts)

    def bpf(self) -> str:
        terms = []
        if self.ip:
            terms.append(f"host {self.ip}")
        if self.port:
            terms.append(f"port {self.port}")
        p = {"tcp": "tcp", "udp": "udp", "icmp": "(icmp or icmp6)", "arp": "arp", "dns": "(port 53 or port 5353)",
             "web": "(tcp port 80 or tcp port 443 or udp port 443 or tcp port 8080 or tcp port 8443)"}.get(self.proto)
        if p:
            terms.append(p)
        return " and ".join(terms)

    def matches(self, s: dict) -> bool:
        if self.ip and self.ip not in (s.get("src"), s.get("dst")):
            return False
        if self.port and self.port not in (s.get("sport"), s.get("dport")):
            return False
        pr = self.proto
        if pr == "any":
            return True
        b = s.get("bucket")
        if pr == "tcp":
            return s.get("sport") is not None and (b in ("tcp", "web") or s.get("proto") in ("TCP", "HTTP", "TLS", "iperf3"))
        if pr == "udp":
            return s.get("sport") is not None and s.get("proto") not in ("TCP", "HTTP", "TLS") and s.get("flags") == ""
        if pr == "icmp":
            return b == "icmp"
        if pr == "arp":
            return b == "arp"
        if pr == "dns":
            return b == "dns"
        if pr == "web":
            return b == "web"
        return True


# ----------------------------------------------------------------------------
# Engines
# ----------------------------------------------------------------------------
class NpcapEngine:
    name = "npcap"
    _dll = None

    @classmethod
    def load(cls):
        if cls._dll is not None:
            return cls._dll
        import ctypes
        from ctypes import POINTER, Structure, c_char_p, c_int, c_long, c_ubyte, c_uint, c_void_p
        if IS_WIN:
            path = os.path.join(NPCAP_DIR, "wpcap.dll")
            if os.path.isdir(NPCAP_DIR):
                os.add_dll_directory(NPCAP_DIR)
            dll = ctypes.CDLL(path if os.path.isfile(path) else "wpcap.dll")
        elif IS_MAC:
            # Ships with macOS (dyld shared cache); ctypes.util finds it even when no file is on disk.
            import ctypes.util
            dll = ctypes.CDLL(ctypes.util.find_library("pcap") or "/usr/lib/libpcap.A.dylib")
        else:
            import ctypes.util
            dll = ctypes.CDLL(ctypes.util.find_library("pcap") or "libpcap.so.1")

        class timeval(Structure):
            _fields_ = [("tv_sec", c_long), ("tv_usec", c_long)]

        class pcap_pkthdr(Structure):
            _fields_ = [("ts", timeval), ("caplen", c_uint), ("len", c_uint)]

        class bpf_program(Structure):
            _fields_ = [("bf_len", c_uint), ("bf_insns", c_void_p)]

        class pcap_addr(Structure):
            pass
        pcap_addr._fields_ = [("next", POINTER(pcap_addr)), ("addr", c_void_p), ("netmask", c_void_p), ("broadaddr", c_void_p), ("dstaddr", c_void_p)]

        class pcap_if(Structure):
            pass
        pcap_if._fields_ = [("next", POINTER(pcap_if)), ("name", c_char_p), ("description", c_char_p), ("addresses", POINTER(pcap_addr)), ("flags", c_uint)]

        dll.pcap_lib_version.restype = c_char_p
        dll.pcap_findalldevs.argtypes = [POINTER(POINTER(pcap_if)), c_char_p]
        dll.pcap_freealldevs.argtypes = [POINTER(pcap_if)]
        dll.pcap_open_live.argtypes = [c_char_p, c_int, c_int, c_int, c_char_p]
        dll.pcap_open_live.restype = c_void_p
        dll.pcap_datalink.argtypes = [c_void_p]
        dll.pcap_geterr.argtypes = [c_void_p]
        dll.pcap_geterr.restype = c_char_p
        dll.pcap_compile.argtypes = [c_void_p, POINTER(bpf_program), c_char_p, c_int, c_uint]
        dll.pcap_setfilter.argtypes = [c_void_p, POINTER(bpf_program)]
        dll.pcap_freecode.argtypes = [POINTER(bpf_program)]
        dll.pcap_next_ex.argtypes = [c_void_p, POINTER(POINTER(pcap_pkthdr)), POINTER(POINTER(c_ubyte))]
        dll.pcap_close.argtypes = [c_void_p]
        dll.pcap_breakloop.argtypes = [c_void_p]
        try:
            dll.pcap_setmintocopy.argtypes = [c_void_p, c_int]
        except AttributeError:
            pass

        class pcap_stat(Structure):
            _fields_ = [("ps_recv", c_uint), ("ps_drop", c_uint), ("ps_ifdrop", c_uint), ("ps_capt", c_uint), ("ps_sent", c_uint), ("ps_netdrop", c_uint)]
        dll.pcap_stats.argtypes = [c_void_p, POINTER(pcap_stat)]
        cls._types = (pcap_pkthdr, bpf_program, pcap_addr, pcap_if, pcap_stat)
        cls._dll = dll
        return dll

    @classmethod
    def available(cls) -> bool:
        try:
            cls.load()
            return True
        except Exception:
            return False

    @classmethod
    def version(cls) -> str:
        try:
            return cls.load().pcap_lib_version().decode(errors="replace")
        except Exception:
            return ""

    @staticmethod
    def admin_only() -> bool:
        if not IS_WIN:
            return False
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\npcap\Parameters") as k:
                return bool(winreg.QueryValueEx(k, "AdminOnly")[0])
        except OSError:
            return False

    @classmethod
    def list_devices(cls) -> list[dict]:
        import ctypes
        dll = cls.load()
        pcap_pkthdr, bpf_program, pcap_addr, pcap_if, _ = cls._types
        devs = ctypes.POINTER(pcap_if)()
        err = ctypes.create_string_buffer(256)
        if dll.pcap_findalldevs(ctypes.byref(devs), err) != 0:
            raise OSError(err.value.decode(errors="replace") or "pcap_findalldevs failed")
        out = []
        p = devs
        while p:
            d = p.contents
            name = (d.name or b"").decode(errors="replace")
            desc = (d.description or b"").decode(errors="replace")
            ipv4, ipv6 = [], []
            a = d.addresses
            while a:
                ad = a.contents
                if ad.addr:
                    raw = ctypes.string_at(ad.addr, 28)
                    if IS_MAC:
                        fam = raw[1]                               # BSD sockaddr: u8 len, u8 family
                        fam6 = 30
                    else:
                        fam = struct.unpack_from("<H", raw)[0]      # Windows/Linux sockaddr: u16 family
                        fam6 = 23 if IS_WIN else 10
                    if fam == 2:
                        ipv4.append(socket.inet_ntoa(raw[4:8]))
                    elif fam == fam6:
                        ipv6.append(_ip6(raw[8:24]))
                a = ad.next
            loop = bool(d.flags & 0x1) or "Loopback" in name or name == "lo0"
            if not (desc.startswith("WAN Miniport") and not ipv4):
                out.append({"name": name, "description": desc, "ipv4": ipv4, "ipv6": ipv6, "loopback": loop})
            p = d.next
        dll.pcap_freealldevs(devs)
        return out

    def __init__(self):
        import ctypes
        self.ct = ctypes
        self.dll = self.load()
        self.h = None
        self.linktype = LINKTYPE_ETHERNET
        self._prog = None

    def open(self, device: str, bpf: str = "", promisc: bool = True, snaplen: int = 65535):
        ct = self.ct
        pcap_pkthdr, bpf_program, *_ = self._types
        err = ct.create_string_buffer(256)
        h = self.dll.pcap_open_live(device.encode(), snaplen, 1 if promisc else 0, 200, err)
        if not h:
            msg = err.value.decode(errors="replace")
            if "denied" in msg.lower():
                raise PermissionError(msg)
            raise OSError(msg or "Could not open the network adapter.")
        self.h = h
        self.linktype = self.dll.pcap_datalink(h)
        try:
            self.dll.pcap_setmintocopy(h, 1)
        except Exception:
            pass
        if bpf:
            prog = bpf_program()
            if self.dll.pcap_compile(h, ct.byref(prog), bpf.encode(), 1, 0xFFFFFFFF) != 0:
                raise ValueError("Filter problem: " + (self.dll.pcap_geterr(h) or b"").decode(errors="replace"))
            if self.dll.pcap_setfilter(h, ct.byref(prog)) != 0:
                raise ValueError("Filter problem: " + (self.dll.pcap_geterr(h) or b"").decode(errors="replace"))
            self.dll.pcap_freecode(ct.byref(prog))
        self._hdrp = ct.POINTER(pcap_pkthdr)()
        self._datap = ct.POINTER(ct.c_ubyte)()

    def next(self):
        rc = self.dll.pcap_next_ex(self.h, self.ct.byref(self._hdrp), self.ct.byref(self._datap))
        if rc == 1:
            hd = self._hdrp.contents
            data = self.ct.string_at(self._datap, hd.caplen)
            return hd.ts.tv_sec * 1_000_000 + hd.ts.tv_usec, data, hd.len
        if rc == 0:
            return None
        if rc == -1:
            raise OSError((self.dll.pcap_geterr(self.h) or b"").decode(errors="replace") or "capture error")
        raise EOFError()

    def stats(self) -> dict:
        try:
            st = self._types[4]()
            if self.dll.pcap_stats(self.h, self.ct.byref(st)) == 0:
                return {"recv": st.ps_recv, "drop": st.ps_drop + st.ps_ifdrop}
        except Exception:
            pass
        return {}

    def close(self):
        if self.h:
            try:
                self.dll.pcap_close(self.h)
            except Exception:
                pass
            self.h = None


class LibpcapEngine(NpcapEngine):
    """The same libpcap calls on macOS/Linux (system libpcap). Needs /dev/bpf access on macOS."""
    name = "libpcap"
    _dll = None


class RawSockEngine:
    """Windows raw IP capture (SIO_RCVALL). Needs administrator. IPv4 only, one adapter."""
    name = "rawsock"

    def __init__(self):
        self.s = None
        self.linktype = LINKTYPE_RAW

    def open(self, local_ip: str, bpf: str = "", promisc: bool = True, snaplen: int = 65535):
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)  # PermissionError for non-admins
        s.bind((local_ip, 0))
        try:
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        except OSError:
            s.ioctl(socket.SIO_RCVALL, 3)  # RCVALL_IPLEVEL
        s.settimeout(0.5)
        self.s = s

    def next(self):
        try:
            data, _ = self.s.recvfrom(65535)
        except socket.timeout:
            return None
        return int(time.time() * 1_000_000), data, len(data)

    def stats(self) -> dict:
        return {}

    def close(self):
        if self.s:
            try:
                self.s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except OSError:
                pass
            self.s.close()
            self.s = None


class AfPacketEngine:
    """Linux AF_PACKET capture. Needs root (or CAP_NET_RAW)."""
    name = "afpacket"
    SO_TIMESTAMP = 29

    def __init__(self):
        self.s = None
        self.linktype = LINKTYPE_ETHERNET

    def open(self, ifname: str, bpf: str = "", promisc: bool = True, snaplen: int = 65535):
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))  # PermissionError when not root
        s.bind((ifname, 0))
        try:
            s.setsockopt(socket.SOL_SOCKET, self.SO_TIMESTAMP, 1)
        except OSError:
            pass
        s.settimeout(0.5)
        self.s = s

    def next(self):
        try:
            data, anc, _flags, _addr = self.s.recvmsg(65535, 1024)
        except socket.timeout:
            return None
        ts_us = None
        for lvl, typ, cd in anc:
            if lvl == socket.SOL_SOCKET and typ == self.SO_TIMESTAMP and len(cd) >= 16:
                sec, usec = struct.unpack("ll", cd[:16])
                ts_us = sec * 1_000_000 + usec
        if ts_us is None:
            ts_us = int(time.time() * 1_000_000)
        return ts_us, data, len(data)

    def stats(self) -> dict:
        return {}

    def close(self):
        if self.s:
            self.s.close()
            self.s = None


ENGINES = {"npcap": NpcapEngine, "libpcap": LibpcapEngine, "rawsock": RawSockEngine, "afpacket": AfPacketEngine}
BPF_ENGINES = ("npcap", "libpcap")


# ----------------------------------------------------------------------------
# Helper process
# ----------------------------------------------------------------------------
def _write_json_atomic(path: str, data: dict) -> None:
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.replace(tmp, path)
    except OSError:
        pass


def capture_helper_main(argv: list[str]) -> int:
    """Entry point for `LinkTest --capture-helper ...` (may run elevated). Never prints."""
    import argparse
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--capture-helper", action="store_true")
    ap.add_argument("--engine", required=True, choices=list(ENGINES))
    ap.add_argument("--iface", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--duration", type=float, default=60)
    ap.add_argument("--max-mb", type=float, default=100)
    ap.add_argument("--filter", default="{}")
    ap.add_argument("--filter-b64", default="")     # urlsafe base64 of the JSON: survives every launcher's quoting
    ap.add_argument("--stop", required=True)
    ap.add_argument("--meta", required=True)
    ap.add_argument("--label", default="")           # legacy; the app no longer sends it
    ns, _rest = ap.parse_known_args(argv)
    meta = {"state": "starting", "packets": 0, "bytes": 0, "dropped": 0, "started": time.time(), "ended": None,
            "error": None, "engine": ns.engine, "linktype": None, "sizeBytes": 0, "pid": os.getpid()}
    _write_json_atomic(ns.meta, meta)
    try:
        raw = ns.filter or "{}"
        if ns.filter_b64:
            import base64
            raw = base64.urlsafe_b64decode(ns.filter_b64.encode()).decode("utf-8")
        fdict = json.loads(raw)
        filt = SimpleFilter(fdict.get("host", ""), fdict.get("port"), fdict.get("proto", "any"))
    except (ValueError, json.JSONDecodeError) as e:
        meta.update(state="error", error="badargs", detail=f"{e}; argv={argv!r}", ended=time.time())
        _write_json_atomic(ns.meta, meta)
        return 4
    eng = ENGINES[ns.engine]()
    try:
        eng.open(ns.iface, filt.bpf() if ns.engine in BPF_ENGINES else "")
    except PermissionError as e:
        meta.update(state="error", error="permission", detail=str(e), ended=time.time())
        _write_json_atomic(ns.meta, meta)
        return 2
    except ValueError as e:
        meta.update(state="error", error=str(e), ended=time.time())
        _write_json_atomic(ns.meta, meta)
        return 4
    except OSError as e:
        meta.update(state="error", error=f"Could not open the network adapter: {e}", ended=time.time())
        _write_json_atomic(ns.meta, meta)
        return 3
    meta["linktype"] = eng.linktype
    dis = Dissector(eng.linktype)
    need_py_filter = ns.engine not in BPF_ENGINES and (filt.ip or filt.port or filt.proto != "any")
    try:
        w = PcapngWriter(ns.out, eng.linktype, ns.iface, ns.label or ns.iface)
    except OSError as e:
        meta.update(state="error", error=f"Could not write the capture file: {e}", ended=time.time())
        _write_json_atomic(ns.meta, meta)
        eng.close()
        return 3
    meta["state"] = "running"
    _write_json_atomic(ns.meta, meta)
    t0 = time.time()
    last_meta = last_stop = t0
    max_bytes = ns.max_mb * 1024 * 1024
    reason = "stopped"
    try:
        while True:
            now = time.time()
            if ns.duration and now - t0 >= ns.duration:
                reason = "time"
                break
            if w.size >= max_bytes:
                reason = "size"
                break
            if now - last_stop >= 0.5:
                last_stop = now
                if os.path.exists(ns.stop):
                    reason = "stopped"
                    break
            try:
                pkt = eng.next()
            except EOFError:
                break
            except OSError as e:
                meta.update(error=f"Capture error: {e}")
                break
            if pkt is not None:
                ts_us, data, olen = pkt
                if need_py_filter:
                    try:
                        if not filt.matches(dis.summary(0, ts_us / 1e6, data)):
                            pkt = None
                    except Exception:
                        pass
                if pkt is not None:
                    w.write(ts_us, data, olen)
            if now - last_meta >= 1.0:
                last_meta = now
                w.flush()
                st = eng.stats()
                meta.update(packets=w.packets, bytes=w.bytes, sizeBytes=w.size, dropped=st.get("drop", 0))
                _write_json_atomic(ns.meta, meta)
    finally:
        try:
            w.close()
        except Exception:
            pass
        eng.close()
        st = {}
        meta.update(state="done" if not meta.get("error") else "error", packets=w.packets, bytes=w.bytes, sizeBytes=w.size,
                    ended=time.time(), reason=reason)
        _write_json_atomic(ns.meta, meta)
    return 0


# ----------------------------------------------------------------------------
# Wireshark
# ----------------------------------------------------------------------------
def find_wireshark() -> str | None:
    if IS_WIN:
        for base in (os.environ.get("ProgramFiles", r"C:\Program Files"), os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")):
            p = os.path.join(base, "Wireshark", "Wireshark.exe")
            if os.path.isfile(p):
                return p
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wireshark") as k:
                d = winreg.QueryValueEx(k, "InstallDir")[0]
                p = os.path.join(d, "Wireshark.exe")
                if os.path.isfile(p):
                    return p
        except OSError:
            pass
        return shutil.which("Wireshark")
    if IS_MAC:
        for p in ("/Applications/Wireshark.app/Contents/MacOS/Wireshark", os.path.expanduser("~/Applications/Wireshark.app/Contents/MacOS/Wireshark")):
            if os.path.isfile(p):
                return p
    return shutil.which("wireshark")


# ----------------------------------------------------------------------------
# Stats accumulator
# ----------------------------------------------------------------------------
class _Stats:
    def __init__(self):
        self.packets = 0
        self.bytes = 0
        self.first = None
        self.last = None
        self.protos: collections.Counter = collections.Counter()
        self.proto_bytes: collections.Counter = collections.Counter()
        self.talkers: dict = {}
        self.convs: dict = {}

    def add(self, s: dict):
        self.packets += 1
        self.bytes += s["len"]
        ts = s["ts"]
        if self.first is None or ts < self.first:
            self.first = ts
        if self.last is None or ts > self.last:
            self.last = ts
        self.protos[s["proto"]] += 1
        self.proto_bytes[s["proto"]] += s["len"]
        for ip in (s["src"], s["dst"]):
            if ip:
                t = self.talkers.setdefault(ip, [0, 0])
                t[0] += 1
                t[1] += s["len"]
        if s.get("conv"):
            c = self.convs.setdefault(s["conv"], [0, 0, s["proto"]])
            c[0] += 1
            c[1] += s["len"]

    def to_dict(self) -> dict:
        dur = (self.last - self.first) if (self.first is not None and self.last is not None) else 0
        top_t = sorted(self.talkers.items(), key=lambda kv: kv[1][1], reverse=True)[:12]
        top_c = sorted(self.convs.items(), key=lambda kv: kv[1][1], reverse=True)[:12]
        return {"packets": self.packets, "bytes": self.bytes, "duration": round(dur, 3), "first": self.first, "last": self.last,
                "protos": [{"proto": p, "packets": n, "bytes": self.proto_bytes[p]} for p, n in self.protos.most_common()],
                "talkers": [{"ip": ip, "packets": v[0], "bytes": v[1]} for ip, v in top_t],
                "conversations": [{"conv": c, "packets": v[0], "bytes": v[1], "proto": v[2]} for c, v in top_c],
                "hosts": len(self.talkers), "convCount": len(self.convs)}


class LoadedCapture:
    def __init__(self, cid: str, path: str):
        self.id = cid
        self.path = path
        self.reader = PcapReader(path)
        self.dis = Dissector()
        self.summaries: list[dict] = []
        self.offsets: list[tuple] = []  # (offset, caplen, linktype)
        self.stats = _Stats()
        self.truncated = False
        self.lock = threading.Lock()

    def ingest(self) -> list[dict]:
        new = []
        for ts, off, caplen, olen, lt in self.reader.read_new():
            n = self.reader.packets  # 1-based running count at read time; recompute below
            data = self.reader.read_packet(off, caplen) if caplen else b""
            idx = len(self.offsets) + 1
            s = self.dis.summary(idx, ts, data, lt)
            with self.lock:
                self.stats.add(s)
                if len(self.summaries) < MAX_SUMMARIES:
                    self.summaries.append(s)
                    self.offsets.append((off, caplen, lt))
                else:
                    self.truncated = True
            new.append(s)
        return new

    def packet(self, n: int) -> dict:
        if not 1 <= n <= len(self.offsets):
            raise ValueError("That packet is not available.")
        off, caplen, lt = self.offsets[n - 1]
        data = self.reader.read_packet(off, caplen)
        d = self.dis.detail(data, lt)
        d["summary"] = self.summaries[n - 1]
        return d

    def query(self, proto: str = "", host: str = "", port=None, q: str = "", offset: int = 0, limit: int = 500) -> dict:
        buckets = {b for b in (proto or "").lower().split(",") if b}
        host = (host or "").strip().lower()
        q = (q or "").strip().lower()
        p = None
        if port not in (None, "", 0):
            try:
                p = int(port)
            except ValueError:
                p = None
        with self.lock:
            rows = self.summaries
            if buckets or host or p or q:
                def ok(s):
                    if buckets and s.get("bucket") not in buckets:
                        return False
                    if host and host not in s["src"].lower() and host not in s["dst"].lower():
                        return False
                    if p and p not in (s.get("sport"), s.get("dport")):
                        return False
                    if q and q not in s["info"].lower() and q not in s["src"].lower() and q not in s["dst"].lower() and q not in s["proto"].lower():
                        return False
                    return True
                rows = [s for s in rows if ok(s)]
            total = len(rows)
            page = rows[offset:offset + limit]
        return {"total": total, "offset": offset, "limit": limit, "rows": page, "truncated": self.truncated}

    def csv(self, **filters) -> str:
        import io
        res = self.query(limit=10_000_000, **filters)
        buf = io.StringIO()
        buf.write("no,time,source,destination,protocol,length,info\n")
        t0 = self.stats.first or 0
        for s in res["rows"]:
            info = s["info"].replace('"', "'")
            buf.write(f"{s['n']},{s['ts'] - t0:.6f},{s['src']},{s['dst']},{s['proto']},{s['len']},\"{info}\"\n")
        return buf.getvalue()


# ----------------------------------------------------------------------------
# Capture session (used by the app)
# ----------------------------------------------------------------------------
class CaptureSession:
    def __init__(self, state_dir: str, version: str, settings: dict, save_settings, netinfo, main_script: str | None):
        from nettools import EventLog
        self.dir = os.path.join(state_dir, "captures")
        os.makedirs(self.dir, exist_ok=True)
        self.index_path = os.path.join(self.dir, "captures.json")
        self.version = version
        self.settings = settings
        self.save_settings = save_settings
        self.netinfo = netinfo
        self.main_script = main_script
        self.log = EventLog(keep=4000)
        self.lock = threading.Lock()
        self.index: list[dict] = self._load_index()
        self.loaded: dict[str, LoadedCapture] = {}
        self.current: dict | None = None
        self._proc = None
        self._thread = None
        self._stop_evt = threading.Event()

    # -- environment -----------------------------------------------------------------
    def engine_info(self) -> dict:
        npcap = NpcapEngine.available() if IS_WIN else False
        return {"platform": sys.platform, "isAdmin": is_admin(), "npcap": {"installed": npcap, "version": NpcapEngine.version() if npcap else "",
                                                                          "adminOnly": NpcapEngine.admin_only() if npcap else False},
                "wireshark": find_wireshark(), "pkexec": bool(shutil.which("pkexec")) if IS_LINUX else False,
                "libpcap": LibpcapEngine.available() if IS_MAC else False,
                "bpfAccess": (os.access("/dev/bpf0", os.R_OK | os.W_OK) if IS_MAC else False)}

    def interfaces(self) -> list[dict]:
        info = self.engine_info()
        out = []
        nis = self.netinfo.interfaces()
        by_ip = {i["ip"]: i for i in nis}
        if IS_WIN:
            use_npcap = info["npcap"]["installed"] and (not info["npcap"]["adminOnly"] or info["isAdmin"])
            if use_npcap:
                try:
                    for d in NpcapEngine.list_devices():
                        ip = d["ipv4"][0] if d["ipv4"] else ""
                        ni = by_ip.get(ip)
                        if d["loopback"]:
                            label = "Loopback (this computer talking to itself)"
                        else:
                            label = (ni["name"] if ni else d["description"]) + (f" – {ip}" if ip else "")
                        if not ip and not d["loopback"]:
                            continue
                        if ip.startswith("169.254.") and not d["loopback"]:
                            continue  # adapter without a real address (no network)
                        out.append({"id": d["name"], "label": label, "ip": ip, "engine": "npcap", "loopback": d["loopback"],
                                    "needsElevation": False, "primary": bool(ni and ni.get("primary")), "detail": d["description"]})
                except OSError:
                    use_npcap = False
            if not use_npcap or not out:
                for ni in nis:
                    if ni["ip"].startswith("169.254."):
                        continue
                    out.append({"id": ni["ip"], "label": f"{ni['name']} – {ni['ip']}", "ip": ni["ip"], "engine": "rawsock", "loopback": False,
                                "needsElevation": not info["isAdmin"], "primary": bool(ni.get("primary")), "detail": "IPv4 only (built-in capture)"})
        elif IS_MAC:
            needs = not (info["isAdmin"] or info.get("bpfAccess"))
            by_dev = {i.get("dev") or i["name"]: i for i in nis}
            try:
                devs = LibpcapEngine.list_devices() if info.get("libpcap") else []
            except OSError:
                devs = []
            for d in devs:
                name = d["name"]
                if name.startswith(("utun", "awdl", "llw", "gif", "stf", "anpi", "ap", "pktap", "ipsec", "bridge")):
                    continue
                ip = d["ipv4"][0] if d["ipv4"] else ""
                if not ip and not d["loopback"]:
                    continue
                ni = by_dev.get(name)
                label = "Loopback (this computer talking to itself)" if d["loopback"] else f"{ni['name'] if ni else name} – {ip}"
                out.append({"id": name, "label": label, "ip": ip or "127.0.0.1", "engine": "libpcap", "loopback": d["loopback"],
                            "needsElevation": needs, "primary": bool(ni and ni.get("primary")), "detail": d["description"] or ""})
            if not devs:
                for ni in nis:
                    out.append({"id": ni.get("dev") or ni["name"], "label": f"{ni['name']} – {ni['ip']}", "ip": ni["ip"], "engine": "libpcap",
                                "loopback": False, "needsElevation": needs, "primary": bool(ni.get("primary")), "detail": ""})
        else:
            for ni in nis:
                out.append({"id": ni["name"], "label": f"{ni['name']} – {ni['ip']}", "ip": ni["ip"], "engine": "afpacket", "loopback": False,
                            "needsElevation": not info["isAdmin"], "primary": bool(ni.get("primary")), "detail": "Ethernet frames"})
            out.append({"id": "lo", "label": "Loopback (this computer talking to itself)", "ip": "127.0.0.1", "engine": "afpacket", "loopback": True,
                        "needsElevation": not info["isAdmin"], "primary": False, "detail": ""})
        out.sort(key=lambda i: (not i["primary"], i["loopback"], i["label"]))
        return out

    # -- index -----------------------------------------------------------------------
    def _load_index(self) -> list[dict]:
        try:
            with open(self.index_path, encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, list) else []
        except (OSError, ValueError):
            return []

    def _save_index(self):
        _write_json_atomic(self.index_path, self.index)

    def list(self) -> list[dict]:
        with self.lock:
            out = []
            for e in self.index:
                p = e.get("path") or os.path.join(self.dir, e["file"])
                e = dict(e)
                e["exists"] = os.path.isfile(p)
                e["sizeBytes"] = os.path.getsize(p) if e["exists"] else 0
                out.append(e)
        out.sort(key=lambda e: e.get("started") or 0, reverse=True)
        return out

    def entry(self, cid: str) -> dict:
        for e in self.index:
            if e["id"] == cid:
                return e
        raise ValueError("That capture no longer exists.")

    def path_for(self, cid: str) -> str:
        e = self.entry(cid)
        return e.get("path") or os.path.join(self.dir, e["file"])

    def rename(self, cid: str, name: str) -> dict:
        e = self.entry(cid)
        e["name"] = name.strip()[:80] or e["name"]
        self._save_index()
        return e

    def delete(self, cid: str) -> None:
        if self.current and self.current["id"] == cid and self.running():
            raise RuntimeError("Stop the capture before deleting it.")
        e = self.entry(cid)
        with self.lock:
            self.index = [x for x in self.index if x["id"] != cid]
            self._save_index()
        self.loaded.pop(cid, None)
        if not e.get("external"):
            for ext in (".pcapng", ".meta.json", ".stop"):
                try:
                    os.remove(os.path.join(self.dir, cid + ext))
                except OSError:
                    pass

    def open_external(self, path: str) -> dict:
        path = os.path.abspath(path)
        if not os.path.isfile(path):
            raise ValueError("That file does not exist.")
        for e in self.index:
            if e.get("path") == path:
                return e
        cid = uuid.uuid4().hex[:10]
        e = {"id": cid, "name": os.path.basename(path), "path": path, "external": True, "started": os.path.getmtime(path), "ended": None,
             "iface": "", "ifaceLabel": "", "engine": "file", "filter": {}, "duration": 0, "packets": None, "bytes": None}
        with self.lock:
            self.index.append(e)
            self._save_index()
        return e

    # -- running a capture ------------------------------------------------------------------
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def helper_command(self) -> list[str]:
        if getattr(sys, "frozen", False):
            return [sys.executable]
        return [sys.executable, self.main_script or os.path.abspath(sys.argv[0])]

    def start(self, opts: dict) -> dict:
        if self.running():
            raise RuntimeError("A capture is already running. Stop it first.")
        ifaces = self.interfaces()
        iface_id = str(opts.get("iface") or "")
        iface = next((i for i in ifaces if i["id"] == iface_id), None) or (next((i for i in ifaces if i["primary"]), None) if not iface_id else None)
        if not iface:
            raise ValueError("Choose a network connection to capture on.")
        f = opts.get("filter") or {}
        filt = SimpleFilter(f.get("host", ""), f.get("port"), f.get("proto", "any"))
        duration = float(opts.get("duration") or 0)
        duration = max(0.0, min(duration, 24 * 3600))
        max_mb = float(opts.get("maxMB") or 100)
        max_mb = max(1.0, min(max_mb, 10000))
        name = str(opts.get("name") or "").strip()[:80] or time.strftime("Capture %Y-%m-%d %H-%M")
        cid = uuid.uuid4().hex[:10]
        out = os.path.join(self.dir, cid + ".pcapng")
        meta = os.path.join(self.dir, cid + ".meta.json")
        stop = os.path.join(self.dir, cid + ".stop")
        for p in (out, meta, stop):
            try:
                os.remove(p)
            except OSError:
                pass
        args = ["--capture-helper", "--engine", iface["engine"], "--iface", iface["id"], "--out", out, "--duration", str(duration),
                "--max-mb", str(max_mb), "--filter-b64", base64.urlsafe_b64encode(json.dumps(filt.to_dict()).encode()).decode(),
                "--stop", stop, "--meta", meta]
        elevated = bool(iface["needsElevation"])
        cmd = self.helper_command() + args
        if elevated:
            if IS_WIN:
                self._launch_runas(cmd)
            elif IS_MAC:
                self._launch_osascript(cmd)
            else:
                if shutil.which("pkexec") and (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
                    self._proc = subprocess.Popen(["pkexec"] + cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                else:
                    raise RuntimeError("Capturing needs administrator rights. Run this in a terminal, then try again:\n"
                                       "sudo " + " ".join(cmd))
        else:
            self._proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=CREATE_NO_WINDOW)
        entry = {"id": cid, "name": name, "file": cid + ".pcapng", "iface": iface["id"], "ifaceLabel": iface["label"], "engine": iface["engine"],
                 "filter": filt.to_dict(), "filterText": filt.describe(), "duration": duration, "maxMB": max_mb, "started": time.time(), "ended": None,
                 "packets": 0, "bytes": 0, "elevated": elevated, "linktype": None, "cmd": subprocess.list2cmdline(cmd) if IS_WIN else " ".join(cmd)}
        with self.lock:
            self.index.append(entry)
            self._save_index()
        self.current = {"id": cid, "entry": entry, "meta": meta, "stop": stop, "out": out, "helperState": "starting", "error": None}
        self.loaded = {cid: LoadedCapture(cid, out)}
        self.log.clear()
        self._stop_evt.clear()
        self.log.push({"type": "start", "id": cid, "name": name, "engine": iface["engine"], "elevated": elevated, "duration": duration})
        self.settings["captureOpts"] = {"iface": iface["id"], "filter": filt.to_dict(), "duration": duration, "maxMB": max_mb}
        try:
            self.save_settings()
        except Exception:
            pass
        self._thread = threading.Thread(target=self._tail, daemon=True, name="pcap-tail")
        self._thread.start()
        msg = ("Windows is asking for administrator permission to capture." if elevated and IS_WIN else
               "macOS is asking for your password to capture." if elevated and IS_MAC else
               "Linux is asking for your password to capture." if elevated else "Capturing…")
        return {"id": cid, "engine": iface["engine"], "elevated": elevated, "message": msg}

    def _launch_osascript(self, cmd: list[str]):
        """macOS: run the helper as root through the standard password dialog, detached."""
        import shlex
        inner = " ".join(shlex.quote(a) for a in cmd) + " >/dev/null 2>&1 &"
        esc = inner.replace("\\", "\\\\").replace('"', '\\"')
        script = f'do shell script "{esc}" with administrator privileges'
        # osascript blocks while the dialog is up and exits once the helper is launched;
        # the helper's meta file (not this process) tells us how the capture is doing.
        subprocess.Popen(["osascript", "-e", script], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _launch_runas(self, cmd: list[str]):
        """Windows: start the helper elevated (UAC prompt).

        The arguments go to Start-Process as ONE pre-quoted command line (list2cmdline, the
        quoting the helper's C runtime undoes) through environment variables. Passing them as
        a PowerShell array looked right but PowerShell re-joined the array with spaces and no
        quotes, which shredded the JSON filter and any adapter name containing spaces.
        """
        env = dict(os.environ, LT_HELPER_EXE=cmd[0], LT_HELPER_ARGS=subprocess.list2cmdline(cmd[1:]))
        script = "Start-Process -Verb RunAs -WindowStyle Hidden -FilePath $env:LT_HELPER_EXE -ArgumentList $env:LT_HELPER_ARGS"
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True,
                           timeout=120, creationflags=CREATE_NO_WINDOW, env=env)
        if r.returncode != 0:
            err = (r.stderr or "").strip()
            if "cancel" in err.lower():
                raise RuntimeError("The administrator prompt was cancelled.")
            raise RuntimeError(err.splitlines()[0] if err else "Windows did not start the capture helper.")

    def stop(self) -> bool:
        cur = self.current
        if not cur or not self.running():
            return False
        try:
            with open(cur["stop"], "w") as f:
                f.write("stop")
        except OSError:
            pass
        if self._proc and not cur["entry"].get("elevated"):
            try:
                self._proc.wait(timeout=4)
            except subprocess.TimeoutExpired:
                self._proc.terminate()
        self._stop_evt.set()
        return True

    def _read_meta(self) -> dict | None:
        cur = self.current
        try:
            with open(cur["meta"], encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return None

    def _tail(self):
        cur = self.current
        lc = self.loaded[cur["id"]]
        entry = cur["entry"]
        t0 = time.time()
        last_progress = 0.0
        meta = None
        finished = False
        while True:
            time.sleep(0.25)
            m = self._read_meta()
            if m:
                meta = m
                cur["helperState"] = m.get("state")
                if m.get("linktype") is not None and entry.get("linktype") is None:
                    entry["linktype"] = m["linktype"]
                    lc.dis.linktype = m["linktype"]
            try:
                new = lc.ingest()
            except ValueError as e:
                cur["error"] = str(e)
                new = []
            if new:
                self.log.push({"type": "packets", "rows": new[-60:], "total": lc.stats.packets})
            now = time.time()
            if now - last_progress >= 1.0:
                last_progress = now
                self.log.push({"type": "progress", **self._counters(meta, lc)})
            if meta and meta.get("state") in ("done", "error"):
                # drain what is left
                time.sleep(0.3)
                new = lc.ingest()
                if new:
                    self.log.push({"type": "packets", "rows": new[-60:], "total": lc.stats.packets})
                finished = True
                break
            if not meta and now - t0 > 12 and not os.path.exists(cur["out"]):
                cur["error"] = "The capture did not start. If a permission prompt appeared, it may have been cancelled."
                break
            if self._proc is not None and self._proc.poll() is not None and not meta and now - t0 > 3:
                cur["error"] = "The capture helper stopped before it could start."
                break
            if self._stop_evt.is_set() and now - t0 > 6 and (not meta or meta.get("state") == "starting"):
                cur["error"] = "The capture was cancelled."
                break
        err = None
        if meta and meta.get("state") == "error":
            err = meta.get("error")
            if err == "badargs":
                err = ("The capture helper did not understand its options (" + str(meta.get("detail") or "")[:160] +
                       "). Please report this with the command line shown in the capture's details.")
            if err == "permission":
                err = ("Capturing needs administrator rights on this network connection. " +
                       ("Windows refused the request." if IS_WIN else
                        "Enter your password when macOS asks, or install Wireshark's ChmodBPF to capture without it." if IS_MAC else
                        "Run LinkTest with sudo or install a polkit agent."))
        err = err or cur.get("error")
        entry.update(ended=time.time(), packets=lc.stats.packets, bytes=lc.stats.bytes,
                     reason=(meta or {}).get("reason"), error=err)
        if not finished and not err:
            entry["error"] = "The capture ended unexpectedly."
        with self.lock:
            self._save_index()
        self.log.push({"type": "done", "id": cur["id"], "packets": lc.stats.packets, "bytes": lc.stats.bytes, "error": entry.get("error"),
                       "reason": entry.get("reason")})

    def _counters(self, meta: dict | None, lc: LoadedCapture) -> dict:
        cur = self.current
        entry = cur["entry"]
        elapsed = time.time() - entry["started"]
        dur = entry.get("duration") or 0
        size = (meta or {}).get("sizeBytes") or (os.path.getsize(cur["out"]) if os.path.exists(cur["out"]) else 0)
        st = lc.stats
        return {"packets": st.packets, "bytes": st.bytes, "elapsed": round(elapsed, 1), "remaining": round(max(0.0, dur - elapsed), 1) if dur else None,
                "sizeBytes": size, "maxBytes": int(entry.get("maxMB", 100) * 1024 * 1024), "dropped": (meta or {}).get("dropped", 0),
                "protos": [{"proto": p, "packets": n} for p, n in st.protos.most_common(8)], "helperState": cur.get("helperState")}

    def state(self) -> dict:
        cur = self.current
        if not cur:
            return {"running": False}
        lc = self.loaded.get(cur["id"])
        return {"running": self.running(), "id": cur["id"], "name": cur["entry"]["name"], "engine": cur["entry"]["engine"],
                "elevated": cur["entry"].get("elevated"), "started": cur["entry"]["started"], "duration": cur["entry"]["duration"],
                "counters": self._counters(self._read_meta(), lc) if lc else None, "error": cur["entry"].get("error") or cur.get("error"),
                "seq": self.log.seq, "recent": (lc.summaries[-200:] if lc else [])}

    # -- viewer ----------------------------------------------------------------------------
    def load(self, cid: str) -> LoadedCapture:
        lc = self.loaded.get(cid)
        if lc is None:
            path = self.path_for(cid)
            if not os.path.isfile(path):
                raise ValueError("The capture file is missing.")
            lc = LoadedCapture(cid, path)
            e = self.entry(cid)
            if e.get("linktype") is not None:
                lc.dis.linktype = e["linktype"]
            lc.ingest()
            if lc.reader.linktype is not None:
                lc.dis.linktype = lc.reader.linktype
            # keep at most 3 loaded captures (the running one included)
            if len(self.loaded) >= 3:
                for k in list(self.loaded):
                    if not (self.current and k == self.current["id"]):
                        self.loaded.pop(k)
                        break
            self.loaded[cid] = lc
        elif not (self.current and cid == self.current["id"] and self.running()):
            lc.ingest()  # pick up anything appended since
        return lc

    def stats(self, cid: str) -> dict:
        lc = self.load(cid)
        e = dict(self.entry(cid))
        e["stats"] = lc.stats.to_dict()
        e["truncated"] = lc.truncated
        e["linktype"] = lc.reader.linktype
        e["wireshark"] = bool(find_wireshark())
        return e

    def packets(self, cid: str, **kw) -> dict:
        return self.load(cid).query(**kw)

    def packet(self, cid: str, n: int) -> dict:
        return self.load(cid).packet(n)

    def csv(self, cid: str, **kw) -> str:
        return self.load(cid).csv(**kw)

    def open_in_wireshark(self, cid: str) -> bool:
        exe = find_wireshark()
        if not exe:
            raise RuntimeError("Wireshark is not installed on this computer.")
        path = self.path_for(cid)
        subprocess.Popen([exe, path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
