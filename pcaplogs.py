"""Zeek-style logs from capture files (LinkTest's own implementation; Zeek is not needed).

Reads a .pcap / .pcapng and produces the logs Zeek would write for it, with the same
file names, field names, value formats and connection semantics:

  conn.log      one line per connection: state (SF, S0, REJ...), history (ShADadFf), bytes,
                packets, missed bytes, service, local/remote, MAC, VLAN, Community ID
  dns.log       queries matched to answers, rcode, TTLs, round-trip time
  http.log      requests and replies, host, URI, user agent, status, body sizes, file types
  ssl.log       TLS version, cipher, curve, server name, ALPN, resumed/established,
                certificate chain, plus JA3 / JA3S / JA4 fingerprints
  x509.log      certificates seen in cleartext handshakes (TLS 1.2 and older)
  files.log     files carried over HTTP / FTP and certificates, with MD5 / SHA1 / SHA256
  ssh.log       banners, negotiated algorithms, host key fingerprint, login success guess
  dhcp.log      DHCP transactions (who got which address from which server)
  ftp.log       FTP commands with replies and data channels
  ntp.log       time-sync messages
  quic.log      QUIC connections (server name read by decrypting the Initial packet)
  software.log  software versions seen in banners and User-Agent / Server headers
  known_hosts / known_services
  notice.log    findings (scans, weak TLS, expired certificates, cleartext passwords,
                failing connections, retransmissions...)
  weird.log     protocol oddities

The TCP state machine, connection-state names and history letters follow Zeek's own source
(src/packet_analysis/protocol/tcp/TCPSessionAdapter.cc and base/protocols/conn/main.zeek),
so conn.log lines read the same as Zeek's. UIDs are generated deterministically from the
file, so re-analysing the same capture gives the same UIDs.

Entry points: Analyzer(...).run(path) -> Result; Result.tsv(log) / .json_lines(log) /
.write_zip(path, fmt) / .summary(); cli_main(argv) for `linktest.py --zeek-logs file.pcap`.
"""
from __future__ import annotations

import base64
import collections
import hashlib
import heapq
import io
import ipaddress
import json
import os
import re
import struct
import time
import zipfile
import zlib

import pcapproto as P
import zeek_tables as ZT
from pcaptool import PcapReader, link_decap

# ----------------------------------------------------------------------------
# Log schemas (field, Zeek type) - same order as Zeek writes them
# ----------------------------------------------------------------------------
_ID = [("id.orig_h", "addr"), ("id.orig_p", "port"), ("id.resp_h", "addr"), ("id.resp_p", "port")]
SCHEMAS: dict[str, list[tuple[str, str]]] = {
    "conn": [("ts", "time"), ("uid", "string"), *_ID, ("proto", "enum"), ("service", "string"), ("duration", "interval"),
             ("orig_bytes", "count"), ("resp_bytes", "count"), ("conn_state", "string"), ("local_orig", "bool"),
             ("local_resp", "bool"), ("missed_bytes", "count"), ("history", "string"), ("orig_pkts", "count"),
             ("orig_ip_bytes", "count"), ("resp_pkts", "count"), ("resp_ip_bytes", "count"), ("tunnel_parents", "set[string]"),
             ("ip_proto", "count"), ("orig_l2_addr", "string"), ("resp_l2_addr", "string"), ("vlan", "int"),
             ("inner_vlan", "int"), ("community_id", "string")],
    "dns": [("ts", "time"), ("uid", "string"), *_ID, ("proto", "enum"), ("trans_id", "count"), ("rtt", "interval"),
            ("query", "string"), ("qclass", "count"), ("qclass_name", "string"), ("qtype", "count"), ("qtype_name", "string"),
            ("rcode", "count"), ("rcode_name", "string"), ("AA", "bool"), ("TC", "bool"), ("RD", "bool"), ("RA", "bool"),
            ("Z", "count"), ("answers", "vector[string]"), ("TTLs", "vector[interval]"), ("rejected", "bool"),
            ("opcode", "count"), ("opcode_name", "string")],
    "http": [("ts", "time"), ("uid", "string"), *_ID, ("trans_depth", "count"), ("method", "string"), ("host", "string"),
             ("uri", "string"), ("referrer", "string"), ("version", "string"), ("user_agent", "string"), ("origin", "string"),
             ("request_body_len", "count"), ("response_body_len", "count"), ("status_code", "count"), ("status_msg", "string"),
             ("info_code", "count"), ("info_msg", "string"), ("tags", "set[enum]"), ("username", "string"), ("password", "string"),
             ("proxied", "set[string]"), ("orig_fuids", "vector[string]"), ("orig_filenames", "vector[string]"),
             ("orig_mime_types", "vector[string]"), ("resp_fuids", "vector[string]"), ("resp_filenames", "vector[string]"),
             ("resp_mime_types", "vector[string]")],
    "ssl": [("ts", "time"), ("uid", "string"), *_ID, ("version", "string"), ("cipher", "string"), ("curve", "string"),
            ("server_name", "string"), ("resumed", "bool"), ("last_alert", "string"), ("next_protocol", "string"),
            ("established", "bool"), ("ssl_history", "string"), ("cert_chain_fps", "vector[string]"),
            ("client_cert_chain_fps", "vector[string]"), ("sni_matches_cert", "bool"), ("ja3", "string"), ("ja3s", "string"),
            ("ja4", "string")],
    "x509": [("ts", "time"), ("fingerprint", "string"), ("certificate.version", "count"), ("certificate.serial", "string"),
             ("certificate.subject", "string"), ("certificate.issuer", "string"), ("certificate.not_valid_before", "time"),
             ("certificate.not_valid_after", "time"), ("certificate.key_alg", "string"), ("certificate.sig_alg", "string"),
             ("certificate.key_type", "string"), ("certificate.key_length", "count"), ("certificate.exponent", "string"),
             ("certificate.curve", "string"), ("san.dns", "vector[string]"), ("san.uri", "vector[string]"),
             ("san.email", "vector[string]"), ("san.ip", "vector[addr]"), ("basic_constraints.ca", "bool"),
             ("basic_constraints.path_len", "count"), ("host_cert", "bool"), ("client_cert", "bool")],
    "files": [("ts", "time"), ("fuid", "string"), ("uid", "string"), *_ID, ("source", "string"), ("depth", "count"),
              ("analyzers", "set[string]"), ("mime_type", "string"), ("filename", "string"), ("duration", "interval"),
              ("local_orig", "bool"), ("is_orig", "bool"), ("seen_bytes", "count"), ("total_bytes", "count"),
              ("missing_bytes", "count"), ("overflow_bytes", "count"), ("timedout", "bool"), ("parent_fuid", "string"),
              ("md5", "string"), ("sha1", "string"), ("sha256", "string")],
    "ssh": [("ts", "time"), ("uid", "string"), *_ID, ("version", "count"), ("auth_success", "bool"), ("auth_attempts", "count"),
            ("direction", "enum"), ("client", "string"), ("server", "string"), ("cipher_alg", "string"), ("mac_alg", "string"),
            ("compression_alg", "string"), ("kex_alg", "string"), ("host_key_alg", "string"), ("host_key_fingerprint", "string")],
    "dhcp": [("ts", "time"), ("uids", "set[string]"), ("client_addr", "addr"), ("server_addr", "addr"), ("mac", "string"),
             ("host_name", "string"), ("client_fqdn", "string"), ("domain", "string"), ("requested_addr", "addr"),
             ("assigned_addr", "addr"), ("lease_time", "interval"), ("client_message", "string"), ("server_message", "string"),
             ("msg_types", "vector[string]"), ("duration", "interval")],
    "ftp": [("ts", "time"), ("uid", "string"), *_ID, ("user", "string"), ("password", "string"), ("command", "string"),
            ("arg", "string"), ("mime_type", "string"), ("file_size", "count"), ("reply_code", "count"), ("reply_msg", "string"),
            ("data_channel.passive", "bool"), ("data_channel.orig_h", "addr"), ("data_channel.resp_h", "addr"),
            ("data_channel.resp_p", "port"), ("fuid", "string")],
    "ntp": [("ts", "time"), ("uid", "string"), *_ID, ("version", "count"), ("mode", "count"), ("stratum", "count"),
            ("poll", "interval"), ("precision", "interval"), ("root_delay", "interval"), ("root_disp", "interval"),
            ("ref_id", "string"), ("ref_time", "time"), ("org_time", "time"), ("rec_time", "time"), ("xmt_time", "time"),
            ("num_exts", "count")],
    "quic": [("ts", "time"), ("uid", "string"), *_ID, ("version", "string"), ("client_initial_dcid", "string"),
             ("client_scid", "string"), ("server_scid", "string"), ("server_name", "string"), ("client_protocol", "string"),
             ("history", "string")],
    "software": [("ts", "time"), ("host", "addr"), ("host_p", "port"), ("software_type", "enum"), ("name", "string"),
                 ("version.major", "count"), ("version.minor", "count"), ("version.minor2", "count"), ("version.minor3", "count"),
                 ("version.addl", "string"), ("unparsed_version", "string")],
    "known_hosts": [("ts", "time"), ("host", "addr")],
    "known_services": [("ts", "time"), ("host", "addr"), ("port_num", "port"), ("port_proto", "enum"), ("service", "set[string]")],
    "notice": [("ts", "time"), ("uid", "string"), *_ID, ("fuid", "string"), ("file_mime_type", "string"), ("file_desc", "string"),
               ("proto", "enum"), ("note", "enum"), ("msg", "string"), ("sub", "string"), ("src", "addr"), ("dst", "addr"),
               ("p", "port"), ("n", "count"), ("peer_descr", "string"), ("actions", "set[enum]"), ("email_dest", "set[string]"),
               ("suppress_for", "interval")],
    "weird": [("ts", "time"), ("uid", "string"), *_ID, ("name", "string"), ("addl", "string"), ("notice", "bool"),
              ("peer", "string"), ("source", "string")],
}
LOG_ORDER = ["notice", "conn", "dns", "http", "ssl", "x509", "files", "quic", "ssh", "dhcp", "ftp", "ntp", "software",
             "known_hosts", "known_services", "weird"]

# ports Zeek treats as "likely server" (used to guess who started a connection it saw mid-way)
LIKELY_TCP = {21, 22, 23, 25, 53, 79, 80, 81, 88, 110, 135, 139, 143, 389, 443, 445, 502, 563, 585, 587, 614, 631, 636,
              989, 990, 992, 993, 995, 1080, 1433, 1434, 1883, 2811, 3128, 3268, 3306, 3389, 5222, 5223, 5269, 5432, 5201,
              6379, 6666, 6667, 6668, 6669, 8000, 8080, 8888, 20000}
LIKELY_UDP = {53, 67, 69, 88, 123, 137, 161, 162, 389, 500, 514, 1812, 3389, 4011, 5060, 5201, 5353, 5355, 20000}
_LOCAL_NETS = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
    "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/24", "239.0.0.0/8",
    "240.0.0.0/4", "255.255.255.255/32", "2002::/24", "2002:a00::/24", "2002:6440::/26", "2002:7f00::/24", "2002:a9fe::/32",
    "2002:ac10::/28", "2002:c000::/40", "2002:c000:200::/40", "2002:c0a8::/32", "2002:c612::/31", "2002:c633:6400::/40",
    "2002:cb00:7100::/40", "2002:e000::/40", "2002:ef00::/24", "2002:f000::/20", "2002:ffff:ffff::/48", "::/128", "::1/128",
    "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:2::/48", "2001:db8::/32", "fc00::/7", "fe80::/10", "fec0::/10")]
_MULTICAST = [ipaddress.ip_network("224.0.0.0/4"), ipaddress.ip_network("ff00::/8")]

TCP_INACTIVE, TCP_SYN_SENT, TCP_SYN_ACK_SENT, TCP_PARTIAL, TCP_ESTABLISHED, TCP_CLOSED, TCP_RESET = range(7)
F_FIN, F_SYN, F_RST, F_PSH, F_ACK, F_URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20
H_SYN, H_FIN, H_RST, H_FINRST, H_DATA, H_ACK, H_MULTI = 0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40
TOO_LARGE = 1048576
M32 = 0xFFFFFFFF
TCP_TIMEOUT, UDP_TIMEOUT, ICMP_TIMEOUT, CLOSE_DELAY, ATTEMPT_DELAY = 300.0, 60.0, 60.0, 5.0, 5.0
B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

ICMP4_PAIRS = {8: 0, 13: 14, 15: 16, 10: 9, 17: 18}
ICMP6_PAIRS = {128: 129, 133: 134, 135: 136, 130: 131, 139: 140, 144: 145}

CONN_STATE_TEXT = {
    "S0": "Connection attempt seen, no reply.", "S1": "Connection established, not closed.",
    "SF": "Normal: established and closed.", "REJ": "Connection attempt rejected (refused).",
    "S2": "Established; the starting side closed it, no reply to that.", "S3": "Established; the answering side closed it, no reply to that.",
    "RSTO": "Established, then the starting side aborted it (reset).", "RSTR": "The answering side aborted it (reset).",
    "RSTOS0": "The starting side sent a SYN then reset; never answered.", "RSTRH": "The answering side sent SYN-ACK then reset; no SYN seen.",
    "SH": "The starting side sent a SYN then a FIN; never answered (half-open).", "SHR": "Only the answering side was seen.",
    "OTH": "No handshake seen (traffic caught mid-way, or not TCP).",
}


def _is_in(nets, ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a.version == n.version and a in n for n in nets)


# ----------------------------------------------------------------------------
# Value formatting (Zeek ASCII / JSON writers)
# ----------------------------------------------------------------------------
def _esc(s: str) -> str:
    out = []
    for ch in s:
        o = ord(ch)
        if o < 32 or o == 127 or ch == "\\":
            out.append(f"\\x{o:02x}")
        else:
            out.append(ch)
    return "".join(out)


def fmt_value(v, typ: str) -> str:
    if v is None:
        return "-"
    if typ.startswith(("set[", "vector[")):
        if not v:
            return "(empty)"
        inner = typ[typ.index("[") + 1:-1]
        return ",".join(fmt_value(x, inner).replace(",", "\\x2c") for x in v)
    if typ in ("time", "interval", "double"):
        return f"{float(v):.6f}"
    if typ == "bool":
        return "T" if v else "F"
    if typ in ("count", "int", "port"):
        return str(int(v))
    s = str(v)
    if s == "":
        return "(empty)"
    if s == "-":
        return "\\x2d"
    return _esc(s)


def _json_value(v, typ: str):
    if typ.startswith(("set[", "vector[")):
        inner = typ[typ.index("[") + 1:-1]
        return [_json_value(x, inner) for x in v]
    if typ in ("time", "interval", "double"):
        return round(float(v), 6)
    if typ == "bool":
        return bool(v)
    if typ in ("count", "int", "port"):
        return int(v)
    return str(v)


# ----------------------------------------------------------------------------
# Connections
# ----------------------------------------------------------------------------
class _Ep:
    """One side of a TCP connection: Zeek's TCP_Endpoint plus a small reassembler."""
    __slots__ = ("is_orig", "state", "prev_state", "start", "last", "ack", "ref_raw", "ref_abs", "fin_cnt", "rst_cnt",
                 "hl_syn", "hl_fin", "hl_rst", "rx_cnt", "rx_thr", "w0_cnt", "w0_thr", "g_cnt", "g_thr", "fin_rel",
                 "next", "pending", "heap", "missed", "want", "data_pkts", "rx_pkts", "did_close", "win_scale")

    def __init__(self, is_orig: bool):
        self.is_orig = is_orig
        self.state = self.prev_state = TCP_INACTIVE
        self.start = self.last = self.ack = self.ref_raw = self.ref_abs = 0
        self.fin_cnt = self.rst_cnt = 0
        self.hl_syn = self.hl_fin = self.hl_rst = None
        self.rx_cnt = self.w0_cnt = self.g_cnt = 0
        self.rx_thr = self.w0_thr = self.g_thr = 1
        self.fin_rel = None
        self.next = 1
        self.pending: dict = {}
        self.heap: list = []
        self.missed = 0
        self.want = True
        self.data_pkts = self.rx_pkts = 0
        self.did_close = False
        self.win_scale = 0

    def set_state(self, s: int):
        self.prev_state = self.state
        self.state = s

    def to_abs(self, raw: int) -> int:
        d = (raw - self.ref_raw) & M32
        if d & 0x80000000:
            d -= 0x100000000
        return self.ref_abs + d

    def advance(self, a: int, raw: int):
        if a > self.ref_abs:
            self.ref_abs = a
            self.ref_raw = raw

    def init(self, seq: int, start_delta: int, last_raw: int):
        self.ref_raw = seq
        self.ref_abs = seq + (1 << 32)
        self.start = self.ref_abs + start_delta
        self.ack = self.start
        self.last = self.to_abs(last_raw)
        self.advance(self.last, last_raw)
        self.next = 1
        self.pending = {}
        self.heap = []

    def size(self, peer: "_Ep") -> int:
        if self.prev_state == TCP_SYN_SENT and self.state == TCP_RESET and peer.state == TCP_INACTIVE and not \
                (self.ack == self.start or self.ack == self.start + 1):
            return 0
        top = self.last if self.last > self.ack else self.ack
        size = top - self.start
        if size <= 0 and self.state == TCP_INACTIVE:
            return 0
        if size != 0:
            size -= 1
        if self.fin_cnt > 0 and size != 0:
            size -= 1
        return max(0, size)


class Conn:
    __slots__ = ("uid", "proto", "ip_proto", "key", "orig_h", "orig_p", "resp_h", "resp_p", "orig_raw", "start", "last",
                 "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "orig_bytes", "resp_bytes", "hist", "hist_seen",
                 "service", "o", "r", "apps", "dpd_done", "dpd_chunks", "dpd_bytes", "orig_l2", "resp_l2", "vlan", "inner_vlan",
                 "udp_o", "udp_r", "close_time", "local_orig", "local_resp", "icmp_type", "weirds", "dns_state", "rec", "extra",
                 "first_ack_seen")

    def __init__(self):
        self.service: list[str] = []
        self.apps: list = []
        self.dpd_done = False
        self.dpd_chunks: list = []
        self.dpd_bytes = 0
        self.hist: list[str] = []
        self.hist_seen = 0
        self.orig_pkts = self.orig_ip_bytes = self.resp_pkts = self.resp_ip_bytes = 0
        self.orig_bytes = self.resp_bytes = 0
        self.udp_o = self.udp_r = False
        self.close_time = None
        self.o = self.r = None
        self.weirds: set = set()
        self.dns_state = None
        self.rec = None
        self.extra: dict = {}
        self.first_ack_seen = False

    def add_service(self, s: str):
        if s not in self.service:
            self.service.append(s)

    def id_fields(self) -> dict:
        return {"uid": self.uid, "id.orig_h": self.orig_h, "id.orig_p": self.orig_p, "id.resp_h": self.resp_h, "id.resp_p": self.resp_p}

    def flip(self):
        self.orig_h, self.resp_h = self.resp_h, self.orig_h
        self.orig_p, self.resp_p = self.resp_p, self.orig_p
        self.orig_pkts, self.resp_pkts = self.resp_pkts, self.orig_pkts
        self.orig_ip_bytes, self.resp_ip_bytes = self.resp_ip_bytes, self.orig_ip_bytes
        self.orig_bytes, self.resp_bytes = self.resp_bytes, self.orig_bytes
        self.orig_l2, self.resp_l2 = self.resp_l2, self.orig_l2
        self.local_orig, self.local_resp = self.local_resp, self.local_orig
        self.udp_o, self.udp_r = self.udp_r, self.udp_o
        self.hist.append("^")
        if self.o is not None:
            self.o, self.r = self.r, self.o
            self.o.is_orig, self.r.is_orig = True, False
        self.orig_raw = self._raw_of(self.orig_h)

    @staticmethod
    def _raw_of(ip: str) -> bytes:
        try:
            return ipaddress.ip_address(ip).packed
        except ValueError:
            return b""


# ----------------------------------------------------------------------------
# Application analyzers
# ----------------------------------------------------------------------------
class App:
    service = ""

    def __init__(self, an: "Analyzer", c: Conn):
        self.an = an
        self.c = c
        self.active = True

    def data(self, is_orig: bool, b: bytes):
        pass

    def gap(self, is_orig: bool, n: int):
        pass

    def finish(self):
        pass

    def confirm(self):
        self.c.add_service(self.service)

    def stop(self):
        self.active = False


class FileTracker:
    """A file carried in a connection (HTTP body, FTP transfer, certificate): type, size, hashes."""

    def __init__(self, an: "Analyzer", c: Conn, source: str, is_orig: bool, filename=None, encoding=None, total=None,
                 depth=0, analyzers=("MD5", "SHA1", "SHA256")):
        self.an, self.c = an, c
        self.fuid = an.new_uid("F")
        self.source, self.is_orig, self.filename, self.total, self.depth = source, is_orig, filename, total, depth
        self.analyzers = list(analyzers)
        self.ts = self.last = an.now
        self.head = bytearray()
        self.hashes = [hashlib.md5(), hashlib.sha1(), hashlib.sha256()]
        self.seen = self.missing = 0
        enc = (encoding or "").lower()
        self.dec = zlib.decompressobj(16 + zlib.MAX_WBITS) if "gzip" in enc else zlib.decompressobj() if "deflate" in enc else None
        self.deflate_raw_tried = False
        self.mime = None
        self.done = False

    def feed(self, b: bytes) -> int:
        """Returns the number of decoded bytes (what Zeek counts as body length)."""
        if not b:
            return 0
        self.last = self.an.now
        if self.dec is not None:
            try:
                out = self.dec.decompress(b)
            except zlib.error:
                if not self.deflate_raw_tried and not self.seen:
                    self.deflate_raw_tried = True
                    self.dec = zlib.decompressobj(-zlib.MAX_WBITS)
                    return self.feed(b)
                self.dec = None
                out = b""
        else:
            out = b
        if out:
            if len(self.head) < 4096:
                self.head += out[:4096 - len(self.head)]
            for h in self.hashes:
                h.update(out)
            self.seen += len(out)
        return len(out)

    def gap(self, n: int):
        self.missing += n

    def finish(self) -> dict:
        if self.done:
            return self.rec
        self.done = True
        if self.dec is not None:
            try:
                tail = self.dec.flush()
            except zlib.error:
                tail = b""
            if tail:
                self.feed_plain(tail)
        self.mime = P.sniff_mime(bytes(self.head)) if self.seen else None
        c = self.c
        rec = {"ts": self.ts, "fuid": self.fuid, "uid": c.uid if c else None, "source": self.source, "depth": self.depth,
               "analyzers": self.analyzers, "mime_type": self.mime, "filename": self.filename, "duration": max(0.0, self.last - self.ts),
               "local_orig": (c.local_orig if self.is_orig else c.local_resp) if c else None, "is_orig": self.is_orig, "seen_bytes": self.seen, "total_bytes": self.total,
               "missing_bytes": self.missing, "overflow_bytes": 0, "timedout": False, "parent_fuid": None,
               "md5": self.hashes[0].hexdigest(), "sha1": self.hashes[1].hexdigest(), "sha256": self.hashes[2].hexdigest()}
        if c:
            rec.update({"id.orig_h": c.orig_h, "id.orig_p": c.orig_p, "id.resp_h": c.resp_h, "id.resp_p": c.resp_p})
        self.rec = rec
        self.an.log("files", rec)
        return rec

    def feed_plain(self, out: bytes):
        if len(self.head) < 4096:
            self.head += out[:4096 - len(self.head)]
        for h in self.hashes:
            h.update(out)
        self.seen += len(out)


HTTP_REQ_RE = re.compile(rb"^([A-Za-z][A-Za-z0-9_.\-]{0,31}) +(.*?)(?: +HTTP/(\d+(?:\.\d+)?))? *$")
HTTP_RESP_RE = re.compile(rb"^HTTP/(\d+(?:\.\d+)?) +(\d{3})(?: +(.*))?$")
HTTP_SIG_RE = re.compile(rb"^(GET|POST|HEAD|PUT|DELETE|OPTIONS|TRACE|CONNECT|PATCH|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK|"
                         rb"SEARCH|REPORT|NOTIFY|SUBSCRIBE|UNSUBSCRIBE|POLL|QUERY|PURGE|MKACTIVITY|CHECKOUT|MERGE|BCOPY|BDELETE|"
                         rb"BMOVE|BPROPFIND|BPROPPATCH|RPC_IN_DATA|RPC_OUT_DATA|X-MS-ENUMATTS) +\S")
HTTP_METHODS = {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE", "CONNECT", "PATCH", "PROPFIND", "PROPPATCH", "MKCOL",
                "COPY", "MOVE", "LOCK", "UNLOCK", "SEARCH", "REPORT", "NOTIFY", "SUBSCRIBE", "UNSUBSCRIBE", "POLL", "QUERY",
                "PURGE", "MKACTIVITY", "CHECKOUT", "MERGE", "BCOPY", "BDELETE", "BMOVE", "BPROPFIND", "BPROPPATCH",
                "RPC_IN_DATA", "RPC_OUT_DATA", "X-MS-ENUMATTS"}
PROXY_HEADERS = {"FORWARDED", "X-FORWARDED-FOR", "X-FORWARDED-FROM", "CLIENT-IP", "VIA", "XROXY-CONNECTION", "PROXY-CONNECTION"}


def _unescape_uri(u: bytes) -> bytes:
    """Zeek's unescape_URI: %XX becomes the byte, anything else is kept."""
    if b"%" not in u:
        return u
    out = bytearray()
    i = 0
    n = len(u)
    while i < n:
        ch = u[i]
        if ch == 0x25 and i + 2 < n:
            h = u[i + 1:i + 3]
            if len(h) == 2 and all(c in b"0123456789abcdefABCDEF" for c in h):
                out.append(int(h, 16))
                i += 3
                continue
        out.append(ch)
        i += 1
    return bytes(out)


class _HSide:
    __slots__ = ("buf", "state", "remain", "headers", "rec", "file", "body_len", "is_orig", "lines")

    def __init__(self, is_orig):
        self.is_orig = is_orig
        self.buf = bytearray()
        self.state = "start"
        self.remain = 0
        self.headers: list = []
        self.rec = None
        self.file = None
        self.body_len = 0
        self.lines = 0


class HttpApp(App):
    service = "http"

    def __init__(self, an, c):
        super().__init__(an, c)
        self.sides = [_HSide(True), _HSide(False)]
        self.pending: collections.deque = collections.deque()
        self.depth = 0
        self.confirmed = False
        self.logged: set = set()

    def _new_rec(self) -> dict:
        self.depth += 1
        r = self.c.id_fields()
        r.update(ts=self.an.now, trans_depth=self.depth, method=None, host=None, uri=None, referrer=None, version=None,
                 user_agent=None, origin=None, request_body_len=0, response_body_len=0, status_code=None, status_msg=None,
                 info_code=None, info_msg=None, tags=[], username=None, password=None, proxied=None, orig_fuids=None,
                 orig_filenames=None, orig_mime_types=None, resp_fuids=None, resp_filenames=None, resp_mime_types=None)
        return r

    def _log(self, rec):
        if id(rec) in self.logged:
            return
        self.logged.add(id(rec))
        self.an.log("http", rec)

    def data(self, is_orig, b):
        s = self.sides[0 if is_orig else 1]
        if s.state == "dead":
            return
        s.buf += b
        while self.active and s.state != "dead":
            st = s.state
            if st in ("start", "headers", "chunk_size", "chunk_crlf", "trailer"):
                i = s.buf.find(b"\n")
                if i < 0:
                    if len(s.buf) > 16384:
                        self._violation(s, "HTTP line too long")
                    break
                line = bytes(s.buf[:i]).rstrip(b"\r")
                del s.buf[:i + 1]
                self._line(s, line)
            elif st == "body":
                if not s.buf:
                    break
                n = min(s.remain, len(s.buf))
                self._body(s, bytes(s.buf[:n]))
                del s.buf[:n]
                s.remain -= n
                if s.remain == 0:
                    self._end_message(s)
            elif st == "chunk_data":
                if not s.buf:
                    break
                n = min(s.remain, len(s.buf))
                self._body(s, bytes(s.buf[:n]))
                del s.buf[:n]
                s.remain -= n
                if s.remain == 0:
                    s.state = "chunk_crlf"
            elif st == "close":
                if s.buf:
                    self._body(s, bytes(s.buf))
                    s.buf.clear()
                break
            else:
                break

    def gap(self, is_orig, n):
        s = self.sides[0 if is_orig else 1]
        if s.state in ("body", "chunk_data") and n <= s.remain:
            s.remain -= n
            if s.file:
                s.file.gap(n)
            s.body_len += n
            if s.remain == 0:
                if s.state == "body":
                    self._end_message(s)
                else:
                    s.state = "chunk_crlf"
        elif s.state == "close":
            if s.file:
                s.file.gap(n)
            s.body_len += n
        else:
            s.state = "dead"
            s.buf.clear()

    def _violation(self, s, why):
        if not self.confirmed:
            self.an.weird("bad_HTTP_request" if s.is_orig else "bad_HTTP_reply", self.c, why)
        s.state = "dead"
        s.buf.clear()

    def _line(self, s: _HSide, line: bytes):
        st = s.state
        if st == "start":
            if not line.strip():
                return
            if s.is_orig:
                m = HTTP_REQ_RE.match(line)
                if not m:
                    self._violation(s, line[:60].decode("latin-1"))
                    return
                method = m.group(1).decode("latin-1")
                if method.upper() not in HTTP_METHODS:
                    self.an.weird("unknown_HTTP_method", self.c, method)
                rec = self._new_rec()
                rec["method"] = method
                rec["uri"] = _unescape_uri(m.group(2)).decode("latin-1")
                s.rec = rec
                self.pending.append(rec)
            else:
                m = HTTP_RESP_RE.match(line)
                if not m:
                    if self.pending and self.pending[0]["status_code"] is None:
                        rec = self.pending[0]
                        rec.update(version="0.9", status_code=0, status_msg="<empty>")
                        s.rec = rec
                        s.body_len = 0
                        s.file = FileTracker(self.an, self.c, "HTTP", False)
                        s.state = "close"
                        rest = bytes(s.buf)
                        s.buf.clear()
                        self._body(s, line + b"\n" + rest)
                        if not self.confirmed:
                            self.confirmed = True
                            self.confirm()
                        return
                    self._violation(s, line[:60].decode("latin-1"))
                    return
                code = int(m.group(2))
                if self.pending:
                    rec = self.pending[0]
                else:
                    rec = self._new_rec()
                    rec["ts"] = self.an.now
                    self.pending.append(rec)
                msg = (m.group(3) or b"").decode("latin-1")
                rec["status_code"], rec["status_msg"] = code, msg
                if 100 <= code < 200:
                    rec["info_code"], rec["info_msg"] = code, msg
                rec["version"] = m.group(1).decode()
                s.rec = rec
                s.remain = code  # stash the code until the headers are done
                if not self.confirmed:
                    self.confirmed = True
                    self.confirm()
            s.headers = []
            s.state = "headers"
            s.lines = 0
        elif st == "headers":
            if line == b"":
                self._headers_done(s)
                return
            s.lines += 1
            if s.lines > 500:
                self._violation(s, "too many headers")
                return
            if line[:1] in (b" ", b"\t") and s.headers:
                n, v = s.headers[-1]
                s.headers[-1] = (n, v + " " + line.strip().decode("latin-1"))
                return
            name, _, val = line.partition(b":")
            s.headers.append((name.strip().decode("latin-1").upper(), val.strip().decode("latin-1")))
        elif st == "chunk_size":
            sz = line.split(b";", 1)[0].strip()
            if not sz:
                return
            try:
                n = int(sz, 16)
            except ValueError:
                self.an.weird("HTTP_bad_chunk_size", self.c, sz[:20].decode("latin-1"))
                s.state = "close"
                return
            if n == 0:
                s.state = "trailer"
            else:
                s.remain = n
                s.state = "chunk_data"
        elif st == "chunk_crlf":
            s.state = "chunk_size"
            if line:
                self._line(s, line)
        elif st == "trailer":
            if line == b"":
                self._end_message(s)

    def _headers_done(self, s: _HSide):
        rec = s.rec
        h = s.headers
        get = lambda k: next((v for n, v in h if n == k), None)  # noqa: E731
        if s.is_orig:
            for n, v in h:
                if n == "HOST":
                    rec["host"] = v
                elif n == "REFERER":
                    rec["referrer"] = v
                elif n == "USER-AGENT":
                    rec["user_agent"] = v
                    self.an.software(self.c.orig_h, None, "HTTP::BROWSER", v)
                elif n == "ORIGIN":
                    rec["origin"] = v
                elif n == "AUTHORIZATION" and v.lower().startswith("basic "):
                    try:
                        dec = base64.b64decode(v.split(None, 1)[1] + "==").decode("latin-1")
                        user, _, pw = dec.partition(":")
                        rec["username"] = user
                        self.an.cleartext_login(self.c, "HTTP", user, "an HTTP Basic login")
                    except (ValueError, IndexError):
                        pass
                elif n in PROXY_HEADERS:
                    rec["proxied"] = (rec["proxied"] or []) + [f"{n} -> {v}"]
            method = (rec["method"] or "").upper()
        else:
            code = s.remain
            for n, v in h:
                if n == "SERVER":
                    self.an.software(self.c.resp_h, self.c.resp_p, "HTTP::SERVER", v)
                elif n == "X-POWERED-BY":
                    self.an.software(self.c.resp_h, self.c.resp_p, "HTTP::APPSERVER", v)
            method = (rec["method"] or "").upper()
            if 100 <= code < 200 and code != 101:
                s.state = "start"
                s.rec = None
                return
            if code == 101 or (method == "CONNECT" and 200 <= code < 300):
                self._finish_rec(rec)
                leftovers = [(side.is_orig, bytes(side.buf)) for side in self.sides if side.buf]
                for side in self.sides:
                    side.state = "dead"
                    side.buf.clear()
                self.stop()
                if method == "CONNECT":
                    self.c.dpd_done = False
                    self.c.dpd_chunks = []
                    self.c.dpd_bytes = 0
                    for o, d in leftovers:
                        self.an._dpd(self.c, o, d)
                return
        te = (get("TRANSFER-ENCODING") or "").lower()
        cl = get("CONTENT-LENGTH")
        fname = None
        cd = get("CONTENT-DISPOSITION")
        if cd:
            m = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)"?', cd, re.I)
            if m:
                fname = m.group(1)
        enc = get("CONTENT-ENCODING")
        multipart = (get("CONTENT-TYPE") or "").lower().startswith("multipart/")
        s.body_len = 0
        s.file = None
        no_body = (not s.is_orig) and (method == "HEAD" or s.remain in (204, 304))
        if no_body:
            self._end_message(s)
            return
        length = None
        if cl is not None:
            try:
                length = int(cl.split(",")[0].strip())
                if length < 0:
                    raise ValueError
            except ValueError:
                self.an.weird("HTTP_bad_content_length", self.c, cl[:30])
                length = None
        if "chunked" in te:
            s.file = FileTracker(self.an, self.c, "HTTP", s.is_orig, fname, enc)
            s.state = "chunk_size"
        elif length is not None:
            if length == 0:
                self._end_message(s)
                return
            s.file = FileTracker(self.an, self.c, "HTTP", s.is_orig, fname, enc, total=length if not enc else None)
            s.remain = length
            s.state = "body"
        elif s.is_orig:
            self._end_message(s)
        else:
            s.file = FileTracker(self.an, self.c, "HTTP", s.is_orig, fname, enc)
            s.state = "close"
        if s.file is not None and multipart:
            s.file.multipart = True

    def _body(self, s: _HSide, b: bytes):
        if s.file is not None:
            s.body_len += s.file.feed(b)
        else:
            s.body_len += len(b)

    def _end_message(self, s: _HSide):
        rec = s.rec
        if rec is not None:
            if s.file is not None and (s.file.seen or s.file.missing):
                if s.is_orig and s.file.filename is None:
                    m = re.search(rb'Content-Disposition:[^\r\n]*filename="([^"\r\n]*)"', bytes(s.file.head), re.I)
                    if m:
                        s.file.filename = m.group(1).decode("latin-1")
                f = s.file.finish()
                if getattr(s.file, "multipart", False):
                    f["mime_type"] = None
                pre = "orig" if s.is_orig else "resp"
                rec[pre + "_fuids"] = (rec[pre + "_fuids"] or []) + [f["fuid"]]
                if f.get("filename"):
                    rec[pre + "_filenames"] = (rec[pre + "_filenames"] or []) + [f["filename"]]
                if f.get("mime_type"):
                    rec[pre + "_mime_types"] = (rec[pre + "_mime_types"] or []) + [f["mime_type"]]
            if s.is_orig:
                rec["request_body_len"] = s.body_len
            else:
                rec["response_body_len"] = s.body_len
                self._finish_rec(rec)
        s.file = None
        s.rec = None
        s.body_len = 0
        s.state = "start"

    def _finish_rec(self, rec):
        try:
            self.pending.remove(rec)
        except ValueError:
            pass
        self._log(rec)

    def finish(self):
        for s in self.sides:
            if s.state == "close" and s.rec is not None:
                self._end_message(s)
            elif s.rec is not None and s.file is not None:
                self._end_message(s)
        while self.pending:
            self._finish_rec(self.pending[0])


class TlsApp(App):
    service = "ssl"

    def __init__(self, an, c):
        super().__init__(an, c)
        self.buf = [bytearray(), bytearray()]
        self.hs = [bytearray(), bytearray()]
        self.ccs = [False, False]
        self.appdata = [False, False]
        self.rec = None
        self.tls13 = False
        self.client_psk = False
        self.client_ticket = False
        self.client_kex = False
        self.client_sid = b""
        self.hist: list[str] = []
        self.host_cert = None
        self.logged = False
        self.confirmed = False

    def _ensure(self):
        if self.rec is None:
            r = self.c.id_fields()
            r.update(ts=self.an.now, version=None, cipher=None, curve=None, server_name=None, resumed=False, last_alert=None,
                     next_protocol=None, established=False, ssl_history=None, cert_chain_fps=None, client_cert_chain_fps=None,
                     sni_matches_cert=None, ja3=None, ja3s=None, ja4=None)
            self.rec = r
        return self.rec

    def _h(self, is_orig, letter):
        if len(self.hist) < 100:
            self.hist.append(letter.upper() if is_orig else letter.lower())

    def data(self, is_orig, b):
        i = 0 if is_orig else 1
        buf = self.buf[i]
        buf += b
        while self.active and len(buf) >= 5:
            ct = buf[0]
            if ct & 0x80 and is_orig and self.rec is None and len(buf) >= 3:
                ln = ((ct & 0x7F) << 8) | buf[1]
                if len(buf) < 2 + ln:
                    break
                if buf[2] == 1:
                    self._ensure()
                    self._h(True, "C")
                del buf[:2 + ln]
                continue
            if ct not in (20, 21, 22, 23, 24) or buf[1] not in (2, 3, 0xFE):
                self._fail()
                return
            ln = (buf[3] << 8) | buf[4]
            if ln > 18432 + 2048:
                self._fail()
                return
            if len(buf) < 5 + ln:
                break
            body = bytes(buf[5:5 + ln])
            del buf[:5 + ln]
            self._record(is_orig, ct, body)

    def gap(self, is_orig, n):
        if not (self.rec and self.rec["established"]):
            self._fail()

    def _fail(self):
        self.buf = [bytearray(), bytearray()]
        self.stop()

    def _record(self, is_orig, ct, body):
        i = 0 if is_orig else 1
        if self.ccs[i] and not self.tls13 and ct != 20:
            # ciphertext record (Zeek: proc_ciphertext_record) - Finished, alerts and data after ChangeCipherSpec
            r = self._ensure()
            if ct == 23:
                self.appdata[i] = True
            if self.ccs[0] and self.ccs[1] and not r["established"]:
                r["established"] = True
                self._log()
                self.stop()
            return
        if ct == 22:
            if self.ccs[i]:
                return  # encrypted Finished
            hs = self.hs[i]
            hs += body
            while len(hs) >= 4:
                t = hs[0]
                ml = (hs[1] << 16) | (hs[2] << 8) | hs[3]
                if ml > 262144:
                    self._fail()
                    return
                if len(hs) < 4 + ml:
                    break
                msg = bytes(hs[4:4 + ml])
                del hs[:4 + ml]
                self._hs_msg(is_orig, t, msg)
        elif ct == 20:
            self._ensure()
            self._h(is_orig, "I")
            self.ccs[i] = True
            if is_orig and self.client_ticket and not self.client_kex and not self.tls13:
                self.rec["resumed"] = True
        elif ct == 21:
            self._ensure()
            if not self.ccs[i] and not (self.tls13 and not is_orig) and len(body) >= 2:
                self._h(is_orig, "L")
                self.rec["last_alert"] = ZT.SSL_ALERTS.get(body[1], f"unknown-{body[1]}")
        elif ct == 23:
            self.appdata[i] = True
            r = self._ensure()
            if not r["established"] and ((self.ccs[0] and self.ccs[1]) or (self.tls13 and self.appdata[0] and self.appdata[1])):
                r["established"] = True
                self._log()
                self.stop()
        elif ct == 24:
            self._ensure()
            self._h(is_orig, "B")

    def _hs_msg(self, is_orig, t, msg):
        r = self._ensure()
        letter = P.TLS_HS_LETTER.get(t, "Z")
        if t == 1:
            ch = P.parse_client_hello(msg)
            if ch is None:
                self._fail()
                return
            self._h(is_orig, letter)
            if not self.confirmed:
                self.confirmed = True
                self.confirm()
            if ch["sni"]:
                r["server_name"] = ch["sni"][0]
                if len(ch["sni"]) > 1:
                    self.an.weird("SSL_many_server_names", self.c)
            self.client_sid = ch["session_id"]
            self.client_psk = ch["psk"]
            self.client_ticket = bool(ch["ticket"])
            r["ja3"] = P.ja3(ch)
            r["ja4"] = P.ja4(ch)
            if r["version"] is None:
                pass
        elif t == 2:
            sh = P.parse_server_hello(msg)
            if sh is None:
                self._fail()
                return
            self._h(is_orig, "J" if sh["hrr"] else letter)
            v = sh["selected_version"] or sh["version"]
            r["version"] = P.tls_version_name(v)
            self.tls13 = v == 0x0304 or (v >> 8) == 0x7F
            r["cipher"] = P.cipher_name(sh["cipher"])
            if sh["alpn"]:
                r["next_protocol"] = sh["alpn"]
            if sh["key_share"] is not None and not sh["hrr"]:
                r["curve"] = ZT.SSL_CURVES.get(sh["key_share"], f"unknown-{sh['key_share']}")
            if self.client_sid and sh["session_id"] == self.client_sid and not self.tls13:
                r["resumed"] = True
            if sh["psk"] and self.client_psk:
                r["resumed"] = True
            r["ja3s"] = P.ja3s(sh)
            if not self.confirmed:
                self.confirmed = True
                self.confirm()
        else:
            self._h(is_orig, letter)
            if t == 11:
                self._certificates(is_orig, msg)
            elif t == 12 and len(msg) >= 3 and msg[0] == 3 and r["cipher"] and "ECDH" in r["cipher"]:
                cid = (msg[1] << 8) | msg[2]
                r["curve"] = ZT.SSL_CURVES.get(cid, f"unknown-{cid}")
            elif t == 16:
                self.client_kex = True

    def _certificates(self, is_orig, msg):
        if len(msg) < 3:
            return
        ders = []
        p = 3
        end = min(len(msg), 3 + ((msg[0] << 16) | (msg[1] << 8) | msg[2]))
        while p + 3 <= end:
            ln = (msg[p] << 16) | (msg[p + 1] << 8) | msg[p + 2]
            ders.append(msg[p + 3:p + 3 + ln])
            p += 3 + ln
        fps = []
        for k, der in enumerate(ders):
            fp = hashlib.sha256(der).hexdigest()
            fps.append(fp)
            x = self.an.certificate(self.c, der, host=(k == 0 and not is_orig), client=is_orig, depth=k)
            if k == 0 and not is_orig and x:
                self.host_cert = x
        if is_orig:
            self.rec["client_cert_chain_fps"] = fps
            if self.rec["cert_chain_fps"] is None:
                self.rec["cert_chain_fps"] = []
        else:
            self.rec["cert_chain_fps"] = fps
            if self.rec["client_cert_chain_fps"] is None:
                self.rec["client_cert_chain_fps"] = []

    def _log(self):
        if self.logged or self.rec is None:
            return
        self.logged = True
        r = self.rec
        r["ssl_history"] = "".join(self.hist) or None
        if r["server_name"] and self.host_cert:
            names = list(self.host_cert.get("san.dns") or [])
            cn = P.cert_cn(self.host_cert.get("certificate.subject") or "")
            if cn:
                names.append(cn)
            r["sni_matches_cert"] = P.hostname_matches(r["server_name"], names)
        self.an.log("ssl", r)
        self.an.tls_done(self.c, r, self.host_cert)

    def finish(self):
        if self.rec is not None and self.confirmed:
            self._log()


class SshApp(App):
    service = "ssh"

    def __init__(self, an, c):
        super().__init__(an, c)
        self.buf = [bytearray(), bytearray()]
        self.banner = [None, None]
        self.enc = [False, False]
        self.kex = [None, None]
        self.rec = None
        self.version = None
        self.saw_enc_client = False
        self.service_accept = None
        self.fail_size = None
        self.skipped_banner = False
        self.decided = False
        self.host_blob = None

    def data(self, is_orig, b):
        i = 0 if is_orig else 1
        if self.enc[i]:
            self._encrypted(is_orig, len(b))
            return
        buf = self.buf[i]
        buf += b
        if self.banner[i] is None:
            while True:
                j = buf.find(b"\n")
                if j < 0:
                    if len(buf) > 8192:
                        self.stop()
                    return
                line = bytes(buf[:j]).rstrip(b"\r")
                del buf[:j + 1]
                if line.startswith(b"SSH-"):
                    self.banner[i] = line.decode("latin-1")
                    self._on_banner(is_orig)
                    break
        if self.version == 1 or (self.banner[i] and self.banner[i].startswith("SSH-1.") and not self.banner[i].startswith("SSH-1.99")):
            if self.version == 1 and buf:
                self.confirm()
            buf.clear()
            return
        while len(buf) >= 6 and not self.enc[i]:
            plen = struct.unpack_from("!I", buf, 0)[0]
            if plen < 5 or plen > 262144:
                buf.clear()
                self.enc[i] = True
                return
            if len(buf) < 4 + plen:
                break
            pkt = bytes(buf[4:4 + plen])
            del buf[:4 + plen]
            pad = pkt[0]
            payload = pkt[1:max(1, plen - pad)]
            if not payload:
                continue
            mt = payload[0]
            if mt == 20:
                self.kex[i] = self._kexinit(payload)
                self._negotiate()
            elif mt == 21:
                self.enc[i] = True
                if self.banner[0] and self.banner[1]:
                    self.confirm()
                rest = len(buf)
                buf.clear()
                if rest:
                    self._encrypted(is_orig, rest)
            elif mt in (31, 33) and not is_orig and self.host_blob is None:
                kex = self.rec.get("kex_alg") or ""
                if kex and (mt == 33) == ("group-exchange" in kex):
                    try:
                        ln = struct.unpack_from("!I", payload, 1)[0]
                        blob = payload[5:5 + ln]
                        if blob:
                            self.host_blob = blob
                            self.rec["host_key_fingerprint"] = "SHA256:" + P.b64_nopad(hashlib.sha256(blob).digest())
                    except struct.error:
                        pass

    def _on_banner(self, is_orig):
        if self.rec is None:
            r = self.c.id_fields()
            lo, lr = self.c.local_orig, self.c.local_resp
            r.update(ts=self.an.now, version=None, auth_success=None, auth_attempts=0,
                     direction="OUTBOUND" if lo and not lr else "INBOUND" if lr and not lo else None, client=None, server=None,
                     cipher_alg=None, mac_alg=None, compression_alg=None, kex_alg=None, host_key_alg=None, host_key_fingerprint=None)
            self.rec = r
        if is_orig:
            self.rec["client"] = self.banner[0]
            self.an.software(self.c.orig_h, None, "SSH::CLIENT", self.banner[0])
        else:
            self.rec["server"] = self.banner[1]
            self.an.software(self.c.resp_h, self.c.resp_p, "SSH::SERVER", self.banner[1])
        self.version = self._zeek_version(self.banner[0], self.banner[1])
        self.rec["version"] = self.version

    @staticmethod
    def _zeek_version(cl, sv):
        """Zeek's SSH::set_version: needs both banners."""
        if not cl or not sv or len(cl) <= 4 or len(sv) <= 4:
            return None
        c99 = len(cl) > 7 and cl[6] == "9" and cl[7] == "9"
        s99 = len(sv) > 7 and sv[6] == "9" and sv[7] == "9"
        a, b = cl[4], sv[4]
        if a == "1" and b == "2":
            return 2 if c99 else None
        if a == "2" and b == "1":
            return 2 if s99 else None
        if a == "1" and b == "1":
            return (2 if c99 else 1) if s99 else 1
        if a == "2" and b == "2":
            return 2
        return None

    @staticmethod
    def _proto_ver(banner):
        if not banner:
            return None
        return banner[4:].split("-", 1)[0]

    @staticmethod
    def _kexinit(payload):
        lists = []
        off = 17
        try:
            for _ in range(10):
                ln = struct.unpack_from("!I", payload, off)[0]
                lists.append(payload[off + 4:off + 4 + ln].decode("latin-1").split(","))
                off += 4 + ln
        except struct.error:
            return None
        return lists

    def _negotiate(self):
        c, s = self.kex
        if not c or not s:
            return

        def find(ci, si):
            ss = set(s[si])
            return next((a for a in c[ci] if a in ss), "Algorithm negotiation failed")

        def bidi(i):
            a, b = find(i, i), find(i + 1, i + 1)
            return a if a == b else f"To server: {a}, to client: {b}"
        r = self.rec
        r["kex_alg"] = find(0, 0)
        r["host_key_alg"] = find(1, 1)
        r["cipher_alg"] = bidi(2)
        r["mac_alg"] = bidi(4)
        r["compression_alg"] = bidi(6)

    def _attempt(self, ok: bool):
        r = self.rec
        if r["auth_success"]:
            return
        if r.get("compression_alg") in ("zlib", "zlib@openssh.com"):
            return
        r["auth_success"] = ok
        r["auth_attempts"] += 1

    def _encrypted(self, is_orig, n):
        if self.decided or self.version != 2:
            return
        if is_orig:
            self.saw_enc_client = True
            return
        if not self.saw_enc_client:
            return
        if self.service_accept is None:
            self.service_accept = n
            return
        if self.fail_size is None and n + 16 == self.service_accept:
            self.decided = True
            self._attempt(True)
            return
        if self.fail_size is None:
            if not self.skipped_banner and n - self.service_accept > 256:
                self.skipped_banner = True
                return
            self.fail_size = n
            return
        if n == self.fail_size:
            self._attempt(False)
            return
        if n - self.service_accept == -16:
            self.decided = True
            self._attempt(True)

    def finish(self):
        if self.rec is not None:
            r = self.rec
            self.an.log("ssh", r)
            self.an.ssh_done(self.c, r)


def _build_path(d: str, f: str) -> str:
    if re.match(r"(/|[A-Za-z]:[\\/])", f) or d == "":
        return f
    return d + ("" if d.endswith("/") else "/") + f


def _compress_path(p: str) -> str:
    """zeek::util::detail::normalize_path: collapse //, drop /./ and resolve dir/.."""
    absolute = p.startswith("/")
    out: list[str] = []
    parts = p.split("/")
    for i, part in enumerate(parts):
        if part == "" or (part == "." and i > 0):
            continue
        if part == ".." and out and out[-1] not in ("..", "."):
            out.pop()
            continue
        out.append(part)
    res = "/".join(out)
    if absolute:
        res = "/" + res
    return res


FTP_LOGGED = {"APPE", "DELE", "RETR", "STOR", "STOU", "ACCT", "PORT", "PASV", "EPRT", "EPSV"}
FTP_GUESTS = {"anonymous", "ftp", "ftpuser", "guest"}


class FtpApp(App):
    service = "ftp"

    def __init__(self, an, c):
        super().__init__(an, c)
        self.buf = [bytearray(), bytearray()]
        self.cmds: collections.deque = collections.deque()
        self.user = "<unknown>"
        self.password = None
        self.cwd = "."
        self.multi = None
        self.confirmed = False
        self.pending_dc = None
        self.fails = 0

    def data(self, is_orig, b):
        i = 0 if is_orig else 1
        buf = self.buf[i]
        buf += b
        while True:
            j = buf.find(b"\n")
            if j < 0:
                if len(buf) > 8192:
                    buf.clear()
                return
            line = bytes(buf[:j]).rstrip(b"\r").decode("latin-1")
            del buf[:j + 1]
            if is_orig:
                self._command(line)
            else:
                self._reply(line)
            if not self.active:
                return

    def _command(self, line):
        cmd, _, arg = line.strip().partition(" ")
        cmd = cmd.upper()
        if not cmd:
            return
        if cmd == "USER":
            self.user = arg
        elif cmd == "PASS":
            self.password = arg if self.user.lower() in FTP_GUESTS else "<hidden>"
            if self.user.lower() not in FTP_GUESTS:
                self.an.cleartext_login(self.c, "FTP", self.user, "an FTP login")
        self.cmds.append({"ts": self.an.now, "cmd": cmd, "arg": arg})

    def _reply(self, line):
        m = re.match(r"^(\d{3})([ -])(.*)$", line)
        if self.multi is not None:
            if m and m.group(1) == self.multi[0] and m.group(2) == " ":
                code, msg = int(self.multi[0]), self.multi[1]
                self.multi = None
                self._handle_reply(code, msg)
            return
        if not m:
            return
        if m.group(2) == "-":
            self.multi = (m.group(1), m.group(3))
            return
        self._handle_reply(int(m.group(1)), m.group(3))

    def _handle_reply(self, code, msg):
        if not self.confirmed and code in (220, 331, 230, 530, 421):
            self.confirmed = True
            self.confirm()
        if code == 220 and not self.cmds:
            return
        if 100 <= code < 200 and self.cmds and self.cmds[0]["cmd"] in ("RETR", "STOR", "STOU", "APPE", "LIST", "NLST"):
            m = re.search(r"\((\d+) bytes\)", msg)
            if m:
                self.cmds[0]["size"] = int(m.group(1))
            return
        if not self.cmds:
            return
        c = self.cmds.popleft()
        cmd, arg = c["cmd"], c["arg"]
        if cmd == "PASS" and code == 530:
            self.fails += 1
            self.an.ftp_failed_login(self.c)
        if (cmd, code) in (("CWD", 250), ("CDUP", 200), ("CDUP", 250), ("PWD", 257), ("XPWD", 257)):
            if cmd == "CWD":
                self.cwd = _compress_path(_build_path(self.cwd, arg))
            elif cmd == "CDUP":
                self.cwd = _compress_path(_build_path(self.cwd, "/.."))
            else:
                m = re.search(r'(/|[A-Za-z]:[\\/])([^" ]|(\\ ))*', msg)
                self.cwd = m.group(0) if m else ""
        if code == 234 and cmd == "AUTH":
            self.stop()
            return
        if cmd not in FTP_LOGGED:
            return
        rec = self.c.id_fields()
        rec.update(ts=c["ts"], user=self.user, password=self.password, command=cmd, arg=arg or None, mime_type=None,
                   file_size=c.get("size"), reply_code=code, reply_msg=msg, fuid=None)
        rec.update({"data_channel.passive": None, "data_channel.orig_h": None, "data_channel.resp_h": None, "data_channel.resp_p": None})
        dc = None
        if cmd == "PASV" and code == 227:
            m = re.search(r"(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)", msg)
            if m:
                h = ".".join(m.group(1, 2, 3, 4))
                dc = (True, self.c.orig_h, h, int(m.group(5)) * 256 + int(m.group(6)))
        elif cmd == "EPSV" and code == 229:
            m = re.search(r"\(\|\|\|(\d+)\|\)", msg)
            if m:
                dc = (True, self.c.orig_h, self.c.resp_h, int(m.group(1)))
        elif cmd == "PORT" and 200 <= code < 300:
            m = re.search(r"(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)", arg)
            if m:
                dc = (False, self.c.resp_h, ".".join(m.group(1, 2, 3, 4)), int(m.group(5)) * 256 + int(m.group(6)))
        elif cmd == "EPRT" and 200 <= code < 300:
            parts = arg.split(arg[:1]) if arg else []
            if len(parts) >= 4:
                try:
                    dc = (False, self.c.resp_h, parts[2], int(parts[3]))
                except ValueError:
                    pass
        if dc:
            rec["data_channel.passive"], rec["data_channel.orig_h"], rec["data_channel.resp_h"], rec["data_channel.resp_p"] = dc
            self.pending_dc = (dc[2], dc[3])
            self.an.ftp_expect[(dc[2], dc[3])] = self.c.uid
            rec["arg"] = None if cmd in ("PASV", "EPSV") else rec["arg"]
        if cmd in ("RETR", "STOR", "STOU", "APPE"):
            path = _compress_path(_build_path(self.cwd, arg))
            if not path.startswith("/"):
                path = "/" + path
            host = f"[{self.c.resp_h}]" if ":" in self.c.resp_h else self.c.resp_h
            rec["arg"] = f"ftp://{host}{path}"
            if self.pending_dc:
                rec["_dc"] = self.pending_dc
                self.pending_dc = None
        self.an.log("ftp", rec)


class FtpDataApp(App):
    service = "ftp-data"

    def __init__(self, an, c):
        super().__init__(an, c)
        self.file = None
        self.confirm()

    def data(self, is_orig, b):
        if self.file is None:
            self.file = FileTracker(self.an, self.c, "FTP_DATA", is_orig)
        self.file.feed(b)

    def gap(self, is_orig, n):
        if self.file:
            self.file.gap(n)

    def finish(self):
        if self.file:
            rec = self.file.finish()
            self.an.ftp_files[(self.c.resp_h, self.c.resp_p)] = rec


class MailApp(App):
    """SMTP / POP3 / IMAP: service name plus cleartext-login detection."""

    def __init__(self, an, c, kind):
        super().__init__(an, c)
        self.service = kind
        self.buf = bytearray()
        self.user = None
        self.expect_login = 0
        self.confirmed = False

    def data(self, is_orig, b):
        if not is_orig:
            if not self.confirmed and (b.startswith((b"220", b"+OK", b"* OK", b"250"))):
                self.confirmed = True
                self.confirm()
            return
        self.buf += b
        while True:
            j = self.buf.find(b"\n")
            if j < 0:
                if len(self.buf) > 8192:
                    self.buf.clear()
                return
            line = bytes(self.buf[:j]).rstrip(b"\r").decode("latin-1")
            del self.buf[:j + 1]
            self._line(line)
            if not self.active:
                return

    def _line(self, line):
        u = line.upper()
        k = self.service
        if u.startswith("STARTTLS") or u.endswith(" STARTTLS") or u.startswith("STLS"):
            self.stop()
            return
        if k == "pop3":
            if u.startswith("USER "):
                self.user = line[5:].strip()
            elif u.startswith("PASS "):
                self.an.cleartext_login(self.c, "POP3", self.user or "?", "a POP3 mail login")
        elif k == "imap":
            parts = line.split(" ", 3)
            if len(parts) >= 3 and parts[1].upper() == "LOGIN":
                self.an.cleartext_login(self.c, "IMAP", parts[2].strip('"'), "an IMAP mail login")
        elif k == "smtp":
            if u.startswith("AUTH PLAIN"):
                arg = line[10:].strip()
                user = "?"
                if arg:
                    try:
                        user = base64.b64decode(arg + "==").split(b"\x00")[1].decode("latin-1")
                    except (ValueError, IndexError):
                        pass
                self.an.cleartext_login(self.c, "SMTP", user, "an SMTP mail login")
            elif u.startswith("AUTH LOGIN"):
                self.expect_login = 1
            elif self.expect_login == 1:
                try:
                    self.user = base64.b64decode(line.strip() + "==").decode("latin-1")
                except ValueError:
                    self.user = "?"
                self.expect_login = 2
            elif self.expect_login == 2:
                self.expect_login = 0
                self.an.cleartext_login(self.c, "SMTP", self.user or "?", "an SMTP mail login")


class DnsTcpApp(App):
    service = "dns"

    def __init__(self, an, c):
        super().__init__(an, c)
        self.buf = [bytearray(), bytearray()]

    def data(self, is_orig, b):
        buf = self.buf[0 if is_orig else 1]
        buf += b
        while len(buf) >= 2:
            ln = (buf[0] << 8) | buf[1]
            if len(buf) < 2 + ln:
                if len(buf) > 70000:
                    buf.clear()
                break
            msg = bytes(buf[2:2 + ln])
            del buf[:2 + ln]
            self.an.dns_message(self.c, is_orig, msg, "tcp")


class QuicState:
    def __init__(self, an, c):
        self.an, self.c = an, c
        self.rec = None
        self.hist: list[str] = []
        self.keys = None
        self.skeys = None
        self.crypto: dict = {}
        self.ch_done = False
        self.sh_done = False
        self.short = [0, 0]
        self.version = None
        self.dcid = None

    def _h(self, is_orig, letter):
        if len(self.hist) < 100:
            self.hist.append(letter.upper() if is_orig else letter.lower())

    def datagram(self, is_orig, d):
        if not d:
            return
        if not d[0] & 0x80:
            if self.rec is None or not d[0] & 0x40:
                return
            i = 0 if is_orig else 1
            self.short[i] += 1
            n = self.short[i]
            if n & (n - 1) == 0:
                self._h(is_orig, "O")
            return
        pkts = P.quic_long_headers(d)
        tail = pkts[-1].get("end") if pkts else None
        if tail is not None and tail < len(d) and d[tail] & 0xC0 == 0x40 and self.rec is not None:
            pkts = pkts + [{"type": "short"}]
        for p in pkts:
            if p["type"] == "short":
                i = 0 if is_orig else 1
                self.short[i] += 1
                n = self.short[i]
                if n & (n - 1) == 0:
                    self._h(is_orig, "O")
                continue
            if p["type"] == "version_negotiation":
                continue
            if self.rec is None:
                r = self.c.id_fields()
                r.update(ts=self.an.now, version=P.quic_version_name(p["version"]), client_initial_dcid=None, client_scid=None,
                         server_scid=None, server_name=None, client_protocol=None, history=None)
                self.rec = r
                self.version = p["version"]
            r = self.rec
            t = p["type"]
            if t == "unknown":
                self._h(is_orig, "U")
                continue
            if is_orig and r["client_initial_dcid"] is None and t == "initial":
                r["client_initial_dcid"] = p["dcid"].hex()
                r["client_scid"] = p["scid"].hex()
                self.dcid = p["dcid"]
            if not is_orig and r["server_scid"] is None:
                r["server_scid"] = p["scid"].hex()
            if t == "initial":
                self._h(is_orig, "I")
                if self.dcid is not None:
                    self._initial(is_orig, p)
            elif t == "handshake":
                self._h(is_orig, "H")
            elif t == "0rtt":
                self._h(is_orig, "Z")
            elif t == "retry":
                self._h(is_orig, "R")

    def _initial(self, is_orig, p):
        try:
            if is_orig:
                if self.ch_done:
                    return
                if self.keys is None:
                    self.keys = P.quic_initial_keys(self.version, self.dcid, True)
                keys = self.keys
            else:
                if self.sh_done:
                    return
                if self.skeys is None:
                    self.skeys = P.quic_initial_keys(self.version, self.dcid, False)
                keys = self.skeys
            if keys is None:
                return
            frames = P.quic_decrypt_initial(p, keys)
            if not frames:
                return
            crypto, close = P.quic_crypto_frames(frames)
            if is_orig:
                for off, data in crypto:
                    if off < 65536:
                        self.crypto[off] = data
                buf = bytearray()
                while len(buf) in self.crypto:
                    nxt = self.crypto[len(buf)]
                    if not nxt:
                        break
                    buf += nxt
                if len(buf) >= 4 and buf[0] == 1:
                    ml = (buf[1] << 16) | (buf[2] << 8) | buf[3]
                    if len(buf) >= 4 + ml:
                        ch = P.parse_client_hello(bytes(buf[4:4 + ml]))
                        if ch:
                            self.ch_done = True
                            self._h(True, "S")
                            if ch["sni"]:
                                self.rec["server_name"] = ch["sni"][0]
                            if ch["alpn"]:
                                self.rec["client_protocol"] = ch["alpn"][0]
                            self.c.add_service("quic")
                            t = self._tls()
                            t["server_name"] = ch["sni"][0] if ch["sni"] else None
                            t["ja3"], t["ja4"] = P.ja3(ch), P.ja4(ch, quic=True)
                            t["_hist"].append("C")
                            self.client_psk = ch["psk"]
            else:
                for off, data in crypto:
                    if off == 0 and data[:1] == b"\x02":
                        self.sh_done = True
                        self._h(False, "S")
                        self.c.add_service("quic")
                        ml = int.from_bytes(data[1:4], "big")
                        sh = P.parse_server_hello(data[4:4 + ml])
                        if sh:
                            t = self._tls()
                            v = sh["selected_version"] or sh["version"]
                            t["version"] = P.tls_version_name(v)
                            t["cipher"] = P.cipher_name(sh["cipher"])
                            if sh["key_share"] is not None:
                                t["curve"] = ZT.SSL_CURVES.get(sh["key_share"], f"unknown-{sh['key_share']}")
                            t["resumed"] = bool(sh["psk"] and getattr(self, "client_psk", False))
                            t["ja3s"] = P.ja3s(sh)
                            t["_hist"].append("s")
            if close:
                self._h(is_orig, "C")
        except (IndexError, ValueError, struct.error):
            return

    def _tls(self) -> dict:
        t = self.__dict__.get("ssl")
        if t is None:
            t = self.c.id_fields()
            t.update(ts=self.rec["ts"] if self.rec else self.an.now, version=None, cipher=None, curve=None, server_name=None,
                     resumed=False, last_alert=None, next_protocol=None, established=False, ssl_history=None, cert_chain_fps=None,
                     client_cert_chain_fps=None, sni_matches_cert=None, ja3=None, ja3s=None, ja4=None, _hist=[])
            self.ssl = t
        return t

    def finish(self):
        if self.rec is not None:
            self.rec["history"] = "".join(self.hist) or None
            self.an.log("quic", self.rec)
            t = self.__dict__.get("ssl")
            if t is not None:
                t["ssl_history"] = "".join(t.pop("_hist")) or None
                self.an.log("ssl", t)
                self.c.add_service("ssl")
            self.an.quic_done(self.c, self.rec)


# ----------------------------------------------------------------------------
# Analyzer
# ----------------------------------------------------------------------------
class Cancelled(Exception):
    pass


class Result:
    def __init__(self, logs: dict, meta: dict, summary: dict):
        self.logs = logs
        self.meta = meta
        self._summary = summary

    def summary(self) -> dict:
        return self._summary

    def counts(self) -> dict:
        return {k: len(v) for k, v in self.logs.items()}

    def tsv(self, name: str) -> str:
        fields = SCHEMAS[name]
        opened = time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime(self.meta.get("analysed", time.time())))
        out = io.StringIO()
        out.write("#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n")
        out.write(f"#path\t{name}\n#open\t{opened}\n")
        out.write("#fields\t" + "\t".join(f for f, _ in fields) + "\n")
        out.write("#types\t" + "\t".join(t for _, t in fields) + "\n")
        for r in self.logs.get(name, []):
            out.write("\t".join(fmt_value(r.get(f), t) for f, t in fields) + "\n")
        out.write(f"#close\t{opened}\n")
        return out.getvalue()

    def json_lines(self, name: str) -> str:
        fields = SCHEMAS[name]
        lines = []
        for r in self.logs.get(name, []):
            o = {}
            for f, t in fields:
                v = r.get(f)
                if v is not None:
                    o[f] = _json_value(v, t)
            lines.append(json.dumps(o, ensure_ascii=False))
        return "\n".join(lines) + ("\n" if lines else "")

    def write_zip(self, path: str, fmt: str = "zeek") -> str:
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
            for name in LOG_ORDER:
                if not self.logs.get(name) and name != "conn":
                    continue
                z.writestr(f"{name}.log", self.tsv(name) if fmt == "zeek" else self.json_lines(name))
            z.writestr("README.txt", _README.format(src=self.meta.get("source", ""), when=time.strftime("%Y-%m-%d %H:%M"),
                                                     fmt="Zeek TSV (zeek-cut compatible)" if fmt == "zeek" else "JSON lines (one object per line)"))
        return path

    def write_dir(self, d: str, fmt: str = "zeek") -> list[str]:
        os.makedirs(d, exist_ok=True)
        out = []
        for name in LOG_ORDER:
            if not self.logs.get(name) and name != "conn":
                continue
            p = os.path.join(d, f"{name}.log")
            with open(p, "w", encoding="utf-8", newline="\n") as f:
                f.write(self.tsv(name) if fmt == "zeek" else self.json_lines(name))
            out.append(p)
        return out

    # -- viewer queries ---------------------------------------------------------------
    def rows(self, name: str, q: str = "", uid: str = "", offset: int = 0, limit: int = 200, sort: str = "", desc: bool = False) -> dict:
        if name not in SCHEMAS:
            raise ValueError("Unknown log.")
        fields = SCHEMAS[name]
        recs = self.logs.get(name, [])
        if uid:
            if name == "dhcp":
                recs = [r for r in recs if uid in (r.get("uids") or [])]
            elif name == "x509":
                fps = set()
                for s in self.logs.get("ssl", []):
                    if s.get("uid") == uid:
                        fps.update(s.get("cert_chain_fps") or [])
                        fps.update(s.get("client_cert_chain_fps") or [])
                recs = [r for r in recs if r.get("fingerprint") in fps]
            elif name in ("software", "known_hosts", "known_services"):
                recs = []
            else:
                recs = [r for r in recs if r.get("uid") == uid]
        if q:
            ql = q.lower()
            recs = [r for r in recs if any(ql in fmt_value(r.get(f), t).lower() for f, t in fields)]
        if sort and any(f == sort for f, _ in fields):
            recs = sorted(recs, key=lambda r: (r.get(sort) is None, _sort_key(r.get(sort))), reverse=desc)
        total = len(recs)
        page = recs[offset:offset + limit]
        return {"log": name, "fields": [f for f, _ in fields], "types": [t for _, t in fields], "total": total, "offset": offset,
                "rows": [[fmt_value(r.get(f), t) for f, t in fields] for r in page],
                "extra": [{k: r[k] for k in ("_severity", "_plain", "_filter") if k in r} for r in page] if name == "notice" else None}


def _sort_key(v):
    if isinstance(v, (int, float)):
        return (0, v, "")
    if isinstance(v, list):
        return (1, 0, ",".join(map(str, v)))
    return (1, 0, str(v))


_README = """These logs were produced by LinkTest from {src} on {when}.
Format: {fmt}.

They follow Zeek's log layout (https://docs.zeek.org/en/current/logs/), so zeek-cut, Splunk / Elastic
Zeek add-ons and RITA-style tools read them. The "uid" field links the lines that belong to one
connection across all the logs.

LinkTest's analyzer is its own implementation, not Zeek itself: conn.log states and history follow
Zeek's rules, and the protocol logs carry the same fields; a few fields Zeek fills only with extra
scripts (JA3/JA4, file hashes, MAC addresses, VLAN, Community ID) are included here by default.
"""


class Analyzer:
    def __init__(self, progress=None, cancel=None, seed: str = ""):
        self.progress = progress
        self.cancel = cancel
        self.seed = seed
        self.logs: dict[str, list] = {k: [] for k in SCHEMAS}
        self.conns: dict = {}
        self.frags: dict = {}
        self.now = 0.0
        self.first_ts = None
        self.last_ts = 0.0
        self.pkts = 0
        self.bytes = 0
        self.non_ip = 0
        self.uid_n = 0
        self.local_cache: dict = {}
        self.x509_seen: set = set()
        self.sw_seen: set = set()
        self.dhcp_tx: dict = {}
        self.ftp_expect: dict = {}
        self.ftp_files: dict = {}
        self.weird_seen: set = set()
        self.notice_seen: set = set()
        self.arp: dict = {}
        self.ssh_fail: collections.Counter = collections.Counter()
        self.ftp_fail: collections.Counter = collections.Counter()
        self.creds: list = []
        self.traceroute: dict = {}
        self.last_sweep = 0.0
        self.dhcp_servers: dict = {}

    # -- helpers ------------------------------------------------------------------------
    def new_uid(self, prefix: str = "C") -> str:
        self.uid_n += 1
        h = hashlib.sha1(f"{self.seed}|{prefix}|{self.uid_n}".encode()).digest()
        n = int.from_bytes(h[:12], "big")
        s = ""
        while n and len(s) < 17:
            n, r = divmod(n, 62)
            s += B62[r]
        return prefix + s

    def is_local(self, ip: str) -> bool:
        v = self.local_cache.get(ip)
        if v is None:
            v = _is_in(_LOCAL_NETS, ip)
            self.local_cache[ip] = v
        return v

    def log(self, name: str, rec: dict):
        self.logs[name].append(rec)

    def weird(self, name: str, c: Conn | None = None, addl=None, source="zeek"):
        if c is not None:
            if name in c.weirds:
                return
            c.weirds.add(name)
            rec = c.id_fields()
        else:
            k = (name, addl)
            if k in self.weird_seen:
                return
            self.weird_seen.add(k)
            rec = {"uid": None, "id.orig_h": None, "id.orig_p": None, "id.resp_h": None, "id.resp_p": None}
        rec.update(ts=self.now, name=name, addl=addl, notice=False, peer=source, source=None)
        self.log("weird", rec)

    def notice(self, note: str, msg: str, c: Conn | None = None, sub=None, src=None, dst=None, p=None, n=None, severity="warn",
               plain="", flt=None, key=None, ts=None, proto=None, fuid=None):
        k = key or (note, src, dst, p, sub)
        if k in self.notice_seen:
            return
        self.notice_seen.add(k)
        rec = c.id_fields() if c else {"uid": None, "id.orig_h": None, "id.orig_p": None, "id.resp_h": None, "id.resp_p": None}
        rec.update(ts=self.now if ts is None else ts, fuid=fuid, file_mime_type=None, file_desc=None,
                   proto=(c.proto if c else proto), note=note, msg=msg, sub=sub, src=src, dst=dst, p=p, n=n, peer_descr=None,
                   actions=["Notice::ACTION_LOG"], email_dest=[], suppress_for=3600.0,
                   _severity=severity, _plain=plain, _filter=flt or ({"uid": c.uid} if c else None))
        self.log("notice", rec)

    def software(self, host, port, typ, s):
        if not s or not host:
            return
        parsed = P.parse_software(s)
        if not parsed:
            return
        name, (a, b, c2, d, addl) = parsed
        key = (host, typ, name, a, b, c2, d, addl)
        if key in self.sw_seen:
            return
        self.sw_seen.add(key)
        self.log("software", {"ts": self.now, "host": host, "host_p": port, "software_type": typ, "name": name, "version.major": a,
                              "version.minor": b, "version.minor2": c2, "version.minor3": d, "version.addl": addl,
                              "unparsed_version": s})

    def certificate(self, c: Conn, der: bytes, host: bool, client: bool, depth: int):
        x = P.parse_x509(der)
        f = FileTracker(self, c, "SSL", client, depth=depth, analyzers=("MD5", "SHA1", "SHA256", "X509"))
        f.feed(der)
        f.total = len(der)
        rec = f.finish()
        rec["mime_type"] = "application/x-x509-user-cert" if depth == 0 else "application/x-x509-ca-cert"
        if x is None:
            self.weird("x509_cert_parse_error", c)
            return None
        if x["fingerprint"] not in self.x509_seen:
            self.x509_seen.add(x["fingerprint"])
            r = dict(x)
            r.update(ts=self.now, host_cert=host, client_cert=client)
            self.log("x509", r)
        return x

    def cleartext_login(self, c: Conn, proto: str, user: str, what: str):
        self.creds.append((c, proto, user))
        self.notice("LinkTest::Cleartext_Password", f"{proto} password sent unencrypted by {c.orig_h} for user {user}", c,
                    sub=user, src=c.orig_h, dst=c.resp_h, p=c.resp_p, severity="bad",
                    plain=f"{c.orig_h} sent {what} to {c.resp_h} without encryption. Anyone on the network path can read "
                          f"the user name and password. Switch that service to its encrypted version.")

    def ftp_failed_login(self, c: Conn):
        self.ftp_fail[c.orig_h] += 1

    # -- protocol results feeding notices ----------------------------------------------------
    def tls_done(self, c: Conn, r: dict, cert: dict | None):
        v = r.get("version")
        if v in ("SSLv2", "SSLv3", "TLSv10", "TLSv11"):
            self.notice("SSL::Old_Version", f"Host uses protocol version {v} which is lower than the safe minimum TLSv12", c,
                        sub=r.get("server_name"), src=c.orig_h, dst=c.resp_h, p=c.resp_p, severity="warn",
                        key=("SSL::Old_Version", c.resp_h, c.resp_p, v),
                        plain=f"{c.resp_h} ({r.get('server_name') or 'no name'}) still uses {v}, an outdated version of encryption "
                              f"with known weaknesses. Update the server or device to TLS 1.2 or newer.")
        ciph = r.get("cipher") or ""
        if re.search(r"_(RC4|NULL|EXPORT|DES_CBC|DES40|anon)_|_WITH_NULL|3DES|_RC2_", ciph):
            self.notice("SSL::Weak_Cipher", f"Host established connection with weak cipher ({ciph})", c, sub=ciph, src=c.orig_h,
                        dst=c.resp_h, p=c.resp_p, severity="warn", key=("SSL::Weak_Cipher", c.resp_h, ciph),
                        plain=f"The secure connection to {c.resp_h} uses {ciph}, a cipher that is considered breakable.")
        if cert:
            now = self.now
            subj = cert.get("certificate.subject") or ""
            if cert.get("certificate.not_valid_after") and cert["certificate.not_valid_after"] < now:
                self.notice("SSL::Certificate_Expired", f"Certificate {subj} expired at "
                            f"{time.strftime('%Y-%m-%d', time.gmtime(cert['certificate.not_valid_after']))}", c, sub=subj,
                            src=c.orig_h, dst=c.resp_h, p=c.resp_p, severity="bad", key=("expired", cert["fingerprint"]),
                            plain=f"The certificate {c.resp_h} presented had already expired when this was captured, so browsers "
                                  f"and apps show a security warning (or refuse to connect).")
            elif cert.get("certificate.not_valid_before") and cert["certificate.not_valid_before"] > now:
                self.notice("SSL::Certificate_Not_Valid_Yet", f"Certificate {subj} isn't valid until "
                            f"{time.strftime('%Y-%m-%d', time.gmtime(cert['certificate.not_valid_before']))}", c, sub=subj,
                            src=c.orig_h, dst=c.resp_h, p=c.resp_p, severity="bad", key=("notyet", cert["fingerprint"]),
                            plain="The certificate is not valid yet. Usually the clock on one of the devices is wrong.")
            if subj and subj == cert.get("certificate.issuer"):
                self.notice("SSL::Invalid_Server_Cert", "SSL certificate validation failed with (self signed certificate)", c,
                            sub=subj, src=c.orig_h, dst=c.resp_h, p=c.resp_p, severity="warn", key=("selfsigned", cert["fingerprint"]),
                            plain=f"{c.resp_h} uses a self-signed certificate. That is normal for printers, routers and lab gear, but "
                                  f"on a public website it means the connection cannot be trusted.")
            if cert.get("certificate.key_type") == "rsa" and (cert.get("certificate.key_length") or 4096) < 2048:
                self.notice("SSL::Weak_Key", f"Host uses weak certificate with {cert['certificate.key_length']} bit key", c,
                            sub=subj, src=c.orig_h, dst=c.resp_h, p=c.resp_p, severity="warn", key=("weakkey", cert["fingerprint"]),
                            plain=f"The certificate from {c.resp_h} uses a {cert['certificate.key_length']}-bit RSA key; 2048 bits is "
                                  f"the minimum considered safe.")
        if r.get("sni_matches_cert") is False:
            self.notice("LinkTest::Certificate_Name_Mismatch", f"Certificate does not match the requested name {r.get('server_name')}",
                        c, sub=r.get("server_name"), src=c.orig_h, dst=c.resp_h, p=c.resp_p, severity="warn",
                        key=("mismatch", c.resp_h, r.get("server_name")),
                        plain=f"{c.orig_h} asked for {r.get('server_name')} but {c.resp_h} answered with a certificate for a "
                              f"different name. That causes certificate warnings, and can mean traffic is being intercepted.")

    def ssh_done(self, c: Conn, r: dict):
        if r.get("auth_success") is False:
            self.ssh_fail[c.orig_h] += max(1, r.get("auth_attempts") or 1)
        if (r.get("version") or 2) == 1:
            self.notice("LinkTest::Old_SSH_Version", f"SSH protocol version 1 used between {c.orig_h} and {c.resp_h}", c,
                        src=c.orig_h, dst=c.resp_h, p=c.resp_p, severity="warn", key=("ssh1", c.resp_h),
                        plain="SSH version 1 is obsolete and insecure; configure the device to use SSH version 2.")

    def quic_done(self, c: Conn, r: dict):
        pass

    # -- DNS ---------------------------------------------------------------------------------
    def dns_message(self, c: Conn, is_orig: bool, payload: bytes, proto: str):
        m = P.parse_dns(payload)
        if m is None:
            self.weird("DNS_truncated_len_lt_hdr_len", c)
            return
        if m["opcode"] not in (0, 4, 5):
            return
        if m["QR"] and is_orig and c.dns_state is None and c.resp_pkts == 0 and c.proto == "udp":
            c.flip()
            is_orig = False
        c.add_service("dns")
        st = c.dns_state
        if st is None:
            st = c.dns_state = {"pq": None, "pqs": collections.defaultdict(collections.deque), "prs": collections.defaultdict(collections.deque)}
        is_query = not m["QR"]
        qid = m["id"]

        def new():
            r = c.id_fields()
            r.update(ts=self.now, proto=proto, trans_id=qid, rtt=None, query=None, qclass=None, qclass_name=None, qtype=None,
                     qtype_name=None, rcode=None, rcode_name=None, AA=False, TC=False, RD=False, RA=False, Z=0, answers=None,
                     TTLs=None, rejected=False, opcode=None, opcode_name=None, _sq=False, _sr=False)
            return r
        if _is_in(_MULTICAST, c.resp_h):
            d = new()
            d["_sq"] = d["_sr"] = True
        elif is_query:
            if st["prs"].get(qid):
                d = st["prs"][qid].popleft()
            else:
                d = new()
                if st["pq"] is None:
                    st["pq"] = d
                else:
                    st["pqs"][qid].append(d)
        else:
            if st["pq"] is not None and st["pq"]["trans_id"] == qid:
                d = st["pq"]
                st["pq"] = None
                if st["pqs"].get(qid):
                    st["pq"] = st["pqs"][qid].popleft()
                else:
                    for k2, q2 in st["pqs"].items():
                        if q2:
                            st["pq"] = q2.popleft()
                            break
            elif st["pqs"].get(qid):
                d = st["pqs"][qid].popleft()
            else:
                d = new()
                st["prs"][qid].append(d)
        if not is_query:
            d["rcode"] = m["rcode"]
            d["rcode_name"] = ZT.DNS_RCODES.get(m["rcode"], f"rcode-{m['rcode']}")
            if m["rcode"] != 0 and m["num_queries"] == 0:
                d["rejected"] = True
            if m["queries"] and m["num_answers"] == 0 and m["num_auth"] == 0 and m["num_addl"] == 0:
                d["rejected"] = True
        d["opcode"] = m["opcode"]
        d["opcode_name"] = ZT.DNS_OPCODES.get(m["opcode"], f"opcode-{m['opcode']}")
        netbios = 137 in (c.orig_p, c.resp_p)
        if is_query:
            d["RD"], d["TC"], d["Z"] = m["RD"], m["TC"], m["Z"]
            if m["queries"]:
                q, qt, qc = m["queries"][0]
                if netbios:
                    q = P.decode_netbios_name(q)
                d["query"], d["qtype"], d["qclass"] = q, qt, qc
                d["qtype_name"] = ZT.DNS_QTYPES.get(qt, f"query-{qt}")
                d["qclass_name"] = ZT.DNS_CLASSES.get(qc, f"qclass-{qc}")
            d["_sq"] = True
        else:
            for name, rtype, ttl, reply in m["answers"]:
                if d["query"] is None:
                    d["query"] = P.decode_netbios_name(name) if netbios else name
                d["AA"], d["RA"] = m["AA"], m["RA"]
                if d["rtt"] is None:
                    rtt = self.now - d["ts"]
                    d["rtt"] = rtt if rtt > 0 else None
                    if rtt <= 0:
                        d["rtt"] = None
                if reply:
                    d["answers"] = (d["answers"] or []) + [reply]
                    d["TTLs"] = (d["TTLs"] or []) + [float(ttl)]
            if m["TC"]:
                d["TC"] = True
            d["_sr"] = True
            if m["rcode"] == 3:
                c.extra["nxdomain"] = c.extra.get("nxdomain", 0) + 1
        if d["_sq"] and d["_sr"]:
            self.log("dns", d)
            d["_sq"] = d["_sr"] = False
            d["_logged"] = True

    def _dns_finish(self, c: Conn):
        st = c.dns_state
        if not st:
            return
        left = []
        if st["pq"] is not None:
            left.append(st["pq"])
        for q in list(st["pqs"].values()) + list(st["prs"].values()):
            left.extend(q)
        for d in left:
            if not d.get("_logged"):
                self.log("dns", d)

    # -- DHCP --------------------------------------------------------------------------------
    def dhcp_message(self, c: Conn, is_orig: bool, payload: bytes):
        m = P.parse_dhcp(payload)
        if m is None or m["type"] is None:
            return
        c.add_service("dhcp")
        self._dhcp_expire()
        info = self.dhcp_tx.get(m["xid"])
        if info is None:
            info = {"ts": self.now, "uids": [], "client_addr": None, "server_addr": None, "mac": None, "host_name": None,
                    "client_fqdn": None, "domain": None, "requested_addr": None, "assigned_addr": None, "lease_time": None,
                    "client_message": None, "server_message": None, "msg_types": [], "duration": 0.0, "_last": self.now,
                    "_chaddr": None, "_servers": set()}
            self.dhcp_tx[m["xid"]] = info
        info["duration"] = self.now - info["ts"]
        if c.uid not in info["uids"]:
            info["uids"].append(c.uid)
        info["msg_types"].append(ZT.DHCP_MSG_TYPES.get(m["type"], str(m["type"])))
        is_client = is_orig and (c.orig_h == "0.0.0.0" or c.orig_p == 68 or c.resp_p == 67)
        if m["message"]:
            info["client_message" if is_client else "server_message"] = m["message"]
        info["_last"] = self.now
        if is_client:
            if c.orig_h not in ("0.0.0.0", "255.255.255.255"):
                info["client_addr"] = c.orig_h
            if m["host_name"]:
                info["host_name"] = m["host_name"]
            if m["fqdn"]:
                info["client_fqdn"] = m["fqdn"]
            if m["client_id_mac"]:
                info["mac"] = m["client_id_mac"]
            else:
                info["_chaddr"] = m["chaddr"]
            if m["requested"]:
                info["requested_addr"] = m["requested"]
        else:
            if m["yiaddr"] != "0.0.0.0":
                info["server_addr"] = c.orig_h if is_orig else c.resp_h
            srv = m["server_id"] or (c.orig_h if is_orig else c.resp_h)
            if m["type"] in (2, 5):
                info["_servers"].add(srv)
                self._dhcp_servers(srv, c)
            if m["chaddr"] and not info["mac"]:
                info["mac"] = m["chaddr"]
            if m["yiaddr"] != "0.0.0.0":
                info["assigned_addr"] = m["yiaddr"]
            if not info["client_addr"] and info["assigned_addr"]:
                info["client_addr"] = info["assigned_addr"]
            if m["domain"]:
                info["domain"] = m["domain"]
            if m["lease"] is not None:
                info["lease_time"] = m["lease"]

    def _dhcp_servers(self, srv, c):
        s = self.dhcp_servers
        s.setdefault(srv, c)
        if len(s) > 1:
            names = ", ".join(sorted(s))
            self.notice("LinkTest::Multiple_DHCP_Servers", f"More than one DHCP server answered: {names}", None, sub=names,
                        severity="bad", key=("dhcp-servers", names), proto="udp",
                        plain=f"More than one device is handing out addresses on this network ({names}). Unless that is intended, "
                              f"one of them is a rogue DHCP server (often a home router plugged in the wrong way round), and devices "
                              f"that get their address from it lose connectivity.", flt={"log": "dhcp"})

    def _dhcp_write(self, info):
        if not info["mac"] and info["_chaddr"]:
            info["mac"] = info["_chaddr"]
        self.log("dhcp", info)

    def _dhcp_expire(self, force=False):
        for xid in list(self.dhcp_tx):
            info = self.dhcp_tx[xid]
            if force or self.now - info["_last"] > 5.0 or self.now - info["ts"] > 30.0:
                self._dhcp_write(info)
                del self.dhcp_tx[xid]

    # -- NTP ---------------------------------------------------------------------------------
    def ntp_message(self, c: Conn, is_orig: bool, payload: bytes):
        m = P.parse_ntp(payload)
        if m is None:
            return
        if is_orig and m["mode"] == 4 and c.resp_pkts == 0 and c.orig_pkts == 1:
            c.flip()  # the server's reply was seen first
        c.add_service("ntp")
        rec = c.id_fields()
        rec["ts"] = self.now
        for f, _t in SCHEMAS["ntp"][6:]:
            rec[f] = m.get(f)
        self.log("ntp", rec)

    # -- packets -------------------------------------------------------------------------------
    def run(self, path: str) -> Result:
        t0 = time.time()
        size = os.path.getsize(path)
        rd = PcapReader(path)
        if not self.seed:
            with open(path, "rb") as f:
                head = f.read(4096)
            self.seed = hashlib.sha1(head + str(size).encode()).hexdigest()
        n = 0
        for ts, data, lt, wire in rd.iter_packets():
            n += 1
            self.now = ts if ts > self.now or self.first_ts is None else self.now
            if self.first_ts is None:
                self.first_ts = ts
            self.pkts += 1
            self.bytes += wire
            try:
                self._packet(ts, data, lt)
            except (IndexError, struct.error, ValueError) as e:
                self.weird("LinkTest_decode_error", None, type(e).__name__)
            if n % 2000 == 0:
                if self.cancel is not None and self.cancel():
                    raise Cancelled()
                if self.progress:
                    self.progress(min(0.99, rd.pos / max(1, size)), n)
                if self.now - self.last_sweep > 30:
                    self._sweep()
        self.last_ts = self.now
        for c in list(self.conns.values()):
            self._finalize(c)
        self.conns.clear()
        self._dhcp_expire(force=True)
        self._post()
        for k in self.logs:
            self.logs[k].sort(key=lambda r: r.get("ts") or 0)
        meta = {"source": os.path.basename(path), "packets": self.pkts, "bytes": self.bytes, "first": self.first_ts, "last": self.last_ts,
                "seconds": round(time.time() - t0, 2), "analysed": time.time(), "non_ip": self.non_ip}
        res = Result(self.logs, meta, {})
        res._summary = build_summary(res)
        return res

    def _packet(self, ts, data, lt):
        dec = link_decap(data, lt)
        if dec is None:
            self.non_ip += 1
            return
        et, off, smac, dmac, vlans = dec
        if et == 0x0800:
            self._ipv4(data, off, smac, dmac, vlans)
        elif et == 0x86DD:
            self._ipv6(data, off, smac, dmac, vlans)
        elif et == 0x0806:
            self._arp(data, off)
        else:
            self.non_ip += 1

    def _arp(self, d, off):
        if len(d) < off + 28:
            return
        op = (d[off + 6] << 8) | d[off + 7]
        smac, sip = d[off + 8:off + 14], d[off + 14:off + 18]
        if sip == b"\x00\x00\x00\x00" or op not in (1, 2):
            return
        ip = P.ip4(sip)
        macs = self.arp.setdefault(ip, {})
        macs.setdefault(P.mac(smac), self.now)

    def _ipv4(self, d, off, smac, dmac, vlans):
        if len(d) < off + 20:
            self.weird("truncated_IP", None)
            return
        b0 = d[off]
        ihl = (b0 & 0x0F) * 4
        if b0 >> 4 != 4 or ihl < 20:
            self.weird("bad_IP_header_len" if b0 >> 4 == 4 else "unknown_protocol", None)
            return
        total = (d[off + 2] << 8) | d[off + 3]
        if total < ihl:
            self.weird("bad_IP_length", None)
            return
        fr = (d[off + 6] << 8) | d[off + 7]
        proto = d[off + 9]
        src, dst = d[off + 12:off + 16], d[off + 16:off + 20]
        l4 = d[off + ihl:off + total]
        l4_len = total - ihl
        if fr & 0x3FFF:
            ident = (d[off + 4] << 8) | d[off + 5]
            full = self._defrag((4, src, dst, ident, proto), (fr & 0x1FFF) * 8, bool(fr & 0x2000), l4 if len(l4) == l4_len else None)
            if full is None:
                return
            l4, l4_len = full, len(full)
            total = ihl + l4_len
        self._l4(proto, src, dst, l4, l4_len, total, smac, dmac, vlans, d[off + 8])

    def _ipv6(self, d, off, smac, dmac, vlans):
        if len(d) < off + 40:
            self.weird("truncated_IPv6", None)
            return
        plen = (d[off + 4] << 8) | d[off + 5]
        nh = d[off + 6]
        src, dst = d[off + 8:off + 24], d[off + 24:off + 40]
        p = off + 40
        end = off + 40 + plen
        frag = None
        for _ in range(8):
            if nh in (0, 43, 60, 135) and len(d) >= p + 8:
                nh, p = d[p], p + (d[p + 1] + 1) * 8
            elif nh == 51 and len(d) >= p + 8:
                nh, p = d[p], p + (d[p + 1] + 2) * 4
            elif nh == 44 and len(d) >= p + 8:
                fo = struct.unpack_from("!H", d, p + 2)[0]
                ident = struct.unpack_from("!I", d, p + 4)[0]
                frag = ((fo >> 3) * 8, bool(fo & 1), ident)
                nh, p = d[p], p + 8
            else:
                break
        l4 = d[p:end]
        l4_len = end - p
        if frag and (frag[0] or frag[1]):
            full = self._defrag((6, src, dst, frag[2], nh), frag[0], frag[1], l4 if len(l4) == l4_len else None)
            if full is None:
                return
            l4, l4_len = full, len(full)
        self._l4(nh, src, dst, l4, l4_len, 40 + plen, smac, dmac, vlans, d[off + 7])

    def _defrag(self, key, foff, mf, data):
        e = self.frags.get(key)
        if e is None:
            if len(self.frags) > 5000:
                self.frags.clear()
            e = self.frags[key] = {"parts": {}, "total": None, "ts": self.now, "bad": False}
        if data is None:
            e["bad"] = True
            return None
        e["parts"][foff] = data
        if not mf:
            e["total"] = foff + len(data)
        if e["total"] is None:
            return None
        buf = bytearray()
        for o in sorted(e["parts"]):
            if o > len(buf):
                return None
            buf[o:o + len(e["parts"][o])] = e["parts"][o]
        if len(buf) < e["total"]:
            return None
        del self.frags[key]
        if e["bad"]:
            return None
        return bytes(buf[:e["total"]])

    # -- connections -----------------------------------------------------------------------------
    def _l4(self, proto, src, dst, l4, l4_len, ip_len, smac, dmac, vlans, ttl):
        if proto == 6:
            if len(l4) < 20:
                self.weird("truncated_header", None, "TCP")
                return
            sp = (l4[0] << 8) | l4[1]
            dp = (l4[2] << 8) | l4[3]
            key = (6, src, sp, dst, dp) if (src, sp) < (dst, dp) else (6, dst, dp, src, sp)
            c = self.conns.get(key)
            flags = l4[13]
            if c is not None:
                if self._tcp_expired(c, flags, l4):
                    self._finalize(c)
                    del self.conns[key]
                    c = None
            if c is None:
                c = self._new_conn(key, "tcp", 6, src, sp, dst, dp, smac, dmac, vlans, flags=flags)
            is_orig = src == c.orig_raw and sp == c.orig_p
            self._count(c, is_orig, ip_len)
            self._tcp(c, is_orig, l4, l4_len)
        elif proto == 17:
            if len(l4) < 8:
                self.weird("truncated_header", None, "UDP")
                return
            sp = (l4[0] << 8) | l4[1]
            dp = (l4[2] << 8) | l4[3]
            key = (17, src, sp, dst, dp) if (src, sp) < (dst, dp) else (17, dst, dp, src, sp)
            c = self.conns.get(key)
            if c is not None and self.now - c.last > UDP_TIMEOUT:
                self._finalize(c)
                del self.conns[key]
                c = None
            if c is None:
                c = self._new_conn(key, "udp", 17, src, sp, dst, dp, smac, dmac, vlans)
            is_orig = src == c.orig_raw and sp == c.orig_p
            self._count(c, is_orig, ip_len)
            ulen = (l4[4] << 8) | l4[5]
            plen = max(0, min(ulen, l4_len) - 8)
            payload = l4[8:8 + plen]
            if is_orig:
                c.orig_bytes += plen
                c.udp_o = True
            else:
                c.resp_bytes += plen
                c.udp_r = True
            if plen:
                self._hist_check(c, is_orig, H_DATA, "D")
            if len(payload) == plen and plen:
                self._udp_app(c, is_orig, payload, sp, dp)
        elif proto in (1, 58):
            if len(l4) < 4:
                return
            t, code = l4[0], l4[1]
            pairs = ICMP4_PAIRS if proto == 1 else ICMP6_PAIRS
            rev = {v: k for k, v in pairs.items()}
            if t in pairs:
                a, b, sp, dp = src, dst, t, pairs[t]
            elif t in rev:
                a, b, sp, dp = dst, src, rev[t], t
            else:
                a, b, sp, dp = src, dst, t, code
            key = (proto, a, sp, b, dp) if (a, sp) < (b, dp) else (proto, b, dp, a, sp)
            if t not in pairs and t not in rev:
                key = (proto, src, t, dst, code, "oneway")
            c = self.conns.get(key)
            if c is not None and self.now - c.last > ICMP_TIMEOUT:
                self._finalize(c)
                del self.conns[key]
                c = None
            if c is None:
                c = self._new_conn(key, "icmp", proto, a, sp, b, dp, smac if a == src else dmac, dmac if a == src else smac, vlans)
            is_orig = src == c.orig_raw
            self._count(c, is_orig, ip_len)
            n = max(0, l4_len - 8)
            if is_orig:
                c.orig_bytes += n
            else:
                c.resp_bytes += n
            if proto == 1 and t == 11:
                self.traceroute.setdefault(P.ip4(dst), set()).add(P.ip4(src))
        else:
            key = (proto, src, 0, dst, 0) if src < dst else (proto, dst, 0, src, 0)
            c = self.conns.get(key)
            if c is not None and self.now - c.last > UDP_TIMEOUT:
                self._finalize(c)
                del self.conns[key]
                c = None
            if c is None:
                c = self._new_conn(key, "unknown_transport", proto, src, 0, dst, 0, smac, dmac, vlans)
            is_orig = src == c.orig_raw
            self._count(c, is_orig, ip_len)
            if is_orig:
                c.orig_bytes += l4_len
            else:
                c.resp_bytes += l4_len

    def _count(self, c, is_orig, ip_len):
        if is_orig:
            c.orig_pkts += 1
            c.orig_ip_bytes += ip_len
        else:
            c.resp_pkts += 1
            c.resp_ip_bytes += ip_len
        if c.o is None or not (c.o.did_close and c.r.did_close):
            c.last = self.now
        c.extra["seen"] = self.now

    def _new_conn(self, key, proto, ip_proto, src, sp, dst, dp, smac, dmac, vlans, flags=None) -> Conn:
        c = Conn()
        c.uid = self.new_uid("C")
        c.key = key
        c.proto = proto
        c.ip_proto = ip_proto
        c.orig_raw = src
        c.orig_h, c.orig_p, c.resp_h, c.resp_p = P.ipstr(src), sp, P.ipstr(dst), dp
        c.start = c.last = self.now
        c.orig_l2 = P.mac(smac) if smac else None
        c.resp_l2 = P.mac(dmac) if dmac else None
        c.vlan = vlans[0] if vlans else None
        c.inner_vlan = vlans[1] if len(vlans) > 1 else None
        c.local_orig = self.is_local(c.orig_h)
        c.local_resp = self.is_local(c.resp_h)
        if proto == "tcp":
            c.o, c.r = _Ep(True), _Ep(False)
            flip = False
            if not (flags & F_SYN) or (flags & F_ACK):
                if sp in LIKELY_TCP:
                    flip = (not (flags & F_SYN) and sp < dp) if dp in LIKELY_TCP else True
            if flip:
                c.flip()
            ftp = self.ftp_expect.pop((c.resp_h, c.resp_p), None)
            if ftp is not None:
                c.apps.append(FtpDataApp(self, c))
                c.dpd_done = True
        elif proto == "udp":
            if sp in LIKELY_UDP and dp not in LIKELY_UDP and not _is_in(_MULTICAST, c.resp_h) and not c.resp_h.endswith(".255"):
                c.flip()
        self.conns[key] = c
        return c

    def _tcp_expired(self, c: Conn, flags, l4) -> bool:
        if self.now - c.last > TCP_TIMEOUT:
            return True
        o, r = c.o, c.r
        if o.state in (TCP_SYN_SENT, TCP_SYN_ACK_SENT) and r.state == TCP_INACTIVE and self.now - c.start > ATTEMPT_DELAY:
            return True  # Zeek's tcp_attempt_delay: an unanswered attempt is dropped after 5 s
        closed = (o.state in (TCP_CLOSED, TCP_RESET) and r.state in (TCP_CLOSED, TCP_RESET, TCP_INACTIVE)) or \
                 (r.state == TCP_RESET) or (o.state == TCP_RESET)
        if closed and c.close_time is not None and self.now - c.close_time > CLOSE_DELAY:
            return True
        if flags & F_SYN and not flags & F_ACK:
            seq = struct.unpack_from("!I", l4, 4)[0]
            if (seq - (o.start - (1 << 32))) & M32 == 0 or o.state == TCP_INACTIVE:
                return False
            if o.state == TCP_SYN_SENT:
                self.weird("SYN_seq_jump", c)
            elif not closed:
                self.weird("active_connection_reuse", c)
            return True
        return False

    def _hist_check(self, c: Conn, is_orig: bool, mask: int, code: str) -> bool:
        if code in "AD" and len(c.hist) == 1 and c.hist[0] == "H":
            c.flip()
            c.hist = ["^", "h"]
            is_orig = not is_orig
        if not is_orig:
            mask <<= 16
            code = code.lower()
        if not c.hist_seen & mask:
            c.hist_seen |= mask
            c.hist.append(code)
            return False
        return True

    def _hist_add(self, c: Conn, is_orig: bool, code: str):
        c.hist.append(code if is_orig else code.lower())

    def _scaled(self, c: Conn, ep: _Ep, code: str, which: str):
        cnt = getattr(ep, which + "_cnt") + 1
        thr = getattr(ep, which + "_thr")
        if cnt == thr:
            self._hist_add(c, ep.is_orig, code)
            setattr(ep, which + "_thr", thr * 10)
        setattr(ep, which + "_cnt", cnt)

    def _tcp(self, c: Conn, is_orig: bool, l4: bytes, l4_len: int):
        seq, ack = struct.unpack_from("!II", l4, 4)
        doff = (l4[12] >> 4) * 4
        flags = l4[13]
        win = (l4[14] << 8) | l4[15]
        if doff < 20:
            self.weird("bad_TCP_header_len", c)
            return
        dlen = max(0, l4_len - doff)
        payload = l4[doff:doff + dlen]
        SYN, FIN, RST, ACK = flags & F_SYN, flags & F_FIN, flags & F_RST, flags & F_ACK
        ep = c.o if is_orig else c.r
        peer = c.r if is_orig else c.o
        seg_len = dlen + (1 if SYN else 0) + (1 if FIN else 0)
        past = (seq + seg_len) & M32
        # init_endpoint
        st = ep.state
        if st == TCP_INACTIVE:
            if SYN:
                ep.init(seq, 0, past)
            else:
                ep.init(seq, -1, seq)
        elif st in (TCP_SYN_SENT, TCP_SYN_ACK_SENT):
            if SYN and ep.to_abs(seq) != ep.start:
                self.weird("SYN_seq_jump", c)
                ep.init(seq, 0, past)
        elif st in (TCP_ESTABLISHED, TCP_PARTIAL):
            if SYN:
                if ep.size(peer) > 0:
                    self.weird("SYN_inside_connection", c)
                if ep.to_abs(seq) != ep.start:
                    self.weird("SYN_seq_jump", c)
                ep.init(seq, 0, past)
        elif st == TCP_RESET and SYN and ep.prev_state == TCP_INACTIVE:
            ep.init(seq, 0, past)
        rel_seq = ep.to_abs(seq) - ep.start
        underflow = rel_seq < 0
        if underflow and not RST:
            self.weird("TCP_seq_underflow_or_misorder", c)
        # history
        bits = (1 if SYN else 0) + (1 if FIN else 0) + (1 if RST else 0)
        if bits > 1:
            if FIN and RST:
                self._hist_check(c, ep.is_orig, H_FINRST, "I")
            else:
                self._hist_check(c, ep.is_orig, H_MULTI, "Q")
        elif bits == 1:
            if SYN:
                code = "H" if ACK else "S"
                if self._hist_check(c, ep.is_orig, H_SYN, code) and rel_seq != ep.hl_syn:
                    self._hist_add(c, ep.is_orig, code)
                ep.hl_syn = rel_seq
            if FIN:
                if self._hist_check(c, ep.is_orig, H_FIN, "F") and rel_seq + dlen != ep.hl_fin:
                    self._hist_add(c, ep.is_orig, "F")
                ep.hl_fin = rel_seq + dlen
            if RST:
                if self._hist_check(c, ep.is_orig, H_RST, "R") and rel_seq != ep.hl_rst:
                    self._hist_add(c, ep.is_orig, "R")
                ep.hl_rst = rel_seq
        else:
            if dlen:
                self._hist_check(c, ep.is_orig, H_DATA, "D")
            elif ACK:
                self._hist_check(c, ep.is_orig, H_ACK, "A")
        # _hist_check may have flipped the connection
        is_orig = ep.is_orig
        if win == 0 and not RST and peer.state != TCP_CLOSED and ep.state != TCP_RESET:
            self._scaled(c, ep, "W", "w0")
            c.extra["zero_win"] = c.extra.get("zero_win", 0) + 1
        if SYN:
            if dlen:
                self.weird("SYN_with_data", c)
            if flags & (F_FIN | F_RST | F_URG | F_PSH) == (F_FIN | F_RST | F_URG | F_PSH):
                self.weird("TCP_christmas", c)
        if FIN:
            ep.fin_cnt += 1
            ep.fin_rel = rel_seq + seg_len
        if RST:
            ep.rst_cnt += 1
        rel_ack = 0
        if ACK:
            if peer.state == TCP_INACTIVE:
                rel_ack = 1
                if not SYN and not FIN and not RST and ep.state in (TCP_SYN_SENT, TCP_SYN_ACK_SENT, TCP_ESTABLISHED):
                    self.weird("possible_split_routing", c)
                a1 = (ack - 1) & M32
                peer.init(a1, 0, a1)
            else:
                a = peer.to_abs(ack)
                rel_ack = a - peer.start
                if rel_ack < 0:
                    rel_ack = 0
                    self.weird("TCP_ack_underflow_or_misorder", c)
                elif not RST:
                    if a > peer.ack and not (ack == 0 and a - peer.ack > TOO_LARGE):
                        peer.ack = a
                        peer.advance(a, ack)
        # update_last_seq
        a_past = ep.to_abs(past)
        delta_last = a_past - ep.last
        if (SYN or RST) and (delta_last > TOO_LARGE or delta_last < -TOO_LARGE):
            pass
        elif FIN and ep.last == ep.start + 1:
            ep.last = a_past
            ep.advance(a_past, past)
        elif ep.state == TCP_RESET:
            pass
        elif delta_last > 0:
            ep.last = a_past
            ep.advance(a_past, past)
        elif dlen > 0:
            self._scaled(c, ep, "T", "rx")
            ep.rx_pkts += 1
        if dlen:
            ep.data_pkts += 1
        self._state_machine(c, ep, peer, is_orig, flags, dlen, delta_last)
        if ACK and not FIN and not RST:
            self._ack_received(c, peer, rel_ack)
        rel_data = rel_seq + 1 if SYN else rel_seq
        if dlen > 0 and len(payload) == dlen and not RST and not underflow:
            self._seg(c, ep, rel_data, payload)

    def _state_machine(self, c, ep: _Ep, peer: _Ep, is_orig, flags, dlen, delta_last):
        SYN, FIN, RST, ACK = flags & F_SYN, flags & F_FIN, flags & F_RST, flags & F_ACK
        st = ep.state
        closed_before = self._is_closed(c)
        if st == TCP_INACTIVE:
            if SYN:
                if is_orig:
                    if ACK:
                        self.weird("connection_originator_SYN_ack", c)
                        ep.set_state(TCP_SYN_ACK_SENT)
                    else:
                        ep.set_state(TCP_SYN_SENT)
                else:
                    if not ACK:
                        self.weird("simultaneous_open", c)
                    if peer.state == TCP_SYN_SENT:
                        peer.set_state(TCP_ESTABLISHED)
                    elif peer.state == TCP_INACTIVE:
                        self.weird("unsolicited_SYN_response", c)
                    ep.set_state(TCP_ESTABLISHED)
            if FIN:
                ep.set_state(TCP_CLOSED)
                ep.did_close = True
                if peer.state != TCP_PARTIAL and not SYN:
                    self.weird("spontaneous_FIN", c)
            if RST:
                ep.set_state(TCP_RESET)
                ep.did_close = True
                is_reject = (peer.state == TCP_ESTABLISHED) if is_orig else peer.state in (TCP_SYN_SENT, TCP_SYN_ACK_SENT)
                if not is_reject and peer.state == TCP_INACTIVE:
                    self.weird("spontaneous_RST", c)
            if ep.state == TCP_INACTIVE:
                if not is_orig and dlen == 0 and c.o.state == TCP_SYN_SENT:
                    pass
                elif ACK and peer.state == TCP_ESTABLISHED:
                    ep.set_state(TCP_ESTABLISHED)
                else:
                    ep.set_state(TCP_PARTIAL)
        elif st in (TCP_SYN_SENT, TCP_SYN_ACK_SENT):
            if SYN:
                if is_orig and ACK and not FIN and not RST and st != TCP_SYN_ACK_SENT:
                    self.weird("repeated_SYN_with_ack", c)
                elif not is_orig and not ACK and st != TCP_SYN_SENT:
                    self.weird("repeated_SYN_reply_wo_ack", c)
            if FIN:
                if peer.state in (TCP_INACTIVE, TCP_SYN_SENT):
                    self.weird("inappropriate_FIN", c)
                ep.set_state(TCP_CLOSED)
                ep.did_close = True
            if RST:
                ep.set_state(TCP_RESET)
                ep.did_close = True
            elif dlen > 0:
                self.weird("data_before_established", c)
        elif st in (TCP_ESTABLISHED, TCP_PARTIAL):
            if SYN and st == TCP_PARTIAL and peer.state == TCP_INACTIVE and not ACK:
                self.weird("SYN_after_partial", c)
                ep.set_state(TCP_SYN_SENT)
            if FIN and not RST:
                ep.set_state(TCP_CLOSED)
                ep.did_close = True
                if peer.state == TCP_RESET and peer.prev_state == TCP_CLOSED:
                    peer.set_state(TCP_CLOSED)
            if RST:
                ep.set_state(TCP_RESET)
                ep.did_close = True
        elif st == TCP_CLOSED:
            if SYN:
                self.weird("SYN_after_close", c)
            if FIN and delta_last > 0:
                self.weird("FIN_advanced_last_seq", c)
            if RST and peer.state != TCP_CLOSED:
                ep.set_state(TCP_RESET)
                ep.did_close = True
        elif st == TCP_RESET:
            if SYN:
                self.weird("SYN_after_reset", c)
            if FIN:
                self.weird("FIN_after_reset", c)
            if dlen > 0 and not RST:
                self.weird("data_after_reset", c)
        if not closed_before and self._is_closed(c):
            c.close_time = self.now

    @staticmethod
    def _is_closed(c: Conn) -> bool:
        o, r = c.o.state, c.r.state
        return (o in (TCP_CLOSED, TCP_RESET) and r in (TCP_CLOSED, TCP_RESET)) or o == TCP_RESET or r == TCP_RESET

    # -- reassembly ------------------------------------------------------------------------------
    def _seg(self, c: Conn, ep: _Ep, rel: int, payload: bytes):
        end = rel + len(payload)
        if end <= ep.next:
            return
        if rel <= ep.next:
            if ep.want:
                self._deliver(c, ep, payload[ep.next - rel:] if rel < ep.next else payload)
            ep.next = end
            if ep.heap:
                self._drain(c, ep)
        else:
            if len(ep.pending) >= 2048:
                self._skip_hole(c, ep, ep.heap[0], history=True)
                return self._seg(c, ep, rel, payload)
            prev = ep.pending.get(rel)
            if prev is None:
                heapq.heappush(ep.heap, rel)
                ep.pending[rel] = (end, payload if ep.want else None)
            elif prev[0] < end:
                ep.pending[rel] = (end, payload if ep.want else None)

    def _drain(self, c: Conn, ep: _Ep):
        while ep.heap and ep.heap[0] <= ep.next:
            s = heapq.heappop(ep.heap)
            e, d = ep.pending.pop(s)
            if e > ep.next:
                if ep.want and d is not None:
                    self._deliver(c, ep, d[ep.next - s:])
                ep.next = e

    def _skip_hole(self, c: Conn, ep: _Ep, upto: int, history: bool):
        n = upto - ep.next
        if n <= 0:
            return
        ep.missed += n
        if history:
            self._scaled(c, ep, "G", "g")
        if ep.want:
            for a in c.apps:
                if a.active:
                    a.gap(ep.is_orig, n)
        ep.next = upto
        self._drain(c, ep)

    def _ack_received(self, c: Conn, ep: _Ep, rel_ack: int):
        if rel_ack <= ep.next:
            return
        limit = rel_ack
        if ep.fin_rel is not None:
            limit = min(limit, ep.fin_rel - 1 if ep.fin_rel - 1 >= ep.next else limit)
        if ep.heap:
            limit = min(limit, ep.heap[0])
        if limit > ep.next:
            self._skip_hole(c, ep, limit, history=True)

    def _deliver(self, c: Conn, ep: _Ep, b: bytes):
        is_orig = ep.is_orig
        if not c.dpd_done:
            self._dpd(c, is_orig, b)
        else:
            for a in c.apps:
                if a.active:
                    a.data(is_orig, b)
        if c.dpd_done and not any(a.active for a in c.apps):
            c.o.want = c.r.want = False

    def _dpd(self, c: Conn, is_orig: bool, b: bytes):
        c.dpd_chunks.append((is_orig, b))
        c.dpd_bytes += len(b)
        app = self._detect(c)
        if app is None:
            sides = {o for o, _ in c.dpd_chunks}
            if len(sides) == 2 or c.dpd_bytes > 4096 or len(c.dpd_chunks) >= 4:
                c.dpd_done = True
                c.dpd_chunks = []
            return
        c.apps.append(app)
        c.dpd_done = True
        chunks, c.dpd_chunks = c.dpd_chunks, []
        for o, d in chunks:
            if app.active:
                app.data(o, d)

    def _detect(self, c: Conn):
        rp, op = c.resp_p, c.orig_p
        first_o = b"".join(d for o, d in c.dpd_chunks if o)[:2048]
        first_r = b"".join(d for o, d in c.dpd_chunks if not o)[:2048]
        if first_o.startswith(b"SSH-") or first_r.startswith(b"SSH-"):
            return SshApp(self, c)
        for data in (first_o, first_r):
            if len(data) >= 6 and data[0] == 0x16 and data[1] == 3 and data[2] <= 4 and data[5] in (1, 2):
                return TlsApp(self, c)
        if len(first_o) >= 3 and first_o[0] & 0x80 and first_o[2] == 1 and rp in (443, 993, 995, 465, 636, 8443):
            return TlsApp(self, c)
        if first_o and HTTP_SIG_RE.match(first_o):
            return HttpApp(self, c)
        if first_r.startswith((b"HTTP/1.", b"HTTP/0.9")) and not first_o:
            return HttpApp(self, c)
        if rp in (21, 2811):
            return FtpApp(self, c)
        if rp == 53:
            return DnsTcpApp(self, c)
        if rp in (25, 587) or (first_r.startswith(b"220") and b"SMTP" in first_r[:200].upper()):
            return MailApp(self, c, "smtp")
        if rp == 110 or first_r.startswith(b"+OK"):
            return MailApp(self, c, "pop3")
        if rp == 143 or first_r.startswith(b"* OK"):
            return MailApp(self, c, "imap")
        if first_r.startswith(b"220") and b"FTP" in first_r[:200].upper():
            return FtpApp(self, c)
        return None

    def _udp_app(self, c: Conn, is_orig: bool, payload: bytes, sp: int, dp: int):
        ports = (c.orig_p, c.resp_p)
        if 53 in ports or 5353 in ports or 5355 in ports or 137 in ports:
            self.dns_message(c, is_orig, payload, "udp")
        elif 67 in ports or 68 in ports or 4011 in ports:
            self.dhcp_message(c, is_orig, payload)
        elif 123 in ports:
            self.ntp_message(c, is_orig, payload)
        elif "quic" in c.extra or 443 in ports or (payload[0] & 0xC0 == 0xC0 and len(payload) >= 1200 and c.orig_pkts + c.resp_pkts <= 2):
            q = c.extra.get("quic")
            if q is None:
                if not payload[0] & 0x80:
                    return
                q = c.extra["quic"] = QuicState(self, c)
            q.datagram(is_orig, payload)

    # -- finishing ------------------------------------------------------------------------------
    def _sweep(self):
        self.last_sweep = self.now
        dead = []
        for k, c in self.conns.items():
            idle = self.now - c.last
            if c.proto == "tcp":
                if c.o.state in (TCP_SYN_SENT, TCP_SYN_ACK_SENT) and c.r.state == TCP_INACTIVE and self.now - c.start > ATTEMPT_DELAY:
                    dead.append(k)
                elif idle > TCP_TIMEOUT or (c.close_time is not None and self._is_closed(c) and self.now - c.close_time > CLOSE_DELAY + 30):
                    dead.append(k)
            elif idle > UDP_TIMEOUT:
                dead.append(k)
        for k in dead:
            self._finalize(self.conns.pop(k))
        for k in [k for k, e in self.frags.items() if self.now - e["ts"] > 60]:
            del self.frags[k]
        self._dhcp_expire()

    def _finalize(self, c: Conn):
        if c.proto == "tcp":
            for ep in (c.o, c.r):
                while ep.heap:
                    s = ep.heap[0]
                    if s > ep.next:
                        self._skip_hole(c, ep, s, history=False)
                    else:
                        self._drain(c, ep)
        for a in c.apps:
            try:
                a.finish()
            except (IndexError, ValueError, struct.error, KeyError):
                pass
        q = c.extra.get("quic")
        if q:
            q.finish()
        self._dns_finish(c)
        dur = c.last - c.start
        if c.proto == "tcp":
            osz, rsz = c.o.size(c.r), c.r.size(c.o)
            state = self._conn_state_tcp(c, osz, rsz)
            missed = c.o.missed + c.r.missed
        else:
            osz, rsz = c.orig_bytes, c.resp_bytes
            if c.proto == "udp":
                state = ("SF" if c.udp_r else "S0") if c.udp_o else ("SHR" if c.udp_r else "OTH")
            else:
                state = "OTH"
            missed = 0
        rec = c.id_fields()
        rec.update(ts=c.start, proto="icmp" if c.proto == "icmp" else c.proto, service=",".join(c.service) or None,
                   duration=dur if dur > 0 else None, orig_bytes=osz if dur > 0 else None, resp_bytes=rsz if dur > 0 else None,
                   conn_state=state, local_orig=c.local_orig, local_resp=c.local_resp, missed_bytes=missed,
                   history="".join(c.hist) or None, orig_pkts=c.orig_pkts, orig_ip_bytes=c.orig_ip_bytes, resp_pkts=c.resp_pkts,
                   resp_ip_bytes=c.resp_ip_bytes, tunnel_parents=None, ip_proto=c.ip_proto, orig_l2_addr=c.orig_l2,
                   resp_l2_addr=c.resp_l2, vlan=c.vlan, inner_vlan=c.inner_vlan, community_id=self._community_id(c),
                   _rx=(c.o.rx_pkts + c.r.rx_pkts) if c.proto == "tcp" else 0,
                   _dp=(c.o.data_pkts + c.r.data_pkts) if c.proto == "tcp" else 0, _zw=c.extra.get("zero_win", 0),
                   _nx=c.extra.get("nxdomain", 0), _last=c.last)
        self.log("conn", rec)

    @staticmethod
    def _conn_state_tcp(c: Conn, osz: int, rsz: int) -> str:
        os_, rs = c.o.state, c.r.state
        o_in = os_ in (TCP_INACTIVE, TCP_PARTIAL)
        r_in = rs in (TCP_INACTIVE, TCP_PARTIAL)
        if rs == TCP_RESET:
            if os_ in (TCP_SYN_SENT, TCP_SYN_ACK_SENT) or (os_ == TCP_RESET and osz == 0 and rsz == 0):
                return "REJ"
            return "RSTRH" if o_in else "RSTR"
        if os_ == TCP_RESET:
            if r_in:
                if re.fullmatch(r"\^?S[^HAFGIQ]*R.*", "".join(c.hist)):
                    return "RSTOS0"
                return "OTH"
            return "RSTO"
        if rs == TCP_CLOSED and os_ == TCP_CLOSED:
            return "SF"
        if os_ == TCP_CLOSED:
            return "SH" if r_in else "S2"
        if rs == TCP_CLOSED:
            return "SHR" if o_in else "S3"
        if os_ == TCP_SYN_SENT and rs == TCP_INACTIVE:
            return "S0"
        if os_ == TCP_ESTABLISHED and rs == TCP_ESTABLISHED:
            return "S1"
        return "OTH"

    @staticmethod
    def _community_id(c: Conn) -> str | None:
        try:
            sip = ipaddress.ip_address(c.orig_h).packed
            dip = ipaddress.ip_address(c.resp_h).packed
        except ValueError:
            return None
        sp, dp = c.orig_p, c.resp_p
        proto = c.ip_proto
        one_way = False
        if c.proto == "icmp":
            pairs = ICMP4_PAIRS if proto == 1 else ICMP6_PAIRS
            one_way = sp not in pairs
            if one_way:
                dp = c.resp_p
        if proto not in (1, 6, 17, 58, 132):
            sp = dp = 0
        if not one_way and (sip, sp) > (dip, dp):
            sip, dip, sp, dp = dip, sip, dp, sp
        elif one_way and sip > dip:
            sip, dip = dip, sip
        data = struct.pack("!H", 0) + sip + dip + bytes([proto, 0])
        if proto in (1, 6, 17, 58, 132):
            data += struct.pack("!HH", sp, dp)
        return "1:" + base64.b64encode(hashlib.sha1(data).digest()).decode()

    # -- post-processing: known_*, ftp file links, notices ------------------------------------------
    def _post(self):
        conns = self.logs["conn"]
        # ftp data files
        for r in self.logs["ftp"]:
            dc = r.pop("_dc", None)
            if dc and dc in self.ftp_files:
                f = self.ftp_files[dc]
                r["fuid"] = f["fuid"]
                r["mime_type"] = f.get("mime_type")
                if r.get("file_size") is None:
                    r["file_size"] = f.get("seen_bytes")
        # known hosts / services
        kh, ks = {}, {}
        for r in conns:
            if r["proto"] == "tcp" and r["conn_state"] in ("SF", "S1", "S2", "S3", "RSTO", "RSTR") and "h" in (r["history"] or "").lower():
                for h, loc in ((r["id.orig_h"], r["local_orig"]), (r["id.resp_h"], r["local_resp"])):
                    if loc and h not in kh:
                        kh[h] = r["ts"]
                k = (r["id.resp_h"], r["id.resp_p"], "tcp")
                if r["local_resp"]:
                    e = ks.setdefault(k, {"ts": r["ts"], "service": []})
                    for s in (r["service"] or "").split(","):
                        if s and s.upper() not in e["service"]:
                            e["service"].append(s.upper())
            elif r["proto"] == "udp" and r["service"] and r["conn_state"] == "SF" and r["local_resp"]:
                k = (r["id.resp_h"], r["id.resp_p"], "udp")
                e = ks.setdefault(k, {"ts": r["ts"], "service": []})
                for s in r["service"].split(","):
                    if s.upper() not in e["service"]:
                        e["service"].append(s.upper())
        self.logs["known_hosts"] = [{"ts": t, "host": h} for h, t in kh.items()]
        self.logs["known_services"] = [{"ts": e["ts"], "host": k[0], "port_num": k[1], "port_proto": k[2], "service": e["service"]}
                                       for k, e in ks.items()]
        self._scan_notices(conns)
        self._health_notices(conns)

    def _scan_notices(self, conns):
        failed = [r for r in conns if r["proto"] == "tcp" and r["conn_state"] in ("S0", "REJ", "RSTOS0", "RSTRH", "SH", "OTH")
                  and not r.get("orig_bytes")]
        by_src_host = collections.defaultdict(set)
        by_src_port = collections.defaultdict(set)
        for r in failed:
            by_src_host[(r["id.orig_h"], r["id.resp_h"])].add(r["id.resp_p"])
            by_src_port[(r["id.orig_h"], r["id.resp_p"])].add(r["id.resp_h"])
        for (src, dst), ports in by_src_host.items():
            if len(ports) >= 15:
                first = min(r["ts"] for r in failed if r["id.orig_h"] == src and r["id.resp_h"] == dst)
                self.notice("Scan::Port_Scan", f"{src} scanned at least {len(ports)} unique ports of host {dst}", None,
                            sub="local" if self.is_local(src) else "remote", src=src, dst=dst, n=len(ports), severity="bad",
                            key=("portscan", src, dst), ts=first, proto="tcp", flt={"log": "conn", "q": src},
                            plain=f"{src} tried {len(ports)} different ports on {dst} without getting in. That is a port scan: "
                                  f"either a security tool (like LinkTest's own scanner) or something probing for weaknesses.")
        for (src, port), hosts in by_src_port.items():
            if len(hosts) >= 25:
                first = min(r["ts"] for r in failed if r["id.orig_h"] == src and r["id.resp_p"] == port)
                self.notice("Scan::Address_Scan", f"{src} scanned at least {len(hosts)} unique hosts on port {port}/tcp", None,
                            sub="local" if self.is_local(src) else "remote", src=src, p=port, n=len(hosts), severity="bad",
                            key=("addrscan", src, port), ts=first, proto="tcp", flt={"log": "conn", "q": src},
                            plain=f"{src} tried port {port} on {len(hosts)} different addresses. That is an address sweep, "
                                  f"typical of network discovery tools and of malware looking for other machines to infect.")
        for src, n in self.ssh_fail.items():
            if n >= 30:
                self.notice("SSH::Password_Guessing", f"{src} appears to be guessing SSH passwords (seen in {n} connections).", None,
                            src=src, n=n, severity="bad", key=("sshguess", src), proto="tcp", flt={"log": "ssh", "q": src},
                            plain=f"{src} failed to log in over SSH {n} times. That looks like password guessing.")
        for src, n in self.ftp_fail.items():
            if n >= 20:
                self.notice("FTP::Bruteforcing", f"{src} had {n} failed logins on FTP servers", None, src=src, n=n, severity="bad",
                            key=("ftpbrute", src), proto="tcp", flt={"log": "ftp", "q": src},
                            plain=f"{src} failed to log in to FTP {n} times, which looks like password guessing.")
        for host, routers in self.traceroute.items():
            if len(routers) >= 3:
                self.notice("Traceroute::Detected", f"{host} seems to be running traceroute using icmp", None, src=host,
                            n=len(routers), severity="info", key=("traceroute", host), proto="icmp", flt={"log": "conn", "q": host},
                            plain=f"{host} ran a traceroute: {len(routers)} routers along the path reported back. Normal when "
                                  f"someone is troubleshooting.")

    def _health_notices(self, conns):
        # connections that keep failing to the same place (troubleshooting view)
        fails = collections.defaultdict(list)
        for r in conns:
            if r["proto"] == "tcp" and r["conn_state"] in ("S0", "REJ", "RSTOS0", "SH"):
                fails[(r["id.orig_h"], r["id.resp_h"], r["id.resp_p"])].append(r)
        scanners = {k[1] for k in self.notice_seen if isinstance(k, tuple) and k and k[0] in ("portscan", "addrscan")}
        for (src, dst, port), rs in fails.items():
            if len(rs) < 3 or src in scanners:
                continue
            refused = sum(1 for r in rs if r["conn_state"] == "REJ")
            what = "was refused" if refused > len(rs) / 2 else "got no answer"
            self.notice("LinkTest::Repeated_Connection_Failures", f"{src} failed {len(rs)} times to connect to {dst}:{port}/tcp ({what})",
                        None, sub=what, src=src, dst=dst, p=port, n=len(rs), severity="warn", key=("fails", src, dst, port),
                        ts=rs[0]["ts"], proto="tcp", flt={"log": "conn", "q": dst},
                        plain=(f"{src} tried {len(rs)} times to reach {dst} on port {port}" +
                               (f" and {dst} refused every time: nothing is listening on that port, or a firewall rejects it."
                                if what == "was refused" else
                                f" and never got an answer: {dst} is off, unreachable, or a firewall silently drops the traffic.")))
        # retransmissions / zero windows (performance)
        for r in conns:
            if r["proto"] != "tcp":
                continue
            dp, rx = r.get("_dp", 0), r.get("_rx", 0)
            if dp >= 50 and rx >= 10 and rx / dp >= 0.03:
                pct = round(rx / dp * 100, 1)
                self.notice("LinkTest::Heavy_Retransmission", f"{pct}% of data packets were retransmitted between {r['id.orig_h']} and "
                            f"{r['id.resp_h']}:{r['id.resp_p']}", None, sub=f"{rx} of {dp}", src=r["id.orig_h"], dst=r["id.resp_h"],
                            p=r["id.resp_p"], n=rx, severity="warn" if pct < 10 else "bad", key=("rx", r["uid"]), ts=r["ts"],
                            proto="tcp", flt={"uid": r["uid"]},
                            plain=f"{pct}% of the data in this connection had to be sent twice. Packets are being lost on the way "
                                  f"(Wi-Fi interference, a bad cable, a congested link or an overloaded device), which slows it down.")
                self.logs["notice"][-1]["uid"] = r["uid"]
            if r.get("_zw", 0) >= 5:
                self.notice("LinkTest::Zero_Window", f"The receiver in {r['id.orig_h']} -> {r['id.resp_h']}:{r['id.resp_p']} ran out of "
                            f"buffer {r['_zw']} times", None, src=r["id.orig_h"], dst=r["id.resp_h"], p=r["id.resp_p"], n=r["_zw"],
                            severity="info", key=("zw", r["uid"]), ts=r["ts"], proto="tcp", flt={"uid": r["uid"]},
                            plain="One side told the other to pause because it could not keep up (a full receive buffer). The "
                                  "bottleneck is that device or program, not the network.")
                self.logs["notice"][-1]["uid"] = r["uid"]
        # DNS failures
        nx = collections.Counter()
        for d in self.logs["dns"]:
            if d.get("rcode") == 3:
                nx[d["id.orig_h"]] += 1
        for host, n in nx.items():
            if n >= 20:
                self.notice("LinkTest::Many_Failed_Lookups", f"{host} looked up {n} names that do not exist (NXDOMAIN)", None,
                            src=host, n=n, severity="warn", key=("nx", host), proto="udp", flt={"log": "dns", "q": "NXDOMAIN"},
                            plain=f"{host} asked for {n} names that do not exist. A few are normal; many can mean a mistyped "
                                  f"server name in a setting, a broken search domain, or malware generating random names.")
        servfail = sum(1 for d in self.logs["dns"] if d.get("rcode") == 2)
        if servfail >= 5:
            self.notice("LinkTest::DNS_Server_Failures", f"{servfail} DNS answers were SERVFAIL", None, n=servfail, severity="warn",
                        key=("servfail",), proto="udp", flt={"log": "dns", "q": "SERVFAIL"},
                        plain="The DNS server failed to answer several lookups (SERVFAIL). Name resolution is unreliable: check "
                              "the DNS server or its upstream connection.")
        unanswered = [d for d in self.logs["dns"] if d.get("rcode") is None and d.get("qtype") is not None and
                      not _is_in(_MULTICAST, d.get("id.resp_h") or "")]
        if len(unanswered) >= 5:
            srv = collections.Counter(d["id.resp_h"] for d in unanswered).most_common(1)[0][0]
            self.notice("LinkTest::DNS_No_Answer", f"{len(unanswered)} DNS queries got no answer (mostly to {srv})", None, dst=srv,
                        n=len(unanswered), severity="warn", key=("dnsnoanswer",), proto="udp", flt={"log": "dns", "q": srv},
                        plain=f"{len(unanswered)} name lookups never got a reply, most of them sent to {srv}. That DNS server is "
                              f"unreachable or overloaded, which makes everything feel slow or broken.")
        # ARP conflicts
        for ip, macs in self.arp.items():
            if len(macs) > 1:
                ms = ", ".join(sorted(macs))
                self.notice("LinkTest::ARP_Address_Conflict", f"{ip} is claimed by more than one hardware address: {ms}", None,
                            sub=ms, src=ip, severity="bad", key=("arp", ip), ts=min(macs.values()), proto=None,
                            plain=f"Two or more devices ({ms}) answered for {ip}. Either two devices were given the same address "
                                  f"(an IP conflict, which breaks both) or something is intercepting traffic (ARP spoofing).")
        # cleartext HTTP logins handled as they appear; weird volume
        # most talkative ports with no service
        if self.non_ip and self.pkts and self.non_ip / self.pkts > 0.5:
            pass


# ----------------------------------------------------------------------------
# Summary for the UI
# ----------------------------------------------------------------------------
def build_summary(res: Result) -> dict:
    logs = res.logs
    conns = logs["conn"]
    states = collections.Counter(r["conn_state"] for r in conns)
    svc_bytes: collections.Counter = collections.Counter()
    svc_conns: collections.Counter = collections.Counter()
    for r in conns:
        if r["service"]:
            s = r["service"].split(",")[0]
        elif r["proto"] in ("tcp", "udp"):
            s = f"{r['proto']}/{r['id.resp_p']}"
        else:
            s = r["proto"]
        svc_bytes[s] += (r["orig_ip_bytes"] or 0) + (r["resp_ip_bytes"] or 0)
        svc_conns[s] += 1
    queries = collections.Counter()
    nx = collections.Counter()
    for d in logs["dns"]:
        if d.get("query"):
            queries[d["query"]] += 1
            if d.get("rcode") == 3:
                nx[d["query"]] += 1
    sites: dict = {}
    by_uid = {r["uid"]: r for r in conns}

    def site(name, uid, how):
        if not name:
            return
        e = sites.setdefault(name.lower(), {"name": name, "conns": 0, "bytes": 0, "how": set()})
        e["conns"] += 1
        c = by_uid.get(uid)
        if c:
            e["bytes"] += (c["orig_ip_bytes"] or 0) + (c["resp_ip_bytes"] or 0)
        e["how"].add(how)
    for r in logs["ssl"]:
        site(r.get("server_name"), r["uid"], "HTTPS")
    for r in logs["quic"]:
        site(r.get("server_name"), r["uid"], "QUIC")
    for r in logs["http"]:
        h = (r.get("host") or "").split(":")[0]
        site(h, r["uid"], "HTTP")
    top_sites = sorted(sites.values(), key=lambda e: (-e["bytes"], -e["conns"]))[:15]
    for e in top_sites:
        e["how"] = sorted(e["how"])
    fails = collections.Counter()
    for r in conns:
        if r["proto"] == "tcp" and r["conn_state"] in ("S0", "REJ"):
            fails[(r["id.resp_h"], r["id.resp_p"], r["conn_state"])] += 1
    sev = collections.Counter(n.get("_severity", "warn") for n in logs["notice"])
    weirds = collections.Counter(w["name"] for w in logs["weird"])
    hosts = set()
    for r in conns:
        hosts.add(r["id.orig_h"])
        hosts.add(r["id.resp_h"])
    tcp = [r for r in conns if r["proto"] == "tcp"]
    return {
        "counts": {k: len(v) for k, v in logs.items()},
        "meta": res.meta,
        "hosts": len(hosts),
        "states": [{"state": s, "count": n, "text": CONN_STATE_TEXT.get(s, "")} for s, n in states.most_common()],
        "tcpTotal": len(tcp),
        "tcpOk": sum(1 for r in tcp if r["conn_state"] in ("SF", "S1", "S2", "S3", "RSTO", "RSTR")),
        "tcpFailed": sum(1 for r in tcp if r["conn_state"] in ("S0", "REJ", "RSTOS0", "SH")),
        "services": [{"service": s, "bytes": b, "conns": svc_conns[s]} for s, b in svc_bytes.most_common(12)],
        "queries": [{"name": q, "count": n, "nx": nx.get(q, 0)} for q, n in queries.most_common(12)],
        "nxdomain": sum(nx.values()),
        "sites": top_sites,
        "failures": [{"host": h, "port": p, "state": s, "count": n} for (h, p, s), n in fails.most_common(10)],
        "findings": {"bad": sev.get("bad", 0), "warn": sev.get("warn", 0), "info": sev.get("info", 0)},
        "weirds": [{"name": n, "count": c} for n, c in weirds.most_common(10)],
    }


# ----------------------------------------------------------------------------
# Command line: linktest.py --zeek-logs capture.pcap [--out DIR] [--json]
# ----------------------------------------------------------------------------
def cli_main(argv: list[str]) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="linktest --zeek-logs", description="Write Zeek-style logs for a capture file.")
    ap.add_argument("pcap")
    ap.add_argument("--out", default=None, help="folder for the .log files (default: <capture>-logs next to the file)")
    ap.add_argument("--json", action="store_true", help="JSON lines instead of Zeek TSV")
    ap.add_argument("--zip", default=None, help="write a .zip instead of a folder")
    ns = ap.parse_args(argv)
    t = time.time()
    last = [0.0]

    def prog(frac, n):
        if time.time() - last[0] > 1:
            last[0] = time.time()
            print(f"  {frac * 100:5.1f}%  {n:,} packets", flush=True)
    res = Analyzer(progress=prog).run(ns.pcap)
    fmt = "json" if ns.json else "zeek"
    if ns.zip:
        res.write_zip(ns.zip, fmt)
        print(f"Wrote {ns.zip}")
    else:
        out = ns.out or os.path.splitext(ns.pcap)[0] + "-logs"
        files = res.write_dir(out, fmt)
        print(f"Wrote {len(files)} logs to {out}")
    counts = ", ".join(f"{k} {v}" for k, v in res.counts().items() if v)
    print(f"{res.meta['packets']:,} packets in {time.time() - t:.1f} s: {counts}")
    return 0
