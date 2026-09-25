"""Protocol parsers for LinkTest's Zeek-style analyzer (pcaplogs.py). Standard library only.

Everything here is a pure function or a small self-contained class: it takes bytes and returns
Python values, and knows nothing about connections or logs.

  * TLS  - ClientHello / ServerHello / Certificate parsing, JA3, JA3S and JA4 fingerprints
  * X.509 - a small DER reader producing Zeek's x509.log fields
  * QUIC - Initial-packet decryption (RFC 9001, v1/v2/draft-29) to read the ClientHello
           inside it; needs AES-128, implemented here because the standard library has none
  * DNS, DHCP, NTP message parsers
  * file-type sniffing (the mime_type Zeek puts in http.log / files.log)
  * software version parsing for software.log
"""
from __future__ import annotations

import base64
import calendar
import hashlib
import hmac
import re
import socket
import struct

import zeek_tables as ZT


def ip4(b: bytes) -> str:
    return socket.inet_ntoa(b[:4])


def ip6(b: bytes) -> str:
    try:
        return socket.inet_ntop(socket.AF_INET6, b[:16])
    except (OSError, ValueError):
        return b[:16].hex()


def ipstr(b: bytes) -> str:
    return ip4(b) if len(b) == 4 else ip6(b)


def mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b[:6])


def is_grease(v: int) -> bool:
    return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)


# ----------------------------------------------------------------------------
# TLS handshake messages
# ----------------------------------------------------------------------------
HRR_RANDOM = bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A2111 67ABB8C5E079E09E2C8A8339C".replace(" ", ""))

TLS_HS_LETTER = {0: "H", 1: "C", 2: "S", 3: "V", 4: "T", 8: "O", 11: "X", 12: "K", 13: "R", 14: "N", 15: "Y",
                 16: "G", 20: "F", 21: "W", 22: "U", 23: "A", 24: "P", 254: "M"}


def _u16list(b: bytes) -> list[int]:
    return [struct.unpack_from("!H", b, i)[0] for i in range(0, len(b) - 1, 2)]


def parse_extensions(p: bytes, off: int, end: int) -> list[tuple[int, bytes]]:
    out = []
    while off + 4 <= end:
        et, el = struct.unpack_from("!HH", p, off)
        off += 4
        out.append((et, p[off:off + el]))
        off += el
    return out


def parse_client_hello(body: bytes) -> dict | None:
    """body = the handshake message body (after the 4-byte type+length header)."""
    try:
        ver = struct.unpack_from("!H", body, 0)[0]
        off = 2 + 32
        sid_len = body[off]
        sid = body[off + 1:off + 1 + sid_len]
        off += 1 + sid_len
        cs_len = struct.unpack_from("!H", body, off)[0]
        ciphers = _u16list(body[off + 2:off + 2 + cs_len])
        off += 2 + cs_len
        cm_len = body[off]
        off += 1 + cm_len
        exts = []
        if off + 2 <= len(body):
            el = struct.unpack_from("!H", body, off)[0]
            exts = parse_extensions(body, off + 2, min(len(body), off + 2 + el))
    except (struct.error, IndexError):
        return None
    ch = {"version": ver, "session_id": sid, "ciphers": ciphers, "ext_types": [e[0] for e in exts], "sni": [], "alpn": [],
          "groups": [], "point_formats": [], "sig_algs": [], "versions": [], "psk": False, "ticket": b"", "has_ticket_ext": False}
    for et, ev in exts:
        try:
            if et == 0 and len(ev) >= 5:
                p = 2
                while p + 3 <= len(ev):
                    nt, nl = ev[p], struct.unpack_from("!H", ev, p + 1)[0]
                    if nt == 0:
                        ch["sni"].append(ev[p + 3:p + 3 + nl].decode("ascii", "replace"))
                    p += 3 + nl
            elif et == 16 and len(ev) >= 2:
                p = 2
                while p < len(ev):
                    ln = ev[p]
                    ch["alpn"].append(ev[p + 1:p + 1 + ln].decode("ascii", "replace"))
                    p += 1 + ln
            elif et == 10 and len(ev) >= 2:
                ch["groups"] = _u16list(ev[2:2 + struct.unpack_from("!H", ev, 0)[0]])
            elif et == 11 and ev:
                ch["point_formats"] = list(ev[1:1 + ev[0]])
            elif et == 13 and len(ev) >= 2:
                ch["sig_algs"] = _u16list(ev[2:2 + struct.unpack_from("!H", ev, 0)[0]])
            elif et == 43 and ev:
                ch["versions"] = _u16list(ev[1:1 + ev[0]])
            elif et == 41:
                ch["psk"] = True
            elif et == 35:
                ch["has_ticket_ext"] = True
                ch["ticket"] = ev
        except (struct.error, IndexError):
            continue
    return ch


def parse_server_hello(body: bytes) -> dict | None:
    try:
        ver = struct.unpack_from("!H", body, 0)[0]
        rnd = body[2:34]
        off = 34
        sid_len = body[off]
        sid = body[off + 1:off + 1 + sid_len]
        off += 1 + sid_len
        cipher = struct.unpack_from("!H", body, off)[0]
        off += 3  # cipher + compression
        exts = []
        if off + 2 <= len(body):
            el = struct.unpack_from("!H", body, off)[0]
            exts = parse_extensions(body, off + 2, min(len(body), off + 2 + el))
    except (struct.error, IndexError):
        return None
    sh = {"version": ver, "random": rnd, "session_id": sid, "cipher": cipher, "ext_types": [e[0] for e in exts],
          "selected_version": None, "alpn": None, "key_share": None, "psk": False, "hrr": rnd == HRR_RANDOM}
    for et, ev in exts:
        try:
            if et == 43 and len(ev) >= 2:
                sh["selected_version"] = struct.unpack_from("!H", ev, 0)[0]
            elif et == 16 and len(ev) >= 3:
                sh["alpn"] = ev[3:3 + ev[2]].decode("ascii", "replace")
            elif et in (51, 40) and len(ev) >= 2:
                sh["key_share"] = struct.unpack_from("!H", ev, 0)[0]
            elif et == 41:
                sh["psk"] = True
        except (struct.error, IndexError):
            continue
    return sh


def ja3(ch: dict) -> str:
    s = ",".join([str(ch["version"]),
                  "-".join(str(c) for c in ch["ciphers"] if not is_grease(c)),
                  "-".join(str(e) for e in ch["ext_types"] if not is_grease(e)),
                  "-".join(str(g) for g in ch["groups"] if not is_grease(g)),
                  "-".join(str(p) for p in ch["point_formats"])])
    return hashlib.md5(s.encode()).hexdigest()


def ja3s(sh: dict) -> str:
    s = f"{sh['version']},{sh['cipher']}," + "-".join(str(e) for e in sh["ext_types"])
    return hashlib.md5(s.encode()).hexdigest()


def ja4(ch: dict, quic: bool = False) -> str:
    vers = [v for v in ch["versions"] if not is_grease(v)]
    v = max(vers) if vers else ch["version"]
    vs = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3", 0x0002: "s2", 0xfeff: "d1", 0xfefd: "d2", 0xfefc: "d3"}.get(v, "00")
    ciphers = [c for c in ch["ciphers"] if not is_grease(c)]
    exts = [e for e in ch["ext_types"] if not is_grease(e)]
    alpn = ch["alpn"][0] if ch["alpn"] else ""
    if not alpn:
        a = "00"
    elif alpn[0].isalnum() and alpn[-1].isalnum() and alpn.isascii():
        a = alpn[0] + alpn[-1]
    else:
        hx = alpn.encode("latin-1", "replace").hex()
        a = hx[0] + hx[-1]
    part_a = f"{'q' if quic else 't'}{vs}{'d' if 0 in exts else 'i'}{min(len(ciphers), 99):02d}{min(len(exts), 99):02d}{a}"
    part_b = hashlib.sha256(",".join(f"{c:04x}" for c in sorted(ciphers)).encode()).hexdigest()[:12] if ciphers else "000000000000"
    ex = [e for e in exts if e not in (0, 16)]
    s = ",".join(f"{e:04x}" for e in sorted(ex))
    sigs = ",".join(f"{x:04x}" for x in ch["sig_algs"])
    if sigs:
        s += "_" + sigs
    part_c = hashlib.sha256(s.encode()).hexdigest()[:12] if ex else "000000000000"
    return f"{part_a}_{part_b}_{part_c}"


def tls_version_name(v: int | None) -> str | None:
    if v is None:
        return None
    if v in ZT.SSL_VERSIONS:
        return ZT.SSL_VERSIONS[v]
    if v >> 8 == 0x7F:
        return f"TLSv13-draft{v & 0xFF}"
    return f"unknown-{v}"


def cipher_name(c: int) -> str:
    return ZT.SSL_CIPHERS.get(c, f"unknown-{c}")


# ----------------------------------------------------------------------------
# X.509 (DER)
# ----------------------------------------------------------------------------
OID_NAMES = {
    "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.10": "O", "2.5.4.11": "OU",
    "2.5.4.5": "serialNumber", "2.5.4.9": "street", "2.5.4.17": "postalCode", "2.5.4.4": "SN", "2.5.4.42": "GN",
    "2.5.4.12": "title", "2.5.4.15": "businessCategory", "2.5.4.46": "dnQualifier", "2.5.4.65": "pseudonym",
    "0.9.2342.19200300.100.1.25": "DC", "0.9.2342.19200300.100.1.1": "UID", "1.2.840.113549.1.9.1": "emailAddress",
    "1.3.6.1.4.1.311.60.2.1.3": "jurisdictionC", "1.3.6.1.4.1.311.60.2.1.2": "jurisdictionST",
    "1.3.6.1.4.1.311.60.2.1.1": "jurisdictionL", "2.5.4.97": "organizationIdentifier",
}
SIG_ALGS = {
    "1.2.840.113549.1.1.2": "md2WithRSAEncryption", "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption", "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption", "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.113549.1.1.14": "sha224WithRSAEncryption", "1.2.840.113549.1.1.10": "rsassaPss",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1", "1.2.840.10045.4.3.1": "ecdsa-with-SHA224",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256", "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512", "1.2.840.10040.4.3": "dsaWithSHA1",
    "2.16.840.1.101.3.4.3.2": "dsa_with_SHA256", "1.3.101.112": "ED25519", "1.3.101.113": "ED448",
    "1.2.156.10197.1.501": "SM2-with-SM3", "2.16.840.1.101.3.4.3.17": "ML-DSA-44", "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
}
KEY_ALGS = {"1.2.840.113549.1.1.1": ("rsaEncryption", "rsa"), "1.2.840.10045.2.1": ("id-ecPublicKey", "ecdsa"),
            "1.2.840.10040.4.1": ("dsaEncryption", "dsa"), "1.3.101.112": ("ED25519", None), "1.3.101.113": ("ED448", None),
            "1.2.840.113549.1.1.10": ("rsassaPss", "rsa"), "2.16.840.1.101.3.4.3.17": ("ML-DSA-44", "ML-DSA-44"),
            "2.16.840.1.101.3.4.3.18": ("ML-DSA-65", "ML-DSA-65"), "2.16.840.1.101.3.4.3.19": ("ML-DSA-87", "ML-DSA-87")}
EC_CURVES = {"1.2.840.10045.3.1.7": ("prime256v1", 256), "1.3.132.0.34": ("secp384r1", 384), "1.3.132.0.35": ("secp521r1", 521),
             "1.3.132.0.33": ("secp224r1", 224), "1.2.840.10045.3.1.1": ("prime192v1", 192), "1.3.132.0.10": ("secp256k1", 256)}


def _der(b: bytes, off: int) -> tuple[int, int, int]:
    """-> (tag, value_start, value_end)."""
    tag = b[off]
    ln = b[off + 1]
    off += 2
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0 or n > 4:
            raise ValueError("bad DER length")
        ln = int.from_bytes(b[off:off + n], "big")
        off += n
    if off + ln > len(b):
        raise ValueError("DER overrun")
    return tag, off, off + ln


def _children(b: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    out = []
    while start < end:
        t, s, e = _der(b, start)
        out.append((t, s, e))
        start = e
    return out


def _oid(b: bytes) -> str:
    if not b:
        return ""
    first = b[0]
    parts = [str(min(first // 40, 2)), str(first - 40 * min(first // 40, 2))]
    v = 0
    for x in b[1:]:
        v = (v << 7) | (x & 0x7F)
        if not x & 0x80:
            parts.append(str(v))
            v = 0
    return ".".join(parts)


def _der_str(tag: int, v: bytes) -> str:
    if tag == 30:
        return v.decode("utf-16-be", "replace")
    if tag == 28:
        return v.decode("utf-32-be", "replace")
    if tag in (12,):
        return v.decode("utf-8", "replace")
    return v.decode("latin-1")


def _rfc2253_escape(s: str) -> str:
    out = []
    for i, ch in enumerate(s):
        if ch in ',+"\\<>;' or (ch == "#" and i == 0) or (ch == " " and (i == 0 or i == len(s) - 1)):
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


def _name(b: bytes, s: int, e: int) -> str:
    rdns = []
    for _t, rs, re_ in _children(b, s, e):          # SET
        avas = []
        for _t2, as_, ae in _children(b, rs, re_):  # SEQUENCE {oid, value}
            kids = _children(b, as_, ae)
            if len(kids) < 2:
                continue
            oid = _oid(b[kids[0][1]:kids[0][2]])
            vt, vs, ve = kids[1]
            key = OID_NAMES.get(oid)
            if key:
                avas.append(f"{key}={_rfc2253_escape(_der_str(vt, b[vs:ve]))}")
            else:
                avas.append(f"{oid}=#{b[kids[1][1] - 2:ve].hex()}")
        if avas:
            rdns.append("+".join(avas))
    return ",".join(reversed(rdns))


def _der_time(tag: int, v: bytes) -> float | None:
    s = v.decode("ascii", "replace").rstrip("Z")
    try:
        if tag == 23:
            yy = int(s[0:2])
            year = 2000 + yy if yy < 50 else 1900 + yy
            rest = s[2:]
        else:
            year = int(s[0:4])
            rest = s[4:]
        mo, d, h, mi = int(rest[0:2]), int(rest[2:4]), int(rest[4:6]), int(rest[6:8])
        sec = int(rest[8:10]) if len(rest) >= 10 else 0
        return float(calendar.timegm((year, mo, d, h, mi, sec, 0, 0, 0)))
    except (ValueError, IndexError):
        return None


def _int_hex(v: bytes) -> str:
    v = v.lstrip(b"\x00") or b"\x00"
    return v.hex().upper()


def parse_x509(der: bytes) -> dict | None:
    """Zeek x509.log fields for one DER certificate (fingerprint = SHA-256)."""
    try:
        _t, cs, ce = _der(der, 0)
        tbs_t, ts, te = _der(der, cs)
        kids = _children(der, ts, te)
        i = 0
        version = 1
        if kids and kids[0][0] == 0xA0:
            vt, vs, ve = _der(der, kids[0][1])
            version = int.from_bytes(der[vs:ve], "big") + 1
            i = 1
        serial = _int_hex(der[kids[i][1]:kids[i][2]])
        sig_oid = _oid(der[_der(der, kids[i + 1][1])[1]:_der(der, kids[i + 1][1])[2]])
        issuer = _name(der, kids[i + 2][1], kids[i + 2][2])
        validity = _children(der, kids[i + 3][1], kids[i + 3][2])
        nb = _der_time(validity[0][0], der[validity[0][1]:validity[0][2]])
        na = _der_time(validity[1][0], der[validity[1][1]:validity[1][2]])
        subject = _name(der, kids[i + 4][1], kids[i + 4][2])
        spki = _children(der, kids[i + 5][1], kids[i + 5][2])
        algid = _children(der, spki[0][1], spki[0][2])
        key_oid = _oid(der[algid[0][1]:algid[0][2]])
        key_alg, key_type = KEY_ALGS.get(key_oid, (key_oid, None))
        key_len = exponent = curve = None
        bits = der[spki[1][1] + 1:spki[1][2]]
        if key_type == "rsa":
            try:
                rk = _children(bits, *_der(bits, 0)[1:])
                modulus = bits[rk[0][1]:rk[0][2]].lstrip(b"\x00")
                key_len = len(modulus) * 8 - (8 - modulus[0].bit_length()) if modulus else 0
                exponent = str(int.from_bytes(bits[rk[1][1]:rk[1][2]], "big"))
            except (ValueError, IndexError):
                pass
        elif key_type == "ecdsa" and len(algid) > 1 and algid[1][0] == 6:
            curve, key_len = EC_CURVES.get(_oid(der[algid[1][1]:algid[1][2]]), (None, None))
        elif key_type and key_type.startswith("ML-DSA"):
            key_len = (len(bits)) * 8
        elif key_type == "dsa" and len(algid) > 1:
            try:
                pq = _children(der, algid[1][1], algid[1][2])
                p = der[pq[0][1]:pq[0][2]].lstrip(b"\x00")
                key_len = len(p) * 8
            except (ValueError, IndexError):
                pass
        san_dns: list[str] = []
        san_uri: list[str] = []
        san_email: list[str] = []
        san_ip: list[str] = []
        bc_ca = bc_path = None
        for t, s, e in kids[i + 6:]:
            if t != 0xA3:
                continue
            exts = _children(der, *_der(der, s)[1:])
            for _et, es, ee in exts:
                parts = _children(der, es, ee)
                oid = _oid(der[parts[0][1]:parts[0][2]])
                val = parts[-1]
                vb = der[val[1]:val[2]]
                if oid == "2.5.29.17":
                    for gt, gs, ge in _children(vb, *_der(vb, 0)[1:]):
                        gv = vb[gs:ge]
                        if gt == 0x82:
                            san_dns.append(gv.decode("latin-1"))
                        elif gt == 0x86:
                            san_uri.append(gv.decode("latin-1"))
                        elif gt == 0x81:
                            san_email.append(gv.decode("latin-1"))
                        elif gt == 0x87 and len(gv) in (4, 16):
                            san_ip.append(ipstr(gv))
                elif oid == "2.5.29.19":
                    bc_ca = False
                    for bt, bs, be in _children(vb, *_der(vb, 0)[1:]):
                        if bt == 1:
                            bc_ca = vb[bs:be] != b"\x00"
                        elif bt == 2:
                            bc_path = int.from_bytes(vb[bs:be], "big")
    except (ValueError, IndexError, struct.error):
        return None
    return {"fingerprint": hashlib.sha256(der).hexdigest(), "certificate.version": version, "certificate.serial": serial,
            "certificate.subject": subject, "certificate.issuer": issuer, "certificate.not_valid_before": nb,
            "certificate.not_valid_after": na, "certificate.key_alg": key_alg, "certificate.sig_alg": SIG_ALGS.get(sig_oid, sig_oid),
            "certificate.key_type": key_type, "certificate.key_length": key_len, "certificate.exponent": exponent,
            "certificate.curve": curve, "san.dns": san_dns or None, "san.uri": san_uri or None, "san.email": san_email or None,
            "san.ip": san_ip or None, "basic_constraints.ca": bc_ca, "basic_constraints.path_len": bc_path}


def cert_cn(subject: str) -> str | None:
    m = re.search(r"(?:^|,)CN=((?:\\.|[^,])*)", subject or "")
    return m.group(1).replace("\\", "") if m else None


def hostname_matches(name: str, patterns: list[str]) -> bool:
    name = name.lower().rstrip(".")
    for p in patterns:
        p = p.lower().rstrip(".")
        if p == name:
            return True
        if p.startswith("*.") and "." in name and name.split(".", 1)[1] == p[2:]:
            return True
    return False


# ----------------------------------------------------------------------------
# AES-128 (encrypt only) + HKDF, for QUIC Initial packets
# ----------------------------------------------------------------------------
def _gen_sbox() -> list[int]:
    sbox = [0] * 256
    p = q = 1
    rotl = lambda x, s: ((x << s) | (x >> (8 - s))) & 0xFF  # noqa: E731
    while True:
        p = (p ^ (p << 1) ^ (0x1B if p & 0x80 else 0)) & 0xFF
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        sbox[p] = q ^ rotl(q, 1) ^ rotl(q, 2) ^ rotl(q, 3) ^ rotl(q, 4) ^ 0x63
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox


_SBOX = _gen_sbox()
_XT = [((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1 for a in range(256)]


class AES128:
    def __init__(self, key: bytes):
        s = _SBOX
        rk = list(key)
        rcon = 1
        for i in range(4, 44):
            t = rk[(i - 1) * 4:i * 4]
            if i % 4 == 0:
                t = [s[t[1]] ^ rcon, s[t[2]], s[t[3]], s[t[0]]]
                rcon = _XT[rcon]
            rk += [rk[(i - 4) * 4 + j] ^ t[j] for j in range(4)]
        self.rk = rk

    def encrypt(self, block: bytes) -> bytes:
        s, xt, rk = _SBOX, _XT, self.rk
        st = [b ^ k for b, k in zip(block, rk[:16])]
        for rnd in range(1, 11):
            b = [s[x] for x in st]
            b = [b[0], b[5], b[10], b[15], b[4], b[9], b[14], b[3], b[8], b[13], b[2], b[7], b[12], b[1], b[6], b[11]]
            if rnd != 10:
                m = []
                for c in range(0, 16, 4):
                    a0, a1, a2, a3 = b[c], b[c + 1], b[c + 2], b[c + 3]
                    x = a0 ^ a1 ^ a2 ^ a3
                    m += [a0 ^ x ^ xt[a0 ^ a1], a1 ^ x ^ xt[a1 ^ a2], a2 ^ x ^ xt[a2 ^ a3], a3 ^ x ^ xt[a3 ^ a0]]
                b = m
            k = rk[16 * rnd:16 * rnd + 16]
            st = [x ^ y for x, y in zip(b, k)]
        return bytes(st)

    def ctr(self, iv12: bytes, data: bytes, start_counter: int = 2) -> bytes:
        out = bytearray()
        ctr = start_counter
        for i in range(0, len(data), 16):
            ks = self.encrypt(iv12 + struct.pack("!I", ctr))
            chunk = data[i:i + 16]
            out += bytes(a ^ b for a, b in zip(chunk, ks))
            ctr += 1
        return bytes(out)


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand_label(secret: bytes, label: str, length: int) -> bytes:
    full = b"tls13 " + label.encode()
    info = struct.pack("!H", length) + bytes([len(full)]) + full + b"\x00"
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(secret, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


QUIC_VERSIONS = {0x00000001: "1", 0x6b3343cf: "quicv2", 0xff00001d: "draft-29", 0xff00001e: "draft-30",
                 0xff00001f: "draft-30", 0xff000020: "draft-32", 0xff000021: "draft-33", 0xff000022: "draft-34",
                 0xff00001b: "draft-27", 0xff00001c: "draft-28"}
_QUIC_SALTS = {0x00000001: "38762cf7f55934b34d179ae6a4c80cadccbb7f0a", 0x6b3343cf: "0dede3def700a6db819381be6e269dcbf9bd2ed9",
               0xff00001d: "afbfec289993d24c9e9786f19c6111e04390a899"}


def quic_version_name(v: int) -> str:
    return QUIC_VERSIONS.get(v, f"unknown-{v:x}")


def varint(b: bytes, off: int) -> tuple[int, int]:
    first = b[off]
    ln = 1 << (first >> 6)
    v = first & 0x3F
    for i in range(1, ln):
        v = (v << 8) | b[off + i]
    return v, off + ln


def quic_packet_type(first: int, version: int) -> str:
    t = (first >> 4) & 3
    if version == 0x6b3343cf:
        return {1: "initial", 2: "0rtt", 3: "handshake", 0: "retry"}[t]
    return {0: "initial", 1: "0rtt", 2: "handshake", 3: "retry"}[t]


def quic_initial_keys(version: int, dcid: bytes, client: bool = True) -> tuple[AES128, bytes, AES128] | None:
    salt = _QUIC_SALTS.get(version)
    if salt is None and (version >> 8) == 0xff0000:
        salt = _QUIC_SALTS[0xff00001d]
    if salt is None:
        return None
    initial = hkdf_extract(bytes.fromhex(salt), dcid)
    secret = hkdf_expand_label(initial, "client in" if client else "server in", 32)
    pre = "quicv2 " if version == 0x6b3343cf else "quic "
    key = hkdf_expand_label(secret, pre + "key", 16)
    iv = hkdf_expand_label(secret, pre + "iv", 12)
    hp = hkdf_expand_label(secret, pre + "hp", 16)
    return AES128(key), iv, AES128(hp)


def quic_long_headers(d: bytes) -> list[dict]:
    """Split a UDP payload into its (coalesced) long-header packets; stops at a short header."""
    out = []
    off = 0
    while off + 7 <= len(d) and d[off] & 0x80:
        try:
            first = d[off]
            version = struct.unpack_from("!I", d, off + 1)[0]
            p = off + 5
            dl = d[p]
            dcid = d[p + 1:p + 1 + dl]
            p += 1 + dl
            sl = d[p]
            scid = d[p + 1:p + 1 + sl]
            p += 1 + sl
            if version == 0:
                out.append({"type": "version_negotiation", "version": 0, "dcid": dcid, "scid": scid})
                break
            ptype = quic_packet_type(first, version) if version in QUIC_VERSIONS or (version >> 8) == 0xff0000 else "unknown"
            token = b""
            if ptype == "initial":
                tl, p = varint(d, p)
                token = d[p:p + tl]
                p += tl
            if ptype == "retry" or ptype == "unknown":
                out.append({"type": ptype, "version": version, "dcid": dcid, "scid": scid})
                break
            length, p = varint(d, p)
            out.append({"type": ptype, "version": version, "dcid": dcid, "scid": scid, "token": token, "first_off": off,
                        "pn_off": p, "end": min(len(d), p + length), "raw": d})
            off = p + length
        except (IndexError, struct.error):
            break
    return out


def quic_decrypt_initial(pkt: dict, keys: tuple) -> bytes | None:
    """Remove header protection and decrypt (without checking the tag). Returns the frame bytes."""
    aes, iv, hp = keys
    d = pkt["raw"]
    pn_off = pkt["pn_off"]
    end = pkt["end"]
    if pn_off + 4 + 16 > len(d):
        return None
    mask = hp.encrypt(d[pn_off + 4:pn_off + 20])
    first = d[pkt["first_off"]] ^ (mask[0] & 0x0F)
    pn_len = (first & 3) + 1
    pn = 0
    for i in range(pn_len):
        pn = (pn << 8) | (d[pn_off + i] ^ mask[1 + i])
    nonce = bytes(a ^ b for a, b in zip(iv, pn.to_bytes(12, "big")))
    ct = d[pn_off + pn_len:end - 16]
    if not ct:
        return None
    return aes.ctr(nonce, ct)


def quic_crypto_frames(frames: bytes) -> tuple[list[tuple[int, bytes]], bool]:
    """-> ([(offset, data)], saw_connection_close)."""
    out = []
    close = False
    off = 0
    try:
        while off < len(frames):
            ft, off = varint(frames, off)
            if ft == 0x00 or ft == 0x01:
                continue
            if ft in (0x02, 0x03):
                _la, off = varint(frames, off)
                _dl, off = varint(frames, off)
                rc, off = varint(frames, off)
                _fr, off = varint(frames, off)
                for _ in range(rc):
                    _g, off = varint(frames, off)
                    _l, off = varint(frames, off)
                if ft == 0x03:
                    for _ in range(3):
                        _e, off = varint(frames, off)
            elif ft == 0x06:
                o, off = varint(frames, off)
                ln, off = varint(frames, off)
                out.append((o, frames[off:off + ln]))
                off += ln
            elif ft in (0x1c, 0x1d):
                close = True
                break
            else:
                break
    except IndexError:
        pass
    return out, close


# ----------------------------------------------------------------------------
# DNS
# ----------------------------------------------------------------------------
def dns_name(msg: bytes, off: int) -> tuple[str, int]:
    labels = []
    end = None
    jumps = 0
    while off < len(msg):
        ln = msg[off]
        if ln & 0xC0 == 0xC0:
            if off + 1 >= len(msg):
                break
            ptr = ((ln & 0x3F) << 8) | msg[off + 1]
            if end is None:
                end = off + 2
            off = ptr
            jumps += 1
            if jumps > 64:
                break
            continue
        off += 1
        if ln == 0:
            break
        lab = msg[off:off + ln]
        labels.append("".join(chr(c) if 33 <= c < 127 and c != 0x2e else f"\\x{c:02x}" for c in lab.lower()) if any(c < 33 or c >= 127 for c in lab) else lab.decode("ascii").lower())
        off += ln
    return ".".join(labels), (end if end is not None else off)


def decode_netbios_name(name: str) -> str:
    n = name.split(".", 1)[0]
    if len(n) != 32 or not all("A" <= c <= "P" for c in n.upper()):
        return name
    n = n.upper()
    out = bytes(((ord(n[i]) - 65) << 4) | (ord(n[i + 1]) - 65) for i in range(0, 32, 2))
    s = out[:15].decode("latin-1").rstrip(" \x00")
    return "".join(ch for ch in s if 32 <= ord(ch) < 127)


def parse_dns(p: bytes) -> dict | None:
    if len(p) < 12:
        return None
    qid, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", p, 0)
    m = {"id": qid, "QR": bool(flags & 0x8000), "opcode": (flags >> 11) & 0xF, "AA": bool(flags & 0x0400), "TC": bool(flags & 0x0200),
         "RD": bool(flags & 0x0100), "RA": bool(flags & 0x0080), "Z": (flags >> 4) & 0x7, "rcode": flags & 0xF,
         "num_queries": qd, "num_answers": an, "num_auth": ns, "num_addl": ar, "queries": [], "answers": []}
    off = 12
    try:
        for _ in range(min(qd, 16)):
            name, off = dns_name(p, off)
            if off + 4 > len(p):
                break
            qtype, qclass = struct.unpack_from("!HH", p, off)
            off += 4
            m["queries"].append((name, qtype, qclass))
        for _ in range(min(an, 200)):
            name, off = dns_name(p, off)
            if off + 10 > len(p):
                break
            rtype, rclass, ttl, rdlen = struct.unpack_from("!HHIH", p, off)
            off += 10
            rd = p[off:off + rdlen]
            m["answers"].append((name, rtype, ttl, _dns_rdata(p, off, rtype, rd).replace("{q}", name)))
            off += rdlen
    except (IndexError, struct.error):
        pass
    return m


def _dns_rdata(p: bytes, off: int, rtype: int, rd: bytes) -> str:
    if rtype == 1 and len(rd) == 4:
        return ip4(rd)
    if rtype == 28 and len(rd) == 16:
        return ip6(rd)
    if rtype in (2, 5, 12):
        return dns_name(p, off)[0]
    if rtype == 15 and len(rd) >= 3:
        return dns_name(p, off + 2)[0]
    if rtype == 6:
        return dns_name(p, off)[0]
    if rtype == 33 and len(rd) >= 7:
        return dns_name(p, off + 6)[0]
    if rtype in (16, 99):
        parts = []
        i = 0
        label = "TXT" if rtype == 16 else "SPF"
        while i < len(rd):
            ln = rd[i]
            s = rd[i + 1:i + 1 + ln]
            parts.append(f"{label} {len(s)} " + s.decode("utf-8", "backslashreplace"))
            i += 1 + ln
        return " ".join(parts)
    if rtype == 46 and len(rd) >= 18:  # RRSIG
        return f"RRSIG {struct.unpack_from('!H', rd, 0)[0]} {dns_name(p, off + 18)[0] or '<Root>'}"
    if rtype == 48 and len(rd) >= 4:  # DNSKEY
        return f"DNSKEY {rd[3]}"
    if rtype == 43 and len(rd) >= 4:  # DS
        return f"DS {rd[2]} {rd[3]}"
    if rtype == 47:  # NSEC
        return "NSEC {q} " + dns_name(p, off)[0]
    if rtype == 44 and len(rd) >= 2:  # SSHFP
        return "SSHFP: " + rd[2:].hex()
    if rtype == 257 and len(rd) >= 2:
        tl = rd[1]
        return f"CAA {rd[0]} {rd[2:2 + tl].decode('ascii', 'replace')} {rd[2 + tl:].decode('utf-8', 'replace')}"
    return ""


# ----------------------------------------------------------------------------
# DHCP / NTP
# ----------------------------------------------------------------------------
def parse_dhcp(p: bytes) -> dict | None:
    if len(p) < 240 or p[236:240] != b"\x63\x82\x53\x63":
        return None
    m = {"op": p[0], "xid": struct.unpack_from("!I", p, 4)[0], "ciaddr": ip4(p[12:16]), "yiaddr": ip4(p[16:20]),
         "siaddr": ip4(p[20:24]), "chaddr": mac(p[28:34]) if p[1] == 1 and p[2] == 6 else p[28:28 + min(16, p[2])].hex(),
         "type": None, "host_name": None, "fqdn": None, "domain": None, "requested": None, "lease": None, "message": None,
         "server_id": None, "client_id_mac": None}
    off = 240
    while off < len(p):
        code = p[off]
        if code == 255:
            break
        if code == 0:
            off += 1
            continue
        if off + 1 >= len(p):
            break
        ln = p[off + 1]
        v = p[off + 2:off + 2 + ln]
        if code == 53 and v:
            m["type"] = v[0]
        elif code == 12:
            m["host_name"] = v.decode("utf-8", "replace").rstrip("\x00")
        elif code == 81 and len(v) > 3:
            raw = v[3:]
            if v[0] & 0x04:
                m["fqdn"] = dns_name(b"\x00" * 0 + raw, 0)[0]
            else:
                m["fqdn"] = raw.decode("utf-8", "replace")
        elif code == 15:
            m["domain"] = v.decode("utf-8", "replace").rstrip("\x00")
        elif code == 50 and len(v) == 4:
            m["requested"] = ip4(v)
        elif code == 51 and len(v) == 4:
            m["lease"] = float(struct.unpack("!I", v)[0])
        elif code == 56:
            m["message"] = v.decode("utf-8", "replace")
        elif code == 54 and len(v) == 4:
            m["server_id"] = ip4(v)
        elif code == 61 and len(v) == 7 and v[0] == 1:
            m["client_id_mac"] = mac(v[1:7])
        off += 2 + ln
    return m


NTP_EPOCH = 2208988800


def _ntp_ts(b: bytes) -> float:
    sec, frac = struct.unpack("!II", b)
    if sec == 0 and frac == 0:
        return 0.0
    return sec - NTP_EPOCH + frac / 4294967296.0


def parse_ntp(p: bytes) -> dict | None:
    if len(p) < 1:
        return None
    li_vn_mode = p[0]
    version = (li_vn_mode >> 3) & 7
    mode = li_vn_mode & 7
    if not 1 <= version <= 4:
        return None
    r = {"version": version, "mode": mode}
    if mode in (6, 7) or len(p) < 48:
        return None
    stratum, poll, prec = p[1], struct.unpack_from("!b", p, 2)[0], struct.unpack_from("!b", p, 3)[0]
    rd, rdisp = struct.unpack_from("!II", p, 4)
    ref = p[12:16]
    if stratum <= 1:
        ref_id = ref.decode("latin-1")
    else:
        ref_id = ip4(ref)
    r.update(stratum=stratum, poll=float(2 ** poll), precision=float(2.0 ** prec), root_delay=rd / 65536.0, root_disp=rdisp / 65536.0,
             ref_id=ref_id, ref_time=_ntp_ts(p[16:24]), org_time=_ntp_ts(p[24:32]), rec_time=_ntp_ts(p[32:40]),
             xmt_time=_ntp_ts(p[40:48]), num_exts=0)
    # NTPv4 extension fields: anything past 48 bytes other than a 20/24-byte MAC
    extra = len(p) - 48
    if version == 4 and extra > 24:
        off, n = 48, 0
        while off + 4 <= len(p) - 20:
            ln = struct.unpack_from("!H", p, off + 2)[0]
            if ln < 16:
                break
            n += 1
            off += ln
        r["num_exts"] = n
    return r


# ----------------------------------------------------------------------------
# File-type sniffing (mime_type)
# ----------------------------------------------------------------------------
_MAGIC = [
    (b"\x89PNG\r\n\x1a\n", "image/png"), (b"\xff\xd8\xff", "image/jpeg"), (b"GIF87a", "image/gif"), (b"GIF89a", "image/gif"),
    (b"%PDF-", "application/pdf"), (b"PK\x03\x04", "application/zip"), (b"\x1f\x8b", "application/x-gzip"),
    (b"MZ", "application/x-dosexec"), (b"\x7fELF", "application/x-executable"), (b"BZh", "application/x-bzip2"),
    (b"\xfd7zXZ\x00", "application/x-xz"), (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed"), (b"Rar!\x1a\x07", "application/x-rar"),
    (b"\x00\x00\x01\x00", "image/x-icon"), (b"RIFF", "application/x-riff"), (b"OggS", "application/ogg"), (b"ID3", "audio/mpeg"),
    (b"\xca\xfe\xba\xbe", "application/x-java-applet"), (b"FWS", "application/x-shockwave-flash"), (b"CWS", "application/x-shockwave-flash"),
    (b"wOFF", "application/font-woff"), (b"wOF2", "application/font-woff2"), (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/msword"),
    (b"{\\rtf", "text/rtf"), (b"-----BEGIN CERTIFICATE", "application/x-pem"), (b"\x30\x82", "application/x-x509-ca-cert"),
]


def sniff_mime(b: bytes) -> str | None:
    if not b:
        return None
    for sig, mime in _MAGIC:
        if b.startswith(sig):
            if mime == "application/x-riff":
                return {b"WEBP": "image/webp", b"WAVE": "audio/x-wav", b"AVI ": "video/x-msvideo"}.get(b[8:12], "application/octet-stream")
            return mime
    if len(b) > 8 and b[4:8] == b"ftyp":
        return "video/mp4"
    head = b[:1024].lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if head.startswith((b"<!doctype html", b"<html", b"<head", b"<body", b"<title", b"<script", b"<!--", b"<div", b"<meta", b"<iframe", b"<style", b"<table", b"<a ", b"<p>", b"<br")):
        return "text/html"
    if head.startswith(b"<?xml"):
        return "image/svg+xml" if b"<svg" in head else "application/xml"
    if head.startswith(b"<svg"):
        return "image/svg+xml"
    try:
        text = b[:1024].decode("utf-8")
    except UnicodeDecodeError:
        text = None
        if len(b) > 1024:
            try:
                text = b[:1020].decode("utf-8")
            except UnicodeDecodeError:
                text = None
    if text is not None:
        if sum(1 for c in text if ord(c) < 32 and c not in "\r\n\t\f") <= len(text) // 50:
            if text.lstrip().startswith(("{", "[")):
                return "text/json"
            return "text/plain"
    return None


# ----------------------------------------------------------------------------
# Software versions (software.log)
# ----------------------------------------------------------------------------
def _version_parts(v: str) -> tuple:
    m = re.match(r"(\d+)(?:[._](\d+))?(?:[._](\d+))?(?:[._](\d+))?(.*)", v)
    if not m:
        return (None, None, None, None, v or None)
    nums = [int(x) if x is not None else None for x in m.group(1, 2, 3, 4)]
    addl = m.group(5).lstrip(" -._") or None
    return (*nums, addl)


def parse_software(s: str) -> tuple[str, tuple] | None:
    """-> (name, (major, minor, minor2, minor3, addl)) or None."""
    s = s.strip()
    if not s:
        return None
    browsers = [("Edg/", "Edge"), ("EdgA/", "Edge"), ("OPR/", "Opera"), ("Vivaldi/", "Vivaldi"), ("YaBrowser/", "Yandex"),
                ("SamsungBrowser/", "Samsung Internet"), ("Firefox/", "Firefox"), ("Chrome/", "Chrome"), ("CriOS/", "Chrome")]
    if s.startswith("Mozilla/"):
        for token, name in browsers:
            i = s.find(token)
            if i >= 0:
                v = re.match(r"[\d.]+", s[i + len(token):])
                return name, _version_parts(v.group(0) if v else "")
        m = re.search(r"Version/([\d.]+).*Safari/", s)
        if m:
            return "Safari", _version_parts(m.group(1))
        m = re.search(r"MSIE ([\d.]+)", s)
        if m:
            return "MSIE", _version_parts(m.group(1))
        if "Trident/" in s:
            m = re.search(r"rv:([\d.]+)", s)
            return "MSIE", _version_parts(m.group(1) if m else "")
    m = re.match(r"SSH-[\d.]+-([A-Za-z][\w.\-]*?)[_\-/ ]v?(\d[\w.\-]*)", s)
    if m:
        return m.group(1), _version_parts(m.group(2))
    m = re.match(r"SSH-[\d.]+-(\S+)", s)
    if m:
        return m.group(1), (None, None, None, None, None)
    m = re.match(r"([A-Za-z][\w.\- ]*?)[/ _\-]v?(\d+(?:[._]\d+)*)([^\s;()]*)", s)
    if m:
        name = m.group(1).strip()
        parts = _version_parts(m.group(2) + m.group(3))
        return name, parts
    m = re.match(r"([A-Za-z][\w.\-]*)", s)
    if m:
        return m.group(1), (None, None, None, None, None)
    return None


def b64_nopad(b: bytes) -> str:
    return base64.b64encode(b).decode().rstrip("=")
