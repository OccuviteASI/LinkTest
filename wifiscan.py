"""Wi-Fi scanner for LinkTest (WiFi Explorer style).

Lists the networks the wireless adapter can hear, with signal, channel, band,
channel width, security, vendor and the connected one, and keeps a short
signal history per network. Standard library only, no admin rights:
  * Windows: the native WLAN API (wlanapi.dll via ctypes), netsh as a fallback
  * Linux: nmcli (NetworkManager) or `iw ... scan dump`
"""
from __future__ import annotations

import collections
import os
import json
import re
import shutil
import struct
import subprocess
import sys
import threading
import time

import nettools as nt

IS_WIN = os.name == "nt"
IS_LINUX = sys.platform.startswith("linux")
IS_MAC = sys.platform == "darwin"
PHY_NAMES = {1: "legacy", 2: "b", 3: "b", 4: "a", 5: "b", 6: "g", 7: "n", 8: "ac", 9: "ad", 10: "ax", 11: "be"}
PHY_WORDS = {"a": "Wi‑Fi 2", "b": "Wi‑Fi 1", "g": "Wi‑Fi 3", "n": "Wi‑Fi 4", "ac": "Wi‑Fi 5", "ax": "Wi‑Fi 6", "be": "Wi‑Fi 7"}


# ----------------------------------------------------------------------------
# Channels and frequencies
# ----------------------------------------------------------------------------
def band_of(mhz: float | None) -> str | None:
    if not mhz:
        return None
    if 2400 <= mhz < 2500:
        return "2.4"
    if 4900 <= mhz < 5925:
        return "5"
    if 5925 <= mhz <= 7125:
        return "6"
    return None


def freq_to_channel(mhz: float | None) -> int | None:
    if not mhz:
        return None
    mhz = int(round(mhz))
    if mhz == 2484:
        return 14
    if 2400 <= mhz < 2500:
        return (mhz - 2407) // 5
    if 4900 <= mhz < 5925:
        return (mhz - 5000) // 5
    if 5925 <= mhz <= 7125:
        return (mhz - 5950) // 5
    return None


def channel_to_freq(ch: int, band: str) -> int:
    if band == "2.4":
        return 2484 if ch == 14 else 2407 + 5 * ch
    if band == "5":
        return 5000 + 5 * ch
    return 5950 + 5 * ch


def signal_word(rssi: float | None) -> str:
    if rssi is None:
        return ""
    if rssi >= -50:
        return "excellent"
    if rssi >= -60:
        return "good"
    if rssi >= -70:
        return "fair"
    if rssi >= -80:
        return "weak"
    return "very weak"


def quality_from_rssi(rssi: float | None) -> int | None:
    if rssi is None:
        return None
    return int(max(0, min(100, (rssi + 100) * 2)))


# ----------------------------------------------------------------------------
# Information elements
# ----------------------------------------------------------------------------
def parse_ies(blob: bytes) -> dict:
    ies: dict = {"akms": set(), "wpa1": False, "ext": set()}
    off = 0
    while off + 2 <= len(blob):
        eid, ln = blob[off], blob[off + 1]
        body = blob[off + 2:off + 2 + ln]
        off += 2 + ln
        if len(body) < ln:
            break
        try:
            if eid == 0:
                ies["ssid"] = body
            elif eid == 3 and ln >= 1:
                ies["ds_channel"] = body[0]
            elif eid == 11 and ln >= 3:
                ies["qbss_util"] = round(body[2] / 255 * 100)
            elif eid == 61 and ln >= 2:
                ies["ht_op"] = {"primary": body[0], "secoff": body[1] & 3}
            elif eid == 192 and ln >= 3:
                ies["vht_op"] = {"cw": body[0], "seg0": body[1], "seg1": body[2]}
            elif eid == 48 and ln >= 8:
                p = 2 + 4  # version + group cipher
                if p + 2 <= ln:
                    pc = struct.unpack_from("<H", body, p)[0]
                    p += 2 + 4 * pc
                    if p + 2 <= ln:
                        ac = struct.unpack_from("<H", body, p)[0]
                        p += 2
                        for _ in range(ac):
                            if p + 4 <= ln:
                                ies["akms"].add(body[p:p + 4].hex())
                                p += 4
            elif eid == 221 and ln >= 4 and body[:4] == b"\x00\x50\xf2\x01":
                ies["wpa1"] = True
            elif eid == 255 and ln >= 1:
                ext = body[0]
                ies["ext"].add(ext)
                b = body[1:]
                if ext == 36 and len(b) >= 6:  # HE Operation
                    params = b[0] | (b[1] << 8) | (b[2] << 16)
                    p = 3 + 1 + 2  # params, bss colour, basic mcs
                    if params & (1 << 14):
                        p += 3
                    if params & (1 << 15):
                        p += 1
                    if b[1] & 0x02 and len(b) >= p + 5:  # 6 GHz operation info present
                        ies["he6"] = {"primary": b[p], "width": b[p + 1] & 3, "seg0": b[p + 2], "seg1": b[p + 3]}
                elif ext == 106 and len(b) >= 5:  # EHT Operation
                    if b[0] & 0x01 and len(b) >= 8:
                        ies["eht_op"] = {"width": b[5] & 7, "ccfs0": b[6], "ccfs1": b[7]}
        except (struct.error, IndexError):
            continue
    return ies


def security_from(ies: dict, cap: int) -> str:
    akms = ies.get("akms") or set()
    sae = "000fac08" in akms
    psk = "000fac02" in akms or "000fac06" in akms
    ent = bool(akms & {"000fac01", "000fac05", "000fac0c", "000fac0d"})
    owe = "000fac12" in akms
    if sae and psk:
        return "WPA2/WPA3"
    if sae:
        return "WPA3"
    if ent:
        return "WPA3-Enterprise" if "000fac0c" in akms else "WPA2-Enterprise"
    if psk:
        return "WPA2" + ("/WPA" if ies.get("wpa1") else "")
    if owe:
        return "Enhanced Open"
    if ies.get("wpa1"):
        return "WPA"
    if cap & 0x10:
        return "WEP"
    return "Open"


def width_and_center(ies: dict, primary_mhz: int, band: str | None) -> tuple[int, int]:
    """Return (width MHz, centre MHz) from the operation elements."""
    width, center = 20, primary_mhz
    ht = ies.get("ht_op")
    if ht and ht["secoff"] in (1, 3):
        width = 40
        center = primary_mhz + (10 if ht["secoff"] == 1 else -10)
    vht = ies.get("vht_op")
    if vht and band in ("5", "6", None):
        base = 5000 if band != "6" else 5950
        cw, s0, s1 = vht["cw"], vht["seg0"], vht["seg1"]
        if cw == 1:
            if s1 and abs(s1 - s0) == 8:
                width, center = 160, base + 5 * s1
            elif s1 and abs(s1 - s0) > 8:
                width, center = 80, base + 5 * s0  # 80+80: show the primary segment
            else:
                width, center = 80, base + 5 * s0
        elif cw == 2:
            width, center = 160, base + 5 * s0
        elif cw == 3:
            width, center = 80, base + 5 * s0
    he6 = ies.get("he6")
    if he6 and band == "6":
        w = {0: 20, 1: 40, 2: 80, 3: 160}.get(he6["width"], 20)
        seg = he6["seg1"] if w == 160 and he6["seg1"] else he6["seg0"]
        width, center = w, 5950 + 5 * (seg or he6["primary"])
    eht = ies.get("eht_op")
    if eht and band in ("5", "6"):
        w = {0: 20, 1: 40, 2: 80, 3: 160, 4: 320}.get(eht["width"])
        if w:
            base = 5950 if band == "6" else 5000
            seg = eht["ccfs1"] if w >= 160 and eht["ccfs1"] else eht["ccfs0"]
            if seg:
                width, center = w, base + 5 * seg
    return width, center


# ----------------------------------------------------------------------------
# Windows: native WLAN API
# ----------------------------------------------------------------------------
class WlanApiBackend:
    name = "wlanapi"

    def __init__(self):
        if not IS_WIN:
            raise OSError("wlanapi is Windows-only")
        import ctypes
        from ctypes import wintypes as wt
        self.ct = ctypes
        self.dll = ctypes.WinDLL("wlanapi")
        c = ctypes

        class GUID(c.Structure):
            _fields_ = [("d1", c.c_uint32), ("d2", c.c_uint16), ("d3", c.c_uint16), ("d4", c.c_ubyte * 8)]

        class DOT11_SSID(c.Structure):
            _fields_ = [("uSSIDLength", c.c_uint32), ("ucSSID", c.c_ubyte * 32)]

        class WLAN_RATE_SET(c.Structure):
            _fields_ = [("uRateSetLength", c.c_uint32), ("usRateSet", c.c_uint16 * 126)]

        class WLAN_BSS_ENTRY(c.Structure):
            _fields_ = [("dot11Ssid", DOT11_SSID), ("uPhyId", c.c_uint32), ("dot11Bssid", c.c_ubyte * 6), ("dot11BssType", c.c_uint32),
                        ("dot11BssPhyType", c.c_uint32), ("lRssi", c.c_int32), ("uLinkQuality", c.c_uint32), ("bInRegDomain", c.c_ubyte),
                        ("usBeaconPeriod", c.c_uint16), ("ullTimestamp", c.c_uint64), ("ullHostTimestamp", c.c_uint64),
                        ("usCapabilityInformation", c.c_uint16), ("ulChCenterFrequency", c.c_uint32), ("wlanRateSet", WLAN_RATE_SET),
                        ("ulIeOffset", c.c_uint32), ("ulIeSize", c.c_uint32)]

        class WLAN_BSS_LIST(c.Structure):
            _fields_ = [("dwTotalSize", c.c_uint32), ("dwNumberOfItems", c.c_uint32), ("wlanBssEntries", WLAN_BSS_ENTRY * 1)]

        class WLAN_INTERFACE_INFO(c.Structure):
            _fields_ = [("InterfaceGuid", GUID), ("strInterfaceDescription", c.c_wchar * 256), ("isState", c.c_uint32)]

        class WLAN_INTERFACE_INFO_LIST(c.Structure):
            _fields_ = [("dwNumberOfItems", c.c_uint32), ("dwIndex", c.c_uint32), ("InterfaceInfo", WLAN_INTERFACE_INFO * 1)]

        class WLAN_AVAILABLE_NETWORK(c.Structure):
            _fields_ = [("strProfileName", c.c_wchar * 256), ("dot11Ssid", DOT11_SSID), ("dot11BssType", c.c_uint32), ("uNumberOfBssids", c.c_uint32),
                        ("bNetworkConnectable", c.c_int32), ("wlanNotConnectableReason", c.c_uint32), ("uNumberOfPhyTypes", c.c_uint32),
                        ("dot11PhyTypes", c.c_uint32 * 8), ("bMorePhyTypes", c.c_int32), ("wlanSignalQuality", c.c_uint32), ("bSecurityEnabled", c.c_int32),
                        ("dot11DefaultAuthAlgorithm", c.c_uint32), ("dot11DefaultCipherAlgorithm", c.c_uint32), ("dwFlags", c.c_uint32), ("dwReserved", c.c_uint32)]

        class WLAN_AVAILABLE_NETWORK_LIST(c.Structure):
            _fields_ = [("dwNumberOfItems", c.c_uint32), ("dwIndex", c.c_uint32), ("Network", WLAN_AVAILABLE_NETWORK * 1)]

        class WLAN_ASSOCIATION_ATTRIBUTES(c.Structure):
            _fields_ = [("dot11Ssid", DOT11_SSID), ("dot11BssType", c.c_uint32), ("dot11Bssid", c.c_ubyte * 6), ("dot11PhyType", c.c_uint32),
                        ("uDot11PhyIndex", c.c_uint32), ("wlanSignalQuality", c.c_uint32), ("ulRxRate", c.c_uint32), ("ulTxRate", c.c_uint32)]

        class WLAN_SECURITY_ATTRIBUTES(c.Structure):
            _fields_ = [("bSecurityEnabled", c.c_int32), ("bOneXEnabled", c.c_int32), ("dot11AuthAlgorithm", c.c_uint32), ("dot11CipherAlgorithm", c.c_uint32)]

        class WLAN_CONNECTION_ATTRIBUTES(c.Structure):
            _fields_ = [("isState", c.c_uint32), ("wlanConnectionMode", c.c_uint32), ("strProfileName", c.c_wchar * 256),
                        ("wlanAssociationAttributes", WLAN_ASSOCIATION_ATTRIBUTES), ("wlanSecurityAttributes", WLAN_SECURITY_ATTRIBUTES)]

        class WLAN_NOTIFICATION_DATA(c.Structure):
            _fields_ = [("NotificationSource", c.c_uint32), ("NotificationCode", c.c_uint32), ("InterfaceGuid", GUID), ("dwDataSize", c.c_uint32), ("pData", c.c_void_p)]

        self.T = dict(GUID=GUID, BSS=WLAN_BSS_ENTRY, BSSL=WLAN_BSS_LIST, IIL=WLAN_INTERFACE_INFO_LIST, II=WLAN_INTERFACE_INFO,
                      ANL=WLAN_AVAILABLE_NETWORK_LIST, AN=WLAN_AVAILABLE_NETWORK, CONN=WLAN_CONNECTION_ATTRIBUTES, ND=WLAN_NOTIFICATION_DATA)
        d = self.dll
        d.WlanOpenHandle.argtypes = [wt.DWORD, c.c_void_p, c.POINTER(wt.DWORD), c.POINTER(wt.HANDLE)]
        d.WlanCloseHandle.argtypes = [wt.HANDLE, c.c_void_p]
        d.WlanEnumInterfaces.argtypes = [wt.HANDLE, c.c_void_p, c.POINTER(c.POINTER(WLAN_INTERFACE_INFO_LIST))]
        d.WlanScan.argtypes = [wt.HANDLE, c.POINTER(GUID), c.c_void_p, c.c_void_p, c.c_void_p]
        d.WlanGetNetworkBssList.argtypes = [wt.HANDLE, c.POINTER(GUID), c.c_void_p, c.c_uint32, c.c_int32, c.c_void_p, c.POINTER(c.POINTER(WLAN_BSS_LIST))]
        d.WlanGetAvailableNetworkList.argtypes = [wt.HANDLE, c.POINTER(GUID), wt.DWORD, c.c_void_p, c.POINTER(c.POINTER(WLAN_AVAILABLE_NETWORK_LIST))]
        d.WlanQueryInterface.argtypes = [wt.HANDLE, c.POINTER(GUID), c.c_uint32, c.c_void_p, c.POINTER(wt.DWORD), c.POINTER(c.c_void_p), c.c_void_p]
        d.WlanFreeMemory.argtypes = [c.c_void_p]
        self.CB = c.WINFUNCTYPE(None, c.POINTER(WLAN_NOTIFICATION_DATA), c.c_void_p)
        d.WlanRegisterNotification.argtypes = [wt.HANDLE, wt.DWORD, c.c_int32, self.CB, c.c_void_p, c.c_void_p, c.POINTER(wt.DWORD)]
        self.handle = wt.HANDLE()
        neg = wt.DWORD()
        rc = d.WlanOpenHandle(2, None, c.byref(neg), c.byref(self.handle))
        if rc != 0:
            raise OSError(f"WlanOpenHandle failed ({rc})")
        self.scan_done = threading.Event()
        self._cb = self.CB(self._on_notify)
        prev = wt.DWORD()
        d.WlanRegisterNotification(self.handle, 0x8, 1, self._cb, None, None, c.byref(prev))  # ACM notifications
        self.iface_guid = None
        self.iface_desc = ""
        self.iface_state = None
        self._enum()

    def _on_notify(self, data, ctx):
        try:
            code = data.contents.NotificationCode
            if code in (7, 8, 26):  # scan complete / scan fail / list refresh
                self.scan_done.set()
        except Exception:
            pass

    def _enum(self):
        c = self.ct
        p = c.POINTER(self.T["IIL"])()
        rc = self.dll.WlanEnumInterfaces(self.handle, None, c.byref(p))
        if rc != 0:
            raise OSError(f"WlanEnumInterfaces failed ({rc})")
        try:
            n = p.contents.dwNumberOfItems
            if n == 0:
                self.iface_guid = None
                return
            base = c.addressof(p.contents.InterfaceInfo)
            best = None
            for k in range(n):
                ii = self.T["II"].from_address(base + k * c.sizeof(self.T["II"]))
                if best is None or ii.isState == 1:  # prefer the connected one
                    best = ii
            self.iface_guid = self.T["GUID"].from_buffer_copy(bytes(best.InterfaceGuid))
            self.iface_desc = best.strInterfaceDescription
            self.iface_state = best.isState
        finally:
            self.dll.WlanFreeMemory(p)

    def _radio_on(self) -> bool | None:
        c = self.ct
        size = c.c_uint32()
        data = c.c_void_p()
        rc = self.dll.WlanQueryInterface(self.handle, c.byref(self.iface_guid), 4, None, c.byref(size), c.byref(data), None)
        if rc != 0 or not data:
            return None
        try:
            raw = c.string_at(data, min(size.value, 16))
            if len(raw) >= 16:
                _n, _idx, sw, hw = struct.unpack_from("<IIII", raw)
                return sw == 1 and hw == 1
        finally:
            self.dll.WlanFreeMemory(data)
        return None

    def _connection(self) -> dict | None:
        c = self.ct
        size = c.c_uint32()
        data = c.c_void_p()
        rc = self.dll.WlanQueryInterface(self.handle, c.byref(self.iface_guid), 7, None, c.byref(size), c.byref(data), None)
        if rc != 0 or not data:
            return None
        try:
            conn = self.T["CONN"].from_address(data.value)
            if conn.isState != 1:
                return None
            a = conn.wlanAssociationAttributes
            return {"bssid": ":".join(f"{b:02x}" for b in a.dot11Bssid), "profile": conn.strProfileName,
                    "rxMbps": a.ulRxRate / 1000, "txMbps": a.ulTxRate / 1000, "quality": a.wlanSignalQuality,
                    "ssid": bytes(a.dot11Ssid.ucSSID[:a.dot11Ssid.uSSIDLength]).decode("utf-8", "replace")}
        finally:
            self.dll.WlanFreeMemory(data)

    def scan(self, rescan: bool = True) -> dict:
        c = self.ct
        if self.iface_guid is None:
            self._enum()
            if self.iface_guid is None:
                return {"rows": [], "error": "No Wi‑Fi adapter was found on this computer."}
        out = {"iface": {"desc": self.iface_desc}, "rows": [], "error": None}
        radio = self._radio_on()
        out["iface"]["radioOn"] = radio
        if radio is False:
            out["error"] = "The Wi‑Fi radio is switched off."
            return out
        if rescan:
            self.scan_done.clear()
            rc = self.dll.WlanScan(self.handle, c.byref(self.iface_guid), None, None, None)
            if rc == 1168:
                self.iface_guid = None
                out["error"] = "The Wi‑Fi adapter is switched off or not present."
                return out
            if rc == 5:
                out["error"] = "Windows blocked Wi‑Fi scanning. Turn on Location in Settings > Privacy & security, or allow desktop apps to use it."
            elif rc == 5023:
                out["error"] = "The Wi‑Fi radio is off."
                return out
            self.scan_done.wait(6.0)
        p = c.POINTER(self.T["BSSL"])()
        rc = self.dll.WlanGetNetworkBssList(self.handle, c.byref(self.iface_guid), None, 3, 0, None, c.byref(p))
        if rc != 0:
            msgs = {1168: "The Wi‑Fi adapter is switched off or not present.", 5: "Windows blocked Wi‑Fi scanning (Location privacy setting).",
                    5023: "The Wi‑Fi radio is off."}
            out["error"] = msgs.get(rc, f"Wi‑Fi scan failed (code {rc}).")
            if rc == 1168:
                self.iface_guid = None
            return out
        now = time.time()
        rows = []
        try:
            n = p.contents.dwNumberOfItems
            base = c.addressof(p.contents.wlanBssEntries)
            esz = c.sizeof(self.T["BSS"])
            for k in range(n):
                e = self.T["BSS"].from_address(base + k * esz)
                ssid = bytes(e.dot11Ssid.ucSSID[:min(32, e.dot11Ssid.uSSIDLength)]).decode("utf-8", "replace")
                ie = c.string_at(c.addressof(e) + e.ulIeOffset, e.ulIeSize) if e.ulIeSize else b""
                ies = parse_ies(ie)
                freq = e.ulChCenterFrequency / 1000.0
                band = band_of(freq)
                width, center = width_and_center(ies, int(round(freq)), band)
                rates = [(r & 0x7FFF) / 2 for r in e.wlanRateSet.usRateSet[:min(126, e.wlanRateSet.uRateSetLength)]]
                host_ts = (e.ullHostTimestamp - 116444736000000000) / 1e7 if e.ullHostTimestamp else now
                rows.append({"ssid": ssid, "hidden": not ssid, "bssid": ":".join(f"{b:02x}" for b in e.dot11Bssid),
                             "freqMHz": int(round(freq)), "band": band, "channel": freq_to_channel(freq), "widthMHz": width, "centerMHz": center,
                             "rssi": e.lRssi, "quality": e.uLinkQuality, "phy": PHY_NAMES.get(e.dot11BssPhyType, str(e.dot11BssPhyType)),
                             "security": security_from(ies, e.usCapabilityInformation), "utilization": ies.get("qbss_util"),
                             "maxRate": max(rates) if rates else None, "lastSeen": max(0.0, now - host_ts), "adhoc": e.dot11BssType == 2})
        finally:
            self.dll.WlanFreeMemory(p)
        out["rows"] = rows
        conn = self._connection()
        out["connected"] = conn
        return out

    def close(self):
        try:
            self.dll.WlanCloseHandle(self.handle, None)
        except Exception:
            pass


class NetshBackend:
    name = "netsh"
    _MAC = re.compile(r"\b([0-9a-f]{2}(?::[0-9a-f]{2}){5})\b", re.I)

    def __init__(self):
        if not IS_WIN or not shutil.which("netsh"):
            raise OSError("netsh not available")

    def scan(self, rescan: bool = True) -> dict:
        r = nt._run(["netsh", "wlan", "show", "networks", "mode=bssid"], timeout=20)
        if not r or r.returncode != 0:
            return {"rows": [], "error": "Could not read Wi‑Fi networks (netsh)."}
        rows = []
        ssid, sec = "", ""
        cur = None
        for line in (r.stdout or "").splitlines():
            s = line.strip()
            if not s:
                continue
            key, _, val = s.partition(":")
            val = val.strip()
            if re.match(r"^SSID \d+\s*$", key.strip(), re.I) or (key.strip().upper().startswith("SSID") and not self._MAC.search(s) and re.search(r"\d", key)):
                ssid = val
                cur = None
                sec = ""
                continue
            m = self._MAC.search(s)
            if m and "BSSID" in key.upper():
                cur = {"ssid": ssid, "hidden": not ssid, "bssid": m.group(1).lower(), "rssi": None, "quality": None, "phy": "", "band": None,
                       "channel": None, "freqMHz": None, "widthMHz": 20, "centerMHz": None, "security": sec or "?", "utilization": None,
                       "maxRate": None, "lastSeen": 0.0}
                rows.append(cur)
                continue
            if cur is None:
                if re.search(r"WPA3", val, re.I):
                    sec = "WPA3"
                elif re.search(r"WPA2", val, re.I):
                    sec = "WPA2"
                elif re.search(r"WPA", val, re.I):
                    sec = "WPA"
                elif re.search(r"\bOpen\b|None", val, re.I) and "Authentication" in key or (re.search(r"\bOpen\b", val, re.I) and not sec):
                    sec = "Open"
                continue
            pm = re.search(r"(\d+)\s*%", val)
            if pm and cur["quality"] is None:
                cur["quality"] = int(pm.group(1))
                cur["rssi"] = int(pm.group(1)) / 2 - 100
                continue
            rm = re.search(r"802\.11(\w+)", val)
            if rm:
                cur["phy"] = rm.group(1)
                continue
            bm = re.search(r"(\d+(?:\.\d+)?)\s*GHz", val)
            if bm:
                cur["band"] = "2.4" if bm.group(1).startswith("2") else ("5" if bm.group(1).startswith("5") else "6")
                continue
            if cur["channel"] is None and re.fullmatch(r"\d+", val) and cur["band"]:
                cur["channel"] = int(val)
                cur["freqMHz"] = channel_to_freq(cur["channel"], cur["band"])
                cur["centerMHz"] = cur["freqMHz"]
                continue
            um = re.search(r"\((\d+)\s*%\)", val)
            if um and "util" in key.lower():
                cur["utilization"] = int(um.group(1))
        conn = None
        r2 = nt._run(["netsh", "wlan", "show", "interfaces"], timeout=10)
        if r2 and r2.returncode == 0:
            m = self._MAC.search(r2.stdout or "")
            if m:
                conn = {"bssid": m.group(1).lower()}
        return {"rows": rows, "connected": conn, "error": None, "iface": {"desc": "Wi‑Fi (netsh)"}}


# ----------------------------------------------------------------------------
# Linux backends
# ----------------------------------------------------------------------------
def _sec_from_text(t: str) -> str:
    t = t.upper()
    if "WPA3" in t and ("WPA2" in t or "WPA1" in t):
        return "WPA2/WPA3"
    if "WPA3" in t or "SAE" in t:
        return "WPA3"
    if "802.1X" in t or "EAP" in t:
        return "WPA2-Enterprise"
    if "WPA2" in t:
        return "WPA2"
    if "WPA" in t:
        return "WPA"
    if "OWE" in t:
        return "Enhanced Open"
    if "WEP" in t:
        return "WEP"
    return "Open"


class NmcliBackend:
    name = "nmcli"

    def __init__(self):
        if not shutil.which("nmcli"):
            raise OSError("nmcli not found")
        r = nt._run(["nmcli", "-t", "-f", "DEVICE,TYPE", "dev"])
        self.iface = None
        for line in (r.stdout if r else "").splitlines():
            parts = line.split(":")
            if len(parts) >= 2 and parts[1] == "wifi":
                self.iface = parts[0]
                break
        if not self.iface:
            raise OSError("no Wi‑Fi device")

    def scan(self, rescan: bool = True) -> dict:
        if rescan:
            nt._run(["nmcli", "dev", "wifi", "rescan", "ifname", self.iface], timeout=10)
        fields = "SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY,BANDWIDTH,RATE,ACTIVE"
        r = nt._run(["nmcli", "-t", "--escape", "yes", "-f", fields, "dev", "wifi", "list", "ifname", self.iface, "--rescan", "no"], timeout=15)
        if not r or r.returncode != 0:
            fields = "SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY,RATE,ACTIVE"
            r = nt._run(["nmcli", "-t", "--escape", "yes", "-f", fields, "dev", "wifi", "list", "ifname", self.iface, "--rescan", "no"], timeout=15)
        if not r or r.returncode != 0:
            return {"rows": [], "error": "Could not list Wi‑Fi networks (nmcli)."}
        rows, conn = [], None
        names = fields.split(",")
        for line in (r.stdout or "").splitlines():
            parts = [p.replace("\\:", ":").replace("\\\\", "\\") for p in re.split(r"(?<!\\):", line)]
            if len(parts) < len(names):
                continue
            d = dict(zip(names, parts))
            try:
                freq = int(re.sub(r"\D", "", d["FREQ"]) or 0)
            except ValueError:
                freq = 0
            band = band_of(freq)
            sig = int(d["SIGNAL"] or 0)
            width = int(re.sub(r"\D", "", d.get("BANDWIDTH", "")) or 20)
            row = {"ssid": d["SSID"], "hidden": not d["SSID"], "bssid": d["BSSID"].lower(), "freqMHz": freq, "band": band,
                   "channel": int(d["CHAN"]) if d["CHAN"].isdigit() else freq_to_channel(freq), "widthMHz": width, "centerMHz": freq,
                   "rssi": sig / 2 - 100, "quality": sig, "phy": "", "security": _sec_from_text(d["SECURITY"] if d["SECURITY"] != "--" else ""),
                   "utilization": None, "maxRate": float(re.sub(r"[^\d.]", "", d["RATE"]) or 0) or None, "lastSeen": 0.0}
            rows.append(row)
            if d["ACTIVE"] == "yes":
                conn = {"bssid": row["bssid"], "ssid": row["ssid"]}
        return {"rows": rows, "connected": conn, "error": None, "iface": {"desc": self.iface}}


class IwBackend:
    name = "iw"

    def __init__(self):
        if not shutil.which("iw"):
            raise OSError("iw not found")
        r = nt._run(["iw", "dev"])
        m = re.search(r"Interface\s+(\S+)", r.stdout if r else "")
        if not m:
            raise OSError("no Wi‑Fi device")
        self.iface = m.group(1)

    def scan(self, rescan: bool = True) -> dict:
        if rescan:
            nt._run(["iw", "dev", self.iface, "scan"], timeout=15)  # may need privileges; dump still works
        r = nt._run(["iw", "dev", self.iface, "scan", "dump"], timeout=15)
        if not r or r.returncode != 0:
            return {"rows": [], "error": "Could not list Wi‑Fi networks (iw)."}
        rows = []
        cur = None
        for line in (r.stdout or "").splitlines():
            m = re.match(r"^BSS ([0-9a-f:]{17})", line)
            if m:
                cur = {"ssid": "", "hidden": True, "bssid": m.group(1).lower(), "freqMHz": None, "band": None, "channel": None, "widthMHz": 20,
                       "centerMHz": None, "rssi": None, "quality": None, "phy": "", "security": "Open", "utilization": None, "maxRate": None,
                       "lastSeen": 0.0, "_akm": "", "_priv": "Privacy" in line}
                rows.append(cur)
                continue
            if cur is None:
                continue
            s = line.strip()
            if s.startswith("freq:"):
                cur["freqMHz"] = int(float(s.split(":")[1]))
                cur["band"] = band_of(cur["freqMHz"])
                cur["channel"] = freq_to_channel(cur["freqMHz"])
                cur["centerMHz"] = cur["freqMHz"]
            elif s.startswith("signal:"):
                cur["rssi"] = float(re.sub(r"[^\d.-]", "", s.split(":")[1].split("dBm")[0]))
                cur["quality"] = quality_from_rssi(cur["rssi"])
            elif s.startswith("SSID:"):
                cur["ssid"] = s[5:].strip()
                cur["hidden"] = not cur["ssid"]
            elif s.startswith("capability:"):
                cur["_priv"] = "Privacy" in s
            elif s.startswith("last seen:"):
                mm = re.search(r"(\d+) ms", s)
                if mm:
                    cur["lastSeen"] = int(mm.group(1)) / 1000
            elif "channel utilisation" in s:
                mm = re.search(r"(\d+)/255", s)
                if mm:
                    cur["utilization"] = round(int(mm.group(1)) / 255 * 100)
            elif s.startswith("* Authentication suites:"):
                cur["_akm"] += " " + s.split(":", 1)[1]
            elif s.startswith("WPA:"):
                cur["_akm"] += " WPA1"
            elif s.startswith("* channel width:"):
                mm = re.search(r"\((\d+) MHz\)", s)
                if mm:
                    cur["widthMHz"] = max(cur["widthMHz"], int(mm.group(1)))
            elif s.startswith("* secondary channel offset:") and "no secondary" not in s:
                cur["widthMHz"] = max(cur["widthMHz"], 40)
        for cur in rows:
            akm = cur.pop("_akm", "")
            priv = cur.pop("_priv", False)
            cur["security"] = _sec_from_text(akm) if akm.strip() else ("WEP" if priv else "Open")
        conn = None
        r2 = nt._run(["iw", "dev", self.iface, "link"])
        m = re.search(r"Connected to ([0-9a-f:]{17})", r2.stdout if r2 else "")
        if m:
            conn = {"bssid": m.group(1).lower()}
        return {"rows": rows, "connected": conn, "error": None, "iface": {"desc": self.iface}}


class CoreWlanBackend:
    """macOS: Apple's CoreWLAN framework through PyObjC (pyobjc-framework-CoreWLAN).

    macOS 14+ hides SSIDs and BSSIDs from apps that are not allowed to use Location
    Services; the scan still works (channel, signal, width, security) and the hint says
    where to grant it.
    """
    name = "corewlan"
    BANDS = {1: "2.4", 2: "5", 3: "6"}
    WIDTHS = {1: 20, 2: 40, 3: 80, 4: 160}
    # kCWSecurity* constants, checked most-specific first
    SECURITY = [(12, "WPA3 Enterprise"), (11, "WPA3"), (13, "WPA2/WPA3"), (9, "WPA2 Enterprise"), (10, "Enterprise"),
                (4, "WPA2"), (5, "WPA2"), (7, "WPA Enterprise"), (8, "WPA Enterprise"), (2, "WPA"), (3, "WPA/WPA2"),
                (14, "OWE"), (15, "OWE"), (1, "WEP"), (6, "WEP"), (0, "Open")]

    def __init__(self):
        if not IS_MAC:
            raise OSError("macOS only")
        import CoreWLAN  # noqa: F401  (pyobjc-framework-CoreWLAN)
        self.cw = CoreWLAN
        self.client = CoreWLAN.CWWiFiClient.sharedWiFiClient()
        self.iface = self.client.interface()
        if self.iface is None:
            raise OSError("no Wi‑Fi interface")
        self.dev = str(self.iface.interfaceName() or "en0")

    def _security(self, n) -> str:
        for code, label in self.SECURITY:
            try:
                if n.supportsSecurity_(code):
                    return label
            except Exception:
                continue
        return "Unknown"

    def scan(self, rescan: bool = True) -> dict:
        try:
            nets, err = self.iface.scanForNetworksWithName_error_(None, None)
        except Exception as e:  # noqa: BLE001
            return {"rows": [], "error": f"Wi‑Fi scan failed: {e}"}
        if nets is None:
            try:
                if not self.iface.powerOn():
                    return {"rows": [], "error": "Wi‑Fi is turned off."}
            except Exception:
                pass
            return {"rows": [], "error": f"Wi‑Fi scan failed: {err}"}
        rows = []
        no_ids = 0
        for n in nets:
            ssid = str(n.ssid() or "")
            bssid = str(n.bssid() or "").lower()
            ch = n.wlanChannel()
            chan = int(ch.channelNumber()) if ch else None
            band = self.BANDS.get(int(ch.channelBand())) if ch else None
            width = self.WIDTHS.get(int(ch.channelWidth()), 20) if ch else 20
            freq = channel_to_freq(chan, band) if chan and band else None
            if freq and not band:
                band = band_of(freq)
            raw = n.informationElementData()
            ies = parse_ies(bytes(raw)) if raw else {}
            if ies and freq:
                try:
                    width, center = width_and_center(ies, freq, band)
                except Exception:
                    center = freq
            else:
                center = freq
            phy = "be" if ies.get("eht_op") else "ax" if (ies.get("he6") or 36 in ies.get("ext", set())) else \
                  "ac" if ies.get("vht_op") else "n" if ies.get("ht_op") else ("g" if band == "2.4" else "a")
            if not bssid:
                no_ids += 1
                bssid = f"{ssid or 'hidden'}@{chan}"
            rows.append({"ssid": ssid, "hidden": not ssid, "bssid": bssid, "freqMHz": freq, "band": band, "channel": chan,
                         "widthMHz": width, "centerMHz": center, "rssi": float(n.rssiValue()), "quality": quality_from_rssi(float(n.rssiValue())),
                         "phy": phy, "security": self._security(n), "utilization": ies.get("qbss_util"), "maxRate": None, "lastSeen": 0.0})
        conn = None
        try:
            cb = str(self.iface.bssid() or "").lower()
            cs = str(self.iface.ssid() or "")
            if cb or cs:
                conn = {"bssid": cb or next((r["bssid"] for r in rows if r["ssid"] == cs), cs), "ssid": cs,
                        "rxMbps": float(self.iface.transmitRate() or 0) or None}
        except Exception:
            conn = None
        error = None
        if rows and no_ids == len(rows):
            error = ("macOS hides network names and identifiers until LinkTest may use Location Services: "
                     "System Settings → Privacy & Security → Location Services → allow LinkTest, then rescan.")
        return {"rows": rows, "connected": conn, "error": error, "iface": {"desc": f"Wi‑Fi ({self.dev})"}}


class SystemProfilerBackend:
    """macOS fallback without PyObjC: `system_profiler SPAirPortDataType -json` (slow, no BSSIDs)."""
    name = "system_profiler"

    def __init__(self):
        if not IS_MAC or not shutil.which("system_profiler"):
            raise OSError("system_profiler not available")

    @staticmethod
    def _row(n: dict, is_current: bool) -> dict | None:
        name = str(n.get("_name") or "")
        m = re.match(r"(\d+)\s*\((\S+?)\s*GHz,\s*(\d+)\s*MHz\)", str(n.get("spairport_network_channel") or ""))
        if not m:
            return None
        chan, gh, width = int(m.group(1)), m.group(2), int(m.group(3))
        band = "2.4" if gh.startswith("2") else "5" if gh.startswith("5") else "6" if gh.startswith("6") else None
        sm = re.match(r"\s*(-?\d+)", str(n.get("spairport_signal_noise") or ""))
        rssi = float(sm.group(1)) if sm else None
        sec = str(n.get("spairport_security_mode") or "").replace("spairport_security_mode_", "")
        sec = {"none": "Open", "wep": "WEP", "wpa_personal": "WPA", "wpa2_personal": "WPA2", "wpa3_personal": "WPA3",
               "wpa3_transition": "WPA2/WPA3", "wpa2_enterprise": "WPA2 Enterprise", "wpa3_enterprise": "WPA3 Enterprise",
               "wpa_wpa2_personal": "WPA/WPA2"}.get(sec, sec.replace("_", " ").upper() or "Unknown")
        freq = channel_to_freq(chan, band) if band else None
        phy = str(n.get("spairport_network_phymode") or "").replace("802.11", "")
        bssid = str(n.get("spairport_network_bssid") or "").lower() or f"{name or 'hidden'}@{chan}"
        return {"ssid": name, "hidden": not name, "bssid": bssid, "freqMHz": freq, "band": band, "channel": chan, "widthMHz": width,
                "centerMHz": freq, "rssi": rssi, "quality": quality_from_rssi(rssi), "phy": phy, "security": sec,
                "utilization": None, "maxRate": None, "lastSeen": 0.0}

    def scan(self, rescan: bool = True) -> dict:
        r = nt._run(["system_profiler", "SPAirPortDataType", "-json"], timeout=40)
        if not r or r.returncode != 0:
            return {"rows": [], "error": "Could not list Wi‑Fi networks (system_profiler)."}
        try:
            data = json.loads(r.stdout or "{}")
            ifs = data["SPAirPortDataType"][0]["spairport_airport_interfaces"]
        except (ValueError, KeyError, IndexError, TypeError):
            return {"rows": [], "error": "Could not read the Wi‑Fi report (system_profiler)."}
        rows, conn, desc = [], None, "Wi‑Fi"
        for itf in ifs:
            desc = f"Wi‑Fi ({itf.get('_name', 'en0')})"
            cur = itf.get("spairport_current_network_information") or {}
            for n in itf.get("spairport_airport_other_local_wireless_networks") or []:
                row = self._row(n, False)
                if row:
                    rows.append(row)
            if cur:
                row = self._row(cur, True)
                if row:
                    rows.append(row)
                    conn = {"bssid": row["bssid"], "ssid": row["ssid"]}
        hint = "Names only: install pyobjc-framework-CoreWLAN for identifiers and faster scans." if rows else None
        return {"rows": rows, "connected": conn, "error": hint, "iface": {"desc": desc}}


def make_backend():
    errors = []
    order = [WlanApiBackend, NetshBackend] if IS_WIN else [CoreWlanBackend, SystemProfilerBackend] if IS_MAC else [NmcliBackend, IwBackend]
    for cls in order:
        try:
            return cls(), None
        except Exception as e:
            errors.append(f"{cls.name}: {e}")
    if IS_WIN:
        return None, "No Wi‑Fi adapter was found on this computer."
    if IS_MAC:
        return None, "No Wi‑Fi interface was found on this Mac."
    return None, "No Wi‑Fi tool was found. Install NetworkManager (nmcli) or iw, and make sure this computer has a Wi‑Fi adapter."


# ----------------------------------------------------------------------------
# Least-busy channel hint
# ----------------------------------------------------------------------------
CANDIDATES = {"2.4": [1, 6, 11], "5": [36, 40, 44, 48, 149, 153, 157, 161, 165, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144],
              "6": list(range(5, 234, 16))}


def least_busy(rows: list[dict]) -> dict:
    out = {}
    for band, cands in CANDIDATES.items():
        scores = []
        for ch in cands:
            f = channel_to_freq(ch, band)
            lo, hi = f - 10, f + 10
            weight = 0.0
            count = 0
            for r in rows:
                if r.get("band") != band or not r.get("centerMHz"):
                    continue
                rlo, rhi = r["centerMHz"] - r["widthMHz"] / 2, r["centerMHz"] + r["widthMHz"] / 2
                ov = max(0, min(hi, rhi) - max(lo, rlo))
                if ov <= 0:
                    continue
                count += 1
                strength = max(0.0, min(1.0, ((r.get("rssi") or -95) + 95) / 45))
                weight += (ov / 20) * (0.3 + strength)
            scores.append((weight, count, ch))
        if not scores:
            continue
        scores.sort()
        best = scores[0]
        out[band] = {"channel": best[2], "networks": best[1], "scores": [{"channel": c, "networks": n, "load": round(w, 2)} for w, n, c in sorted(scores, key=lambda x: x[2])]}
    return out


# ----------------------------------------------------------------------------
# Scanner
# ----------------------------------------------------------------------------
class WifiScanner:
    INTERVAL = 5.0
    IDLE_STOP = 30.0
    KEEP_UNSEEN = 90.0

    def __init__(self, vendors: nt.MacVendors):
        self.vendors = vendors
        self.backend = None
        self.backend_error = None
        self.log = nt.EventLog(keep=2000)
        self.lock = threading.Lock()
        self.rows: dict[str, dict] = {}
        self.history: dict[str, collections.deque] = {}
        self.connected: dict | None = None
        self.iface: dict = {}
        self.error: str | None = None
        self.last_scan = 0.0
        self.last_poll = 0.0
        self.scans = 0
        self._thread = None
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._vendor_cache: dict[str, str | None] = {}

    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def touch(self):
        self.last_poll = time.time()

    def start(self):
        self.touch()
        if self.running():
            return
        if self.backend is None:
            self.backend, self.backend_error = make_backend()
        if self.backend is None:
            self.error = self.backend_error
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="wifi-scan")
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._wake.set()

    def rescan(self):
        self.touch()
        if not self.running():
            self.start()
        self._wake.set()

    def _loop(self):
        while not self._stop.is_set():
            if time.time() - self.last_poll > self.IDLE_STOP:
                break  # nobody is looking; stop taking the radio off-channel
            t0 = time.time()
            try:
                res = self.backend.scan(rescan=True)
            except Exception as e:  # keep the thread alive on driver hiccups
                res = {"rows": [], "error": f"Wi‑Fi scan failed: {e}"}
            self._apply(res)
            self.scans += 1
            self.log.push({"type": "scan", "n": len(self.rows), "error": self.error})
            wait = max(0.5, self.INTERVAL - (time.time() - t0))
            self._wake.wait(wait)
            self._wake.clear()

    def _vendor(self, bssid: str, rows: list[dict]) -> str | None:
        if bssid in self._vendor_cache:
            return self._vendor_cache[bssid]
        v = self.vendors.lookup(bssid)
        if not v:
            first = int(bssid[:2], 16)
            if first & 0x02:  # locally administered: try the global version and sibling BSSIDs
                alt = f"{first & ~0x02:02x}" + bssid[2:]
                v = self.vendors.lookup(alt)
                if v:
                    v += "?"
                else:
                    tail = bssid[3:]
                    for r in rows:
                        if r["bssid"][3:] == tail and r["bssid"] != bssid and not int(r["bssid"][:2], 16) & 0x02:
                            vv = self.vendors.lookup(r["bssid"])
                            if vv:
                                v = vv + "?"
                                break
        self._vendor_cache[bssid] = v
        return v

    def _apply(self, res: dict):
        now = time.time()
        with self.lock:
            self.error = res.get("error")
            self.iface = res.get("iface") or self.iface
            conn = res.get("connected")
            self.connected = conn
            cb = (conn or {}).get("bssid")
            seen = set()
            for r in res.get("rows") or []:
                b = r["bssid"]
                seen.add(b)
                r["vendor"] = self._vendor(b, res.get("rows") or [])
                r["connected"] = (b == cb)
                r["seenAt"] = now - (r.get("lastSeen") or 0)
                r["stale"] = False
                if r.get("rssi") is None and r.get("quality") is not None:
                    r["rssi"] = r["quality"] / 2 - 100
                r["signalWord"] = signal_word(r.get("rssi"))
                r["phyWord"] = PHY_WORDS.get(r.get("phy") or "", "")
                self.rows[b] = r
                h = self.history.setdefault(b, collections.deque(maxlen=720))
                if r.get("rssi") is not None and (r.get("lastSeen") or 0) < self.INTERVAL * 3:
                    h.append((round(now, 1), round(r["rssi"], 1)))
            for b, r in list(self.rows.items()):
                if b not in seen:
                    age = now - r.get("seenAt", now)
                    r["stale"] = True
                    r["connected"] = False
                    if age > self.KEEP_UNSEEN:
                        self.rows.pop(b, None)
                        self.history.pop(b, None)
            if conn and cb in self.rows:
                rr = self.rows[cb]
                conn.update({k: rr.get(k) for k in ("ssid", "band", "channel", "freqMHz", "widthMHz", "rssi", "security", "phy", "vendor", "phyWord")})
                conn["signalWord"] = signal_word(rr.get("rssi"))
            self.last_scan = now

    def state(self) -> dict:
        self.touch()
        with self.lock:
            rows = sorted(self.rows.values(), key=lambda r: (r.get("rssi") is None, -(r.get("rssi") or -200)))
            live = [r for r in rows if not r.get("stale")]
            return {"running": self.running(), "backend": getattr(self.backend, "name", None), "iface": self.iface, "connected": self.connected,
                    "rows": rows, "error": self.error or (self.backend_error if self.backend is None else None), "lastScan": self.last_scan,
                    "scans": self.scans, "hint": least_busy(live), "seq": self.log.seq, "interval": self.INTERVAL}

    def history_for(self, bssids: list[str]) -> dict:
        with self.lock:
            return {b: list(self.history.get(b, [])) for b in bssids}

    def csv(self) -> str:
        import io
        buf = io.StringIO()
        buf.write("ssid,bssid,vendor,band,channel,width_mhz,center_mhz,rssi_dbm,quality,security,phy,connected,last_seen_s\n")
        with self.lock:
            for r in sorted(self.rows.values(), key=lambda r: -(r.get("rssi") or -200)):
                ssid = (r.get("ssid") or "").replace('"', "'")
                buf.write(f"\"{ssid}\",{r['bssid']},{r.get('vendor') or ''},{r.get('band') or ''},{r.get('channel') or ''},{r.get('widthMHz') or ''},"
                          f"{r.get('centerMHz') or ''},{r.get('rssi') if r.get('rssi') is not None else ''},{r.get('quality') if r.get('quality') is not None else ''},"
                          f"{r.get('security') or ''},{r.get('phy') or ''},{'yes' if r.get('connected') else 'no'},{round(time.time() - r.get('seenAt', time.time()))}\n")
        return buf.getvalue()
