"""Re-test the public iperf3 servers listed in ui/app.js (PUBLIC_SERVERS).

Run before changing the list:  python tools/check_public_servers.py [-t SECONDS]
Each server is tried on up to three ports from its range with the bundled iperf3; a "busy"
reply is retried up to 5 times at 3 s intervals per port (the same rule the app follows).
Exit code 0 when every server passed, 1 otherwise.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import iperf_runner as ir  # noqa: E402


def load_servers() -> list[dict]:
    src = open(os.path.join(ROOT, "ui", "app.js"), encoding="utf-8").read()
    block = src[src.index("const PUBLIC_SERVERS = ["):]
    block = block[: block.index("];")]
    out = []
    for m in re.finditer(r"\{([^}]*)\}", block):
        f = dict(re.findall(r"(\w+):\s*'([^']*)'", m.group(1)))
        port = re.search(r"port:\s*(\d+)", m.group(1))
        f["port"] = int(port.group(1)) if port else 5201
        out.append(f)
    return out


def ports_to_try(s: dict) -> list[int]:
    rng = re.match(r"(\d+)\D+(\d+)$", s.get("ports", ""))
    if not rng:
        return [s["port"]]
    lo, hi = int(rng.group(1)), int(rng.group(2))
    cands = [s["port"], lo, hi, lo + 2]
    return [p for i, p in enumerate(cands) if lo <= p <= hi and p not in cands[:i]][:3]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("-t", type=int, default=2, help="seconds per test (default 2)")
    a = ap.parse_args()
    exe = ir.bundled_iperf_path()
    if not exe or not os.path.exists(exe):
        print("iperf3 not found; run fetch-helpers.py first")
        return 2
    servers = load_servers()
    bad = 0
    for s in servers:
        verdict = "no ports"
        for port in ports_to_try(s):
            d = {}
            for attempt in range(5):
                try:
                    r = subprocess.run([exe, "-c", s["host"], "-p", str(port), "-t", str(a.t), "-J", "--connect-timeout", "4000"],
                                       capture_output=True, text=True, timeout=a.t + 20)
                    d = json.loads(r.stdout or "{}")
                except Exception as e:  # noqa: BLE001
                    d = {"error": f"{type(e).__name__}"}
                if "busy" in str(d.get("error", "")).lower() and attempt < 4:
                    time.sleep(3)
                    continue
                break
            if "error" in d:
                verdict = f"ERR :{port} {str(d['error'])[:60]}"
                continue
            mbps = d["end"]["sum_received"]["bits_per_second"] / 1e6
            verdict = f"OK  :{port} {mbps:.0f} Mbps"
            break
        ok = verdict.startswith("OK")
        bad += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {s['name']:32} {s['host']:36} {verdict}")
    print(f"\n{len(servers) - bad}/{len(servers)} servers OK")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
