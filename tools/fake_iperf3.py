"""A stand-in for iperf3 used to test LinkTest without a network or the real binary.

Build it into bin/iperf3.exe with tools/make_fake.py, then point LinkTest at it.
It speaks the 3.17+ --json-stream dialect (and classic text if --json-stream is
absent) and reacts to a few magic host names:

    fail      -> connection refused error
    busy      -> server busy error
    slow      -> low, jittery throughput
"""
import json
import random
import sys
import time

argv = sys.argv[1:]


def flag(name, default=None):
    if name in argv:
        i = argv.index(name)
        return argv[i + 1] if i + 1 < len(argv) else default
    return default


if "--version" in argv or "-v" in argv:
    print("iperf 3.21 (cJSON 1.7.15)\nCYGWIN_NT-10.0 fake 3.5.3 x86_64\nOptimizations: fake")
    sys.exit(0)

stream = "--json-stream" in argv
udp = "-u" in argv
bidir = "--bidir" in argv
reverse = "-R" in argv
server = "-s" in argv
host = flag("-c", "")
dur = int(float(flag("-t", "10")))
par = int(flag("-P", "1"))
port = int(flag("-p", "5201"))
interval = float(flag("-i", "1"))
bitrate = flag("-b")
omit = int(flag("-O", "0"))


def emit(event, data):
    print(json.dumps({"event": event, "data": data}), flush=True)


def size(v):
    if not v:
        return None
    m = {"K": 1e3, "M": 1e6, "G": 1e9, "T": 1e12}
    return float(v[:-1]) * m[v[-1].upper()] if v[-1].upper() in m else float(v)


def run_test(peer, base):
    target = size(bitrate) if udp and bitrate else None
    if target == 0:
        target = None
    rate0 = min(base, target) if target else base
    sender = not reverse
    start = {
        "version": "iperf 3.21", "system_info": "fake",
        "connecting_to" if not server else "accepted_connection": {"host": peer, "port": port},
        "test_start": {"protocol": "UDP" if udp else "TCP", "num_streams": par, "reverse": int(reverse),
                       "duration": dur, "bytes": 0, "blocks": 0, "omit": omit, "bidir": int(bidir)},
        "timestamp": {"time": time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())},
        "tcp_mss_default": 1448,
    }
    if stream:
        emit("start", start)
    else:
        print(f"{'Accepted connection from' if server else 'Connecting to host'} {peer}, port {port}", flush=True)
    tot_bytes = tot_retr = tot_lost = tot_pk = 0
    rtot = 0
    n = int(dur / interval)
    for k in range(-int(omit / interval), n):
        time.sleep(interval)
        wobble = random.uniform(0.75, 1.0) if peer == "slow" else random.uniform(0.96, 1.0)
        bps = rate0 * wobble
        byts = bps * interval / 8
        t0, t1 = round(k * interval, 2), round((k + 1) * interval, 2)
        omitted = k < 0
        streams = []
        s = {"start": t0, "end": t1, "seconds": interval, "bytes": int(byts), "bits_per_second": bps,
             "omitted": omitted, "sender": sender}
        if udp:
            pk = int(byts / 1400)
            lost = int(pk * (random.uniform(0.02, 0.06) if peer == "slow" else random.uniform(0, 0.001)))
            s.update(jitter_ms=random.uniform(20, 60) if peer == "slow" else random.uniform(0.05, 0.4),
                     lost_packets=lost, packets=pk, lost_percent=(lost / pk * 100) if pk else 0)
            if not omitted:
                tot_lost += lost
                tot_pk += pk
        else:
            retr = random.choice([0, 0, 0, 1, 3]) if peer != "slow" else random.randint(20, 90)
            s["retransmits"] = retr
            if not omitted:
                tot_retr += retr
        if not omitted:
            tot_bytes += byts
        for i in range(par):
            st = dict(s)
            st["socket"] = 5 + i
            st["bits_per_second"] = bps / par
            st["bytes"] = int(byts / par)
            streams.append(st)
        data = {"streams": streams, "sum": s}
        if bidir:
            rb = bps * random.uniform(0.85, 0.95)
            data["sum_bidir_reverse"] = {"start": t0, "end": t1, "seconds": interval, "bytes": int(rb * interval / 8),
                                         "bits_per_second": rb, "retransmits": 0, "omitted": omitted, "sender": not sender}
            if not omitted:
                rtot += rb * interval / 8
        if stream:
            emit("interval", data)
        else:
            if udp:
                print(f"[  5]  {t0:5.2f}-{t1:5.2f}  sec  {byts/1e6:.2f} MBytes  {bps/1e6:.1f} Mbits/sec  {s['jitter_ms']:.3f} ms  {s['lost_packets']}/{s['packets']} ({s['lost_percent']:.2g}%)" + ("  (omitted)" if omitted else ""), flush=True)
            else:
                print(f"[  5]  {t0:5.2f}-{t1:5.2f}  sec  {byts/1e6:.2f} MBytes  {bps/1e6:.1f} Mbits/sec    {s['retransmits']}   1.41 MBytes" + ("  (omitted)" if omitted else ""), flush=True)
    avg = tot_bytes * 8 / dur
    end_sum = {"start": 0, "end": dur, "seconds": dur, "bytes": int(tot_bytes), "bits_per_second": avg, "sender": sender}
    end = {"streams": [], "cpu_utilization_percent": {"host_total": random.uniform(3, 12), "remote_total": random.uniform(3, 12)}}
    if udp:
        end_sum.update(jitter_ms=random.uniform(0.1, 0.5) if peer != "slow" else 35.0, lost_packets=tot_lost, packets=tot_pk,
                       lost_percent=(tot_lost / tot_pk * 100) if tot_pk else 0)
        end["sum"] = end_sum
        end["sum_sent"] = dict(end_sum, sender=True)
        end["sum_received"] = dict(end_sum, sender=False)
    else:
        end["sum_sent"] = dict(end_sum, retransmits=tot_retr, sender=True)
        end["sum_received"] = dict(end_sum, bytes=int(tot_bytes * 0.999), bits_per_second=avg * 0.999, sender=False)
    if bidir:
        ravg = rtot * 8 / dur
        end["sum_sent_bidir_reverse"] = {"start": 0, "end": dur, "seconds": dur, "bytes": int(rtot), "bits_per_second": ravg, "retransmits": 2, "sender": True}
        end["sum_received_bidir_reverse"] = {"start": 0, "end": dur, "seconds": dur, "bytes": int(rtot), "bits_per_second": ravg * 0.999, "sender": False}
    if stream:
        emit("end", end)
    else:
        print("- - - - - - - - - - - - - - - - - - - - - - - - -")
        if udp:
            print(f"[  5]   0.00-{dur:.2f}  sec  {tot_bytes/1e6:.1f} MBytes  {avg/1e6:.1f} Mbits/sec  0.300 ms  {tot_lost}/{tot_pk} ({(tot_lost/tot_pk*100) if tot_pk else 0:.2g}%)  sender")
            print(f"[  5]   0.00-{dur:.2f}  sec  {tot_bytes/1e6:.1f} MBytes  {avg/1e6:.1f} Mbits/sec  0.300 ms  {tot_lost}/{tot_pk} ({(tot_lost/tot_pk*100) if tot_pk else 0:.2g}%)  receiver")
        else:
            print(f"[  5]   0.00-{dur:.2f}  sec  {tot_bytes/1e6:.1f} MBytes  {avg/1e6:.1f} Mbits/sec  {tot_retr}             sender")
            print(f"[  5]   0.00-{dur:.2f}  sec  {tot_bytes*0.999/1e6:.1f} MBytes  {avg*0.999/1e6:.1f} Mbits/sec                  receiver")
        print("\niperf Done.", flush=True)


if server:
    if "--fail-listen" in argv or port == 1:
        msg = "unable to start listener for connections: Address already in use"
        emit("error", msg) if stream else print(f"iperf3: error - {msg}", file=sys.stderr, flush=True)
        sys.exit(1)
    while True:
        time.sleep(4)
        run_test("192.168.1.77", 940e6)
        if "-1" in argv:
            break
        time.sleep(1)
    sys.exit(0)

if host == "fail":
    msg = "unable to connect to server: Connection refused"
    emit("error", msg) if stream else print(f"iperf3: error - {msg}", file=sys.stderr, flush=True)
    sys.exit(1)
if host == "busy":
    msg = "the server is busy running a test. try again later"
    emit("error", msg) if stream else print(f"iperf3: error - {msg}", file=sys.stderr, flush=True)
    sys.exit(1)
time.sleep(0.6)
run_test(host, 320e6 if host == "slow" else (30e9 if par >= 8 else 941e6 if not udp else 10e9))
sys.exit(0)
