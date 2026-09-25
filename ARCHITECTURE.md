# LinkTest architecture

LinkTest is a self-contained network toolbox for non-technical users: speed
test (iperf3), network scan, ping monitor with traceroute, and DNS lookup. It
is a Python 3 program that serves a small web UI to itself and shows it in a
native window. Nothing is downloaded at runtime and no administrator rights
are needed. This document describes how it is built and why; the
requirements ledger is `REQUIREMENTS.md`, releases are in `CHANGELOG.md`.

## 1. Process model

```
 LinkTest.exe / LinkTest  (PyInstaller one-file; unpacks to _MEI*/ then runs)
 |
 |-- main thread ........ pywebview window (WebView2 on Windows, Qt on Linux)
 |                        webview.start() returns when the LAST window closes
 |                        -> that is the shutdown signal
 |-- HTTP thread ........ ThreadingHTTPServer on 127.0.0.1:<free port>
 |     one handler thread per request; serves ui/ and the JSON API
 |-- iperf3 ............. subprocess started by Runner; a pump thread reads
 |                        its --json-stream output into an event list
 |-- Scanner ............ manager thread + ThreadPoolExecutor(128) per scan
 |-- PingMonitor ........ one loop thread per target (end-to-end ping) + a shared
 |                        64-worker pool for per-hop TTL probes + one reverse-name thread
 |-- DnsClient .......... runs inside the request thread (bounded timeouts)
 `-- Capture ............ helper subprocess `LinkTest --capture-helper` (elevated when the
                         engine needs it) writes .pcapng + meta.json; a tail thread in the
                         app reads complete blocks and dissects them
```

Browser fallback (`--browser`, dev only): the server runs on the main thread,
the UI opens in a browser tab and a heartbeat watchdog closes the app when the
tab is gone (never while a test/listener is running). `--no-open` just serves
(used by the browser-pane dev server in `.claude/launch.json`).

A second launch finds the running instance via `<state>/instance.json`, asks
it to open another window (`POST /api/window`) and exits.

## 2. Modules

| File | Role |
|---|---|
| `linktest.py` | Entry point. `App` (settings, history, tool objects), `Handler` (routes), `QuietServer`, native window helpers, `main()`. **Single source of `VERSION`.** |
| `iperf_runner.py` | Everything iperf3: locating the bundled binary, option dict → argv (`build_args`), running it (`Runner`), parsing `--json-stream` and classic text, friendly error mapping, local addresses, firewall helpers (Windows netsh, Linux ufw/firewalld). |
| `pcaptool.py` | Packet capture: pcapng writer, incremental pcap/pcapng reader, plain-language `Dissector`, `SimpleFilter`, engines (Npcap ctypes / raw socket / AF_PACKET), `capture_helper_main` (the `--capture-helper` process), `CaptureSession` (helper lifecycle, file tailing, stats, saved index, viewer queries, Zeek-style analysis jobs). `link_decap` strips Ethernet/VLAN/PPPoE/MPLS/SLL/SLL2/raw headers for both the viewer and the analyzer; `PcapReader.iter_packets` streams big files.
| `pcaplogs.py` | Zeek-style analyzer. `Analyzer.run(path)` → `Result`: connection table (5-tuple, Zeek TCP endpoint state machine ported from `TCPSessionAdapter.cc`, conn_state/history rules from `base/protocols/conn`, flip heuristics, 5 s attempt / 5 min TCP / 60 s UDP-ICMP timeouts), per-endpoint reassembly with gap detection (missed_bytes), content-based protocol detection, application analyzers (HTTP, TLS, SSH, FTP + ftp-data, SMTP/POP3/IMAP credentials, DNS over UDP/TCP, DHCP aggregation by xid, NTP, QUIC), files with hashes, post-processing (known_*, notices). `Result.tsv/json_lines/write_zip/rows`; `build_summary` feeds the UI; `cli_main` is `--zeek-logs`. |
| `pcapproto.py` | Pure parsers for the analyzer: TLS ClientHello/ServerHello, JA3/JA3S/JA4, X.509 DER, AES-128 + HKDF for QUIC Initial decryption (RFC 9001 vectors), DNS/DHCP/NTP messages, file-type sniffing, software versions. |
| `zeek_tables.py` | Generated name tables (cipher suites, TLS versions, curves, alerts, DNS types/classes/rcodes/opcodes, DHCP types) from Zeek's scripts via `tools/gen_zeek_tables.py`; BSD notice kept. |
| `wifiscan.py` | Wi‑Fi scanner: WLAN API (ctypes) / netsh / nmcli / iw backends, 802.11 information-element parsing (HT/VHT/HE/EHT width, RSN security), `WifiScanner` thread with per-BSSID signal history and least-busy channel hint. |
| `nettools.py` | ICMP pinger backends, `NetInfo` (interfaces, DNS servers, ARP), `parse_targets`, `Scanner`, `PingMonitor`/`Target`/`Hop` (PingPlotter-style route per target), `DnsClient`, `MacVendors`, `EventLog`.; `NetInfo.arp_rows()` (GetIpNetTable with adapter index → name / `/proc/net/arp` Device column), `MacVendors.lookup_smart()` (private-address heuristic), `mac_kind()`, `arp_report()`, `arp_lookup()` |
| `ui/index.html` | One page; tab bar + one `<section class="tab">` per tool; dialogs. |
| `ui/app.js` | Shell helpers (`api`, `toast`, `copyText`, `download`, `esc`, `fmt*`, `tile`, `drawChart`) and the speed-test tool. |
| `ui/tools.js` | Tabs, Scan, Ping monitor (route table + latency chart, collapsible cards), DNS compare. |
| `ui/style.css` | Design tokens (light/dark via `prefers-color-scheme`), components. |
| `fetch-helpers.py` | Downloads and SHA-256-pins bundled helpers into `bin/<tag>/` and `assets/` (iperf3 per platform, MAC vendor table). Never used at runtime. |
| `build.py` | PyInstaller one-file build for the current platform; `--wsl` runs the Linux build inside WSL; on macOS emits `LinkTest.app` + zip (`finish_mac_bundle` patches Info.plist and ad-hoc signs). `build-mac.sh` wraps venv + fetch + build; `MACOS.md` documents it. |
| `tools/` | Dev aids: `fake_iperf3.py` (+ `make_fake.py`), `make_icon.py`. |

## 3. UI ↔ backend contract

The UI never touches the OS; it calls the local JSON API. Two patterns:

- **Request/response**: `GET /api/status`, `POST /api/start {opts}`, `POST /api/dns/lookup {...}` … Errors come back as `{"error": "sentence for the user"}` with HTTP 400; `ValueError`/`RuntimeError` raised in the backend map to that automatically.
- **Seq polling** for anything long-running: the backend appends events to an `EventLog` (`seq`, `ts`, `type`, payload); the UI polls `GET …/events?since=<lastSeq>` every ~0.4–1 s and applies each event. A page reload replays from `since=0` (or a `state` route), so the UI always rehydrates.

### Routes

| Route | Method | Purpose |
|---|---|---|
| `/`, `/ui/*` | GET | Static UI |
| `/api/ping` | GET | Instance identity (`{app, version}`) |
| `/api/status` | GET | App info (version, windowed, platform, firewall backend), iperf3 info, local addresses, runner state, tools state |
| `/api/events?since` | GET | Speed-test events (`state, log, start, interval, end, error, exit`) |
| `/api/start {opts, skipRecent?, retry?}`, `/api/stop`, `/api/preview` | POST | Speed test control (`skipRecent` keeps the host out of `recentHosts`; `retry {every, maxSeconds, ports}` makes the runner re-run a client that hit "busy"/"unable to connect" before any data flowed, rotating ports, and emit `retry` events — the UI sets both for the built-in public servers); preview returns the command line |
| `/api/settings` | GET/POST | Persisted settings (POST `{patch}`) |
| `/api/history`, `/api/history/{delete,rename,clear}` | GET/POST | Speed-test history |
| `/api/iperf/path`, `/api/iperf/forget` | POST | Dev: use a specific iperf3 |
| `/api/firewall {port}` | POST | Open TCP+UDP port via UAC / pkexec; returns `{status: added|already|manual|unsupported, commands}` |
| `/api/window` | POST | Open another native window |
| `/api/export {name, text}` | POST | Native Save dialog + write |
| `/api/net/info[?refresh=1]` | GET | Interfaces (each with `network` CIDR, narrowed to /24 when wider than /20, `fullNetwork`, `index` on Windows), DNS servers, default scan range, pinger backend |
| `/api/arp` | GET | ARP table rows `{ip, mac, vendor, macKind, kind, iface, hostname, inScan}` + `conflicts[]` (`nettools.arp_report`) |
| `/api/arp/cmd {action, ip?, mac?}` | POST | Runs an ARP command (`show`, `neighbors`, `flush`, `delete`, `add`) via `nettools.arp_command`; admin actions elevate with the firewall helper's RunAs pattern (output via a temp file) or pkexec; `/api/arp` also returns the per-OS command templates |
| `/api/arp/lookup {q}` | POST | MAC → maker, type, IPs; IP/name → one ping, then MAC, maker, name, connection (`nettools.arp_lookup`) |
| `/api/scan/start {range, ports, …}`, `/api/scan/stop` | POST | Scanner control |
| `/api/scan/events?since`, `/api/scan/state`, `/api/scan/csv` | GET | Scanner stream (`start`, `host`, `detail`, `progress`, `intercept {ports, phase}`, `arp`, `done`) / rehydrate (includes `intercepted`) / export |
| `/api/pings/targets` | GET | Targets with stats, recent samples and per-hop recent samples (load/reload only) |
| `/api/pings/samples?since` | GET | Events (`sample`, `hops`, `route`, `outage`, `recovery`, `removed`) + a stats snapshot per target (route rows without samples) |
| `/api/pings/history?id&hours`, `/api/pings/csv?id&days` | GET | Backfill / export from day files |
| `/api/pings/{add,remove,pause,update,clear}` | POST | Target management (`add` takes host, kind auto\|ping\|tcp\|http, port, label, interval; `nettools.parse_watch_target` derives kind/host/port/url; `update` takes label, muted, hopsOn, collapsed, interval, timeoutMs, host). Checks: `tcp_check`, `http_check` (statuses ok/timeout/refused/http_error/error) |
| `/api/pings/collapse {collapsed}` | POST | Collapse or expand every card |
| `/api/pings/reorder {ids}` | POST | Set the display order (persisted as `order` per target) |
| `/api/dns/servers`, `/api/dns/lookup {name, type, servers}` | GET/POST | DNS |
| `/api/wifi/state`, `/api/wifi/history?bssid=a,b`, `/api/wifi/csv` | GET | Wi‑Fi scan results (polling `state` keeps the scanner alive; it stops 30 s after the last poll) |
| `/api/wifi/start`, `/api/wifi/stop`, `/api/wifi/rescan` | POST | Scanner control (the UI uses start/stop; rescan is kept for tooling) |
| `/api/changelog` | GET | CHANGELOG.md text for the What's new dialog |
| `/api/pcap/interfaces` | GET | Connections to record on (engine, elevation needed), engine info, last options |
| `/api/pcap/start {iface, filter{host,port,proto}, duration, maxMB, name}`, `/api/pcap/stop` | POST | Capture control (helper process) |
| `/api/pcap/status?since` | GET | Events `start, packets, progress, done` + live state |
| `/api/pcap/list`, `/api/pcap/stats?id`, `/api/pcap/packets?id&proto&host&port&q&conn&offset&limit` (`conn=a|pa|b|pb|t0|t1` = one connection), `/api/pcap/packet?id&n`, `/api/pcap/csv?id…` | GET | Saved recordings and the viewer |
| `/api/pcap/{open,rename,delete,wireshark,import,export}` | POST | Open external file (native dialog), rename, delete, hand to Wireshark, save a copy |
| `/api/pcap/analyze {id, force}` | POST | Start (or reuse) the Zeek-style analysis in a background thread |
| `/api/pcap/analysis?id` | GET | `{state none/running/done/error, progress, packets, summary}` |
| `/api/pcap/log?id&log&q&uid&sort&desc&offset&limit` | GET | One log page: `fields`, `types`, rows formatted as Zeek TSV values; notices carry `extra` (severity, plain text, filter) |
| `/api/pcap/log-text?id&log&fmt` | GET | One log as Zeek TSV or JSON lines (for `download`) |
| `/api/pcap/logs-export {id, format}` | POST | All logs as .zip: native Save dialog, or base64 in browser mode |
| `/api/quit` | POST | Shut down |

## 4. State on disk

`%LOCALAPPDATA%\LinkTest` (Windows) / `~/.config/linktest` (Linux):

| Path | Content |
|---|---|
| `settings.json` | `lastOpts` (speed test), `recentHosts` (last 5 speed-test servers), `iperfPath` (dev override), `lastTab`, `scanRange`, `scanPorts`, `scanOpts`, `pingTargets` `[{id, host, label, interval, timeoutMs, paused, muted, hopsOn, collapsed, order}]`, `pingRetentionDays` (30), `pingOutageThreshold` (3), `dnsCustomServers`, `dnsLastType` | `wifiFilters` + `wifiShowStale` (Wi‑Fi tab filters), `collapsed {key: bool}` (collapsible cards, keys like `scan.devices`). `window: {width, height, x, y, maximized}` is written by the native window's resized/moved/maximized/restored/closing events (debounced) and restored by `open_native_window`.
| `history.json` | Speed-test results (≤ 300), each `{id, ts, label?, mode, opts, cmd, summary, intervals, iperfVersion, host}` |
| `pings/<targetId>/<YYYY-MM-DD>.csv` | `ts,rtt_ms,status` per sample; written every 5 s; pruned after `pingRetentionDays` |
| `captures/<id>.pcapng` + `captures.json` | Recordings and their index (name, connection, filter, times, counts); `<id>.meta.json` / `<id>.stop` are the helper's status and stop-flag files |
| `captures/<id>-logs-<zeek|json>.zip` | Last exported log bundle (analysis results themselves live in memory, at most 3) |
| `instance.json` | `{port, pid}` of the running instance |
| `webview/` | WebView2 / Qt profile data |

## 5. Platform backends (all without elevation)

| Need | Windows | Linux | Fallback |
|---|---|---|---|
| ICMP echo / TTL probes | ctypes → `iphlpapi.IcmpSendEcho` (statuses 0 ok, 11010 timeout, 11013 TTL expired, 11003 unreachable) | `socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)` + `IP_TTL` + `IP_RECVERR`/`MSG_ERRQUEUE` (offender address in the cmsg) | Linux: `LC_ALL=C ping -n -c 1 -W s [-t ttl]` parsed, ≤ 32 concurrent |
| Interfaces / masks / gateway | ctypes `GetAdaptersInfo` | `ip -o -4 addr show` | PowerShell `Get-NetIPAddress` JSON; else /24 around the primary IP |
| System DNS servers | ctypes `GetNetworkParams` | `/etc/resolv.conf` | PowerShell `Get-DnsClientServerAddress` |
| ARP table (MACs) | ctypes `GetIpNetTable` | `/proc/net/arp` | `arp -a` regex |
| DNS queries | pure-Python UDP + TCP-on-truncation client | same | — |
| Firewall rule | `netsh advfirewall` via `Start-Process -Verb RunAs` | `ufw` / `firewall-cmd` via `pkexec` | show `sudo` commands to copy |
| Speed test | bundled `iperf3.exe` + `cygwin1.dll` | bundled static `iperf3` | dev: any iperf3 on PATH |
| Wi‑Fi scan | `wlanapi.dll` via ctypes (WlanScan + WlanGetNetworkBssList; no admin, no Location needed on 25H2) | `nmcli dev wifi list` or `iw dev X scan dump` | Windows `netsh wlan show networks mode=bssid` (locale-tolerant parse) |
| Packet capture | Npcap via ctypes (`wpcap.dll`; no admin unless Npcap is admin-only) | `AF_PACKET` socket (root via `pkexec`) | Windows raw socket `SIO_RCVALL` (admin via UAC, IPv4 only) |

## 6. Bundled assets and build pipeline

```
fetch-helpers.py  --downloads + SHA-256 pins-->  bin/win64/{iperf3.exe,cygwin1.dll,LICENSE.txt}
                                                 bin/linux-x86_64/{iperf3,LICENSE.txt}
                                                 assets/manuf.z (Wireshark MAC vendor table, zlib)
tools/make_icon.py ------------------------>  assets/linktest.{ico,png}   (committed)
build.py  (per platform; --wsl for Linux from Windows)
   PyInstaller --onefile --add-data ui --add-data assets --add-binary bin/<tag>/*
   -> dist/win64/LinkTest.exe (~20 MB)   dist/linux-x86_64/LinkTest (~240 MB, QtWebEngine)
   + VERSION.txt + THIRD-PARTY-LICENSES.txt
```

Frozen layout: data under `sys._MEIPASS` (`ui/`, `assets/`, `bin/`);
`iperf_runner.resource_dir()` / `bundled_bin_dir()` abstract dev vs frozen.

Linux build host: WSL Ubuntu 26.04, venv `/opt/linktestbuild` (pywebview,
PySide6, qtpy, pyinstaller) + Qt runtime libs (list in README). glibc floor
of the result = the build host's (2.38 needed by the Python runtime).

## 7. Conventions

- **Version** in `linktest.py` only; every user-visible change bumps it and
  adds a CHANGELOG entry; `REQUIREMENTS.md` statuses follow in the same pass.
- **Plain language**: labels say what the user wants ("Address of the other
  computer", "Be the test target"), technical terms are explained inline or
  in About; iperf3/OS errors are mapped to sentences (`friendly_error`).
- **Offline**: no code path opens a network connection except the tests the
  user starts. External links in About open in the system browser only if
  clicked.
- **Stdlib only** for logic; ctypes over subprocess where a Windows API exists
  (locale-independent, faster); subprocess only for `ping`/`ip`/`netsh`/
  `pkexec`.
- **One long-running job per tool** (`Runner`, `Scanner`) with the same
  `start/stop/state/running` shape; `PingMonitor` is the exception: many
  targets, one loop thread each, plus a shared hop-probe pool (rounds are
  skipped rather than queued when the pool is busy; silent hops back off).
- **Threads are daemon**; shutdown flushes ping CSVs, stops iperf3, then exits.

## 8. Testing recipes

- Zeek-style analyzer: sparse-clone Zeek (`testing/btest/Traces`, `testing/btest/Baseline/scripts.base.protocols.*`) and compare each log with ours ignoring `ts`/`uid`; `python linktest.py --zeek-logs file.pcap --out dir` for a quick look. Differences that remain on purpose: packets with bad checksums are analysed (Zeek drops them unless `-C`; local captures always have offloaded checksums), the SSH host-key fingerprint is the full `ssh-keygen -l` value (Zeek truncates it to 32 characters), software/known_* cover all hosts' software rather than only local ones, and Zeek's weird bookkeeping for malformed traffic is partial.

- Browser-pane dev server: `.claude/launch.json` entry `linktest`
  (`python linktest.py --no-open --port 8765`); same HTML/JS as the window.
  Stop it before testing the exe (the exe would attach to it via
  `instance.json`).
- Fake iperf3: `python tools/make_fake.py` → `tools/fake/iperf3.exe`
  (json-stream dialect; hosts `fail`, `busy`, `slow`); register via the
  setup box or `POST /api/iperf/path`.
- Real loopback: `bin\win64\iperf3.exe -s -p 5202` then a client test to
  `127.0.0.1:5202`; drive the API with `curl.exe --data-binary @file.json`
  (PowerShell strips JSON quotes; `Invoke-RestMethod` may resend POSTs).
- One-file exe = bootloader pid + child pid; windows belong to the child
  (the pid in `instance.json`).
- Linux: run `dist/linux-x86_64/LinkTest` under WSLg; `chmod +x` after
  copying through Windows.
