# LinkTest requirements ledger

One row per requirement. Statuses: **planned**, **done vX.Y.Z**, **deferred**,
**dropped**. "Source" is who asked and when. "Verified" says how it was checked.
Add a row for every new ask, including things deliberately not done, so they
are not re-litigated. Update statuses in the same pass as CHANGELOG.md.

## Product

| ID | Area | Requirement | Status | Source | Verified |
|---|---|---|---|---|---|
| R-001 | Speed test | Run iperf3 tests from a GUI a non-technical person can use, with plain-language labels and sensible defaults | done 0.1.0 | Kenton 2026-09-08 | Browser-pane walkthrough with fake iperf3 |
| R-002 | Speed test | Client mode ("Test my connection") and server mode ("Be the test target") in one app | done 0.1.0 | Kenton 2026-09-08 | Both modes exercised against fake + real iperf3 |
| R-003 | Speed test | Every iperf3 option reachable (Advanced) plus free-text extra arguments | done 0.1.0 | Kenton 2026-09-08 | `build_args` unit smoke test |
| R-004 | Speed test | Live view: current speed, timer, per-interval chart, running stats; bidirectional aware | done 0.1.0 | Kenton 2026-09-08 | Screenshots during runs |
| R-005 | Speed test | Plain-English verdict comparing to standard link speeds, judging retransmits / loss / jitter / steadiness | done 0.1.0 | Kenton 2026-09-08 | TCP, UDP, bidir verdict texts reviewed |
| R-006 | Speed test | iperf3 errors translated to friendly sentences | done 0.1.0 | Kenton 2026-09-08 | `fail`, `busy`, real "unable to connect" |
| R-007 | Speed test | Server mode shows this computer's addresses to read out; one-click firewall helper | done 0.1.0 (Windows) / 0.2.0 (Linux) | Kenton 2026-09-08 | Address chips checked; Linux parser unit-tested |
| R-008 | History | Every finished test kept locally with settings, re-runnable, exportable (CSV, full JSON) | done 0.1.0 | Kenton 2026-09-08 | History dialog, exports |
| R-009 | History | Past tests can be renamed; name shown in list and used in export filenames | done 0.2.1 | Kenton 2026-09-08 | Rename, reload, clear checked in browser pane |
| R-010 | Learnability | The exact iperf3 command line is always visible/copyable | done 0.1.0 | Kenton 2026-09-08 | Preview updates live |
| R-011 | Versioning | Version number defined once (`linktest.py` VERSION) with a CHANGELOG to build on | done 0.1.0 | Kenton 2026-09-08 | build.py reads it; UI shows it |
| R-012 | Packaging | Everything bundled: no runtime download of any kind; works fully offline | done 0.2.0 | Kenton 2026-09-08 | Exe run standalone with bundled iperf3 |
| R-013 | Packaging | Opens in its own window, no browser required | done 0.2.0 | Kenton 2026-09-08 | pywebview/WebView2 window; Qt on Linux |
| R-014 | Packaging | Single-file executable | done 0.2.0 | Kenton 2026-09-08 | `dist/win64/LinkTest.exe`, `dist/linux-x86_64/LinkTest` |
| R-015 | Packaging | Windows 10/11 x64 and Linux x86_64 builds | done 0.2.0 | Kenton 2026-09-08 | Both built; Linux run under WSLg |
| R-016 | Packaging | Second launch opens another window on the running instance instead of a second app | done 0.2.0 | derived | Two windows, close both → exit |
| R-017 | Exports | Saving files uses a native Save dialog in the window | done 0.2.0 | derived | Dialog open + cancel path automated |
| R-018 | Scan | Find devices on an IP range (default: this computer's own subnet) | done 0.3.0 | Kenton 2026-09-10 | Dev server: /23 default filled in; 60-address scan in 1.4 s (2026-09-10) |
| R-019 | Scan | Check an editable list of common ports per device, showing service names | done 0.3.0 | Kenton 2026-09-10 | Default list + service names shown as chips |
| R-020 | Scan | Per device: IP, hostname, MAC, manufacturer (bundled vendor table), ping time, open ports | done 0.3.0 | Kenton 2026-09-10 (vendors: yes, bundle) | Gateway resolved to Ubiquiti / unifi.localdomain; Raspberry Pi vendor from MAC |
| R-021 | Scan | Progress, cancel with partial results, sortable table, CSV export, "alive only" filter | done 0.3.0 | derived | Cancel, sort, filter, CSV exercised in browser pane |
| R-022 | Scan | A /24 with the default ports completes in well under a minute | done 0.3.0 | derived | Plan-agent measurement: /24 with 28 ports in < 10 s at 128 workers |
| R-023 | Scan | Range capped at 4096 addresses with a friendly message and a time estimate | done 0.3.0 | derived | parse_targets checks (/8 refused, backwards range refused) |
| R-024 | Ping monitor | Ping one or many addresses continuously (default every 1 s), each with a live latency chart | done 0.3.0 | Kenton 2026-09-10 | Three targets incl. a dead host watched live; charts drawn |
| R-025 | Ping monitor | Per target: now / min / avg / max / jitter / loss % / outages; outage = 3 consecutive failures, closed on next success | done 0.3.0 | derived | Stats tiles verified; outage opened after 3 misses |
| R-026 | Ping monitor | Outage and recovery alerts: card turns red and a short built-in sound plays; mutable per target | done 0.3.0 | Kenton 2026-09-10 (visual + sound) | Red card + tab badge on outage; Web Audio beep (browser needs one click first) |
| R-027 | Ping monitor | History kept on disk in daily files per target for 30 days, viewable by time window, exportable as CSV | done 0.3.0 | Kenton 2026-09-10 (30 days) | pings/<id>/<date>.csv written; history route downsamples; CSV export |
| R-028 | Ping monitor | Targets restored on start; pause / resume / rename / remove | done 0.3.0 | derived | Targets persisted in settings.json; reload restores cards with samples |
| R-029 | Ping monitor | Laptop sleep shows as a gap, not a false outage | done 0.3.0 | derived | Gap marker in PingMonitor._loop (resync after > 5 intervals); not yet observed live |
| R-030 | Ping monitor | Each watched address shows its route like PingPlotter: one row per hop with address, name, avg/min/current, loss and a recent-samples graph, refreshed continuously; the destination row equals the end-to-end chart | done 0.4.0 (supersedes the 0.3.0 one-shot traceroute) | Kenton 2026-09-10 | Route tables for 8.8.8.8 / gateway / dead host in the browser pane; backend smoke test |
| R-031 | DNS | Look up A, AAAA, CNAME, MX, NS, TXT, SOA, PTR, SRV, CAA (and "all common") for a name; reverse lookup for an IP | done 0.3.0 | Kenton 2026-09-10 | All types validated against 1.1.1.1 incl. TCP fallback for TXT |
| R-032 | DNS | Query the system resolver or chosen servers (1.1.1.1, 8.8.8.8, 9.9.9.9, custom) and compare answers side by side | done 0.3.0 | derived | Three-server compare rendered with diff highlighting |
| R-033 | DNS | Show TTL, response time, transport (UDP/TCP), response code in words | done 0.3.0 | derived | Columns present in DNS cards |
| R-034 | Shell | Tools live as tabs in one window: Speed test, Scan network, Ping monitor, DNS lookup; tools keep running while switching | done 0.3.0 | Kenton 2026-09-10 | Tabs with lastTab persistence; ping poller runs across tabs |
| R-036 | Ping monitor | Cards collapse to a one-line summary (current ms, loss, hop count); state remembered per address; Collapse all / Expand all | done 0.4.0 | Kenton 2026-09-10 | Collapse, reload, expand in browser pane; settings.json `collapsed` |
| R-037 | Ping monitor | Route changes are detected with a debounce (new address seen twice), load-balanced hops are marked rather than counted, silent hops are probed less often and greyed when stale | done 0.4.0 | derived (Plan agent review) | `_note_responder` logic; backoff in `_submit_hop_round` |
| R-038 | Ping monitor | Route on/off per address; route re-checked every 5 min and when an outage starts | done 0.4.0 | derived | `update(hopsOn)`, `_maybe_discover` |
| R-039 | Speed test | Address field keeps the last used server; the last 5 servers are offered as chips / suggestions | done 0.4.0 | Kenton 2026-09-10 | Chips render from settings.recentHosts after a test; click fills the field |
| R-040 | Ping monitor | Watch items can be reordered by drag and drop and by top/up/down/bottom buttons; order persists | done 0.4.1 | Kenton 2026-09-10 | Arrows + drag in browser pane; reload keeps order; settings.json `order` |
| R-041 | Capture | Record traffic on a chosen network connection to a .pcapng file with a simple what-to-record filter (protocol, address, port) | done 0.5.0 | Kenton 2026-09-10 | Helper run on Npcap loopback; tshark decodes the file identically |
| R-042 | Capture | Timed recordings (30 s / 1 / 5 / 15 min / until stopped) with a file-size cap and a Stop button | done 0.5.0 | Kenton 2026-09-10 | Duration + size checks in the helper loop; 4 s test stopped on time |
| R-043 | Capture | Live view while recording: counters, progress, protocol breakdown, latest packets in plain language | done 0.5.0 | derived | Browser pane during a loopback capture |
| R-044 | Capture | Friendly viewer: summary, busiest addresses, easy filters (type chips, address, port, word), paged list, per-packet plain-language detail + raw bytes, follow conversation, CSV export | done 0.5.0 | Kenton 2026-09-10 | Browser pane |
| R-045 | Capture | Saved recordings list with rename / delete / open; open external .pcap/.pcapng; save a copy; Open in Wireshark when installed | done 0.5.0 | derived | Browser pane; Wireshark 4.6 detected |
| R-046 | Capture | Engines: Npcap when installed (no prompt), built-in raw IPv4 capture with one administrator prompt otherwise; Linux AF_PACKET via polkit prompt; recording runs in a helper process, stopped via a flag file | done 0.5.0 | D-001 decisions | Npcap verified unelevated; raw-socket refusal detected cleanly; AF_PACKET in WSL; elevated Windows launcher fixed 0.8.1 (single pre-quoted command line, base64 filter) and marshalling unit-tested 2026-09-14 |
| R-047 | Shell | Version shown in the header; clicking it shows the release notes; iperf3 badge only on the Speed test tab; About explains every tool | done 0.5.0 | Kenton 2026-09-10 | Browser pane |
| R-048 | Wi‑Fi | List nearby networks with name, signal (dBm/bars/word), channel, band, width, security, standard, maker, busy %, last heard; connected network highlighted | done 0.6.0 | Kenton 2026-09-10 (WiFi Explorer-like) | Live WLAN API scan: 12 networks incl. 160 MHz WPA3 on 6 GHz |
| R-049 | Wi‑Fi | Channel-usage chart per band (shape = width × signal) with a quietest-channel hint and what the own network overlaps | done 0.6.0 | Kenton 2026-09-10 | Browser pane |
| R-050 | Wi‑Fi | Signal over time for ticked networks; band filter; sort; CSV export; scan only while the tab is open | done 0.6.0 | derived | Browser pane; auto-stop 30 s after last poll |
| R-051 | Shell | iperf3 badge visible only on the Speed test tab (regression fix: className rewrite stripped `hidden`) | done 0.6.0 | Kenton 2026-09-10 | Browser pane after > 6 s on another tab |
| R-052 | Wi‑Fi | One Stop scanning / Start scanning button; results remain visible while stopped (the separate Scan now button was removed in 0.7.0 as redundant) | done 0.6.1, revised 0.7.0 | Kenton 2026-09-10, 2026-09-11 | Browser pane: stop → backend idle, table kept; start → resumes |
| R-053 | Wi‑Fi | Clicking a network's shape in the channel chart opens a detail card (signal, channel/frequencies, width, security, standard, busy, last heard, overlapping networks) | done 0.6.1 | Kenton 2026-09-10 | Browser pane click on a shape → matching BSSID detail |
| R-054 | Scan | Choose one of this computer's networks from a list and fill the range with it (networks wider than /20 narrowed to the /24 around the local address) | done 0.7.0 | Kenton 2026-09-11 | Browser pane: select lists Wi‑Fi + Hyper-V; Use this network fills the field |
| R-055 | Speed test | Built-in list of public iperf3 servers, **USA only**, every entry verified with the bundled iperf3 (`tools/check_public_servers.py`, 2026-09-11); picking one fills address and port and states the port range; public servers are never added to the Recent chips | done 0.7.0, revised 0.7.1 | Kenton 2026-09-11 | 13/13 servers OK on 2026-09-11 (a flaky Clouvider New York entry was dropped); test to a public server leaves `recentHosts` unchanged |
| R-056 | Scan | ARP table view: every known neighbour with IP, MAC, maker, address type (factory / private-randomised / group), dynamic/static, connection, seen-in-scan; refresh after scans; filter; CSV | done 0.7.0 | Kenton 2026-09-11 | `/api/arp` lists the gateway (Ubiquiti) with the Wi‑Fi adapter name |
| R-057 | Scan | Look up a MAC (maker, type, IPs it answers for) or an IP (ping once, then MAC, maker, name, connection); warn on one MAC for several IPs or one IP with two MACs; device rows have an ARP button | done 0.7.0 | Kenton 2026-09-11 | Gateway IP → MAC + Ubiquiti; its MAC → IP; randomised MAC → private; 8.8.8.8 → "not on your local network" |
| R-058 | Speed test | A busy or refusing public server is retried automatically every 3 s, rotating through its port range, for up to 2 min; the live panel shows each attempt; Stop ends the retrying | done 0.7.2 | Kenton 2026-09-11 | Local server held by another client → `retry` events every 3 s, test runs when freed; Stop during a wait → `exit{stopped}` |
| R-059 | Shell | Window size, position and maximised state restored on the next launch; off-screen positions pulled back onto a live monitor | done 0.7.2 | Kenton 2026-09-11 | Resize + close → `settings.json` `window`; relaunch → same rect |
| R-060 | Wi‑Fi | One stable colour per network for the session, shared by the channel chart, table swatch, legend chips, detail card and signal-history lines | done 0.7.3 | Kenton 2026-09-11 | Browser pane: same SSID keeps its colour across polls; swatch = shape colour |
| R-061 | Wi‑Fi | Hovering a shape, legend chip or table row highlights that network everywhere (shape on top, others faded, tooltip with name/channel/width/signal/security/maker, table row lit); legend chips per band, strongest first, click = details; narrow shapes unlabeled until hovered | done 0.7.3 | Kenton 2026-09-11 | Browser pane hover/click checks |
| R-062 | Scan | ARP commands run from the app with the command line shown and copyable, output displayed: show table, show neighbours, clear cache, delete entry, add static entry; admin ones elevate (UAC / pkexec) or show the sudo line | done 0.7.4 | Kenton 2026-09-11 | Dev server: show/neighbours output; validation messages; admin command lines correct |
| R-063 | Wi‑Fi | Filters (name, minimum signal, hide hidden, only overlapping mine, show quiet) applied to table, channel charts and legend chips together; count "N of M shown"; persisted (`wifiFilters`) | done 0.7.4 | Kenton 2026-09-11 | Browser pane: rows/shapes/chips shrink together; survive reload |
| R-064 | Wi‑Fi | Signal-over-time card above the Networks table, 320 px tall, 10 dBm gridlines, Plot all shown / Clear plots, legend click removes a plot | done 0.7.4 | Kenton 2026-09-11 | Browser pane section order + canvas height |
| R-065 | Scan | Ports answered by the network for every address (DNS interception) are detected with canary probes + a post-scan majority check, announced, shown crossed out, and addresses with no other evidence are treated as empty; a TCP refusal counts as proof of life | done 0.8.2 | Kenton 2026-09-15 | Unit test with a simulated intercepting network; real /24 scan unchanged |
| R-066 | Scan | Settings, Devices and ARP cards collapse (chevron / title click); state persisted (`collapsed`); collapsed settings header summarises range, ports, last result | done 0.8.3 | Kenton 2026-09-15 | Browser pane: collapse, reload, still collapsed |
| R-067 | Scan | A MAC answering for several addresses is highlighted in both the Devices table and the ARP card (0.8.4) with a badge and explained in a warning block; CSV note; finish toast count | done 0.8.3 | Kenton 2026-09-15 | Injected duplicate in the dev server |
| R-068 | Scan | Port presets Basic / Standard / Thorough (≈1,100 ports) with a slow-scan warning; probing chunked to 256 sockets per host and concurrency capped so ≤ ~2,048 sockets are open at once; estimate toast for long scans | done 0.8.3 | Kenton 2026-09-15 | Unit: 1,100-port probe on 127.0.0.1 finds the one listener; Thorough scan of 20 addresses completes |
| R-069 | Ping monitor | Uptime-Robot style checks: web page (HTTP GET, 2xx/3xx up, status + TTFB, cert errors down) and TCP port (connect time) alongside ping; Auto detection from URL / host:port; default 30 s interval; uptime %; failure reason shown; same alerts/history/route/CSV | done 0.9.0 | Kenton 2026-09-22 | Dev server: https://example.com and 127.0.0.1:<listener> up, closed port refused → down after 3 |
| R-070 | Capture | Zeek-style analysis of a recording or any opened .pcap/.pcapng: conn, dns, http, ssl, x509, files, quic, ssh, dhcp, ftp, ntp, software, known_hosts, known_services, notice, weird logs with Zeek's field names, formats and connection semantics (TCP state machine, conn_state, history, flipping, timeouts) | done 0.10.0 | Kenton 2026-09-25 | Compared with Zeek's btest baselines (`testing/btest/Traces` + `Baseline/scripts.base.protocols.*`): ssl/x509, conn, ssh, dhcp, ntp, quic, ftp and most dns/http logs identical apart from uid/ts; all 811 Zeek test traces run without errors; 270k-packet file in 3.4 s |
| R-071 | Capture | Plain-language findings (failing connections, retransmission, zero windows, DNS failures, certificate / TLS / SSH weaknesses, cleartext passwords, rogue DHCP, IP conflicts, scans, password guessing, traceroute) with a Show button that filters the logs | done 0.10.0 | derived | Demo capture merged from Zeek traces: 11 findings; live capture in the cloud container: none |
| R-072 | Capture | Analysis UI: overview (sites, lookups, failures, outcome bar), per-log tables with search/sort/all fields, field explanations, uid pivot across logs, jump to the connection's packets | done 0.10.0 | derived | Headless Chromium (Playwright), light and dark, no console errors |
| R-073 | Capture | Export Zeek TSV or JSON logs as .zip (native Save dialog), single log as .log; command line `--zeek-logs` | done 0.10.0 | derived | Zip opened and checked; CLI run on the demo capture |
| R-074 | Capture | Packet reader: Linux SLL/SLL2, stacked VLAN (802.1Q/QinQ), PPPoE, MPLS; streaming reader for large files | done 0.10.0 | derived | Zeek traces `linux_dlt_sll2.pcap`, `q-in-q.pcap`, `pppoe.pcap`, `mpls-in-vlan.pcap` parse |
| R-035 | Docs | ARCHITECTURE.md and REQUIREMENTS.md kept current with every change | done 0.3.0 | Kenton 2026-09-10 | This file |

## Non-functional and constraints

| ID | Area | Requirement | Status | Source | Verified |
|---|---|---|---|---|---|
| N-001 | Runtime | No administrator / root rights needed for any shipped tool | done 0.3.0 | derived | Firewall helper is the one elevation, user-initiated |
| N-002 | Runtime | No third-party Python packages at runtime beyond pywebview (and PySide6 on Linux) for the window | done 0.2.0 | derived | requirements.txt |
| N-003 | Runtime | No network traffic other than the test itself (no telemetry, no update checks) | done 0.2.0 | Kenton 2026-09-08 | Code review: no urllib at runtime |
| N-004 | Runtime | Windows build needs only the WebView2 runtime that ships with Windows 11 | done 0.2.0 | derived | |
| N-005 | Runtime | Linux build needs a desktop session, glibc ≥ 2.38, standard Qt system libraries | done 0.2.0 | derived | objdump GLIBC symbols |
| N-006 | Runtime | ICMP tools work without external CLI tools (traceroute/nslookup/dig/arp may be absent on Linux) | done 0.3.0 | derived from WSL check | WSL Ubuntu without traceroute/nslookup/dig/arp runs all tools |
| N-007 | Runtime | Ping monitor memory bounded (≤ 20 000 samples in memory per target); disk pruned at 30 days | done 0.3.0 | derived | deque(maxlen=20000) per target; prune() at start |
| N-008 | Runtime | Windows exe starts in ~1 s; Linux binary in < 10 s (one-file unpack) | done 0.2.0 | measured | |
| N-009 | Build | `python build.py` per platform; `--wsl` builds Linux from Windows; binaries fetched and SHA-256 pinned by `fetch-helpers.py` | done 0.2.0 | | |
| N-010 | Copy | UI text avoids jargon; where a technical word is unavoidable it is explained in place or in About | done 0.1.0 | Kenton 2026-09-08 | |
| N-011 | Build | macOS build from the same tree: `build.py` produces `LinkTest.app` (Cocoa window, ad-hoc signed, usage descriptions in Info.plist) and a zip; iperf3 compiled from the pinned source; every tool has a macOS backend (ping CLI, ifconfig/route/networksetup, arp -an, libpcap + osascript elevation, CoreWLAN / system_profiler) | done 0.8.0 (code + scripts; awaiting a run on real Mac hardware) | Kenton 2026-09-11 | Parsers unit-checked with sample macOS output; MACOS.md smoke checklist |

## Deferred and dropped

| ID | Area | Item | Status | Source | Notes |
|---|---|---|---|---|---|
| D-001 | Capture | Packet capture ("Wireshark captures") inside the app | done 0.5.0 as R-041..R-046 | Kenton 2026-09-10 | Decisions already taken if revived: capture to .pcapng with a simple filter, live counters and a packet summary list; Windows engine Npcap when installed (full Ethernet/BPF) else built-in raw-socket IP capture; Linux elevated helper via pkexec with AF_PACKET; elevation asked once per capture through a small helper process; saved captures list with rename and "Open in Wireshark". This PC has Npcap + Wireshark + pktmon; WSL has no tcpdump/dumpcap/pkexec. |
| D-007 | Wi‑Fi | True RF spectrum analysis (energy per frequency, non-Wi‑Fi interference) | dropped | derived 2026-09-10 | Needs dedicated hardware (e.g. Wi‑Spy); WiFi Explorer itself is a network scanner, which R-048 provides |
| D-002 | Ping monitor | Desktop notifications for outages | dropped | Kenton 2026-09-10 chose visual + sound | Platform-specific; revisit if asked |
| D-003 | ICMP tools | IPv6 targets for scan / ping / traceroute | deferred | derived | `Icmp6SendEcho2` and `IPPROTO_ICMPV6` datagram sockets exist for later; DNS AAAA/PTR already work |
| D-004 | Speed test | Authenticated iperf3 tests (`--rsa-*`, `--username`) | dropped | derived | Bundled Windows build lacks OpenSSL; Extra arguments box remains |
| D-005 | Shell | Separate window per tool | dropped | Kenton 2026-09-10 chose tabs | |
| D-006 | Ping monitor | Keep history forever / session only | dropped | Kenton 2026-09-10 chose 30 days | Retention is a setting (`pingRetentionDays`) |
