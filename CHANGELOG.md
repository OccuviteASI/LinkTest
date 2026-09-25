# Changelog

All notable changes to LinkTest. The version number is defined once, in
`linktest.py` (`VERSION`), and read by the UI and `build.py`.

## 0.10.0 - 2026-09-25

- Packet capture: **Connections & findings**, a Zeek-style analysis of any
  recording or opened .pcap / .pcapng (Wireshark files included). LinkTest
  reads the capture the way the Zeek network monitor does and writes the same
  logs: conn (one line per connection with Zeek's states SF/S0/REJ/RSTO…,
  history letters, bytes, packets, missed bytes, service found from the
  content, MAC, VLAN, Community ID), dns, http, ssl (with JA3, JA3S and JA4),
  x509, files (type, size, MD5/SHA1/SHA256), quic (server name read by
  decrypting the Initial packet), ssh (algorithms, host key, login guess),
  dhcp, ftp, ntp, software, known_hosts, known_services, notice and weird.
  Checked against Zeek's own test captures and expected output.
- "What stands out" explains findings in plain language: connections that
  keep failing (refused or unanswered), heavy retransmission, full receive
  buffers, DNS servers that fail or do not answer, many non-existent names,
  expired / not-yet-valid / self-signed / name-mismatched certificates, weak
  keys, old TLS and SSH versions, weak ciphers, passwords sent in the clear
  (HTTP Basic, FTP, POP3, IMAP, SMTP), several DHCP servers, IP address
  conflicts, port and address scans, SSH/FTP password guessing, traceroutes.
- Overview of sites and services contacted, names looked up, failed
  connections and connection outcomes; every log browsable with search,
  sorting and all Zeek fields; click a line for every field explained,
  "Everything about this connection" (the uid across all logs) and "Show its
  packets" (the packet list filtered to that one connection, time window
  included; "Show only this conversation" uses the same exact filter now).
- Save the logs as Zeek TSV (zeek-cut, Splunk / Elastic add-ons, RITA) or JSON
  lines in a .zip, or one log at a time. Command line:
  `LinkTest --zeek-logs capture.pcapng [--out DIR] [--json] [--zip FILE]`.
- A long findings list shows the first six, with "Show N more".
- Fix (Linux / macOS): a window restored onto a monitor that is no longer
  connected is pulled back onto a live screen again (the check always failed
  with "'list' object is not callable" because `webview.screens` is a proxy).
- The packet viewer now also reads Linux "cooked" captures (SLL / SLL2, what
  capturing on "any" produces), stacked VLAN tags, PPPoE and MPLS.

## 0.9.0 - 2026-09-22

- Ping monitor: **service checks** like Uptime Robot. Besides pinging, a
  watched item can be a **web page** (type or paste an https://… address:
  LinkTest fetches it and counts 2xx/3xx as up, showing the HTTP status and
  time to first byte; certificate problems count as down) or a **port**
  (host:port, or pick Port and give the number: a TCP connection each
  interval). Auto mode picks the check from what you typed. Service checks
  default to every 30 seconds, show uptime % instead of loss, say why they
  are down (HTTP 503, refused, timed out…), and get the same red card,
  sound, history, route table and CSV as pings.

## 0.8.4 - 2026-09-15

- Scan network: the ARP card now shows duplicate hardware addresses the same
  way the Devices table does: amber rows with a "⚠ also …" badge and a
  warning block directly above the table (it used to be a plain grey list
  above the Commands block, easy to miss). An address seen with two
  different MACs is badged "⚠ two MACs".

## 0.8.3 - 2026-09-15

- Scan network: the three cards (settings, Devices, ARP) collapse with a
  chevron or by clicking their title; the state is remembered, and a
  collapsed settings card shows the range, port count and last result in
  its header.
- Scan network: a hardware (MAC) address that answers for several addresses
  is highlighted (amber row, "⚠ also …" badge) with a warning explaining
  that it is usually a router or a multi-address device, and otherwise an
  IP conflict or spoofing. The CSV and the finish message mention it too.
- Scan network: port presets Basic (9 ports), Standard (the usual 28) and
  Thorough (every well-known port 1–1024 plus common extras, about 1,100).
  Thorough warns that it takes several minutes; the scanner probes in
  batches and lowers its concurrency so the machine never has more than
  about 2,000 half-open connections. The estimate is shown when you start.

## 0.8.2 - 2026-09-15

- Scan network: detects ports that the network itself answers for every
  address (typically a gateway intercepting DNS on port 53) by probing
  three canary addresses before the scan and checking the results
  afterwards. Addresses whose only sign of life is such a port are treated
  as empty and hidden by "Only devices that answered"; on real devices the
  port is shown crossed out, and a note under the progress bar explains
  what was detected. A refused connection now counts as proof of life, so
  devices that drop pings but have no open ports are still found.

## 0.8.1 - 2026-09-14

- Fix: starting a packet capture that needs the administrator prompt
  (built-in raw-socket capture, or Npcap in admin-only mode) failed with
  "Filter problem: Expecting property name enclosed in double quotes".
  PowerShell was re-joining the helper's arguments without quotes, which
  shredded the filter and any adapter name with spaces. The helper is now
  started with one pre-quoted command line, the filter travels base64-encoded
  on every platform, and the helper command line is kept with the capture
  for troubleshooting.

## 0.8.0 - 2026-09-11

- **macOS build.** `python build.py` on a Mac now produces `LinkTest.app`
  (and a zip for sharing) with the Cocoa/WKWebView window; `fetch-helpers.py
  mac` compiles iperf3 from the pinned source tarball with the Xcode command
  line tools so nothing depends on Homebrew. `build-mac.sh` does the whole
  thing; `MACOS.md` explains it step by step, including the first-launch
  Gatekeeper step and the permissions macOS asks for.
- macOS support in every tool: ping/route via the system `ping`, interfaces
  and gateway via `ifconfig`/`route`/`networksetup`, ARP via `arp -an` with
  `sudo arp` commands through the standard password dialog, packet capture
  with the system libpcap (password dialog or Wireshark's ChmodBPF), Wi‑Fi
  scanning via CoreWLAN (falls back to `system_profiler`), Wireshark in
  /Applications. The firewall button is hidden on macOS because the system
  asks on its own the first time LinkTest listens.
- `tools/pack_source.py` zips the source tree for moving it to another
  machine. Not yet run on real Mac hardware: see the checklist in MACOS.md.

## 0.7.4 - 2026-09-11

- Scan network: the ARP card gains **Commands**: Show table (`arp -a`),
  Show neighbours (`netsh interface ip show neighbors`), Clear cache
  (`arp -d *`), Delete entry (`arp -d <ip>`) and Add static entry
  (`arp -s <ip> <mac>`), with the exact command line shown and copyable next
  to each button and the output displayed below. Admin actions use the
  Windows administrator prompt; Linux runs the `ip neigh` equivalents.
- Wi‑Fi: a filter bar (name contains, hide weaker than −60/−70/−80 dBm, hide
  hidden networks, only networks overlapping mine, show quiet networks,
  Clear filters). Filters apply to the table, the channel charts and the
  legend chips together, the count reads "12 of 37 shown", and they are
  remembered between sessions.
- Wi‑Fi: Signal over time now sits above the Networks table, is nearly twice
  as tall with a gridline every 10 dBm, and has Plot all shown / Clear plots;
  click a name in its legend to stop plotting it.

## 0.7.3 - 2026-09-11

- Wi‑Fi "Channels in use": every network keeps one colour for the whole
  session (chart, table swatch, legend chips, detail card and signal-history
  lines), instead of colours reshuffling after each scan.
- Hovering a shape brings it to the front, fades the others and shows a
  tooltip (name, channel, width, signal, security, maker) so you know what a
  click will open; the matching table row lights up. Hovering a table row or
  a legend chip highlights the shape the same way.
- Each band chart is taller and has a row of colour chips listing its
  networks strongest-first; click a chip to open the details. Labels on very
  narrow shapes are hidden until hovered, so dense 2.4 GHz overlaps stay
  readable.

## 0.7.2 - 2026-09-11

- Speed test: when a public server is busy or refuses the connection,
  LinkTest now keeps trying by itself every 3 seconds, rotating through the
  server's port range, for up to 2 minutes. The live panel shows each
  attempt; Stop gives up at any time.
- The window reopens at the size and position it had when you closed it
  (and maximised if it was maximised). A position on a monitor that is no
  longer connected is pulled back onto the main screen.

## 0.7.1 - 2026-09-11

- Speed test: the public server list is USA only (Hurricane Electric,
  Clouvider ×3, Leaseweb ×9), and every entry was tested with the bundled
  iperf3 before being listed. `tools/check_public_servers.py` re-tests the
  list. Picking or testing a public server no longer adds it to the Recent
  chips, which stay reserved for your own targets.

## 0.7.0 - 2026-09-11

- Scan network: **ARP / MAC tools** card. Lists every hardware (MAC) address
  this computer knows (address, MAC, maker, factory vs private/randomised,
  dynamic/static entry, which connection, seen in the last scan), refreshed
  after each scan; filter and CSV. **Look up** a MAC (any separator) to get
  its maker, address type and the IPs it currently answers for, or an IP to
  ping it once and report its MAC, maker, name and connection. Warns when one
  MAC answers for several IPs or one IP has been seen with two MACs. Device
  rows gain an **ARP** button.
- Scan network: pick one of this computer's networks from a list and press
  **Use this network** to fill the range (large networks are narrowed to the
  /24 around your address).
- Speed test: a **public test servers** list (USA, Europe, Asia) fills the
  address and port with one click, with a hint about the port range each
  server accepts. Recent servers stay as chips.
- Wi‑Fi: the redundant "Scan now" button is gone; one Stop scanning / Start
  scanning button remains.

## 0.6.1 - 2026-09-10

- Wi‑Fi: Stop scanning / Start scanning button (results stay on screen while
  stopped; Scan now does a single scan).
- Wi‑Fi: click a shape in "Channels in use" to open a detail card for that
  network: signal, channel and occupied frequencies, width, security,
  standard, how busy it reports itself, last heard, and which other networks
  overlap it with a plain-language reading. Plot its signal from there.

## 0.6.0 - 2026-09-10

New **Wi‑Fi** tab (WiFi Explorer style).

- Lists every network your adapter can hear: name, signal (bars, dBm and a
  word), channel and band, channel width, security (WPA2/WPA3/Open…), Wi‑Fi
  standard, maker, how busy the access point reports itself, and when it was
  last heard. Your connected network is highlighted with its link speed.
- **Channels in use** chart per band: one shape per network spanning the
  channel width it occupies, as tall as its signal, so overlaps are obvious.
  A hint names the quietest channel on each band and says what your own
  network overlaps.
- **Signal over time** for the networks you tick (5 min to 1 h), band filter,
  sorting, "show networks that went quiet", Scan now, CSV export.
- Scanning runs only while the tab is open (it briefly takes the radio off
  channel). Windows uses the native WLAN API without administrator rights or
  Location permission; Linux uses NetworkManager (nmcli) or iw.
- Fix: the iperf3 badge no longer reappears on other tabs.

## 0.5.0 - 2026-09-10

New **Packet capture** tab (Wireshark-style recording, made friendly).

- Record the traffic on a network connection for 30 s, 1, 5 or 15 minutes or
  until you stop it, with a size cap. Choose what to record: everything, web,
  DNS, pings, TCP, UDP or ARP, optionally limited to one address and/or port.
- Live view while recording: packets, data, rate, a progress bar, a protocol
  breakdown and the latest packets described in plain language.
- Viewer for any recording: summary tiles, protocol bar, busiest addresses
  (click to filter), filters by type / address / port / word, 500-row pages,
  click a packet for a plain-language breakdown of each layer plus the raw
  bytes, "Show only this conversation", export the list as CSV, save a copy
  of the .pcapng, open it in Wireshark when installed. Opens .pcap/.pcapng
  files made elsewhere too.
- Engines: Npcap on Windows when Wireshark/Npcap is installed (no prompt);
  otherwise Windows' built-in raw capture (asks for administrator permission
  once per recording, IPv4 only); on Linux AF_PACKET through a password
  prompt. The recording itself runs in a small helper process.
- Header shows the version; click it for these release notes. The iperf3
  badge only appears on the Speed test tab. The About dialog now explains
  each tool.

## 0.4.1 - 2026-09-10

- Ping monitor cards can be rearranged: drag the ⋮⋮ handle, or use the
  ⤒ ▲ ▼ ⤓ buttons to move a card to the top, up, down or to the bottom. The
  order is remembered.

## 0.4.0 - 2026-09-10

Ping monitor works like PingPlotter.

- Each watched address now shows its **route**: one row per hop with address,
  name, average / minimum / current reply time, loss and a small recent-samples
  graph, refreshed continuously alongside the end-to-end chart. The last row is
  the destination and always matches the big chart. Silent hops are dimmed,
  hops that stopped answering are greyed, routers that answer from several
  addresses (load balancing) are marked instead of counted as changes, and
  real route changes are counted and announced. Route on/off per address.
- **Collapsible cards**: click a card header (or its chevron) to collapse it to
  one line with the current reply time, loss and hop count; state is remembered.
  Collapse all / Expand all buttons.
- The separate "Trace the route" section and the scan-row Trace button are
  gone; watching an address covers it.
- Hop probing is designed to stay light: rounds are skipped rather than
  queued when the machine is busy, hops that never answer are probed less
  often, and the route is re-checked every 5 minutes and when an outage starts.
- CSV export of a watched address now ends with a snapshot of its route.
- Speed test: the last five servers you tested against appear as clickable chips under the address field (and as suggestions while typing); the last one used is pre-filled.

## 0.3.0 - 2026-09-10

LinkTest becomes a network toolbox. Four tabs: Speed test, Scan network,
Ping monitor, DNS lookup.

- **Scan network**: finds the devices on your network (own subnet filled in;
  ranges/CIDR accepted, up to 4096 addresses) and checks an editable list of
  common ports. Shows address, name, maker (bundled MAC vendor table), MAC,
  ping time and open ports with service names; devices seen only via ARP are
  included. Progress, cancel with partial results, sort, "only answering"
  filter, CSV export, and one-click hand-off to Watch / Trace / DNS.
- **Ping monitor**: watch many addresses continuously (interval per address,
  default 1 s) with a live reply-time chart, average/best/worst/jitter/loss,
  outage detection (3 misses) with a red card and a short sound (mutable),
  time windows 5 min to 24 h, rename/pause/reset/remove, CSV export. History
  is written to daily files per address and kept 30 days; targets and today's
  samples come back after a restart. Laptop sleep shows as a gap, not an
  outage.
- **Traceroute**: hop-by-hop route with names and three timings per hop,
  streamed live.
- **DNS lookup**: A, AAAA, CNAME, MX, NS, TXT, SOA, SRV, CAA, PTR or all
  common records; reverse lookups for addresses; ask this computer's server,
  Cloudflare, Google, Quad9 or your own, side by side with differences
  highlighted; shows cache time, response time and whether TCP was needed.
- All of it works without administrator rights and without external tools:
  Windows uses the IP Helper API, Linux uses unprivileged ICMP sockets (or the
  system `ping` if the kernel refuses), DNS is a built-in client.
- New documents: `ARCHITECTURE.md` and `REQUIREMENTS.md`. `fetch-iperf3.py`
  became `fetch-helpers.py` and also fetches the vendor table.

## 0.2.1 - 2026-09-08

- Past tests can be given a name: open a test, type a name, Save name. The
  name shows in the Past tests list and is used in export filenames.

## 0.2.0 - 2026-09-08

Self-contained and offline.

- iperf3 3.21 is bundled inside the executable (Windows: ar51an build with the
  Cygwin runtime; Linux: userdocs static build). The runtime download flow and
  every network call other than the test itself are gone.
- The UI opens in its own native window (pywebview: WebView2 on Windows, Qt on
  Linux) instead of launching Edge/Chrome. The app exits when the last window
  closes; launching it again while it runs opens a second window on the same
  instance.
- Save as CSV / Save full report use a native Save dialog.
- Firewall helper on Linux too: ufw or firewalld via a polkit prompt, with the
  exact `sudo` commands shown when no prompt is possible. Windows keeps the
  administrator-prompt flow.
- Single-file builds for Windows x64 (`dist/win64/LinkTest.exe`) and Linux
  x86_64 (`dist/linux-x86_64/LinkTest`); `build.py --wsl` builds the Linux
  binary from Windows through WSL. `fetch-iperf3.py` pins the bundled
  binaries by SHA-256.
- Parser: an empty `end` event after an iperf3 error no longer overwrites the
  error verdict. Heartbeat watchdog only applies to `--browser` mode and never
  closes the app while a test or listener is running.

## 0.1.0 - 2026-09-08

Initial version.

- Client and server modes with plain-language labels and quick-pick presets.
- Full iperf3 option coverage under Advanced, plus free-text extra arguments.
- Live speed, per-interval chart (bidirectional aware), running stats.
- Plain-English verdict with link-speed comparison, retransmit/loss/jitter
  assessment and steadiness note.
- Local history with re-run, CSV export, full JSON report export.
- One-click iperf3 download on Windows; use-existing-binary option.
- Windows Firewall helper for server mode.
- App-window launcher (Edge/Chrome) with automatic shutdown when closed;
  PyInstaller build script.
