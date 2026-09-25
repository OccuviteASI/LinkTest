# LinkTest

A friendly network toolbox for people who are not network engineers. Six
tabs in one window:

| Tab | What it does |
|---|---|
| **Speed test** | A front end for [iperf3](https://github.com/esnet/iperf): measure how fast two computers can move data, with plain-language options, live graphs and a readable verdict. |
| **Scan network** | Find the devices on your network and see their names, makers, and which common ports are open. |
| **Ping monitor** | Watch one or many addresses over time PingPlotter-style: the route hop by hop with per-hop reply times and loss, the address's own reply-time chart, outage alerts and 30 days of history. |
| **DNS lookup** | Look up any record type for a name (or reverse for an address) against your own DNS server or public ones, side by side. |
| **Packet capture** | Record the traffic on a connection for a set time, then browse it in plain language with easy filters, analyse it into Zeek-style connection and protocol logs with plain-language findings, or hand the file to Wireshark. |
| **Wi‑Fi** | See the networks around you with signal, channel, width and security, a channel-usage chart with the quietest channel, and signal over time. |

**Self-contained and offline.** The executable carries its own copy of iperf3
and a MAC vendor table, opens in its own window, and needs no administrator
rights. Nothing is downloaded, no browser is needed, and no installation is
required: copy `LinkTest.exe` (Windows) or `LinkTest` (Linux) anywhere and
double-click it.

Current version: **0.6.0** (see `CHANGELOG.md`; the number lives in
`linktest.py`). Design notes are in `ARCHITECTURE.md`; the requirements
ledger is `REQUIREMENTS.md`.

## The tools

### Scan network
The range is pre-filled with your own network; type another range such as
`192.168.1.1-254` or `10.0.0.0/24` (up to 4096 addresses). The port list
defaults to the usual suspects (web, SSH, Remote Desktop, file sharing, printers,
databases, iperf3) and can be edited. Results show address, name, maker (from
the MAC address), ping time and open ports, and can be sorted, filtered to
answering devices, and saved as CSV. Each row has Watch / ARP / DNS buttons that
hand the device to the other tools. A list of this computer's networks with a
**Use this network** button fills the range for you.

Below the results, the **ARP / MAC** card shows every hardware address this
computer knows (maker, factory vs private/randomised address, dynamic or
static, which connection, whether the last scan saw it) and lets you look up
a MAC (maker, type, the IPs it answers for) or an IP (one ping, then its MAC,
maker and name). It warns when one MAC answers for several IPs or one IP has
been seen with two MACs. A **Commands** block runs the usual ARP commands for
you (show table, show neighbours, clear cache, delete entry, add static
entry) with the command line shown next to each button; the admin ones ask
for the Windows administrator prompt.

### Ping monitor
Type an address or name, optionally a label, choose how often to check, press
Watch. Paste a web address (https://…) to check a web page like Uptime Robot
(up when it answers 2xx/3xx, with the HTTP status and response time), or
`host:port` (or pick Port) to check that a port accepts connections; service
checks default to every 30 seconds and show uptime %. Each address gets a card that works like PingPlotter: a route table
with one row per hop (address, name, average / minimum / current reply time,
loss, and a small graph of recent samples), refreshed continuously, and below
it the address's own reply-time chart with average/best/worst/jitter, loss and
outage counts. The last row of the table is the destination and always matches
the chart. After three missed replies the card turns red and a short sound
plays (Sound on/off per card); it turns back when replies return. Click a
card's header to collapse it to one line; Collapse all / Expand all sit next to
the add row. Route on/off per card. Windows of 5 min to 24 h; history is kept
in daily files for 30 days and can be saved as CSV (with a route snapshot).
Watching continues while LinkTest is open and resumes when you start it again.

Reading the route table: loss at a middle hop that does not continue to the
hops after it is that router limiting how often it replies, not a real
problem. A hop that answers from several addresses is a load-balanced router
and is marked as such rather than counted as a route change.

### DNS lookup
Enter a name (or an address for a reverse lookup), pick a record type or "All
common records", and choose which servers to ask: this computer's own server,
Cloudflare, Google, Quad9 or any address you add. Answers appear in one column
per server with cache time, response time and whether the query needed TCP;
rows that differ between servers are highlighted.

### Packet capture
Pick the network connection, what to record (everything, web, DNS, pings, TCP,
UDP or ARP, optionally one address and/or port), how long (30 s to 15 min or
until you stop it) and a size cap, then press Start. While recording you see
counters, a progress bar and the latest packets described in plain language.
Afterwards the viewer shows a summary, the busiest addresses, filters by type /
address / port / word, and a plain-language breakdown of any packet with its
raw bytes. Recordings are kept in the Saved captures list (rename, delete,
save a copy, Open in Wireshark when it is installed) and you can open .pcap
or .pcapng files made elsewhere.

**Connections & findings** turns a capture into Zeek-style logs: one line per
connection (who, how long, how much, how it ended), and logs for DNS, web,
TLS, certificates, files, QUIC, SSH, DHCP, FTP, NTP and software versions,
all linked by a connection ID. A "What stands out" list explains problems in
plain language (failing connections, packet loss, DNS trouble, bad
certificates, old encryption, cleartext passwords, rogue DHCP, IP conflicts,
scans). Save the logs in Zeek's format or as JSON for Zeek tools, Splunk or
Elastic, or from a terminal: `LinkTest --zeek-logs capture.pcapng`.

On Windows, recording uses Npcap when Wireshark or Npcap is installed and
needs no permission prompt. Without it, LinkTest uses Windows' built-in raw
capture, which asks for administrator permission once per recording and sees
IPv4 traffic only. On Linux the recording helper runs through a password
prompt (polkit); without one, the `sudo` command to run is shown.

### Wi‑Fi
Open the tab and the adapter scans every few seconds. The table lists each
network with signal bars and dBm, channel and band, channel width, security,
Wi‑Fi standard, maker and when it was last heard; your connected network is
highlighted with its link speed. The **Channels in use** chart draws one
shape per network (width = the channel width it occupies, height = signal) so
you can see what overlaps what, and a hint names the quietest channel on each
band. Tick networks to plot their signal over time. One button stops and
restarts scanning. Scanning only runs while
the tab is open because it briefly takes the radio off your channel. Windows
needs no administrator rights or Location permission for this; Linux needs
NetworkManager (`nmcli`) or `iw`.

## Using the speed test

1. On one computer choose **Be the test target** and press Start. Note the
   address it shows. Press **Allow through the firewall** once if the other
   computer cannot connect.
2. On the other computer choose **Test my connection**, type that address, and
   press Start. Recently used addresses are offered as chips, and a list of
   public iperf3 servers in the USA fills in an internet target with the
   right port; those measure your internet connection rather than your LAN
   and are shared; when one is busy LinkTest keeps trying every few seconds
   (rotating through the server's ports) for up to two minutes, and Stop gives
   up. Public servers are not added to the Recent chips. Every listed server was tested before it went
   in; run `python tools/check_public_servers.py` to re-test the list before
   changing it.
3. Read the result: speed, retransmits or packet loss, jitter, and a
   plain-English verdict. Every test is kept under **Past tests** and can be
   re-run or saved as CSV or a full report.

Quick picks: *Quick check*, *Max out the link* (8 connections), *Both
directions* (`--bidir`), *Voice & video quality* (UDP with jitter and loss).
Every other iperf3 option is under **Advanced options**, and the exact command
line is shown under **Show the iperf3 command this runs**.

### What each build needs

| Build | Runs on | Needs |
|---|---|---|
| `dist/win64/LinkTest.exe` (~40 MB) | Windows 10/11, 64-bit | The WebView2 runtime, which is part of Windows 11 and of any Windows 10 kept up to date. |
| `dist/linux-x86_64/LinkTest` (~200 MB) | Linux x86_64 with a desktop session (X11 or Wayland) | glibc 2.43 or newer (Ubuntu 26.04 era; rebuild on an older distro for older targets) and the usual desktop libraries Qt applications use. First start takes a few seconds while the file unpacks itself to `/tmp`. |
| `dist/mac-arm64/LinkTest.app` or `dist/mac-x86_64/LinkTest.app` | macOS 12 or newer, same CPU type as the Mac it was built on | Nothing extra (WKWebView is part of macOS). Ad-hoc signed: right-click → Open the first time. See `MACOS.md`. |

Settings and history live in `%LOCALAPPDATA%\LinkTest` (Windows),
`~/.config/linktest` (Linux) or `~/Library/Application Support/LinkTest` (macOS).

### Firewall button

- Windows adds inbound TCP+UDP rules for the chosen port with `netsh` after
  the normal administrator prompt.
- Linux uses `ufw` or `firewalld`, asking for your password through polkit.
  If no prompt is possible (no polkit agent, SSH session), the exact `sudo`
  commands are shown with a Copy button.
- macOS has no button: the system asks "accept incoming connections?" by
  itself the first time LinkTest listens for a test.

## Running from source

Python 3.10+ (3.14 tested). `python linktest.py --browser` needs nothing beyond
the standard library and opens a browser tab; the native window needs
`pip install -r requirements.txt` (pywebview, plus PySide6 on Linux).

```bash
python fetch-helpers.py       # once: iperf3 into bin/win64 and bin/linux-x86_64, MAC vendor table into assets/
python linktest.py            # native window
python linktest.py --browser  # browser tab instead
python linktest.py --no-open  # just serve; prints the URL
```

`--port N` pins the UI port, `--verbose` logs HTTP requests and enables the
web inspector.

## Building the executables

PyInstaller cannot cross-compile, so each platform builds its own binary with
the same script:

```bash
python fetch-helpers.py                  # binaries + vendor table, SHA-256 checked
pip install -r requirements.txt
python build.py                          # this platform -> dist/<tag>/
python build.py --wsl                    # Windows: also build Linux inside WSL
./build-mac.sh                           # macOS: venv + iperf3 from source + LinkTest.app (see MACOS.md)
```

**macOS**: copy the source over (`python tools/pack_source.py` makes a zip) and
run `./build-mac.sh` on the Mac. It needs only the Xcode Command Line Tools
and Python 3; iperf3 is compiled from the pinned source tarball so the app
depends on nothing outside macOS. Full instructions, permissions and a smoke
checklist: [MACOS.md](MACOS.md).

`--wsl` copies the tree into WSL (`rsync`, so `/mnt/c` slowness and permission
quirks do not matter), runs `build.py` with the `/opt/linktestbuild` venv, and
copies `dist/linux-x86_64/` back. One-time WSL setup:

```bash
sudo apt install rsync python3-venv libxkbfile1 libnss3 libxkbcommon0 libxkbcommon-x11-0 \
  libegl1 libgl1 libgbm1 libxcb-cursor0 libxcb-icccm4 libxcb-keysyms1 libxcb-shape0 \
  libxcb-image0 libxcb-render-util0 libxcb-xinerama0 libasound2t64 libxcomposite1 \
  libxdamage1 libxrandr2 libxtst6 libfontconfig1 libdbus-1-3
python3 -m venv /opt/linktestbuild
/opt/linktestbuild/bin/pip install -r requirements.txt
```

The library list is what QtWebEngine needs to import during the build (and
what the finished binary expects on the target desktop; any distro with a
graphical session already has them).

Other flags: `--console` keeps a console window on Windows for debugging,
`--onedir` produces a folder build that starts instantly.

## Layout

| File | Purpose |
|---|---|
| `linktest.py` | Entry point: native window (pywebview), local HTTP server + JSON API, settings/history, version |
| `pcaptool.py`, `pcaplogs.py`, `pcapproto.py`, `zeek_tables.py` | Packet capture and the Zeek-style analyzer (see ARCHITECTURE.md) |
| `iperf_runner.py` | Finds the bundled iperf3, builds command lines, runs it, parses `--json-stream` and classic text output, firewall helpers |
| `ui/index.html`, `ui/app.js`, `ui/style.css` | The interface (vanilla JS, no build step, no CDN) |
| `fetch-helpers.py` | Downloads and pins the iperf3 builds into `bin/<platform>/` and the MAC vendor table into `assets/` |
| `build.py` | PyInstaller single-file build, per platform, `--wsl` helper; on macOS produces `LinkTest.app` + zip |
| `build-mac.sh`, `MACOS.md` | One-shot macOS build script and its guide |
| `tools/pack_source.py` | Zips the source tree for moving it to another build machine |
| `bin/<platform>/` | iperf3 binaries (git-ignored) and their licence notes |
| `assets/` | App icon (`tools/make_icon.py` regenerates it) |
| `tools/fake_iperf3.py` | A stand-in iperf3 for UI testing without a network |

## Notes and limits

- The bundled iperf3 is 3.21, so live data uses `--json-stream`. Pointing
  LinkTest at an older system iperf3 (setup box, dev use) falls back to the
  text parser; features that version lacks are hidden or reported clearly.
- Authenticated tests (`--rsa-*`, `--username`) are not exposed; the bundled
  Windows build has no OpenSSL. Use *Extra iperf3 arguments* with an
  auth-enabled build if you need them.
- Third-party licences: iperf3 is BSD-3-Clause; the Windows build ships the
  LGPL Cygwin runtime (`cygwin1.dll`). See `THIRD-PARTY-LICENSES.txt` next to
  each built binary.
