# Building LinkTest on a Mac

LinkTest builds its own binary on each platform (PyInstaller cannot
cross-compile). On a Mac the result is `dist/mac-arm64/LinkTest.app` (Apple
Silicon) or `dist/mac-x86_64/LinkTest.app` (Intel), plus a zip of the app for
sharing. Build on the kind of Mac you want to run on; an Apple Silicon build
does not run on Intel Macs and vice versa.

## 1. What you need on the Mac

| Item | Why | How |
|---|---|---|
| macOS 12 or newer | WKWebView features pywebview relies on | |
| Xcode Command Line Tools | `clang` and `make` to compile iperf3 from source | `xcode-select --install` (a dialog appears; ~1 GB) |
| Python 3.11 or newer | Runs the build. The python.org installer or Homebrew (`brew install python`) both work | `python3 --version` |
| Internet, once | `fetch-helpers.py` downloads the pinned iperf3 source tarball (0.7 MB); `pip` downloads pywebview, PyObjC and PyInstaller | |

Nothing else. No Homebrew packages are bundled: iperf3 is compiled without
OpenSSL so the finished app depends only on macOS itself.

## 2. Get the source onto the Mac

On the Windows machine, from the LinkTest folder:

```bash
python tools/pack_source.py
```

That writes `dist/LinkTest-src-<version>.zip` (source only: no built
binaries, no caches). Copy it to the Mac (AirDrop, USB, a share) and unzip it,
for example into `~/LinkTest`. A `git clone` of the repository is the same
thing if you keep one.

## 3. Build

```bash
cd ~/LinkTest
chmod +x build-mac.sh
./build-mac.sh
```

The script:

1. checks for the Xcode Command Line Tools,
2. creates `.venv/` and installs `requirements.txt` (pywebview, PyObjC,
   CoreWLAN, PyInstaller),
3. runs `python fetch-helpers.py mac` — downloads `iperf-3.21.tar.gz`, checks
   its SHA-256, compiles it (`./configure --disable-shared --without-openssl`,
   `make`), strips and ad-hoc signs it into `bin/mac-<arch>/iperf3`, and runs
   `iperf3 --version` to prove it works,
4. runs `python build.py`, which produces the app, writes the usage
   descriptions macOS wants into `Info.plist`, ad-hoc signs the bundle and
   zips it with `ditto`.

Expect about two minutes the first time. Output:

```
dist/mac-arm64/LinkTest.app              the app
dist/mac-arm64/LinkTest-0.8.0-mac-arm64.zip   the same app zipped for sharing
dist/mac-arm64/LinkTest                  bare one-file executable (terminal debugging)
dist/mac-arm64/VERSION.txt, THIRD-PARTY-LICENSES.txt
```

Doing it by hand instead of the script:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt pillow
python fetch-helpers.py mac
python build.py                 # add --console to keep a terminal window, --onedir for a folder build
```

## 4. First launch (Gatekeeper)

The app is signed with an ad-hoc signature, not an Apple Developer ID, so
the first double-click says it cannot be opened. Either:

- right-click `LinkTest.app` → **Open**, then **Open** again in the dialog
  (once per Mac), or
- in Terminal: `xattr -dr com.apple.quarantine dist/mac-arm64/LinkTest.app`

For handing the app to other people without that step you need an Apple
Developer account: sign with `codesign --deep --force --options runtime
--sign "Developer ID Application: …" LinkTest.app` and notarize with `xcrun
notarytool submit … --wait` then `xcrun stapler staple`. Nothing in the build
prevents that; it is just not automated here.

## 5. Permissions macOS will ask for

| When | Prompt | Why |
|---|---|---|
| First **Be the test target** | "Accept incoming network connections?" | macOS application firewall; there is no LinkTest firewall button on macOS because this prompt does the job |
| First scan / ping of the local network | "LinkTest would like to find and connect to devices on your local network" | Local Network privacy (macOS 15+) |
| Wi‑Fi tab | Network names show as hidden until Location Services is allowed | macOS 14+ hides SSIDs/BSSIDs from apps without Location access: System Settings → Privacy & Security → Location Services → LinkTest |
| Packet capture, ARP admin commands | Password dialog | Capture needs `/dev/bpf*`; `arp -d`/`arp -s` need root. Installing Wireshark's **ChmodBPF** makes capture work without the password |

## 6. Where things live on macOS

- Settings, history, ping history, captures: `~/Library/Application Support/LinkTest/`
- Bundled iperf3 inside the app: `LinkTest.app/Contents/Frameworks/bin/iperf3`
  (PyInstaller 6 layout; older versions used `Contents/MacOS/bin`)

## 7. Smoke checklist after the first Mac build

This port was written and unit-checked on Windows against sample macOS
command output, but has not yet been run on a Mac. Run through this list
and note anything that misbehaves:

1. App opens in its own window; About → version shows 0.8.0.
2. Speed test: **Be the test target** → firewall prompt → allow. From another
   computer, test against the Mac. Then the reverse: pick a public server.
3. Scan network: the network list shows `Wi‑Fi (en0) – 192.168.x.0/24`;
   a scan finds devices with makers; the ARP card lists the gateway with
   `en0` as the connection; **Show table** prints `arp -an` output;
   **Clear cache** shows the password dialog and then "Done".
4. Ping monitor: add the gateway and 8.8.8.8; hop rows appear (route via
   `ping -m`), latency chart moves.
5. DNS lookup: system servers listed (from `/etc/resolv.conf`).
6. Packet capture: connections list `en0` and the loopback; a 30 s capture
   asks for the password (or none with ChmodBPF) and shows packets;
   **Open in Wireshark** works if Wireshark is in /Applications.
7. Wi‑Fi: networks appear within ~5 s; if names show as hidden, grant
   Location Services and rescan.
8. Quit: closing the window exits the process (`ps aux | grep LinkTest`).

Terminal debugging: run the bare executable
`dist/mac-arm64/LinkTest --verbose` to see logs, or from source
`source .venv/bin/activate && python linktest.py --verbose`.

## 8. Troubleshooting

- **"xcrun: error: invalid active developer path"**: the command line tools
  are missing → `xcode-select --install`.
- **`pip install` fails on pyobjc**: use Python 3.11–3.13 from python.org if
  the Homebrew Python is very new and no wheel exists yet.
- **Build says `bin/mac-arm64/ is missing iperf3`**: run
  `python fetch-helpers.py mac` (needs the command line tools).
- **App bounces and closes**: run `dist/mac-*/LinkTest --console` build or
  the bare executable from Terminal to read the error; the usual cause is a
  missing PyObjC framework, fixed by `pip install -r requirements.txt` in the
  venv used for the build.
- **Wi‑Fi tab shows "system_profiler"**: `pyobjc-framework-CoreWLAN` was not
  installed when building; install it and rebuild.
