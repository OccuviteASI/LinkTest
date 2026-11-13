#!/usr/bin/env python3
"""The progress window for "Update LinkTest" (tray menu and About).

Runs updater.py in the background with no console window, turns its output into
a progress bar and a one-line status, and keeps the full log under "Show details".
Options are passed on to updater.py (--exe, --have, --pid, --port, --force ...).
It is its own process so it outlives LinkTest, which the update closes.

Without Tk the update still runs, silently, logging to dist/update.log.
"""
from __future__ import annotations

import os
import queue
import re
import subprocess
import sys
import threading

ROOT = os.path.dirname(os.path.abspath(__file__))
UPDATER = os.path.join(ROOT, "updater.py")
IS_WINDOWS = sys.platform == "win32"
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
LOG_FILE = os.path.join(ROOT, "dist", "update.log")

# (pattern in the updater / build output, progress %, status shown)
STAGES: list[tuple[str, int, str]] = [
    (r"checking .* for updates", 4, "Checking GitHub for updates…"),
    (r"updated \w+ -> \w+", 10, "Downloaded the latest version"),
    (r"source is already up to date", 10, "The source is up to date"),
    (r"installed build:", 12, "Preparing the update…"),
    (r"installing build packages", 14, "Installing build packages…"),
    (r"closing the running LinkTest", 30, "Closing LinkTest…"),
    (r"building LinkTest", 34, "Building LinkTest (a minute or two)…"),
    (r"^Done in \d+s", 90, "Build finished"),
    (r"installing the new version", 93, "Installing the new version…"),
    (r"\[update\] starting ", 97, "Starting LinkTest…"),
]
# While pip / PyInstaller print lines, creep forward inside the current stage.
CREEP_LIMIT = {14: 28, 34: 88}


def parse_line(line: str, percent: int) -> tuple[int, str | None, str | None]:
    """(percent, new status or None, outcome or None); outcome is ok / current / failed."""
    text = line.strip()
    if "UPDATE FAILED" in text:
        reason = text.split("FAILED", 1)[1].lstrip(": ").strip().replace("messages above", "details below")
        return percent, f"Update failed: {reason or 'see the details below'}", "failed"
    if "UPDATE OK" in text:
        m = re.search(r"build (\S+)( \(([^)]+)\))?", text)
        what = f" {m.group(3)} (build {m.group(1)})" if m and m.group(3) else (f" (build {m.group(1)})" if m else "")
        return 100, f"LinkTest is updated to{what}." if what else "LinkTest is updated.", "ok"
    if "nothing to do" in text:
        m = re.search(r"already build (\S+?):", text)
        return 100, f"LinkTest is already the latest version{f' (build {m.group(1)})' if m else ''}.", "current"
    for pattern, pct, status in STAGES:
        if re.search(pattern, text):
            return max(percent, pct), status, None
    for start, limit in CREEP_LIMIT.items():
        if start <= percent < limit - 1 and text and _creep_tick():
            return percent + 1, None, None
    return percent, None, None


_tick = [0]


def _creep_tick() -> bool:
    # PyInstaller prints a few hundred lines; move one percent every 6 of them
    _tick[0] += 1
    return _tick[0] % 6 == 0


def error_line(line: str) -> bool:
    """A line naming the cause of a failure (pip, git, PyInstaller and Python errors)."""
    text = line.strip()
    return bool(re.match(r"(ERROR|error|fatal|\w+Error)\b[:\s]", text)) and "FAILED" not in text


def console_python() -> str:
    """python.exe rather than pythonw.exe, so the update's child processes share one hidden console."""
    exe = sys.executable
    if os.path.basename(exe).lower() == "pythonw.exe":
        alt = os.path.join(os.path.dirname(exe), "python.exe")
        if os.path.exists(alt):
            return alt
    return exe


def start_update(args: list[str]) -> subprocess.Popen:
    env = dict(os.environ, PYTHONUNBUFFERED="1", PYTHONUTF8="1", PYTHONIOENCODING="utf-8")
    return subprocess.Popen([console_python(), "-u", UPDATER, *args], cwd=ROOT, env=env,
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            creationflags=NO_WINDOW)


class UpdateWindow:
    def __init__(self, args: list[str]):
        import tkinter as tk
        from tkinter import ttk
        from tkinter.scrolledtext import ScrolledText

        self.args = args
        self.lines: queue.Queue[str | None] = queue.Queue()
        self.percent, self.outcome, self.proc = 0, None, None
        self.last_error = ""
        self.running = True
        self.log_lines: list[str] = []

        _dpi_aware()
        root = self.root = tk.Tk()
        root.title("Updating LinkTest")
        root.resizable(True, False)
        root.minsize(480, 0)
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        _set_icon(root)

        frame = ttk.Frame(root, padding=(18, 16, 18, 14))
        frame.pack(fill="both", expand=True)
        font = ("Segoe UI", 12, "bold") if IS_WINDOWS else ("TkDefaultFont", 12, "bold")
        self.title = ttk.Label(frame, text="Updating LinkTest", font=font)
        self.title.pack(anchor="w")
        self.status = ttk.Label(frame, text="Starting…", wraplength=520, justify="left")
        self.status.pack(anchor="w", pady=(6, 10), fill="x")
        self.bar = ttk.Progressbar(frame, mode="determinate", maximum=100, length=520)
        self.bar.pack(fill="x")
        buttons = ttk.Frame(frame)
        buttons.pack(fill="x", pady=(14, 0))
        self.details_btn = ttk.Button(buttons, text="Show details", command=self.toggle_details)
        self.details_btn.pack(side="left")
        self.close_btn = ttk.Button(buttons, text="Run in background", command=self.on_close)
        self.close_btn.pack(side="right")
        self.log = ScrolledText(frame, height=14, width=80, wrap="word", state="disabled",
                                font=("Consolas", 9) if IS_WINDOWS else ("TkFixedFont", 9))
        self.details_shown = False

        root.update_idletasks()
        x = (root.winfo_screenwidth() - root.winfo_width()) // 2
        y = (root.winfo_screenheight() - root.winfo_height()) // 3
        root.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        root.lift()
        root.attributes("-topmost", True)
        root.after(800, lambda: root.attributes("-topmost", False))

    def start(self) -> None:
        try:
            self.proc = start_update(self.args)
        except OSError as exc:
            self.lines.put(f"[update] UPDATE FAILED: could not start the updater: {exc}")
            self.lines.put(None)
            return
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self) -> None:
        assert self.proc is not None and self.proc.stdout is not None
        for raw in self.proc.stdout:
            self.lines.put(raw.decode("utf-8", errors="replace").rstrip())
        self.proc.wait()
        self.lines.put(None)

    def poll(self) -> None:
        try:
            while True:
                line = self.lines.get_nowait()
                if line is None:
                    self.finish(self.proc.returncode if self.proc else 1)
                    return
                self.add_log(line)
                if error_line(line):
                    self.last_error = re.sub(r"^(ERROR|error):\s*", "", line.strip())
                self.percent, status, outcome = parse_line(line, self.percent)
                self.bar["value"] = self.percent
                if outcome == "failed":
                    if self.outcome != "failed":   # the first failure is the cause
                        self.status["text"] = status
                    self.outcome = outcome
                elif status and self.outcome != "failed":
                    self.status["text"] = status
                    self.outcome = outcome or self.outcome
        except queue.Empty:
            pass
        self.root.after(100, self.poll)

    def finish(self, rc: int) -> None:
        self.running = False
        _write_log(self.log_lines)
        if rc != 0 and self.outcome != "failed":
            self.outcome = "failed"
            self.status["text"] = (f"Update failed: {self.last_error}" if self.last_error
                                   else f"Update failed (exit code {rc}); see the details below.")
        if self.outcome == "failed":
            self.title["text"] = "LinkTest update failed"
            self.root.title("LinkTest update failed")
            if not self.details_shown:
                self.toggle_details()
            self.add_log("\nLinkTest keeps running the previous version. Send the lines above if you need help.")
        else:
            self.bar["value"] = 100
            self.title["text"] = "LinkTest is up to date" if self.outcome == "current" else "LinkTest updated"
            self.root.title(self.title["text"])
        self.close_btn["text"] = "Close"
        if self.root.state() == "withdrawn":   # hidden while running: nothing left to show
            self.root.destroy()

    def add_log(self, line: str) -> None:
        self.log_lines.append(line)
        self.log.configure(state="normal")
        self.log.insert("end", line + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def toggle_details(self) -> None:
        if self.details_shown:
            self.log.pack_forget()
            self.root.resizable(True, False)
        else:
            self.log.pack(fill="both", expand=True, pady=(12, 0))
            self.root.resizable(True, True)
        self.details_shown = not self.details_shown
        self.details_btn["text"] = "Hide details" if self.details_shown else "Show details"

    def on_close(self) -> None:
        if not self.running:
            self.root.destroy()
            return
        self.root.withdraw()   # keep reading its output so the update can finish

    def run(self) -> int:
        self.start()
        self.root.after(100, self.poll)
        self.root.mainloop()
        return 0 if self.outcome in ("ok", "current") else 1


def _write_log(lines: list[str]) -> None:
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    except OSError:
        pass


def _dpi_aware() -> None:
    if IS_WINDOWS:
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass


def _set_icon(root) -> None:
    try:
        import tkinter as tk
        img = tk.PhotoImage(file=os.path.join(ROOT, "assets", "linktest.png"))
        root.iconphoto(True, img)
        root._icon = img
    except Exception:
        pass


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        import tkinter  # noqa: F401
        window = UpdateWindow(args)
    except Exception:   # no Tk or no display: update without a window
        proc = start_update(args)
        out = [raw.decode("utf-8", errors="replace").rstrip() for raw in proc.stdout]
        proc.wait()
        _write_log(out)
        return proc.returncode
    return window.run()


if __name__ == "__main__":
    sys.exit(main())
