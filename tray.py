"""System-tray icon for the native window (pystray).

Minimizing the window hides it to the tray (and, if chosen in About, so does
closing it); the icon's menu has Open LinkTest, Update LinkTest and Quit.
Clicking the icon opens the window again. The X11 tray has no menu (pystray
limitation): there Update and Quit are in About.

Windows uses pystray's win32 backend. Linux uses the X11 tray (the
"system tray" of KDE, Xfce, Cinnamon, MATE; GNOME needs the AppIndicator
extension); when no tray is there, `ok` stays False and minimizing behaves
normally, so a window can never be hidden with no way back. macOS has no
tray icon here (the Dock already keeps the app).
"""
from __future__ import annotations

import os
import sys
import threading
from typing import Callable


class Tray:
    def __init__(self, icon_file: str | None, on_open: Callable[[], None], on_update: Callable[[], None],
                 on_quit: Callable[[], None], update_label: Callable[[], str | None]):
        self.icon_file = icon_file
        self.on_open, self.on_update, self.on_quit = on_open, on_update, on_quit
        self.update_label = update_label        # None hides the menu item
        self.icon = None
        self.ok = False                         # the icon is really in a tray
        self.backend = ""
        self.has_menu = False
        self._ready = threading.Event()

    # -- start / stop --------------------------------------------------------
    def start(self, timeout: float = 5.0) -> bool:
        """Show the icon from its own thread; True when it is docked in a tray."""
        if sys.platform == "darwin":
            return False
        if sys.platform.startswith("linux"):
            if not os.environ.get("DISPLAY"):
                return False
            os.environ.setdefault("PYSTRAY_BACKEND", "xorg")   # AppIndicator would run a GTK loop next to Qt's
        try:
            import pystray
            from PIL import Image
        except Exception:
            return False
        try:
            image = Image.open(self.icon_file) if self.icon_file else Image.new("RGBA", (64, 64), (42, 120, 214, 255))
            image.load()
        except Exception:
            image = Image.new("RGBA", (64, 64), (42, 120, 214, 255))
        item = pystray.MenuItem
        menu = pystray.Menu(
            item("Open LinkTest", self._open, default=True),
            item(lambda _i: self.update_label() or "Update LinkTest", self._update,
                 visible=lambda _i: self.update_label() is not None),
            pystray.Menu.SEPARATOR,
            item("Quit LinkTest", self._quit),
        )
        try:
            self.icon = pystray.Icon("LinkTest", image, "LinkTest", menu)
        except Exception:
            return False
        self.backend = type(self.icon).__module__.rsplit(".", 1)[-1].lstrip("_")
        self.has_menu = bool(getattr(self.icon, "HAS_MENU", False))
        threading.Thread(target=self._run, name="tray", daemon=True).start()
        self._ready.wait(timeout)
        return self.ok

    def _run(self) -> None:
        def setup(icon):
            try:
                icon.visible = True
                # X11: docked only when a tray (systray selection owner) took the icon
                self.ok = self.backend == "win32" or getattr(icon, "_systray_manager", None) is not None
                if self.backend == "xorg":
                    # pystray's X11 icon window does not ask for button presses, so clicks never arrive
                    import Xlib.X
                    icon._window.change_attributes(event_mask=Xlib.X.ExposureMask | Xlib.X.StructureNotifyMask
                                                   | Xlib.X.ButtonPressMask)
                    icon._display.flush()
            except Exception:
                self.ok = False
            self._ready.set()
        try:
            self.icon.run(setup=setup)
        except Exception:
            self.ok = False
            self._ready.set()

    def stop(self) -> None:
        if self.icon is not None:
            try:
                self.icon.stop()
            except Exception:
                pass

    # -- helpers ---------------------------------------------------------------
    def refresh(self) -> None:
        if self.icon is not None:
            try:
                self.icon.update_menu()
            except Exception:
                pass

    def set_title(self, text: str) -> None:
        if self.icon is not None:
            try:
                self.icon.title = text[:120]
            except Exception:
                pass

    def notify(self, message: str) -> None:
        if self.icon is not None and getattr(self.icon, "HAS_NOTIFICATION", False):
            try:
                self.icon.notify(message, "LinkTest")
            except Exception:
                pass

    # -- menu actions (run on the tray thread: hand off quickly) -----------------
    def _open(self, *_a) -> None:
        threading.Thread(target=self.on_open, daemon=True).start()

    def _update(self, *_a) -> None:
        threading.Thread(target=self.on_update, daemon=True).start()

    def _quit(self, *_a) -> None:
        threading.Thread(target=self.on_quit, daemon=True).start()
