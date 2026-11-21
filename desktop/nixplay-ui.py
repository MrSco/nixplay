#!/usr/bin/env python3
"""Native GTK3 + WebKit2GTK Control Center window for NixPlay.

Single instance: launching it while a window is already open (tray click, app menu,
`nixplay serve --open`) just brings the existing window to the front.

Usage: nixplay-ui.py [URL] [DAEMON_PID]
"""
import os
import sys

import gi

gi.require_version("Gtk", "3.0")
gi.require_version("WebKit2", "4.1")
from gi.repository import Gdk, Gio, GLib, Gtk, WebKit2

APP_ID = "dev.nixplay.ControlCenter"


class ControlCenter(Gtk.Application):
    def __init__(self, url, daemon_pid):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.FLAGS_NONE)
        self.url = url
        self.daemon_pid = daemon_pid
        self.window = None

    def do_activate(self):
        # Runs in the first instance only; later launches are forwarded here by D-Bus.
        if self.window is None:
            self.window = self.build_window()
            self.window.show_all()
        else:
            self.raise_window()

    def build_window(self):
        win = Gtk.ApplicationWindow(application=self, title="NixPlay — AirPlay")
        win.set_icon_name("nixplay")
        win.set_default_size(940, 640)
        win.set_position(Gtk.WindowPosition.CENTER)

        webview = WebKit2.WebView()
        webview.get_settings().set_enable_developer_extras(False)
        webview.set_background_color(Gdk.RGBA(0.043, 0.055, 0.078, 1.0))
        webview.load_uri(self.url)
        win.add(webview)

        def on_key(_widget, event):
            if event.keyval == Gdk.KEY_Escape:
                win.close()
                return True
            return False

        win.connect("key-press-event", on_key)

        # Close automatically when the NixPlay daemon / tray exits.
        if self.daemon_pid:
            def check_daemon():
                try:
                    os.kill(self.daemon_pid, 0)
                    return True
                except OSError:
                    win.close()
                    return False

            GLib.timeout_add(750, check_daemon)
        return win

    def raise_window(self):
        win = self.window
        win.deiconify()
        win.show_all()
        # Some window managers ignore present() from a background activation without this.
        win.set_keep_above(True)
        win.present()
        GLib.timeout_add(300, lambda: win.set_keep_above(False) and False)


def main():
    url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:17420"
    daemon_pid = int(sys.argv[2]) if len(sys.argv) > 2 else None
    # Match the installed nixplay.desktop so the taskbar shows the NixPlay penguin, not "python3"
    GLib.set_prgname("nixplay")
    GLib.set_application_name("NixPlay")
    # Our own arguments aren't files for GApplication to open, so don't pass them on.
    return ControlCenter(url, daemon_pid).run([sys.argv[0]])


if __name__ == "__main__":
    sys.exit(main())
