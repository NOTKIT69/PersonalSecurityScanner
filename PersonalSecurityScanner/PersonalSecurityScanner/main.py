"""
main.py
-------
Entry point for Personal Security Scanner.

Wires together settings, themes, history, the scanner (run in a background
thread so the GUI never freezes), and the CustomTkinter screens defined in
ui.py.

This application is strictly a PASSIVE, educational security inspector:
it only ever contacts the single website URL the user types in, using
ordinary read-only HTTP/TLS requests (the same requests any web browser
makes). It performs no brute forcing, exploitation, port scanning, or
denial-of-service behaviour of any kind.
"""

import os
import sys
import threading
import subprocess
import platform
import tkinter as tk

import customtkinter as ctk

from settings import Settings
from themes import get_theme
from history import HistoryManager
import scanner
import report as report_mod

import ui

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ASSETS_DIR = os.path.join(BASE_DIR, "assets")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")


class SplashScreen(ctk.CTkToplevel):
    """Brief branded splash shown while the main window initializes."""

    def __init__(self, master, theme, on_done):
        super().__init__(master)
        self.overrideredirect(True)
        w, h = 420, 280
        self.geometry(f"{w}x{h}+{(self.winfo_screenwidth() - w) // 2}+{(self.winfo_screenheight() - h) // 2}")
        self.configure(fg_color=theme["bg"])
        self.attributes("-topmost", True)

        ctk.CTkLabel(self, text="🛡️", font=ctk.CTkFont(size=72)).pack(pady=(50, 10))
        ctk.CTkLabel(
            self, text="Personal Security Scanner",
            font=ctk.CTkFont(size=20, weight="bold"), text_color=theme["text"],
        ).pack()
        ctk.CTkLabel(
            self, text="Passive & educational security auditing",
            font=ctk.CTkFont(size=12), text_color=theme["text_muted"],
        ).pack(pady=(4, 20))
        self.progress = ctk.CTkProgressBar(self, width=280, progress_color=theme["accent"], fg_color=theme["input_bg"])
        self.progress.set(0)
        self.progress.pack()

        self._step = 0
        self._on_done = on_done
        self.after(30, self._animate)

    def _animate(self):
        self._step += 1
        self.progress.set(min(1.0, self._step / 30))
        if self._step >= 30:
            self.destroy()
            self._on_done()
        else:
            self.after(20, self._animate)


class App(ctk.CTk):
    """Main application window / controller for all screens."""

    def __init__(self):
        super().__init__()
        self.withdraw()  # hide main window until splash finishes

        self.settings = Settings()
        self.theme = get_theme(self.settings.get("theme"))
        ctk.set_appearance_mode(self.theme.get("mode", "dark"))

        self.history_manager = HistoryManager(REPORTS_DIR)

        self.title("Personal Security Scanner")
        self.geometry(self.settings.get("window_size", "1200x760"))
        self.minsize(980, 640)
        self.configure(fg_color=self.theme["bg"])

        icon_path = os.path.join(ASSETS_DIR, "logo.png")
        try:
            if os.path.exists(icon_path):
                self._icon_image = tk.PhotoImage(file=icon_path)
                self.iconphoto(True, self._icon_image)
        except Exception:
            pass  # icon is cosmetic only — never fatal if it can't load

        self.current_frame_name = None
        self._active_scan_thread = None
        self._last_result = None

        self._build_frames()
        self._bind_shortcuts()

        splash = SplashScreen(self, self.theme, on_done=self._reveal_main_window)

    # ------------------------------------------------------------------ #
    # Startup / window management
    # ------------------------------------------------------------------ #

    def _reveal_main_window(self):
        self.deiconify()
        self.go_home()

    def _build_frames(self):
        self.container = ctk.CTkFrame(self, fg_color="transparent")
        self.container.pack(fill="both", expand=True)

        self.frames = {
            "home": ui.HomeFrame(self.container, self),
            "scan": ui.ScanFrame(self.container, self),
            "scanning": ui.ScanningFrame(self.container, self),
            "result": ui.ResultFrame(self.container, self),
            "history": ui.HistoryFrame(self.container, self),
            "settings": ui.SettingsFrame(self.container, self),
        }
        for frame in self.frames.values():
            frame.place(relx=0, rely=0, relwidth=1, relheight=1)

    def _bind_shortcuts(self):
        self.bind("<Escape>", lambda e: self.go_home())
        self.bind("<Control-q>", lambda e: self.quit_app())
        self.bind("<Control-n>", lambda e: self.go_scan())
        self.bind("<Control-h>", lambda e: self.go_history())
        self.bind("<Control-comma>", lambda e: self.go_settings())

    # ------------------------------------------------------------------ #
    # Navigation
    # ------------------------------------------------------------------ #

    def _show(self, name):
        self.current_frame_name = name
        self.frames[name].tkraise()

    def go_home(self):
        if self._active_scan_thread and self._active_scan_thread.is_alive():
            return  # don't navigate away mid-scan
        self._show("home")

    def _replace_frame(self, name, frame_cls):
        """Destroy the old Tk widget for this frame (not just drop the Python
        reference) before building a fresh one, so repeated navigation never
        leaks hidden widgets."""
        old = self.frames.get(name)
        if old is not None:
            old.destroy()
        new_frame = frame_cls(self.container, self)
        new_frame.place(relx=0, rely=0, relwidth=1, relheight=1)
        self.frames[name] = new_frame

    def go_scan(self):
        self._replace_frame("scan", ui.ScanFrame)
        self._show("scan")

    def go_history(self):
        self._replace_frame("history", ui.HistoryFrame)
        self._show("history")

    def go_settings(self):
        self._replace_frame("settings", ui.SettingsFrame)
        self._show("settings")

    def quit_app(self):
        self.destroy()
        sys.exit(0)

    # ------------------------------------------------------------------ #
    # Theme handling
    # ------------------------------------------------------------------ #

    def set_theme(self, name):
        self.theme = get_theme(name)
        self.settings.set("theme", name)
        ctk.set_appearance_mode(self.theme.get("mode", "dark"))
        self.configure(fg_color=self.theme["bg"])
        for frame in self.frames.values():
            frame.refresh_theme()

    def open_theme_menu(self):
        ui.ThemeMenu(self)

    # ------------------------------------------------------------------ #
    # Scanning (background thread — keeps GUI responsive)
    # ------------------------------------------------------------------ #

    def start_scan(self, raw_url: str):
        self._replace_frame("scanning", ui.ScanningFrame)
        self._show("scanning")
        self.frames["scanning"].set_target(raw_url)

        def progress_cb(text, percent):
            self.after(0, lambda: self.frames["scanning"].update_progress(text, percent))

        def log_cb(line):
            self.after(0, lambda: self.frames["scanning"].add_log(line))

        def worker():
            s = scanner.SecurityScanner(progress_callback=progress_cb, log_callback=log_cb)
            result = s.scan(raw_url)
            self.after(0, lambda: self._on_scan_complete(result))

        self._active_scan_thread = threading.Thread(target=worker, daemon=True)
        self._active_scan_thread.start()

    def _on_scan_complete(self, result: dict):
        self._last_result = result
        self.history_manager.add(result)

        if self.settings.get("auto_save_reports"):
            try:
                report_mod.save_html(result, self.settings.get("export_folder", REPORTS_DIR))
            except Exception:
                pass  # non-fatal — the user can still export manually

        self.frames["result"].show_result(result)
        self._show("result")

    def open_history_entry(self, entry: dict):
        full = self.history_manager.load_full(entry["id"])
        if full:
            self._last_result = full
            self.frames["result"].show_result(full)
            self._show("result")

    # ------------------------------------------------------------------ #
    # Report export
    # ------------------------------------------------------------------ #

    def _export_folder(self):
        folder = self.settings.get("export_folder") or REPORTS_DIR
        os.makedirs(folder, exist_ok=True)
        return folder

    def export_report(self, fmt: str):
        if not self._last_result:
            return
        folder = self._export_folder()
        try:
            if fmt == "pdf":
                path = report_mod.save_pdf(self._last_result, folder)
            elif fmt == "html":
                path = report_mod.save_html(self._last_result, folder)
            else:
                path = report_mod.save_txt(self._last_result, folder)
            self._notify(f"Saved: {path}")
        except Exception as e:
            self._notify(f"Export failed: {e}", error=True)

    def copy_report_summary(self):
        if not self._last_result:
            return
        text = report_mod.build_txt(self._last_result)
        self.clipboard_clear()
        self.clipboard_append(text)
        self._notify("Report summary copied to clipboard.")

    def open_export_folder(self):
        folder = self._export_folder()
        try:
            if platform.system() == "Windows":
                os.startfile(folder)  # noqa: S606
            elif platform.system() == "Darwin":
                subprocess.Popen(["open", folder])
            else:
                subprocess.Popen(["xdg-open", folder])
        except Exception as e:
            self._notify(f"Couldn't open folder: {e}", error=True)

    def _notify(self, message: str, error: bool = False):
        """Lightweight transient toast at the bottom of the window."""
        theme = self.theme
        toast = ctk.CTkLabel(
            self, text=message, fg_color=theme["danger"] if error else theme["success"],
            text_color="#FFFFFF", corner_radius=10, height=36,
        )
        toast.place(relx=0.5, rely=0.95, anchor="center")
        self.after(3200, toast.destroy)


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
