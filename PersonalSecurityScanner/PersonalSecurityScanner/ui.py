"""
ui.py
-----
All CustomTkinter screens (frames) for Personal Security Scanner:

    HomeFrame, ScanFrame, ScanningFrame, ResultFrame,
    HistoryFrame, SettingsFrame, ThemeMenu (popup)

Each frame receives a reference to the main App so it can navigate between
screens, read the active theme, and trigger scans / history / settings
operations. Frames expose a `refresh_theme()` method so the whole UI can be
re-skinned instantly when the user changes theme.
"""

import os
import time
import math
import tkinter as tk
import webbrowser

import customtkinter as ctk

from themes import THEME_ORDER, get_theme, SEVERITY_COLORS
from scanner import risk_label


# --------------------------------------------------------------------------- #
# Small reusable building blocks
# --------------------------------------------------------------------------- #

class Card(ctk.CTkFrame):
    """A rounded, bordered 'card' container used throughout the app."""

    def __init__(self, master, theme, **kwargs):
        super().__init__(
            master,
            fg_color=theme["card"],
            border_color=theme["card_border"],
            border_width=1,
            corner_radius=16,
            **kwargs,
        )


class GradientButton(ctk.CTkButton):
    """A big accent button used for primary actions."""

    def __init__(self, master, theme, text, command=None, height=48, **kwargs):
        super().__init__(
            master,
            text=text,
            command=command,
            height=height,
            corner_radius=14,
            fg_color=theme["accent"],
            hover_color=theme["accent_hover"],
            text_color="#FFFFFF",
            font=ctk.CTkFont(size=15, weight="bold"),
            **kwargs,
        )


class GhostButton(ctk.CTkButton):
    """A secondary, outlined button."""

    def __init__(self, master, theme, text, command=None, height=44, **kwargs):
        super().__init__(
            master,
            text=text,
            command=command,
            height=height,
            corner_radius=14,
            fg_color="transparent",
            hover_color=theme["input_bg"],
            border_width=1,
            border_color=theme["card_border"],
            text_color=theme["text"],
            font=ctk.CTkFont(size=14),
            **kwargs,
        )


class SeverityBadge(ctk.CTkLabel):
    """Small colour-coded pill for severity level."""

    def __init__(self, master, theme, severity: str, **kwargs):
        color_key = SEVERITY_COLORS.get(severity, "text_muted")
        color = theme.get(color_key, theme["text_muted"])
        super().__init__(
            master,
            text=severity.upper(),
            fg_color=color,
            text_color="#FFFFFF",
            corner_radius=8,
            width=80,
            height=22,
            font=ctk.CTkFont(size=10, weight="bold"),
            **kwargs,
        )


class TopBar(ctk.CTkFrame):
    """Shared top bar with title + theme button, used on every screen."""

    def __init__(self, master, app, title_text, subtitle_text=None, show_back=False):
        theme = app.theme
        super().__init__(master, fg_color="transparent")
        self.app = app

        left = ctk.CTkFrame(self, fg_color="transparent")
        left.pack(side="left", fill="x", expand=True)

        if show_back:
            back_btn = GhostButton(left, theme, "⬅ Back", command=app.go_home, width=90, height=34)
            back_btn.pack(side="left", padx=(0, 12))

        title_box = ctk.CTkFrame(left, fg_color="transparent")
        title_box.pack(side="left")
        ctk.CTkLabel(
            title_box, text=title_text, font=ctk.CTkFont(size=22, weight="bold"), text_color=theme["text"]
        ).pack(anchor="w")
        if subtitle_text:
            ctk.CTkLabel(
                title_box, text=subtitle_text, font=ctk.CTkFont(size=13), text_color=theme["text_muted"]
            ).pack(anchor="w")

        theme_btn = ctk.CTkButton(
            self, text="🎨 Theme", width=100, height=34, corner_radius=10,
            fg_color=theme["input_bg"], hover_color=theme["accent_hover"],
            text_color=theme["text"], command=app.open_theme_menu,
        )
        theme_btn.pack(side="right")


# --------------------------------------------------------------------------- #
# Theme picker popup
# --------------------------------------------------------------------------- #

class ThemeMenu(ctk.CTkToplevel):
    def __init__(self, app):
        super().__init__(app)
        self.app = app
        theme = app.theme
        self.title("Choose Theme")
        self.geometry("280x420")
        self.resizable(False, False)
        self.configure(fg_color=theme["bg"])
        self.attributes("-topmost", True)

        ctk.CTkLabel(self, text="Select a Theme", font=ctk.CTkFont(size=16, weight="bold"),
                     text_color=theme["text"]).pack(pady=(18, 10))

        for name in THEME_ORDER:
            t = get_theme(name)
            btn = ctk.CTkButton(
                self, text=t["label"], height=42, corner_radius=12,
                fg_color=t["accent"], hover_color=t["accent_hover"], text_color="#FFFFFF",
                font=ctk.CTkFont(size=14),
                command=lambda n=name: self._select(n),
            )
            btn.pack(padx=20, pady=6, fill="x")

    def _select(self, name):
        self.app.set_theme(name)
        self.destroy()


# --------------------------------------------------------------------------- #
# HOME
# --------------------------------------------------------------------------- #

class HomeFrame(ctk.CTkFrame):
    def __init__(self, master, app):
        super().__init__(master, fg_color=app.theme["bg"])
        self.app = app
        self._build()

    def _build(self):
        for w in self.winfo_children():
            w.destroy()
        theme = self.app.theme
        self.configure(fg_color=theme["bg"])

        top = TopBar(self, self.app, "", subtitle_text=None)
        top.pack(fill="x", padx=30, pady=(20, 0))
        # Hide the empty title/back on home - we draw a custom hero instead
        top.destroy()

        theme_btn = ctk.CTkButton(
            self, text="🎨 Theme", width=100, height=34, corner_radius=10,
            fg_color=theme["input_bg"], hover_color=theme["accent_hover"],
            text_color=theme["text"], command=self.app.open_theme_menu,
        )
        theme_btn.place(relx=0.97, rely=0.04, anchor="ne")

        center = ctk.CTkFrame(self, fg_color="transparent")
        center.place(relx=0.5, rely=0.42, anchor="center")

        logo_circle = ctk.CTkLabel(
            center, text="🛡️", font=ctk.CTkFont(size=64),
            fg_color=theme["card"], corner_radius=100, width=120, height=120,
        )
        logo_circle.pack(pady=(0, 18))

        ctk.CTkLabel(
            center, text="Personal Security Scanner",
            font=ctk.CTkFont(size=30, weight="bold"), text_color=theme["text"],
        ).pack()

        ctk.CTkLabel(
            center, text="Scan websites for common security misconfigurations.",
            font=ctk.CTkFont(size=15), text_color=theme["text_muted"],
        ).pack(pady=(6, 30))

        btn_box = ctk.CTkFrame(center, fg_color="transparent")
        btn_box.pack()

        GradientButton(btn_box, theme, "🔍  Start Scan", command=self.app.go_scan, width=260).pack(pady=8)
        GhostButton(btn_box, theme, "📜  History", command=self.app.go_history, width=260).pack(pady=8)
        GhostButton(btn_box, theme, "⚙️  Settings", command=self.app.go_settings, width=260).pack(pady=8)
        GhostButton(btn_box, theme, "🚪  Exit", command=self.app.quit_app, width=260).pack(pady=8)

        ctk.CTkLabel(
            self, text="Passive & educational — scans only the website you specify.",
            font=ctk.CTkFont(size=11), text_color=theme["text_muted"],
        ).place(relx=0.5, rely=0.97, anchor="center")

    def refresh_theme(self):
        self._build()


# --------------------------------------------------------------------------- #
# SCAN INPUT
# --------------------------------------------------------------------------- #

class ScanFrame(ctk.CTkFrame):
    def __init__(self, master, app):
        super().__init__(master, fg_color=app.theme["bg"])
        self.app = app
        self._build()

    def _build(self):
        for w in self.winfo_children():
            w.destroy()
        theme = self.app.theme
        self.configure(fg_color=theme["bg"])

        top = TopBar(self, self.app, "Start a Scan",
                     "Enter a website URL to check for common misconfigurations.",
                     show_back=True)
        top.pack(fill="x", padx=30, pady=20)

        card = Card(self, theme)
        card.place(relx=0.5, rely=0.45, anchor="center", relwidth=0.6)

        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(padx=36, pady=36, fill="x")

        ctk.CTkLabel(inner, text="Website URL", font=ctk.CTkFont(size=14, weight="bold"),
                     text_color=theme["text"]).pack(anchor="w")

        self.entry = ctk.CTkEntry(
            inner, placeholder_text="https://example.com", height=46, corner_radius=12,
            fg_color=theme["input_bg"], border_color=theme["card_border"],
            text_color=theme["text"], font=ctk.CTkFont(size=14),
        )
        self.entry.pack(fill="x", pady=(8, 4))
        self.entry.bind("<Return>", lambda e: self._start())

        self.error_label = ctk.CTkLabel(inner, text="", text_color=theme["danger"], font=ctk.CTkFont(size=12))
        self.error_label.pack(anchor="w", pady=(0, 10))

        btn_row = ctk.CTkFrame(inner, fg_color="transparent")
        btn_row.pack(fill="x", pady=(10, 0))

        GradientButton(btn_row, theme, "Scan", command=self._start, width=140).pack(side="left", padx=(0, 10))
        GhostButton(btn_row, theme, "Clear", command=self._clear, width=120).pack(side="left", padx=(0, 10))
        GhostButton(btn_row, theme, "Back", command=self.app.go_home, width=120).pack(side="left")

    def _clear(self):
        self.entry.delete(0, "end")
        self.error_label.configure(text="")

    def _start(self):
        url = self.entry.get().strip()
        if not url:
            self.error_label.configure(text="Please enter a website URL.")
            return
        self.error_label.configure(text="")
        self.app.start_scan(url)

    def refresh_theme(self):
        self._build()


# --------------------------------------------------------------------------- #
# SCANNING (progress) SCREEN
# --------------------------------------------------------------------------- #

class ScanningFrame(ctk.CTkFrame):
    def __init__(self, master, app):
        super().__init__(master, fg_color=app.theme["bg"])
        self.app = app
        self.start_time = None
        self._build()

    def _build(self):
        for w in self.winfo_children():
            w.destroy()
        theme = self.app.theme
        self.configure(fg_color=theme["bg"])

        center = ctk.CTkFrame(self, fg_color="transparent")
        center.place(relx=0.5, rely=0.38, anchor="center")

        ctk.CTkLabel(center, text="🔄 Scanning...", font=ctk.CTkFont(size=24, weight="bold"),
                     text_color=theme["text"]).pack(pady=(0, 4))

        self.target_label = ctk.CTkLabel(center, text="", font=ctk.CTkFont(size=13), text_color=theme["text_muted"])
        self.target_label.pack(pady=(0, 20))

        self.progress = ctk.CTkProgressBar(
            center, width=460, height=16, corner_radius=8,
            fg_color=theme["input_bg"], progress_color=theme["progress"],
        )
        self.progress.set(0)
        self.progress.pack(pady=(0, 10))

        row = ctk.CTkFrame(center, fg_color="transparent")
        row.pack(fill="x")
        self.status_label = ctk.CTkLabel(row, text="Preparing scan...", font=ctk.CTkFont(size=14),
                                          text_color=theme["text"])
        self.status_label.pack(side="left")
        self.percent_label = ctk.CTkLabel(row, text="0%", font=ctk.CTkFont(size=14, weight="bold"),
                                           text_color=theme["accent"])
        self.percent_label.pack(side="right")

        self.timer_label = ctk.CTkLabel(center, text="Elapsed: 0.0s", font=ctk.CTkFont(size=12),
                                         text_color=theme["text_muted"])
        self.timer_label.pack(pady=(6, 0))

        # Live scanning log panel
        log_card = Card(self, theme)
        log_card.place(relx=0.5, rely=0.78, anchor="center", relwidth=0.6, relheight=0.28)
        ctk.CTkLabel(log_card, text="Live Log", font=ctk.CTkFont(size=12, weight="bold"),
                     text_color=theme["text_muted"]).pack(anchor="w", padx=16, pady=(10, 0))
        self.log_box = ctk.CTkTextbox(
            log_card, fg_color="transparent", text_color=theme["text_muted"],
            font=ctk.CTkFont(size=12), wrap="word",
        )
        self.log_box.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self.log_box.configure(state="disabled")

    def set_target(self, url):
        self.target_label.configure(text=url)
        self.start_time = time.time()
        self._tick_timer()

    def _tick_timer(self):
        if self.start_time is None:
            return
        elapsed = time.time() - self.start_time
        self.timer_label.configure(text=f"Elapsed: {elapsed:.1f}s")
        if self.app.current_frame_name == "scanning":
            self.after(100, self._tick_timer)

    def update_progress(self, text, percent):
        self.status_label.configure(text=text)
        self.percent_label.configure(text=f"{percent}%")
        self.progress.set(percent / 100)

    def add_log(self, line):
        self.log_box.configure(state="normal")
        self.log_box.insert("end", f"› {line}\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def refresh_theme(self):
        self._build()


# --------------------------------------------------------------------------- #
# RESULT DASHBOARD
# --------------------------------------------------------------------------- #

class ResultFrame(ctk.CTkFrame):
    def __init__(self, master, app):
        super().__init__(master, fg_color=app.theme["bg"])
        self.app = app
        self.result = None

    def show_result(self, result: dict):
        self.result = result
        self._build()

    def _build(self):
        for w in self.winfo_children():
            w.destroy()
        theme = self.app.theme
        self.configure(fg_color=theme["bg"])
        result = self.result
        if result is None:
            return

        scroll = ctk.CTkScrollableFrame(self, fg_color=theme["bg"])
        scroll.pack(fill="both", expand=True, padx=24, pady=20)

        # ---- Top summary card ----
        score = result.get("risk_score", 0)
        top_card = Card(scroll, theme)
        top_card.pack(fill="x", pady=(0, 20))
        top_inner = ctk.CTkFrame(top_card, fg_color="transparent")
        top_inner.pack(fill="x", padx=24, pady=20)

        left = ctk.CTkFrame(top_inner, fg_color="transparent")
        left.pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(left, text=result.get("url", ""), font=ctk.CTkFont(size=20, weight="bold"),
                     text_color=theme["text"]).pack(anchor="w")
        ctk.CTkLabel(
            left, text=f"Scanned {result.get('date')} at {result.get('time')}  •  {result.get('duration_seconds')}s",
            font=ctk.CTkFont(size=12), text_color=theme["text_muted"],
        ).pack(anchor="w", pady=(4, 0))
        if result.get("error"):
            ctk.CTkLabel(left, text=f"⚠ {result['error']}", font=ctk.CTkFont(size=12),
                         text_color=theme["danger"]).pack(anchor="w", pady=(6, 0))

        right = ctk.CTkFrame(top_inner, fg_color="transparent")
        right.pack(side="right")
        score_color = theme["success"] if score >= 75 else (theme["warning"] if score >= 50 else theme["danger"])
        ctk.CTkLabel(right, text=f"{score}/100", font=ctk.CTkFont(size=32, weight="bold"),
                     text_color=score_color).pack()
        ctk.CTkLabel(right, text=risk_label(score), font=ctk.CTkFont(size=13, weight="bold"),
                     text_color=theme["text_muted"]).pack()

        # ---- Findings / Recommendations ----
        self._section(scroll, theme, "Findings & Recommendations")
        self._severity_pie(scroll, theme, result.get("findings", []))
        for f in result.get("findings", []):
            self._finding_card(scroll, theme, f)

        # ---- SSL ----
        self._section(scroll, theme, "SSL / TLS")
        ssl_info = result.get("ssl", {})
        self._kv_card(scroll, theme, [
            ("HTTPS Enabled", "Yes" if result.get("https_enabled") else "No"),
            ("Issuer", ssl_info.get("issuer") or "—"),
            ("Expires On", ssl_info.get("expires_on") or "—"),
            ("Valid", "Yes" if ssl_info.get("valid") else "No"),
            ("TLS Version", ssl_info.get("tls_version") or "—"),
        ])

        # ---- Headers ----
        self._section(scroll, theme, "Security Headers")
        self._kv_card(scroll, theme, [
            (h, "✅ Present" if v else "❌ Missing") for h, v in result.get("security_headers", {}).items()
        ])

        # ---- Cookies ----
        self._section(scroll, theme, "Cookies")
        cookies = result.get("cookies", [])
        if cookies:
            self._kv_card(scroll, theme, [
                (c["name"], f"Secure={c['secure']}  HttpOnly={c['httponly']}  SameSite={c['samesite']}")
                for c in cookies
            ])
        else:
            self._kv_card(scroll, theme, [("Cookies", "No cookies observed on initial response.")])

        # ---- Server ----
        self._section(scroll, theme, "Server Information")
        self._kv_card(scroll, theme, [
            (h, v or "Not disclosed") for h, v in result.get("server_info", {}).items()
        ])

        # ---- Files ----
        self._section(scroll, theme, "Exposed File Paths")
        self._kv_card(scroll, theme, [
            (f["path"], "🛑 Accessible" if f["accessible"] else "✅ Not accessible")
            for f in result.get("exposed_files", [])
        ])

        # ---- Export buttons ----
        self._section(scroll, theme, "Export Report")
        export_row = ctk.CTkFrame(scroll, fg_color="transparent")
        export_row.pack(fill="x", pady=(4, 20))
        GradientButton(export_row, theme, "📄 Save PDF", command=lambda: self.app.export_report("pdf"), width=150).pack(side="left", padx=6)
        GradientButton(export_row, theme, "🌐 Save HTML", command=lambda: self.app.export_report("html"), width=150).pack(side="left", padx=6)
        GradientButton(export_row, theme, "📝 Save TXT", command=lambda: self.app.export_report("txt"), width=150).pack(side="left", padx=6)
        GhostButton(export_row, theme, "📋 Copy Summary", command=self.app.copy_report_summary, width=170).pack(side="left", padx=6)
        GhostButton(export_row, theme, "📂 Open Folder", command=self.app.open_export_folder, width=160).pack(side="left", padx=6)

        # ---- After-scan navigation (always present) ----
        after_row = ctk.CTkFrame(scroll, fg_color="transparent")
        after_row.pack(fill="x", pady=(10, 10))
        GradientButton(after_row, theme, "🔄 Scan Another Website", command=self.app.go_scan, width=230).pack(side="left", padx=6)
        GhostButton(after_row, theme, "⬅ Back to Home", command=self.app.go_home, width=180).pack(side="left", padx=6)
        GhostButton(after_row, theme, "🚪 Exit", command=self.app.quit_app, width=120).pack(side="left", padx=6)

    def _section(self, parent, theme, text):
        ctk.CTkLabel(parent, text=text, font=ctk.CTkFont(size=17, weight="bold"),
                     text_color=theme["text"]).pack(anchor="w", pady=(10, 8))

    def _kv_card(self, parent, theme, pairs):
        card = Card(parent, theme)
        card.pack(fill="x", pady=(0, 4))
        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=18, pady=12)
        if not pairs:
            ctk.CTkLabel(inner, text="No data available.", text_color=theme["text_muted"]).pack(anchor="w")
            return
        for k, v in pairs:
            row = ctk.CTkFrame(inner, fg_color="transparent")
            row.pack(fill="x", pady=3)
            ctk.CTkLabel(row, text=str(k), font=ctk.CTkFont(size=13, weight="bold"),
                         text_color=theme["text"], width=260, anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=str(v), font=ctk.CTkFont(size=13),
                         text_color=theme["text_muted"], anchor="w").pack(side="left", fill="x", expand=True)

    def _severity_pie(self, parent, theme, findings):
        """Small pie chart summarizing findings by severity, plus a legend."""
        counts = {}
        for f in findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        total = sum(counts.values())
        if total == 0:
            return

        card = Card(parent, theme)
        card.pack(fill="x", pady=(0, 10))
        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=18, pady=16)

        size = 130
        canvas = tk.Canvas(inner, width=size, height=size, highlightthickness=0, bg=theme["card"])
        canvas.pack(side="left", padx=(0, 20))

        order = ["critical", "high", "medium", "low", "good"]
        start_angle = 90
        for sev in order:
            n = counts.get(sev, 0)
            if n == 0:
                continue
            extent = -360 * (n / total)
            color = theme.get(SEVERITY_COLORS.get(sev, "text_muted"), theme["text_muted"])
            canvas.create_arc(
                6, 6, size - 6, size - 6, start=start_angle, extent=extent,
                fill=color, outline=theme["card"], width=2,
            )
            start_angle += extent
        canvas.create_oval(size * 0.28, size * 0.28, size * 0.72, size * 0.72, fill=theme["card"], outline="")
        canvas.create_text(size / 2, size / 2, text=str(total), fill=theme["text"], font=("Segoe UI", 16, "bold"))

        legend = ctk.CTkFrame(inner, fg_color="transparent")
        legend.pack(side="left", fill="both", expand=True)
        for sev in order:
            n = counts.get(sev, 0)
            if n == 0:
                continue
            color = theme.get(SEVERITY_COLORS.get(sev, "text_muted"), theme["text_muted"])
            row = ctk.CTkFrame(legend, fg_color="transparent")
            row.pack(anchor="w", pady=2)
            dot = tk.Canvas(row, width=12, height=12, highlightthickness=0, bg=theme["card"])
            dot.create_oval(1, 1, 11, 11, fill=color, outline="")
            dot.pack(side="left", padx=(0, 8))
            ctk.CTkLabel(
                row, text=f"{sev.capitalize()}: {n}", font=ctk.CTkFont(size=12), text_color=theme["text"]
            ).pack(side="left")

    def _finding_card(self, parent, theme, finding):
        card = Card(parent, theme)
        card.pack(fill="x", pady=6)
        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=18, pady=14)

        header = ctk.CTkFrame(inner, fg_color="transparent")
        header.pack(fill="x")
        ctk.CTkLabel(header, text=finding["title"], font=ctk.CTkFont(size=15, weight="bold"),
                     text_color=theme["text"]).pack(side="left")
        SeverityBadge(header, theme, finding["severity"]).pack(side="right")

        ctk.CTkLabel(inner, text=f"Why it matters: {finding['why']}", font=ctk.CTkFont(size=12),
                     text_color=theme["text_muted"], anchor="w", justify="left", wraplength=760).pack(anchor="w", pady=(8, 2))
        ctk.CTkLabel(inner, text=f"Recommendation: {finding['fix']}", font=ctk.CTkFont(size=12, weight="bold"),
                     text_color=theme["accent"], anchor="w", justify="left", wraplength=760).pack(anchor="w")

    def refresh_theme(self):
        if self.result:
            self._build()
        else:
            self.configure(fg_color=self.app.theme["bg"])


# --------------------------------------------------------------------------- #
# HISTORY
# --------------------------------------------------------------------------- #

class HistoryFrame(ctk.CTkFrame):
    def __init__(self, master, app):
        super().__init__(master, fg_color=app.theme["bg"])
        self.app = app
        self._build()

    def _build(self):
        for w in self.winfo_children():
            w.destroy()
        theme = self.app.theme
        self.configure(fg_color=theme["bg"])

        top = TopBar(self, self.app, "Scan History", "Previously completed scans.", show_back=True)
        top.pack(fill="x", padx=30, pady=20)

        search_row = ctk.CTkFrame(self, fg_color="transparent")
        search_row.pack(fill="x", padx=30)
        self.search_entry = ctk.CTkEntry(
            search_row, placeholder_text="🔎 Search by website...", height=38, corner_radius=10,
            fg_color=theme["input_bg"], text_color=theme["text"], border_color=theme["card_border"],
        )
        self.search_entry.pack(side="left", fill="x", expand=True)
        self.search_entry.bind("<KeyRelease>", lambda e: self._refresh_list())

        self.list_area = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.list_area.pack(fill="both", expand=True, padx=30, pady=16)

        self._refresh_list()

    def _refresh_list(self):
        theme = self.app.theme
        for w in self.list_area.winfo_children():
            w.destroy()

        query = self.search_entry.get().strip().lower() if hasattr(self, "search_entry") else ""
        entries = self.app.history_manager.all()
        if query:
            entries = [e for e in entries if query in e["url"].lower()]

        if not entries:
            ctk.CTkLabel(self.list_area, text="No scans yet.", text_color=theme["text_muted"]).pack(pady=30)
            return

        for entry in reversed(entries):
            card = Card(self.list_area, theme)
            card.pack(fill="x", pady=6)
            row = ctk.CTkFrame(card, fg_color="transparent")
            row.pack(fill="x", padx=16, pady=12)

            info = ctk.CTkFrame(row, fg_color="transparent")
            info.pack(side="left", fill="x", expand=True)
            ctk.CTkLabel(info, text=entry["url"], font=ctk.CTkFont(size=14, weight="bold"),
                         text_color=theme["text"]).pack(anchor="w")
            ctk.CTkLabel(info, text=f"{entry['date']} {entry['time']}", font=ctk.CTkFont(size=11),
                         text_color=theme["text_muted"]).pack(anchor="w")

            score = entry.get("risk_score", 0)
            score_color = theme["success"] if score >= 75 else (theme["warning"] if score >= 50 else theme["danger"])
            ctk.CTkLabel(row, text=f"{score}/100", font=ctk.CTkFont(size=16, weight="bold"),
                         text_color=score_color, width=80).pack(side="left")

            btns = ctk.CTkFrame(row, fg_color="transparent")
            btns.pack(side="right")
            GhostButton(btns, theme, "Open", command=lambda e=entry: self._open(e), width=90, height=32).pack(side="left", padx=4)
            GhostButton(btns, theme, "Delete", command=lambda e=entry: self._delete(e), width=90, height=32).pack(side="left", padx=4)

    def _open(self, entry):
        self.app.open_history_entry(entry)

    def _delete(self, entry):
        self.app.history_manager.delete(entry["id"])
        self._refresh_list()

    def refresh_theme(self):
        self._build()


# --------------------------------------------------------------------------- #
# SETTINGS
# --------------------------------------------------------------------------- #

class SettingsFrame(ctk.CTkFrame):
    def __init__(self, master, app):
        super().__init__(master, fg_color=app.theme["bg"])
        self.app = app
        self._build()

    def _build(self):
        for w in self.winfo_children():
            w.destroy()
        theme = self.app.theme
        self.configure(fg_color=theme["bg"])

        top = TopBar(self, self.app, "Settings", "Customize your experience.", show_back=True)
        top.pack(fill="x", padx=30, pady=20)

        card = Card(self, theme)
        card.pack(fill="x", padx=30, pady=10)
        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=28, pady=24)

        # Default theme
        self._row_label(inner, theme, "Default Theme")
        self.theme_option = ctk.CTkOptionMenu(
            inner, values=THEME_ORDER, command=self.app.set_theme,
            fg_color=theme["input_bg"], button_color=theme["accent"],
            button_hover_color=theme["accent_hover"], text_color=theme["text"],
        )
        self.theme_option.set(self.app.settings.get("theme"))
        self.theme_option.pack(anchor="w", pady=(4, 16))

        # Animation speed
        self._row_label(inner, theme, "Animation Speed")
        self.speed_option = ctk.CTkOptionMenu(
            inner, values=["Slow", "Normal", "Fast"], command=self._set_speed,
            fg_color=theme["input_bg"], button_color=theme["accent"],
            button_hover_color=theme["accent_hover"], text_color=theme["text"],
        )
        self.speed_option.set(self.app.settings.get("animation_speed"))
        self.speed_option.pack(anchor="w", pady=(4, 16))

        # Auto save
        self._row_label(inner, theme, "Auto Save Reports")
        self.autosave_switch = ctk.CTkSwitch(
            inner, text="Automatically save a report after each scan",
            command=self._set_autosave, progress_color=theme["accent"], text_color=theme["text"],
        )
        if self.app.settings.get("auto_save_reports"):
            self.autosave_switch.select()
        self.autosave_switch.pack(anchor="w", pady=(4, 16))

        # Export folder
        self._row_label(inner, theme, "Default Export Folder")
        folder_row = ctk.CTkFrame(inner, fg_color="transparent")
        folder_row.pack(fill="x", pady=(4, 16))
        self.folder_entry = ctk.CTkEntry(
            folder_row, height=38, corner_radius=10, fg_color=theme["input_bg"],
            text_color=theme["text"], border_color=theme["card_border"],
        )
        self.folder_entry.insert(0, self.app.settings.get("export_folder"))
        self.folder_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        GhostButton(folder_row, theme, "Save", command=self._save_folder, width=90, height=38).pack(side="left")

        # Reset
        GhostButton(inner, theme, "♻ Reset Settings", command=self._reset, width=200).pack(anchor="w", pady=(10, 0))

    def _row_label(self, parent, theme, text):
        ctk.CTkLabel(parent, text=text, font=ctk.CTkFont(size=13, weight="bold"),
                     text_color=theme["text"]).pack(anchor="w")

    def _set_speed(self, value):
        self.app.settings.set("animation_speed", value)

    def _set_autosave(self):
        self.app.settings.set("auto_save_reports", bool(self.autosave_switch.get()))

    def _save_folder(self):
        self.app.settings.set("export_folder", self.folder_entry.get().strip())

    def _reset(self):
        self.app.settings.reset()
        self.app.set_theme(self.app.settings.get("theme"))
        self._build()

    def refresh_theme(self):
        self._build()
