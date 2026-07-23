# Personal Security Scanner

A modern desktop app (CustomTkinter) that runs **passive, read-only** security
checks against a single website URL you provide — SSL/TLS certificate health,
missing security headers, cookie flags, common accidentally-exposed file
paths, HTTP method support, and HTTP→HTTPS redirect behavior. It never
attempts exploitation, brute forcing, port scanning, or denial-of-service —
every check is the same kind of ordinary request a web browser makes.

## Setup

```bash
cd PersonalSecurityScanner
pip install -r requirements.txt
python main.py
```

Requires Python 3.9+. Tkinter ships with most standard Python installs; on
some Linux distros you may need `sudo apt install python3-tk` first.

## Project layout

```
main.py          Entry point, app shell, navigation, threading, exports
ui.py            All CustomTkinter screens (Home, Scan, Scanning, Result, History, Settings)
scanner.py        Orchestrates a scan and computes the risk score / findings
ssl_checker.py    Passive TLS handshake + certificate inspection
headers.py        Security headers, server info, robots/sitemap, exposed
                   file checks, HTTP methods, redirects, cookies
report.py         TXT / HTML / PDF report generation
history.py        JSON-backed scan history (index + full saved results)
settings.py       JSON-backed persistent settings
themes.py         6 built-in color themes
requirements.txt  Python dependencies
assets/logo.png   App icon / logo
reports/          Saved reports + history.json (created on first run)
```

## Notes

- All settings and history persist in `settings.json` and
  `reports/history.json`, both created automatically on first run.
- PDF export requires `reportlab` (already in requirements.txt).
- I wasn't able to launch the GUI in this sandboxed build environment (no
  network access to install `customtkinter`/no display), so please do a
  quick smoke test on your machine — happy to fix anything that comes up.
