"""
scanner.py
----------
Orchestrates a single, fully passive scan of ONE user-supplied URL.

The scan performs a fixed, small sequence of read-only HTTP/TLS requests
(the same kind any browser makes) against the target the user typed in.
It never attempts login, brute force, injection, denial-of-service, or
scanning of hosts/paths other than what the user provided.

Designed to be run inside a background thread; progress is reported via a
callback so the GUI thread never blocks.
"""

import time
from urllib.parse import urlparse

import ssl_checker
import headers as headers_mod


STEPS = [
    ("Checking HTTPS...", "https"),
    ("Checking SSL...", "ssl"),
    ("Checking Security Headers...", "headers"),
    ("Checking server information...", "server"),
    ("Checking robots.txt...", "robots"),
    ("Checking sitemap.xml...", "sitemap"),
    ("Looking for exposed files...", "files"),
    ("Checking HTTP methods...", "methods"),
    ("Checking redirects...", "redirect"),
    ("Checking cookies...", "cookies"),
]


class ScanCancelled(Exception):
    pass


def normalize_url(raw_url: str) -> str:
    raw_url = raw_url.strip()
    if not raw_url:
        raise ValueError("Please enter a website URL.")
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url
    parsed = urlparse(raw_url)
    if not parsed.netloc:
        raise ValueError("That doesn't look like a valid URL.")
    return raw_url


class SecurityScanner:
    """Runs a full passive scan and reports progress via callback."""

    def __init__(self, progress_callback=None, log_callback=None):
        """
        progress_callback(step_text: str, percent: int)
        log_callback(line: str)  -- optional live log panel feed
        """
        self.progress_callback = progress_callback or (lambda *a: None)
        self.log_callback = log_callback or (lambda *a: None)
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def _report(self, text, percent):
        self.progress_callback(text, percent)
        self.log_callback(text)

    def scan(self, raw_url: str) -> dict:
        start_time = time.time()
        url = normalize_url(raw_url)
        parsed = urlparse(url)
        hostname = parsed.hostname
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        result = {
            "url": url,
            "hostname": hostname,
            "date": time.strftime("%Y-%m-%d"),
            "time": time.strftime("%H:%M:%S"),
            "duration_seconds": None,
            "error": None,
        }

        total_steps = len(STEPS)

        try:
            base_response = None
            base_error = None

            for i, (label, key) in enumerate(STEPS):
                if self._cancelled:
                    raise ScanCancelled("Scan cancelled by user.")

                percent = int(((i) / total_steps) * 100)
                self._report(label, percent)

                if key == "https":
                    result["https_enabled"] = url.startswith("https://")

                elif key == "ssl":
                    if hostname:
                        result["ssl"] = ssl_checker.check_ssl(hostname)
                    else:
                        result["ssl"] = {"error": "Could not determine hostname."}

                elif key == "headers":
                    if base_response is None:
                        base_response, base_error = headers_mod.fetch_base_response(url)
                    if base_response is not None:
                        result["security_headers"] = headers_mod.check_security_headers(base_response)
                    else:
                        result["security_headers"] = {}
                        result["error"] = base_error

                elif key == "server":
                    if base_response is not None:
                        result["server_info"] = headers_mod.check_server_info(base_response)
                    else:
                        result["server_info"] = {}

                elif key == "robots":
                    result["robots"] = headers_mod.check_robots_txt(base_url)

                elif key == "sitemap":
                    result["sitemap"] = headers_mod.check_sitemap_xml(base_url)

                elif key == "files":
                    result["exposed_files"] = headers_mod.check_exposed_files(base_url)

                elif key == "methods":
                    result["http_methods"] = headers_mod.check_http_methods(url)

                elif key == "redirect":
                    result["redirect"] = headers_mod.check_redirect_to_https(base_url)

                elif key == "cookies":
                    if base_response is not None:
                        result["cookies"] = headers_mod.check_cookies(base_response)
                    else:
                        result["cookies"] = []

                time.sleep(0.15)  # small pacing so progress UI feels smooth

            self._report("Finalizing report...", 100)

        except ScanCancelled:
            result["error"] = "Scan cancelled."
        except ValueError as e:
            result["error"] = str(e)
        except Exception as e:  # noqa: BLE001
            result["error"] = f"Unexpected error during scan: {e}"

        result["duration_seconds"] = round(time.time() - start_time, 2)
        result["risk_score"], result["findings"] = score_and_findings(result)
        return result


def score_and_findings(result: dict):
    """
    Compute a simple 0-100 risk score (100 = best / most secure) plus a
    list of plain-English findings with severity + recommendation text.
    Purely a heuristic aggregation of the passive checks above — not a
    penetration-test verdict.
    """
    findings = []
    score = 100

    def deduct(points, severity, title, why, fix):
        nonlocal score
        score -= points
        findings.append({"severity": severity, "title": title, "why": why, "fix": fix})

    # HTTPS
    if not result.get("https_enabled"):
        deduct(20, "high", "❌ Site is not served over HTTPS",
               "Traffic can be intercepted or modified in transit.",
               "Enable HTTPS with a valid TLS certificate for all pages.")

    # SSL
    ssl_info = result.get("ssl", {})
    if ssl_info.get("error"):
        deduct(15, "high", "❌ SSL/TLS certificate could not be verified",
               f"Detail: {ssl_info['error']}",
               "Install a valid, trusted TLS certificate covering this hostname.")
    else:
        if ssl_info.get("expired"):
            deduct(20, "critical", "❌ SSL certificate has expired",
                   "Browsers will show security warnings to visitors.",
                   "Renew the TLS certificate immediately.")
        elif ssl_info.get("days_remaining") is not None and ssl_info["days_remaining"] < 15:
            deduct(5, "medium", "⚠️ SSL certificate expires soon",
                   f"Only {ssl_info['days_remaining']} day(s) remain before expiry.",
                   "Renew the certificate before it expires.")

    # Security headers
    header_labels = {
        "Content-Security-Policy": ("Attackers may inject malicious scripts (XSS).", "Configure a proper Content-Security-Policy header."),
        "Strict-Transport-Security": ("Visitors could be downgraded to insecure HTTP.", "Add Strict-Transport-Security (HSTS) with a sensible max-age."),
        "X-Frame-Options": ("The site could be embedded in a malicious iframe (clickjacking).", "Set X-Frame-Options to DENY or SAMEORIGIN."),
        "X-Content-Type-Options": ("Browsers may MIME-sniff responses, enabling certain attacks.", "Set X-Content-Type-Options: nosniff."),
        "Referrer-Policy": ("Full URLs (possibly with sensitive data) may leak to third parties.", "Set a strict Referrer-Policy such as strict-origin-when-cross-origin."),
        "Permissions-Policy": ("Browser features (camera, mic, geolocation) aren't explicitly restricted.", "Add a Permissions-Policy limiting unneeded browser features."),
        "Cross-Origin-Opener-Policy": ("The page may be vulnerable to cross-window attacks like Spectre.", "Set Cross-Origin-Opener-Policy: same-origin."),
        "Cross-Origin-Resource-Policy": ("Resources could be embedded/read by other origins.", "Set Cross-Origin-Resource-Policy appropriately."),
        "Cross-Origin-Embedder-Policy": ("Cross-origin isolation is not enforced.", "Set Cross-Origin-Embedder-Policy: require-corp if isolation is needed."),
    }
    missing_headers = [h for h, v in result.get("security_headers", {}).items() if not v]
    for h in missing_headers:
        why, fix = header_labels.get(h, ("This header helps protect visitors.", "Configure this header on the server."))
        deduct(4, "medium", f"❌ Missing {h}", why, fix)

    # Server info disclosure
    server_info = result.get("server_info", {})
    disclosed = [k for k, v in server_info.items() if v]
    if disclosed:
        deduct(3 * len(disclosed), "low",
               f"⚠️ Server discloses version/technology info ({', '.join(disclosed)})",
               "Detailed server/technology banners help attackers fingerprint known vulnerabilities.",
               "Suppress or minimize Server, X-Powered-By, and Via headers.")

    # Exposed files
    exposed = [f for f in result.get("exposed_files", []) if f["accessible"]]
    for f in exposed:
        deduct(10, "critical", f"❌ Publicly accessible: {f['path']}",
               "Sensitive configuration, credentials, or source history could be exposed.",
               f"Restrict or remove public access to {f['path']} immediately.")

    # Cookies
    insecure_cookies = [c for c in result.get("cookies", []) if not c["secure"] or not c["httponly"]]
    for c in insecure_cookies:
        deduct(5, "medium", f"⚠️ Cookie '{c['name']}' missing security flags",
               "Cookies without Secure/HttpOnly can be stolen via network sniffing or XSS.",
               "Set the Secure and HttpOnly flags (and SameSite) on this cookie.")

    # Redirect to HTTPS
    redirect_info = result.get("redirect", {})
    if redirect_info.get("checked") and not redirect_info.get("redirects_to_https"):
        deduct(8, "high", "❌ HTTP does not redirect to HTTPS",
               "Visitors typing the plain http:// address stay unencrypted.",
               "Add a server-side redirect from HTTP to HTTPS.")

    # HTTP methods - flag risky verbs being open broadly
    methods = result.get("http_methods", {})
    if methods.get("POST"):
        # Not necessarily bad, informational only, small deduction if combined with missing CSRF-relevant headers
        pass

    # robots / sitemap are informational only (not deducted)

    score = max(0, min(100, score))

    if not findings:
        findings.append({
            "severity": "good",
            "title": "✅ No significant issues found",
            "why": "All passive checks performed came back clean.",
            "fix": "Keep monitoring headers and certificate expiry periodically.",
        })

    return score, findings


def risk_label(score: int) -> str:
    if score >= 90:
        return "Excellent"
    if score >= 75:
        return "Good"
    if score >= 50:
        return "Needs Improvement"
    if score >= 25:
        return "Poor"
    return "Critical"
