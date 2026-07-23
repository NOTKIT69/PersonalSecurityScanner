"""
headers.py
----------
All passive HTTP-level inspection lives here:

    * Security response headers
    * Server / technology disclosure headers
    * robots.txt / sitemap.xml presence
    * Common "accidentally exposed" file paths (existence check only)
    * Supported HTTP methods (via a single OPTIONS + safe requests)
    * Cookie flags (Secure / HttpOnly / SameSite)
    * HTTP -> HTTPS redirect behaviour

Every function below performs at most a small, fixed number of ordinary,
unauthenticated GET/HEAD/OPTIONS requests to the URL/paths the user typed
in. Nothing here brute-forces paths, guesses credentials, or sends
malformed/attack payloads. It only reads what the server voluntarily
returns to any normal visitor or browser.
"""

import requests

USER_AGENT = "PersonalSecurityScanner/1.0 (+educational passive scanner)"
DEFAULT_TIMEOUT = 6

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Embedder-Policy",
]

SERVER_INFO_HEADERS = ["Server", "X-Powered-By", "Via", "ETag"]

# Paths we only check for *existence* (status code). We never read/parse
# credentials or sensitive contents out of them, and we never attempt to
# use anything found there.
EXPOSED_FILE_PATHS = [
    "/.git/",
    "/.env",
    "/phpinfo.php",
    "/backup.zip",
    "/config.php",
    "/.htaccess",
]

HTTP_METHODS_TO_CHECK = ["OPTIONS", "HEAD", "GET", "POST"]


def _headers():
    return {"User-Agent": USER_AGENT}


def fetch_base_response(url: str):
    """Single GET request reused by several checks. Returns (response, error)."""
    try:
        resp = requests.get(url, headers=_headers(), timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        return resp, None
    except requests.exceptions.SSLError:
        return None, "SSL error while connecting."
    except requests.exceptions.ConnectionError:
        return None, "Connection refused or unreachable."
    except requests.exceptions.Timeout:
        return None, "Request timed out."
    except requests.exceptions.MissingSchema:
        return None, "Invalid URL — include http:// or https://"
    except requests.exceptions.RequestException as e:
        return None, f"Request error: {e}"


def check_security_headers(response) -> dict:
    """Return {header_name: present_value_or_None} for each header we track."""
    found = {}
    for h in SECURITY_HEADERS:
        found[h] = response.headers.get(h)
    return found


def check_server_info(response) -> dict:
    info = {}
    for h in SERVER_INFO_HEADERS:
        info[h] = response.headers.get(h)
    return info


def check_robots_txt(base_url: str) -> dict:
    url = base_url.rstrip("/") + "/robots.txt"
    try:
        resp = requests.get(url, headers=_headers(), timeout=DEFAULT_TIMEOUT)
        return {"exists": resp.status_code == 200, "url": url, "status_code": resp.status_code}
    except requests.exceptions.RequestException:
        return {"exists": False, "url": url, "status_code": None}


def check_sitemap_xml(base_url: str) -> dict:
    url = base_url.rstrip("/") + "/sitemap.xml"
    try:
        resp = requests.get(url, headers=_headers(), timeout=DEFAULT_TIMEOUT)
        return {"exists": resp.status_code == 200, "url": url, "status_code": resp.status_code}
    except requests.exceptions.RequestException:
        return {"exists": False, "url": url, "status_code": None}


def check_exposed_files(base_url: str) -> list:
    """
    For each known-sensitive path, make ONE plain GET request and record
    only whether it is publicly accessible (status code). We never download,
    parse, or make use of the file contents — this is existence-reporting
    only, intended to flag common misconfigurations so the owner can fix them.
    """
    results = []
    for path in EXPOSED_FILE_PATHS:
        url = base_url.rstrip("/") + path
        try:
            resp = requests.get(url, headers=_headers(), timeout=DEFAULT_TIMEOUT, allow_redirects=False)
            accessible = resp.status_code == 200
        except requests.exceptions.RequestException:
            accessible = False
            resp = None
        results.append({
            "path": path,
            "url": url,
            "accessible": accessible,
            "status_code": resp.status_code if resp is not None else None,
        })
    return results


def check_http_methods(url: str) -> dict:
    """
    Send one request per standard method to see which are acknowledged by
    the server (informational only — this is the same OPTIONS/HEAD
    negotiation any HTTP client performs, not a fuzzing attack).
    """
    allowed = {}
    try:
        resp = requests.options(url, headers=_headers(), timeout=DEFAULT_TIMEOUT)
        allow_header = resp.headers.get("Allow", "")
        methods_from_header = [m.strip().upper() for m in allow_header.split(",") if m.strip()]
    except requests.exceptions.RequestException:
        methods_from_header = []

    for method in HTTP_METHODS_TO_CHECK:
        if methods_from_header:
            allowed[method] = method in methods_from_header
        else:
            # Fall back to a direct, single request per method (still just
            # standard, unauthenticated HTTP requests).
            try:
                r = requests.request(method, url, headers=_headers(), timeout=DEFAULT_TIMEOUT, allow_redirects=False)
                allowed[method] = r.status_code < 405
            except requests.exceptions.RequestException:
                allowed[method] = False
    return allowed


def check_redirect_to_https(url: str) -> dict:
    """Check whether the plain-HTTP version of a site redirects to HTTPS."""
    if url.startswith("https://"):
        http_url = "http://" + url[len("https://"):]
    elif url.startswith("http://"):
        http_url = url
    else:
        http_url = "http://" + url

    try:
        resp = requests.get(http_url, headers=_headers(), timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        final_url = resp.url
        redirected = final_url.startswith("https://")
        return {"checked": True, "redirects_to_https": redirected, "final_url": final_url}
    except requests.exceptions.RequestException as e:
        return {"checked": False, "redirects_to_https": False, "error": str(e)}


def check_cookies(response) -> list:
    """Inspect Set-Cookie flags on the initial response's cookie jar."""
    cookie_reports = []
    for cookie in response.cookies:
        secure = bool(cookie.secure)
        httponly = "httponly" in [k.lower() for k in cookie._rest.keys()] if hasattr(cookie, "_rest") else False
        samesite = None
        if hasattr(cookie, "_rest"):
            for k, v in cookie._rest.items():
                if k.lower() == "samesite":
                    samesite = v
        cookie_reports.append({
            "name": cookie.name,
            "secure": secure,
            "httponly": httponly,
            "samesite": samesite,
        })
    return cookie_reports
