"""
ssl_checker.py
--------------
Passive SSL/TLS inspection.

This module ONLY opens a standard TLS handshake (the same handshake any
browser performs when visiting a site) to read the certificate that the
server voluntarily presents. It never attempts weak-cipher downgrade
attacks, certificate forgery, or any other active/exploitative behaviour.
"""

import socket
import ssl
from datetime import datetime


class SSLCheckError(Exception):
    pass


def check_ssl(hostname: str, port: int = 443, timeout: float = 6.0) -> dict:
    """
    Perform a standard TLS handshake and return certificate details.

    Returns a dict with keys:
        https_enabled, valid, expired, issuer, subject, expires_on,
        days_remaining, hostname_match, tls_version, error
    """
    result = {
        "https_enabled": False,
        "valid": False,
        "expired": None,
        "issuer": None,
        "subject": None,
        "expires_on": None,
        "days_remaining": None,
        "hostname_match": None,
        "tls_version": None,
        "error": None,
    }

    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                result["https_enabled"] = True
                result["tls_version"] = ssock.version()
                cert = ssock.getpeercert()

                # Issuer / Subject as readable strings
                result["issuer"] = _format_name(cert.get("issuer", []))
                result["subject"] = _format_name(cert.get("subject", []))

                # Expiration
                not_after = cert.get("notAfter")
                if not_after:
                    expires_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %GMT")
                    result["expires_on"] = expires_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                    remaining = (expires_dt - datetime.utcnow()).days
                    result["days_remaining"] = remaining
                    result["expired"] = remaining < 0

                # Hostname match: the default context already verifies this
                # during the handshake (it raises ssl.CertificateError if it
                # fails), so if we got here it matched.
                result["hostname_match"] = True
                result["valid"] = not result["expired"]

    except ssl.SSLCertVerificationError as e:
        result["error"] = f"Certificate verification failed: {e.verify_message if hasattr(e, 'verify_message') else str(e)}"
        result["hostname_match"] = False
    except socket.timeout:
        result["error"] = "Connection timed out while checking SSL certificate."
    except ConnectionRefusedError:
        result["error"] = "Connection refused on port 443 (HTTPS may not be enabled)."
    except socket.gaierror:
        result["error"] = "Could not resolve hostname (DNS error)."
    except OSError as e:
        result["error"] = f"Network error while checking SSL: {e}"
    except Exception as e:  # noqa: BLE001 - surface any unexpected error safely
        result["error"] = f"Unexpected SSL check error: {e}"

    return result


def _format_name(name_tuple) -> str:
    """Convert the awkward nested tuple format cert names come in into a
    simple 'CN=..., O=...' style string."""
    parts = []
    for rdn in name_tuple:
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts) if parts else "Unknown"
