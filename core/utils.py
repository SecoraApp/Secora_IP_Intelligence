"""
utils.py — Shared helper functions: validation, sanitization, URL checks.
"""

import re
import html
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# IP helpers
# ---------------------------------------------------------------------------

def is_valid_ip(ip):
    """Validate an IPv4 address and reject private/reserved ranges."""
    if not ip or not isinstance(ip, str):
        return False

    if len(ip) > 15 or len(ip) < 7:
        return False

    ip_pattern = re.compile(
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    )
    if not ip_pattern.match(ip):
        return False

    parts = ip.split('.')
    if len(parts) != 4:
        return False

    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False

    # Block private/reserved ranges
    if (octets[0] == 10
            or (octets[0] == 172 and 16 <= octets[1] <= 31)
            or (octets[0] == 192 and octets[1] == 168)
            or octets[0] == 127   # localhost
            or octets[0] == 0     # invalid
            or octets[0] >= 224): # multicast/reserved
        return False

    return True


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------

def is_valid_url(url):
    """Return True if *url* has an http/https scheme and a host."""
    try:
        parsed = urlparse(url)
        return parsed.scheme in ('http', 'https') and bool(parsed.netloc)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# String helpers
# ---------------------------------------------------------------------------

def sanitize_string(value, max_length=500):
    """HTML-escape, truncate, and strip dangerous characters from *value*."""
    if not isinstance(value, str):
        return ''
    sanitized = html.escape(value.strip())[:max_length]
    sanitized = re.sub(r'[<>"\']', '', sanitized)
    return sanitized


# ---------------------------------------------------------------------------
# Password complexity
# ---------------------------------------------------------------------------

import re as _re


def validate_password_complexity(password: str) -> tuple[bool, str | None]:
    """
    Enforce the same rules shown in the frontend strength bar.
    Returns (ok, error_message).
    """
    if len(password) < 15:
        return False, 'Password must be at least 15 characters long.'
    if not _re.search(r'[A-Z]', password):
        return False, 'Password must contain at least one uppercase letter.'
    if not _re.search(r'[a-z]', password):
        return False, 'Password must contain at least one lowercase letter.'
    if not _re.search(r'[0-9]', password):
        return False, 'Password must contain at least one number.'
    if not _re.search(r'[^A-Za-z0-9]', password):
        return False, 'Password must contain at least one special character.'
    return True, None
