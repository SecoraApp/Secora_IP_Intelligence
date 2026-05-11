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

    if (octets[0] == 10
            or (octets[0] == 172 and 16 <= octets[1] <= 31)
            or (octets[0] == 192 and octets[1] == 168)
            or octets[0] == 127
            or octets[0] == 0
            or octets[0] >= 224):
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


def validate_username(username):
    """
    Validate a username string.
    Returns (ok: bool, error: str | None).
    Rules: 3–80 chars, letters/numbers/underscore/hyphen only.
    """
    if not username or not isinstance(username, str):
        return False, 'Username is required.'
    if len(username) < 3:
        return False, 'Username must be at least 3 characters.'
    if len(username) > 80:
        return False, 'Username must be 80 characters or fewer.'
    if not re.match(r'^[a-zA-Z0-9_\-]+$', username):
        return False, 'Username may only contain letters, numbers, underscores, and hyphens.'
    return True, None


def validate_email(email):
    """
    Basic email format validation and length cap.
    Returns (ok: bool, error: str | None).
    Full deliverability is checked by mail_check() in services.
    """
    if not email or not isinstance(email, str):
        return False, 'Email address is required.'
    if len(email) > 254:
        return False, 'Email address is too long.'
    if '@' not in email or '.' not in email.split('@')[-1]:
        return False, 'Please enter a valid email address.'
    return True, None


# ---------------------------------------------------------------------------
# Password complexity
# ---------------------------------------------------------------------------

def validate_password_complexity(password):
    """
    Enforce the same rules shown in the frontend strength bar.
    Returns (ok: bool, error: str | None).
    """
    if not password or not isinstance(password, str):
        return False, 'Password is required.'
    if len(password) < 15:
        return False, 'Password must be at least 15 characters long.'
    if len(password) > 1024:
        return False, 'Password is too long.'
    if not re.search(r'[A-Z]', password):
        return False, 'Password must contain at least one uppercase letter.'
    if not re.search(r'[a-z]', password):
        return False, 'Password must contain at least one lowercase letter.'
    if not re.search(r'[0-9]', password):
        return False, 'Password must contain at least one number.'
    if not re.search(r'[^A-Za-z0-9]', password):
        return False, 'Password must contain at least one special character.'
    return True, None


# ---------------------------------------------------------------------------
# Allowlists for enum-type fields
# ---------------------------------------------------------------------------

ALLOWED_REPORT_TYPES = {
    'spam',
    'malicious',
    'brute_force',
    'scanning',
    'phishing',
    'ddos',
    'botnet',
    'other',
}


def validate_report_type(value):
    """Return (ok, error) — ensures report_type is one of the allowed values."""
    if value not in ALLOWED_REPORT_TYPES:
        return False, f'Invalid report type. Must be one of: {", ".join(sorted(ALLOWED_REPORT_TYPES))}'
    return True, None
