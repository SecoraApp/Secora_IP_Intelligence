"""
services/mail_checker.py — Email domain blocklist check.
"""

import json

_DOMAINS: set | None = None


def mail_check(email, blocklist_path='email_deny_list.json'):
    """
    Return True if *email*'s domain is NOT on the deny list, False otherwise.

    The blocklist JSON file is read once and cached for the lifetime of the
    process.
    """
    global _DOMAINS

    if _DOMAINS is None:
        try:
            with open(blocklist_path, 'r') as f:
                data = json.load(f)
                _DOMAINS = {d.lower() for d in data.get('denied_domains', [])}
        except (FileNotFoundError, json.JSONDecodeError):
            _DOMAINS = set()

    if not email or '@' not in email:
        return False

    try:
        parts = email.split('@')
        if len(parts) != 2 or not parts[0] or not parts[1]:
            return False
        domain = parts[1].lower().strip()
        return domain not in _DOMAINS
    except (IndexError, AttributeError):
        return False
