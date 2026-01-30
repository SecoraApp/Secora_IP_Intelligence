import re
import html

def sanitize_string(value, max_length=500):
    """Sanitize and validate string input"""
    if not isinstance(value, str):
        return ''

    # HTML escape and truncate
    sanitized = html.escape(value.strip())[:max_length]

    # Remove any potentially dangerous characters
    sanitized = re.sub(r'[<>"\']', '', sanitized)

    return sanitized
