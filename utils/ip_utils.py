import re

def is_valid_ip(ip):
    """Validate IP address format with additional security checks"""
    if not ip or not isinstance(ip, str):
        return False

    # Basic length check
    if len(ip) > 15 or len(ip) < 7:
        return False

    # Check for valid IPv4 format
    ip_pattern = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    if not ip_pattern.match(ip):
        return False

    # Block private/reserved IP ranges for external lookups
    parts = ip.split('.')
    if len(parts) != 4:
        return False

    try:
        octets = [int(part) for part in parts]
    except ValueError:
        return False

    # Check for private/reserved ranges
    if (octets[0] == 10 or
        (octets[0] == 172 and 16 <= octets[1] <= 31) or
        (octets[0] == 192 and octets[1] == 168) or
        octets[0] == 127 or  # localhost
        octets[0] == 0 or    # invalid
        octets[0] >= 224):   # multicast/reserved
        return False

    return True
