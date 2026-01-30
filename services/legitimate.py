def is_known_legitimate_service(ip_address, org_info):
    """Check if IP belongs to known legitimate services to reduce false positives"""
    legitimate_indicators = [
        # Major CDNs and cloud providers
        'cloudflare', 'amazon', 'google', 'microsoft', 'akamai',
        'fastly', 'cdn', 'aws', 'azure', 'gcp', 'facebook',
        # Major ISPs
        'comcast', 'verizon', 'at&t', 'charter', 'cox',
        # Public DNS providers
        'quad9', 'opendns', 'level3'
    ]

    # Check common legitimate IP ranges
    legitimate_ips = [
        '1.1.1.1', '1.0.0.1',  # Cloudflare DNS
        '8.8.8.8', '8.8.4.4',  # Google DNS
        '9.9.9.9', '149.112.112.112',  # Quad9 DNS
    ]

    if ip_address in legitimate_ips:
        return True

    if org_info:
        org_lower = str(org_info).lower()
        for indicator in legitimate_indicators:
            if indicator in org_lower:
                return True

    return False
