def is_valid_url(url):
    """Validate URL format"""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.scheme in ('http', 'https') and parsed.netloc
    except Exception:
        return False
