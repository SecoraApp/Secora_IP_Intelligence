"""
services/__init__.py

Re-exports the public API of each service module so callers can simply do:

    from services import lookup_ip, shorten_with_multiple_services, mail_check
"""

from services.ip_intelligence import (
    lookup_ip,
    lookup_ipinfo,
    lookup_ipapi,
    check_vpn_proxy,
    get_vpn_provider_info,
    check_apple_nordvpn,
    lookup_abuseipdb,
    lookup_abuseipdb_confidence,
)
from services.url_shortener import shorten_with_multiple_services
from services.mail_checker import mail_check

__all__ = [
    'lookup_ip',
    'lookup_ipinfo',
    'lookup_ipapi',
    'check_vpn_proxy',
    'get_vpn_provider_info',
    'check_apple_nordvpn',
    'lookup_abuseipdb',
    'lookup_abuseipdb_confidence',
    'shorten_with_multiple_services',
    'mail_check',
]
