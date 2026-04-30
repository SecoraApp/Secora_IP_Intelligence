"""
services/ip_intelligence.py — IP intelligence: geo-lookup, VPN/proxy/Tor
detection, AbuseIPDB integration, and provider identification.

All previously separate files (ip_lookup, vpn_proxy, tor_lookup, abuse,
legitimate) have been merged here to keep related logic together and reduce
import churn.
"""

import os
import ipaddress
import threading
import concurrent.futures

import requests


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY', 'your-abuseapi-key-was-not-found')

APPLE_IP_LIST_URL  = (
    "https://raw.githubusercontent.com/hroost/icloud-private-relay-iplist"
    "/refs/heads/main/ip-ranges.txt"
)
NORDVPN_IP_LIST_URL = (
    "https://gist.githubusercontent.com/JamoCA/eedaf4f7cce1cb0aeb5c1039af35f0b7"
    "/raw/cb6568528820c09e94cac7ef3461bc6cbf792e7e/NordVPN-Server-IP-List.txt"
)

# Module-level cache for Apple / NordVPN IP lists
_apple_ip_ranges: list | None = None
_nordvpn_ips: set | None = None
_ip_lists_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Geo / basic lookup
# ---------------------------------------------------------------------------

def lookup_ipinfo(ip_address):
    """Fetch geo data from ipinfo.io."""
    try:
        r = requests.get(f'https://ipinfo.io/{ip_address}/json', timeout=5)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


def lookup_ipapi(ip_address):
    """Fetch geo data from ip-api.com and normalise to ipinfo shape."""
    try:
        fields = ('status,message,country,countryCode,region,regionName,'
                  'city,zip,lat,lon,timezone,isp,org,as,query,proxy,hosting')
        r = requests.get(
            f'http://ip-api.com/json/{ip_address}?fields={fields}',
            timeout=5
        )
        if r.status_code == 200:
            d = r.json()
            if d.get('status') == 'success':
                lat, lon = d.get('lat'), d.get('lon')
                return {
                    'ip':          d.get('query'),
                    'city':        d.get('city'),
                    'region':      d.get('regionName'),
                    'country':     d.get('country'),
                    'loc':         f"{lat},{lon}" if lat and lon else None,
                    'org':         d.get('org') or d.get('isp'),
                    'postal':      d.get('zip'),
                    'timezone':    d.get('timezone'),
                    'vpn_detected': d.get('proxy', False) or d.get('hosting', False),
                    'source':      'ip-api.com',
                }
    except Exception:
        pass
    return None


def lookup_ipgeolocation(ip_address):
    """Fetch geo data from ipgeolocation.io (free tier)."""
    try:
        r = requests.get(
            f'https://api.ipgeolocation.io/ipgeo?ip={ip_address}', timeout=5
        )
        if r.status_code == 200:
            d = r.json()
            lat, lon = d.get('latitude'), d.get('longitude')
            return {
                'ip':       d.get('ip'),
                'city':     d.get('city'),
                'region':   d.get('state_prov'),
                'country':  d.get('country_name'),
                'loc':      f"{lat},{lon}" if lat and lon else None,
                'org':      d.get('isp'),
                'postal':   d.get('zipcode'),
                'timezone': d.get('time_zone', {}).get('name'),
                'source':   'ipgeolocation.io',
            }
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# AbuseIPDB
# ---------------------------------------------------------------------------

def lookup_abuseipdb(ip_address, max_age_days=90):
    """Return recent abuse reports from AbuseIPDB."""
    url = "https://api.abuseipdb.com/api/v2/reports"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params  = {"ipAddress": ip_address, "maxAgeInDays": max_age_days,
               "perPage": 6, "page": 1}
    try:
        r = requests.get(url, headers=headers, params=params, timeout=8)
        if r.status_code == 200:
            d = r.json().get("data", {})
            return {
                "abuseipdb_total_reports": d.get("total", 0),
                "abuseipdb_reports":       d.get("results", []),
                "abuseipdb_last_page":     d.get("lastPage", 1),
                "abuseipdb_error":         None,
            }
        return {"abuseipdb_error": f"Status {r.status_code}"}
    except Exception as e:
        return {"abuseipdb_error": str(e)}


def lookup_abuseipdb_confidence(ip_address):
    """Return the AbuseIPDB confidence score (0–100) or None on failure."""
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params  = {"ipAddress": ip_address, "maxAgeInDays": 90}
    try:
        r = requests.get(url, headers=headers, params=params, timeout=8)
        if r.status_code == 200:
            return r.json().get("data", {}).get("abuseConfidenceScore")
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# VPN / Proxy detection helpers
# ---------------------------------------------------------------------------

def _check_proxycheck(ip):
    try:
        r = requests.get(
            f'http://proxycheck.io/v2/{ip}?key=&vpn=1&asn=1', timeout=5
        )
        if r.status_code == 200:
            d = r.json().get(ip, {})
            if isinstance(d, dict):
                return {
                    'vpn_detected': d.get('proxy') == 'yes' or d.get('type') in ('VPN', 'TOR'),
                    'proxy_type':   d.get('type', 'Unknown'),
                    'source':       'proxycheck.io',
                }
    except Exception:
        pass
    return {}


def _check_getipintel(ip):
    try:
        url = (f'http://check.getipintel.net/check.php'
               f'?ip={ip}&contact=admin@example.com&format=json')
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            prob = float(r.json().get('result', 0))
            return {'vpn_detected': prob > 0.99, 'vpn_probability': prob,
                    'source': 'getipintel.net'}
    except Exception:
        pass
    return {}


def _check_vpnapi(ip):
    try:
        r = requests.get(f'https://vpnapi.io/api/{ip}', timeout=5)
        if r.status_code == 200:
            d = r.json()
            sec = d.get('security', {})
            loc = d.get('location', {})
            net = d.get('network', {})
            return {
                'vpn_detected': sec.get('vpn') or sec.get('proxy') or sec.get('tor'),
                'is_tor':       sec.get('tor', False),
                'is_proxy':     sec.get('proxy', False),
                'is_vpn':       sec.get('vpn', False),
                'city':         loc.get('city'),
                'region':       loc.get('region'),
                'country':      loc.get('country'),
                'org':          net.get('autonomous_system_organization'),
                'source':       'vpnapi.io',
            }
    except Exception:
        pass
    return {}


def _check_ipqualityscore(ip):
    try:
        r = requests.get(
            f'https://ipqualityscore.com/api/json/ip/{ip}', timeout=5
        )
        if r.status_code == 200:
            d = r.json()
            return {
                'vpn_detected':   d.get('vpn', False),
                'proxy_detected': d.get('proxy', False),
                'tor_detected':   d.get('tor', False),
                'fraud_score':    d.get('fraud_score', 0),
                'source':         'ipqualityscore.com',
            }
    except Exception:
        pass
    return {}


def _check_scamalytics(ip):
    try:
        r = requests.get(f'https://scamalytics.com/ip/{ip}', timeout=5)
        if r.status_code == 200:
            c = r.text.lower()
            return {
                'vpn_detected': 'vpn' in c or 'proxy' in c or 'anonymizer' in c,
                'source':       'scamalytics.com',
            }
    except Exception:
        pass
    return {}


def _check_blacklist_de(ip):
    try:
        r = requests.get(
            f'http://www.blacklist.de/query_ip.php?ip={ip}', timeout=5
        )
        if r.status_code == 200:
            return {'vpn_detected': 'found' in r.text.lower(),
                    'source': 'blacklist.de'}
    except Exception:
        pass
    return {}


def _check_ip2proxy(ip):
    try:
        r = requests.get(
            f'https://api.ip2proxy.com/?ip={ip}&format=json&package=PX1',
            timeout=5
        )
        if r.status_code == 200:
            d = r.json()
            return {
                'vpn_detected': d.get('isProxy', 'NO') == 'YES',
                'proxy_type':   d.get('proxyType', 'Unknown'),
                'source':       'ip2proxy.com',
            }
    except Exception:
        pass
    return {}


def _check_freeipapi(ip):
    try:
        r = requests.get(f'https://freeipapi.com/api/json/{ip}', timeout=5)
        if r.status_code == 200:
            d = r.json()
            isp = d.get('isp', '').lower()
            return {
                'vpn_detected': any(kw in isp for kw in
                                    ('vpn', 'proxy', 'hosting', 'cloud', 'datacenter')),
                'source': 'freeipapi.com',
            }
    except Exception:
        pass
    return {}


# ---------------------------------------------------------------------------
# Tor detection helpers
# ---------------------------------------------------------------------------

def _tor_torproject_exit_list(ip):
    try:
        r = requests.get('https://check.torproject.org/torbulkexitlist', timeout=10)
        if r.status_code == 200:
            found = ip in r.text.strip().split('\n')
            return {'is_tor': found, 'vpn_detected': found,
                    'source': 'torproject.org'}
    except Exception:
        pass
    return {}


def _tor_dan_me(ip):
    try:
        r = requests.get(f'https://www.dan.me.uk/torcheck?ip={ip}', timeout=5)
        if r.status_code == 200:
            found = r.text.strip().upper() == 'Y'
            return {'is_tor': found, 'vpn_detected': found, 'source': 'dan.me.uk'}
    except Exception:
        pass
    return {}


def _tor_iphunter(ip):
    try:
        r = requests.get(f'https://www.iphunter.info/api/v1/ip/{ip}', timeout=5)
        if r.status_code == 200:
            d = r.json()
            found = d.get('is_tor', False) or d.get('is_proxy', False)
            return {'is_tor': d.get('is_tor', False), 'vpn_detected': found,
                    'source': 'iphunter.info'}
    except Exception:
        pass
    return {}


def _tor_stopforumspam(ip):
    try:
        r = requests.get(
            f'http://www.stopforumspam.com/api?ip={ip}&json', timeout=5
        )
        if r.status_code == 200:
            appears = r.json().get('ip', {}).get('appears', 0)
            return {'is_tor': appears > 0, 'vpn_detected': appears > 0,
                    'source': 'stopforumspam.com'}
    except Exception:
        pass
    return {}


def _tor_ipthreat(ip):
    try:
        r = requests.get(f'https://api.ipthreat.net/v1/check/{ip}', timeout=5)
        if r.status_code == 200:
            d = r.json()
            found = d.get('is_tor') or d.get('is_proxy') or d.get('threat_level', 0) > 3
            return {'is_tor': d.get('is_tor', False), 'vpn_detected': found,
                    'source': 'ipthreat.net'}
    except Exception:
        pass
    return {}


def _tor_onionoo(ip):
    try:
        r = requests.get(
            f'https://onionoo.torproject.org/details?search={ip}', timeout=10
        )
        if r.status_code == 200:
            for relay in r.json().get('relays', []):
                if ip in relay.get('or_addresses', []) or ip in relay.get('exit_addresses', []):
                    return {'is_tor': True, 'vpn_detected': True,
                            'source': 'onionoo.torproject.org'}
    except Exception:
        pass
    return {}


def _tor_bulk_mirrors(ip):
    mirrors = [
        'https://www.dan.me.uk/torlist/',
        'https://torstatus.rueckgr.at/ip_list_exit.php/Tor_ip_list_EXIT.csv',
        'https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1',
    ]
    for url in mirrors:
        try:
            r = requests.get(url, timeout=8)
            if r.status_code == 200 and ip in r.text:
                return {'is_tor': True, 'vpn_detected': True,
                        'source': 'tor_bulk_exit_list'}
        except Exception:
            continue
    return {}


# ---------------------------------------------------------------------------
# Main VPN/proxy/Tor orchestrator
# ---------------------------------------------------------------------------

def check_vpn_proxy(ip_address):
    """
    Run multiple VPN/proxy/Tor checks concurrently and aggregate results.
    Returns a dict with detection flags, sources, and confidence level.
    """
    vpn_detected = proxy_detected = tor_detected = False
    vpn_sources, tor_sources = [], []
    detection_count = sources_used = 0

    vpn_methods = [
        _check_proxycheck, _check_getipintel, _check_vpnapi,
        _check_ipqualityscore, _check_scamalytics, _check_blacklist_de,
        _check_ip2proxy, _check_freeipapi,
    ]
    tor_methods = [
        _tor_torproject_exit_list, _tor_dan_me, _tor_iphunter,
        _tor_stopforumspam, _tor_ipthreat, _tor_onionoo, _tor_bulk_mirrors,
    ]

    def _run_methods(methods):
        nonlocal vpn_detected, proxy_detected, tor_detected
        nonlocal vpn_sources, tor_sources, detection_count, sources_used

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            futures = {ex.submit(m, ip_address): m.__name__ for m in methods}
            for future in concurrent.futures.as_completed(futures, timeout=15):
                try:
                    result = future.result() or {}
                    name   = futures[future]
                    sources_used += 1

                    if result.get('vpn_detected') or result.get('is_vpn'):
                        vpn_detected = True
                        detection_count += 1
                        if name not in vpn_sources:
                            vpn_sources.append(name)

                    if result.get('proxy_detected') or result.get('is_proxy'):
                        proxy_detected = True
                        detection_count += 1
                        if name not in vpn_sources:
                            vpn_sources.append(name)

                    if result.get('tor_detected') or result.get('is_tor'):
                        tor_detected = True
                        if name not in tor_sources:
                            tor_sources.append(name)
                except Exception:
                    pass

    _run_methods(vpn_methods)
    _run_methods(tor_methods)

    # Org-name check for legitimate services
    org_info = ''
    try:
        r = requests.get(f'https://ipinfo.io/{ip_address}/json', timeout=5)
        if r.status_code == 200:
            org_info = r.json().get('org', '')
    except Exception:
        pass

    is_legitimate = _is_known_legitimate_service(ip_address, org_info)

    if tor_detected:
        confidence = 'High' if len(tor_sources) > 1 else 'Medium'
    elif vpn_detected or proxy_detected:
        if detection_count >= 4:
            confidence = 'High'
        elif detection_count >= 2:
            confidence = 'Medium'
        else:
            confidence = 'Low'
    else:
        confidence = 'Clean'

    return {
        'vpn_detected':        vpn_detected,
        'proxy_detected':      proxy_detected,
        'tor_detected':        tor_detected,
        'vpn_sources':         vpn_sources,
        'tor_sources':         tor_sources,
        'detection_count':     detection_count,
        'tor_detection_count': len(tor_sources),
        'sources_used':        sources_used,
        'is_legitimate_service': is_legitimate,
        'detection_confidence': confidence,
    }


def _is_known_legitimate_service(ip_address, org_info):
    """Return True if the IP belongs to a well-known legitimate provider."""
    legitimate_ips = {'1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4',
                      '9.9.9.9', '149.112.112.112'}
    if ip_address in legitimate_ips:
        return True

    indicators = [
        'cloudflare', 'amazon', 'google', 'microsoft', 'akamai',
        'fastly', 'cdn', 'aws', 'azure', 'gcp', 'facebook',
        'comcast', 'verizon', 'at&t', 'charter', 'cox',
        'quad9', 'opendns', 'level3',
    ]
    if org_info:
        org_lower = str(org_info).lower()
        if any(ind in org_lower for ind in indicators):
            return True

    return False


# ---------------------------------------------------------------------------
# VPN provider identification
# ---------------------------------------------------------------------------

# Known VPN provider name patterns found in org/ISP strings
_VPN_ORG_PATTERNS = {
    'nordvpn': 'NordVPN', 'expressvpn': 'ExpressVPN', 'surfshark': 'Surfshark',
    'cyberghost': 'CyberGhost', 'protonvpn': 'ProtonVPN',
    'private internet access': 'Private Internet Access', 'pia': 'Private Internet Access',
    'tunnelbear': 'TunnelBear', 'windscribe': 'Windscribe', 'mullvad': 'Mullvad',
    'ivpn': 'IVPN', 'perfect privacy': 'Perfect Privacy', 'airvpn': 'AirVPN',
    'hide.me': 'Hide.me', 'vpn.ac': 'VPN.ac', 'ovpn': 'OVPN',
    'azirevpn': 'AzireVPN', 'cactusvpn': 'CactusVPN', 'fastestvpn': 'FastestVPN',
    'ipvanish': 'IPVanish', 'purevpn': 'PureVPN', 'vyprvpn': 'VyprVPN',
    'hotspot shield': 'Hotspot Shield', 'hoxx': 'Hoxx', 'zenmate': 'ZenMate',
    'torguard': 'TorGuard', 'vpn unlimited': 'VPN Unlimited', 'safervpn': 'SaferVPN',
    'hide my ass': 'Hide My Ass', 'hma': 'Hide My Ass', 'buffered': 'Buffered VPN',
    'vpn.ht': 'VPN.ht', 'liquidvpn': 'LiquidVPN', 'blackvpn': 'BlackVPN',
    'vpnsecure': 'VPNSecure', 'vpnarea': 'VPNArea',
}

_VPN_ASNS = {
    'AS16509': 'Amazon AWS', 'AS14618': 'Amazon AWS',
    'AS15169': 'Google Cloud', 'AS396982': 'Google Cloud',
    'AS8075':  'Microsoft Azure',
    'AS16276': 'OVH',
    'AS14061': 'DigitalOcean',
    'AS20473': 'Choopa',
    'AS13335': 'Cloudflare', 'AS36351': 'Cloudflare',
    'AS45102': 'Alibaba Cloud',
}


def get_vpn_provider_info(ip_address):
    """Return a list of possible VPN provider dicts for *ip_address*."""
    providers = []

    # Source 1: vpnapi.io
    try:
        r = requests.get(f'https://vpnapi.io/api/{ip_address}', timeout=5)
        if r.status_code == 200:
            d = r.json()
            if d.get('security', {}).get('vpn'):
                name = d.get('security', {}).get('name', 'Unknown VPN')
                providers.append({'name': name, 'confidence': 'high',
                                  'source': 'vpnapi.io'})
    except Exception:
        pass

    # Source 2: IPHub ASN check
    try:
        r = requests.get(f'http://v2.api.iphub.info/guest/ip/{ip_address}', timeout=5)
        if r.status_code == 200:
            d = r.json()
            if d.get('block') == 1:
                asn = d.get('asn', '')
                if asn in _VPN_ASNS:
                    providers.append({'name': _VPN_ASNS[asn], 'confidence': 'medium',
                                      'source': 'iphub.info'})
    except Exception:
        pass

    # Source 3: ipinfo.io org name matching
    try:
        r = requests.get(f'https://ipinfo.io/{ip_address}/json', timeout=5)
        if r.status_code == 200:
            org = r.json().get('org', '').lower()
            for pattern, name in _VPN_ORG_PATTERNS.items():
                if pattern in org:
                    providers.append({'name': name, 'confidence': 'high',
                                      'source': 'organization analysis'})
                    break
    except Exception:
        pass

    return providers


# ---------------------------------------------------------------------------
# Apple iCloud / NordVPN IP list check
# ---------------------------------------------------------------------------

def _load_ip_lists():
    global _apple_ip_ranges, _nordvpn_ips
    with _ip_lists_lock:
        if _apple_ip_ranges is not None and _nordvpn_ips is not None:
            return

        # Apple
        try:
            r = requests.get(APPLE_IP_LIST_URL, timeout=10)
            _apple_ip_ranges = []
            if r.status_code == 200:
                for line in r.text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        cidr = line if '/' in line else line + '/32'
                        _apple_ip_ranges.append(
                            ipaddress.ip_network(cidr, strict=False)
                        )
                    except Exception:
                        pass
        except Exception:
            _apple_ip_ranges = []

        # NordVPN
        try:
            r = requests.get(NORDVPN_IP_LIST_URL, timeout=10)
            _nordvpn_ips = set()
            if r.status_code == 200:
                for line in r.text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        _nordvpn_ips.add(ipaddress.ip_address(line))
                    except Exception:
                        pass
        except Exception:
            _nordvpn_ips = set()


def check_apple_nordvpn(ip_address):
    """Return provider name if *ip_address* belongs to Apple or NordVPN, else None."""
    _load_ip_lists()
    try:
        ip = ipaddress.ip_address(ip_address)
        for net in _apple_ip_ranges:
            if ip in net:
                return 'Apple (iCloud Private Relay)'
        if ip in _nordvpn_ips:
            return 'NordVPN'
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Main public entry point
# ---------------------------------------------------------------------------

def lookup_ip(ip_address):
    """
    Perform a full IP intelligence lookup:
      - Geo data (ipinfo.io → ip-api.com fallback)
      - VPN/proxy/Tor detection
      - VPN provider identification
      - AbuseIPDB reports & confidence score
      - Apple / NordVPN list check
    """
    try:
        ipinfo_data = lookup_ipinfo(ip_address)
        ipapi_data  = lookup_ipapi(ip_address)

        if ipinfo_data:
            org = ipinfo_data.get('org', '')
            result = {
                'ip':       ip_address,
                'city':     ipinfo_data.get('city'),
                'region':   ipinfo_data.get('region'),
                'country':  ipinfo_data.get('country'),
                'loc':      ipinfo_data.get('loc'),
                'org':      org,
                'postal':   ipinfo_data.get('postal'),
                'timezone': ipinfo_data.get('timezone'),
                'asn':      (ipinfo_data.get('asn')
                             or (org.split()[0] if org.startswith('AS') else None)),
            }
        elif ipapi_data:
            org = ipapi_data.get('org', '')
            result = {
                'ip':       ip_address,
                'city':     ipapi_data.get('city'),
                'region':   ipapi_data.get('regionName'),
                'country':  ipapi_data.get('country'),
                'loc':      (f"{ipapi_data['lat']},{ipapi_data['lon']}"
                             if ipapi_data.get('lat') and ipapi_data.get('lon')
                             else None),
                'org':      org,
                'postal':   ipapi_data.get('zip'),
                'timezone': ipapi_data.get('timezone'),
                'asn':      (ipapi_data.get('as')
                             or (org.split()[0] if org.startswith('AS') else None)),
            }
        else:
            result = {'ip': ip_address}

        # VPN / proxy / Tor
        vpn_result = check_vpn_proxy(ip_address)
        if vpn_result:
            result.update(vpn_result)

        # Provider info
        providers = get_vpn_provider_info(ip_address)
        if providers:
            result['vpn_providers'] = providers
            high = [p for p in providers if p['confidence'] == 'high']
            result['likely_vpn_provider'] = (high or providers)[0]['name']

        # AbuseIPDB
        result.update(lookup_abuseipdb(ip_address))
        score = lookup_abuseipdb_confidence(ip_address)
        if score is not None:
            result['abuseipdb_confidence_score'] = score

        # Apple / NordVPN override
        try:
            provider = check_apple_nordvpn(ip_address)
            if provider:
                result['likely_vpn_provider'] = provider
        except Exception:
            pass

        return result

    except Exception as e:
        print(f"Error in lookup_ip: {e}")
        return {'ip': ip_address, 'error': 'Lookup failed'}
