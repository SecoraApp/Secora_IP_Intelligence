import requests
from .ip_list import *

def lookup_proxycheck(ip_address):
    """Check VPN/Proxy using proxycheck.io (free tier - 100 queries/day)"""
    try:
        response = requests.get(f'http://proxycheck.io/v2/{ip_address}?key=&vpn=1&asn=1', timeout=5)
        if response.status_code == 200:
            data = response.json()
            ip_data = data.get(ip_address, {})
            if isinstance(ip_data, dict):
                return {
                    'ip': ip_address,
                    'country': ip_data.get('country'),
                    'city': ip_data.get('city'),
                    'region': ip_data.get('region'),
                    'org': ip_data.get('organisation'),
                    'vpn_detected': ip_data.get('proxy') == 'yes' or ip_data.get('type') in ['VPN', 'TOR'],
                    'proxy_type': ip_data.get('type', 'Unknown'),
                    'source': 'proxycheck.io'
                }
        return {'ip': ip_address, 'source': 'proxycheck', 'status': 'Error', 'code': response.status_code}
    except Exception:
        return {'ip': ip_address, 'source': 'proxycheck', 'status': 'Down', 'code': None}

def lookup_getipintel(ip_address):
    """Check proxy using getipintel.net (free API)"""
    try:
        # Free API with contact email parameter
        response = requests.get(f'http://check.getipintel.net/check.php?ip={ip_address}&contact=admin@example.com&format=json', timeout=5)
        if response.status_code == 200:
            data = response.json()
            # getipintel returns a probability score (0-1)
            probability = float(data.get('result', 0))
            return {
                'ip': ip_address,
                'vpn_detected': probability > 0.99,  # Much higher threshold to reduce false positives
                'vpn_probability': probability,
                'source': 'getipintel.net'
            }
        return {'ip': ip_address, 'source': 'getipintel', 'status': 'Error', 'code': response.status_code}
    except Exception:
        return {'ip': ip_address, 'source': 'getipintel', 'status': 'Down', 'code': None}

def lookup_vpnapi(ip_address):
    """Check VPN using vpnapi.io (free tier - 1000 requests/month)"""
    try:
        response = requests.get(f'https://vpnapi.io/api/{ip_address}', timeout=5)
        if response.status_code == 200:
            data = response.json()
            security = data.get('security', {})
            location = data.get('location', {})
            network = data.get('network', {})

            return {
                'ip': ip_address,
                'city': location.get('city'),
                'region': location.get('region'),
                'country': location.get('country'),
                'org': network.get('autonomous_system_organization'),
                'vpn_detected': security.get('vpn', False) or security.get('proxy', False) or security.get('tor', False),
                'is_tor': security.get('tor', False),
                'is_proxy': security.get('proxy', False),
                'is_vpn': security.get('vpn', False),
                'source': 'vpnapi.io'
            }
        return {'ip': ip_address, 'source': 'vpnapi', 'status': 'Error', 'code': response.status_code}
    except Exception:
        return {'ip': ip_address, 'source': 'vpnapi', 'status': 'Down', 'code': None}

def check_vpn_proxy(ip_address):
    """Check if IP is VPN/Proxy using multiple methods"""
    vpn_detected = False
    proxy_detected = False
    tor_detected = False
    vpn_sources = []
    tor_sources = []
    detection_count = 0
    sources_used = 0

    # Run multiple VPN/Proxy detection methods concurrently
    detection_methods = [
        lookup_proxycheck,
        lookup_getipintel,
        lookup_vpnapi,
        lookup_ipqualityscore,
        lookup_scamalytics,
        lookup_blacklist_de,
        lookup_ip2proxy,
        lookup_threatcrowd,
        lookup_ipstack,
        lookup_freeipapi
    ]

    # Run detection methods concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(method, ip_address): method.__name__ for method in detection_methods}

        for future in concurrent.futures.as_completed(futures, timeout=15):
            try:
                result = future.result()
                sources_used += 1

                if result:
                    if result.get('vpn_detected') or result.get('is_vpn'):
                        vpn_detected = True
                        detection_count += 1
                        source_name = futures[future]
                        if source_name not in vpn_sources:
                            vpn_sources.append(source_name)

                    if result.get('proxy_detected') or result.get('is_proxy'):
                        proxy_detected = True
                        detection_count += 1
                        source_name = futures[future]
                        if source_name not in vpn_sources:
                            vpn_sources.append(source_name)

                    if result.get('tor_detected') or result.get('is_tor'):
                        tor_detected = True
                        source_name = futures[future]
                        if source_name not in tor_sources:
                            tor_sources.append(source_name)

            except Exception:
                continue

    # Check for Tor exit nodes
    tor_methods = [
        lookup_tor_exit_nodes,
        lookup_dan_me_tor,
        lookup_iphunter_tor,
        lookup_stopforumspam_tor,
        lookup_ipthreat_tor,
        lookup_torflix_tor,
        lookup_nordvpn_tor,
        lookup_blutmagie_tor,
        lookup_onionoo_tor,
        lookup_tor_eff,
        lookup_tor_bulk_exit
    ]

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(method, ip_address): method.__name__ for method in tor_methods}

        for future in concurrent.futures.as_completed(futures, timeout=15):
            try:
                result = future.result()
                sources_used += 1

                if result and (result.get('tor_detected') or result.get('is_tor')):
                    tor_detected = True
                    source_name = futures[future]
                    if source_name not in tor_sources:
                        tor_sources.append(source_name)

            except Exception:
                continue

    # Check if it's a known legitimate service
    org_info = ""
    try:
        ipinfo_response = requests.get(f'https://ipinfo.io/{ip_address}/json', timeout=5)
        if ipinfo_response.status_code == 200:
            ipinfo_data = ipinfo_response.json()
            org_info = ipinfo_data.get('org', '')
    except Exception:
        pass

    is_legitimate = is_known_legitimate_service(ip_address, org_info)

    # Determine confidence level
    if tor_detected:
        detection_confidence = 'High' if len(tor_sources) > 1 else 'Medium'
    elif vpn_detected or proxy_detected:
        if detection_count >= 4:
            detection_confidence = 'High'
        elif detection_count >= 2:
            detection_confidence = 'Medium'
        else:
            detection_confidence = 'Low'
    else:
        detection_confidence = 'Clean'

    return {
        'vpn_detected': vpn_detected,
        'proxy_detected': proxy_detected,
        'tor_detected': tor_detected,
        'vpn_sources': vpn_sources,
        'tor_sources': tor_sources,
        'detection_count': detection_count,
        'tor_detection_count': len(tor_sources),
        'sources_used': sources_used,
        'is_legitimate_service': is_legitimate,
        'detection_confidence': detection_confidence
    }

def get_vpn_provider_info(ip_address):
    """Get VPN provider information from multiple sources"""
    vpn_providers = []

    # Source 1: VPN IP Database (free API)
    try:
        response = requests.get(f'https://vpnapi.io/api/{ip_address}', timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get('security', {}).get('vpn'):
                provider = data.get('security', {}).get('name', 'Unknown VPN')
                vpn_providers.append({
                    'name': provider,
                    'confidence': 'high',
                    'source': 'vpnapi.io'
                })
    except Exception:
        pass

    # Source 2: IPHub (free tier)
    try:
        response = requests.get(f'http://v2.api.iphub.info/guest/ip/{ip_address}', timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get('block') == 1:  # VPN/Proxy detected
                asn = data.get('asn', '')
                if asn:
                    # Common VPN ASN patterns
                    vpn_asns = {
                        'AS16509': 'Amazon AWS',
                        'AS14618': 'Amazon AWS',
                        'AS15169': 'Google Cloud',
                        'AS396982': 'Google Cloud',
                        'AS8075': 'Microsoft Azure',
                        'AS8075': 'Microsoft Azure',
                        'AS16276': 'OVH',
                        'AS16276': 'OVH',
                        'AS14061': 'DigitalOcean',
                        'AS14061': 'DigitalOcean',
                        'AS20473': 'Choopa',
                        'AS20473': 'Choopa',
                        'AS36351': 'Cloudflare',
                        'AS13335': 'Cloudflare',
                        'AS45102': 'Alibaba Cloud',
                        'AS45102': 'Alibaba Cloud',
                        'AS16509': 'Amazon AWS',
                        'AS14618': 'Amazon AWS',
                        'AS15169': 'Google Cloud',
                        'AS396982': 'Google Cloud',
                        'AS8075': 'Microsoft Azure',
                        'AS8075': 'Microsoft Azure',
                        'AS16276': 'OVH',
                        'AS16276': 'OVH',
                        'AS14061': 'DigitalOcean',
                        'AS14061': 'DigitalOcean',
                        'AS20473': 'Choopa',
                        'AS20473': 'Choopa',
                        'AS36351': 'Cloudflare',
                        'AS13335': 'Cloudflare',
                        'AS45102': 'Alibaba Cloud',
                        'AS45102': 'Alibaba Cloud'
                    }
                    if asn in vpn_asns:
                        vpn_providers.append({
                            'name': vpn_asns[asn],
                            'confidence': 'medium',
                            'source': 'iphub.info'
                        })
    except Exception:
        pass

    # Source 3: Manual VPN provider detection based on organization names
    try:
        # Get basic IP info to check organization
        ipinfo_response = requests.get(f'https://ipinfo.io/{ip_address}/json', timeout=5)
        if ipinfo_response.status_code == 200:
            ipinfo_data = ipinfo_response.json()
            org = ipinfo_data.get('org', '').lower()

            # Common VPN provider patterns
            vpn_patterns = {
                'nordvpn': 'NordVPN',
                'expressvpn': 'ExpressVPN',
                'surfshark': 'Surfshark',
                'cyberghost': 'CyberGhost',
                'protonvpn': 'ProtonVPN',
                'private internet access': 'Private Internet Access',
                'pia': 'Private Internet Access',
                'tunnelbear': 'TunnelBear',
                'windscribe': 'Windscribe',
                'mullvad': 'Mullvad',
                'ivpn': 'IVPN',
                'perfect privacy': 'Perfect Privacy',
                'airvpn': 'AirVPN',
                'hide.me': 'Hide.me',
                'vpn.ac': 'VPN.ac',
                'ovpn': 'OVPN',
                'azirevpn': 'AzireVPN',
                'cactusvpn': 'CactusVPN',
                'fastestvpn': 'FastestVPN',
                'ipvanish': 'IPVanish',
                'purevpn': 'PureVPN',
                'vyprvpn': 'VyprVPN',
                'hotspot shield': 'Hotspot Shield',
                'hoxx': 'Hoxx',
                'zenmate': 'ZenMate',
                'torguard': 'TorGuard',
                'vpn unlimited': 'VPN Unlimited',
                'safervpn': 'SaferVPN',
                'hide my ass': 'Hide My Ass',
                'hma': 'Hide My Ass',
                'buffered': 'Buffered VPN',
                'vpn.ht': 'VPN.ht',
                'liquidvpn': 'LiquidVPN',
                'blackvpn': 'BlackVPN',
                'vpnsecure': 'VPNSecure',
                'vpnarea': 'VPNArea',
                'vpnbaron': 'VPNBaron',
                'vpnjack': 'VPNJack',
                'vpnland': 'VPNLand',
                'vpnme': 'VPNMe',
                'vpnshazam': 'VPNShazam',
                'vpntunnel': 'VPNTunnel',
                'vpnunlimited': 'VPNUnlimited',
                'vpn.ac': 'VPN.ac',
                'vpnsecure': 'VPNSecure',
                'vpnarea': 'VPNArea',
                'vpnbaron': 'VPNBaron',
                'vpnjack': 'VPNJack',
                'vpnland': 'VPNLand',
                'vpnme': 'VPNMe',
                'vpnshazam': 'VPNShazam',
                'vpntunnel': 'VPNTunnel',
                'vpnunlimited': 'VPNUnlimited'
            }

            for pattern, provider in vpn_patterns.items():
                if pattern in org:
                    vpn_providers.append({
                        'name': provider,
                        'confidence': 'high',
                        'source': 'organization analysis'
                    })
                    break
    except Exception:
        pass

    return vpn_providers

def check_apple_nordvpn(ip_address):
    # Ensure lists are loaded
    apple_ip_ranges, nordvpn_ips = download_and_parse_ip_lists()
    ip = ipaddress.ip_address(ip_address)
    # Check Apple
    for net in apple_ip_ranges:
        if ip in net:
            return 'Apple (iCloud Private Relay)'
    # Check NordVPN
    if ip in nordvpn_ips:
        return 'NordVPN'
    return None
