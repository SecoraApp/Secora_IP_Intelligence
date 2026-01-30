import requests
from .vpn_proxy import *
from .abuse import *
from utils.ip_utils import *

def lookup_ipinfo(ip_address):
    """Lookup IP information using ipinfo.io"""
    try:
        response = requests.get(f'https://ipinfo.io/{ip_address}/json', timeout=5)
        if response.status_code == 200:
            return response.json()
        return None
    except Exception:
        return None

def lookup_ipapi(ip_address):
    """Lookup IP information using ip-api.com"""
    try:
        response = requests.get(f'http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query,proxy,hosting', timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                # Convert to ipinfo format
                return {
                    'ip': data.get('query'),
                    'city': data.get('city'),
                    'region': data.get('regionName'),
                    'country': data.get('country'),
                    'loc': f"{data.get('lat', '')},{data.get('lon', '')}" if data.get('lat') and data.get('lon') else None,
                    'org': data.get('org') or data.get('isp'),
                    'postal': data.get('zip'),
                    'timezone': data.get('timezone'),
                    'vpn_detected': data.get('proxy', False) or data.get('hosting', False),
                    'source': 'ip-api.com'
                }
        return {'ip': ip_address, 'source': 'ipapi', 'status': 'Error', 'code': response.status_code}
    except Exception:
        return {'ip': ip_address, 'source': 'ipapi', 'status': 'Down', 'code': None}

def lookup_ipgeolocation(ip_address):
    """Lookup IP information using ipgeolocation.io (free tier)"""
    try:
        # Using free tier (no API key required but limited requests)
        response = requests.get(f'https://api.ipgeolocation.io/ipgeo?ip={ip_address}', timeout=5)
        if response.status_code == 200:
            data = response.json()
            return {
                'ip': data.get('ip'),
                'city': data.get('city'),
                'region': data.get('state_prov'),
                'country': data.get('country_name'),
                'loc': f"{data.get('latitude', '')},{data.get('longitude', '')}" if data.get('latitude') and data.get('longitude') else None,
                'org': data.get('isp'),
                'postal': data.get('zipcode'),
                'timezone': data.get('time_zone', {}).get('name'),
                'source': 'ipgeolocation.io'
            }
        return {'ip': ip_address, 'source': 'ipgeolocation', 'status': 'Error', 'code': response.status_code}
    except Exception:
        return {'ip': ip_address, 'source': 'ipgeolocation', 'status': 'Down', 'code': None}

def lookup_ip(ip_address):
    """Main IP lookup function that combines multiple sources"""
    try:
        # Get basic IP information
        ipinfo_data = lookup_ipinfo(ip_address)
        ipapi_data = lookup_ipapi(ip_address)

        # Use the best available data
        if ipinfo_data:
            result = {
                'ip': ip_address,
                'city': ipinfo_data.get('city'),
                'region': ipinfo_data.get('region'),
                'country': ipinfo_data.get('country'),
                'loc': ipinfo_data.get('loc'),
                'org': ipinfo_data.get('org'),
                'postal': ipinfo_data.get('postal'),
                'timezone': ipinfo_data.get('timezone'),
                'asn': ipinfo_data.get('asn') or (ipinfo_data.get('org').split()[0] if ipinfo_data.get('org') and ipinfo_data.get('org').startswith('AS') else None)
            }
        elif ipapi_data:
            result = {
                'ip': ip_address,
                'city': ipapi_data.get('city'),
                'region': ipapi_data.get('regionName'),
                'country': ipapi_data.get('country'),
                'loc': f"{ipapi_data.get('lat')},{ipapi_data.get('lon')}" if ipapi_data.get('lat') and ipapi_data.get('lon') else None,
                'org': ipapi_data.get('org'),
                'postal': ipapi_data.get('zip'),
                'timezone': ipapi_data.get('timezone'),
                'asn': ipapi_data.get('as') or (ipapi_data.get('org').split()[0] if ipapi_data.get('org') and ipapi_data.get('org').startswith('AS') else None)
            }
        else:
            result = {'ip': ip_address}

        # Check VPN/Proxy status
        vpn_proxy_result = check_vpn_proxy(ip_address)
        if vpn_proxy_result and isinstance(vpn_proxy_result, dict):
            result.update(vpn_proxy_result)

        # Get VPN provider information
        vpn_providers = get_vpn_provider_info(ip_address)
        if vpn_providers:
            result['vpn_providers'] = vpn_providers
            # Set the most likely provider as the primary one
            high_confidence = [p for p in vpn_providers if p['confidence'] == 'high']
            if high_confidence:
                result['likely_vpn_provider'] = high_confidence[0]['name']
            else:
                result['likely_vpn_provider'] = vpn_providers[0]['name']

        # AbuseIPDB integration
        abuseipdb_data = lookup_abuseipdb(ip_address)
        result.update(abuseipdb_data)
        # Optionally, get the confidence score
        abuseipdb_conf = lookup_abuseipdb_confidence(ip_address)
        if abuseipdb_conf is not None:
            result['abuseipdb_confidence_score'] = abuseipdb_conf

        # Apple/NordVPN detection
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

def lookup_ipqualityscore(ip_address):
    """Check IP using IPQualityScore (free checks available)"""
    try:
        response = requests.get(f'https://ipqualityscore.com/api/json/ip/{ip_address}', timeout=5)
        if response.status_code == 200:
            data = response.json()
            return {
                'vpn_detected': data.get('vpn', False),
                'proxy_detected': data.get('proxy', False),
                'tor_detected': data.get('tor', False),
                'fraud_score': data.get('fraud_score', 0)
            }
        return {'ip': ip_address, 'source': 'ipqualityscore', 'status': 'Error', 'code': response.status_code}
    except Exception:
        return {'ip': ip_address, 'source': 'ipqualityscore', 'status': 'Down', 'code': None}

def lookup_scamalytics(ip_address):
    """Check IP using Scamalytics (free checks available)"""
    try:
        # Scamalytics has a simple check endpoint
        response = requests.get(f'https://scamalytics.com/ip/{ip_address}', timeout=5)
        if response.status_code == 200:
            # Simple text parsing for basic detection
            content = response.text.lower()
            is_vpn = 'vpn' in content or 'proxy' in content or 'anonymizer' in content
            return {
                'ip': ip_address,
                'vpn_detected': is_vpn,
                'source': 'scamalytics.com'
            }
        return {'ip': ip_address, 'source': 'scamalytics', 'status': 'Error', 'code': response.status_code}
    except Exception:
        return {'ip': ip_address, 'source': 'scamalytics', 'status': 'Down', 'code': None}

def lookup_blacklist_de(ip_address):
    """Check IP using blacklist.de"""
    try:
        response = requests.get(f'http://www.blacklist.de/query_ip.php?ip={ip_address}', timeout=5)
        if response.status_code == 200:
            # Returns "found" if IP is in blacklist
            is_blacklisted = 'found' in response.text.lower()
            return {
                'ip': ip_address,
                'vpn_detected': is_blacklisted,
                'source': 'blacklist.de'
            }
        return {'ip': ip_address, 'source': 'blacklist_de', 'status': 'Error', 'code': response.status_code}
    except Exception:
        return {'ip': ip_address, 'source': 'blacklist_de', 'status': 'Down', 'code': None}

def lookup_ip2proxy(ip_address):
    """Check IP using IP2Proxy Web Service (free tier)"""
    try:
        # IP2Proxy lite database check
        response = requests.get(f'https://api.ip2proxy.com/?ip={ip_address}&format=json&package=PX1', timeout=5)
        if response.status_code == 200:
            data = response.json()
            # PX1 package checks for proxy
            is_proxy = data.get('isProxy', 'NO') == 'YES'
            return {
                'ip': ip_address,
                'vpn_detected': is_proxy,
                'proxy_type': data.get('proxyType', 'Unknown'),
                'country': data.get('countryName'),
                'source': 'ip2proxy.com'
            }
        return {'ip': ip_address, 'source': 'ip2proxy', 'status': 'Error', 'code': response.status_code}
    except Exception:
        return {'ip': ip_address, 'source': 'ip2proxy', 'status': 'Down', 'code': None}

def lookup_threatcrowd(ip_address):
    """Check IP using ThreatCrowd (free threat intelligence)"""
    try:
        response = requests.get(f'https://www.threatcrowd.org/searchApi/v2/ip/report/?ip={ip_address}', timeout=5)
        if response.status_code == 200:
            data = response.json()
            # Check if IP has malicious indicators
            malware_count = len(data.get('hashes', []))
            domains_count = len(data.get('resolutions', []))
            # High activity might indicate VPN/proxy usage
            is_suspicious = malware_count > 0 or domains_count > 10
            return {
                'ip': ip_address,
                'vpn_detected': is_suspicious,
                'malware_count': malware_count,
                'domains_count': domains_count,
                'source': 'threatcrowd.org'
            }
        return {'ip': ip_address, 'source': 'threatcrowd', 'status': 'Error', 'code': response.status_code}
    except Exception:
        return {'ip': ip_address, 'source': 'threatcrowd', 'status': 'Down', 'code': None}

def lookup_ipapi_co(ip_address):
    """Check IP using ipapi.co (different from ip-api.com)"""
    try:
        response = requests.get(f'https://ipapi.co/{ip_address}/json/', timeout=5)
        if response.status_code == 200:
            data = response.json()
            # Check org field for VPN indicators
            org = data.get('org', '').lower()
            is_vpn = any(keyword in org for keyword in ['vpn', 'proxy', 'hosting', 'cloud', 'datacenter'])
            return {
                'ip': ip_address,
                'city': data.get('city'),
                'region': data.get('region'),
                'country': data.get('country_name'),
                'org': data.get('org'),
                'vpn_detected': is_vpn,
                'source': 'ipapi.co'
            }
        return {'ip': ip_address, 'source': 'ipapi_co', 'status': 'Error', 'code': response.status_code}
    except Exception:
        return {'ip': ip_address, 'source': 'ipapi_co', 'status': 'Down', 'code': None}

def lookup_ipstack(ip_address):
    """Check IP using IPStack (free tier available)"""
    try:
        # Using free tier without API key (limited features)
        response = requests.get(f'http://api.ipstack.com/{ip_address}?access_key=demo', timeout=5)
        if response.status_code == 200:
            data = response.json()
            if not data.get('error'):
                return {
                    'ip': ip_address,
                    'city': data.get('city'),
                    'region': data.get('region_name'),
                    'country': data.get('country_name'),
                    'source': 'ipstack.com'
                }
        return {'ip': ip_address, 'source': 'ipstack', 'status': 'Error', 'code': response.status_code}
    except Exception:
        return {'ip': ip_address, 'source': 'ipstack', 'status': 'Down', 'code': None}

def lookup_ipwhois(ip_address):
    """Check IP using ipwhois.app (free API)"""
    try:
        response = requests.get(f'http://ipwhois.app/json/{ip_address}', timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                # Check org and ISP for VPN indicators
                org = data.get('org', '').lower()
                isp = data.get('isp', '').lower()
                is_vpn = any(keyword in f"{org} {isp}" for keyword in ['vpn', 'proxy', 'hosting', 'datacenter', 'cloud'])
                return {
                    'ip': ip_address,
                    'city': data.get('city'),
                    'region': data.get('region'),
                    'country': data.get('country'),
                    'org': data.get('org'),
                    'isp': data.get('isp'),
                    'vpn_detected': is_vpn,
                    'source': 'ipwhois.app'
                }
        return {'ip': ip_address, 'source': 'ipwhois', 'status': 'Error', 'code': response.status_code}
    except Exception:
        return {'ip': ip_address, 'source': 'ipwhois', 'status': 'Down', 'code': None}

def lookup_freeipapi(ip_address):
    """Check IP using freeipapi.com"""
    try:
        response = requests.get(f'https://freeipapi.com/api/json/{ip_address}', timeout=5)
        if response.status_code == 200:
            data = response.json()
            # Check for VPN/proxy indicators in ISP field
            isp = data.get('isp', '').lower()
            is_vpn = any(keyword in isp for keyword in ['vpn', 'proxy', 'hosting', 'cloud', 'datacenter'])
            return {
                'ip': ip_address,
                'city': data.get('cityName'),
                'region': data.get('regionName'),
                'country': data.get('countryName'),
                'isp': data.get('isp'),
                'vpn_detected': is_vpn,
                'source': 'freeipapi.com'
            }
        return {'ip': ip_address, 'source': 'freeipapi', 'status': 'Error', 'code': response.status_code}
    except Exception:
        return {'ip': ip_address, 'source': 'freeipapi', 'status': 'Down', 'code': None}
