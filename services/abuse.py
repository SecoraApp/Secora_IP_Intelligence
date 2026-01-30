import os
import requests

ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY', 'your-abuseapi-key-was-not-found')
def lookup_abuseipdb(ip_address, max_age_days=90, per_page=5):
    url = "https://api.abuseipdb.com/api/v2/reports"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": max_age_days,
        "perPage": 6,
        "page": 1
    }
    try:
        response = requests.get(url, headers=headers, params=params, timeout=8)
        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "abuseipdb_total_reports": data.get("total", 0),
                "abuseipdb_reports": data.get("results", []),
                "abuseipdb_last_page": data.get("lastPage", 1),
                "abuseipdb_error": None
            }
        else:
            return {"abuseipdb_error": f"Status {response.status_code}"}
    except Exception as e:
        return {"abuseipdb_error": str(e)}

# Optionally, get the confidence score from the /check endpoint
def lookup_abuseipdb_confidence(ip_address):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90
    }
    try:
        response = requests.get(url, headers=headers, params=params, timeout=8)
        if response.status_code == 200:
            data = response.json().get("data", {})
            return data.get("abuseConfidenceScore", None)
        else:
            return {'ip': ip_address, 'source': 'abuseipdb', 'status': 'Error', 'code': response.status_code}
    except Exception:
        return {'ip': ip_address, 'source': 'abuseipdb', 'status': 'Down', 'code': None}

def lookup_cleantalk(ip_address):
    """Check IP using CleanTalk (spam/abuse database)"""
    try:
        response = requests.get(f'https://cleantalk.org/blacklists/{ip_address}', timeout=5)
        if response.status_code == 200:
            content = response.text.lower()
            # Check for blacklist indicators
            is_blacklisted = any(keyword in content for keyword in
                               ['blacklisted', 'spam', 'abuse', 'proxy', 'vpn'])
            return {
                'ip': ip_address,
                'vpn_detected': is_blacklisted,
                'source': 'cleantalk.org'
            }
        return {'ip': ip_address, 'source': 'cleantalk', 'status': 'Error', 'code': response.status_code}
    except Exception:
        return {'ip': ip_address, 'source': 'cleantalk', 'status': 'Down', 'code': None}

def lookup_virustotal_community(ip_address):
    """Check IP using VirusTotal community (without API key)"""
    try:
        # VirusTotal has a simple check page we can scrape
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(f'https://www.virustotal.com/vtapi/v2/ip-address/report?apikey=public&ip={ip_address}',
                              headers=headers, timeout=5)

        # For free access, we'll do basic detection
        if response.status_code == 200:
            try:
                data = response.json()
                # Look for malicious detections
                detected_urls = data.get('detected_urls', [])
                detected_samples = data.get('detected_samples', [])

                # High activity might indicate compromised/VPN IP
                is_suspicious = len(detected_urls) > 5 or len(detected_samples) > 2

                return {
                    'ip': ip_address,
                    'vpn_detected': is_suspicious,
                    'malicious_urls': len(detected_urls),
                    'malicious_samples': len(detected_samples),
                    'source': 'virustotal.com'
                }
            except:
                pass
        return {'ip': ip_address, 'source': 'virustotal_community', 'status': 'Error', 'code': response.status_code}
    except Exception:
        return {'ip': ip_address, 'source': 'virustotal_community', 'status': 'Down', 'code': None}
