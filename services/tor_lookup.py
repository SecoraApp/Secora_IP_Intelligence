import requests

def lookup_tor_exit_nodes(ip_address):
    """Check against Tor Project's official exit node list"""
    try:
        # Official Tor exit node list
        response = requests.get('https://check.torproject.org/torbulkexitlist', timeout=10)
        if response.status_code == 200:
            exit_nodes = response.text.strip().split('\n')
            is_tor_exit = ip_address in exit_nodes
            return {
                'ip': ip_address,
                'vpn_detected': is_tor_exit,
                'is_tor': is_tor_exit,
                'tor_type': 'exit_node' if is_tor_exit else None,
                'source': 'torproject.org'
            }
        return {'ip': ip_address, 'source': 'tor_exit_nodes_official', 'status': 'Error', 'code': response.status_code}
    except Exception:
        return {'ip': ip_address, 'source': 'tor_exit_nodes_official', 'status': 'Down', 'code': None}


def lookup_dan_me_tor(ip_address):
    """Check Tor using dan.me.uk Tor detector"""
    try:
        # Dan.me.uk provides a simple Tor check API
        response = requests.get(f'https://www.dan.me.uk/torcheck?ip={ip_address}', timeout=5)
        if response.status_code == 200:
            # Returns "Y" for Tor, "N" for not Tor
            is_tor = response.text.strip().upper() == 'Y'
            return {
                'ip': ip_address,
                'vpn_detected': is_tor,
                'is_tor': is_tor,
                'source': 'dan.me.uk'
            }
        return {'ip': ip_address, 'source': 'dan_me_tor', 'status': 'Error', 'code': response.status_code}
    except Exception:
        return {'ip': ip_address, 'source': 'dan_me_tor', 'status': 'Down', 'code': None}


def lookup_iphunter_tor(ip_address):
    """Check Tor using IP Hunter database"""
    try:
        response = requests.get(f'https://www.iphunter.info/api/v1/ip/{ip_address}', timeout=5)
        if response.status_code == 200:
            data = response.json()
            is_tor = data.get('is_tor', False)
            is_proxy = data.get('is_proxy', False)
            return {
                'ip': ip_address,
                'vpn_detected': is_tor or is_proxy,
                'is_tor': is_tor,
                'is_proxy': is_proxy,
                'source': 'iphunter.info'
            }
        return {'ip': ip_address, 'source': 'iphunter_tor', 'status': 'Error', 'code': response.status_code}
    except Exception:
        return {'ip': ip_address, 'source': 'iphunter_tor', 'status': 'Down', 'code': None}


def lookup_stopforumspam_tor(ip_address):
    """Check using StopForumSpam database (tracks Tor)"""
    try:
        response = requests.get(f'http://www.stopforumspam.com/api?ip={ip_address}&json', timeout=5)
        if response.status_code == 200:
            data = response.json()
            appears = data.get('ip', {}).get('appears', 0)
            # High appearances often indicate Tor/proxy usage
            is_suspicious = appears > 0
            return {
                'ip': ip_address,
                'vpn_detected': is_suspicious,
                'spam_reports': appears,
                'source': 'stopforumspam.com'
            }
        return {'ip': ip_address, 'source': 'stopforumspam_tor', 'status': 'Error', 'code': response.status_code}
    except Exception:
        return {'ip': ip_address, 'source': 'stopforumspam_tor', 'status': 'Down', 'code': None}


def lookup_ipthreat_tor(ip_address):
    """Check using IP Threat database"""
    try:
        response = requests.get(f'https://api.ipthreat.net/v1/check/{ip_address}', timeout=5)
        if response.status_code == 200:
            data = response.json()
            is_tor = data.get('is_tor', False)
            is_proxy = data.get('is_proxy', False)
            threat_level = data.get('threat_level', 0)
            return {
                'ip': ip_address,
                'vpn_detected': is_tor or is_proxy or threat_level > 3,
                'is_tor': is_tor,
                'is_proxy': is_proxy,
                'threat_level': threat_level,
                'source': 'ipthreat.net'
            }
        return {'ip': ip_address, 'source': 'ipthreat_tor', 'status': 'Error', 'code': response.status_code}
    except Exception:
        return {'ip': ip_address, 'source': 'ipthreat_tor', 'status': 'Down', 'code': None}


def lookup_torflix_tor(ip_address):
    """Check using TorFlix Tor detection"""
    try:
        response = requests.get(f'https://torflix.org/api/ip/{ip_address}', timeout=8)
        if response.status_code == 200:
            data = response.json()
            is_tor = data.get('tor', False) or data.get('is_tor', False)
            if is_tor:
                return {
                    'ip': ip_address,
                    'is_tor': True,
                    'vpn_detected': True,
                    'source': 'torflix.org'
                }
        return {'ip': ip_address, 'source': 'torflix_tor', 'status': 'Error', 'code': response.status_code}
    except Exception:
        return {'ip': ip_address, 'source': 'torflix_tor', 'status': 'Down', 'code': None}


def lookup_nordvpn_tor(ip_address):
    """Check using NordVPN's Tor detection API"""
    try:
        response = requests.get(f'https://nordvpn.com/wp-admin/admin-ajax.php?action=get_user_info_data&ip={ip_address}', timeout=8)
        if response.status_code == 200:
            data = response.json()
            if data.get('tor_detected') or 'tor' in str(data).lower():
                return {
                    'ip': ip_address,
                    'is_tor': True,
                    'vpn_detected': True,
                    'source': 'nordvpn.com'
                }
        return {'ip': ip_address, 'source': 'nordvpn_tor', 'status': 'Error', 'code': response.status_code}
    except Exception:
        return {'ip': ip_address, 'source': 'nordvpn_tor', 'status': 'Down', 'code': None}


def lookup_blutmagie_tor(ip_address):
    """Check using Blutmagie Tor exit list"""
    try:
        response = requests.get('https://torstatus.blutmagie.de/query_exit.php/Tor_ip_list_EXIT.csv', timeout=10)
        if response.status_code == 200:
            content = response.text
            # Parse CSV format exit list
            lines = content.strip().split('\n')
            for line in lines[1:]:  # Skip header
                if ip_address in line:
                    return {
                        'ip': ip_address,
                        'is_tor': True,
                        'vpn_detected': True,
                        'source': 'blutmagie.de'
                    }
        return {'ip': ip_address, 'source': 'blutmagie_tor', 'status': 'Error', 'code': response.status_code}
    except Exception:
        return {'ip': ip_address, 'source': 'blutmagie_tor', 'status': 'Down', 'code': None}


def lookup_onionoo_tor(ip_address):
    """Check using Tor Onionoo protocol"""
    try:
        # Onionoo is the protocol used by Tor Metrics
        response = requests.get(f'https://onionoo.torproject.org/details?search={ip_address}', timeout=10)
        if response.status_code == 200:
            data = response.json()
            relays = data.get('relays', [])
            if relays:
                for relay in relays:
                    if ip_address in relay.get('or_addresses', []) or ip_address in relay.get('exit_addresses', []):
                        return {
                            'ip': ip_address,
                            'is_tor': True,
                            'vpn_detected': True,
                            'relay_type': 'exit' if relay.get('exit_probability', 0) > 0 else 'relay',
                            'source': 'onionoo.torproject.org'
                        }
        return {'ip': ip_address, 'source': 'onionoo_tor', 'status': 'Error', 'code': response.status_code}
    except Exception:
        return {'ip': ip_address, 'source': 'onionoo_tor', 'status': 'Down', 'code': None}


def lookup_tor_eff(ip_address):
    """Check using EFF's Tor detection"""
    try:
        # EFF sometimes maintains Tor lists
        response = requests.get('https://atlas.torproject.org/api/search?type=relay&running=true', timeout=10)
        if response.status_code == 200:
            data = response.json()
            results = data.get('results', [])
            for result in results:
                if ip_address in str(result.get('addresses', [])):
                    return {
                        'ip': ip_address,
                        'is_tor': True,
                        'vpn_detected': True,
                        'source': 'atlas.torproject.org'
                    }
        return {'ip': ip_address, 'source': 'tor_eff', 'status': 'Error', 'code': response.status_code}
    except Exception:
        return {'ip': ip_address, 'source': 'tor_eff', 'status': 'Down', 'code': None}

def lookup_tor_bulk_exit(ip_address):
    """Check using Tor bulk exit list from multiple mirrors"""
    try:
        # Try multiple Tor exit list sources
        exit_lists = [
            'https://www.dan.me.uk/torlist/',
            'https://torstatus.rueckgr.at/ip_list_exit.php/Tor_ip_list_EXIT.csv',
            'https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1'
        ]

        for url in exit_lists:
            try:
                response = requests.get(url, timeout=8)
                if response.status_code == 200:
                    content = response.text
                    if ip_address in content:
                        return {
                            'ip': ip_address,
                            'is_tor': True,
                            'vpn_detected': True,
                            'source': f'tor_bulk_exit_list'
                        }
            except:
                continue
        return {'ip': ip_address, 'source': 'tor_bulk_exit_mirros', 'status': 'Error', 'code': response.status_code}
    except Exception:
        return {'ip': ip_address, 'source': 'tor_bulk_exit_mirros', 'status': 'Down', 'code': None}

