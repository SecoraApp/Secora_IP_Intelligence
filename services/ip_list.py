import threading
import requests
import ipaddress

APPLE_IP_LIST_URL = "https://raw.githubusercontent.com/hroost/icloud-private-relay-iplist/refs/heads/main/ip-ranges.txt"
NORDVPN_IP_LIST_URL = "https://gist.githubusercontent.com/JamoCA/eedaf4f7cce1cb0aeb5c1039af35f0b7/raw/cb6568528820c09e94cac7ef3461bc6cbf792e7e/NordVPN-Server-IP-List.txt"

apple_ip_ranges = None
nordvpn_ips = None
ip_lists_lock = threading.Lock()

def download_apple_ip_ranges():
    ranges = []
    try:
        resp = requests.get(APPLE_IP_LIST_URL, timeout=10)
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    strict = True
                    if '/' in line:
                        strict = False
                    else:
                        line += "/32"
                        strict = True
                    ipnet_object = ipaddress.ip_network(line, strict=strict)
                    ranges.append(ipnet_object)
                except Exception:
                    continue
    except Exception:
        pass
    return ranges

def download_nordvpn_ips():
    ips = set()
    try:
        resp = requests.get(NORDVPN_IP_LIST_URL, timeout=10)
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    ip = ipaddress.ip_address(line)
                    ips.add(ip)
                except Exception:
                    continue
    except Exception:
        pass
    return ips

def download_and_parse_ip_lists():
    global apple_ip_ranges, nordvpn_ips
    with ip_lists_lock:
        if apple_ip_ranges is None:
             apple_ip_ranges = download_apple_ip_ranges()

        if nordvpn_ips is None:
            nordvpn_ips = download_nordvpn_ips()
    return apple_ip_ranges, nordvpn_ips
