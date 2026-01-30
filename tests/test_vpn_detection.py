from services.ip_list import *
from services.vpn_proxy import check_apple_nordvpn

apple_ip_ranges, nordvpn_ips = download_and_parse_ip_lists()
print(len(apple_ip_ranges), len(nordvpn_ips))

result = check_apple_nordvpn("104.28.29.54")
print(result)

result = check_apple_nordvpn("103.1.212.107")
print(result)
