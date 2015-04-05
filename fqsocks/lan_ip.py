import china_ip

# Following ip range are copied from Wikipedia:Reserved_IP_Addresses
# Link: https://en.wikipedia.org/wiki/Reserved_IP_addresses

LOCAL_NETWORKS = [
    china_ip.translate_ip_range('0.0.0.0', 8),
    # china_ip.translate_ip_range('7.0.0.0', 8), # US Dept of Defense, I don't think anyone will use this network :P
    china_ip.translate_ip_range('10.0.0.0', 8),
    china_ip.translate_ip_range('100.64.0.0', 10),
    china_ip.translate_ip_range('127.0.0.0', 8),
    china_ip.translate_ip_range('169.254.0.0', 16),
    china_ip.translate_ip_range('172.16.0.0', 12),
    china_ip.translate_ip_range('192.0.0.0', 24),
    china_ip.translate_ip_range('192.0.2.0', 24), # Network for documentation.
    # china_ip.translate_ip_range('192.88.99.0', 24), # This network is marked as Internet, thus not enabled for shortcut.
    china_ip.translate_ip_range('192.168.0.0', 16),
    china_ip.translate_ip_range('198.18.0.0', 15),
    china_ip.translate_ip_range('198.51.100.0', 24), # Network for documentation.
    china_ip.translate_ip_range('203.0.113.0', 24), # Network for documentation.
    china_ip.translate_ip_range('224.0.0.0', 4),
    china_ip.translate_ip_range('240.0.0.0', 4)]


def is_lan_traffic(src, dst):
    from_lan = is_lan_ip(src)
    to_lan = is_lan_ip(dst)
    return from_lan and to_lan


def is_lan_ip(ip):
    ip_as_int = china_ip.ip_to_int(ip)
    return any(start_ip_as_int <= ip_as_int <= end_ip_as_int for start_ip_as_int, end_ip_as_int in LOCAL_NETWORKS)
