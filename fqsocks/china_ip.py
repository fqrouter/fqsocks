import socket
import struct
import math
import os
import logging

LOGGER = logging.getLogger(__name__)

def load_china_ip_ranges():
    with open(os.path.join(os.path.dirname(__file__), 'china_ip.txt')) as f:
        line = f.readline()
        while line:
            line = line.strip()
            if not line:
                continue
            if line.startswith('#'):
                continue
            if 'CN|ipv4' not in line:
                continue
                # apnic|CN|ipv4|223.255.252.0|512|20110414|allocated
            _, _, _, start_ip, ip_count, _, _ = line.split('|')
            start_ip_as_int = ip_to_int(start_ip)
            end_ip_as_int = start_ip_as_int + int(ip_count)
            yield start_ip_as_int, end_ip_as_int
            line = f.readline()
    yield translate_ip_range('111.0.0.0', 10) # china mobile
    yield translate_ip_range('202.55.0.0', 19) # china telecom


def translate_ip_range(ip, netmask):
    return ip_to_int(ip), ip_to_int(ip) + int(math.pow(2, 32 - netmask))


def ip_to_int(ip):
    return struct.unpack('!i', socket.inet_aton(ip))[0]


CHINA_IP_RANGES = list(load_china_ip_ranges())

def is_china_ip(ip):
    if ip.startswith('203.208.46.'): # guxiang
        return False
    ip_as_int = ip_to_int(ip)
    for start_ip_as_int, end_ip_as_int in CHINA_IP_RANGES:
        if start_ip_as_int <= ip_as_int <= end_ip_as_int:
            return True
    return False