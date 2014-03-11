import socket
import struct
import dpkt
import logging
import random
import contextlib
import gevent
import sys
import re
import fqlan

LOGGER = logging.getLogger(__name__)
SO_ORIGINAL_DST = 80
OUTBOUND_IP = None
SPI = {}
RE_IP = re.compile(r'^\d+\.\d+\.\d+\.\d+$')

default_interface_ip_cache = None

def get_default_interface_ip():
    global default_interface_ip_cache
    if not default_interface_ip_cache:
        default_interface_ip_cache = fqlan.get_default_interface_ip()
    return default_interface_ip_cache


def create_tcp_socket(server_ip, server_port, connect_timeout):
    sock = SPI['create_tcp_socket'](server_ip, server_port, connect_timeout)
    # set reuseaddr option to avoid 10048 socket error
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # resize socket recv buffer 8K->32K to improve browser releated application performance
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
    # disable negal algorithm to send http request quickly.
    sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
    return sock


def _create_tcp_socket(server_ip, server_port, connect_timeout):
    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
    if OUTBOUND_IP:
        sock.bind((OUTBOUND_IP, 0))
    sock.setblocking(0)
    sock.settimeout(connect_timeout)
    try:
        sock.connect((server_ip, server_port))
    except:
        sock.close()
        raise
    sock.settimeout(None)
    return sock


SPI['create_tcp_socket'] = _create_tcp_socket


def create_udp_socket():
    return socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)


def get_original_destination(sock, src_ip, src_port):
    return SPI['get_original_destination'](sock, src_ip, src_port)


def _get_original_destination(sock, src_ip, src_port):
    dst = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    dst_port, dst_ip = struct.unpack("!2xH4s8x", dst)
    dst_ip = socket.inet_ntoa(dst_ip)
    return dst_ip, dst_port


SPI['get_original_destination'] = _get_original_destination


def resolve_ips(host, dns_ip='8.8.8.8', dns_port=53):
    if RE_IP.match(host):
        return [host]
    for i in range(3):
        try:
            sock = create_udp_socket()
            with contextlib.closing(sock):
                sock.settimeout(10)
                request = dpkt.dns.DNS(
                    id=random.randint(1, 65535), qd=[dpkt.dns.DNS.Q(name=str(host), type=dpkt.dns.DNS_A)])
                sock.sendto(str(request), (dns_ip, dns_port))
                gevent.sleep(0.1)
                response = dpkt.dns.DNS(sock.recv(8192))
                return [socket.inet_ntoa(an.ip) for an in response.an if hasattr(an, 'ip')]
        except:
            if LOGGER.isEnabledFor(logging.DEBUG):
                LOGGER.debug('failed to resolve %s' % host, exc_info=1)
            else:
                LOGGER.info('failed to resolve %s: %s' % (host, sys.exc_info()[1]), exc_info=1)
        gevent.sleep(1)
    return []