import socket
import struct
import dpkt
import logging
import random
import contextlib
import gevent

LOGGER = logging.getLogger(__name__)
SO_ORIGINAL_DST = 80
OUTBOUND_IP = None
SPI = {}

DNS_SERVERS = [
    # http://www.privacyfoundation.ch/de/service/server.html
    ('77.109.138.45', 110),
    ('77.109.139.29', 110),
    ('87.118.85.241', 110),
    # http://www.privacyfoundation.de/service/serveruebersicht
    ('87.118.100.175 ', 110),
    # http://dns.v2ex.com
    ('199.91.73.222', 3389),
    # http://www.opendns.com
    ('208.67.222.222', 443),
    ('208.67.220.220', 443),
    # google dns
    ('8.8.8.8', 53)
]


def create_tcp_socket(server_ip, server_port, connect_timeout):
    return SPI['create_tcp_socket'](server_ip, server_port, connect_timeout)


# SshProxy.create_tcp_socket = staticmethod(create_tcp_socket)
# SpdyClient.create_tcp_socket = staticmethod(create_tcp_socket)


def _create_tcp_socket(server_ip, server_port, connect_timeout):
    sock = create_socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
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
    return SPI['create_udp_socket']()


def _create_udp_socket():
    return create_socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)


SPI['create_udp_socket'] = _create_udp_socket


def create_socket(*args, **kwargs):
    sock = socket.socket(*args, **kwargs)
    if OUTBOUND_IP:
        sock.bind((OUTBOUND_IP, 0))
    return sock


def get_original_destination(sock, src_ip, src_port):
    return SPI['get_original_destination'](sock, src_ip, src_port)


def _get_original_destination(sock, src_ip, src_port):
    dst = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    dst_port, dst_ip = struct.unpack("!2xH4s8x", dst)
    dst_ip = socket.inet_ntoa(dst_ip)
    return dst_ip, dst_port


SPI['get_original_destination'] = _get_original_destination


def resolve_ips(host):
    for i in range(3):
        try:
            sock = create_udp_socket()
            with contextlib.closing(sock):
                sock.settimeout(3)
                request = dpkt.dns.DNS(
                    id=random.randint(1, 65535), qd=[dpkt.dns.DNS.Q(name=host, type=dpkt.dns.DNS_A)])
                sock.sendto(str(request), pick_dns_server())
                response = dpkt.dns.DNS(sock.recv(1024))
                return [socket.inet_ntoa(an.ip) for an in response.an if hasattr(an, 'ip')]
        except:
            if LOGGER.isEnabledFor(logging.DEBUG):
                LOGGER.debug('failed to resolve google ips', exc_info=1)
        gevent.sleep(1)
    return []


def pick_dns_server():
    return random.choice(DNS_SERVERS)