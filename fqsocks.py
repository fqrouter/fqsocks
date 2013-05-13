#!/usr/bin/env python
# thanks @phuslu https://github.com/phus/sniproxy/blob/master/sniproxy.py
# thanks @ofmax https://github.com/madeye/gaeproxy/blob/master/assets/modules/python.mp3
import logging
import sys
import struct
import socket
import errno
import select
import signal
import subprocess
import atexit
import random
import re
import dpkt

import gevent.server
import gevent.monkey

from direct import DirectProxy


LOGGER = logging.getLogger(__name__)
SO_ORIGINAL_DST = 80

DIRECT_PROXY = DirectProxy()
http_connect_proxies = []

TLS1_1_VERSION = 0x0302
RE_HTTP_HOST = re.compile('Host: (.+)')


class ProxyClient(object):
    def __init__(self, downstream_sock, upstream_sock, src_ip, src_port, dst_ip, dst_port):
        super(ProxyClient, self).__init__()
        self.downstream_sock = downstream_sock
        self.upstream_sock = upstream_sock
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.description = '%s:%s => %s:%s' % (self.src_ip, self.src_port, self.dst_ip, self.dst_port)

    def close(self):
        try:
            self.downstream_sock.close()
        finally:
            self.upstream_sock.close()

    def forward(self):
        forward_socket(self.downstream_sock, self.upstream_sock)

    def __repr__(self):
        return self.description


def handle(downstream_sock, address):
    dst = downstream_sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    dst_port, dst_ip = struct.unpack("!2xH4s8x", dst)
    dst_ip = socket.inet_ntoa(dst_ip)
    upstream_sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
    upstream_sock.bind(('10.1.2.3', 0))
    client = ProxyClient(downstream_sock, upstream_sock, address[0], address[1], dst_ip, dst_port)
    try:
        LOGGER.debug('[%s] downstream connected' % repr(client))
        proxy, peaked_data = select_proxy(client)
        if not proxy.connect_upstream(client):
            LOGGER.debug('[%s] upstream connect failed' % repr(client))
            return
        LOGGER.debug('[%s] upstream connected' % repr(client))
        client.upstream_sock.sendall(peaked_data)
        client.forward()
        LOGGER.debug('[%s] done' % repr(client))
    except:
        LOGGER.exception('[%s] done with error' % repr(client))
    finally:
        client.close()


def select_proxy(client):
    ins, _, errors = select.select([client.downstream_sock], [], [client.downstream_sock], 0.1)
    if errors:
        LOGGER.error('[%s] peek data failed' % repr(client))
        return DIRECT_PROXY, ''
    if not ins:
        LOGGER.error('[%s] peek data timed out' % repr(client))
        return pick_http_connect_proxy() if client.dst_port in (80, 443) else DIRECT_PROXY, ''
    peeked_data = client.downstream_sock.recv(512)
    protocol, domain = analyze_protocol(peeked_data)
    LOGGER.info('[%s] analyzed protocol: %s %s' % (repr(client), protocol, domain))
    return pick_http_connect_proxy(), peeked_data


def analyze_protocol(peeked_data):
    try:
        match = RE_HTTP_HOST.search(peeked_data)
        if match:
            return 'HTTP', match.group(1)
        ssl3 = dpkt.ssl.SSL3(peeked_data)
        if ssl3.version in (dpkt.ssl.SSL3_VERSION, dpkt.ssl.TLS1_VERSION, TLS1_1_VERSION):
            return 'HTTPS', parse_sni_domain(peeked_data)
    except:
        LOGGER.exception('failed to analyze protocol')
    return 'UNKNOWN', ''


def parse_sni_domain(data):
    domain = ''
    try:
        # extrace SNI from ClientHello packet, quick and dirty.
        domain = (m.group(2) for m in re.finditer('\x00\x00(.)([\\w\\.]{4,255})', data)
                  if ord(m.group(1)) == len(m.group(2))).next()
    except StopIteration:
        pass
    return domain


def pick_http_connect_proxy():
    if http_connect_proxies:
        return random.choice(http_connect_proxies)
    else:
        return DIRECT_PROXY


def forward_socket(local, remote, timeout=60, tick=2, bufsize=8192, maxping=None, maxpong=None):
    try:
        timecount = timeout
        while 1:
            timecount -= tick
            if timecount <= 0:
                break
            ins, _, errors = select.select([local, remote], [], [local, remote], tick)
            if errors:
                break
            if ins:
                for sock in ins:
                    data = sock.recv(bufsize)
                    if data:
                        if sock is remote:
                            local.sendall(data)
                            timecount = maxpong or timeout
                        else:
                            remote.sendall(data)
                            timecount = maxping or timeout
                    else:
                        return
    except socket.error as e:
        if e[0] not in (10053, 10054, 10057, errno.EPIPE):
            raise


def on_exit(signum, frame):
    delete_iptables_rule()


def delete_iptables_rule():
    subprocess.check_call(
        'iptables -t nat -D OUTPUT -p tcp ! -s 10.1.2.3 -j DNAT --to-destination 10.1.2.3:1234', shell=True)


if '__main__' == __name__:
    signal.signal(signal.SIGTERM, on_exit)
    signal.signal(signal.SIGINT, on_exit)
    atexit.register(delete_iptables_rule)
    gevent.monkey.patch_all()
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s')
    ip = '10.1.2.3'
    port = 1234
    server = gevent.server.StreamServer((ip, port), handle)
    LOGGER.info('started fqsocks at %s:%s' % (ip, port))
    subprocess.check_call(
        'iptables -t nat -I OUTPUT -p tcp ! -s 10.1.2.3 -j DNAT --to-destination 10.1.2.3:1234', shell=True)
    try:
        server.serve_forever()
    finally:
        delete_iptables_rule()