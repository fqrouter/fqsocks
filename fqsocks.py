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

from direct import DIRECT_PROXY
from urlfetch import UrlFetchProxy
from http_connect import HttpConnectProxy


LOGGER = logging.getLogger(__name__)
SO_ORIGINAL_DST = 80

proxies = [UrlFetchProxy('freegoagent001', '203.208.46.131'), UrlFetchProxy('freegoagent002', '203.208.46.131')]
for proxy in proxies:
    proxy.died = False

TLS1_1_VERSION = 0x0302
RE_HTTP_HOST = re.compile('Host: (.+)')


class ProxyClient(object):
    def __init__(self, downstream_sock, upstream_bind_ip, src_ip, src_port, dst_ip, dst_port):
        super(ProxyClient, self).__init__()
        self.downstream_sock = downstream_sock
        self.downstream_rfile = downstream_sock.makefile('rb', 8192)
        self.downstream_wfile = downstream_sock.makefile('wb', 0)
        self.upstream_bind_ip = upstream_bind_ip
        self.upstream_socks = []
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.description = '%s:%s => %s:%s' % (self.src_ip, self.src_port, self.dst_ip, self.dst_port)
        self.peeked_data = ''

    def create_upstream_sock(self, family=socket.AF_INET, type=socket.SOCK_STREAM, **kwargs):
        upstream_sock = socket.socket(family=family, type=type, **kwargs)
        upstream_sock.bind((self.upstream_bind_ip, 0))
        self.upstream_socks.append(upstream_sock)
        return upstream_sock

    def add_upstream_sock(self, sock):
        self.upstream_socks.append(sock)

    def forward(self, to_sock):
        forward_socket(self.downstream_sock, to_sock)

    def fall_back(self, reason, died=False):
        raise ProxyFallBack(reason, died)

    def close(self):
        for res in [self.downstream_sock, self.downstream_rfile, self.downstream_wfile] + self.upstream_socks:
            try:
                res.close()
            except:
                LOGGER.exception('failed to close: %s' % res)

    def __repr__(self):
        return self.description


class ProxyFallBack(Exception):
    def __init__(self, reason, died):
        super(ProxyFallBack, self).__init__(reason)
        self.reason = reason
        self.died = died


def handle(downstream_sock, address):
    dst = downstream_sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    dst_port, dst_ip = struct.unpack("!2xH4s8x", dst)
    dst_ip = socket.inet_ntoa(dst_ip)
    client = ProxyClient(downstream_sock, '10.1.2.3', address[0], address[1], dst_ip, dst_port)
    proxy = None
    try:
        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.debug('[%s] downstream connected' % repr(client))
        pick_proxy_and_forward(client)
        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.debug('[%s] done' % repr(client))
    except:
        LOGGER.exception('[%s] done with error' % repr(client))
        if proxy:
            proxy.died = True
    finally:
        client.close()
    if proxy and proxy.died and proxy in proxies:
        LOGGER.info('[%s] remove died proxy: %s' % (repr(client), repr(proxy)))
        proxies.remove(proxy)


def pick_proxy_and_forward(client):
    for i in range(3):
        proxy = pick_proxy(client)
        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.debug('[%s] picked proxy: %s' % (repr(client), repr(proxy)))
        try:
            proxy.forward(client)
            return
        except ProxyFallBack, e:
            LOGGER.error('[%s] fall back to other proxy due to %s: %s' % (repr(client), e.reason, repr(proxy)))
            if e.died and proxy in proxies:
                LOGGER.info('[%s] remove died proxy: %s' % (repr(client), repr(proxy)))
                proxies.remove(proxy)
    LOGGER.error('[%s] fall back too many times' % repr(client))
    DIRECT_PROXY.forward(client)


def pick_proxy(client):
    if not client.peeked_data:
        ins, _, errors = select.select([client.downstream_sock], [], [client.downstream_sock], 0.1)
        if errors:
            LOGGER.error('[%s] peek data failed' % repr(client))
            return DIRECT_PROXY, ''
        if not ins:
            LOGGER.error('[%s] peek data timed out' % repr(client))
        else:
            client.peeked_data = client.downstream_sock.recv(8192)
    protocol, domain = analyze_protocol(client.peeked_data)
    if LOGGER.isEnabledFor(logging.DEBUG):
        LOGGER.debug('[%s] analyzed protocol: %s %s' % (repr(client), protocol, domain))
    if protocol == 'HTTP' or client.dst_port == 80:
        proxy = pick_urlfetch_proxy()
        if proxy:
            return proxy
    if protocol in ('HTTP', 'HTTPS') or client.dst_port in (80, 443):
        proxy = pick_http_connect_proxy()
        if proxy:
            return proxy
    return DIRECT_PROXY


def analyze_protocol(peeked_data):
    try:
        match = RE_HTTP_HOST.search(peeked_data)
        if match:
            return 'HTTP', match.group(1)
        try:
            ssl3 = dpkt.ssl.SSL3(peeked_data)
        except dpkt.NeedData:
            return 'UNKNOWN', ''
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


def pick_urlfetch_proxy():
    urlfetch_proxies = [proxy for proxy in proxies if isinstance(proxy, UrlFetchProxy)]
    if urlfetch_proxies:
        return random.choice(urlfetch_proxies)
    else:
        return None


def pick_http_connect_proxy():
    http_connect_proxies = [proxy for proxy in proxies if isinstance(proxy, HttpConnectProxy)]
    if http_connect_proxies:
        return random.choice(http_connect_proxies)
    else:
        return None


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