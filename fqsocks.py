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
import random
import re
import argparse
import atexit
import fnmatch

import dpkt
import gevent.server
import gevent.monkey
import china_ip

from direct import DIRECT_PROXY
from http_try import HTTP_TRY_PROXY
from goagent import GoAgentProxy
from http_connect import HttpConnectProxy
from dynamic import DynamicProxy


proxy_types = {
    'http-connect': HttpConnectProxy,
    'goagent': GoAgentProxy,
    'dynamic': DynamicProxy
}
LOGGER = logging.getLogger(__name__)
SO_ORIGINAL_DST = 80

proxies = []
# ip is default to be gray, will go through proxy and start direct connect attempt
ip_black_list = set() # always go through proxy
ip_white_list = set() # always go direct
ip_tried_times = {} # ip => tried direct connection

TLS1_1_VERSION = 0x0302
RE_HTTP_HOST = re.compile('Host: (.+)')
LISTEN_IP = None
LISTEN_PORT = None
OUTBOUND_IP = None
NO_PUBLIC_PROXY_HOSTS = {
    'www.google.com',
    'google.com',
    'www.google.com.hk',
    'google.com.hk'
}
NO_DIRECT_PROXY_HOSTS = {
    '*.twitter.com',
    'twitter.com',
    '*.t.co',
    't.co',
    '*.twimg.com',
    'twimg.com'
}


class ProxyClient(object):
    def __init__(self, downstream_sock, src_ip, src_port, dst_ip, dst_port):
        super(ProxyClient, self).__init__()
        self.downstream_sock = downstream_sock
        self.downstream_rfile = downstream_sock.makefile('rb', 8192)
        self.downstream_wfile = downstream_sock.makefile('wb', 0)
        self.resources = [self.downstream_sock, self.downstream_rfile, self.downstream_wfile]
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.description = '%s:%s => %s:%s' % (self.src_ip, self.src_port, self.dst_ip, self.dst_port)
        self.peeked_data = ''
        self.host = ''
        self.tried_proxies = []
        self.forwarding_by = None

    def create_upstream_sock(self, family=socket.AF_INET, type=socket.SOCK_STREAM, **kwargs):
        upstream_sock = socket.socket(family=family, type=type, **kwargs)
        upstream_sock.bind((OUTBOUND_IP, 0))
        self.resources.append(upstream_sock)
        return upstream_sock

    def add_resource(self, res):
        self.resources.append(res)

    def forward(self, to_sock, **kwargs):
        forward_socket(self.downstream_sock, to_sock, **kwargs)

    def close(self):
        for res in self.resources:
            try:
                res.close()
            except:
                pass

    def fall_back(self, reason):
        raise ProxyFallBack(reason)

    def direct_connection_succeeded(self):
        ip_white_list.add(self.dst_ip)
        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.debug('[%s] direct connection succeeded' % repr(self))

    def direct_connection_failed(self):
        ip_black_list.add(self.dst_ip)
        LOGGER.info('[%s] direct connection failed' % repr(self))

    def __repr__(self):
        description = self.description
        if self.host:
            description = '%s %s' % (description, self.host)
        if self.forwarding_by:
            description = '%s %s' % (description, repr(self.forwarding_by))
        return description


class ProxyFallBack(Exception):
    def __init__(self, reason):
        super(ProxyFallBack, self).__init__(reason)
        self.reason = reason


def handle(downstream_sock, address):
    dst = downstream_sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    dst_port, dst_ip = struct.unpack("!2xH4s8x", dst)
    dst_ip = socket.inet_ntoa(dst_ip)
    client = ProxyClient(downstream_sock, address[0], address[1], dst_ip, dst_port)
    try:
        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.debug('[%s] downstream connected' % repr(client))
        pick_proxy_and_forward(client)
        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.debug('[%s] done' % repr(client))
    except:
        LOGGER.exception('[%s] done with error' % repr(client))
    finally:
        client.close()


def pick_proxy_and_forward(client):
    for i in range(3):
        proxy = pick_proxy(client)
        while proxy:
            if not client.host:
                break
            if 'DIRECT' in proxy.flags and any(fnmatch.fnmatch(client.host, host) for host in NO_DIRECT_PROXY_HOSTS):
                client.tried_proxies.append(proxy)
            elif 'PUBLIC' in proxy.flags and any(fnmatch.fnmatch(client.host, host) for host in NO_PUBLIC_PROXY_HOSTS):
                client.tried_proxies.append(proxy)
            else:
                break
            proxy = pick_proxy(client)
        proxy = proxy or DIRECT_PROXY
        client.tried_proxies.append(proxy)
        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.debug('[%s] picked proxy: %s' % (repr(client), repr(proxy)))
        try:
            proxy.forward(client)
            return
        except ProxyFallBack, e:
            if china_ip.is_china_ip(client.dst_ip):
                DIRECT_PROXY.forward(client)
            else:
                LOGGER.error('[%s] fall back to other proxy due to %s: %s' % (repr(client), e.reason, repr(proxy)))
    LOGGER.error('[%s] fall back to direct after too many retries' % repr(client))
    DIRECT_PROXY.forward(client)


def pick_proxy(client):
    if china_ip.is_china_ip(client.dst_ip):
        return DIRECT_PROXY
    if not client.peeked_data:
        ins, _, errors = select.select([client.downstream_sock], [], [client.downstream_sock], 0.1)
        if errors:
            LOGGER.error('[%s] peek data failed' % repr(client))
            return DIRECT_PROXY, ''
        if not ins:
            if LOGGER.isEnabledFor(logging.DEBUG):
                LOGGER.debug('[%s] peek data timed out' % repr(client))
        else:
            client.peeked_data = client.downstream_sock.recv(8192)
    protocol, domain = analyze_protocol(client.peeked_data)
    if domain:
        client.host = domain
    ip_color = get_ip_color(client.dst_ip)
    if LOGGER.isEnabledFor(logging.DEBUG):
        LOGGER.debug('[%s] analyzed traffic: %s %s %s' % (repr(client), ip_color, protocol, domain))
    if protocol == 'HTTP' or client.dst_port == 80:
        if 'BLACK' == ip_color:
            return pick_http_proxy(client)
        elif 'WHITE' == ip_color:
            return pick_http_try_proxy(client) or pick_http_proxy(client)
        else:
            spawn_try_direct_connection(client)
            return pick_http_proxy(client)
    elif protocol == 'HTTPS' or client.dst_port == 443:
        if 'BLACK' == ip_color:
            return pick_https_proxy(client)
        elif 'WHITE' == ip_color:
            return pick_direct_proxy(client) or pick_https_proxy(client)
        else:
            spawn_try_direct_connection(client)
            return pick_https_proxy(client)
    else:
        return None


def spawn_try_direct_connection(client):
    if client.host and any(fnmatch.fnmatch(client.host, host) for host in NO_DIRECT_PROXY_HOSTS):
        return
    tried_times = ip_tried_times.get(client.dst_ip, 0)
    if tried_times < 2:
        gevent.spawn(try_direct_connection, client)
        ip_tried_times[client.dst_ip] = tried_times + 1


def try_direct_connection(client):
    upstream_sock = client.create_upstream_sock()
    upstream_sock.settimeout(5)
    try:
        try:
            upstream_sock.connect((client.dst_ip, client.dst_port))
            client.direct_connection_succeeded()
        except:
            client.direct_connection_failed()
    finally:
        upstream_sock.close()


def get_ip_color(ip):
    if ip in ip_black_list:
        return 'BLACK'
    if ip in ip_white_list:
        return 'WHITE'
    return 'GRAY'


def analyze_protocol(peeked_data):
    try:
        match = RE_HTTP_HOST.search(peeked_data)
        if match:
            return 'HTTP', match.group(1).strip()
        try:
            ssl3 = dpkt.ssl.SSL3(peeked_data)
        except dpkt.NeedData:
            return 'UNKNOWN', ''
        if ssl3.version in (dpkt.ssl.SSL3_VERSION, dpkt.ssl.TLS1_VERSION, TLS1_1_VERSION):
            return 'HTTPS', parse_sni_domain(peeked_data).strip()
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


def pick_direct_proxy(client):
    return None if DIRECT_PROXY in client.tried_proxies else DIRECT_PROXY


def pick_http_try_proxy(client):
    return None if HTTP_TRY_PROXY in client.tried_proxies else HTTP_TRY_PROXY


def pick_http_proxy(client):
    http_only_proxies = [proxy for proxy in proxies if
                         proxy.is_protocol_supported('HTTP') and not proxy.is_protocol_supported('HTTPS')
                         and not proxy.died and proxy not in client.tried_proxies]
    if http_only_proxies:
        return random.choice(http_only_proxies)
    http_proxies = [proxy for proxy in proxies if
                    proxy.is_protocol_supported('HTTP')
                    and not proxy.died and proxy not in client.tried_proxies]
    if http_proxies:
        return random.choice(http_proxies)
    return None


def pick_https_proxy(client):
    https_proxies = [proxy for proxy in proxies if
                     proxy.is_protocol_supported('HTTPS') and not proxy.died and proxy not in client.tried_proxies]
    if https_proxies:
        return random.choice(https_proxies)
    else:
        return None


def forward_socket(downstream, upstream, timeout=60, tick=2, bufsize=8192, maxping=None, maxpong=None,
                   on_upstream_timed_out=None):
    upstream_responded = False
    try:
        timecount = timeout
        while 1:
            timecount -= tick
            if timecount <= 0:
                if not upstream_responded and on_upstream_timed_out:
                    on_upstream_timed_out()
            ins, _, errors = select.select([downstream, upstream], [], [downstream, upstream], tick)
            if errors:
                break
            if ins:
                for sock in ins:
                    data = sock.recv(bufsize)
                    if data:
                        if sock is upstream:
                            remote_responded = True
                            downstream.sendall(data)
                            timecount = maxpong or timeout
                        else:
                            upstream.sendall(data)
                            timecount = maxping or timeout
                    else:
                        return
    except socket.error as e:
        if e[0] not in (10053, 10054, 10057, errno.EPIPE):
            raise


def refresh_proxies():
    global proxies
    LOGGER.info('refresh proxies: %s' % proxies)
    socks = []

    def create_sock(family=socket.AF_INET, type=socket.SOCK_STREAM, **kwargs):
        sock = socket.socket(family=family, type=type, **kwargs)
        sock.bind((OUTBOUND_IP, 0))
        socks.append(sock)
        return sock

    type_to_proxies = {}
    for proxy in proxies:
        type_to_proxies.setdefault(proxy.__class__, []).append(proxy)
    for proxy_type, instances in type_to_proxies.items():
        proxy_type.refresh(instances, create_sock)
    for sock in socks:
        try:
            sock.close()
        except:
            pass
    LOGGER.info('refreshed proxies: %s' % proxies)


def setup_development_env():
    subprocess.check_call(
        'iptables -t nat -I OUTPUT -p tcp ! -s %s -j DNAT --to-destination %s:%s' %
        (OUTBOUND_IP, LISTEN_IP, LISTEN_PORT), shell=True)


def teardown_development_env():
    subprocess.check_call(
        'iptables -t nat -D OUTPUT -p tcp ! -s %s -j DNAT --to-destination %s:%s' %
        (OUTBOUND_IP, LISTEN_IP, LISTEN_PORT), shell=True)

# TODO twitter, go http-connect
# TODO refresh every 30 minutes
# TODO refresh failure detection, retry after 10 seconds, for 3 times
# TODO refresh retry, with exponential backoff (1s => 2s => 4s => 8s)
# TODO check twitter/youtube/facebook/google+ access after refresh
# TODO === merge into fqrouter ===
# TODO measure the speed of proxy which adds weight to the picking process
# TODO add http-relay proxy
# TODO add socks4 proxy
# TODO add socks5 proxy
# TODO add ssh proxy
# TODO add shadowsocks proxy
# TODO add spdy proxy
# TODO === future ===
# TODO add vpn as proxy (setup vpn, mark packet, mark based routing)

if '__main__' == __name__:
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument('--listen', default='127.0.0.1:12345')
    argument_parser.add_argument('--outbound-ip', default='10.1.2.3')
    argument_parser.add_argument('--dev', action='store_true', help='setup network/iptables on development machine')
    argument_parser.add_argument('--log-level', default='INFO')
    argument_parser.add_argument('--proxy', action='append', default=[])
    argument_parser.add_argument(
        '--google-host', action='append', default=[])
    args = argument_parser.parse_args()
    logging.basicConfig(
        stream=sys.stdout, level=getattr(logging, args.log_level), format='%(asctime)s %(levelname)s %(message)s')
    LISTEN_IP, LISTEN_PORT = args.listen.split(':')
    LISTEN_IP = '' if '*' == LISTEN_IP else LISTEN_IP
    LISTEN_PORT = int(LISTEN_PORT)
    OUTBOUND_IP = args.outbound_ip
    if args.google_host:
        GoAgentProxy.GOOGLE_HOSTS = args.google_host
    for proxy_properties in args.proxy:
        proxy_properties = proxy_properties.split(',')
        proxy = proxy_types[proxy_properties[0]](**dict(p.split('=') for p in proxy_properties[1:]))
        proxies.append(proxy)
    refresh_proxies()
    if args.dev:
        signal.signal(signal.SIGTERM, lambda signum, fame: teardown_development_env())
        signal.signal(signal.SIGINT, lambda signum, fame: teardown_development_env())
        atexit.register(teardown_development_env)
        setup_development_env()
    gevent.monkey.patch_all()
    server = gevent.server.StreamServer((LISTEN_IP, LISTEN_PORT), handle)
    LOGGER.info('started fqsocks at %s:%s' % (LISTEN_IP, LISTEN_PORT))
    server.serve_forever()