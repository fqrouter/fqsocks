#!/usr/bin/env python
# thanks @phuslu https://github.com/phus/sniproxy/blob/master/sniproxy.py
# thanks @ofmax https://github.com/madeye/gaeproxy/blob/master/assets/modules/python.mp3
import logging
import logging.handlers
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
import math
import urllib2
import traceback
import time
import contextlib

import dpkt
import gevent.server
import gevent.monkey

import lan_ip
import china_ip
import fqdns
from direct import DIRECT_PROXY
from direct import HTTPS_TRY_PROXY
from direct import DirectProxy
from direct import NONE_PROXY
from http_try import HTTP_TRY_PROXY
from http_try import NotHttp
from goagent import GoAgentProxy
from http_connect import HttpConnectProxy
from dynamic import DynamicProxy
from shadowsocks import ShadowSocksProxy


proxy_types = {
    'http-connect': HttpConnectProxy,
    'goagent': GoAgentProxy,
    'dynamic': DynamicProxy,
    'ss': ShadowSocksProxy
}
LOGGER = logging.getLogger(__name__)
SO_ORIGINAL_DST = 80

mandatory_proxies = []
proxies = []
direct_connection_successes = set() # set of (ip, port)
direct_connection_failures = {} # (ip, port) => failed_at
ip_black_list = set() # always go through proxy

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
REFRESH_INTERVAL = 60 * 30
CHINA_PROXY = None
CHECK_ACCESS = True
SPI = {}


class ProxyClient(object):
    def __init__(self, downstream_sock, src_ip, src_port, dst_ip, dst_port):
        super(ProxyClient, self).__init__()
        self.downstream_sock = downstream_sock
        self.downstream_rfile = downstream_sock.makefile('rb', 8192)
        self.downstream_wfile = downstream_sock.makefile('wb', 0)
        self.forward_started = False
        self.resources = [self.downstream_sock, self.downstream_rfile, self.downstream_wfile]
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.description = '%s:%s => %s:%s' % (self.src_ip, self.src_port, self.dst_ip, self.dst_port)
        self.peeked_data = ''
        self.host = ''
        self.tried_proxies = {}
        self.forwarding_by = None

    def create_tcp_socket(self, server_ip, server_port, connect_timeout):
        upstream_sock = create_tcp_socket(server_ip, server_port, connect_timeout)
        self.resources.append(upstream_sock)
        return upstream_sock

    def add_resource(self, res):
        self.resources.append(res)

    def forward(self, upstream_sock, timeout=7, tick=2, bufsize=8192, encrypt=None, decrypt=None):
        buffer_multiplier = 1
        try:
            timecount = 61 if self.forward_started else timeout
            while 1:
                timecount -= tick
                if timecount <= 0:
                    return
                ins, _, errors = select.select(
                    [self.downstream_sock, upstream_sock], [], [self.downstream_sock, upstream_sock], tick)
                if errors:
                    break
                if ins:
                    for sock in ins:
                        if sock is upstream_sock:
                            data = sock.recv(bufsize * buffer_multiplier)
                            buffer_multiplier = min(16, buffer_multiplier + 1)
                            if data:
                                self.forward_started = True
                                if decrypt:
                                    data = decrypt(data)
                                self.downstream_sock.sendall(data)
                                timecount = 61 if self.forward_started else timeout
                            else:
                                return
                        else:
                            buffer_multiplier = 1
                            data = sock.recv(bufsize)
                            if data:
                                if encrypt:
                                    data = encrypt(data)
                                upstream_sock.sendall(data)
                                timecount = 61 if self.forward_started else timeout
                            else:
                                return
        except socket.error as e:
            if e[0] not in (10053, 10054, 10057, errno.EPIPE):
                raise
        finally:
            if not self.forward_started:
                self.fall_back(reason='direct connection does not receive any response')

    def close(self):
        for res in self.resources:
            try:
                res.close()
            except:
                pass

    def fall_back(self, reason):
        if self.forward_started:
            LOGGER.fatal('[%s] fall back can not happen after forward started:\n%s' %
                         (repr(self), traceback.format_stack()))
            raise Exception('!!! fall back can not happen after forward started !!!')
        raise ProxyFallBack(reason)

    def direct_connection_succeeded(self):
        direct_connection_successes.add((self.dst_ip, self.dst_port))
        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.debug('[%s] direct connection succeeded' % repr(self))

    def direct_connection_failed(self):
        direct_connection_failures[(self.dst_ip, self.dst_port)] = time.time()
        LOGGER.info('[%s] direct connection failed' % repr(self))

    def dump_proxies(self):
        LOGGER.info('dump proxies: %s' % [p for p in proxies if not p.died])

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
    src_ip, src_port = address
    try:
        dst_ip, dst_port = get_original_destination(downstream_sock, src_ip, src_port)
        client = ProxyClient(downstream_sock, src_ip, src_port, dst_ip, dst_port)
        try:
            if LOGGER.isEnabledFor(logging.DEBUG):
                LOGGER.debug('[%s] downstream connected' % repr(client))
            pick_proxy_and_forward(client)
            if LOGGER.isEnabledFor(logging.DEBUG):
                LOGGER.debug('[%s] done' % repr(client))
        except:
            if LOGGER.isEnabledFor(logging.DEBUG):
                LOGGER.debug('[%s] done with error' % repr(client), exc_info=1)
            else:
                LOGGER.info('[%s] done with error: %s' % (repr(client), sys.exc_info()[1]))
        finally:
            client.close()
    except:
        LOGGER.exception('failed to handle %s:%s' % (src_ip, src_port))


def get_original_destination(sock, src_ip, src_port):
    return SPI['get_original_destination'](sock, src_ip, src_port)


def _get_original_destination(sock, src_ip, src_port):
    dst = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    dst_port, dst_ip = struct.unpack("!2xH4s8x", dst)
    dst_ip = socket.inet_ntoa(dst_ip)
    return dst_ip, dst_port


SPI['get_original_destination'] = _get_original_destination


def pick_proxy_and_forward(client):
    if lan_ip.is_lan_traffic(client.src_ip, client.dst_ip):
        try:
            DIRECT_PROXY.forward(client)
        except ProxyFallBack:
            pass
        return
    if client.dst_ip in fqdns.BUILTIN_WRONG_ANSWERS():
        LOGGER.error('[%s] destination is GFW wrong answer' % repr(client))
        NONE_PROXY.forward(client)
        return
    if CHINA_PROXY and china_ip.is_china_ip(client.dst_ip):
        try:
            CHINA_PROXY.forward(client)
        except ProxyFallBack:
            pass
        return
    for i in range(3):
        proxy = pick_proxy(client)
        while proxy:
            if not client.host:
                break
            elif 'PUBLIC' in proxy.flags and any(fnmatch.fnmatch(client.host, host) for host in NO_PUBLIC_PROXY_HOSTS):
                client.tried_proxies[proxy] = 'skip PUBLIC'
            else:
                break
            proxy = pick_proxy(client)
        proxy = proxy or DIRECT_PROXY
        if 'DIRECT' in proxy.flags:
            LOGGER.debug('[%s] picked proxy: %s' % (repr(client), repr(proxy)))
        else:
            LOGGER.info('[%s] picked proxy: %s' % (repr(client), repr(proxy)))
        try:
            proxy.forward(client)
            return
        except ProxyFallBack, e:
            LOGGER.error('[%s] fall back to other proxy due to %s: %s' % (repr(client), e.reason, repr(proxy)))
            client.tried_proxies[proxy] = e.reason
        except NotHttp:
            client.tried_proxies[proxy] = 'not http'
            continue
    LOGGER.error('[%s] fall back to direct after too many retries: %s' % (repr(client), client.tried_proxies))
    try:
        DIRECT_PROXY.forward(client)
    except ProxyFallBack:
        pass


def pick_proxy(client):
    if mandatory_proxies:
        available_mandatory_proxies = [p for p in mandatory_proxies if not p.died and p not in client.tried_proxies]
        if available_mandatory_proxies:
            return random.choice(available_mandatory_proxies)
        raise Exception('[%s] no proxy to handle' % repr(client))
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
        if any(fnmatch.fnmatch(client.host, host) for host in NO_DIRECT_PROXY_HOSTS):
            ip_black_list.add(client.dst_ip)
    dst_color = get_dst_color(client.dst_ip, client.dst_port)
    if LOGGER.isEnabledFor(logging.DEBUG):
        LOGGER.debug('[%s] analyzed traffic: %s %s %s' % (repr(client), dst_color, protocol, domain))
    if protocol == 'HTTP' or client.dst_port == 80:
        if 'BLACK' == dst_color:
            return pick_http_proxy(client)
        else:
            return pick_http_try_proxy(client) or pick_http_proxy(client)
    elif protocol == 'HTTPS' or client.dst_port == 443:
        if 'BLACK' == dst_color:
            return pick_https_proxy(client)
        else:
            return pick_https_try_proxy(client) or pick_https_proxy(client)
    else:
        return None


def get_dst_color(ip, port):
    dst = (ip, port)
    if dst in direct_connection_successes:
        return 'WHITE'
    failure = direct_connection_failures.get(dst)
    if failure and (time.time() - failure) < 60: # make dst BLACK for 1 minute
        return 'BLACK'
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


def pick_https_try_proxy(client):
    return None if HTTPS_TRY_PROXY in client.tried_proxies else HTTPS_TRY_PROXY


def pick_http_proxy(client):
    http_only_proxies = [proxy for proxy in proxies if
                         proxy.is_protocol_supported('HTTP') and not proxy.is_protocol_supported('HTTPS')
                         and not proxy.died and proxy not in client.tried_proxies]
    if http_only_proxies:
        return random.choice(http_only_proxies)
    ss_proxies = [proxy for proxy in proxies if proxy.is_protocol_supported('SHADOWSOCKS')
                                                and not proxy.died and proxy not in client.tried_proxies]
    if ss_proxies:
        return random.choice(ss_proxies)
    http_proxies = [proxy for proxy in proxies if
                    proxy.is_protocol_supported('HTTP')
                    and not proxy.died and proxy not in client.tried_proxies]
    if http_proxies:
        return random.choice(http_proxies)
    return None


def pick_https_proxy(client):
    private_https_proxies = [proxy for proxy in proxies if
                            proxy.is_protocol_supported('HTTPS') and
                            'PUBLIC' not in proxy.flags and
                            not proxy.died and proxy not in client.tried_proxies]
    if private_https_proxies:
        return random.choice(private_https_proxies)
    https_proxies = [proxy for proxy in proxies if
                     proxy.is_protocol_supported('HTTPS') and not proxy.died and proxy not in client.tried_proxies]
    if https_proxies:
        return random.choice(https_proxies)
    else:
        return None


def refresh_proxies():
    global proxies
    LOGGER.info('refresh proxies: %s' % proxies)
    socks = []
    type_to_proxies = {}
    for proxy in proxies:
        type_to_proxies.setdefault(proxy.__class__, []).append(proxy)
    success = True
    for proxy_type, instances in type_to_proxies.items():
        try:
            success = success and proxy_type.refresh(instances, create_udp_socket, create_tcp_socket)
        except:
            LOGGER.exception('failed to refresh proxies %s' % instances)
            success = False
    for sock in socks:
        try:
            sock.close()
        except:
            pass
    LOGGER.info('refreshed proxies: %s' % proxies)
    if success and CHECK_ACCESS:
        check_access_many_times('https://www.twitter.com', 10)
        check_access_many_times('https://plus.google.com', 5)
        check_access_many_times('http://www.youtube.com', 5)
        check_access_many_times('http://www.facebook.com', 5)
    return success


def check_access_many_times(url, times):
    success = 0
    for i in range(times):
        greenlet = gevent.spawn(check_access, url)
        try:
            if greenlet.get(timeout=10):
                success += 1
                LOGGER.info('checking access %s: passed' % url)
        except:
            LOGGER.error('checking access %s: failed' % url)
        finally:
            greenlet.kill(block=False)
    LOGGER.fatal('checked access %s: %s/%s' % (url, success, times))
    return success


def check_access(url):
    try:
        with contextlib.closing(urllib2.urlopen(url)) as response:
            response.read()
        return True
    except:
        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.debug('check access %s failed' % url, exc_info=1)
        else:
            LOGGER.info('check access %s failed: %s' % (url, sys.exc_info()[1]))
        return False


def setup_development_env():
    subprocess.check_call(
        'iptables -t nat -I OUTPUT -p tcp ! -s %s -j DNAT --to-destination %s:%s' %
        (OUTBOUND_IP, LISTEN_IP, LISTEN_PORT), shell=True)


def teardown_development_env():
    subprocess.check_call(
        'iptables -t nat -D OUTPUT -p tcp ! -s %s -j DNAT --to-destination %s:%s' %
        (OUTBOUND_IP, LISTEN_IP, LISTEN_PORT), shell=True)


def start_server():
    server = gevent.server.StreamServer((LISTEN_IP, LISTEN_PORT), handle)
    LOGGER.info('started fqsocks at %s:%s' % (LISTEN_IP, LISTEN_PORT))
    try:
        server.serve_forever()
    except:
        LOGGER.exception('failed to start server')
    finally:
        LOGGER.info('server stopped')


def keep_refreshing_proxies():
    while True:
        for i in range(8):
            if refresh_proxies():
                break
            retry_interval = math.pow(2, i)
            LOGGER.error('refresh failed, will retry %s seconds later' % retry_interval)
            gevent.sleep(retry_interval)
        LOGGER.info('next refresh will happen %s seconds later' % REFRESH_INTERVAL)
        gevent.sleep(REFRESH_INTERVAL)


def create_tcp_socket(server_ip, server_port, connect_timeout):
    return SPI['create_tcp_socket'](server_ip, server_port, connect_timeout)


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


def setup_logging(log_level, log_file=None):
    logging.basicConfig(
        stream=sys.stdout, level=log_level, format='%(asctime)s %(levelname)s %(message)s')
    if log_file:
        handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=1024 * 512, backupCount=0)
        handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
        handler.setLevel(log_level)
        logging.getLogger('fqsocks').addHandler(handler)


def main(argv):
    global LISTEN_IP, LISTEN_PORT, OUTBOUND_IP, CHINA_PROXY, CHECK_ACCESS
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument('--listen', default='127.0.0.1:12345')
    argument_parser.add_argument('--outbound-ip', default='10.1.2.3')
    argument_parser.add_argument('--dev', action='store_true', help='setup network/iptables on development machine')
    argument_parser.add_argument('--log-level', default='INFO')
    argument_parser.add_argument('--log-file')
    argument_parser.add_argument(
        '--proxy', action='append', default=[], help='for example --proxy goagent,appid=abcd')
    argument_parser.add_argument('--google-host', action='append', default=[])
    argument_parser.add_argument('--disable-china-optimization', action='store_true')
    argument_parser.add_argument('--disable-access-check', action='store_true')
    argument_parser.add_argument('--http-request-mark')
    args = argument_parser.parse_args(argv)
    log_level = getattr(logging, args.log_level)
    setup_logging(log_level, args.log_file)
    LISTEN_IP, LISTEN_PORT = args.listen.split(':')
    LISTEN_IP = '' if '*' == LISTEN_IP else LISTEN_IP
    LISTEN_PORT = int(LISTEN_PORT)
    OUTBOUND_IP = args.outbound_ip
    if args.google_host:
        GoAgentProxy.GOOGLE_HOSTS = args.google_host
    if not args.disable_china_optimization:
        CHINA_PROXY = DIRECT_PROXY
    if args.disable_access_check:
        CHECK_ACCESS = False
    if args.http_request_mark:
        HTTP_TRY_PROXY.http_request_mark = eval(args.http_request_mark)
    for props in args.proxy:
        props = props.split(',')
        prop_dict = dict(p.split('=') for p in props[1:])
        n = prop_dict.pop('n', 0)
        n = int(n)
        if n:
            for i in range(1, 1 + n):
                proxy = proxy_types[props[0]](**{k: v.replace('#n#', str(i)) for k, v in prop_dict.items()})
                proxies.append(proxy)
        else:
            proxy = proxy_types[props[0]](**prop_dict)
            proxies.append(proxy)
    if args.dev:
        signal.signal(signal.SIGTERM, lambda signum, fame: teardown_development_env())
        signal.signal(signal.SIGINT, lambda signum, fame: teardown_development_env())
        atexit.register(teardown_development_env)
        setup_development_env()
    gevent.monkey.patch_all()
    greenlets = [gevent.spawn(start_server), gevent.spawn(keep_refreshing_proxies)]
    for greenlet in greenlets:
        greenlet.join()

# TODO test if connect being blocked by GFW
# TODO kill fqsock -HUP to reload proxy upon connectivity change
# TODO add shadowsocks proxy
# TODO measure the speed of proxy which adds weight to the picking process
# TODO add http-relay proxy
# TODO add socks4 proxy
# TODO add socks5 proxy
# TODO add ssh proxy
# TODO add spdy proxy
# TODO === future ===
# TODO add vpn as proxy (setup vpn, mark packet, mark based routing)

if '__main__' == __name__:
    main(sys.argv[1:])