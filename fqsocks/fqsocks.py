#!/usr/bin/env python
# thanks @phuslu https://github.com/phus/sniproxy/blob/master/sniproxy.py
# thanks @ofmax https://github.com/madeye/gaeproxy/blob/master/assets/modules/python.mp3
import logging
import logging.handlers
import sys
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
import fqdns
import httplib

import dpkt
import gevent.server
import gevent.monkey

import lan_ip
import china_ip
from direct import DIRECT_PROXY
from direct import HTTPS_TRY_PROXY
from direct import NONE_PROXY
from http_try import HTTP_TRY_PROXY
from http_try import NotHttp
from http_try import is_no_direct_host
from http_try import detect_if_ttl_being_ignored
from goagent import GoAgentProxy
from http_relay import HttpRelayProxy
from http_connect import HttpConnectProxy
from spdy_relay import SpdyRelayProxy
from spdy_connect import SpdyConnectProxy
from dynamic import DynamicProxy
from shadowsocks import ShadowSocksProxy
from ssh import SshProxy
import httpd
import networking
import stat


proxy_directories = []
proxy_types = {
    'http-relay': HttpRelayProxy,
    'http-connect': HttpConnectProxy,
    'spdy-relay': SpdyRelayProxy,
    'spdy-connect': SpdyConnectProxy,
    'goagent': GoAgentProxy,
    'dynamic': DynamicProxy,
    'ss': ShadowSocksProxy,
    'ssh': SshProxy
}
LOGGER = logging.getLogger(__name__)

mandatory_proxies = []
proxies = []
direct_connection_successes = set() # set of (ip, port)
direct_connection_failures = {} # (ip, port) => failed_at

TLS1_1_VERSION = 0x0302
RE_HTTP_HOST = re.compile('Host: (.+)')
LISTEN_IP = None
LISTEN_PORT = None
NO_PUBLIC_PROXY_HOSTS = {
    'www.google.com',
    'google.com',
    'www.google.com.hk',
    'google.com.hk'
}
last_refresh_started_at = 0
CHINA_PROXY = None
CHECK_ACCESS = True
dns_polluted_at = 0
dns_pollution_ignored = False
force_us_ip = False
auto_fix_enabled = True


def get_dns_polluted_at(environ, start_response):
    global dns_pollution_ignored
    start_response(httplib.OK, [('Content-Type', 'text/plain')])
    if not dns_pollution_ignored and dns_polluted_at > 0:
        dns_pollution_ignored = True
        yield str(dns_polluted_at)
    else:
        yield '0'


def start_force_us_ip(environ, start_response):
    global force_us_ip
    start_response(httplib.OK, [('Content-Type', 'text/plain')])
    gevent.spawn(reset_force_us_ip)
    LOGGER.info('force_us_ip set to True')
    force_us_ip = True
    yield 'OK'


def reset_force_us_ip():
    global force_us_ip
    gevent.sleep(30)
    LOGGER.info('force_us_ip reset to False')
    force_us_ip = False


def clear_states(environ, start_response):
    global last_refresh_started_at
    if HTTP_TRY_PROXY:
        HTTP_TRY_PROXY.failed_times.clear()
        HTTP_TRY_PROXY.bad_requests.clear()
    if HTTPS_TRY_PROXY:
        HTTPS_TRY_PROXY.failed_times.clear()
    GoAgentProxy.black_list = set()
    last_refresh_started_at = 0
    LOGGER.info('cleared states upon request')
    start_response(httplib.OK, [('Content-Type', 'text/plain')])
    yield 'OK'


httpd.HANDLERS[('GET', 'dns-polluted-at')] = get_dns_polluted_at
httpd.HANDLERS[('POST', 'force-us-ip')] = start_force_us_ip
httpd.HANDLERS[('POST', 'clear-states')] = clear_states


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
        self.us_ip_only = False
        self.delayed_penalties = []

    def create_tcp_socket(self, server_ip, server_port, connect_timeout):
        upstream_sock = networking.create_tcp_socket(server_ip, server_port, connect_timeout)
        upstream_sock.counter = stat.opened(self.forwarding_by, self.host, self.dst_ip)
        self.resources.append(upstream_sock)
        self.resources.append(upstream_sock.counter)
        return upstream_sock

    def add_resource(self, res):
        self.resources.append(res)

    def forward(self, upstream_sock, timeout=7, tick=2, bufsize=8192, encrypt=None, decrypt=None, delayed_penalty=None):
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
                            # upstream_sock.counter.received(len(data))
                            buffer_multiplier = min(16, buffer_multiplier + 1)
                            if data:
                                self.forward_started = True
                                if decrypt:
                                    data = decrypt(data)
                                self.downstream_sock.sendall(data)
                                timecount = 61 if self.forward_started else timeout
                            else:
                                if self.forward_started:
                                    self.apply_delayed_penalties()
                                return
                        else:
                            buffer_multiplier = 1
                            data = sock.recv(bufsize)
                            if data:
                                if encrypt:
                                    data = encrypt(data)
                                # upstream_sock.counter.sending(len(data))
                                upstream_sock.sendall(data)
                                timecount = 61 if self.forward_started else timeout
                            else:
                                if self.forward_started:
                                    self.apply_delayed_penalties()
                                return
        except socket.error as e:
            if e[0] not in (10053, 10054, 10057, errno.EPIPE):
                raise
        finally:
            if not self.forward_started:
                self.fall_back(reason='forward does not receive any response', delayed_penalty=delayed_penalty)


    def apply_delayed_penalties(self):
        for delayed_penalty in self.delayed_penalties:
            try:
                delayed_penalty()
            except:
                LOGGER.exception('failed to apply delayed penalty: %s' % delayed_penalty)


    def close(self):
        for res in self.resources:
            try:
                res.close()
            except:
                pass

    def fall_back(self, reason, delayed_penalty=None):
        if self.forward_started:
            LOGGER.fatal('[%s] fall back can not happen after forward started:\n%s' %
                         (repr(self), traceback.format_stack()))
            raise Exception('!!! fall back can not happen after forward started !!!')
        if delayed_penalty:
            self.delayed_penalties.append(delayed_penalty)
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

    def has_tried(self, proxy):
        if proxy in self.tried_proxies:
            return True
        if isinstance(proxy, DynamicProxy):
            proxy = proxy.delegated_to
        if self.us_ip_only:
            if hasattr(proxy, 'proxy_ip') and not china_ip.is_us_ip(proxy.proxy_ip):
                LOGGER.info('skip %s' % proxy.proxy_ip)
                return True
        return proxy in self.tried_proxies

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


ProxyClient.ProxyFallBack = ProxyFallBack


def handle(downstream_sock, address):
    src_ip, src_port = address
    try:
        dst_ip, dst_port = networking.get_original_destination(downstream_sock, src_ip, src_port)
        client = ProxyClient(downstream_sock, src_ip, src_port, dst_ip, dst_port)
        if force_us_ip:
            client.us_ip_only = True
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


def pick_proxy_and_forward(client):
    global dns_polluted_at
    if lan_ip.is_lan_traffic(client.src_ip, client.dst_ip):
        try:
            DIRECT_PROXY.forward(client)
        except ProxyFallBack:
            pass
        return
    if client.dst_ip in fqdns.BUILTIN_WRONG_ANSWERS():
        LOGGER.error('[%s] destination is GFW wrong answer' % repr(client))
        dns_polluted_at = time.time()
        NONE_PROXY.forward(client)
        return
    if CHINA_PROXY and china_ip.is_china_ip(client.dst_ip):
        try:
            CHINA_PROXY.forward(client)
        except ProxyFallBack:
            pass
        return
    if not client.us_ip_only and should_fix():
        gevent.spawn(fix_by_refreshing_proxies)
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
        if not proxy:
            return
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


def should_fix():
    http_proxies_died = all(proxy.died for proxy in proxies if
                            proxy.is_protocol_supported('HTTP'))
    https_proxies_died = all(proxy.died for proxy in proxies if
                             proxy.is_protocol_supported('HTTPS'))
    dynamic_goagent_proxies = [proxy for proxy in proxies if
                               isinstance(proxy, DynamicProxy)
                               and isinstance(proxy.delegated_to, GoAgentProxy)]
    dynamic_goagent_proxies_died = dynamic_goagent_proxies and all(p.died for p in dynamic_goagent_proxies)
    if auto_fix_enabled and (http_proxies_died or https_proxies_died or dynamic_goagent_proxies_died):
        LOGGER.info('http %s https %s goagent %s, refresh proxies: %s' %
                    (http_proxies_died, https_proxies_died, dynamic_goagent_proxies_died, proxies))
        return True
    else:
        if dynamic_goagent_proxies_died:
            LOGGER.info('dynamic goagent proxies all died, fix now')
            return True
        else:
            return False


def is_direct_access_disabled():
    return not HTTP_TRY_PROXY


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
    dst_color = get_dst_color(client.host, client.dst_ip, client.dst_port)
    if LOGGER.isEnabledFor(logging.DEBUG):
        LOGGER.debug('[%s] analyzed traffic: %s %s %s' % (repr(client), dst_color, protocol, domain))
    if protocol == 'HTTP' or client.dst_port == 80:
        if 'BLACK' == dst_color:
            return pick_proxy_supports(client, 'HTTP')
        else:
            return pick_http_try_proxy(client) or pick_proxy_supports(client, 'HTTP')
    elif protocol == 'HTTPS' or client.dst_port == 443:
        if 'BLACK' == dst_color:
            return pick_proxy_supports(client, 'HTTPS')
        else:
            return pick_https_try_proxy(client) or pick_proxy_supports(client, 'HTTPS')
    else:
        if 'BLACK' == dst_color:
            return pick_proxy_supports(client, 'TCP')
        else:
            return pick_https_try_proxy(client) or pick_proxy_supports(client, 'TCP')


def get_dst_color(host, ip, port):
    if is_no_direct_host(host):
        return 'BLACK'
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
    if client.us_ip_only:
        client.tried_proxies[HTTP_TRY_PROXY] = 'us ip only'
        return None
    return None if HTTP_TRY_PROXY in client.tried_proxies else HTTP_TRY_PROXY


def pick_https_try_proxy(client):
    if client.us_ip_only:
        client.tried_proxies[HTTPS_TRY_PROXY] = 'us ip only'
        return None
    return None if HTTPS_TRY_PROXY in client.tried_proxies else HTTPS_TRY_PROXY


def pick_proxy_supports(client, protocol):
    supported_proxies = [proxy for proxy in proxies if
                         proxy.is_protocol_supported(protocol)
                         and not proxy.died and not client.has_tried(proxy)]
    if not supported_proxies:
        return None
    prioritized_proxies = {}
    for proxy in supported_proxies:
        prioritized_proxies.setdefault(proxy.priority, []).append(proxy)
    highest_priority = sorted(prioritized_proxies.keys())[0]
    return random.choice(prioritized_proxies[highest_priority])


def fix_by_refreshing_proxies():
    global auto_fix_enabled
    if refresh_proxies() and should_fix():
        LOGGER.critical('!!! auto fix does not work, disable it !!!')
        auto_fix_enabled = False


def refresh_proxies():
    global proxies
    global last_refresh_started_at
    if proxy_directories: # wait for proxy directories to load
        LOGGER.error('skip refreshing proxy because proxy directories not loaded yet')
        return False
    if time.time() - last_refresh_started_at < 60:
        LOGGER.error('skip refreshing proxy after last attempt %s seconds' % (time.time() - last_refresh_started_at))
        return False
    last_refresh_started_at = time.time()
    LOGGER.info('refresh proxies: %s' % proxies)
    socks = []
    type_to_proxies = {}
    for proxy in proxies:
        type_to_proxies.setdefault(proxy.__class__, []).append(proxy)
    success = True
    for proxy_type, instances in type_to_proxies.items():
        try:
            success = success and proxy_type.refresh(instances)
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
        LOGGER.info('check access in 10 seconds')
        gevent.sleep(10)
        check_access_many_times('https://www.twitter.com', 5)
        check_access_many_times('https://plus.google.com', 3)
        check_access_many_times('http://www.youtube.com', 3)
        check_access_many_times('http://www.facebook.com', 3)
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
        (networking.OUTBOUND_IP, LISTEN_IP, LISTEN_PORT), shell=True)


def teardown_development_env():
    subprocess.check_call(
        'iptables -t nat -D OUTPUT -p tcp ! -s %s -j DNAT --to-destination %s:%s' %
        (networking.OUTBOUND_IP, LISTEN_IP, LISTEN_PORT), shell=True)


def start_server():
    server = gevent.server.StreamServer((LISTEN_IP, LISTEN_PORT), handle)
    LOGGER.info('started fqsocks at %s:%s' % (LISTEN_IP, LISTEN_PORT))
    try:
        server.serve_forever()
    except:
        LOGGER.exception('failed to start server')
    finally:
        LOGGER.info('server stopped')


def add_proxies(proxy_type, prop_dict):
    n = prop_dict.pop('n', 0)
    n = int(n)
    if n:
        for i in range(1, 1 + n):
            proxy = proxy_types[proxy_type](**{k: v.replace('#n#', str(i)) for k, v in prop_dict.items()})
            proxies.append(proxy)
    else:
        if 'directory' == proxy_type:
            proxy_directories.append(prop_dict)
        else:
            proxy = proxy_types[proxy_type](**prop_dict)
            proxies.append(proxy)


def init_proxies():
    for i in range(8):
        if load_proxies_from_directories():
            if refresh_proxies():
                LOGGER.info('proxies init successfully')
                return
        retry_interval = math.pow(2, i)
        LOGGER.error('refresh failed, will retry %s seconds later' % retry_interval)
        gevent.sleep(retry_interval)
    LOGGER.critical('proxies init successfully')


def load_proxies_from_directories():
    for proxy_directory in list(proxy_directories):
        if not load_proxy_from_directory(proxy_directory):
            return False
    assert not proxy_directories
    return True


def load_proxy_from_directory(proxy_directory):
    try:
        sock = networking.create_udp_socket()
        more_proxies = []
        with contextlib.closing(sock):
            sock.settimeout(10)
            request = dpkt.dns.DNS(
                id=random.randint(1, 65535), qd=[dpkt.dns.DNS.Q(name=proxy_directory['src'], type=dpkt.dns.DNS_TXT)])
            sock.sendto(str(request), ('8.8.8.8', 53))
            gevent.sleep(0.1)
            for an in dpkt.dns.DNS(sock.recv(1024)).an:
                priority, proxy_type, count, partial_dns_record = an.text[0].split(':')[:4]
                count = int(count)
                priority = int(priority)
                if proxy_type in proxy_directory and proxy_type in proxy_types:
                    for i in range(count):
                        dns_record = '%s.fqrouter.com' % partial_dns_record.replace('#', str(i+1))
                        more_proxies.append(DynamicProxy(dns_record=dns_record, type=proxy_type, priority=priority))
        proxies.extend(more_proxies)
        proxy_directories.remove(proxy_directory)
        return True
    except:
        LOGGER.exception('failed to load proxy from directory')
        return False


def setup_logging(log_level, log_file=None):
    logging.basicConfig(
        stream=sys.stdout, level=log_level, format='%(asctime)s %(levelname)s %(message)s')
    if log_file:
        handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=1024 * 512, backupCount=1)
        handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
        handler.setLevel(log_level)
        logging.getLogger('fqsocks').addHandler(handler)


def main(argv):
    global LISTEN_IP, LISTEN_PORT, CHINA_PROXY, CHECK_ACCESS
    global HTTP_TRY_PROXY, HTTPS_TRY_PROXY
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument('--listen', default='127.0.0.1:12345')
    argument_parser.add_argument('--outbound-ip', default='10.1.2.3')
    argument_parser.add_argument('--dev', action='store_true', help='setup network/iptables on development machine')
    argument_parser.add_argument('--log-level', default='INFO')
    argument_parser.add_argument('--log-file')
    argument_parser.add_argument(
        '--proxy', action='append', default=[], help='for example --proxy goagent,appid=abcd')
    argument_parser.add_argument('--google-host', action='append', default=[])
    argument_parser.add_argument('--disable-china-shortcut', action='store_true')
    argument_parser.add_argument('--disable-access-check', action='store_true')
    argument_parser.add_argument('--disable-direct-access', action='store_true')
    argument_parser.add_argument('--http-request-mark')
    argument_parser.add_argument('--enable-youtube-scrambler', action='store_true')
    args = argument_parser.parse_args(argv)
    log_level = getattr(logging, args.log_level)
    setup_logging(log_level, args.log_file)
    LISTEN_IP, LISTEN_PORT = args.listen.split(':')
    LISTEN_IP = '' if '*' == LISTEN_IP else LISTEN_IP
    LISTEN_PORT = int(LISTEN_PORT)
    networking.OUTBOUND_IP = args.outbound_ip
    if args.google_host:
        GoAgentProxy.GOOGLE_HOSTS = args.google_host
    if not args.disable_china_shortcut:
        CHINA_PROXY = DIRECT_PROXY
    if args.disable_direct_access:
        HTTP_TRY_PROXY = None
        HTTPS_TRY_PROXY = None
    if HTTP_TRY_PROXY:
        if args.http_request_mark:
            HTTP_TRY_PROXY.http_request_mark = eval(args.http_request_mark)
        LOGGER.info('youtube scrambler enabled: %s' % args.enable_youtube_scrambler)
        HTTP_TRY_PROXY.enable_youtube_scrambler = args.enable_youtube_scrambler
    if args.disable_access_check:
        CHECK_ACCESS = False
    for props in args.proxy:
        props = props.split(',')
        prop_dict = dict(p.split('=') for p in props[1:])
        add_proxies(props[0], prop_dict)
    if args.dev:
        signal.signal(signal.SIGTERM, lambda signum, fame: teardown_development_env())
        signal.signal(signal.SIGINT, lambda signum, fame: teardown_development_env())
        atexit.register(teardown_development_env)
        setup_development_env()
    gevent.monkey.patch_all(ssl=False)
    try:
        gevent.monkey.patch_ssl()
    except:
        LOGGER.exception('failed to patch ssl')
    greenlets = [
        gevent.spawn(start_server), gevent.spawn(init_proxies),
        gevent.spawn(httpd.serve_forever)]
    if HTTP_TRY_PROXY and HTTP_TRY_PROXY.http_request_mark:
        greenlets.append(gevent.spawn(detect_if_ttl_being_ignored))
    for greenlet in greenlets:
        greenlet.join()

# TODO measure the speed of proxy which adds weight to the picking process
# TODO add socks4 proxy
# TODO add socks5 proxy
# TODO === future ===
# TODO add vpn as proxy (setup vpn, mark packet, mark based routing)

if '__main__' == __name__:
    main(sys.argv[1:])