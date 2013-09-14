#!/usr/bin/env python
# thanks @phuslu https://github.com/phus/sniproxy/blob/master/sniproxy.py
# thanks @ofmax https://github.com/madeye/gaeproxy/blob/master/assets/modules/python.mp3
import logging
import logging.handlers
import sys
import argparse
import httplib

import gevent.server
import gevent.monkey

from .proxies.direct import DIRECT_PROXY
from .proxies.direct import HTTPS_TRY_PROXY
from .proxies.http_try import HTTP_TRY_PROXY
from .proxies.http_try import detect_if_ttl_being_ignored
from .proxies.goagent import GoAgentProxy
import httpd
import networking
from .gateways import proxy_client
from .gateways import tcp_gateway
from .gateways import http_gateway
import fqlan

__import__('fqsocks.web_ui')
LOGGER = logging.getLogger(__name__)

dns_pollution_ignored = False


def get_dns_polluted_at(environ, start_response):
    global dns_pollution_ignored
    start_response(httplib.OK, [('Content-Type', 'text/plain')])
    if not dns_pollution_ignored and proxy_client.dns_polluted_at > 0:
        dns_pollution_ignored = True
        yield str(proxy_client.dns_polluted_at)
    else:
        yield '0'


def start_force_us_ip(environ, start_response):
    start_response(httplib.OK, [('Content-Type', 'text/plain')])
    gevent.spawn(reset_force_us_ip)
    LOGGER.info('force_us_ip set to True')
    proxy_client.force_us_ip = True
    yield 'OK'


def reset_force_us_ip():
    gevent.sleep(30)
    LOGGER.info('force_us_ip reset to False')
    proxy_client.force_us_ip = False


def clear_states(environ, start_response):
    proxy_client.last_refresh_started_at = 0
    if HTTP_TRY_PROXY:
        HTTP_TRY_PROXY.host_black_list.clear()
        HTTP_TRY_PROXY.bad_requests.clear()
    if HTTPS_TRY_PROXY:
        HTTPS_TRY_PROXY.dst_black_list.clear()
    for proxy in proxy_client.proxies:
        proxy.clear_latency_records()
        proxy.clear_failed_times()
    GoAgentProxy.last_refresh_started_at = 0
    GoAgentProxy.black_list = set()
    GoAgentProxy.google_ip_failed_times = {}
    GoAgentProxy.google_ip_latency_records = {}
    LOGGER.info('cleared states upon request')
    start_response(httplib.OK, [('Content-Type', 'text/plain')])
    yield 'OK'


httpd.HANDLERS[('GET', 'dns-polluted-at')] = get_dns_polluted_at
httpd.HANDLERS[('POST', 'force-us-ip')] = start_force_us_ip
httpd.HANDLERS[('POST', 'clear-states')] = clear_states


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
    argument_parser.add_argument('--ip-command')
    argument_parser.add_argument('--ifconfig-command')
    args = argument_parser.parse_args(argv)
    if args.ip_command:
        fqlan.IP_COMMAND = args.ip_command
    if args.ifconfig_command:
        fqlan.IFCONFIG_COMMAND = args.ifconfig_command
    log_level = getattr(logging, args.log_level)
    setup_logging(log_level, args.log_file)
    LOGGER.info('fqsocks args: %s' % argv)
    LISTEN_IP, LISTEN_PORT = args.listen.split(':')
    LISTEN_IP = '' if '*' == LISTEN_IP else LISTEN_IP
    LISTEN_PORT = int(LISTEN_PORT)
    tcp_gateway.LISTEN_IP = LISTEN_IP
    tcp_gateway.LISTEN_PORT = LISTEN_PORT
    http_gateway.LISTEN_IP = ''
    http_gateway.LISTEN_PORT = 2516
    networking.OUTBOUND_IP = args.outbound_ip
    if args.google_host:
        GoAgentProxy.GOOGLE_HOSTS = args.google_host
    if not args.disable_china_shortcut:
        proxy_client.CHINA_PROXY = DIRECT_PROXY
    if args.disable_direct_access:
        proxy_client.HTTP_TRY_PROXY = None
        proxy_client.HTTPS_TRY_PROXY = None
    if proxy_client.HTTP_TRY_PROXY:
        if args.http_request_mark:
            HTTP_TRY_PROXY.http_request_mark = eval(args.http_request_mark)
        LOGGER.info('youtube scrambler enabled: %s' % args.enable_youtube_scrambler)
        HTTP_TRY_PROXY.enable_youtube_scrambler = args.enable_youtube_scrambler
    if args.disable_access_check:
        proxy_client.CHECK_ACCESS = False
    for props in args.proxy:
        props = props.split(',')
        prop_dict = dict(p.split('=') for p in props[1:])
        proxy_client.add_proxies(props[0], prop_dict)
    gevent.monkey.patch_all(ssl=False)
    try:
        gevent.monkey.patch_ssl()
    except:
        LOGGER.exception('failed to patch ssl')
    greenlets = [
        gevent.spawn(tcp_gateway.start_server),
        gevent.spawn(http_gateway.start_server),
        gevent.spawn(proxy_client.init_proxies),
        gevent.spawn(httpd.serve_forever)]
    if proxy_client.HTTP_TRY_PROXY and HTTP_TRY_PROXY.http_request_mark:
        greenlets.append(gevent.spawn(detect_if_ttl_being_ignored))
    for greenlet in greenlets:
        greenlet.join()

# TODO add socks4 proxy
# TODO add socks5 proxy
# TODO === future ===
# TODO add vpn as proxy (setup vpn, mark packet, mark based routing)

if '__main__' == __name__:
    main(sys.argv[1:])