#!/usr/bin/env python
# thanks @phuslu https://github.com/phus/sniproxy/blob/master/sniproxy.py
# thanks @ofmax https://github.com/madeye/gaeproxy/blob/master/assets/modules/python.mp3
import logging
import logging.handlers
import sys
import argparse
import httplib
import fqlan
import fqdns
import functools

import gevent.server
import gevent.monkey

from .proxies.http_try import HTTP_TRY_PROXY
from .proxies.http_try import detect_if_ttl_being_ignored
from .proxies.goagent import GoAgentProxy
import httpd
import networking
from .gateways import proxy_client
from .gateways import tcp_gateway
from .gateways import http_gateway
from .pages import lan_device
from . import config_file


__import__('fqsocks.pages')
LOGGER = logging.getLogger(__name__)

dns_pollution_ignored = False
DNS_HANDLER = fqdns.DnsHandler()


@httpd.http_handler('GET', 'dns-polluted-at')
def get_dns_polluted_at(environ, start_response):
    global dns_pollution_ignored
    start_response(httplib.OK, [('Content-Type', 'text/plain')])
    if not dns_pollution_ignored and proxy_client.dns_polluted_at > 0:
        dns_pollution_ignored = True
        yield str(proxy_client.dns_polluted_at)
    else:
        yield '0'


@httpd.http_handler('POST', 'force-us-ip')
def handle_force_us_ip(environ, start_response):
    start_response(httplib.OK, [('Content-Type', 'text/plain')])
    gevent.spawn(reset_force_us_ip)
    LOGGER.info('force_us_ip set to True')
    proxy_client.force_us_ip = True
    yield 'OK'


def reset_force_us_ip():
    gevent.sleep(30)
    LOGGER.info('force_us_ip reset to False')
    proxy_client.force_us_ip = False


@httpd.http_handler('POST', 'clear-states')
def handle_clear_states(environ, start_response):
    proxy_client.clear_proxy_states()
    http_gateway.dns_cache = {}
    lan_device.lan_devices = {}
    LOGGER.info('cleared states upon request')
    start_response(httplib.OK, [('Content-Type', 'text/plain')])
    yield 'OK'


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
    argument_parser.add_argument('--tcp-gateway-listen')
    argument_parser.add_argument('--http-gateway-listen')
    argument_parser.add_argument('--dns-server-listen')
    argument_parser.add_argument('--http-manager-listen')
    argument_parser.add_argument('--no-http-manager', action='store_true')
    argument_parser.add_argument('--outbound-ip')
    argument_parser.add_argument('--ip-command')
    argument_parser.add_argument('--ifconfig-command')
    argument_parser.add_argument('--config-file')
    argument_parser.add_argument('--log-level', default='INFO')
    argument_parser.add_argument('--log-file')
    argument_parser.add_argument('--proxy', action='append', default=[], help='for example --proxy goagent,appid=abcd')
    argument_parser.add_argument('--google-host', action='append', default=[])
    argument_parser.add_argument('--access-check', dest='access_check_enabled', action='store_true')
    argument_parser.add_argument('--no-access-check', dest='access_check_enabled', action='store_false')
    argument_parser.set_defaults(access_check_enabled=None)
    argument_parser.add_argument('--direct-access', dest='direct_access_enabled', action='store_true')
    argument_parser.add_argument('--no-direct-access', dest='direct_access_enabled', action='store_false')
    argument_parser.set_defaults(direct_access_enabled=None)
    argument_parser.add_argument('--china-shortcut', dest='china_shortcut_enabled', action='store_true')
    argument_parser.add_argument('--no-china-shortcut', dest='china_shortcut_enabled', action='store_false')
    argument_parser.set_defaults(china_shortcut_enabled=None)
    argument_parser.add_argument('--tcp-scrambler', dest='tcp_scrambler_enabled', action='store_true')
    argument_parser.add_argument('--no-tcp-scrambler', dest='youtube_scrambler_enabled', action='store_false')
    argument_parser.set_defaults(tcp_scrambler_enabled=None)
    argument_parser.add_argument('--youtube-scrambler', dest='youtube_scrambler_enabled', action='store_true')
    argument_parser.add_argument('--no-youtube-scrambler', dest='youtube_scrambler_enabled', action='store_false')
    argument_parser.set_defaults(youtube_scrambler_enabled=None)
    args = argument_parser.parse_args(argv)
    log_level = getattr(logging, args.log_level)
    setup_logging(log_level, args.log_file)
    config = read_config(args)
    LOGGER.info('config: %s' % config)
    if args.ip_command:
        fqlan.IP_COMMAND = args.ip_command
    if args.ifconfig_command:
        fqlan.IFCONFIG_COMMAND = args.ifconfig_command
    networking.OUTBOUND_IP = args.outbound_ip
    fqdns.OUTBOUND_IP = args.outbound_ip
    if args.google_host:
        GoAgentProxy.GOOGLE_HOSTS = args.google_host
    proxy_client.china_shortcut_enabled = config['china_shortcut_enabled']
    proxy_client.direct_access_enabled = config['direct_access_enabled']
    proxy_client.access_check_enabled = config['access_check_enabled']
    HTTP_TRY_PROXY.tcp_scrambler_enabled = config['tcp_scrambler_enabled']
    HTTP_TRY_PROXY.youtube_scrambler_enabled = config['youtube_scrambler_enabled']
    for props in args.proxy:
        props = props.split(',')
        prop_dict = dict(p.split('=') for p in props[1:])
        proxy_client.add_proxies(props[0], prop_dict)
    proxy_client.reset_proxy_directories()
    gevent.monkey.patch_all(ssl=False)
    try:
        gevent.monkey.patch_ssl()
    except:
        LOGGER.exception('failed to patch ssl')
    greenlets = []
    if args.dns_server_listen:
        dns_server = fqdns.HandlerDatagramServer(parse_ip_colon_port(args.dns_server_listen), DNS_HANDLER)
        greenlets.append(gevent.spawn(dns_server.serve_forever))
    http_gateway.LISTEN_IP, http_gateway.LISTEN_PORT = config['http_gateway']['ip'], config['http_gateway']['port']
    if config['http_gateway']['enabled']:
        http_gateway.server_greenlet = gevent.spawn(http_gateway.serve_forever)
        greenlets.append(http_gateway.server_greenlet)
    if args.tcp_gateway_listen:
        tcp_gateway.LISTEN_IP, tcp_gateway.LISTEN_PORT = parse_ip_colon_port(args.tcp_gateway_listen)
        tcp_gateway.server_greenlet = gevent.spawn(tcp_gateway.serve_forever)
        greenlets.append(tcp_gateway.server_greenlet)
    httpd.LISTEN_IP, httpd.LISTEN_PORT = config['http_manager']['ip'], config['http_manager']['port']
    if config['http_manager']['enabled']:
        httpd.server_greenlet = gevent.spawn(httpd.serve_forever)
        greenlets.append(httpd.server_greenlet)
    greenlets.append(gevent.spawn(proxy_client.init_proxies))
    if HTTP_TRY_PROXY.tcp_scrambler_enabled:
        greenlets.append(gevent.spawn(detect_if_ttl_being_ignored))
    for greenlet in greenlets:
        try:
            greenlet.join()
        except KeyboardInterrupt:
            return
        except:
            LOGGER.exception('greenlet join failed')
            return


def read_config(args):
    config_file.path = args.config_file
    config = config_file.read_config()
    if args.china_shortcut_enabled is not None:
        config['china_shortcut_enabled'] = args.china_shortcut_enabled
    if args.direct_access_enabled is not None:
        config['direct_access_enabled'] = args.direct_access_enabled
    if args.youtube_scrambler_enabled is not None:
        config['youtube_scrambler_enabled'] = args.youtube_scrambler_enabled
    if args.tcp_scrambler_enabled is not None:
        config['tcp_scrambler_enabled'] = args.tcp_scrambler_enabled
    if args.access_check_enabled is not None:
        config['access_check_enabled'] = args.access_check_enabled
    if args.no_http_manager:
        config['http_manager']['enabled'] = False
    if args.http_manager_listen:
        config['http_manager']['enabled'] = True
        config['http_manager']['ip'], config['http_manager']['port'] = parse_ip_colon_port(args.http_manager_listen)
    if args.http_gateway_listen:
        config['http_gateway']['enabled'] = True
        config['http_gateway']['ip'], config['http_gateway']['port'] = parse_ip_colon_port(args.http_gateway_listen)
    return config


def parse_ip_colon_port(ip_colon_port):
    if not isinstance(ip_colon_port, basestring):
        return ip_colon_port
    if ':' in ip_colon_port:
        server_ip, server_port = ip_colon_port.split(':')
        server_port = int(server_port)
    else:
        server_ip = ip_colon_port
        server_port = 53
    return '' if '*' == server_ip else server_ip, server_port

# TODO add socks4 proxy
# TODO add socks5 proxy
# TODO === future ===
# TODO add vpn as proxy (setup vpn, mark packet, mark based routing)

if '__main__' == __name__:
    main(sys.argv[1:])