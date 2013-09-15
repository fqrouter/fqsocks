# -*- coding: utf-8 -*-
import httplib
import time
import logging
import os.path
import functools
import urlparse
from datetime import datetime
import fqlan
import json

import jinja2
import gevent

import httpd
import stat
from .gateways import proxy_client


PROXIES_HTML_FILE = os.path.join(os.path.dirname(__file__), 'templates', 'proxies.html')
PROXY_LIST_HTML_FILE = os.path.join(os.path.dirname(__file__), 'templates', 'proxy-list.html')
REMOTE_ACCESS_HTML_FILE = os.path.join(os.path.dirname(__file__), 'templates', 'remote-access.html')
FRIENDS_HTML_FILE = os.path.join(os.path.dirname(__file__), 'templates', 'friends.html')
LAN_DEVICES_HTML_FILE = os.path.join(os.path.dirname(__file__), 'templates', 'lan-devices.html')
WHITELIST_PAC_FILE = os.path.join(os.path.dirname(__file__), 'templates', 'whitelist.pac')
ASSETS_DIR = os.path.join(os.path.dirname(__file__), 'assets')
LOGGER = logging.getLogger(__name__)
MAX_TIME_RANGE = 60 * 10


def handle_refresh_proxies(environ, start_response):
    start_response(httplib.OK, [('Content-Type', 'text/plain')])
    proxy_client.auto_fix_enabled = True
    proxy_client.refresh_proxies()
    return ['OK']


def counters_page(environ, start_response):
    start_response(httplib.OK, [('Content-Type', 'text/plain')])
    for counter in stat.counters:
        yield '%s\n' % str(counter)


def proxies_page(environ, start_response):
    arguments = urlparse.parse_qs(environ['QUERY_STRING'])
    start_response(httplib.OK, [('Content-Type', 'text/html')])
    proxies_counters = {}
    for counter in stat.counters:
        proxies_counters.setdefault(counter.proxy.public_name, []).append(counter)
    after = time.time() - MAX_TIME_RANGE
    proxies_stats = {}
    for proxy_public_name, proxy_counters in sorted(proxies_counters.items(),
                                                    key=lambda (proxy_public_name, proxy_counters): proxy_public_name):
        rx_bytes_list, rx_seconds_list, _ = zip(*[counter.total_rx(after) for counter in proxy_counters])
        rx_bytes = sum(rx_bytes_list)
        rx_seconds = sum(rx_seconds_list)
        if rx_seconds:
            rx_speed = rx_bytes / (rx_seconds * 1000)
        else:
            rx_speed = 0
        tx_bytes_list, tx_seconds_list, _ = zip(*[counter.total_tx(after) for counter in proxy_counters])
        tx_bytes = sum(tx_bytes_list)
        tx_seconds = sum(tx_seconds_list)
        if tx_seconds:
            tx_speed = tx_bytes / (tx_seconds * 1000)
        else:
            tx_speed = 0
        if not proxy_public_name:
            continue
        proxies_stats[proxy_public_name] = {
            'rx_speed_value': rx_speed,
            'rx_speed_label': '%05.2f KB/s' % rx_speed,
            'rx_bytes_value': rx_bytes,
            'rx_bytes_label': to_human_readable_size(rx_bytes),
            'tx_speed_value': tx_speed,
            'tx_speed_label': '%05.2f KB/s' % tx_speed,
            'tx_bytes_value': tx_bytes,
            'tx_bytes_label': to_human_readable_size(tx_bytes)
        }
    for proxy in proxy_client.proxies:
        proxy_public_name = proxy.public_name
        if not proxy_public_name:
            continue
        if proxy_public_name in proxies_stats:
            proxies_stats[proxy_public_name]['died'] = proxy.died
        else:
            proxies_stats[proxy_public_name] = {
                'died': proxy.died,
                'rx_speed_value': 0,
                'rx_speed_label': '00.00 KB/s',
                'rx_bytes_value': 0,
                'rx_bytes_label': '000.00 B',
                'tx_speed_value': 0,
                'tx_speed_label': '00.00 KB/s',
                'tx_bytes_value': 0,
                'tx_bytes_label': '000.00 B'
            }
    is_list_only = arguments.get('list-only')
    with open(PROXY_LIST_HTML_FILE) as f:
        proxy_list_template = jinja2.Template(f.read())
    proxy_list = proxy_list_template.render(proxies_stats=proxies_stats).encode('utf8')
    if is_list_only:
        return [proxy_list]
    with open(PROXIES_HTML_FILE) as f:
        proxies_template = jinja2.Template(unicode(f.read(), 'utf8'))
    last_refresh_started_at = datetime.fromtimestamp(proxy_client.last_refresh_started_at)
    return [proxies_template.render(
        _=environ['select_text'], proxy_list=proxy_list,
        last_refresh_started_at=last_refresh_started_at).encode('utf8')]


def remote_access_page(environ, start_response):
    start_response(httplib.OK, [('Content-Type', 'text/html')])
    with open(REMOTE_ACCESS_HTML_FILE) as f:
        template = jinja2.Template(unicode(f.read(), 'utf8'))
    default_interface_ip = fqlan.get_default_interface_ip()
    return [template.render(_=environ['select_text'], default_interface_ip=default_interface_ip).encode('utf8')]


def to_human_readable_size(num):
    for x in ['B', 'KB', 'MB', 'GB', 'TB']:
        if num < 1024.0:
            return '%06.2f %s' % (num, x)
        num /= 1024.0


def get_asset(file_path, content_type, environ, start_response):
    start_response(httplib.OK, [('Content-Type', content_type)])
    with open(file_path) as f:
        return [f.read()]


def pac_page(environ, start_response):
    with open(WHITELIST_PAC_FILE) as f:
        template = jinja2.Template(unicode(f.read(), 'utf8'))
    ip = fqlan.get_default_interface_ip()
    start_response(httplib.OK, [('Content-Type', 'application/x-ns-proxy-autoconfig')])
    return [template.render(http_gateway='%s:2516' % ip).encode('utf8')]


def friends_page(environ, start_response):
    with open(FRIENDS_HTML_FILE) as f:
        template = jinja2.Template(unicode(f.read(), 'utf8'))
    start_response(httplib.OK, [('Content-Type', 'text/html')])
    return [template.render(_=environ['select_text']).encode('utf8')]


scan_greenlet = None
lan_devices = {}


def handle_lan_scan(environ, start_response):
    global scan_greenlet
    start_response(httplib.OK, [('Content-Type', 'application/json')])
    was_running = False
    if scan_greenlet:
        if scan_greenlet.ready():
            scan_greenlet = gevent.spawn(lan_scan)
        else:
            was_running = True
    else:
        scan_greenlet = gevent.spawn(lan_scan)
    return [json.dumps({
        'was_running': was_running
    })]


def lan_scan():
    for result in fqlan.scan(mark='0xcafe'):
        ip, mac, hostname = result
        if ip not in lan_devices:
            lan_devices[ip] = {
                'ip': ip,
                'mac': mac,
                'hostname': hostname,
                'is_picked': False
            }


def handle_lan_update(environ, start_response):
    start_response(httplib.OK, [('Content-Type', 'application/json')])
    ip = environ['REQUEST_ARGUMENTS']['ip'].value
    is_picked = 'true' == environ['REQUEST_ARGUMENTS']['is_picked'].value
    LOGGER.info('update %s %s' % (ip, is_picked))
    if ip not in lan_devices:
        return [json.dumps({'success': False})]
    lan_devices[ip]['is_picked'] = is_picked
    return [json.dumps({'success': True})]


def lan_devices_page(environ, start_response):
    with open(LAN_DEVICES_HTML_FILE) as f:
        template = jinja2.Template(unicode(f.read(), 'utf8'))
    start_response(httplib.OK, [('Content-Type', 'text/html')])
    return [template.render(_=environ['select_text'], lan_devices=lan_devices).encode('utf8')]


httpd.HANDLERS[('GET', 'assets/bootstrap.min.css')] = functools.partial(
    get_asset, os.path.join(ASSETS_DIR, 'bootstrap.min.css'), 'text/css')
httpd.HANDLERS[('GET', 'assets/bootstrap.min.js')] = functools.partial(
    get_asset, os.path.join(ASSETS_DIR, 'bootstrap.min.js'), 'text/javascript')
httpd.HANDLERS[('GET', 'assets/jquery.min.js')] = functools.partial(
    get_asset, os.path.join(ASSETS_DIR, 'jquery.min.js'), 'text/javascript')
httpd.HANDLERS[('GET', 'assets/tablesort.min.js')] = functools.partial(
    get_asset, os.path.join(ASSETS_DIR, 'tablesort.min.js'), 'text/javascript')
httpd.HANDLERS[('GET', 'counters')] = counters_page
httpd.HANDLERS[('POST', 'refresh-proxies')] = handle_refresh_proxies
httpd.HANDLERS[('GET', 'proxies')] = proxies_page
httpd.HANDLERS[('GET', 'remote-access')] = remote_access_page
httpd.HANDLERS[('GET', 'pac')] = pac_page
httpd.HANDLERS[('GET', 'friends')] = friends_page
httpd.HANDLERS[('POST', 'lan/scan')] = handle_lan_scan
httpd.HANDLERS[('POST', 'lan/update')] = handle_lan_update
httpd.HANDLERS[('GET', 'lan/devices')] = lan_devices_page