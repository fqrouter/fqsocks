# -*- coding: utf-8 -*-
import httplib
import time
import logging

import httpd
import jinja2
import os.path
import functools
import urlparse
import stat
import fqsocks
from datetime import datetime

PROXIES_HTML_FILE = os.path.join(os.path.dirname(__file__), 'templates', 'proxies.html')
PROXY_LIST_HTML_FILE = os.path.join(os.path.dirname(__file__), 'templates', 'proxy-list.html')
ASSETS_DIR = os.path.join(os.path.dirname(__file__), 'assets')
LOGGER = logging.getLogger(__name__)

MAX_TIME_RANGE = 60 * 10


def refresh_proxies(environ, start_response):
    start_response(httplib.OK, [('Content-Type', 'text/plain')])
    fqsocks.refresh_proxies()
    return ['OK']


def list_counters(environ, start_response):
    start_response(httplib.OK, [('Content-Type', 'text/plain')])
    for counter in stat.counters:
        yield '%s\n' % str(counter)


def list_proxies(environ, start_response):
    arguments = urlparse.parse_qs(environ['QUERY_STRING'])
    start_response(httplib.OK, [('Content-Type', 'text/html')])
    proxies_counters = {}
    for counter in stat.counters:
        proxies_counters.setdefault(counter.proxy.public_name, []).append(counter)
    after = time.time() - MAX_TIME_RANGE
    proxies_stats = {}
    for proxy_public_name, proxy_counters in sorted(proxies_counters.items(), key=lambda (proxy_public_name, proxy_counters): proxy_public_name):
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
    for proxy in fqsocks.proxies:
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
        proxies_template = jinja2.Template(f.read())
    last_refresh_started_at = datetime.fromtimestamp(fqsocks.last_refresh_started_at)
    return [proxies_template.render(
        proxy_list=proxy_list, last_refresh_started_at=last_refresh_started_at).encode('utf8')]


def to_human_readable_size(num):
    for x in ['B', 'KB', 'MB', 'GB', 'TB']:
        if num < 1024.0:
            return '%06.2f %s' % (num, x)
        num /= 1024.0


def get_asset(file_path, content_type, environ, start_response):
    start_response(httplib.OK, [('Content-Type', content_type)])
    with open(file_path) as f:
        return [f.read()]


httpd.HANDLERS[('GET', 'assets/bootstrap.min.css')] = functools.partial(
    get_asset, os.path.join(ASSETS_DIR, 'bootstrap.min.css'), 'text/css')
httpd.HANDLERS[('GET', 'assets/bootstrap.min.js')] = functools.partial(
    get_asset, os.path.join(ASSETS_DIR, 'bootstrap.min.js'), 'text/javascript')
httpd.HANDLERS[('GET', 'assets/jquery.min.js')] = functools.partial(
    get_asset, os.path.join(ASSETS_DIR, 'jquery.min.js'), 'text/javascript')
httpd.HANDLERS[('GET', 'assets/tablesort.min.js')] = functools.partial(
    get_asset, os.path.join(ASSETS_DIR, 'tablesort.min.js'), 'text/javascript')
httpd.HANDLERS[('GET', 'counters')] = list_counters
httpd.HANDLERS[('POST', 'refresh-proxies')] = refresh_proxies
httpd.HANDLERS[('GET', 'proxies')] = list_proxies