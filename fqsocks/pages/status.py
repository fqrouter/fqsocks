import httplib
import os

import jinja2

from .. import httpd
from ..proxies.http_try import HTTP_TRY_PROXY
from ..gateways import proxy_client
from .. import stat

STATUS_TEMPLATE = os.path.join(os.path.dirname(__file__), '..', 'templates', 'status.html')
STATUS_SCRAMBLER_TEMPLATE = os.path.join(os.path.dirname(__file__), '..', 'templates', 'status', 'scrambler.html')
STATUS_HTTP_TEMPLATE = os.path.join(os.path.dirname(__file__), '..', 'templates', 'status', 'http.html')
STATUS_HTTPS_TEMPLATE = os.path.join(os.path.dirname(__file__), '..', 'templates', 'status', 'https.html')


@httpd.http_handler('GET', '')
def status_page(environ, start_response):
    with open(STATUS_TEMPLATE) as f:
        template = jinja2.Template(unicode(f.read(), 'utf8'))
    start_response(httplib.OK, [('Content-Type', 'text/html')])

    return [template.render(
        _=environ['select_text'],
        status_scrambler=status_scrambler(environ['select_text']),
        status_http=status_http(environ['select_text']),
        status_https=status_https(environ['select_text'])).encode('utf8')]


def status_scrambler(select_text):
    with open(STATUS_SCRAMBLER_TEMPLATE) as f:
        template = jinja2.Template(unicode(f.read(), 'utf8'))
    return template.render(
        _=select_text,
        HTTP_TRY_PROXY=HTTP_TRY_PROXY)


def status_http(select_text):
    http_proxies = [p for p in proxy_client.proxies if p.is_protocol_supported('HTTP')]
    died_http_proxies_count = len([p for p in http_proxies if p.died])
    alive_http_proxies_count = len(http_proxies) - died_http_proxies_count
    total_rx = sum(c.total_rx()[0] for c in stat.counters if c.proxy.is_protocol_supported('HTTP'))
    total_tx = sum(c.total_tx()[0] for c in stat.counters if c.proxy.is_protocol_supported('HTTP'))
    with open(STATUS_HTTP_TEMPLATE) as f:
        template = jinja2.Template(unicode(f.read(), 'utf8'))
    return template.render(
        _=select_text,
        died_http_proxies_count=died_http_proxies_count,
        alive_http_proxies_count=alive_http_proxies_count,
        total_rx=to_human_readable_size(total_rx),
        total_tx=to_human_readable_size(total_tx))


def status_https(select_text):
    https_proxies = [p for p in proxy_client.proxies if p.is_protocol_supported('HTTPS')]
    died_https_proxies_count = len([p for p in https_proxies if p.died])
    alive_https_proxies_count = len(https_proxies) - died_https_proxies_count
    total_rx = sum(c.total_rx()[0] for c in stat.counters if c.proxy.is_protocol_supported('HTTPS'))
    total_tx = sum(c.total_tx()[0] for c in stat.counters if c.proxy.is_protocol_supported('HTTPS'))
    with open(STATUS_HTTPS_TEMPLATE) as f:
        template = jinja2.Template(unicode(f.read(), 'utf8'))
    return template.render(
        _=select_text,
        died_https_proxies_count=died_https_proxies_count,
        alive_https_proxies_count=alive_https_proxies_count,
        total_rx=to_human_readable_size(total_rx),
        total_tx=to_human_readable_size(total_tx))

def to_human_readable_size(num):
    for x in ['B', 'KB', 'MB', 'GB', 'TB']:
        if num < 1024.0:
            return '%06.2f %s' % (num, x)
        num /= 1024.0