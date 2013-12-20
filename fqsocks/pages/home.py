# -*- coding: utf-8 -*-
import httplib
import logging
import os.path
import fqdns
import time

import jinja2

from .. import httpd
from ..gateways import proxy_client
from .. import config_file
from ..gateways import http_gateway
from . import downstream
from .. import networking
from . import upstream
HOME_HTML_FILE = os.path.join(os.path.dirname(__file__), '..', 'templates', 'home.html')
LOGGER = logging.getLogger(__name__)

@httpd.http_handler('GET', '')
@httpd.http_handler('GET', 'home')
def home_page(environ, start_response):
    with open(HOME_HTML_FILE) as f:
        template = jinja2.Template(unicode(f.read(), 'utf8'))
    start_response(httplib.OK, [('Content-Type', 'text/html')])
    is_root = 0 == os.getuid()
    args = dict(
        _=environ['select_text'],
        domain_name=environ.get('HTTP_HOST') or '127.0.0.1:2515',
        tcp_scrambler_enabled=proxy_client.tcp_scrambler_enabled,
        google_scrambler_enabled=proxy_client.google_scrambler_enabled,
        https_enforcer_enabled=proxy_client.https_enforcer_enabled,
        china_shortcut_enabled=proxy_client.china_shortcut_enabled,
        direct_access_enabled=proxy_client.direct_access_enabled,
        config=config_file.read_config(),
        is_root=is_root,
        default_interface_ip=networking.get_default_interface_ip(),
        http_gateway=http_gateway,
        httpd=httpd,
        spi_wifi_repeater=downstream.spi_wifi_repeater if is_root else None,
        now=time.time(),
        hosted_domain_enabled=upstream.DNS_HANDLER.enable_hosted_domain)
    html = template.render(**args).encode('utf8')
    return [html]


@httpd.http_handler('GET', 'notice')
def get_notice_url(environ, start_response):
    try:
        domain = environ['select_text']('en.url.notice.fqrouter.com', 'cn.url.notice.fqrouter.com')
        results = fqdns.resolve('TXT', [domain], 'udp', [('8.8.8.8', 53), ('208.67.222.222', 443)], 3)
        url = results[domain][0]
        if '?' in url:
            url = '%s&_ct=%s' % time.time()
        else:
            url = '%s?_ct=%s' % time.time()
        start_response(httplib.TEMPORARY_REDIRECT, [('Location', url)])
        return []
    except:
        start_response(httplib.TEMPORARY_REDIRECT, [('Location', 'https://s3.amazonaws.com/fqrouter-notice/index.html')])
        return []