# -*- coding: utf-8 -*-
import httplib
import os.path
import fqlan

import jinja2
import gevent

from .. import httpd
from ..gateways import http_gateway
from .. import config_dir


DOWNSTREAM_HTML_FILE = os.path.join(os.path.dirname(__file__), '..', 'templates', 'downstream.html')


@httpd.http_handler('GET', 'downstream')
def downstream_page(environ, start_response):
    with open(DOWNSTREAM_HTML_FILE) as f:
        template = jinja2.Template(unicode(f.read(), 'utf8'))
    start_response(httplib.OK, [('Content-Type', 'text/html')])
    return [template.render(
        _=environ['select_text'],
        default_interface_ip=fqlan.get_default_interface_ip(),
        http_gateway=http_gateway,
        httpd=httpd).encode('utf8')]


@httpd.http_handler('POST', 'http-gateway/enable')
def handle_enable_http_gateway(environ, start_response):
    if not http_gateway.server_greenlet:
        http_gateway.server_greenlet = gevent.spawn(http_gateway.serve_forever)
    config_dir.update_fqrouter_config(http_gateway_enabled=True)
    start_response(httplib.OK, [('Content-Type', 'text/plain')])
    return []


@httpd.http_handler('POST', 'http-gateway/disable')
def handle_disable_http_gateway(environ, start_response):
    if http_gateway.server_greenlet:
        http_gateway.server_greenlet.kill()
        http_gateway.server_greenlet = None
    config_dir.update_fqrouter_config(http_gateway_enabled=False)
    start_response(httplib.OK, [('Content-Type', 'text/plain')])
    return []