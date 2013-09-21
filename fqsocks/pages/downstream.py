# -*- coding: utf-8 -*-
import httplib
import os
import fqlan

import jinja2
import gevent

from .. import httpd
from ..gateways import http_gateway
from .. import config_file


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
    if http_gateway.server_greenlet is None:
        http_gateway.server_greenlet = gevent.spawn(http_gateway.serve_forever)

    def apply(config):
        config['http_gateway']['enabled'] = True

    config_file.update_config(apply)
    start_response(httplib.OK, [('Content-Type', 'text/plain')])
    return []


@httpd.http_handler('POST', 'http-gateway/disable')
def handle_disable_http_gateway(environ, start_response):
    if http_gateway.server_greenlet is not None:
        http_gateway.server_greenlet.kill()
        http_gateway.server_greenlet = None

    def apply(config):
        config['http_gateway']['enabled'] = False

    config_file.update_config(apply)
    start_response(httplib.OK, [('Content-Type', 'text/plain')])
    return []


@httpd.http_handler('POST', 'http-manager/config/validate')
def handle_validate_http_manager_config(environ, start_response):
    start_response(httplib.OK, [('Content-Type', 'text/plain')])
    port = environ['REQUEST_ARGUMENTS']['port'].value
    try:
        port = int(port)
    except:
        return [environ['select_text']('must be a number', '只能是数字')]
    if 0 != os.getuid():
        if port < 1024:
            return [environ['select_text']('must > 1024', '端口号不能小于1024')]
    return []


@httpd.http_handler('POST', 'http-manager/config/update')
def handle_update_http_manager_config(environ, start_response):
    port = environ['REQUEST_ARGUMENTS']['port'].value
    httpd.LISTEN_PORT = int(port)

    def apply(config):
        config['http_manager']['port'] = httpd.LISTEN_PORT

    config_file.update_config(apply)
    start_response(httplib.OK, [('Content-Type', 'text/plain')])
    if httpd.server_greenlet is not None:
        httpd.server_greenlet.kill()
        httpd.server_greenlet = None
    httpd.server_greenlet = gevent.spawn(httpd.serve_forever)
    gevent.sleep(0.5)
    if httpd.server_greenlet.ready():
        httpd.server_greenlet = None
        return [environ['select_text']('failed to start on new port', '用新端口启动失败')]
    return []