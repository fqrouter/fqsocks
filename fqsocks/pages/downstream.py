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
spi_wifi_repeater = None


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


@httpd.http_handler('POST', 'http-manager/config/update')
def handle_update_http_manager_config(environ, start_response):
    start_response(httplib.OK, [('Content-Type', 'text/plain')])
    port = environ['REQUEST_ARGUMENTS']['port'].value
    try:
        httpd.LISTEN_PORT = int(port)
    except:
        return [environ['select_text']('must be a number', '只能是数字')]
    if httpd.server_greenlet is not None:
        httpd.server_greenlet.kill()
        httpd.server_greenlet = None
    httpd.server_greenlet = gevent.spawn(httpd.serve_forever)
    gevent.sleep(0.5)
    if httpd.server_greenlet.ready():
        httpd.server_greenlet = None
        return [environ['select_text']('failed to start on new port', '用新端口启动失败')]

    def apply(config):
        config['http_manager']['port'] = httpd.LISTEN_PORT

    config_file.update_config(apply)
    return []


@httpd.http_handler('POST', 'http-gateway/config/update')
def handle_update_http_gateway_config(environ, start_response):
    start_response(httplib.OK, [('Content-Type', 'text/plain')])
    port = environ['REQUEST_ARGUMENTS']['port'].value
    try:
        http_gateway.LISTEN_PORT = int(port)
    except:
        return [environ['select_text']('must be a number', '只能是数字')]
    if http_gateway.server_greenlet is not None:
        http_gateway.server_greenlet.kill()
        http_gateway.server_greenlet = None
    http_gateway.server_greenlet = gevent.spawn(http_gateway.serve_forever)
    gevent.sleep(0.5)
    if http_gateway.server_greenlet.ready():
        http_gateway.server_greenlet = None
        return [environ['select_text']('failed to start on new port', '用新端口启动失败')]

    def apply(config):
        config['http_gateway']['port'] = http_gateway.LISTEN_PORT

    config_file.update_config(apply)
    return []


@httpd.http_handler('POST', 'wifi-repeater/enable')
def handle_enable_wifi_repeater(environ, start_response):
    config = config_file.read_config()
    if spi_wifi_repeater:
        error = spi_wifi_repeater['start'](config['wifi_repeater']['ssid'], config['wifi_repeater']['password'])
    else:
        error = 'unsupported'
    start_response(httplib.OK, [('Content-Type', 'text/plain')])
    return [error]


@httpd.http_handler('POST', 'wifi-repeater/disable')
def handle_enable_wifi_repeater(environ, start_response):
    if spi_wifi_repeater:
        error = spi_wifi_repeater['stop']()
    else:
        error = 'unsupported'
    start_response(httplib.OK, [('Content-Type', 'text/plain')])
    return [error]


@httpd.http_handler('POST', 'wifi-repeater/reset')
def handle_reset_wifi_repeater(environ, start_response):
    if spi_wifi_repeater:
        spi_wifi_repeater['reset']()
    start_response(httplib.OK, [('Content-Type', 'text/plain')])
    return []


@httpd.http_handler('POST', 'wifi-repeater/config/update')
def handle_update_wifi_repeater_config(environ, start_response):
    start_response(httplib.OK, [('Content-Type', 'text/plain')])
    if not spi_wifi_repeater:
        return ['Wifi repeater is unsupported']
    ssid = environ['REQUEST_ARGUMENTS']['ssid'].value
    password = environ['REQUEST_ARGUMENTS']['password'].value
    if not ssid:
        return [environ['select_text']('SSID must not be empty', 'SSID不能为空')]
    if not password:
        return [environ['select_text']('Password must not be empty', '密码不能为空')]
    if len(password) < 8:
        return [environ['select_text']('Password must not be shorter than 8 characters', '密码长度必须大于8位')]

    def apply(config):
        config['wifi_repeater']['ssid'] = ssid
        config['wifi_repeater']['password'] = password

    config_file.update_config(apply)
    if spi_wifi_repeater['is_started']():
        error = spi_wifi_repeater['stop']()
        if error:
            return [error]
        error = spi_wifi_repeater['start']()
        if error:
            return [error]
    return []