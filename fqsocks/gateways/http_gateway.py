import logging
import gevent.server
from .. import networking
from .proxy_client import ProxyClient
from .proxy_client import handle_client
from .proxy_client import NoMoreProxy
from ..proxies.http_try import recv_till_double_newline
from ..proxies.http_try import parse_request
import urlparse
import sys
import os
import jinja2
from ..web_ui import get_ip_of_interface
from ..web_ui import get_default_interface
from .. import httpd
import httplib


WHITELIST_PAC_FILE = os.path.join(os.path.dirname(__file__), '..', 'templates', 'whitelist.pac')
LOGGER = logging.getLogger(__name__)
LISTEN_IP = None
LISTEN_PORT = None


def handle(downstream_sock, address):
    src_ip, src_port = address
    request, payload = recv_till_double_newline('', downstream_sock)
    if not request:
        return
    method, path, headers = parse_request(request)
    if 'CONNECT' == method.upper():
        dst_host, dst_port = path.split(':')
        dst_port = int(dst_port)
        dst_ip = networking.resolve_ips(dst_host)[0]
        downstream_sock.sendall('HTTP/1.1 200 OK\r\n\r\n')
        client = ProxyClient(downstream_sock, src_ip, src_port, dst_ip, dst_port)
        handle_client(client)
    else:
        dst_host, rel_path = urlparse.urlparse(path)[1:3]
        if ':' in dst_host:
            dst_host, dst_port = dst_host.split(':')
            dst_port = int(dst_port)
        else:
            dst_port = 80
        dst_ip = networking.resolve_ips(dst_host)[0]
        client = ProxyClient(downstream_sock, src_ip, src_port, dst_ip, dst_port)
        request_lines = ['%s %s HTTP/1.1\r\n' % (method, rel_path)]
        headers.pop('Proxy-Connection', None)
        headers['Host'] = dst_host
        for key, value in headers.items():
            request_lines.append('%s: %s\r\n' % (key, value))
        request = ''.join(request_lines)
        client.peeked_data = request + '\r\n' + payload
        handle_client(client)


def get_pac(environ, start_response):
    with open(WHITELIST_PAC_FILE) as f:
        template = jinja2.Template(unicode(f.read(), 'utf8'))
    ip = get_ip_of_interface(get_default_interface())
    start_response(httplib.OK, [('Content-Type', 'application/x-ns-proxy-autoconfig')])
    return [template.render(http_gateway='%s:2516' % ip).encode('utf8')]

httpd.HANDLERS[('GET', 'pac')] = get_pac

def start_server():
    server = gevent.server.StreamServer((LISTEN_IP, LISTEN_PORT), handle)
    LOGGER.info('started fqsocks http gateway at %s:%s' % (LISTEN_IP, LISTEN_PORT))
    try:
        server.serve_forever()
    except:
        LOGGER.exception('failed to start http gateway')
    finally:
        LOGGER.info('http gateway stopped')

