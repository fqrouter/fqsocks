import logging
import gevent.server
from .. import networking
from .proxy_client import ProxyClient
from .proxy_client import handle_client
from ..proxies.http_try import recv_till_double_newline
from ..proxies.http_try import parse_request
import urlparse
import os
import jinja2
from .. import httpd
import httplib


LOGGER = logging.getLogger(__name__)
LISTEN_IP = None
LISTEN_PORT = None
dns_cache = {}


def handle(downstream_sock, address):
    src_ip, src_port = address
    request, payload = recv_till_double_newline('', downstream_sock)
    if not request:
        return
    method, path, headers = parse_request(request)
    if 'CONNECT' == method.upper():
        dst_host, dst_port = path.split(':')
        dst_port = int(dst_port)
        dst_ip = resolve_ip(dst_host)
        if not dst_ip:
            return
        downstream_sock.sendall('HTTP/1.1 200 OK\r\n\r\n')
        client = ProxyClient(downstream_sock, src_ip, src_port, dst_ip, dst_port)
        handle_client(client)
    else:
        dst_host = urlparse.urlparse(path)[1]
        if ':' in dst_host:
            dst_host, dst_port = dst_host.split(':')
            dst_port = int(dst_port)
        else:
            dst_port = 80
        dst_ip = resolve_ip(dst_host)
        if not dst_ip:
            return
        client = ProxyClient(downstream_sock, src_ip, src_port, dst_ip, dst_port)
        request_lines = ['%s %s HTTP/1.1\r\n' % (method, path[path.find(dst_host) + len(dst_host):])]
        headers.pop('Proxy-Connection', None)
        headers['Host'] = dst_host
        headers['Connection'] = 'close'
        for key, value in headers.items():
            request_lines.append('%s: %s\r\n' % (key, value))
        request = ''.join(request_lines)
        client.peeked_data = request + '\r\n' + payload
        handle_client(client)


def resolve_ip(host):
    if host in dns_cache:
        return dns_cache[host]
    ips = networking.resolve_ips(host)
    if ips:
        ip = ips[0]
    else:
        ip = None
    dns_cache[host] = ip
    return dns_cache[host]


def start_server():
    server = gevent.server.StreamServer((LISTEN_IP, LISTEN_PORT), handle)
    LOGGER.info('started fqsocks http gateway at %s:%s' % (LISTEN_IP, LISTEN_PORT))
    try:
        server.serve_forever()
    except:
        LOGGER.exception('failed to start http gateway')
    finally:
        LOGGER.info('http gateway stopped')

