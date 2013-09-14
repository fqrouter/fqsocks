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
        dst_host = urlparse.urlparse(path)[1]
        if ':' in dst_host:
            dst_host, dst_port = dst_host.split(':')
            dst_port = int(dst_port)
        else:
            dst_port = 80
        dst_ip = networking.resolve_ips(dst_host)[0]
        client = ProxyClient(downstream_sock, src_ip, src_port, dst_ip, dst_port)
        client.peeked_data = request + payload
        handle_client(client)


def start_server():
    server = gevent.server.StreamServer((LISTEN_IP, LISTEN_PORT), handle)
    LOGGER.info('started fqsocks http gateway at %s:%s' % (LISTEN_IP, LISTEN_PORT))
    try:
        server.serve_forever()
    except:
        LOGGER.exception('failed to start http gateway')
    finally:
        LOGGER.info('http gateway stopped')