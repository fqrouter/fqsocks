import socket
import time
import logging
import sys

import gevent

from .http_try import HttpTryProxy
from .. import networking
from .. import stat


LOGGER = logging.getLogger(__name__)


class TcpSmuggler(HttpTryProxy):
    def __init__(self):
        super(TcpSmuggler, self).__init__()
        self.died = True
        self.is_trying = False

    def try_start_if_network_is_ok(self):
        if self.is_trying:
            return
        self.died = True
        self.is_trying = True
        gevent.spawn(self._try_start)

    def _try_start(self):
        try:
            LOGGER.info('will try start tcp smuggler in 30 seconds')
            gevent.sleep(5)
            LOGGER.info('try tcp smuggler')
            create_smuggled_sock('8.8.8.8', 53)
            LOGGER.info('tcp smuggler is working')
            self.died = False
        except:
            LOGGER.info('tcp smuggler is not working: %s' % sys.exc_info()[0])
        finally:
            self.is_trying = False

    def create_upstream_sock(self, client):
        upstream_sock = create_smuggled_sock(client.dst_ip, client.dst_port)
        upstream_sock.history = [client.src_port]
        upstream_sock.counter = stat.opened(upstream_sock, client.forwarding_by, client.host, client.dst_ip)
        client.add_resource(upstream_sock)
        client.add_resource(upstream_sock.counter)
        return upstream_sock

    def before_send_request(self, client, upstream_sock, is_payload_complete):
        upstream_sock.setsockopt(socket.SOL_SOCKET, networking.SO_MARK, 0xfeee)
        return ''

    def process_response(self, client, upstream_sock, response, http_response):
        upstream_sock.setsockopt(socket.SOL_SOCKET, networking.SO_MARK, 0)
        return super(TcpSmuggler, self).process_response(client, upstream_sock, response, http_response)

    def __repr__(self):
        return 'TcpSmuggler'


TCP_SMUGGLER = TcpSmuggler()


def create_smuggled_sock(ip, port):
    upstream_sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
    if networking.OUTBOUND_IP:
        upstream_sock.bind((networking.OUTBOUND_IP, 0))
    upstream_sock.setsockopt(socket.SOL_SOCKET, networking.SO_MARK, 0xfeee)
    upstream_sock.settimeout(3)
    try:
        upstream_sock.connect((ip, port))
    except:
        upstream_sock.close()
        raise
    upstream_sock.last_used_at = time.time()
    upstream_sock.settimeout(None)
    return upstream_sock