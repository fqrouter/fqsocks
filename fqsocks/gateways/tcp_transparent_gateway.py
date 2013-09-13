import logging
import gevent.server
from .. import networking
from .proxy_client import ProxyClient
from .proxy_client import pick_proxy_and_forward
from .proxy_client import NoMoreProxy
import sys

LOGGER = logging.getLogger(__name__)
LISTEN_IP = None
LISTEN_PORT = None


def handle(downstream_sock, address):
    src_ip, src_port = address
    try:
        dst_ip, dst_port = networking.get_original_destination(downstream_sock, src_ip, src_port)
        client = ProxyClient(downstream_sock, src_ip, src_port, dst_ip, dst_port)
        try:
            if LOGGER.isEnabledFor(logging.DEBUG):
                LOGGER.debug('[%s] downstream connected' % repr(client))
            pick_proxy_and_forward(client)
            if LOGGER.isEnabledFor(logging.DEBUG):
                LOGGER.debug('[%s] done' % repr(client))
        except NoMoreProxy:
            return
        except:
            if LOGGER.isEnabledFor(logging.DEBUG):
                LOGGER.debug('[%s] done with error' % repr(client), exc_info=1)
            else:
                LOGGER.info('[%s] done with error: %s' % (repr(client), sys.exc_info()[1]))
        finally:
            client.close()
    except:
        LOGGER.exception('failed to handle %s:%s' % (src_ip, src_port))


def start_server():
    server = gevent.server.StreamServer((LISTEN_IP, LISTEN_PORT), handle)
    LOGGER.info('started fqsocks at %s:%s' % (LISTEN_IP, LISTEN_PORT))
    try:
        server.serve_forever()
    except:
        LOGGER.exception('failed to start server')
    finally:
        LOGGER.info('server stopped')