import logging

LOGGER = logging.getLogger(__name__)


class DirectProxy(object):
    def forward(self, client):
        upstream_sock = client.create_upstream_sock()
        upstream_sock.connect((client.dst_ip, client.dst_port))
        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.debug('[%s] upstream connected' % repr(client))
        upstream_sock.sendall(client.peeked_data)
        client.forward(upstream_sock)

    def __repr__(self):
        return 'DirectProxy'


DIRECT_PROXY = DirectProxy()
DIRECT_PROXY.died = False