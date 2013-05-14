import logging

LOGGER = logging.getLogger(__name__)


class Proxy(object):
    def __init__(self):
        super(Proxy, self).__init__()
        self.died = False

    def forward(self, client):
        raise NotImplementedError()

    @classmethod
    def refresh(cls, proxies, create_sock):
        raise NotImplementedError()


class DirectProxy(Proxy):
    def forward(self, client):
        upstream_sock = client.create_upstream_sock()
        upstream_sock.connect((client.dst_ip, client.dst_port))
        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.debug('[%s] upstream connected' % repr(client))
        upstream_sock.sendall(client.peeked_data)
        client.forward(upstream_sock)

    @classmethod
    def refresh(cls, proxies, create_sock):
        return proxies

    def __repr__(self):
        return 'DirectProxy'


DIRECT_PROXY = DirectProxy()