import logging
import socket

LOGGER = logging.getLogger(__name__)
SO_MARK = 36


class Proxy(object):
    def __init__(self):
        super(Proxy, self).__init__()
        self.died = False
        self.flags = set()

    def forward(self, client):
        client.forwarding_by = self
        try:
            self.do_forward(client)
        finally:
            if self.died:
                LOGGER.fatal('[%s] !!! proxy died !!!: %s' % (repr(client), self))
                client.dump_proxies()

    def do_forward(self, client):
        raise NotImplementedError()

    @classmethod
    def refresh(cls, proxies, create_sock):
        return True

    def is_protocol_supported(self, protocol):
        return False


class DirectProxy(Proxy):
    def __init__(self, mark=None):
        super(DirectProxy, self).__init__()
        self.flags.add('DIRECT')
        self.mark = mark

    def do_forward(self, client):
        upstream_sock = client.create_upstream_sock()
        if self.mark:
            upstream_sock.setsockopt(socket.SOL_SOCKET, SO_MARK, self.mark)
        upstream_sock.settimeout(5)
        try:
            upstream_sock.connect((client.dst_ip, client.dst_port))
        except:
            if LOGGER.isEnabledFor(logging.DEBUG):
                LOGGER.debug('[%s] direct connect upstream socket timed out' % (repr(client)), exc_info=1)
            client.direct_connection_failed()
            client.fall_back(reason='direct connect upstream socket timed out')
        client.direct_connection_succeeded()
        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.debug('[%s] direct upstream connected' % repr(client))
        upstream_sock.sendall(client.peeked_data)
        client.forward(upstream_sock)

    def is_protocol_supported(self, protocol):
        return True

    def __repr__(self):
        return 'DirectProxy'


DIRECT_PROXY = DirectProxy()