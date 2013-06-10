import logging

LOGGER = logging.getLogger(__name__)


class Proxy(object):
    def __init__(self):
        super(Proxy, self).__init__()
        self.died = False
        self.flags = set()
        self.priority = 0

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
    def refresh(cls, proxies, create_udp_socket, create_tcp_socket):
        return True

    def is_protocol_supported(self, protocol):
        return False

    def __eq__(self, other):
        return repr(self) == repr(other)

    def __hash__(self):
        return hash(repr(self))


class DirectProxy(Proxy):
    DEFAULT_CONNECT_TIMEOUT = 5

    def __init__(self, connect_timeout=DEFAULT_CONNECT_TIMEOUT):
        super(DirectProxy, self).__init__()
        self.flags.add('DIRECT')
        self.connect_timeout = connect_timeout

    def do_forward(self, client):
        try:
            upstream_sock = client.create_tcp_socket(client.dst_ip, client.dst_port, self.connect_timeout)
        except:
            if LOGGER.isEnabledFor(logging.DEBUG):
                LOGGER.debug('[%s] direct connect upstream socket timed out' % (repr(client)), exc_info=1)
            client.direct_connection_failed()
            client.fall_back(reason='direct connect upstream socket timed out')
            return
        client.direct_connection_succeeded()
        upstream_sock.settimeout(None)
        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.debug('[%s] direct upstream connected' % repr(client))
        upstream_sock.sendall(client.peeked_data)
        client.forward(upstream_sock)

    def is_protocol_supported(self, protocol):
        return True

    def __repr__(self):
        if self.connect_timeout != self.DEFAULT_CONNECT_TIMEOUT:
            return 'DirectProxy[connect_timeout=%s]' % self.connect_timeout
        else:
            return 'DirectProxy'


class NoneProxy(Proxy):
    def do_forward(self, client):
        return

    def is_protocol_supported(self, protocol):
        return True

    def __repr__(self):
        return 'NoneProxy'


DIRECT_PROXY = DirectProxy()
NONE_PROXY = NoneProxy()
HTTPS_TRY_PROXY = DirectProxy(connect_timeout=2)