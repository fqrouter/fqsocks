import logging
from .. import networking

LOGGER = logging.getLogger(__name__)


class Proxy(object):
    def __init__(self):
        super(Proxy, self).__init__()
        self.died = False
        self.flags = set()
        self.priority = 0
        self._proxy_ip = None
        self.latency_records_total = 0
        self.latency_records_count = 0
        self.failed_times = 0

    def increase_failed_time(self):
        LOGGER.error('failed once/%s: %s' % (self.failed_times, self))
        self.failed_times += 1
        if self.failed_times > 3:
            self.died = True
            LOGGER.fatal('!!! proxy died !!!: %s' % self)

    def record_latency(self, latency):
        self.latency_records_total += latency
        self.latency_records_count += 1
        if self.latency_records_count > 100:
            self.latency_records_total = self.latency
            self.latency_records_count = 1

    def clear_latency_records(self):
        self.latency_records_total = 0
        self.latency_records_count = 0

    def clear_failed_times(self):
        self.failed_times = 0

    @property
    def latency(self):
        if self.latency_records_count:
            return self.latency_records_total / self.latency_records_count
        else:
            return 0

    @property
    def proxy_ip(self):
        if self._proxy_ip:
            return self._proxy_ip
        ips = networking.resolve_ips(self.proxy_host)
        if not ips:
            LOGGER.critical('!!! failed to resolve proxy ip: %s' % self.proxy_host)
            self._proxy_ip = '0.0.0.0'
            self.died = True
            return self._proxy_ip
        self._proxy_ip = ips[0]
        return self._proxy_ip

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
    def refresh(cls, proxies):
        return True

    def is_protocol_supported(self, protocol):
        return False

    def __eq__(self, other):
        return repr(self) == repr(other)

    def __hash__(self):
        return hash(repr(self))

    @property
    def public_name(self):
        return None


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
            client.fall_back(reason='direct connect upstream socket timed out')
            return
        upstream_sock.settimeout(None)
        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.debug('[%s] direct upstream connected' % repr(client))
        upstream_sock.counter.sending(len(client.peeked_data))
        upstream_sock.sendall(client.peeked_data)
        client.forward(upstream_sock)

    def is_protocol_supported(self, protocol):
        return True

    def __repr__(self):
        return 'DirectProxy'


class GenericTryProxy(DirectProxy):
    def __init__(self):
        super(GenericTryProxy, self).__init__(2)
        self.dst_black_list = {}

    def do_forward(self, client):
        dst = (client.dst_ip, client.dst_port)
        try:
            failed_count = self.dst_black_list.get(dst, 0)
            if failed_count and (failed_count % 10) != 0:
                client.fall_back('%s:%s tried before' % (client.dst_ip, client.dst_port), silently=True)
            super(GenericTryProxy, self).do_forward(client)
            if dst in self.dst_black_list:
                LOGGER.error('removed dst %s:%s from blacklist' % dst)
                del self.dst_black_list[dst]
        except:
            if dst not in self.dst_black_list:
                LOGGER.error('blacklist dst %s:%s' % dst)
            self.dst_black_list[dst] = self.dst_black_list.get(dst, 0) + 1
            raise

    def __repr__(self):
        return 'GenericTryProxy'


class NoneProxy(Proxy):
    def do_forward(self, client):
        return

    def is_protocol_supported(self, protocol):
        return True

    def __repr__(self):
        return 'NoneProxy'


DIRECT_PROXY = DirectProxy()
NONE_PROXY = NoneProxy()
HTTPS_TRY_PROXY = GenericTryProxy()