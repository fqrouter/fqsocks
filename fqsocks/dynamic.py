import socket
import logging
import random

import gevent
import dpkt
import time
from direct import Proxy
from http_connect import HttpConnectProxy
from goagent import GoAgentProxy


LOGGER = logging.getLogger(__name__)


class DynamicProxy(Proxy):
    def __init__(self, dns_record, type=None, resolve_at='8.8.8.8'):
        self.dns_record = dns_record
        self.type = type
        self.resolve_at = resolve_at
        self.delegated_to = None
        super(DynamicProxy, self).__init__()

    def do_forward(self, client):
        if self.delegated_to:
            self.delegated_to.forward(client)
        else:
            raise NotImplementedError()

    @property
    def died(self):
        if self.delegated_to:
            return self.delegated_to.died
        else:
            return False

    @died.setter
    def died(self, value):
        if self.delegated_to:
            self.delegated_to.died = value
        else:
            pass # ignore

    @classmethod
    def refresh(cls, proxies, create_sock):
        greenlets = []
        for proxy in proxies:
            greenlets.append(gevent.spawn(resolve_proxy, proxy))
        success_count = 0
        deadline = time.time() + 5
        for greenlet in greenlets:
            try:
                timeout = deadline - time.time()
                if timeout > 0:
                    if greenlet.get(timeout=timeout):
                        success_count += 1
                else:
                    if greenlet.get(block=False):
                        success_count += 1
            except:
                pass
        success = success_count > (len(proxies) / 2)
        type_to_proxies = {}
        for proxy in proxies:
            type_to_proxies.setdefault(proxy.delegated_to.__class__, []).append(proxy.delegated_to)
        for proxy_type, instances in type_to_proxies.items():
            success = proxy_type.refresh(instances, create_sock) and success
        return success

    def is_protocol_supported(self, protocol):
        if self.delegated_to:
            return self.delegated_to.is_protocol_supported(protocol)
        else:
            return False

    def __repr__(self):
        return 'DynamicProxy[%s=>%s]' % (self.dns_record, self.delegated_to or 'UNRESOLVED')


def resolve_proxy(proxy):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
        sock.settimeout(3)
        request = dpkt.dns.DNS(
            id=random.randint(1, 65535), qd=[dpkt.dns.DNS.Q(name=proxy.dns_record, type=dpkt.dns.DNS_TXT)])
        sock.sendto(str(request), (proxy.resolve_at, 53))
        connection_info = dpkt.dns.DNS(sock.recv(1024)).an[0].rdata
        connection_info = ''.join(e for e in connection_info if e.isalnum() or e in [':', '.', '-'])
        if 'goagent' == proxy.type:
            proxy.delegated_to = GoAgentProxy(connection_info)
        else:
            proxy_type, ip, port, username, password = connection_info.split(':')
            assert 'http-connect' == proxy_type # only support one type currently
            proxy.delegated_to = HttpConnectProxy(ip, port)
        LOGGER.info('resolved proxy: %s' % repr(proxy))
        return True
    except:
        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.debug('failed to resolve proxy: %s' % repr(proxy), exc_info=1)
        else:
            LOGGER.info('failed to resolve proxy: %s' % repr(proxy))
        return False
