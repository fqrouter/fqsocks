import logging
import random
import time
import sys
import contextlib

import gevent
import dpkt

from .direct import Proxy
from .http_connect import HttpConnectProxy
from .goagent import GoAgentProxy
from .shadowsocks import ShadowSocksProxy
from .. import networking


LOGGER = logging.getLogger(__name__)


class DynamicProxy(Proxy):

    def __init__(self, dns_record, type=None, priority=0, **kwargs):
        self.dns_record = dns_record
        self.type = type
        self.delegated_to = None
        self.kwargs = {k: False if 'False' == v else v for k, v in kwargs.items()}
        super(DynamicProxy, self).__init__()
        self.priority = int(priority)

    def do_forward(self, client):
        if self.delegated_to:
            self.delegated_to.forward(client)
        else:
            raise NotImplementedError()

    def clear_latency_records(self):
        if self.delegated_to:
            self.delegated_to.clear_latency_records()


    def clear_failed_times(self):
        if self.delegated_to:
            self.delegated_to.clear_failed_times()


    @property
    def latency(self):
        if self.delegated_to:
            return self.delegated_to.latency
        else:
            return 0

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

    @property
    def flags(self):
        if self.delegated_to:
            return self.delegated_to.flags
        else:
            return ()

    @flags.setter
    def flags(self, value):
        if self.delegated_to:
            self.delegated_to.flags = value
        else:
            pass

    @classmethod
    def refresh(cls, proxies):
        greenlets = []
        for proxy in proxies:
            gevent.sleep(0.1)
            greenlets.append(gevent.spawn(resolve_proxy, proxy))
        success_count = 0
        deadline = time.time() + 30
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
        LOGGER.info('resolved proxies: %s/%s' % (success_count, len(proxies)))
        success = success_count > (len(proxies) / 2)
        type_to_proxies = {}
        for proxy in proxies:
            if proxy.delegated_to:
                type_to_proxies.setdefault(proxy.delegated_to.__class__, []).append(proxy.delegated_to)
        for proxy_type, instances in type_to_proxies.items():
            try:
                success = proxy_type.refresh(instances) and success
            except:
                LOGGER.exception('failed to refresh proxies %s' % instances)
                success = False
        return success

    def is_protocol_supported(self, protocol, client=None):
        if self.delegated_to:
            return self.delegated_to.is_protocol_supported(protocol, client)
        else:
            return False

    def __eq__(self, other):
        if hasattr(other, 'dns_record'):
            return self.dns_record == other.dns_record
        else:
            return False

    def __hash__(self):
        return hash(self.dns_record)

    def __repr__(self):
        return 'DynamicProxy[%s=>%s]' % (self.dns_record, self.delegated_to or 'UNRESOLVED')

    @property
    def public_name(self):
        if 'GoAgentProxy' == self.delegated_to.__class__.__name__:
            return 'GoAgent\tPublic #%s' % self.dns_record.replace('.fqrouter.com', '').replace('goagent', '')
        elif 'ShadowSocksProxy' == self.delegated_to.__class__.__name__:
            return 'SS\tPublic #%s' % self.dns_record.replace('.fqrouter.com', '').replace('ss', '')
        elif 'HttpConnectProxy' == self.delegated_to.__class__.__name__:
            return 'HTTP\tPublic #%s' % self.dns_record.replace('.fqrouter.com', '').replace('proxy', '')
        else:
            return None # ignore


def resolve_proxy(proxy):
    for i in range(3):
        try:
            sock = networking.create_udp_socket()
            with contextlib.closing(sock):
                sock.settimeout(10)
                request = dpkt.dns.DNS(
                    id=random.randint(1, 65535), qd=[dpkt.dns.DNS.Q(name=proxy.dns_record, type=dpkt.dns.DNS_TXT)])
                sock.sendto(str(request), ('8.8.8.8', 53))
                gevent.sleep(0.1)
                connection_info = dpkt.dns.DNS(sock.recv(1024)).an[0].text[0]
                if not connection_info:
                    LOGGER.info('resolved empty proxy: %s' % repr(proxy))
                    return False
                if 'goagent' == proxy.type:
                    proxy.delegated_to = GoAgentProxy(connection_info, **proxy.kwargs)
                    proxy.delegated_to.resolved_by_dynamic_proxy = proxy
                elif 'ss' == proxy.type:
                    ip, port, password, encrypt_method = connection_info.split(':')
                    proxy.delegated_to = ShadowSocksProxy(ip, port, password, encrypt_method)
                    proxy.delegated_to.resolved_by_dynamic_proxy = proxy
                else:
                    proxy_type, ip, port, username, password = connection_info.split(':')
                    assert 'http-connect' == proxy_type # only support one type currently
                    proxy.delegated_to = HttpConnectProxy(ip, port, username, password, **proxy.kwargs)
                    proxy.delegated_to.resolved_by_dynamic_proxy = proxy
                LOGGER.info('resolved proxy: %s' % repr(proxy))
                return True
        except:
            if LOGGER.isEnabledFor(logging.DEBUG):
                LOGGER.debug('failed to resolve proxy: %s' % repr(proxy), exc_info=1)
            else:
                LOGGER.info('failed to resolve proxy: %s %s' % (repr(proxy), sys.exc_info()[1]))
        gevent.sleep(1)
    LOGGER.error('give up resolving proxy: %s' % repr(proxy))
    return False

