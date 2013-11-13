from . import networking
import logging
import random
import sys
from .proxies.http_try import GOOGLE_SCRAMBLER
from .proxies.http_try import TCP_SCRAMBLER
from .proxies.direct import HTTPS_TRY_PROXY
import gevent

LOGGER = logging.getLogger(__name__)

sub_map = {}

def substitute_ip_if_failed(client, proxy):
    substituted_ip = sub_map.get(client.dst_ip)
    if substituted_ip:
        if is_blacklisted((substituted_ip, client.dst_port)):
            del sub_map[client.dst_ip]
        else:
            LOGGER.info('substitute ip: %s %s => %s' % (client.host, client.dst_ip, substituted_ip))
            client.dst_ip = substituted_ip
    if proxy in client.tried_proxies:
        if substitute_ip(client):
            return proxy # second chance, using different dst ip
        else:
            return None
    else:
        return proxy

def substitute_ip(client):
    if client.ip_substituted:
        return False
    if client.dst_ip in sub_map and sub_map[client.dst_ip] is None:
        return False
    gevent.spawn(fill_sub_map, client.host, client.dst_ip, client.dst_port)
    return False


def fill_sub_map(host, dst_ip, dst_port):
    try:
        sub_host = '%s.sub.fqrouter.com' % '.'.join(reversed(dst_ip.split('.')))
        substituted_ip = resolve_non_blacklisted_ip(sub_host, dst_port)
        if substituted_ip:
            LOGGER.info('resolved hosted sub: %s => %s' % (dst_ip, substituted_ip))
            sub_map[dst_ip] = substituted_ip
            return
        if host:
            sub_map[dst_ip] = resolve_non_blacklisted_ip(host, dst_port)
        else:
            sub_map[dst_ip] = None
    except:
        LOGGER.error('failed to fill host map due to %s' % sys.exc_info()[1])


def resolve_non_blacklisted_ip(host, dst_port):
    ips = networking.resolve_ips(host)
    if not ips:
        return None
    ips = [ip for ip in ips if not is_blacklisted((ip, dst_port))]
    if not ips:
        return None
    return random.choice(ips)


def is_blacklisted(dst):
    if dst in GOOGLE_SCRAMBLER.dst_black_list:
        return True
    if dst in TCP_SCRAMBLER.dst_black_list:
        return True
    if dst in HTTPS_TRY_PROXY.dst_black_list:
        return True
    return False