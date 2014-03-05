from . import networking
import logging
import random
import sys
import gevent

LOGGER = logging.getLogger(__name__)

sub_map = {}
sub_lock = set()

def substitute_ip(client, dst_black_list):
    if client.dst_ip in sub_map and sub_map[client.dst_ip] is None:
        return False
    substituted_ip = sub_map.get(client.dst_ip)
    if substituted_ip:
        if (substituted_ip, client.dst_port) in dst_black_list:
            del sub_map[client.dst_ip]
        else:
            LOGGER.info('[%s] substitute ip: %s %s => %s' % (client, client.host, client.dst_ip, substituted_ip))
            client.dst_ip = substituted_ip
            return True
    gevent.spawn(fill_sub_map, client.host, client.dst_ip, client.dst_port, dst_black_list)
    return False


def fill_sub_map(host, dst_ip, dst_port, dst_black_list):
    if host in sub_lock:
        return
    sub_lock.add(host)
    try:
        # sub_host = '%s.sub.fqrouter.com' % '.'.join(reversed(dst_ip.split('.')))
        # substituted_ip = resolve_non_blacklisted_ip(sub_host, dst_ip, dst_port, dst_black_list)
        # if substituted_ip:
        #     LOGGER.info('resolved hosted sub: %s => %s' % (dst_ip, substituted_ip))
        #     sub_map[dst_ip] = substituted_ip
        #     return
        if host:
            sub_map[dst_ip] = resolve_non_blacklisted_ip(host, dst_ip, dst_port, dst_black_list)
        else:
            sub_map[dst_ip] = None
    except:
        LOGGER.error('failed to fill host map due to %s' % sys.exc_info()[1])
    finally:
        sub_lock.remove(host)


def resolve_non_blacklisted_ip(host, dst_ip, dst_port, dst_black_list):
    ips = networking.resolve_ips(host)
    if not ips:
        return None
    ips = [ip for ip in ips if dst_ip != ip and not (ip, dst_port) in dst_black_list]
    if not ips:
        return None
    return random.choice(ips)


def is_blacklisted(dst, dst_black_list):
    return dst in dst_black_list