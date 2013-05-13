#!/usr/bin/env python
# thanks @phuslu https://github.com/phus/sniproxy/blob/master/sniproxy.py
# thanks @ofmax https://github.com/madeye/gaeproxy/blob/master/assets/modules/python.mp3
import logging
import sys
import struct
import socket
import errno
import select
import signal
import subprocess
import atexit

import gevent.server
import gevent.monkey
from http_connect import HttpConnectProxy


LOGGER = logging.getLogger(__name__)
SO_ORIGINAL_DST = 80


class ProxyClient(object):
    def __init__(self, downstream_sock, upstream_sock, src_ip, src_port, dst_ip, dst_port):
        super(ProxyClient, self).__init__()
        self.downstream_sock = downstream_sock
        self.upstream_sock = upstream_sock
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.description = '%s:%s => %s:%s' % (self.src_ip, self.src_port, self.dst_ip, self.dst_port)

    def close(self):
        try:
            self.downstream_sock.close()
        finally:
            self.upstream_sock.close()

    def forward(self):
        forward_socket(self.downstream_sock, self.upstream_sock)

    def __repr__(self):
        return self.description


def handle(downstream_sock, address):
    dst = downstream_sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    dst_port, dst_ip = struct.unpack("!2xH4s8x", dst)
    dst_ip = socket.inet_ntoa(dst_ip)
    upstream_sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
    upstream_sock.bind(('10.1.2.3', 0))
    client = ProxyClient(downstream_sock, upstream_sock, address[0], address[1], dst_ip, dst_port)
    try:
        LOGGER.debug('downstream connected %s' % repr(client))
        if not HttpConnectProxy('175.143.35.140', 8080).connect_upstream(client):
            LOGGER.debug('upstream connect failed: %s' % repr(client))
            return
        LOGGER.debug('upstream connected: %s' % repr(client))
        try:
            client.forward()
            LOGGER.debug('done: %s' % repr(client))
        except:
            LOGGER.debug('done with error %s: %s' % (sys.exc_info()[1], repr(client)))
    finally:
        client.close()


def forward_socket(local, remote, timeout=60, tick=2, bufsize=8192, maxping=None, maxpong=None):
    try:
        timecount = timeout
        while 1:
            timecount -= tick
            if timecount <= 0:
                break
            (ins, _, errors) = select.select([local, remote], [], [local, remote], tick)
            if errors:
                break
            if ins:
                for sock in ins:
                    data = sock.recv(bufsize)
                    if data:
                        if sock is remote:
                            local.sendall(data)
                            timecount = maxpong or timeout
                        else:
                            remote.sendall(data)
                            timecount = maxping or timeout
                    else:
                        return
    except socket.error as e:
        if e[0] not in (10053, 10054, 10057, errno.EPIPE):
            raise


def on_exit(signum, frame):
    if signal.SIG_DFL == signal.signal(signum, signal.SIG_DFL):
        return
    delete_iptables_rule()


def delete_iptables_rule():
    subprocess.check_call(
        'iptables -t nat -D OUTPUT -p tcp ! -s 10.1.2.3 -j DNAT --to-destination 10.1.2.3:1234', shell=True)


if '__main__' == __name__:
    signal.signal(signal.SIGTERM, on_exit)
    signal.signal(signal.SIGINT, on_exit)
    atexit.register(delete_iptables_rule)
    gevent.monkey.patch_all()
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s')
    ip = '10.1.2.3'
    port = 1234
    server = gevent.server.StreamServer((ip, port), handle)
    LOGGER.info('started fqsocks at %s:%s' % (ip, port))
    subprocess.check_call(
        'iptables -t nat -I OUTPUT -p tcp ! -s 10.1.2.3 -j DNAT --to-destination 10.1.2.3:1234', shell=True)
    try:
        server.serve_forever()
    finally:
        delete_iptables_rule()