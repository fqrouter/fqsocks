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

import gevent.server
import gevent.monkey


LOGGER = logging.getLogger(__name__)
SO_ORIGINAL_DST = 80


class ProxyClient(object):
    def __init__(self, downstream_sock, src_ip, src_port, dst_ip, dst_port):
        super(ProxyClient, self).__init__()
        self.downstream_sock = downstream_sock
        self.upstream_sock = None
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port

    def set_upstream(self, upstream_sock):
        self.upstream_sock = upstream_sock

    def forward(self):
        forward_socket(self.downstream_sock, self.upstream_sock)

    def __repr__(self):
        return '%s:%s => %s:%s' % (self.src_ip, self.src_port, self.dst_ip, self.dst_port)


def handle(downstream_sock, address):
    dst = downstream_sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    dst_port, dst_ip = struct.unpack("!2xH4s8x", dst)
    dst_ip = socket.inet_ntoa(dst_ip)
    client = ProxyClient(downstream_sock, address[0], address[1], dst_ip, dst_port)
    LOGGER.debug('downstream connected %s' % repr(client))
    proxy_via_direct(client)


def proxy_via_direct(client):
    upstream_sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
    upstream_sock.bind(('10.1.2.3', 0))
    upstream_sock.connect((client.dst_ip, client.dst_port))
    LOGGER.debug('direct upstream connected: %s' % repr(client))
    try:
        forward_socket(client.downstream_sock, upstream_sock)
        LOGGER.debug('done without error: %s' % repr(client))
    except:
        LOGGER.debug('done with error %s: %s' % (sys.exc_info()[1], repr(client)))


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
    finally:
        try:
            if local:
                local.close()
        finally:
            if remote:
                remote.close()


def on_exit(signum, frame):
    if signal.SIG_DFL == signal.signal(signum, signal.SIG_DFL):
        return
    subprocess.check_call(
        'iptables -t nat -D OUTPUT -p tcp ! -s 10.1.2.3 -j DNAT --to-destination 10.1.2.3:1234', shell=True)


signal.signal(signal.SIGTERM, on_exit)
signal.signal(signal.SIGINT, on_exit)

if '__main__' == __name__:
    gevent.monkey.patch_all()
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s')
    ip = '10.1.2.3'
    port = 1234
    server = gevent.server.StreamServer((ip, port), handle)
    LOGGER.info('started fqsocks at %s:%s' % (ip, port))
    subprocess.check_call(
        'iptables -t nat -I OUTPUT -p tcp ! -s 10.1.2.3 -j DNAT --to-destination 10.1.2.3:1234', shell=True)
    server.serve_forever()
    subprocess.check_call(
        'iptables -t nat -D OUTPUT -p tcp ! -s 10.1.2.3 -j DNAT --to-destination 10.1.2.3:1234', shell=True)