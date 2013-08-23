import paramiko
from direct import Proxy
import socket
import logging
import sys
import os
import networking
import stat
import gevent
import gevent.event

LOGGER = logging.getLogger(__name__)


class SshProxy(Proxy):
    def __init__(self, proxy_host, proxy_port=22, username=None, password=None, key_filename=None):
        super(SshProxy, self).__init__()
        self.proxy_host = proxy_host
        if not self.proxy_host:
            self.died = True
        self.proxy_port = int(proxy_port)
        self.username = username
        self.password = password
        self.key_filename = key_filename
        self.ssh_client = None
        self.connection_failed = gevent.event.Event()
        self.failed_times = 0

    def connect(self):
        try:
            self.close()
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.load_system_host_keys()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            sock = networking.create_tcp_socket(self.proxy_ip, self.proxy_port, 3)
            self.key_filename = self.key_filename or '/data/data/fq.router2/etc/ssh/%s' % self.proxy_host
            if not os.path.exists(self.key_filename):
                self.key_filename = None
            self.ssh_client.connect(
                self.proxy_ip, self.proxy_port,
                username=self.username, password=self.password,
                key_filename=self.key_filename,
                sock=sock)
            self.reconnected = True
        except:
            LOGGER.exception('failed to connect ssh proxy: %s' % self)
            self.died = True

    def guard(self):
        while not self.died:
            self.connection_failed.wait()
            if self.failed_times >= 3:
                LOGGER.error('failed too many times')
                self.died = True
                break
            self.failed_times += 1
            self.connect()
            self.connection_failed.clear()
        LOGGER.critical('!!! %s gurad loop exit !!!' % self)

    def close(self):
        if self.ssh_client:
            self.ssh_client.close()

    def do_forward(self, client):
        try:
            upstream_socket = self.open_channel(client)
        except:
            LOGGER.info('[%s] failed to open channel: %s' % (repr(client), sys.exc_info()[1]))
            gevent.sleep(1)
            self.connection_failed.set()
            client.fall_back(reason='ssh open channel failed')
        upstream_socket.counter = stat.opened(self, client.host, client.dst_ip)
        LOGGER.info('[%s] channel opened: %s' % (repr(client), upstream_socket))
        client.add_resource(upstream_socket)
        upstream_socket.sendall(client.peeked_data)
        client.forward(upstream_socket)
        self.failed_times = 0

    def open_channel(self, client):
        return self.ssh_client.get_transport().open_channel(
            'direct-tcpip', (client.dst_ip, client.dst_port), (client.src_ip, client.src_port))

    @classmethod
    def refresh(cls, proxies):
        for proxy in proxies:
            proxy.connection_failed.set()
            gevent.spawn(proxy.guard)
        return True

    def is_protocol_supported(self, protocol):
        return True

    def __repr__(self):
        return 'SshProxy[%s:%s]' % (self.proxy_host, self.proxy_port)

    @property
    def public_name(self):
        return 'SSH\t%s' % self.proxy_host