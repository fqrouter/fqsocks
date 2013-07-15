import paramiko
from direct import Proxy
import socket
import logging
import sys
import os
import networking

LOGGER = logging.getLogger(__name__)


class SshProxy(Proxy):
    def __init__(self, proxy_ip, proxy_port=22, username=None, password=None, key_filename=None):
        super(SshProxy, self).__init__()
        self.proxy_ip = proxy_ip
        self.proxy_port = int(proxy_port)
        self.username = username
        self.password = password
        self.key_filename = key_filename
        self.ssh_client = None

    def connect(self):
        try:
            self.close()
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.load_system_host_keys()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            sock = networking.create_tcp_socket(socket.gethostbyname(self.proxy_ip), self.proxy_port, 3)
            self.key_filename = self.key_filename or '/data/data/fq.router2/etc/ssh/%s' % self.proxy_ip
            if not os.path.exists(self.key_filename):
                self.key_filename = None
            self.ssh_client.connect(
                self.proxy_ip, self.proxy_port,
                username=self.username, password=self.password,
                key_filename=self.key_filename,
                sock=sock)
        except:
            LOGGER.exception('failed to connect ssh proxy: %s' % self)
            self.died = True

    def close(self):
        if self.ssh_client:
            self.ssh_client.close()

    def do_forward(self, client):
        try:
            try:
                upstream_socket = self.open_channel(client)
            except:
                LOGGER.info('[%s] failed to open channel: %s' % (repr(client), sys.exc_info()[1]))
                self.connect()
                upstream_socket = self.open_channel(client)
            LOGGER.info('[%s] channel opened: %s' % (repr(client), upstream_socket))
            client.add_resource(upstream_socket)
            upstream_socket.sendall(client.peeked_data)
        except:
            LOGGER.exception('[%s] ssh proxy failed' % repr(client))
            self.died = True
            return
        client.forward(upstream_socket)

    def open_channel(self, client):
        return self.ssh_client.get_transport().open_channel(
            'direct-tcpip', (client.dst_ip, client.dst_port), (client.src_ip, client.src_port))

    @classmethod
    def refresh(cls, proxies):
        for proxy in proxies:
            proxy.connect()
        return True

    def is_protocol_supported(self, protocol):
        return True

    def __repr__(self):
        return 'SshProxy[%s:%s]' % (self.proxy_ip, self.proxy_port)