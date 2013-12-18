import socket
import struct
import logging
import time
import functools

from .direct import Proxy
from . import encrypt


LOGGER = logging.getLogger(__name__)


class ShadowSocksProxy(Proxy):
    def __init__(self, proxy_host, proxy_port, password, encrypt_method, supported_protocol=None, **ignore):
        super(ShadowSocksProxy, self).__init__()
        self.proxy_host = proxy_host
        if not self.proxy_host:
            self.died = True
        self.proxy_port = int(proxy_port)
        self.password = password
        self.encrypt_method = encrypt_method
        self.supported_protocol = supported_protocol

    def do_forward(self, client):
        encryptor = encrypt.Encryptor(self.password, self.encrypt_method)
        addr_to_send = '\x01'
        addr_to_send += socket.inet_aton(client.dst_ip)
        addr_to_send += struct.pack('>H', client.dst_port)
        begin_at = time.time()
        try:
            upstream_sock = client.create_tcp_socket(self.proxy_ip, self.proxy_port, 5)
        except:
            client.fall_back(reason='can not connect to proxy', delayed_penalty=self.increase_failed_time)
        encrypted_addr = encryptor.encrypt(addr_to_send)
        upstream_sock.counter.sending(len(encrypted_addr))
        upstream_sock.sendall(encrypted_addr)
        encrypted_peeked_data = encryptor.encrypt(client.peeked_data)
        upstream_sock.counter.sending(len(encrypted_peeked_data))
        upstream_sock.sendall(encrypted_peeked_data)
        client.forward(
            upstream_sock, timeout=10,
            encrypt=encryptor.encrypt, decrypt=encryptor.decrypt,
            delayed_penalty=self.increase_failed_time,
            on_forward_started=functools.partial(self.on_forward_started, begin_at=begin_at))
        self.failed_times = 0

    def on_forward_started(self, begin_at):
        self.record_latency(time.time() - begin_at)

    def is_protocol_supported(self, protocol, client=None):
        if not self.supported_protocol:
            return True
        return self.supported_protocol == protocol

    def __repr__(self):
        return 'ShadowSocksProxy[%s:%s %0.2f]' % (self.proxy_host, self.proxy_port, self.latency)

    @property
    def public_name(self):
        return 'SS\t%s' % self.proxy_host