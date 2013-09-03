import socket
import struct
import logging

from direct import Proxy
import encrypt


LOGGER = logging.getLogger(__name__)


class ShadowSocksProxy(Proxy):
    def __init__(self, proxy_host, proxy_port, password, encrypt_method):
        super(ShadowSocksProxy, self).__init__()
        self.proxy_host = proxy_host
        if not self.proxy_host:
            self.died = True
        self.proxy_port = int(proxy_port)
        self.password = password
        self.encrypt_method = encrypt_method
        self.failed_times = 0

    def do_forward(self, client):
        encryptor = encrypt.Encryptor(self.password, self.encrypt_method)
        addr_to_send = '\x01'
        addr_to_send += socket.inet_aton(client.dst_ip)
        addr_to_send += struct.pack('>H', client.dst_port)
        try:
            upstream_sock = client.create_tcp_socket(self.proxy_ip, self.proxy_port, 5)
        except:
            self.increase_failed_time()
            client.fall_back(reason='can not connect to proxy')
        encrypted_addr = encryptor.encrypt(addr_to_send)
        upstream_sock.counter.sending(len(encrypted_addr))
        upstream_sock.sendall(encrypted_addr)
        encrypted_peeked_data = encryptor.encrypt(client.peeked_data)
        upstream_sock.counter.sending(len(encrypted_peeked_data))
        upstream_sock.sendall(encrypted_peeked_data)
        client.forward(
            upstream_sock, encrypt=encryptor.encrypt, decrypt=encryptor.decrypt,
            delayed_penalty=self.increase_failed_time)
        self.failed_times = 0

    def increase_failed_time(self):
        LOGGER.error('failed once/%s: %s' % (self.failed_times, self))
        self.failed_times += 1
        if self.failed_times > 3:
            self.died = True
            LOGGER.fatal('!!! proxy died !!!: %s' % self)

    def is_protocol_supported(self, protocol):
        if hasattr(self, 'resolved_by_dynamic_proxy'):
            return protocol in ('HTTP', 'HTTPS')
        else:
            return True

    def __repr__(self):
        return 'ShadowSocksProxy[%s:%s]' % (self.proxy_host, self.proxy_port)

    @property
    def public_name(self):
        return 'SS\t%s' % self.proxy_host