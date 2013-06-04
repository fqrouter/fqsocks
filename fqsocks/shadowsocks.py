import socket
import struct
import logging

from direct import Proxy
import encrypt


LOGGER = logging.getLogger(__name__)


class ShadowSocksProxy(Proxy):
    def __init__(self, proxy_ip, proxy_port, password, encrypt_method):
        super(ShadowSocksProxy, self).__init__()
        self.proxy_ip = proxy_ip
        self.proxy_port = int(proxy_port)
        self.password = password
        self.encrypt_method = encrypt_method
        self.failed_times = 0

    def do_forward(self, client):
        self.encryptor = encrypt.Encryptor(self.password, self.encrypt_method)
        addr_to_send = '\x01'
        addr_to_send += socket.inet_aton(client.dst_ip)
        addr_to_send += struct.pack('>H', client.dst_port)
        try:
            upstream_sock = client.create_tcp_socket(self.proxy_ip, self.proxy_port, 5)
        except:
            self.failed_times += 1
            if self.failed_times > 3:
                self.died = True
            client.fall_back(reason='can not connect to proxy')
        upstream_sock.sendall(self.encryptor.encrypt(addr_to_send))
        upstream_sock.sendall(self.encryptor.encrypt(client.peeked_data))
        client.forward(upstream_sock, encrypt=self.encryptor.encrypt, decrypt=self.encryptor.decrypt)

    def encrypt(self, data):
        return self.encryptor.encrypt(data)

    def decrypt(self, data):
        return self.encryptor.decrypt(data)

    def is_protocol_supported(self, protocol):
        return True

    def __repr__(self):
        return 'ShadowSocksProxy[ip=%s]' % self.proxy_ip


def send_all(sock, data):
    bytes_sent = 0
    while True:
        r = sock.send(data[bytes_sent:])
        if r < 0:
            return r
        bytes_sent += r
        if bytes_sent == len(data):
            return bytes_sent