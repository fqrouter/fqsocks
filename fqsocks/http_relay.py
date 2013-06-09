import logging
import socket
import ssl

from direct import Proxy
from http_try import try_receive_response
from http_try import recv_and_parse_request


LOGGER = logging.getLogger(__name__)


class HttpRelayProxy(Proxy):
    def __init__(self, proxy_ip, proxy_port, username=None, password=None, is_public=True, is_secured=False):
        super(HttpRelayProxy, self).__init__()
        self.proxy_ip = socket.gethostbyname(proxy_ip)
        self.proxy_port = proxy_port
        self.username = username
        self.password = password
        self.failed_times = 0
        self.is_secured = is_secured
        if is_public:
            self.flags.add('PUBLIC')

    def do_forward(self, client):
        LOGGER.info('[%s] http relay %s:%s' % (repr(client), self.proxy_ip, self.proxy_port))
        try:
            upstream_sock = client.create_tcp_socket(self.proxy_ip, self.proxy_port, 3)
            if self.is_secured:
                upstream_sock = ssl.wrap_socket(upstream_sock)
                client.add_resource(upstream_sock)
        except:
            if LOGGER.isEnabledFor(logging.DEBUG):
                LOGGER.debug('[%s] http-relay upstream socket connect timed out' % (repr(client)), exc_info=1)
            self.report_failure(client, 'http-relay upstream socket connect timed out')
            return
        upstream_sock.settimeout(3)
        is_complete_payload = recv_and_parse_request(client)
        request_data = '%s %s HTTP/1.1\r\n' % (client.method, client.url)
        client.headers['Connection'] = 'close' # no keep-alive
        request_data += ''.join('%s: %s\r\n' % (k, v) for k, v in client.headers.items())
        request_data += '\r\n'
        upstream_sock.sendall(request_data + client.payload)
        if is_complete_payload:
            response = try_receive_response(client, upstream_sock)
            client.forward_started = True
            client.downstream_sock.sendall(response)
        client.forward(upstream_sock)

    def report_failure(self, client, reason):
        self.failed_times += 1
        if self.failed_times > 3:
            self.died = True
        client.fall_back(reason=reason)

    def is_protocol_supported(self, protocol):
        return protocol == 'HTTP'

    def __repr__(self):
        return 'HttpRelayProxy[%s:%s]' % (self.proxy_ip, self.proxy_port)

