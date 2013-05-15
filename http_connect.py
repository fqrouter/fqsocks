import logging
import re
from direct import Proxy
from http_try import recv_till_double_newline
from http_try import send_first_request_and_get_response

LOGGER = logging.getLogger(__name__)

RE_STATUS = re.compile(r'HTTP/1.\d (\d+) ')


class HttpConnectProxy(Proxy):
    def __init__(self, proxy_ip, proxy_port):
        super(HttpConnectProxy, self).__init__()
        self.proxy_ip = proxy_ip
        self.proxy_port = proxy_port

    def forward(self, client):
        upstream_sock = client.create_upstream_sock()
        upstream_sock.settimeout(5)
        # upstream_sock = ssl.wrap_socket(upstream_sock)
        # client.add_resource(upstream_sock)
        LOGGER.info('[%s] http connect %s:%s' % (repr(client), self.proxy_ip, self.proxy_port))
        try:
            upstream_sock.connect((self.proxy_ip, self.proxy_port))
        except:
            if LOGGER.isEnabledFor(logging.DEBUG):
                LOGGER.debug('[%s] http-connect upstream socket connect timed out' % (repr(client)), exc_info=1)
            self.died = True
            client.fall_back(reason='http-connect upstream socket connect timed out')
        if 443 == client.dst_port:
            upstream_sock.sendall('CONNECT %s:%s HTTP/1.0\r\n\r\n' % (client.dst_ip, client.dst_port))
            try:
                response = recv_till_double_newline('', upstream_sock)
            except:
                if LOGGER.isEnabledFor(logging.DEBUG):
                    LOGGER.debug('[%s] http-connect upstream connect command failed' % (repr(client)), exc_info=1)
                client.fall_back(reason='http-connect upstream connect command failed')
            match = RE_STATUS.search(response)
            if match and '200' == match.group(1):
                if LOGGER.isEnabledFor(logging.DEBUG):
                    LOGGER.debug('[%s] upstream connected' % repr(client))
                upstream_sock.sendall(client.peeked_data)
                client.forward(upstream_sock)
            else:
                LOGGER.error('[%s] http connect response from %s:%s\n%s' %
                             (repr(client), self.proxy_ip, self.proxy_port, response.strip()))
                self.died = True
                client.fall_back(response.splitlines()[0] if response.splitlines() else 'unknown')
        else:
            response = send_first_request_and_get_response(client, upstream_sock)
            client.downstream_sock.sendall(response)
            client.forward(upstream_sock)

    def is_protocol_supported(self, protocol):
        return protocol in ('HTTP', 'HTTPS')

    def __repr__(self):
        return 'HttpConnectProxy[%s:%s]' % (self.proxy_ip, self.proxy_port)

