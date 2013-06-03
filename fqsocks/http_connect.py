import logging
import re
import sys
from direct import Proxy
from http_try import recv_till_double_newline
from http_try import send_first_request_and_get_response
import base64

LOGGER = logging.getLogger(__name__)

RE_STATUS = re.compile(r'HTTP/1.\d (\d+) ')


class HttpConnectProxy(Proxy):
    def __init__(self, proxy_ip, proxy_port, username=None, password=None, is_public=True):
        super(HttpConnectProxy, self).__init__()
        self.proxy_ip = proxy_ip
        self.proxy_port = proxy_port
        self.username = username
        self.password = password
        self.failed_times = 0
        if is_public:
            self.flags.add('PUBLIC')

    def do_forward(self, client):
        LOGGER.info('[%s] http connect %s:%s' % (repr(client), self.proxy_ip, self.proxy_port))
        try:
            upstream_sock = client.create_tcp_socket(self.proxy_ip, self.proxy_port, 3)
        except:
            if LOGGER.isEnabledFor(logging.DEBUG):
                LOGGER.debug('[%s] http-connect upstream socket connect timed out' % (repr(client)), exc_info=1)
            self.report_failure(client, 'http-connect upstream socket connect timed out')
            return
        upstream_sock.settimeout(3)
        if 443 == client.dst_port:
            upstream_sock.sendall('CONNECT %s:%s HTTP/1.0\r\n' % (client.dst_ip, client.dst_port))
            if self.username:
                auth = base64.b64encode('%s:%s' % (self.username, self.password)).strip()
                upstream_sock.sendall('Proxy-Authorization: Basic %s\r\n' % auth)
            upstream_sock.sendall('\r\n')
            try:
                response, _ = recv_till_double_newline('', upstream_sock)
            except:
                if LOGGER.isEnabledFor(logging.DEBUG):
                    LOGGER.debug('[%s] http-connect upstream connect command failed' % (repr(client)), exc_info=1)
                self.report_failure(client, 'http-connect upstream connect command failed: %s' % sys.exc_info()[1])
            match = RE_STATUS.search(response)
            if match and '200' == match.group(1):
                if LOGGER.isEnabledFor(logging.DEBUG):
                    LOGGER.debug('[%s] upstream connected' % repr(client))
                upstream_sock.sendall(client.peeked_data)
                client.forward(upstream_sock)
            else:
                if LOGGER.isEnabledFor(logging.DEBUG):
                    LOGGER.debug('[%s] http connect response: %s' % (repr(client), response.strip()))
                LOGGER.error('[%s] http connect rejected: %s' %
                             (repr(client), response.splitlines()[0] if response.splitlines() else 'unknown'))
                self.died = True
                client.fall_back(response.splitlines()[0] if response.splitlines() else 'unknown')
        else:
            response = send_first_request_and_get_response(client, upstream_sock)
            client.forward_started = True
            client.downstream_sock.sendall(response)
            client.forward(upstream_sock)

    def report_failure(self, client, reason):
        self.failed_times += 1
        if self.failed_times > 3:
            self.died = True
        client.fall_back(reason=reason)

    def is_protocol_supported(self, protocol):
        if 'PUBLIC' in self.flags:
            return protocol == 'HTTPS'
        else:
            return protocol in ('HTTP', 'HTTPS')

    def __repr__(self):
        return 'HttpConnectProxy[%s:%s]' % (self.proxy_ip, self.proxy_port)

