import logging
import re

LOGGER = logging.getLogger(__name__)

RE_STATUS = re.compile(r'HTTP/1.\d (\d+) ')

class HttpConnectProxy(object):
    def __init__(self, proxy_ip, proxy_port):
        super(HttpConnectProxy, self).__init__()
        self.proxy_ip = proxy_ip
        self.proxy_port = proxy_port

    def forward(self, client):
        upstream_sock = client.create_upstream_sock()
        LOGGER.info('[%s] http connect %s:%s' % (repr(client), self.proxy_ip, self.proxy_port))
        upstream_sock.connect((self.proxy_ip, self.proxy_port))
        upstream_sock.sendall('CONNECT %s:%s HTTP/1.0\r\n\r\n' % (client.dst_ip, client.dst_port))
        response = ''
        rfile = upstream_sock.makefile('rb', 8192)
        while response.find('\r\n\r\n') == -1:
            line = rfile.readline(8192)
            response += line
        match = RE_STATUS.search(response)
        if match and '200' == match.group(1):
            if LOGGER.isEnabledFor(logging.DEBUG):
                LOGGER.debug('[%s] upstream connected' % repr(client))
            upstream_sock.sendall(client.peeked_data)
            client.forward(upstream_sock)
        else:
            LOGGER.error('[%s] http connect response from %s:%s\n%s' %
                         (repr(client), self.proxy_ip, self.proxy_port, response.strip()))

    def __repr__(self):
        return 'HttpConnectProxy[%s:%s]' % (self.proxy_ip, self.proxy_port)

