import logging
import re

LOGGER = logging.getLogger(__name__)

RE_STATUS = re.compile(r'HTTP/1.\d (\d+) ')


class HttpConnectProxy(object):
    def __init__(self, proxy_ip, proxy_port):
        super(HttpConnectProxy, self).__init__()
        self.proxy_ip = proxy_ip
        self.proxy_port = proxy_port

    def connect_upstream(self, client):
        sock = client.upstream_sock
        LOGGER.info('[%s] http connect %s:%s' % (repr(client), self.proxy_ip, self.proxy_port))
        sock.connect((self.proxy_ip, self.proxy_port))
        sock.sendall('CONNECT %s:%s HTTP/1.0\r\n\r\n' % (client.dst_ip, client.dst_port))
        response = sock.recv(1)
        while response.find('\r\n\r\n') == -1:
            response += sock.recv(1)
        match = RE_STATUS.search(response)
        if match and '200' == match.group(1):
            return True
        LOGGER.error('[%s] http connect response from %s:%s\n%s' %
                     (repr(client), self.proxy_ip, self.proxy_port, response.strip()))
        return False
