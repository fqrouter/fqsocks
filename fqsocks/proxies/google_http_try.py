from .http_try import HttpTryProxy
from .http_try import NotHttp
from .http_try import try_receive_response_body
from .http_try import try_receive_response_header
from .. import networking
import logging
import ssl
import socket
import httplib
import gevent

LOGGER = logging.getLogger(__name__)

class HttpsEnforcer(HttpTryProxy):
    def get_or_create_upstream_sock(self, client):
        LOGGER.info('[%s] force https: %s' % (repr(client), client.url))
        upstream_sock = client.create_tcp_socket(client.dst_ip, 443, 3)
        old_counter = upstream_sock.counter
        upstream_sock = ssl.wrap_socket(upstream_sock)
        upstream_sock.counter = old_counter
        return upstream_sock

    def process_response(self, client, upstream_sock, response, http_response):
        if http_response:
            if httplib.FORBIDDEN == http_response.status:
                client.fall_back(reason='403 forbidden')
            if httplib.NOT_FOUND == http_response.status:
                client.fall_back(reason='404 not found')
        return super(HttpsEnforcer, self).process_response(client, upstream_sock, response, http_response)

    def forward_upstream_sock(self, client, http_response, upstream_sock):
        client.forward(upstream_sock)

    def is_protocol_supported(self, protocol, client=None):
        if not super(HttpsEnforcer, self).is_protocol_supported(protocol, client):
            return False
        if not is_blocked_google_host(client.host):
            return False
        return True

    def __repr__(self):
        return 'HttpsEnforcer'


class GoogleScrambler(HttpTryProxy):

    def before_send_request(self, client, upstream_sock, is_payload_complete):
        client.google_scrambler_hacked = is_payload_complete
        if client.google_scrambler_hacked:
            if 'Referer' in client.headers:
                del client.headers['Referer']
            LOGGER.info('[%s] scramble google traffic' % repr(client))
            return 'GET http://www.google.com/ncr HTTP/1.1\r\n\r\n\r\n'
        return ''

    def forward_upstream_sock(self, client, http_response, upstream_sock):
        if client.google_scrambler_hacked:
            client.forward(upstream_sock) # google will 400 error if keep-alive and scrambling
        else:
            super(GoogleScrambler, self).forward_upstream_sock(client, http_response, upstream_sock)

    def after_send_request(self, client, upstream_sock):
        google_scrambler_hacked = getattr(client, 'google_scrambler_hacked', False)
        if google_scrambler_hacked:
            try_receive_response_body(try_receive_response_header(client, upstream_sock), reads_all=True)

    def process_response(self, client, upstream_sock, response, http_response):
        google_scrambler_hacked = getattr(client, 'google_scrambler_hacked', False)
        if not google_scrambler_hacked:
            return response
        if len(response) < 10:
            client.fall_back('response is too small: %s' % response)
        if http_response:
            if httplib.FORBIDDEN == http_response.status:
                client.fall_back(reason='403 forbidden')
            if httplib.NOT_FOUND == http_response.status:
                client.fall_back(reason='404 not found')
            if http_response.content_length \
                and httplib.PARTIAL_CONTENT != http_response.status \
                and 0 < http_response.content_length < 10:
                client.fall_back('content length is too small: %s' % http_response.msg.dict)
        return response

    def is_protocol_supported(self, protocol, client=None):
        if not super(GoogleScrambler, self).is_protocol_supported(protocol, client):
            return False
        if not is_blocked_google_host(client.host):
            return False
        return True

    def __repr__(self):
        return 'GoogleScrambler'


class TcpScrambler(HttpTryProxy):
    def __init__(self):
        super(TcpScrambler, self).__init__()
        self.bad_requests = {} # host => count
        self.is_trying = False

    def try_start_if_network_is_ok(self):
        if self.is_trying:
            return
        self.died = True
        self.is_trying = True
        gevent.spawn(self._try_start)

    def _try_start(self):
        try:
            LOGGER.info('will try start tcp scrambler in 30 seconds')
            gevent.sleep(5)
            LOGGER.info('try tcp scrambler')
            if not detect_if_ttl_being_ignored():
                self.died = False
        finally:
            self.is_trying = False

    def before_send_request(self, client, upstream_sock, is_payload_complete):
        if 'Referer' in client.headers:
            del client.headers['Referer']
        upstream_sock.setsockopt(socket.SOL_SOCKET, networking.SO_MARK, 0xbabe)
        return ''

    def after_send_request(self, client, upstream_sock):
        pass

    def process_response(self, client, upstream_sock, response, http_response):
        upstream_sock.setsockopt(socket.SOL_SOCKET, networking.SO_MARK, 0)
        if httplib.BAD_REQUEST == http_response.status:
            LOGGER.info('[%s] bad request to %s' % (repr(client), client.host))
            self.bad_requests[client.host] = self.bad_requests.get(client.host, 0) + 1
            if self.bad_requests[client.host] >= 3:
                LOGGER.critical('!!! too many bad requests, disable tcp scrambler !!!')
                self.died = True
            client.fall_back('tcp scrambler bad request')
        else:
            if client.host in self.bad_requests:
                LOGGER.info('[%s] reset bad request to %s' % (repr(client), client.host))
                del self.bad_requests[client.host]
            response = response.replace('Connection: keep-alive', 'Connection: close')
        return response

    def is_protocol_supported(self, protocol, client=None):
        if not super(TcpScrambler, self).is_protocol_supported(protocol, client):
            return False
        if not is_blocked_google_host(client.host):
            return False
        return True


    def __repr__(self):
        return 'TcpScrambler'


TCP_SCRAMBLER = TcpScrambler()
GOOGLE_SCRAMBLER = GoogleScrambler()
HTTPS_ENFORCER = HttpsEnforcer()

def is_blocked_google_host(client_host):
    if not client_host:
        return False
    return 'youtube.com' in client_host or 'ytimg.com' in client_host or 'googlevideo.com' in client_host \
        or '.c.android.clients.google.com' in client_host # google play apk


def detect_if_ttl_being_ignored():
    gevent.sleep(5)
    for i in range(2):
        try:
            LOGGER.info('detecting if ttl being ignored')
            baidu_ip = networking.resolve_ips('www.baidu.com')[0]
            sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
            if networking.OUTBOUND_IP:
                sock.bind((networking.OUTBOUND_IP, 0))
            sock.setblocking(0)
            sock.settimeout(2)
            sock.setsockopt(socket.SOL_IP, socket.IP_TTL, 3)
            try:
                sock.connect((baidu_ip, 80))
            finally:
                sock.close()
            LOGGER.info('ttl 3 should not connect baidu, disable fqting')
            return True
        except:
            LOGGER.exception('detected if ttl being ignored')
            gevent.sleep(1)
    return False
