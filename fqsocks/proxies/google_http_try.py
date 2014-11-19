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
        if client.host == 'instagram.com' or client.host.endswith('.instagram.com'):
            return True
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

GOOGLE_SCRAMBLER = GoogleScrambler()
HTTPS_ENFORCER = HttpsEnforcer()

def is_blocked_google_host(client_host):
    if not client_host:
        return False
    return 'youtube.com' in client_host or 'ytimg.com' in client_host or 'googlevideo.com' in client_host
