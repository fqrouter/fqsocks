import logging
import httplib
import socket
import sys
import StringIO
import gzip
import fnmatch
import time
import gevent
import ssl

from .direct import Proxy
from .. import networking
from .. import ip_substitution

LOGGER = logging.getLogger(__name__)

SO_MARK = 36

NO_DIRECT_PROXY_HOSTS = {
    'hulu.com',
    '*.hulu.com',
    'huluim.com',
    '*.huluim.com',
    'netflix.com',
    '*.netflix.com',
    'skype.com',
    '*.skype.com',
    'radiotime.com',
    '*.radiotime.com'
    'myfreecams.com',
    '*.myfreecams.com'
    'pandora.com',
    '*.pandora.com'
}

WHITE_LIST = {
    'www.google.com',
    'google.com',
    'www.google.com.hk',
    'google.com.hk',
}


def is_no_direct_host(client_host):
    return any(fnmatch.fnmatch(client_host, host) for host in NO_DIRECT_PROXY_HOSTS)


class HttpTryProxy(Proxy):

    host_black_list = {} # host => count
    host_slow_list = set()
    host_slow_detection_enabled = True
    dst_black_list = {} # (ip, port) => count

    def __init__(self):
        super(HttpTryProxy, self).__init__()
        self.flags.add('DIRECT')

    def do_forward(self, client):
        try:
            self.try_direct(client)
            if client.host and self.host_black_list.get(client.host, 0) > 3:
                LOGGER.error('remove host %s from blacklist' % client.host)
                del self.host_black_list[client.host]
        except NotHttp:
            raise
        except:
            if client.host and client.host not in WHITE_LIST:
                self.host_black_list[client.host] = self.host_black_list.get(client.host, 0) + 1
                if self.host_black_list[client.host] == 4:
                    LOGGER.error('blacklist host %s' % client.host)
            raise

    def try_direct(self, client):
        is_payload_complete = recv_and_parse_request(client)
        # check host
        if client.host in self.host_slow_list:
            client.fall_back(reason='%s was too slow to direct connect' % client.host, silently=True)
        failed_count = self.host_black_list.get(client.host, 0)
        if failed_count > 3 and (failed_count % 10) != 0:
            client.fall_back(reason='%s tried before' % client.host, silently=True)
        if is_no_direct_host(client.host):
            client.fall_back(reason='%s blacklisted for direct access' % client.host, silently=True)
        # check ip
        ip_substitution.substitute_ip(client, self.dst_black_list)
        failed_count = self.dst_black_list.get((client.dst_ip, client.dst_port), 0)
        if failed_count and (failed_count % 10) != 0:
            client.fall_back(reason='%s:%s tried before' % (client.dst_ip, client.dst_port), silently=True)
        # start trying
        try:
            upstream_sock = self.create_upstream_sock(client)
        except:
            if LOGGER.isEnabledFor(logging.DEBUG):
                LOGGER.debug('[%s] http try connect failed' % (repr(client)), exc_info=1)
            client.fall_back(reason='http try connect failed')
            return
        client.headers['Host'] = client.host
        request_data = self.before_send_request(client, upstream_sock, is_payload_complete)
        request_data += '%s %s HTTP/1.1\r\n' % (client.method, client.path)
        request_data += ''.join('%s: %s\r\n' % (k, v) for k, v in client.headers.items())
        request_data += '\r\n'
        try:
            upstream_sock.sendall(request_data + client.payload)
        except:
            client.fall_back(reason='send to upstream failed: %s' % sys.exc_info()[1])
        self.after_send_request(client, upstream_sock)
        if is_payload_complete:
            http_response = try_receive_response_header(
                client, upstream_sock, rejects_error=('GET' == client.method))
            response = self.detect_slow_host(client, http_response)
            try:
                response = self.process_response(client, upstream_sock, response, http_response)
            except client.ProxyFallBack:
                raise
            except:
                LOGGER.exception('process response failed')
            client.forward_started = True
            client.downstream_sock.sendall(response)
        if not is_payload_complete and client.method and 'GET' != client.method.upper():
            client.forward(upstream_sock, timeout=360)
        else:
            client.forward(upstream_sock)

    def detect_slow_host(self, client, http_response):
        if self.host_slow_detection_enabled:
            greenlet = gevent.spawn(
                try_receive_response_body, http_response, reads_all='youtube.com/watch?' in client.url)
            try:
                return greenlet.get(timeout=5)
            except gevent.Timeout:
                self.host_slow_list.add(client.host)
                LOGGER.error('[%s] host %s is too slow to direct access' % (repr(client), client.host))
                client.fall_back('too slow')
            finally:
                greenlet.kill()
        else:
            return try_receive_response_body(http_response)

    def create_upstream_sock(self, client):
        return client.create_tcp_socket(client.dst_ip, client.dst_port, 3)

    def before_send_request(self, client, upstream_sock, is_payload_complete):
        return ''

    def after_send_request(self, client, upstream_sock):
        pass

    def process_response(self, client, upstream_sock, response, http_response):
        return response

    def is_protocol_supported(self, protocol, client=None):
        return 'HTTP' == protocol

    def __repr__(self):
        return 'HttpTryProxy'


class HttpsEnforcer(HttpTryProxy):
    def create_upstream_sock(self, client):
        if 80 == client.dst_port and (is_blocked_google_host(client.host) or 'www.google.' in client.host):
            LOGGER.info('force https: %s' % client.url)
            upstream_sock = client.create_tcp_socket(client.dst_ip, 443, 3)
            old_counter = upstream_sock.counter
            upstream_sock = ssl.wrap_socket(upstream_sock)
            upstream_sock.counter = old_counter
            return upstream_sock
        else:
            return super(HttpsEnforcer, self).create_upstream_sock(client)


class GoogleScrambler(HttpTryProxy):
    def do_forward(self, client):
        dst = (client.dst_ip, client.dst_port)
        try:
            super(GoogleScrambler, self).do_forward(client)
            if dst in self.dst_black_list:
                LOGGER.error('removed dst %s:%s from blacklist' % dst)
                del self.dst_black_list[dst]
        except NotHttp:
            raise
        except:
            google_scrambler_hacked = getattr(client, 'google_scrambler_hacked', False)
            if google_scrambler_hacked:
                if dst not in self.dst_black_list:
                    LOGGER.error('blacklist dst %s:%s' % dst)
                self.dst_black_list[dst] = self.dst_black_list.get(dst, 0) + 1
            raise

    def before_send_request(self, client, upstream_sock, is_payload_complete):
        client.google_scrambler_hacked = is_payload_complete and is_blocked_google_host(client.host)
        if client.google_scrambler_hacked:
            client.headers['Connection'] = 'close'
            if 'Referer' in client.headers:
                del client.headers['Referer']
            LOGGER.info('[%s] scramble google traffic' % repr(client))
            return 'GET http://www.google.com/ncr HTTP/1.1\r\n\r\n\r\n'
        return ''

    def after_send_request(self, client, upstream_sock):
        google_scrambler_hacked = getattr(client, 'google_scrambler_hacked', False)
        if google_scrambler_hacked:
            try_receive_response_body(try_receive_response_header(client, upstream_sock), reads_all=True)

    def process_response(self, client, upstream_sock, response, http_response):
        google_scrambler_hacked = getattr(client, 'google_scrambler_hacked', False)
        if not google_scrambler_hacked:
            return response
        response = response.replace('Connection: keep-alive', 'Connection: close')
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
            fallback_if_youtube_unplayable(client, http_response)
        return response

    def __repr__(self):
        return 'GoogleScrambler'

class TcpScrambler(HttpTryProxy):
    def __init__(self):
        super(TcpScrambler, self).__init__()
        self.bad_requests = {} # host => count
        self.dst_black_list = {}

    def do_forward(self, client):
        if is_blocked_google_host(client.host):
            LOGGER.info('[%s] tcp scramble youtube' % repr(client))
        dst = (client.dst_ip, client.dst_port)
        try:
            super(TcpScrambler, self).do_forward(client)
            if dst in self.dst_black_list:
                LOGGER.error('removed dst %s:%s from blacklist' % dst)
                del self.dst_black_list[dst]
        except NotHttp:
            raise
        except:
            if dst not in self.dst_black_list:
                LOGGER.error('blacklist dst %s:%s' % dst)
            self.dst_black_list[dst] = self.dst_black_list.get(dst, 0) + 1
            raise

    def before_send_request(self, client, upstream_sock, is_payload_complete):
        client.headers['Connection'] = 'close'
        if 'Referer' in client.headers:
            del client.headers['Referer']
        upstream_sock.setsockopt(socket.SOL_SOCKET, SO_MARK, 0xbabe)
        return ''

    def after_send_request(self, client, upstream_sock):
        pass

    def process_response(self, client, upstream_sock, response, http_response):
        upstream_sock.setsockopt(socket.SOL_SOCKET, SO_MARK, 0)
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
            fallback_if_youtube_unplayable(client, http_response)
        return response

    def __repr__(self):
        return 'TcpScrambler'


HTTP_TRY_PROXY = HttpTryProxy()
GOOGLE_SCRAMBLER = GoogleScrambler()
TCP_SCRAMBLER = TcpScrambler()
HTTPS_ENFORCER = HttpsEnforcer()


def fallback_if_youtube_unplayable(client, http_response):
    if not http_response:
        return
    if 'youtube.com/watch?' not in client.url:
        return
    if http_response.body and 'gzip' == http_response.msg.dict.get('content-encoding'):
        stream = StringIO.StringIO(http_response.body)
        gzipper = gzip.GzipFile(fileobj=stream)
        http_response.body = gzipper.read()
    if http_response.body and (
                'id="unavailable-message" class="message"' in http_response.body or 'UNPLAYABLE' in http_response.body):
        client.fall_back(reason='youtube player not available in China')


def is_blocked_google_host(client_host):
    if not client_host:
        return False
    return 'youtube.com' in client_host or 'ytimg.com' in client_host or 'googlevideo.com' in client_host \
        or '.c.android.clients.google.com' in client_host # google play apk


def try_receive_response_header(client, upstream_sock, rejects_error=False):
    try:
        upstream_rfile = upstream_sock.makefile('rb', 0)
        client.add_resource(upstream_rfile)
        capturing_sock = CapturingSock(upstream_rfile)
        http_response = httplib.HTTPResponse(capturing_sock)
        http_response.capturing_sock = capturing_sock
        http_response.body = None
        http_response.begin()
        content_length = http_response.msg.dict.get('content-length')
        if content_length:
            http_response.content_length = int(content_length)
        else:
            http_response.content_length = 0
        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.debug('[%s] http try read response header: %s %s' %
                         (repr(client), http_response.status, http_response.content_length))
        if http_response.chunked:
            if LOGGER.isEnabledFor(logging.DEBUG):
                LOGGER.debug('[%s] skip try reading response due to chunked' % repr(client))
            return http_response
        if not http_response.content_length:
            if LOGGER.isEnabledFor(logging.DEBUG):
                LOGGER.debug('[%s] skip try reading response due to no content length' % repr(client))
            return http_response
        if rejects_error and not (200 <= http_response.status < 400):
            raise Exception('http try read response status %s not in [200, 400)' % http_response.status)
        return http_response
    except NotHttp:
        raise
    except:
        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.debug('[%s] http try read response failed' % (repr(client)), exc_info=1)
        client.fall_back(reason='http try read response failed: %s' % sys.exc_info()[1])

def try_receive_response_body(http_response, reads_all=False):
    content_type = http_response.msg.dict.get('content-type')
    if content_type and 'text/html' in content_type:
        reads_all = True
    if reads_all:
        http_response.body = http_response.read()
    else:
        http_response.body = http_response.read(min(http_response.content_length, 128 * 1024))
    return http_response.capturing_sock.rfile.captured

class CapturingSock(object):
    def __init__(self, rfile):
        self.rfile = CapturingFile(rfile)

    def makefile(self, mode='r', buffersize=-1):
        if 'rb' != mode:
            raise NotImplementedError()
        return self.rfile


class CapturingFile(object):
    def __init__(self, fp):
        self.fp = fp
        self.captured = ''

    def read(self, *args, **kwargs):
        chunk = self.fp.read(*args, **kwargs)
        self.captured += chunk
        return chunk

    def readline(self, *args, **kwargs):
        chunk = self.fp.readline(*args, **kwargs)
        self.captured += chunk
        return chunk

    def close(self):
        self.fp.close()


def recv_and_parse_request(client):
    client.peeked_data, client.payload = recv_till_double_newline(client.peeked_data, client.downstream_sock)
    if 'Host:' not in client.peeked_data:
        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.debug('[%s] not http' % (repr(client)))
        raise NotHttp()
    try:
        client.method, client.path, client.headers = parse_request(client.peeked_data)
        client.host = client.headers.pop('Host', '')
        if not client.host:
            raise Exception('missing host')
        if client.path[0] == '/':
            client.url = 'http://%s%s' % (client.host, client.path)
        else:
            client.url = client.path
        if 'youtube.com/watch' in client.url:
            LOGGER.info('[%s] %s' % (repr(client), client.url))
        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.debug('[%s] parsed http header: %s %s' % (repr(client), client.method, client.url))
        if 'Content-Length' in client.headers:
            more_payload_len = int(client.headers.get('Content-Length', 0)) - len(client.payload)
            if more_payload_len > 1024 * 1024:
                client.peeked_data += client.payload
                LOGGER.info('[%s] skip try reading request payload due to too large: %s' %
                            (repr(client), more_payload_len))
                return False
            if more_payload_len > 0:
                client.payload += client.downstream_rfile.read(more_payload_len)
        if client.payload:
            client.peeked_data += client.payload
        return True
    except:
        LOGGER.error('[%s] failed to parse http request:\n%s' % (repr(client), client.peeked_data))
        raise


def recv_till_double_newline(peeked_data, sock):
    for i in range(16):
        if peeked_data.find(b'\r\n\r\n') != -1:
            header, crlf, payload = peeked_data.partition(b'\r\n\r\n')
            return header + crlf, payload
        more_data = sock.recv(8192)
        if not more_data:
            return peeked_data, ''
        peeked_data += more_data
    raise Exception('http end not found')


class NotHttp(Exception):
    pass


def parse_request(request):
    lines = request.splitlines()
    method, path = lines[0].split()[:2]
    headers = dict()
    for line in lines[1:]:
        keyword, _, value = line.partition(b':')
        keyword = keyword.title()
        value = value.strip()
        if keyword and value:
            headers[keyword] = value
    return method, path, headers


def detect_if_ttl_being_ignored():
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
    return False
