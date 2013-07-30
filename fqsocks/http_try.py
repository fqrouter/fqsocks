import logging
import httplib
import socket
import sys
import StringIO
import gzip
import fnmatch

from direct import Proxy


LOGGER = logging.getLogger(__name__)

SO_MARK = 36


NO_DIRECT_PROXY_HOSTS = {
    '*.twitter.com',
    'twitter.com',
    '*.t.co',
    't.co',
    '*.twimg.com',
    'twimg.com',
    'hulu.com',
    '*.hulu.com',
    'huluim.com',
    '*.huluim.com',
    'netflix.com',
    '*.netflix.com',
    'skype.com',
    '*.skype.com',
    'pandora.com',
    '*.pandora.com'
}

def is_no_direct_host(client_host):
    return any(fnmatch.fnmatch(client_host, host) for host in NO_DIRECT_PROXY_HOSTS)


class HttpTryProxy(Proxy):
    def __init__(self):
        super(HttpTryProxy, self).__init__()
        self.flags.add('DIRECT')
        self.http_request_mark = None
        self.enable_youtube_scrambler = False

    def do_forward(self, client):
        try:
            upstream_sock = client.create_tcp_socket(client.dst_ip, client.dst_port, 3)
        except:
            if LOGGER.isEnabledFor(logging.DEBUG):
                LOGGER.debug('[%s] http try connect failed' % (repr(client)), exc_info=1)
            client.direct_connection_failed()
            client.fall_back(reason='http try connect failed')
            return
        client.direct_connection_succeeded()
        is_payload_complete = recv_and_parse_request(client)
        if is_no_direct_host(client.host):
            client.fall_back(reason='%s blacklisted for direct access' % client.host)
        request_data = '%s %s HTTP/1.1\r\n' % (client.method, client.path)
        scrambles_youtube = self.enable_youtube_scrambler and is_payload_complete and \
                            ('youtube.com' in client.host or 'ytimg.com' in client.host) and \
                            not HTTP_TRY_PROXY.http_request_mark
        if scrambles_youtube:
            LOGGER.info('[%s] scramble youtube traffic' % repr(client))
            request_data = 'GET http://www.google.com/ncr HTTP/1.1\r\n\r\n\r\n' + request_data
            upstream_sock.sendall(request_data)
            request_data = ''
            client.headers['Connection'] = 'close'
        client.headers['Host'] = client.host
        request_data += ''.join('%s: %s\r\n' % (k, v) for k, v in client.headers.items())
        request_data += '\r\n'
        if HTTP_TRY_PROXY.http_request_mark:
            upstream_sock.setsockopt(socket.SOL_SOCKET, SO_MARK, HTTP_TRY_PROXY.http_request_mark)
        try:
            upstream_sock.sendall(request_data + client.payload)
        except:
            client.fall_back(reason='send to upstream failed: %s' % sys.exc_info()[1])
        if scrambles_youtube:
            try_receive_response(client, upstream_sock, reads_all=True)
        if is_payload_complete:
            response, http_response = try_receive_response(
                client, upstream_sock, rejects_error=('GET' == client.method))
            if scrambles_youtube or HTTP_TRY_PROXY.http_request_mark:
                response = response.replace('Connection: keep-alive', 'Connection: close')
                try:
                    if scrambles_youtube and len(response) < 10:
                        client.fall_back('response is too small: %s' % response)
                    if http_response:
                        if scrambles_youtube and httplib.FORBIDDEN == http_response.status:
                            client.fall_back(reason='403 forbidden')
                        content_length = http_response.msg.dict.get('content-length')
                        if scrambles_youtube and content_length and httplib.PARTIAL_CONTENT != http_response.status and 0 < int(content_length) < 10:
                            client.fall_back('content length is too small: %s' % http_response.msg.dict)
                        if http_response.body and 'gzip' == http_response.msg.dict.get('content-encoding'):
                            stream = StringIO.StringIO(http_response.body)
                            gzipper = gzip.GzipFile(fileobj=stream)
                            http_response.body = gzipper.read()
                        if http_response.body and ('id="unavailable-message" class="message"' in http_response.body or 'UNPLAYABLE' in http_response.body):
                            client.fall_back(reason='youtube player not available in China')
                except client.ProxyFallBack:
                    raise
                except:
                    LOGGER.exception('analyze response failed')
            client.forward_started = True
            client.downstream_sock.sendall(response)
        if HTTP_TRY_PROXY.http_request_mark:
            upstream_sock.setsockopt(socket.SOL_SOCKET, SO_MARK, 0)
        client.forward(upstream_sock)

    def is_protocol_supported(self, protocol):
        return 'HTTP' == protocol

    def __repr__(self):
        return 'HttpTryProxy'


HTTP_TRY_PROXY = HttpTryProxy()


def try_receive_response(client, upstream_sock, rejects_error=False, reads_all=False):
    try:
        upstream_rfile = upstream_sock.makefile('rb', 0)
        client.add_resource(upstream_rfile)
        capturing_sock = CapturingSock(upstream_rfile)
        http_response = httplib.HTTPResponse(capturing_sock)
        http_response.body = None
        http_response.begin()
        if 'text/html' in capturing_sock.rfile.captured:
            reads_all = True
        if not reads_all:
            if LOGGER.isEnabledFor(logging.DEBUG):
                LOGGER.debug('[%s] http try read response header: %s %s' %
                             (repr(client), http_response.status, http_response.length))
            if http_response.chunked:
                if LOGGER.isEnabledFor(logging.DEBUG):
                    LOGGER.debug('[%s] skip try reading response due to chunked' % repr(client))
                return capturing_sock.rfile.captured, http_response
            if not http_response.length:
                if LOGGER.isEnabledFor(logging.DEBUG):
                    LOGGER.debug('[%s] skip try reading response due to no content length' % repr(client))
                return capturing_sock.rfile.captured, http_response
            if http_response.length > 1024 * 1024:
                if LOGGER.isEnabledFor(logging.DEBUG):
                    LOGGER.debug('[%s] skip try reading response due to too large: %s' %
                                 (repr(client), http_response.length))
                return capturing_sock.rfile.captured, http_response
            if rejects_error and not (200 <= http_response.status < 400):
                raise Exception('http try read response status %s not in [200, 400)' % http_response.status)
        http_response.body = http_response.read()
        return capturing_sock.rfile.captured, http_response
    except NotHttp:
        raise
    except:
        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.debug('[%s] http try read response failed' % (repr(client)), exc_info=1)
        client.fall_back(reason='http try read response failed: %s' % sys.exc_info()[1])


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