import logging
import httplib
import socket

from direct import Proxy


LOGGER = logging.getLogger(__name__)

SO_MARK = 36

class HttpTryProxy(Proxy):
    def __init__(self):
        super(HttpTryProxy, self).__init__()
        self.flags.add('DIRECT')
        self.http_request_mark = None

    def do_forward(self, client):
        upstream_sock = client.create_upstream_sock()
        upstream_sock.settimeout(3)
        try:
            upstream_sock.connect((client.dst_ip, client.dst_port))
        except:
            if LOGGER.isEnabledFor(logging.DEBUG):
                LOGGER.debug('[%s] http try connect failed' % (repr(client)), exc_info=1)
            client.direct_connection_failed()
            client.fall_back(reason='http try connect failed')
        client.direct_connection_succeeded()
        try:
            if self.http_request_mark:
                upstream_sock.setsockopt(socket.SOL_SOCKET, SO_MARK, self.http_request_mark)
            response = send_first_request_and_get_response(client, upstream_sock)
        finally:
            if self.http_request_mark:
                upstream_sock.setsockopt(socket.SOL_SOCKET, SO_MARK, 0)
        client.forward_started = True
        client.downstream_sock.sendall(response)
        client.forward(upstream_sock)

    def is_protocol_supported(self, protocol):
        return 'HTTP' == protocol

    def __repr__(self):
        return 'HttpTryProxy'


HTTP_TRY_PROXY = HttpTryProxy()


def send_first_request_and_get_response(client, upstream_sock):
    try:
        recv_and_parse_request(client)
        upstream_sock.sendall(client.peeked_data)
        upstream_rfile = upstream_sock.makefile('rb', 0)
        client.add_resource(upstream_rfile)
        capturing_sock = CapturingSock(upstream_rfile)
        http_response = httplib.HTTPResponse(capturing_sock)
        http_response.begin()
        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.debug('[%s] http try read response header: %s %s' %
                         (repr(client), http_response.status, http_response.length))
        if http_response.chunked:
            if LOGGER.isEnabledFor(logging.DEBUG):
                LOGGER.debug('[%s] skip try reading response due to chunked' % repr(client))
            return capturing_sock.rfile.captured
        if not http_response.length:
            if LOGGER.isEnabledFor(logging.DEBUG):
                LOGGER.debug('[%s] skip try reading response due to no content length' % repr(client))
            return capturing_sock.rfile.captured
        if http_response.length > 1024 * 1024:
            if LOGGER.isEnabledFor(logging.DEBUG):
                LOGGER.debug('[%s] skip try reading response due to too large' % repr(client))
            return capturing_sock.rfile.captured
        if not (200 <= http_response.status < 400):
            raise Exception('http try read response status %s not in [200, 400)' % http_response.status)
        if 'html' not in (http_response.msg.getheader('content-type') or ''):
            if LOGGER.isEnabledFor(logging.DEBUG):
                LOGGER.debug('[%s] skip try reading response due to not html' % repr(client))
            return capturing_sock.rfile.captured
        http_response.read()
        return capturing_sock.rfile.captured
    except NotHttp:
        raise
    except:
        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.debug('[%s] http try read response failed' % (repr(client)), exc_info=1)
        client.fall_back(reason='http try read response failed')


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
        client.method, path, client.headers = parse_request(client.peeked_data)
        client.host = client.headers.pop('Host', '')
        if not client.host:
            raise Exception('missing host')
        if path[0] == '/':
            client.url = 'http://%s%s' % (client.host, path)
        else:
            client.url = path
        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.debug('[%s] parsed http header: %s %s' % (repr(client), client.method, client.url))
        if 'Content-Length' in client.headers:
            more_payload_len = int(client.headers.get('Content-Length', 0)) - len(client.payload)
            if more_payload_len > 0:
                client.payload += client.downstream_rfile.read(more_payload_len)
        if client.payload:
            client.peeked_data += client.payload
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