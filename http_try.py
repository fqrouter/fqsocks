import logging
import httplib

from direct import Proxy


LOGGER = logging.getLogger(__name__)


class HttpTryProxy(Proxy):
    def forward(self, client):
        upstream_sock, response = send_first_request_and_get_response(client)
        client.downstream_sock.sendall(response)
        client.forward(upstream_sock)

    def is_protocol_supported(self, protocol):
        return 'HTTP' == protocol

    def __repr__(self):
        return 'HttpTryProxy'


HTTP_TRY_PROXY = HttpTryProxy()


def send_first_request_and_get_response(client):
    try:
        recv_and_parse_request(client)
        upstream_sock = client.create_upstream_sock()
        upstream_sock.settimeout(2)
        upstream_sock.connect((client.dst_ip, client.dst_port))
        upstream_sock.sendall(client.peeked_data)
        upstream_rfile = upstream_sock.makefile('rb', 8192)
        client.add_resource(upstream_rfile)
        capturing_sock = CapturingSock(upstream_rfile)
        http_response = httplib.HTTPResponse(capturing_sock)
        http_response.begin()
        http_response.read()
        return upstream_sock, capturing_sock.rfile.captured
    except NotHttp:
        raise
    except:
        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.debug('[%s] http try failed' % (repr(client)), exc_info=1)
        client.fall_back(reason='http try failed')


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
    client.peeked_data = recv_http_header(client.peeked_data, client.downstream_sock)
    if 'Host:' not in client.peeked_data:
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
        client.payload = None
        if 'Content-Length' in client.headers:
            client.payload = client.downstream_rfile.read(int(client.headers.get('Content-Length', 0)))
        if client.payload:
            client.peeked_data += client.payload
    except:
        LOGGER.error('[%s] failed to parse http request:\n%s' % (repr(client), client.peeked_data))
        raise


def recv_http_header(peeked_data, sock):
    for i in range(3):
        if peeked_data.find(b'\r\n\r\n') != -1:
            return peeked_data
        peeked_data += sock.recv(8192)
    return peeked_data


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