# coding:utf-8
import logging
import zlib
import base64
import struct
from cStringIO import StringIO as BytesIO
import httplib
import socket
import time
import random
import sys
import errno
import re
import functools

import ssl
import gevent.queue
from direct import DIRECT_PROXY


LOGGER = logging.getLogger(__name__)

SKIP_HEADERS = frozenset(
    ['Vary', 'Via', 'X-Forwarded-For', 'Proxy-Authorization', 'Proxy-Connection', 'Upgrade', 'X-Chrome-Variations',
     'Connection', 'Cache-Control'])
ABBV_HEADERS = {'Accept': ('A', lambda x: '*/*' in x),
                'Accept-Charset': ('AC', lambda x: x.startswith('UTF-8,')),
                'Accept-Language': ('AL', lambda x: x.startswith('zh-CN')),
                'Accept-Encoding': ('AE', lambda x: x.startswith('gzip,')), }
GAE_OBFUSCATE = 0
GAE_VALIDATE = 0
GAE_PASSWORD = ''
GAE_PATH = '/2'
AUTORANGE_MAXSIZE = 1048576
AUTORANGE_HOSTS = '.c.youtube.com|.atm.youku.com|.googlevideo.com|av.vimeo.com|smile-*.nicovideo.jp|video.*.fbcdn.net|s*.last.fm|x*.last.fm|.x.xvideos.com|.edgecastcdn.net|.d.rncdn3.com|cdn*.public.tube8.com|videos.flv*.redtubefiles.com|cdn*.public.extremetube.phncdn.com|cdn*.video.pornhub.phncdn.com|.mms.vlog.xuite.net|vs*.thisav.com|archive.rthk.hk|video*.modimovie.com'.split(
    '|')
AUTORANGE_HOSTS = tuple(AUTORANGE_HOSTS)
AUTORANGE_HOSTS_TAIL = tuple(x.rpartition('*')[2] for x in AUTORANGE_HOSTS)
AUTORANGE_WAITSIZE = 524288
AUTORANGE_BUFSIZE = 8192
AUTORANGE_THREADS = 2
RE_DO_NOT_RANGE = re.compile('^http(?:s)?:\/\/[^\/]+\/[^?]+\.(?:xml|json|html|js|css|jpg|jpeg|png|gif|ico)')

FETCHMAX_LOCAL = 2
tcp_connection_time = {}
ssl_connection_time = {}
normcookie = functools.partial(re.compile(', ([^ =]+(?:=|$))').sub, '\\r\\nSet-Cookie: \\1')


class UrlFetchProxy(object):
    def __init__(self, appid, google_ip, password=False, validate=0):
        super(UrlFetchProxy, self).__init__()
        self.appid = appid
        self.google_ip = google_ip
        self.password = password
        self.validate = validate

    def forward(self, client, peeked_data):
        request = peeked_data
        for i in range(128):
            if request.find(b'\r\n\r\n') != -1:
                break
            line = client.downstream_rfile.readline(8192)
            if not line or line == b'\r\n':
                break
            request += line
        if 'Host:' not in request:
            LOGGER.info('[%s] not http, forward directly' % repr(client))
            DIRECT_PROXY.forward(client, request)
            return
        try:
            LOGGER.debug('request: %s' % request)
            client.method, path, client.headers = parse_request(request)
            host = client.headers.pop('Host', '')
            if not host:
                raise Exception('missing host')
            if path[0] == '/':
                client.url = 'http://%s%s' % (host, path)
            else:
                client.url = path
            if LOGGER.isEnabledFor(logging.DEBUG):
                LOGGER.debug('[%s] parsed request: %s %s' % (repr(client), client.method, client.url))
        except:
            LOGGER.error('[%s] failed to parse http request:\n%s' % (repr(client), request))
            raise
        LOGGER.info('[%s] urlfetch via %s at %s' % (repr(client), self.appid, self.google_ip))
        forward(client, self)


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


def forward(client, proxy):
    # TODO fix autorange
    # if 'Range' in client.headers:
    #     m = re.search('bytes=(\d+)-', client.headers['Range'])
    #     start = int(m.group(1) if m else 0)
    #     client.headers['Range'] = 'bytes=%d-%d' % (start, start + AUTORANGE_MAXSIZE - 1)
    #     LOGGER.info('autorange range=%r match url=%r', client.headers['Range'], client.url)
    # elif client.endswith(AUTORANGE_HOSTS_TAIL) and not RE_DO_NOT_RANGE.match(client.url):
    #     try:
    #         pattern = (p for p in AUTORANGE_HOSTS if client.host.endswith(p) or fnmatch.fnmatch(client.host, p)).next()
    #         LOGGER.debug('autorange pattern=%r match url=%r', pattern, client.url)
    #         m = re.search('bytes=(\d+)-', client.headers.get('Range', ''))
    #         start = int(m.group(1) if m else 0)
    #         client.headers['Range'] = 'bytes=%d-%d' % (start, start + AUTORANGE_MAXSIZE - 1)
    #     except StopIteration:
    #         pass
    try:
        client.payload = None
        if 'Content-Length' in client.headers:
            try:
                client.payload = client.downstream_rfile.read(int(client.headers.get('Content-Length', 0)))
            except (EOFError, socket.error) as e:
                LOGGER.error('handle_method_urlfetch read payload failed:%s', e)
                return
        errors = []
        kwargs = {}
        if proxy.password:
            kwargs['password'] = proxy.password
        if proxy.validate:
            kwargs['validate'] = 1
        response = gae_urlfetch(client, proxy)
        if response is None:
            html = message_html('502 URLFetch failed', 'Local URLFetch %r failed' % client.url, str(errors))
            html = html.encode('utf-8') if isinstance(html, unicode) else html
            client.downstream_sock.sendall(b'HTTP/1.0 502\r\nContent-Type: text/html\r\n\r\n' + html)
            return
        if response.app_status != 200:
            client.downstream_wfile.write('HTTP/1.1 %s\r\n%s\r\n' % (response.status, ''.join(
                '%s: %s\r\n' % (k.title(), v) for k, v in response.getheaders() if k != 'transfer-encoding')))
            client.downstream_wfile.write(response.read())
            response.close()
            return
        if response.status == 206:
            raise Exception('range fetch not implemented yet')
            # fetchservers = [fetchserver]
            # rangefetch = RangeFetch(sock, response, method, path, headers, payload, fetchservers,
            #                         GAE_PASSWORD, maxsize=AUTORANGE_MAXSIZE,
            #                         bufsize=AUTORANGE_BUFSIZE, waitsize=AUTORANGE_WAITSIZE,
            #                         threads=AUTORANGE_THREADS)
            # return rangefetch.fetch()

        if 'Set-Cookie' in response.msg:
            response.msg['Set-Cookie'] = normcookie(response.msg['Set-Cookie'])
        client.downstream_wfile.write('HTTP/1.1 %s\r\n%s\r\n' % (response.status, ''.join(
            '%s: %s\r\n' % (k.title(), v) for k, v in response.getheaders() if k != 'transfer-encoding')))
        while 1:
            data = response.read(8192)
            if not data:
                break
            client.downstream_wfile.write(data)
        response.close()
    except socket.error as e:
        # Connection closed before proxy return
        if e.args[0] not in (errno.ECONNABORTED, errno.EPIPE):
            raise


def message_html(title, banner, detail=''):
    MESSAGE_TEMPLATE = '''
    <html><head>
    <meta http-equiv="content-type" content="text/html;charset=utf-8">
    <title>{{ title }}</title>
    <style><!--
    body {font-family: arial,sans-serif}
    div.nav {margin-top: 1ex}
    div.nav A {font-size: 10pt; font-family: arial,sans-serif}
    span.nav {font-size: 10pt; font-family: arial,sans-serif; font-weight: bold}
    div.nav A,span.big {font-size: 12pt; color: #0000cc}
    div.nav A {font-size: 10pt; color: black}
    A.l:link {color: #6f6f6f}
    A.u:link {color: green}
    //--></style>
    </head>
    <body text=#000000 bgcolor=#ffffff>
    <table border=0 cellpadding=2 cellspacing=0 width=100%>
    <tr><td bgcolor=#3366cc><font face=arial,sans-serif color=#ffffff><b>Message</b></td></tr>
    <tr><td> </td></tr></table>
    <blockquote>
    <H1>{{ banner }}</H1>
    {{ detail }}
    <p>
    </blockquote>
    <table width=100% cellpadding=0 cellspacing=0><tr><td bgcolor=#3366cc><img alt="" width=1 height=4></td></tr></table>
    </body></html>
    '''
    kwargs = dict(title=title, banner=banner, detail=detail)
    template = MESSAGE_TEMPLATE
    for keyword, value in kwargs.items():
        template = template.replace('{{ %s }}' % keyword, value)
    return template


def gae_urlfetch(client, proxy, **kwargs):
    # deflate = lambda x:zlib.compress(x)[2:-4]
    if client.payload:
        if len(client.payload) < 10 * 1024 * 1024 and b'Content-Encoding' not in client.headers:
            zpayload = zlib.compress(client.payload)[2:-4]
            if len(zpayload) < len(client.payload):
                client.payload = zpayload
                client.headers[b'Content-Encoding'] = b'deflate'
        client.headers[b'Content-Length'] = str(len(client.payload))
    metadata = 'G-Method:%s\nG-Url:%s\n%s' % (
        client.method, client.url, ''.join('G-%s:%s\n' % (k, v) for k, v in kwargs.items() if v))
    if GAE_OBFUSCATE and 'X-Requested-With' not in client.headers:
        # not a ajax request, we could abbv the headers
        g_abbv = []
        for keyword in [x for x in client.headers if x not in SKIP_HEADERS]:
            value = client.headers[keyword]
            if keyword in ABBV_HEADERS and ABBV_HEADERS[keyword][1](value):
                g_abbv.append(ABBV_HEADERS[keyword][0])
            else:
                metadata += '%s:%s\n' % (keyword, value)
        if g_abbv:
            metadata += 'G-Abbv:%s\n' % ','.join(g_abbv)
    else:
        metadata += ''.join('%s:%s\n' % (k, v) for k, v in client.headers.items() if k not in SKIP_HEADERS)
    if LOGGER.isEnabledFor(logging.DEBUG):
        LOGGER.debug('[%s] metadata:\n%s' % (repr(client), metadata))
    metadata = zlib.compress(metadata)[2:-4]
    if GAE_OBFUSCATE:
        cookie = base64.b64encode(metadata).strip()
        if not client.payload:
            response = http_request(
                client, proxy, 'GET', client.payload, {b'Cookie': cookie})
        else:
            response = http_request(
                client, proxy, 'POST', client.payload, {b'Cookie': cookie, b'Content-Length': len(client.payload)})
    else:
        payload = '%s%s%s' % (struct.pack('!h', len(metadata)), metadata, client.payload)
        response = http_request(
            client, proxy, b'POST', payload, {b'Content-Length': len(payload)})
    response.app_status = response.status
    if response.status != 200:
        return response
    data = response.read(4)
    if len(data) < 4:
        response.status = 502
        response.fp = BytesIO(b'connection aborted. too short leadtype data=%r' % data)
        return response
    response.status, headers_length = struct.unpack('!hh', data)
    data = response.read(headers_length)
    if len(data) < headers_length:
        response.status = 502
        response.fp = BytesIO(b'connection aborted. too short headers data=%r' % data)
        return response
    response.msg = httplib.HTTPMessage(BytesIO(zlib.decompress(data, -zlib.MAX_WBITS)))
    return response


def http_request(client, proxy, method, payload, headers):
    sock = create_ssl_connection(client, proxy)
    request_data = ''
    request_data += '%s %s %s\r\n' % (method, GAE_PATH, 'HTTP/1.1')
    request_data += 'Host: %s.appspot.com\r\n' % proxy.appid
    request_data += ''.join('%s: %s\r\n' % (k, v) for k, v in headers.items() if k not in SKIP_HEADERS)
    request_data += '\r\n'

    if not payload:
        sock.sendall(request_data)
    else:
        if isinstance(payload, basestring):
            request_data += payload
            sock.sendall(request_data)
        elif hasattr(payload, 'read'):
            sock.sendall(request_data)
            while 1:
                data = payload.read(8192)
                if not data:
                    break
                sock.sendall(data)
        else:
            raise TypeError('http.request(payload) must be a string or buffer, not %r' % type(payload))

    response = httplib.HTTPResponse(sock, buffering=True) if sys.hexversion > 0x02070000 else httplib.HTTPResponse(sock)
    try:
        response.begin()
    except httplib.BadStatusLine:
        response = None
    return response


def create_ssl_connection(client, proxy, timeout=None, max_timeout=16, max_retry=4, max_window=4):
    def _create_ssl_connection(address, timeout, queue):
        try:
            # create a ipv4/ipv6 socket object
            sock = client.create_upstream_sock()
            # set reuseaddr option to avoid 10048 socket error
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # resize socket recv buffer 8K->32K to improve browser releated application performance
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32 * 1024)
            # disable negal algorithm to send http request quickly.
            sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
            # set a short timeout to trigger timeout retry more quickly.
            sock.settimeout(timeout or max_timeout)
            # create ssl socket
            ssl_sock = ssl.wrap_socket(
                sock, do_handshake_on_connect=False, ssl_version=ssl.PROTOCOL_TLSv1)
            client.add_upstream_sock(ssl_sock)
            # start connection time record
            start_time = time.time()
            # TCP connect
            ssl_sock.connect(address)
            connected_time = time.time()
            # SSL handshake
            ssl_sock.do_handshake()
            handshaked_time = time.time()
            # record TCP connection time
            tcp_connection_time[address] = connected_time - start_time
            # record SSL connection time
            ssl_connection_time[address] = handshaked_time - start_time
            # sometimes, we want to use raw tcp socket directly(select/epoll), so setattr it to ssl socket.
            ssl_sock.sock = sock
            queue.put(ssl_sock)
        except socket.error as e:
            LOGGER.exception('[%s] upstream connection error' % repr(client))
            # any socket.error, put Excpetions to output queue.
            queue.put(e)
            # reset a large and random timeout to the address
            ssl_connection_time[address] = max_timeout + random.random()

    addresses = [(proxy.google_ip, 443)]
    for i in xrange(max_retry):
        window = min((max_window + 1) // 2 + i, len(addresses))
        addresses.sort(key=ssl_connection_time.get)
        addrs = addresses[:window] + random.sample(addresses, window)
        queue = gevent.queue.Queue()
        for addr in addrs:
            gevent.spawn(_create_ssl_connection, addr, timeout, queue)
        for i in xrange(len(addrs)):
            result = queue.get()
            if not isinstance(result, socket.error):
                return result


class RangeFetch(object):
    """Range Fetch Class"""

    maxsize = 1024 * 1024 * 4
    bufsize = 8192
    threads = 1
    waitsize = 1024 * 512
    urlfetch = staticmethod(gae_urlfetch)

    def __init__(self, sock, response, method, url, headers, payload, fetchservers, password, maxsize=0, bufsize=0,
                 waitsize=0, threads=0):
        self.sock = sock
        self.response = response
        self.method = method
        self.url = url
        self.headers = headers
        self.payload = payload
        self.fetchservers = fetchservers
        self.password = password
        self.maxsize = maxsize or self.__class__.maxsize
        self.bufsize = bufsize or self.__class__.bufsize
        self.waitsize = waitsize or self.__class__.bufsize
        self.threads = threads or self.__class__.threads
        self._stopped = None
        self._last_app_status = {}

    def fetch(self):
        response_status = self.response.status
        response_headers = dict((k.title(), v) for k, v in self.response.getheaders())
        content_range = response_headers['Content-Range']
        #content_length = response_headers['Content-Length']
        start, end, length = map(int, re.search(r'bytes (\d+)-(\d+)/(\d+)', content_range).group(1, 2, 3))
        if start == 0:
            response_status = 200
            response_headers['Content-Length'] = str(length)
        else:
            response_headers['Content-Range'] = 'bytes %s-%s/%s' % (start, end, length)
            response_headers['Content-Length'] = str(length - start)

        wfile = self.sock.makefile('w', 0)
        LOGGER.info('>>>>>>>>>>>>>>> RangeFetch started(%r) %d-%d', self.url, start, end)
        wfile.write('HTTP/1.1 %s\r\n%s\r\n' % (
            response_status, ''.join('%s: %s\r\n' % (k, v) for k, v in response_headers.items())))

        data_queue = gevent.queue.PriorityQueue()
        range_queue = gevent.queue.PriorityQueue()
        range_queue.put((start, end, self.response))
        for begin in range(end + 1, length, self.maxsize):
            range_queue.put((begin, min(begin + self.maxsize - 1, length - 1), None))
        for i in xrange(self.threads):
            gevent.spawn(self.__fetchlet, range_queue, data_queue)
        has_peek = hasattr(data_queue, 'peek')
        peek_timeout = 90
        expect_begin = start
        while expect_begin < length - 1:
            try:
                if has_peek:
                    begin, data = data_queue.peek(timeout=peek_timeout)
                    if expect_begin == begin:
                        data_queue.get()
                    elif expect_begin < begin:
                        gevent.sleep(0.1)
                        continue
                    else:
                        LOGGER.error('RangeFetch Error: begin(%r) < expect_begin(%r), quit.', begin, expect_begin)
                        break
                else:
                    begin, data = data_queue.get(timeout=peek_timeout)
                    if expect_begin == begin:
                        pass
                    elif expect_begin < begin:
                        data_queue.put((begin, data))
                        gevent.sleep(0.1)
                        continue
                    else:
                        LOGGER.error('RangeFetch Error: begin(%r) < expect_begin(%r), quit.', begin, expect_begin)
                        break
            except gevent.queue.Empty:
                LOGGER.error('data_queue peek timeout, break')
                break
            try:
                wfile.write(data)
                expect_begin += len(data)
            except socket.error as e:
                LOGGER.info('RangeFetch client connection aborted(%s).', e)
                break
        self._stopped = True

    def __fetchlet(self, range_queue, data_queue):
        headers = self.headers.copy()
        headers['Connection'] = 'close'
        while 1:
            try:
                if self._stopped:
                    return
                if data_queue.qsize() * self.bufsize > 180 * 1024 * 1024:
                    gevent.sleep(10)
                    continue
                try:
                    start, end, response = range_queue.get(timeout=1)
                    headers['Range'] = 'bytes=%d-%d' % (start, end)
                    fetchserver = ''
                    if not response:
                        fetchserver = random.choice(self.fetchservers)
                        if self._last_app_status.get(fetchserver, 200) >= 500:
                            gevent.sleep(5)
                        response = self.urlfetch(self.method, self.url, headers, self.payload, fetchserver,
                                                 password=self.password)
                except gevent.queue.Empty:
                    continue
                except socket.error:
                    logging.warning("Response SSLError in __fetchlet")
                if not response:
                    logging.warning('RangeFetch %s return %r', headers['Range'], response)
                    range_queue.put((start, end, None))
                    continue
                if fetchserver:
                    self._last_app_status[fetchserver] = response.app_status
                if response.app_status != 200:
                    logging.warning('Range Fetch "%s %s" %s return %s', self.method, self.url, headers['Range'],
                                    response.app_status)
                    response.close()
                    range_queue.put((start, end, None))
                    continue
                if response.getheader('Location'):
                    self.url = response.getheader('Location')
                    LOGGER.info('RangeFetch Redirect(%r)', self.url)
                    response.close()
                    range_queue.put((start, end, None))
                    continue
                if 200 <= response.status < 300:
                    content_range = response.getheader('Content-Range')
                    if not content_range:
                        logging.warning('RangeFetch "%s %s" return Content-Range=%r: response headers=%r', self.method,
                                        self.url, content_range, str(response.msg))
                        response.close()
                        range_queue.put((start, end, None))
                        continue
                    content_length = int(response.getheader('Content-Length', 0))
                    LOGGER.info('>>>>>>>>>>>>>>> [thread %s] %s %s', id(gevent.getcurrent()), content_length,
                                content_range)
                    while 1:
                        try:
                            data = response.read(self.bufsize)
                            if not data:
                                break
                            data_queue.put((start, data))
                            start += len(data)
                        except socket.error as e:
                            logging.warning('RangeFetch "%s %s" %s failed: %s', self.method, self.url, headers['Range'],
                                            e)
                            break
                    if start < end:
                        logging.warning('RangeFetch "%s %s" retry %s-%s', self.method, self.url, start, end)
                        response.close()
                        range_queue.put((start, end, None))
                        continue
                else:
                    LOGGER.error('RangeFetch %r return %s', self.url, response.status)
                    response.close()
                    #range_queue.put((start, end, None))
                    continue
            except Exception as e:
                LOGGER.exception('RangeFetch._fetchlet error:%s', e)
                raise