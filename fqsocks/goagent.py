# thanks @phuslu modified from https://github.com/goagent/goagent/blob/2.0/local/proxy.py
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
import fnmatch
import ssl

import gevent.queue

from direct import Proxy
from http_try import recv_and_parse_request


LOGGER = logging.getLogger(__name__)

SKIP_HEADERS = frozenset(
    ['Vary', 'Via', 'X-Forwarded-For', 'Proxy-Authorization', 'Proxy-Connection', 'Upgrade', 'X-Chrome-Variations',
     'Connection', 'Cache-Control'])
ABBV_HEADERS = {'Accept': ('A', lambda x: '*/*' in x),
                'Accept-Charset': ('AC', lambda x: x.startswith('UTF-8,')),
                'Accept-Language': ('AL', lambda x: x.startswith('zh-CN')),
                'Accept-Encoding': ('AE', lambda x: x.startswith('gzip,')), }
GAE_OBFUSCATE = 0
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
tcp_connection_time = {}
ssl_connection_time = {}
normcookie = functools.partial(re.compile(', ([^ =]+(?:=|$))').sub, '\\r\\nSet-Cookie: \\1')


class GoAgentProxy(Proxy):
    GOOGLE_HOSTS = ['www.g.cn', 'www.google.cn', 'www.google.com', 'mail.google.com']
    GOOGLE_IPS = []

    def __init__(self, appid, resolve_at='8.8.8.8', password=False, validate=0):
        super(GoAgentProxy, self).__init__()
        self.appid = appid
        self.resolve_at = resolve_at
        self.password = password
        self.validate = validate
        if not self.appid:
            self.died = True

    def do_forward(self, client):
        recv_and_parse_request(client)
        LOGGER.info('[%s] urlfetch %s %s' % (repr(client), client.method, client.url))
        forward(client, self)

    @classmethod
    def is_protocol_supported(cls, protocol):
        return 'HTTP' == protocol

    @classmethod
    def refresh(cls, proxies, create_sock):
        return cls.resolve_google_ips(create_sock)

    @classmethod
    def resolve_google_ips(cls, create_sock):
        if cls.GOOGLE_IPS:
            return True
        LOGGER.info('resolving google ips from %s' % cls.GOOGLE_HOSTS)
        all_ips = set()
        selected_ips = set()
        for host in cls.GOOGLE_HOSTS:
            if re.match(r'\d+\.\d+\.\d+\.\d+', host):
                selected_ips.add(host)
            else:
                ips = resolve_google_ips(host)
                if len(ips) > 1:
                    all_ips |= set(ips)
        if not selected_ips and not all_ips:
            LOGGER.fatal('failed to resolve google ip')
            return False
        queue = gevent.queue.Queue()
        greenlets = []
        try:
            for ip in all_ips:
                greenlets.append(gevent.spawn(test_google_ip, queue, create_sock, ip))
                gevent.sleep(0.1)
            for i in range(min(3, len(all_ips))):
                try:
                    selected_ips.add(queue.get(timeout=1))
                except:
                    break
            if selected_ips:
                cls.GOOGLE_IPS = selected_ips
                LOGGER.info('found google ip: %s' % cls.GOOGLE_IPS)
            else:
                cls.GOOGLE_IPS = all_ips[:3]
                LOGGER.error('failed to find working google ip, fallback to first 3: %s' % cls.GOOGLE_IPS)
            return True
        finally:
            for greenlet in greenlets:
                greenlet.kill(block=False)

    def __repr__(self):
        return 'GoAgentProxy[%s]' % self.appid


def resolve_google_ips(host):
    for i in range(3):
        try:
            return gevent.spawn(socket.gethostbyname_ex, host).get(timeout=3)[-1]
        except:
            if LOGGER.isEnabledFor(logging.DEBUG):
                LOGGER.debug('failed to resolve google ips', exc_info=1)
    return []


def test_google_ip(queue, create_sock, ip):
    try:
        sock = create_sock()
        sock.settimeout(5)
        ssl_sock = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_TLSv1)
        try:
            ssl_sock.connect((ip, 443))
            request = 'GET / HTTP/1.1\r\n'
            request += 'Host: googcloudlabs.appspot.com\r\n'
            request += 'Connection: close\r\n'
            request += '\r\n'
            ssl_sock.sendall(request)
            response = ssl_sock.recv(8192)
            if 'Google App Engine' in response:
                queue.put(ip)
        finally:
            ssl_sock.close()
    except:
        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.debug('failed to test google ip', exc_info=1)


def forward(client, proxy):
    if 'Range' in client.headers:
        m = re.search('bytes=(\d+)-', client.headers['Range'])
        start = int(m.group(1) if m else 0)
        client.headers['Range'] = 'bytes=%d-%d' % (start, start + AUTORANGE_MAXSIZE - 1)
        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.debug('[%s] range found in headers: %s' % (repr(client), client.headers['Range']))
    elif client.host.endswith(AUTORANGE_HOSTS_TAIL) and not RE_DO_NOT_RANGE.match(client.url):
        try:
            pattern = (p for p in AUTORANGE_HOSTS if client.host.endswith(p) or fnmatch.fnmatch(client.host, p)).next()
            m = re.search('bytes=(\d+)-', client.headers.get('Range', ''))
            start = int(m.group(1) if m else 0)
            client.headers['Range'] = 'bytes=%d-%d' % (start, start + AUTORANGE_MAXSIZE - 1)
            if LOGGER.isEnabledFor(logging.DEBUG):
                LOGGER.debug('[%s] auto range pattern=%s: %s' % (repr(client), pattern, client.headers['Range']))
        except StopIteration:
            pass
    try:
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
        if response.app_status == 503:
            proxy.died = True
            client.fall_back('over quota')
        if response.app_status == 404:
            proxy.died = True
            client.fall_back('goagent server not found')
        if response.app_status != 200:
            client.downstream_wfile.write('HTTP/1.1 %s\r\n%s\r\n' % (response.status, ''.join(
                '%s: %s\r\n' % (k.title(), v) for k, v in response.getheaders() if k != 'transfer-encoding')))
            client.downstream_wfile.write(response.read())
            response.close()
            return
        if response.status == 206:
            return gae_range_urlfetch(client, proxy, response)

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


def gae_urlfetch(client, proxy, headers=None, **kwargs):
    headers = headers or client.headers.copy()
    payload = client.payload
    # deflate = lambda x:zlib.compress(x)[2:-4]
    if payload:
        if len(payload) < 10 * 1024 * 1024 and b'Content-Encoding' not in headers:
            zpayload = zlib.compress(payload)[2:-4]
            if len(zpayload) < len(payload):
                payload = zpayload
                headers[b'Content-Encoding'] = b'deflate'
        headers[b'Content-Length'] = str(len(payload))
    metadata = 'G-Method:%s\nG-Url:%s\n%s' % (
        client.method, client.url, ''.join('G-%s:%s\n' % (k, v) for k, v in kwargs.items() if v))
    if GAE_OBFUSCATE and 'X-Requested-With' not in headers:
        # not a ajax request, we could abbv the headers
        g_abbv = []
        for keyword in [x for x in headers if x not in SKIP_HEADERS]:
            value = headers[keyword]
            if keyword in ABBV_HEADERS and ABBV_HEADERS[keyword][1](value):
                g_abbv.append(ABBV_HEADERS[keyword][0])
            else:
                metadata += '%s:%s\n' % (keyword, value)
        if g_abbv:
            metadata += 'G-Abbv:%s\n' % ','.join(g_abbv)
    else:
        metadata += ''.join('%s:%s\n' % (k, v) for k, v in headers.items() if k not in SKIP_HEADERS)
    metadata = zlib.compress(metadata)[2:-4]
    if GAE_OBFUSCATE:
        cookie = base64.b64encode(metadata).strip()
        if not payload:
            response = http_request(
                client, proxy, 'GET', payload, {b'Cookie': cookie})
        else:
            response = http_request(
                client, proxy, 'POST', payload, {b'Cookie': cookie, b'Content-Length': len(payload)})
    else:
        payload = '%s%s%s' % (struct.pack('!h', len(metadata)), metadata, payload)
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
    sock = create_ssl_connection(client)
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


def create_ssl_connection(client, timeout=None, max_timeout=16, max_retry=4, max_window=4):
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
            client.add_resource(ssl_sock)
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

    addresses = [(google_ip, 443) for google_ip in GoAgentProxy.GOOGLE_IPS]
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
    client.fall_back('connect to google ip failed')


def gae_range_urlfetch(client, proxy, response):
    client.range_urlfetch_stopped = False
    client._last_app_status = {}
    response_status = response.status
    response_headers = dict((k.title(), v) for k, v in response.getheaders())
    content_range = response_headers['Content-Range']
    #content_length = response_headers['Content-Length']
    start, end, length = map(int, re.search(r'bytes (\d+)-(\d+)/(\d+)', content_range).group(1, 2, 3))
    if start == 0:
        response_status = 200
        response_headers['Content-Length'] = str(length)
    else:
        response_headers['Content-Range'] = 'bytes %s-%s/%s' % (start, end, length)
        response_headers['Content-Length'] = str(length - start)

    LOGGER.info('>>>>>>>>>>>>>>> RangeFetch started(%r) %d-%d', client.url, start, end)
    client.downstream_wfile.write('HTTP/1.1 %s\r\n%s\r\n' % (
        response_status, ''.join('%s: %s\r\n' % (k, v) for k, v in response_headers.items())))

    data_queue = gevent.queue.PriorityQueue()
    range_queue = gevent.queue.PriorityQueue()
    range_queue.put((start, end, response))
    for begin in range(end + 1, length, AUTORANGE_MAXSIZE):
        range_queue.put((begin, min(begin + AUTORANGE_MAXSIZE - 1, length - 1), None))
    for i in xrange(AUTORANGE_THREADS):
        gevent.spawn(gae_range_urlfetch_worker, client, proxy, range_queue, data_queue)
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
            client.downstream_wfile.write(data)
            expect_begin += len(data)
        except socket.error as e:
            LOGGER.info('RangeFetch client connection aborted(%s).', e)
            break
    client.range_urlfetch_stopped = True


def gae_range_urlfetch_worker(client, proxy, range_queue, data_queue):
    headers = client.headers.copy()
    headers['Connection'] = 'close'
    while 1:
        try:
            if client.range_urlfetch_stopped:
                return
            if data_queue.qsize() * AUTORANGE_BUFSIZE > 180 * 1024 * 1024:
                gevent.sleep(10)
                continue
            try:
                start, end, response = range_queue.get(timeout=1)
                headers['Range'] = 'bytes=%d-%d' % (start, end)
                if not response:
                    if client._last_app_status.get(proxy.appid, 200) >= 500:
                        gevent.sleep(5)
                    response = gae_urlfetch(client, proxy, headers)
            except gevent.queue.Empty:
                continue
            except socket.error:
                LOGGER.warning("Response SSLError in __fetchlet")
            if not response:
                LOGGER.warning('RangeFetch %s return %r', headers['Range'], response)
                range_queue.put((start, end, None))
                continue
            client._last_app_status[proxy.appid] = response.app_status
            if response.app_status != 200:
                LOGGER.warning('Range Fetch "%s %s" %s return %s', client.method, client.url, headers['Range'],
                               response.app_status)
                response.close()
                range_queue.put((start, end, None))
                continue
            if response.getheader('Location'):
                client.url = response.getheader('Location')
                LOGGER.info('RangeFetch Redirect(%r)', client.url)
                response.close()
                range_queue.put((start, end, None))
                continue
            if 200 <= response.status < 300:
                content_range = response.getheader('Content-Range')
                if not content_range:
                    LOGGER.warning('RangeFetch "%s %s" return Content-Range=%r: response headers=%r', client.method,
                                   client.url, content_range, str(response.msg))
                    response.close()
                    range_queue.put((start, end, None))
                    continue
                content_length = int(response.getheader('Content-Length', 0))
                LOGGER.info('>>>>>>>>>>>>>>> [thread %s] %s %s', id(gevent.getcurrent()), content_length,
                            content_range)
                while 1:
                    try:
                        data = response.read(AUTORANGE_BUFSIZE)
                        if not data:
                            break
                        data_queue.put((start, data))
                        start += len(data)
                    except socket.error as e:
                        LOGGER.warning('RangeFetch "%s %s" %s failed: %s', client.method, client.url, headers['Range'],
                                       e)
                        break
                if start < end:
                    LOGGER.warning('RangeFetch "%s %s" retry %s-%s', client.method, client.url, start, end)
                    response.close()
                    range_queue.put((start, end, None))
                    continue
            else:
                LOGGER.error('RangeFetch %r return %s', client.url, response.status)
                response.close()
                #range_queue.put((start, end, None))
                continue
        except Exception as e:
            LOGGER.exception('RangeFetch._fetchlet error:%s', e)
            raise