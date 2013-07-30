# thanks @phuslu modified from https://github.com/goagent/goagent/blob/2.0/local/proxy.py
# coding:utf-8
import logging
import socket
import time
import sys
import re
import functools
import fnmatch
import urllib
import _goagent # local/proxy.py from goagent
import httplib
import ssl
import gevent.queue
import random

import networking
from direct import Proxy
from http_try import recv_and_parse_request
import contextlib
import re


LOGGER = logging.getLogger(__name__)
_goagent.logging = LOGGER

RE_VERSION = re.compile(r'\d+\.\d+\.\d+')
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

AUTORANGE_HOSTS = '*.c.youtube.com|*.atm.youku.com|*.googlevideo.com|*av.vimeo.com|smile-*.nicovideo.jp|' \
                  'video.*.fbcdn.net|s*.last.fm|x*.last.fm|*.x.xvideos.com|*.edgecastcdn.net|*.d.rncdn3.com|' \
                  'cdn*.public.tube8.com|videos.flv*.redtubefiles.com|cdn*.public.extremetube.phncdn.com|' \
                  'cdn*.video.pornhub.phncdn.com|*.mms.vlog.xuite.net|vs*.thisav.com|archive.rthk.hk|' \
                  'video*.modimovie.com'.split('|')
AUTORANGE_HOSTS = tuple(AUTORANGE_HOSTS)
AUTORANGE_HOSTS_MATCH = [re.compile(fnmatch.translate(h)).match for h in AUTORANGE_HOSTS]
AUTORANGE_ENDSWITH = '.f4v|.flv|.hlv|.m4v|.mp4|.mp3|.ogg|.avi|.exe|.zip|.iso|.rar|.bz2|.xz|.dmg'.split('|')
AUTORANGE_ENDSWITH = tuple(AUTORANGE_ENDSWITH)
AUTORANGE_NOENDSWITH = '.xml|.json|.html|.php|.py.js|.css|.jpg|.jpeg|.png|.gif|.ico'.split('|')
AUTORANGE_NOENDSWITH = tuple(AUTORANGE_NOENDSWITH)
AUTORANGE_MAXSIZE = 1048576
AUTORANGE_WAITSIZE = 524288
AUTORANGE_BUFSIZE = 8192
AUTORANGE_THREADS = 2

tcp_connection_time = {}
ssl_connection_time = {}
normcookie = functools.partial(re.compile(', ([^ =]+(?:=|$))').sub, '\\r\\nSet-Cookie: \\1')


class GoAgentProxy(Proxy):
    GOOGLE_HOSTS = ['www.g.cn', 'www.google.cn', 'www.google.com', 'mail.google.com']
    GOOGLE_IPS = []
    proxies = []

    def __init__(self, appid, path='/2', password=False, validate=0):
        super(GoAgentProxy, self).__init__()
        self.appid = appid
        self.path = path
        self.password = password
        self.validate = validate
        if not self.appid:
            self.died = True
        self.version = 'UNKNOWN'
        self.flags.add('PUBLIC')

    def query_version(self):
        try:
            sock = networking.create_tcp_socket(random.choice(list(self.GOOGLE_IPS)), 443, 3)
            with contextlib.closing(sock):
                sock = ssl.wrap_socket(sock)
                sock.settimeout(3)
                with contextlib.closing(sock):
                    sock.sendall('GET https://%s.appspot.com/2 HTTP/1.1\r\n\r\n\r\n' % self.appid)
                    response = sock.recv(8192)
                    match = RE_VERSION.search(response)
                    if 'Over Quota' in response:
                        self.died = True
                        LOGGER.info('%s over quota' % self)
                        return
                    if match:
                        self.version = match.group(0)
                        LOGGER.info('queried appid version: %s' % self)
                    else:
                        LOGGER.info('failed to query appid version: %s' % response)
        except:
            LOGGER.exception('failed to query goagent %s version' % self.appid)

    def do_forward(self, client):
        recv_and_parse_request(client)
        LOGGER.info('[%s] urlfetch %s %s' % (repr(client), client.method, client.url))
        forward(client, self, [p.appid for p in self.proxies if not p.died])

    @classmethod
    def is_protocol_supported(cls, protocol):
        return 'HTTP' == protocol

    @classmethod
    def refresh(cls, proxies):
        _goagent.socket = FakeSocketModule()
        _goagent.socket.socket = None
        _goagent.http_util.dns_resolve = lambda *args, **kwargs: cls.GOOGLE_IPS
        cls.proxies = proxies
        resolved_google_ips = cls.resolve_google_ips()
        if resolved_google_ips:
            for proxy in proxies:
                gevent.spawn(proxy.query_version)
        else:
            for proxy in proxies:
                proxy.died = not resolved_google_ips
        return resolved_google_ips

    @classmethod
    def resolve_google_ips(cls):
        if cls.GOOGLE_IPS:
            return True
        LOGGER.info('resolving google ips from %s' % cls.GOOGLE_HOSTS)
        all_ips = set()
        selected_ips = set()
        for host in cls.GOOGLE_HOSTS:
            if re.match(r'\d+\.\d+\.\d+\.\d+', host):
                selected_ips.add(host)
            else:
                ips = networking.resolve_ips(host)
                if len(ips) > 1:
                    all_ips |= set(ips)
        if not selected_ips and not all_ips:
            LOGGER.fatal('failed to resolve google ip')
            return False
        queue = gevent.queue.Queue()
        greenlets = []
        try:
            for ip in all_ips:
                greenlets.append(gevent.spawn(test_google_ip, queue, ip))
            deadline = time.time() + 5
            for i in range(min(3, len(all_ips))):
                try:
                    timeout = deadline - time.time()
                    if timeout > 0:
                        selected_ips.add(queue.get(timeout=1))
                    else:
                        selected_ips.add(queue.get(block=False))
                except:
                    break
            if selected_ips:
                cls.GOOGLE_IPS = selected_ips
                LOGGER.info('found google ip: %s' % cls.GOOGLE_IPS)
            else:
                cls.GOOGLE_IPS = list(all_ips)[:3]
                LOGGER.error('failed to find working google ip, fallback to first 3: %s' % cls.GOOGLE_IPS)
            return True
        finally:
            for greenlet in greenlets:
                greenlet.kill(block=False)

    def __repr__(self):
        return 'GoAgentProxy[%s ver %s]' % (self.appid, self.version)



def test_google_ip(queue, ip):
    try:
        sock = networking.create_tcp_socket(ip, 443, 5)
        ssl_sock = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_TLSv1)
        try:
            ssl_sock.do_handshake()
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
    except gevent.GreenletExit:
        pass
    except:
        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.debug('failed to test google ip: %s' % ip, exc_info=1)
        else:
            LOGGER.info('failed to test google ip: %s %s' % (ip, sys.exc_info()[1]))


def forward(client, proxy, appids):
    parsed_url = urllib.parse.urlparse(client.url)
    range_in_query = 'range=' in parsed_url.query
    special_range = (any(x(client.host) for x in AUTORANGE_HOSTS_MATCH) or client.url.endswith(
        AUTORANGE_ENDSWITH)) and not client.url.endswith(AUTORANGE_NOENDSWITH)
    range_end = 0
    auto_ranged = False
    if 'Range' in client.headers:
        LOGGER.info('[%s] range present: %s' % (repr(client), client.headers['Range']))
        m = re.search('bytes=(\d+)-(\d*)', client.headers['Range'])
        if m:
            range_start = int(m.group(1))
            range_end = int(m.group(2)) if m.group(2) else 0
            if not range_end or range_end - range_start > AUTORANGE_MAXSIZE:
                client.headers['Range'] = 'bytes=%d-%d' % (range_start, range_start + AUTORANGE_MAXSIZE)
                LOGGER.info('[%s] adjusted range: %s' % (repr(client), client.headers['Range']))
    elif not range_in_query and special_range:
        client.headers['Range'] = 'bytes=%d-%d' % (0, AUTORANGE_MAXSIZE)
        auto_ranged = True
        LOGGER.info('[%s] auto range: %s' % (repr(client), client.headers['Range']))
    response = None
    try:
        kwargs = {}
        if proxy.password:
            kwargs['password'] = proxy.password
        if proxy.validate:
            kwargs['validate'] = 1
        fetchserver = 'https://%s.appspot.com%s?' % (proxy.appid, proxy.path)
        response = _goagent.gae_urlfetch(
            client.method, client.url, client.headers, client.payload, fetchserver,
            create_tcp_socket=client.create_tcp_socket, **kwargs)
        if response is None:
            client.fall_back('urlfetch empty response')
        if response.app_status == 503:
            proxy.died = True
            client.fall_back('goagent server over quota')
        if response.app_status == 404:
            proxy.died = True
            client.fall_back('goagent server not found')
        if response.app_status == 302:
            proxy.died = True
            client.fall_back('goagent server 302 moved')
        if response.app_status == 403 and 'youtube.com' in client.url:
            proxy.died = True
            client.fall_back('goagent server %s banned youtube' % proxy)
        if response.app_status != 200:
            if LOGGER.isEnabledFor(logging.DEBUG):
                LOGGER.debug('HTTP/1.1 %s\r\n%s\r\n' % (response.status, ''.join(
                    '%s: %s\r\n' % (k.title(), v) for k, v in response.getheaders() if k != 'transfer-encoding')))
                LOGGER.debug(response.read())
            client.fall_back('urlfetch failed: %s' % response.app_status)
        client.forward_started = True
        if response.status == 206:
            LOGGER.info('[%s] start range fetch' % repr(client))
            fetchservers = [fetchserver]
            fetchservers += ['https://%s.appspot.com/2?' % appid for appid in appids]
            rangefetch = _goagent.RangeFetch(
                range_end, auto_ranged, client.downstream_wfile, response, client.method, client.url, client.headers, client.payload,
                fetchservers, proxy.password, maxsize=AUTORANGE_MAXSIZE, bufsize=AUTORANGE_BUFSIZE,
                waitsize=AUTORANGE_WAITSIZE, threads=AUTORANGE_THREADS, create_tcp_socket=client.create_tcp_socket)
            return rangefetch.fetch()
        if 'Set-Cookie' in response.msg:
            response.msg['Set-Cookie'] = normcookie(response.msg['Set-Cookie'])
        client.downstream_wfile.write('HTTP/1.1 %s\r\n%s\r\n' % (response.status, ''.join(
            '%s: %s\r\n' % (k.title(), v) for k, v in response.getheaders() if k != 'transfer-encoding')))
        content_length = int(response.getheader('Content-Length', 0))
        content_range = response.getheader('Content-Range', '')
        if content_range:
            start, end, length = list(map(int, re.search(r'bytes (\d+)-(\d+)/(\d+)', content_range).group(1, 2, 3)))
        else:
            start, end, length = 0, content_length-1, content_length
        while 1:
            try:
                data = response.read(8192)
            except httplib.IncompleteRead as e:
                LOGGER.error('incomplete read: %s' % e.partial)
                raise
            if not data:
                response.close()
                return
            start += len(data)
            client.downstream_wfile.write(data)
            if start >= end:
                response.close()
                return
    finally:
        if response:
            response.close()


class FakeSocketModule(object):
    def __getattr__(self, item):
        return getattr(socket, item)