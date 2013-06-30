import logging
import socket
import sys
import base64

import gevent
import gevent.queue
import spdy.context
import spdy.frames

from http_try import recv_and_parse_request
from direct import Proxy
from spdy_client import SpdyClient
from spdy_client import WORKING


LOGGER = logging.getLogger(__name__)


class SpdyRelayProxy(Proxy):
    def __init__(self, proxy_ip, proxy_port, username=None, password=None, is_public=False):
        super(SpdyRelayProxy, self).__init__()
        self.proxy_ip = socket.gethostbyname(proxy_ip)
        self.proxy_port = proxy_port
        self.username = username
        self.password = password
        self.spdy_client = None
        if is_public:
            self.flags.add('PUBLIC')

    def connect(self):
        try:
            self.close()
            self.spdy_client = SpdyClient(self.proxy_ip, self.proxy_port)
        except:
            LOGGER.exception('failed to connect spdy-relay proxy: %s' % self)
            self.died = True

    def close(self):
        if self.spdy_client:
            self.spdy_client.close()

    def do_forward(self, client):
        recv_and_parse_request(client)
        headers = {
            ':method': client.method,
            ':scheme': 'http',
            ':path': client.path,
            ':version': 'HTTP/1.1',
            ':host': client.host
        }
        if self.username and self.password:
            auth = base64.b64encode('%s:%s' % (self.username, self.password)).strip()
            headers['proxy-authorization'] = 'Basic %s\r\n' % auth
        for k, v in client.headers.items():
            headers[k.lower()] = v
        request_content_length = int(headers.get('content-length', 0))
        response_content_length = sys.maxint
        stream_id = self.spdy_client.open_stream(headers, client)
        stream = self.spdy_client.streams[stream_id]
        while stream.received_bytes < response_content_length or stream.sent_bytes < request_content_length:
            stream.request_completed = stream.sent_bytes >= request_content_length
            try:
                frame = stream.upstream_frames.get(timeout=10)
            except gevent.queue.Empty:
                if client.forward_started:
                    return
                else:
                    return client.fall_back('no response from proxy')
            if WORKING == frame:
                continue
            if isinstance(frame, spdy.frames.SynReply):
                response_content_length = self.on_syn_reply_frame(client, frame)
            else:
                LOGGER.warn('[%s] unknown frame: %s %s' % (repr(client), frame, getattr(frame, 'frame_type')))

    def on_syn_reply_frame(self, client, frame):
        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.debug('[%s] syn reply: %s' % (repr(client), frame.headers))
        headers = dict(frame.headers)
        http_version = headers.pop(':version')
        status = headers.pop(':status')
        client.forward_started = True
        client.downstream_sock.sendall('%s %s\r\n' % (http_version, status))
        for k, v in headers.items():
            client.downstream_sock.sendall('%s: %s\r\n' % (k, v))
        client.downstream_sock.sendall('\r\n')
        if status.startswith('304'):
            return 0
        else:
            return int(headers.pop('content-length', sys.maxint))


    @classmethod
    def refresh(cls, proxies, create_udp_socket, create_tcp_socket):
        for proxy in proxies:
            proxy.connect()
        return True

    def is_protocol_supported(self, protocol):
        return protocol == 'HTTP'

    def __repr__(self):
        return 'SpdyRelayProxy[%s:%s]' % (self.proxy_ip, self.proxy_port)

