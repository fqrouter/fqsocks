import logging
import socket
import base64

import gevent
import gevent.queue
import spdy.context
import spdy.frames

from direct import Proxy
from spdy_client import SpdyClient
from spdy_client import WORKING


LOGGER = logging.getLogger(__name__)


class SpdyConnectProxy(Proxy):
    def __init__(self, proxy_ip, proxy_port, username=None, password=None, is_public=False):
        super(SpdyConnectProxy, self).__init__()
        self.proxy_ip = socket.gethostbyname(proxy_ip)
        self.proxy_port = proxy_port
        self.username = username
        self.password = password
        self.spdy_client = None
        if is_public:
            self.flags.add('PUBLIC')
        self.died = True
        self.loop_greenlet = None

    def connect(self):
        try:
            if self.loop_greenlet:
                self.loop_greenlet.kill()
            self.loop_greenlet = gevent.spawn(self.loop)
        except:
            LOGGER.exception('failed to connect spdy-connect proxy: %s' % self)
            self.died = True

    def loop(self):
        try:
            while True:
                self.close()
                self.spdy_client = SpdyClient(self.proxy_ip, self.proxy_port)
                self.died = False
                try:
                    self.spdy_client.loop()
                except:
                    LOGGER.exception('spdy client loop failed')
                finally:
                    LOGGER.info('spdy client loop quit')
                self.died = True
        except:
            LOGGER.exception('spdy connect loop failed')

    def close(self):
        if self.spdy_client:
            self.spdy_client.close()
            self.spdy_client = None

    def do_forward(self, client):
        headers = {
            ':method': 'CONNECT',
            ':scheme': 'https',
            ':path': '%s:%s' % (client.dst_ip, client.dst_port),
            ':version': 'HTTP/1.1',
            ':host': '%s:%s' % (client.dst_ip, client.dst_port)
        }
        if self.username and self.password:
            auth = base64.b64encode('%s:%s' % (self.username, self.password)).strip()
            headers['proxy-authorization'] = 'Basic %s\r\n' % auth
        client.payload = client.peeked_data
        stream_id = self.spdy_client.open_stream(headers, client)
        stream = self.spdy_client.streams[stream_id]
        try:
            while not stream.done:
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
                    self.on_syn_reply_frame(client, frame)
                elif isinstance(frame, spdy.frames.RstStream):
                    LOGGER.info('[%s] rst: %s' % (repr(client), frame))
                    return
                else:
                    LOGGER.warn('!!! [%s] unknown frame: %s %s !!!'
                                % (repr(client), frame, getattr(frame, 'frame_type')))
        finally:
            self.spdy_client.end_stream(stream_id)

    def on_syn_reply_frame(self, client, frame):
        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.debug('[%s] syn reply: %s' % (repr(client), frame.headers))
        headers = dict(frame.headers)
        status = headers.pop(':status')
        if not status.startswith('200'):
            LOGGER.error('[%s] proxy rejected CONNECT: %s' % (repr(client), status))
            self.died = True
            self.loop_greenlet.kill()


    @classmethod
    def refresh(cls, proxies, create_udp_socket, create_tcp_socket):
        for proxy in proxies:
            proxy.connect()
        return True

    def is_protocol_supported(self, protocol):
        return protocol == 'HTTPS'

    def __repr__(self):
        return 'SpdyConnectProxy[%s:%s]' % (self.proxy_ip, self.proxy_port)

