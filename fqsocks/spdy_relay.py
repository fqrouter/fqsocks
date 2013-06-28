import logging
import socket
import ssl
import sys
import _ssl
import struct
from uuid import uuid4
import gevent.ssl
import spdylay
import gevent
import gevent.event
import select

from direct import Proxy
from http_try import recv_and_parse_request


LOGGER = logging.getLogger(__name__)

# the ssl module used here is a modified version, does not work on vanilla python 2.7
class SpdyRelayProxy(Proxy):
    create_tcp_socket = None

    def __init__(self, proxy_ip, proxy_port, username=None, password=None, is_public=False):
        super(SpdyRelayProxy, self).__init__()
        assert ssl.HAS_NPN_SUPPORT
        self.proxy_ip = socket.gethostbyname(proxy_ip)
        self.proxy_port = proxy_port
        self.username = username
        self.password = password
        self.failed_times = 0
        self.resources = []
        self.streams = {} # stream_code => client
        if is_public:
            self.flags.add('PUBLIC')

    def connect(self):
        try:
            self.upstream_sock = self.create_tcp_socket(self.proxy_ip, self.proxy_port, 3)
            self.resources.append(self.upstream_sock)
            # ssl.wrap_socket does not work, because gevent does not know NPN modification we made
            self.upstream_sock = gevent.ssl.SSLSocket(self.upstream_sock, do_handshake_on_connect=False)
            self.resources.append(self.upstream_sock._sslobj)
            npn_protocols = ['spdy/3']
            if npn_protocols:
                npn_protocols = ''.join(
                    [struct.pack('b' + 'c' * len(p), len(p), *p)
                     for p in npn_protocols]
                )
            self.upstream_sock._sslobj = _ssl.sslwrap(
                self.upstream_sock._sock, False, None, None, ssl.CERT_NONE, ssl.PROTOCOL_SSLv23, None, npn_protocols,
                None)
            self.resources.append(self.upstream_sock._sslobj)
        except:
            LOGGER.exception('[%s] spdy-relay upstream socket connect failed' % self)
            self.died = True
            return
        try:
            self.upstream_sock.do_handshake()
            LOGGER.debug(
                '[%s] spdy-relay selected protocol %s' % (self, self.upstream_sock._sslobj.selected_protocol()))
        except:
            LOGGER.exception('[%s] spdy-relay upstream socket handshake failed' % self)
            self.died = True
            return
        self.spdylay_session = spdylay.Session(
            spdylay.CLIENT, spdylay.PROTO_SPDY3,
            send_cb=self.spdylay_send_cb,
            on_ctrl_recv_cb=self.spdylay_on_ctrl_recv_cb,
            on_data_chunk_recv_cb=self.spdylay_on_data_chunk_recv_cb,
            on_stream_close_cb=self.spdylay_on_stream_close_cb)
        self.spdylay_loop_greenlet = gevent.spawn(self.spdylay_loop)

    def spdylay_loop(self):
        self.upstream_sock.settimeout(0)
        try:
            while not self.died:
                if self.spdylay_session.want_read():
                    try:
                        data = self.upstream_sock.recv(4096)
                        if data:
                            self.spdylay_session.recv(data)
                        else:
                            break
                    except ssl.SSLError:
                        select.select([self.upstream_sock], [], [], 1)
                if self.spdylay_session.want_write():
                    try:
                        self.spdylay_session.send()
                    except ssl.SSLError:
                        select.select([], [self.upstream_sock], [], 1)
        except:
            LOGGER.exception('[%s] spdylay loop failed' % self)
        LOGGER.info('!!! spdylay loop quit !!!')
        self.died = True

    def spdylay_send_cb(self, session, data):
        return self.upstream_sock.send(data)


    def spdylay_read_cb(self, session, stream_id, length, read_ctrl, source):
        try:
            stream_code = self.spdylay_session.get_stream_user_data(stream_id)
            client, async_result = self.streams[stream_code]
            if client.remaining_payload_len > 0:
                if client.payload:
                    data = client.payload[:length]
                    client.payload = client.payload[length:]
                else:
                    data = client.downstream_sock.recv(length)
                client.remaining_payload_len -= len(data)
                return data
            else:
                read_ctrl.flags = spdylay.READ_EOF
        except:
            LOGGER.exception('[%s] spdylay_read_cb' % self)


    def spdylay_on_stream_close_cb(self, session, stream_id, status_code):
        try:
            stream_code = self.spdylay_session.get_stream_user_data(stream_id)
            try:
                client, async_result = self.streams[stream_code]
                try:
                    client.close()
                    async_result.set()
                except:
                    async_result.set_exception(sys.exc_info()[1])
            finally:
                del self.streams[stream_code]
        except:
            LOGGER.exception('[%s] spdylay_on_stream_close_cb' % self)


    def spdylay_on_ctrl_recv_cb(self, session, frame):
        try:
            if frame.frame_type == spdylay.SYN_REPLY:
                headers = dict(frame.nv)
                status = headers.pop(':status')
                version = headers.pop(':version')
                stream_code = self.spdylay_session.get_stream_user_data(frame.stream_id)
                client, async_result = self.streams[stream_code]
                client.forward_started = True
                client.downstream_sock.sendall('%s %s\r\n' % (version, status))
                for k, v in headers.items():
                    client.downstream_sock.sendall('%s: %s\r\n' % (k, v))
                client.downstream_sock.sendall('\r\n')
        except:
            LOGGER.exception('[%s] spdylay_on_ctrl_recv_cb' % self)


    def spdylay_on_data_chunk_recv_cb(self, session, flags, stream_id, data):
        try:
            stream_code = self.spdylay_session.get_stream_user_data(stream_id)
            client, async_result = self.streams[stream_code]
            client.downstream_sock.sendall(data)
        except:
            LOGGER.exception('[%s] spdylay_on_data_chunk_recv_cb' % self)


    def do_forward(self, client):
        is_payload_complete = recv_and_parse_request(client)
        client.headers['Connection'] = 'close' # no keep-alive
        headers = [(':method', client.method),
                   (':scheme', 'http'),
                   (':path', client.path),
                   (':version', 'HTTP/1.1'),
                   (':host', client.host)]
        for k, v in client.headers.items():
            headers.append((k, v))
        stream_code = str(uuid4())
        async_result = gevent.event.AsyncResult()
        self.streams[stream_code] = (client, async_result)
        client.remaining_payload_len = int(client.headers.get('Content-Length', 0))
        client.data_prd = spdylay.DataProvider(None, self.spdylay_read_cb)
        self.spdylay_session.submit_request(
            0, headers, data_prd=client.data_prd, stream_user_data=stream_code)
        async_result.wait()


    @classmethod
    def refresh(cls, proxies, create_udp_socket, create_tcp_socket):
        for proxy in proxies:
            proxy.connect()
        return True

    def is_protocol_supported(self, protocol):
        return protocol == 'HTTP'

    def __repr__(self):
        return 'SpdyRelayProxy[%s:%s]' % (self.proxy_ip, self.proxy_port)


class DataProvider(object):
    def __init__(self, read_cb, source=None):
        self.source = source
        self.read_cb = read_cb