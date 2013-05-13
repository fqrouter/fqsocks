import socket
import logging

LOGGER = logging.getLogger(__name__)


class DirectProxy(object):
    def connect_upstream(self, client):
        client.upstream_sock.connect((client.dst_ip, client.dst_port))
        return True