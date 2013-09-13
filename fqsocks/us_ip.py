import urllib2
import json
import logging
import httplib
from . import networking

LOGGER = logging.getLogger(__name__)

US_IP_CACHE = {}


def is_us_ip(ip):
    if ip in US_IP_CACHE:
        return US_IP_CACHE[ip]
    try:
        class MyHTTPConnection(httplib.HTTPConnection):
            def connect(self):
                self.host = networking.resolve_ips(self.host)[0]
                return httplib.HTTPConnection.connect(self)

        class MyHTTPHandler(urllib2.HTTPHandler):
            def http_open(self, req):
                return self.do_open(MyHTTPConnection, req)

        opener = urllib2.build_opener(MyHTTPHandler)
        response = opener.open('http://ip.taobao.com/service/getIpInfo.php?ip=%s' % ip)
        response = json.loads(response.read())
        yes = 'US' == response['data']['country_id']
        US_IP_CACHE[ip] = yes
        LOGGER.info('queried ip %s is us ip %s' % (ip, yes))
        return yes
    except:
        LOGGER.exception('failed to query geo ip')
        return False
