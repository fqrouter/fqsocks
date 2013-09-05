import urllib2
import json
import logging

LOGGER = logging.getLogger(__name__)

US_IP_CACHE = {}


def is_us_ip(ip):
    if ip in US_IP_CACHE:
        return US_IP_CACHE[ip]
    try:
        response = urllib2.urlopen('http://ip.taobao.com/service/getIpInfo.php?ip=%s' % ip)
        response = json.loads(response.read())
        yes = 'US' == response['data']['country_id']
        US_IP_CACHE[ip] = yes
        LOGGER.info('queried ip %s is us ip %s' % (ip, yes))
        return yes
    except:
        LOGGER.exception('failed to query geo ip')
        return False
