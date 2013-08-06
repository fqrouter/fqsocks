# -*- coding: utf-8 -*-
import httpd
import httplib
import time

counters = [] # not closed or closed within 5 minutes
proxy_stats = {}

PROXY_LIST_PAGE = """
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
</head>
<body>
<pre>|</pre>
</body>
</html>
"""

def list_counters(environ, start_response):
    start_response(httplib.OK, [('Content-Type', 'text/plain')])
    for counter in counters:
        yield '%s\n' % str(counter)


def list_proxies(environ, start_response):
    start_response(httplib.OK, [('Content-Type', 'text/html')])
    proxies = {}
    for counter in counters:
        proxies.setdefault(counter.proxy, []).append(counter)
    after = time.time() - 10
    yield PROXY_LIST_PAGE.split('|')[0]
    for proxy, proxy_counters in sorted(proxies.items(), key=lambda (proxy, proxy_counters): format_proxy_name(proxy)):
        rx_bytes_list, rx_seconds_list, _ = zip(*[counter.total_rx(after) for counter in proxy_counters])
        rx_bytes = sum(rx_bytes_list)
        rx_seconds = sum(rx_seconds_list)
        if rx_seconds:
            rx_speed = rx_bytes/(rx_seconds * 1000)
        else:
            rx_speed = 0
        tx_bytes_list, tx_seconds_list, _ = zip(*[counter.total_tx(after) for counter in proxy_counters])
        tx_bytes = sum(tx_bytes_list)
        tx_seconds = sum(tx_seconds_list)
        if tx_seconds:
            tx_speed = tx_bytes/(tx_seconds * 1000)
        else:
            tx_speed = 0
        proxy_name = format_proxy_name(proxy)
        if not proxy_name:
            continue
        yield '%s\trx\t%0.2fkb/s\t%s\ttx\t%0.2fkb/s\t%s\n' % \
              (proxy_name,
               rx_speed,
               to_human_readable_size(proxy_stats.get(proxy, {}).get('tx', 0)),
               tx_speed,
               to_human_readable_size(proxy_stats.get(proxy, {}).get('rx', 0)))
    yield PROXY_LIST_PAGE.split('|')[1]

def format_proxy_name(proxy):
    if 'DynamicProxy' == proxy.__class__.__name__:
        if 'GoAgentProxy' == proxy.delegated_to.__class__.__name__:
            return 'GoAgent\t公共代理\t#%s' % proxy.dns_record.replace('.fqrouter.com', '').replace('goagent', '')
        elif 'ShadowSocksProxy' == proxy.delegated_to.__class__.__name__:
            return 'SS\t公共代理\t#%s' % proxy.dns_record.replace('.fqrouter.com', '').replace('ss', '')
        elif 'HttpConnectProxy' == proxy.delegated_to.__class__.__name__:
            return 'HTTP\t公共代理\t#%s' % proxy.dns_record.replace('.fqrouter.com', '').replace('proxy', '')
        else:
            return None # ignore
    return None

def to_human_readable_size(num):
    for x in ['B','KB','MB','GB','TB']:
        if num < 1024.0:
            return '%06.2f %s' % (num, x)
        num /= 1024.0

httpd.HANDLERS[('GET', 'counters')] = list_counters
httpd.HANDLERS[('GET', 'proxies')] = list_proxies


def opened(proxy, host, ip):
    return Counter(proxy, host, ip)


class Counter(object):
    def __init__(self, proxy, host, ip):
        self.proxy = proxy
        self.host = host
        self.ip = ip
        self.opened_at = time.time()
        self.closed_at = None
        self.rx_events = []
        self.tx_events = []
        if '127.0.0.1' != self.ip:
            counters.append(self)
        proxy_stats.setdefault(self.proxy, {'tx':0, 'rx': 0})

    def sending(self, bytes_count):
        proxy_stats[self.proxy]['tx'] += bytes_count
        self.tx_events.append((time.time(), bytes_count))


    def received(self, bytes_count):
        proxy_stats[self.proxy]['rx'] += bytes_count
        self.rx_events.append((time.time(), bytes_count))

    def total_rx(self, after=0):
        if not self.rx_events:
            return 0, 0, 0
        bytes = sum(bytes for rx_at, bytes in self.rx_events if rx_at > after)
        if not bytes:
            return 0, 0, 0
        seconds = self.rx_events[-1][0] - max(after, self.opened_at)
        return bytes, seconds, bytes/(seconds * 1000)

    def total_tx(self, after=0):
        if not self.tx_events:
            return 0, 0, 0
        matched_tx_events = [(tx_at, bytes) for tx_at, bytes in self.tx_events if tx_at > after]
        if not matched_tx_events:
            return 0, 0, 0
        bytes = sum(bytes for _, bytes in matched_tx_events)
        ended_at = self.closed_at or time.time()
        seconds = ended_at - matched_tx_events[0][0]
        return bytes, seconds, bytes/(seconds * 1000)


    def close(self):
        self.closed_at = time.time()

    def __str__(self):
        rx_bytes, rx_seconds, rx_speed = self.total_rx()
        tx_bytes, tx_seconds, tx_speed = self.total_tx()
        return '[%s~%s] %s%s via %s rx %0.2fkb/s(%s/%s) tx %0.2fkb/s(%s/%s)' % (
            self.opened_at, self.closed_at or '',
            self.ip, '(%s)' % self.host if self.host else '', self.proxy,
            rx_speed, rx_bytes, rx_seconds,
            tx_speed, tx_bytes, tx_seconds)