# -*- coding: utf-8 -*-
import httpd
import httplib
import time

counters = [] # not closed or closed within 5 minutes

PROXY_LIST_PAGE = """
<html>
<head>
<meta http-equiv="refresh" content="1" />
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
    after = time.time() - 60 * 10
    yield PROXY_LIST_PAGE.split('|')[0]
    for proxy, proxy_counters in sorted(proxies.items(), key=lambda (proxy, proxy_counters): proxy.public_name):
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
        if not proxy.public_name:
            continue
        yield '%s\trx\t%0.2fKB/s\t%s\ttx\t%0.2fKB/s\t%s\n' % \
              (proxy.public_name,
               rx_speed,
               to_human_readable_size(rx_bytes),
               tx_speed,
               to_human_readable_size(tx_bytes))
    yield PROXY_LIST_PAGE.split('|')[1]


def to_human_readable_size(num):
    for x in ['B','KB','MB','GB','TB']:
        if num < 1024.0:
            return '%06.2f %s' % (num, x)
        num /= 1024.0

httpd.HANDLERS[('GET', 'counters')] = list_counters
httpd.HANDLERS[('GET', 'proxies')] = list_proxies


def opened(proxy, host, ip):
    if hasattr(proxy, 'shown_as'):
        proxy = proxy.shown_as
    return Counter(proxy, host, ip)


class Counter(object):
    def __init__(self, proxy, host, ip):
        self.proxy = proxy
        self.host = host
        self.ip = ip
        self.opened_at = time.time()
        self.closed_at = None
        self.events = []
        if '127.0.0.1' != self.ip:
            counters.append(self)

    def sending(self, bytes_count):
        self.events.append(('tx', time.time(), bytes_count))


    def received(self, bytes_count):
        self.events.append(('rx', time.time(), bytes_count))

    def total_rx(self, after=0):
        if not self.events:
            return 0, 0, 0
        bytes = 0
        seconds = 0
        last_event_time = self.opened_at
        for event_type, event_time, event_bytes in self.events:
            if event_time > after and 'rx' == event_type:
                seconds += (event_time - last_event_time)
                bytes += event_bytes
            last_event_time = event_time
        if not bytes:
            return 0, 0, 0
        return bytes, seconds, bytes/(seconds * 1000)

    def total_tx(self, after=0):
        if not self.events:
            return 0, 0, 0
        bytes = 0
        seconds = 0
        pending_tx_events = []
        for event_type, event_time, event_bytes in self.events:
            if event_time > after:
                if 'tx' == event_type:
                    pending_tx_events.append((event_time, event_bytes))
                else:
                    if pending_tx_events:
                        seconds += (event_time - pending_tx_events[-1][0])
                        bytes += sum(b for _, b in pending_tx_events)
                    pending_tx_events = []
        if pending_tx_events:
            seconds += ((self.closed_at or time.time()) - pending_tx_events[0][0])
            bytes += sum(b for _, b in pending_tx_events)
        if not bytes:
            return 0, 0, 0
        return bytes, seconds, bytes/(seconds * 1000)



    def close(self):
        self.closed_at = time.time()

    def __str__(self):
        rx_bytes, rx_seconds, rx_speed = self.total_rx()
        tx_bytes, tx_seconds, tx_speed = self.total_tx()
        return '[%s~%s] %s%s via %s rx %0.2fKB/s(%s/%s) tx %0.2fKB/s(%s/%s)' % (
            self.opened_at, self.closed_at or '',
            self.ip, '(%s)' % self.host if self.host else '', self.proxy,
            rx_speed, rx_bytes, rx_seconds,
            tx_speed, tx_bytes, tx_seconds)