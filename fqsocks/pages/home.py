# -*- coding: utf-8 -*-
import httplib
import logging
import os.path
from datetime import datetime

import jinja2

from .. import httpd
from ..gateways import proxy_client
from ..proxies.http_try import HTTP_TRY_PROXY
from .. import config_file


HOME_HTML_FILE = os.path.join(os.path.dirname(__file__), '..', 'templates', 'home.html')
LOGGER = logging.getLogger(__name__)

@httpd.http_handler('GET', '')
def home_page(environ, start_response):
    with open(HOME_HTML_FILE) as f:
        template = jinja2.Template(unicode(f.read(), 'utf8'))
    last_refresh_started_at = datetime.fromtimestamp(proxy_client.last_refresh_started_at)
    start_response(httplib.OK, [('Content-Type', 'text/html')])
    return template.render(
        _=environ['select_text'],
        last_refresh_started_at=last_refresh_started_at,
        proxies_enabled=len(proxy_client.proxies) > 0,
        tcp_scrambler_enabled=HTTP_TRY_PROXY.tcp_scrambler_enabled,
        youtube_scrambler_enabled=HTTP_TRY_PROXY.youtube_scrambler_enabled,
        china_shortcut_enabled=proxy_client.china_shortcut_enabled,
        direct_access_enabled=proxy_client.direct_access_enabled,
        config=config_file.read_config()).encode('utf8')