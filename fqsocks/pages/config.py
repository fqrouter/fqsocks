# -*- coding: utf-8 -*-
import httplib
import os.path
import fqlan

import jinja2

from .. import httpd


CONFIG_HTML_FILE = os.path.join(os.path.dirname(__file__), '..', 'templates', 'config.html')


@httpd.http_handler('GET', 'config')
def config_page(environ, start_response):
    start_response(httplib.OK, [('Content-Type', 'text/html')])
    with open(CONFIG_HTML_FILE) as f:
        template = jinja2.Template(unicode(f.read(), 'utf8'))
    default_interface_ip = fqlan.get_default_interface_ip()
    return [template.render(_=environ['select_text'], default_interface_ip=default_interface_ip).encode('utf8')]

