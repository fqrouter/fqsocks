# -*- coding: utf-8 -*-
import httplib
import os.path
import jinja2
from .. import httpd

DONWSTREAM_HTML_FILE = os.path.join(os.path.dirname(__file__), '..', 'templates', 'downstream.html')

@httpd.http_handler('GET', 'downstream')
def downstream_page(environ, start_response):
    with open(DONWSTREAM_HTML_FILE) as f:
        template = jinja2.Template(unicode(f.read(), 'utf8'))
    start_response(httplib.OK, [('Content-Type', 'text/html')])
    return [template.render(_=environ['select_text']).encode('utf8')]
