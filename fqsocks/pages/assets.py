# -*- coding: utf-8 -*-
import httplib
import os.path
import functools
from .. import httpd

ASSETS_DIR = os.path.join(os.path.dirname(__file__), '..', 'assets')

def get_asset(file_path, content_type, environ, start_response):
    start_response(httplib.OK, [('Content-Type', content_type)])
    with open(file_path) as f:
        return [f.read()]


httpd.HANDLERS[('GET', 'assets/ajax-loader.gif')] = functools.partial(
    get_asset, os.path.join(ASSETS_DIR, 'ajax-loader.gif'), 'image/gif')
httpd.HANDLERS[('GET', 'assets/bootstrap.min.css')] = functools.partial(
    get_asset, os.path.join(ASSETS_DIR, 'bootstrap.min.css'), 'text/css')
httpd.HANDLERS[('GET', 'assets/bootstrap.min.js')] = functools.partial(
    get_asset, os.path.join(ASSETS_DIR, 'bootstrap.min.js'), 'text/javascript')
httpd.HANDLERS[('GET', 'assets/jquery.min.js')] = functools.partial(
    get_asset, os.path.join(ASSETS_DIR, 'jquery.min.js'), 'text/javascript')
httpd.HANDLERS[('GET', 'assets/tablesort.min.js')] = functools.partial(
    get_asset, os.path.join(ASSETS_DIR, 'tablesort.min.js'), 'text/javascript')
httpd.HANDLERS[('GET', 'assets/visibility.core.js')] = functools.partial(
    get_asset, os.path.join(ASSETS_DIR, 'visibility.core.js'), 'text/javascript')
httpd.HANDLERS[('GET', 'assets/visibility.timer.js')] = functools.partial(
    get_asset, os.path.join(ASSETS_DIR, 'visibility.timer.js'), 'text/javascript')
