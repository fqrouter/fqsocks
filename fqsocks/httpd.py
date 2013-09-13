import logging
import httplib
import cgi
import sys
from gevent.wsgi import WSGIServer

LOGGER = logging.getLogger(__name__)
HANDLERS = {

}


def handle_request(environ, start_response):
    method = environ.get('REQUEST_METHOD')
    path = environ.get('PATH_INFO', '').strip('/')
    environ['REQUEST_ARGUMENTS'] = cgi.FieldStorage(
        fp=environ['wsgi.input'],
        environ=environ,
        keep_blank_values=True)
    handler = HANDLERS.get((method, path))
    if handler:
        try:
            lines = handler(environ, lambda status, headers: start_response(get_http_response(status), headers))
        except:
            LOGGER.exception('failed to handle request: %s %s' % (method, path))
            raise
    else:
        start_response(get_http_response(httplib.NOT_FOUND), [('Content-Type', 'text/plain')])
        lines = []
    for line in lines:
        yield line


def get_http_response(code):
    return '%s %s' % (code, httplib.responses[code])


def homepage(environ, start_response):
    start_response(httplib.TEMPORARY_REDIRECT, [('Location', '/proxies')])
    return []


def serve_forever():
    try:
        HANDLERS[('GET', '')] = homepage
        httpd = WSGIServer(('', 2515), handle_request)
        LOGGER.info('serving HTTP on port 2515...')
    except:
        LOGGER.exception('failed to start HTTP server on port 2515')
        sys.exit(1)
    httpd.serve_forever()