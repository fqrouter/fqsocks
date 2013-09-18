import httplib
from .. import httpd


@httpd.http_handler('GET', '')
def status_page(environ, start_response):
    start_response(httplib.TEMPORARY_REDIRECT, [('Location', '/upstream')])
    return []

