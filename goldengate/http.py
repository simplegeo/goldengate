import urllib
from collections import namedtuple
try:
    from urlparse import parse_qs
except ImportError:
    from cgi import parse_qs


STATUS_CODES = {
    100: 'CONTINUE',
    101: 'SWITCHING PROTOCOLS',
    200: 'OK',
    201: 'CREATED',
    202: 'ACCEPTED',
    203: 'NON-AUTHORITATIVE INFORMATION',
    204: 'NO CONTENT',
    205: 'RESET CONTENT',
    206: 'PARTIAL CONTENT',
    300: 'MULTIPLE CHOICES',
    301: 'MOVED PERMANENTLY',
    302: 'FOUND',
    303: 'SEE OTHER',
    304: 'NOT MODIFIED',
    305: 'USE PROXY',
    306: 'RESERVED',
    307: 'TEMPORARY REDIRECT',
    400: 'BAD REQUEST',
    401: 'UNAUTHORIZED',
    402: 'PAYMENT REQUIRED',
    403: 'FORBIDDEN',
    404: 'NOT FOUND',
    405: 'METHOD NOT ALLOWED',
    406: 'NOT ACCEPTABLE',
    407: 'PROXY AUTHENTICATION REQUIRED',
    408: 'REQUEST TIMEOUT',
    409: 'CONFLICT',
    410: 'GONE',
    411: 'LENGTH REQUIRED',
    412: 'PRECONDITION FAILED',
    413: 'REQUEST ENTITY TOO LARGE',
    414: 'REQUEST-URI TOO LONG',
    415: 'UNSUPPORTED MEDIA TYPE',
    416: 'REQUESTED RANGE NOT SATISFIABLE',
    417: 'EXPECTATION FAILED',
    500: 'INTERNAL SERVER ERROR',
    501: 'NOT IMPLEMENTED',
    502: 'BAD GATEWAY',
    503: 'SERVICE UNAVAILABLE',
    504: 'GATEWAY TIMEOUT',
    505: 'HTTP VERSION NOT SUPPORTED',
}


class HTTPException(Exception):
    """
    An HTTPException indicates some sort of HTTP error condition (probably a
    4XX) that should be returned as an HTTP response to the client.

    """
    type = 'error'

    def __init__(self, status=400, headers=None, body=''):
        self.status = status
        self.headers = headers if headers is not None else []
        self.body = body
        super(HTTPException, self).__init__(body)

    def to_response(self):
        return Response(self.status, self.headers, self.body)


def escape(s):
    return urllib.quote(s, safe='-_~')


def urlencode(d):
    if isinstance(d, dict):
        d = d.iteritems()
    return '&'.join(['%s=%s' % (escape(k), escape(v)) for k, v in d])


URL = namedtuple('URL', 'scheme host path parameters')


STANDARD_PORTS = {
    'http': '80',
    'https': '443',
}
def url_from_environ(environ):
    if environ.get('HTTP_HOST'):
        host = environ['HTTP_HOST']
    else:
        host = environ['SERVER_NAME']
        if STANDARD_PORTS.get(environ['wsgi.url_scheme']) != environ['SERVER_PORT']:
            host += ':' + environ['SERVER_PORT']

    # Ignoring the distinction between empty query string and no
    # query string.
    parameters = parse_qs(environ.get('QUERY_STRING', ''))
    for k, v in parameters.iteritems():
        parameters[k] = urllib.unquote(v[0])

    # Ignoring SCRIPT_NAME and URL fragments.
    return URL(
        scheme=environ['wsgi.url_scheme'],
        host=host,
        path=environ.get('PATH_INFO', ''),
        parameters=parameters,
    )


def headers_from_environ(environ):
    headers = dict([(key[5:].replace('_', '-').lower(), value)
                    for key, value in environ.iteritems() if key.startswith('HTTP_')])
    if 'CONTENT_TYPE' in environ:
        headers['content-type'] = environ['CONTENT_TYPE']
    if 'CONTENT_LENGTH' in environ:
        headers['content-length'] = environ['CONTENT_LENGTH']
    return headers


def clone_url(url, **kwargs):
    opts = {
        'scheme': url.scheme,
        'host': url.host,
        'path': url.path,
        'parameters': url.parameters.copy(),
    }
    opts.update(kwargs)
    return URL(**opts)


class Request(object):
    """
    Request encapsulates information related to an HTTP request.

    """

    def __init__(self, method, url, headers, body, callback):
        self.method = method.upper()
        self.url = url
        if isinstance(headers, dict):
            self.headers = headers.items()
        else:
            self.headers = headers[:]
        self.body = body
        self.callback = callback

    @classmethod
    def from_wsgi(cls, environ, start_response):
        return cls(
            method=environ.get('REQUEST_METHOD', 'GET'),
            url=url_from_environ(environ),
            headers=headers_from_environ(environ),
            body=environ['wsgi.input'].read(),
            callback=start_response,
        )

    def get_url(self):
        url = self.url.scheme + '://' + self.url.host + self.url.path
        if self.url.parameters:
            url += '?' + urlencode(self.url.parameters)
        return url

    def _clone(self, klass=None, **kwargs):
        if klass is None:
            klass = self.__class__
        opts = {
            'method': self.method,
            'url': clone_url(self.url),
            'headers': self.headers,
            'body': self.body,
            'callback': self.callback,
        }
        opts.update(kwargs)
        return klass(**opts)

    def to_dict(self):
        return {
            'url': self.get_url(),
            'method': self.method,
            'headers': self.headers,
            'body': self.body,
        }


class Response(object):
    """
    A response object wraps a status, a list of headers, and a response body. It
    also has a send method that accepts a WSGI-stype start_response callable
    which it immediately calls with the status line and headers, and returns the
    response body.

    """

    def __init__(self, status=200, headers=None, body=''):
        self.status = status
        if isinstance(headers, dict):
            headers = headers.items()
        self.headers = headers if headers is not None else []
        self.body = body

    def send(self, start_response):
        status = '%d %s' % (self.status, STATUS_CODES.get(self.status))
        start_response(status, self.headers)
        if isinstance(self.body, unicode):
            return self.body.encode(self.charset)
        else:
            return self.body

    @classmethod
    def encode_headers(cls, headers):
        "Properly encode a dict of headers. They must be ascii."
        def _encode(data):
            if isinstance(data, unicode):
                return data.encode('us-ascii')
            else:
                return str(data)
        return [(_encode(key), _encode(value)) for key, value in headers]
