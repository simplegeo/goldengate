# TODO:
#  - Response object assumes utf-8. Is that ok?
#  - Does Request.relative_uri cover all bases? How 'bout URI fragment IDs?


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


class Request(object):
    def __init__(self, environ, start_response):
        self._environ = environ
        self._start_response = start_response
    
    @property
    def path(self):
        return self._environ.get('PATH_INFO', '')
    
    @property
    def query(self):
        return self._environ.get('QUERY_STRING')

    @property
    def relative_uri(self):
        if self.query is not None:
            return '?'.join((self.path, self.query))
        else:
            return self.path

    @property
    def method(self):
        return self._environ.get('REQUEST_METHOD', 'GET').upper()

    @property
    def headers(self):
        headers = dict([(key[5:].replace('_', '-').lower(), value) 
                        for key, value in self._environ.iteritems() if key.startswith('HTTP_')])
        headers['content-type'] = self._environ.get('CONTENT_TYPE')
        return headers

    @property
    def content_length(self):
        try:
            return int(self._environ.get('CONTENT_LENGTH', 0))
        except ValueError:
            return 0

    @property
    def body(self):
        return self._environ['wsgi.input'].read(self.content_length)

    def to_dict(self):
        return {
            'relative_uri': self.relative_uri,
            'method': self.method,
            'headers': self.headers,
            'body': self.body,
        }


class Response(object):
    headers = []
    charset = 'utf8'
    
    def __init__(self, output, status=200, content_type='application/x-www-form-urlencoded', headers=None):
        self.output = output
        self.status = status
        if ';' in content_type:
            encoding = content_type.split(';')
            assert len(encoding) == 2
            self.content_type = encoding[0].strip()
            self.charset = encoding[1].strip()
        else:
            self.content_type = content_type
        if headers is not None:
            self.headers = headers

    def send(self, start_response):
        status = '%d %s' % (self.status, STATUS_CODES.get(self.status))
        headers = Response.encode_headers([('content-type', '%s; charset=%s' % (self.content_type, self.charset))] + self.headers)
        start_response(status, headers)
        if isinstance(self.output, unicode):
            return self.output.encode(self.charset)
        else:
            return self.output

    @classmethod
    def encode_headers(cls, headers):
        # Headers must be ascii.
        def _encode(data):
            if isinstance(data, unicode):
                return data.encode('us-ascii')
            else:
                return str(data)
        return [(_encode(key), _encode(value)) for key, value in headers]

