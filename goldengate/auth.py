import hmac
import base64
import http
import urlparse
import urllib
import time
import random
try:
    from urlparse import parse_qs
except ImportError:
    from cgi import parse_qs
import setup


# Map of entity => entity's credentials
CREDENTIALS = [
    ('Mike', {'key': 'foo', 'secret': 'bar'}),
]


def _utf8_str(s):
    if isinstance(s, unicode):
        return s.encode('utf-8')
    else:
        return str(s)


def escape(s):
    return urllib.quote(s, safe='-_~')


def urlencode(d):
    if isinstance(d, dict):
        d = d.iteritems()
    return '&'.join(['%s=%s' % (escape(k), escape(v)) for k, v in d])


def generate_timestamp():
    return time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime())


def _are_equal(this, that):
    # Because someone is going to complain about timing attacks.
    if len(this) != len(that):
        return False
    rot = random.randint(0, len(this)-1)
    return (this[:rot] + this[rot:]) == (that[:rot] + that[rot:])


class UnauthorizedException(Exception):
    def __init__(self, entity, request):
        self.entity = entity
        self.request = request
        super(UnauthorizedException, self).__init__("%s is not authorized to make request." % (entity,))


class UnauthenticatedException(Exception):
    def __init__(self, details='<no details>'):
        super(UnauthenticatedException, self).__init__("Request requires authentication (%s)." % (details,))


class AWSQueryRequest(http.Request):
    """
    A request that uses Amazon AWS's token-based signature authentication,
    mostly used by their various REST APIs.

    """

    def __init__(self, request):
        self._request = request
        if 'HTTP_HOST' in request._environ:
            self.host = request._environ['HTTP_HOST']
        else:
            self.host = request._environ['SERVER_NAME']

        parameters = parse_qs(request.query)
        for k, v in parameters.iteritems():
            parameters[k] = urllib.unquote(v[0])
        self.parameters = parameters

    def __getattr__(self, name):
        # delegate anything not overridden to self._request.
        return getattr(self._request, name)

    @property
    def query(self):
        return urlencode(self.parameters)

    @property
    def relative_uri(self):
        if self.query is not None:
            return '?'.join((self.path, self.query))
        else:
            return self.path

    def set_parameter(self, name, value):
        self.parameters[name] = value

    def get_normalized_parameters(self):
        """
        Returns an ordered list of all of the parameters required in the
        signature.

        """
        return urlencode([(_utf8_str(k), _utf8_str(v)) for k, v in
                            sorted(self.parameters.iteritems())
                            if k != 'Signature'])

    def get_normalized_http_method(self):
        return self.method

    def get_normalized_http_host(self):
        return self.host.lower()

    def get_normalized_http_path(self):
        # For an empty path use '/'
        return self.path if self.path else '/'

    def sign_request(self, signature_method, aws_key, aws_secret):
        self.set_parameter('AWSAccessKeyId', aws_key)
        self.set_parameter('SignatureVersion', signature_method.version)
        self.set_parameter('SignatureMethod', signature_method.name)
        self.set_parameter('Timestamp', generate_timestamp())
        self.set_parameter('Signature', signature_method.build_signature(self, aws_secret))


class SignatureMethod(object):

    @property
    def name(self):
        raise NotImplementedError

    def build_signature_base_string(self, request):
        sig = '\n'.join((
            request.get_normalized_http_method(),
            request.get_normalized_http_host(),
            request.get_normalized_http_path(),
            request.get_normalized_parameters(),
        ))
        return sig

    def build_signature(self, request, aws_secret):
        raise NotImplementedError


class SignatureMethod_HMAC_SHA1(SignatureMethod):
    name = 'HmacSHA1'
    version = '2'

    def build_signature(self, request, aws_secret):
        base = self.build_signature_base_string(request)
        try:
            import hashlib # 2.5
            hashed = hmac.new(aws_secret, base, hashlib.sha1)
        except ImportError:
            import sha # deprecated
            hashed = hmac.new(aws_secret, base, sha)
        return base64.b64encode(hashed.digest())


class SignatureMethod_HMAC_SHA256(SignatureMethod):
    name = 'HmacSHA256'
    version = '2'

    def build_signature(self, request, aws_secret):
        import hashlib
        base = self.build_signature_base_string(request)
        hashed = hmac.new(aws_secret, base, hashlib.sha256)
        return base64.b64encode(hashed.digest())


class AWSAuthenticator(object):
    TIMESTAMP_THRESHOLD = 300 # In seconds, five minutes.
    signature_methods = [SignatureMethod_HMAC_SHA1(), SignatureMethod_HMAC_SHA256()]

    def authenticate(self, request):
        # Returns the authentic identity of the requester.
        aws_request = AWSQueryRequest(request)
        entity, aws_secret = self.get_key_details(aws_request.parameters['AWSAccessKeyId'])
        signature_method = self.get_signature_method(
            aws_request.parameters['SignatureMethod'],
            aws_request.parameters['SignatureVersion']
        )

        actual_signature = aws_request.parameters['Signature']
        expected_signature = signature_method.build_signature(aws_request, aws_secret)
        if _are_equal(actual_signature, expected_signature):
            return entity
        else:
            raise UnauthenticatedException('signature mismatch')

    @classmethod
    def get_key_details(cls, aws_key):
        for entity, credentials in CREDENTIALS:
            if credentials['key'] == aws_key:
                return entity, credentials['secret']
        raise UnauthenticatedException('signature mismatch')

    @classmethod
    def get_signature_method(cls, name, version):
        for method in cls.signature_methods:
            if method.name == name and method.version == version:
                return method
        raise UnauthenticatedException('invalid signature method or signature version')


class AWSAuthorizer(object):
    def authorized(self, entity, request):
        if not entity in [credential[0] for credential in CREDENTIALS]:
            raise UnauthenticatedException()
        else:
            return True

    def sign(self, entity, request):
        if self.authorized(entity, request):
            aws_request = AWSQueryRequest(request)
            aws_request.sign_request(SignatureMethod_HMAC_SHA256(), setup.AWS_KEY, setup.AWS_SECRET)
            return aws_request
        else:
            raise UnauthorizedException(entity, request)

