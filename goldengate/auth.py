import hmac
import base64
import http
import time
import random
import setup

from policy import Policy


# Map of entity => entity's credentials
CREDENTIALS = [
    ('Mike', {'key': 'foo', 'secret': 'bar'}),
]


def _utf8_str(s):
    if isinstance(s, unicode):
        return s.encode('utf-8')
    else:
        return str(s)


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

    @property
    def aws_action(self):
        return self.url.parameters['Action']

    def get_normalized_parameters(self):
        """
        Returns an ordered list of all of the parameters required in the
        signature.

        """
        return http.urlencode([(_utf8_str(k), _utf8_str(v)) for k, v in
                            sorted(self.url.parameters.iteritems())
                            if k != 'Signature'])

    def get_normalized_http_method(self):
        return self.method

    def get_normalized_http_host(self):
        host = self.url.host.lower()
        scheme = self.url.scheme.lower()
        if scheme == 'http' and host.endswith(':80') or \
           scheme == 'https' and host.endswith(':443'):
            host = ''.join(host.split(':')[:-1])
        return host

    def get_normalized_http_path(self):
        # For an empty path use '/'
        return self.url.path if self.url.path else '/'

    def signed_request(self, signature_method, aws_key, aws_secret):
        parameters = self.url.parameters
        parameters['AWSAccessKeyId'] = aws_key
        parameters['SignatureVersion'] = signature_method.version
        parameters['SignatureMethod'] = signature_method.name
        parameters['Timestamp'] = generate_timestamp()
        prepared = self._clone(url=http.clone_url(self.url, parameters=parameters))

        parameters['Signature'] = signature_method.build_signature(prepared, aws_secret)
        return self._clone(url=http.clone_url(prepared.url, parameters=parameters))


class SignatureMethod(object):

    @property
    def name(self):
        raise NotImplementedError

    def build_signature_base_string(self, request):
        signature = '\n'.join((
            request.get_normalized_http_method(),
            request.get_normalized_http_host(),
            request.get_normalized_http_path(),
            request.get_normalized_parameters(),
        ))
        return signature

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
        try:
            aws_key = request.url.parameters['AWSAccessKeyId']
            signature = request.url.parameters['Signature']
            signature_method = request.url.parameters['SignatureMethod']
            signature_version = request.url.parameters['SignatureVersion']
        except KeyError:
            raise UnauthenticatedException('missing required signature parameters')

        entity, aws_secret = self.get_key_details(aws_key)
        signer = self.get_signature_method(signature_method, signature_version)

        expected_signature = signer.build_signature(request._clone(klass=AWSQueryRequest), aws_secret)
        if _are_equal(signature, expected_signature):
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
    signature_method = SignatureMethod_HMAC_SHA256()

    def authorized(self, entity, request):
        if not entity in [credential[0] for credential in CREDENTIALS]:
            raise UnauthenticatedException()
        else:
            return Policy.for_request(request).grant(entity, request)

    def sign(self, entity, request):
        aws_request = request._clone(klass=AWSQueryRequest)
        if self.authorized(entity, aws_request):
            return aws_request.signed_request(self.signature_method, setup.AWS_KEY, setup.AWS_SECRET)
        else:
            raise UnauthorizedException(entity, request)

