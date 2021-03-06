"""
Tests are good.
"""

import unittest
import urllib
import time
try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO
from goldengate import goldengate, http, auth, policy, kvstore, credentials, settings, config

from nose.plugins.skip import SkipTest


SIMPLEDB_TEST_DOMAIN = 'goldengatetests' # This has to be created already.
MEMCACHED_TEST_HOST = 'localhost:11211'


class StartResponse(object):
    status = None
    headers = None
    def __call__(self, status, headers):
        self.status = status
        self.headers = headers


class WSGIInput(object):
    def __init__(self, *args, **kwargs):
        self._wrapped = StringIO(*args, **kwargs)
    def __getattr__(self, name):
        return getattr(self._wrapped, name)


class MockAuthorizer(object):
    authorized = True
    entity = None
    request = None
    def authorize(self, entity, request):
        self.entity = entity
        self.request = request
        if self.authorized:
            return request
        else:
            raise auth.UnauthorizedException(self.entity)


class MockAuthenticator(object):
    authenticated = True
    entity = object()
    def __init__(self, credentials):
        self.credentials = credentials
    def authenticate(self, request):
        self.request = request
        if self.authenticated:
            return self.entity
        else:
            raise auth.UnauthenticatedException(self.entity)


class MockAuditor(object):
    def __init__(self):
        self.records = []
    def record(self, entity, action):
        self.records.append((entity, action))


class MockProxy(object):
    response = object()
    def request(self, request):
        self.request = request
        return self.response


class GGTestCase(unittest.TestCase):
    """
    Base test case that defines a couple handy dandy helper assertions and other fun stuff.
    """

    def assertHTTPExceptionEquals(self, exception, status, headers, body):
        self.assertTrue(isinstance(exception, http.HTTPException))
        self.assertEquals(exception.status, status)
        self.assertEquals(exception.headers, headers)
        self.assertEquals(exception.body, body)
        response = exception.to_response()
        self.assertEquals(response.status, status)

        dhead = dict(response.headers)
        self.assert_('Content-Length' in dhead)
        self.assert_(len(body) == dhead['Content-Length'])
        del dhead['Content-Length']
        response.headers = dhead.items()

        self.assertEquals(response.headers, headers)
        self.assertEquals(response.body, body)
        start_response = StartResponse()
        response_body = response.send(start_response)
        self.assert_(isinstance(response_body, type(iter([]))))
        response_body = list(response_body)
        self.assert_(len(response_body) == 1)
        response_body = response_body[0]
        self.assertEquals(response_body, body)
        self.assertEquals(start_response.status, '%d %s' % (status, http.STATUS_CODES.get(status)))
        self.assertEquals(start_response.headers, headers)

    def assertGoldenGateRequestOk(self, goldengate, request, response):
        self.assertTrue(response is goldengate.proxy.response)
        self.assertEquals(len(goldengate.auditor.records), 1)
        record = self.goldengate.auditor.records[0]
        self.assertTrue(record[0] is self.goldengate.authenticator.entity)
        self.assertEquals(record[1][0], 'applied')
        request_dict, proxy_request_dict = record[1][1]
        for key, value in request.to_dict().iteritems():
            self.assertEquals(request_dict[key], value)
        for key, value in goldengate.proxy.request.to_dict().iteritems():
            self.assertEquals(proxy_request_dict[key], value)


class GoldenGateTests(GGTestCase):
    def setUp(self):
        url = http.URL('http', 'example.com', '/foo/bar/', {'monkey': 'wrench'})
        self.request = http.Request('get', url, {'sups': 'word'}, '', StartResponse())
        self.goldengate = goldengate.GoldenGate(authenticator=MockAuthenticator, authorizer=MockAuthorizer, auditor=MockAuditor, proxy=MockProxy)

    def test_request(self):
        response = self.goldengate.handle(self.request)
        self.assertGoldenGateRequestOk(self.goldengate, self.request, response)

    def test_handler(self):
        class FakeResponse(object):
            def send(self, start_response):
                self.start_response = start_response
        response = FakeResponse()
        self.goldengate.proxy.response = response
        handler = goldengate.Handler(self.goldengate)
        environ = {
            'PATH_INFO': '/foo/bar/',
            'REQUEST_METHOD': 'POST',
            'QUERY_STRING': 'monkey=wrench&foo=bar',
            'HTTP_HOST': 'example.com:8000',
            'CONTENT_TYPE': 'application/x-www-form-urlencoded',
            'wsgi.url_scheme': 'https',
            'wsgi.input': WSGIInput(),
        }
        start_response = StartResponse()
        request = http.Request.from_wsgi(environ, start_response)
        handler(environ, start_response)
        self.assertGoldenGateRequestOk(self.goldengate, request, response)

    def test_unauthorized_request(self):
        self.goldengate.authorizer.authorized = False
        self.assertRaises(auth.UnauthorizedException, self.goldengate.handle, self.request)

    def test_unauthenticated_request(self):
        self.goldengate.authenticator.authenticated = False
        self.assertRaises(auth.UnauthenticatedException, self.goldengate.handle, self.request)


class ConfigTests(unittest.TestCase):
    def test_class_setting(self):
        setting = config.ClassSetting()
        setting.set('goldengate.auth.aws.Authorizer')
        self.assertTrue(setting.get() is auth.aws.Authorizer)


class HttpTests(GGTestCase):

    def setUp(self):
        self.environ = {
            'PATH_INFO': '/', 
            'REQUEST_METHOD': 'post', 
            'QUERY_STRING': '', 
            'HTTP_HOST': 'example.com:8000', 
            'CONTENT_TYPE': 'application/x-www-form-urlencoded',
            'wsgi.url_scheme': 'http',
            'wsgi.input': WSGIInput(),
        }

    def request(self, environ):
        return http.Request.from_wsgi(environ, StartResponse())

    def test_url(self):
        request = http.Request.from_wsgi(self.environ, StartResponse())
        self.assertEquals(request.method, 'POST')
        self.assertEquals(request.get_url(), 'http://example.com:8000/')
        self.assertEquals(len(request.headers), 2)
        self.assertEquals(dict(request.headers)['host'], 'example.com:8000')
        self.assertEquals(dict(request.headers)['content-type'], 'application/x-www-form-urlencoded')
        self.assertEquals(request.body, '')

    def test_bad_query(self):
        self.environ['QUERY_STRING'] = '!'
        request = self.request(self.environ)
        self.assertEquals(request.url.parameters, {})

    def test_server_name_no_http_host(self):
        self.environ['SERVER_NAME'] = 'another.example.com'
        self.environ['SERVER_PORT'] = '8080'
        self.environ.pop('HTTP_HOST')
        request = self.request(self.environ)
        self.assertEquals(request.get_url(), 'http://another.example.com:8080/')
        self.assertFalse('host' in request.headers)

    def test_default_port_not_in_canonical_url(self):
        self.environ['HTTP_HOST'] = 'another.example.com'
        self.assertEquals(self.request(self.environ).get_url(), 'http://another.example.com/')

        self.environ.pop('HTTP_HOST')
        self.environ['SERVER_NAME'] = 'another.example.com'
        self.environ['SERVER_PORT'] = '80'
        self.assertEquals(self.request(self.environ).get_url(), 'http://another.example.com/')

        self.environ['wsgi.url_scheme'] = 'https'
        self.assertEquals(self.request(self.environ).get_url(), 'https://another.example.com:80/')

        self.environ['SERVER_PORT'] = '443'
        self.assertEquals(self.request(self.environ).get_url(), 'https://another.example.com/')

        self.environ['HTTP_HOST'] = 'another.example.com'
        self.assertEquals(self.request(self.environ).get_url(), 'https://another.example.com/')

    def test_some_scheme_other_than_http(self):
        self.environ['wsgi.url_scheme'] = 'webdav'
        self.environ['SERVER_PORT'] = '80'
        self.environ['HTTP_HOST'] = 'example.com:80'
        self.assertEquals(self.request(self.environ).get_url(), 'webdav://example.com:80/')

    def test_empty_path_info(self):
        self.environ['PATH_INFO'] = ''
        self.assertEquals(self.request(self.environ).get_url(), 'http://example.com:8000')

    def test_https_scheme(self):
        self.environ['wsgi.url_scheme'] = 'https'
        self.assertEquals(self.request(self.environ).get_url(), 'https://example.com:8000/')

    def test_server_name_and_port_no_http_host(self):
        self.environ.pop('HTTP_HOST')
        self.environ['SERVER_NAME'] = 'snarf.example.com'
        self.environ['SERVER_PORT'] = '80'
        self.assertEquals(self.request(self.environ).get_url(), 'http://snarf.example.com/')

    def test_http_host_overrides_server_name(self):
        self.environ['SERVER_NAME'] = 'snarf.example.com'
        self.environ['SERVER_PORT'] = '80'
        self.assertEquals(self.request(self.environ).get_url(), 'http://example.com:8000/')

    def test_missing_content_type(self):
        self.environ.pop('CONTENT_TYPE')
        self.assertFalse('content-type' in self.request(self.environ).headers)
        # content-type is just passed through... so I guess this is expected behavior?
        self.environ['CONTENT_TYPE'] = None
        self.assertTrue(dict(self.request(self.environ).headers)['content-type'] is None)

    def test_fancy_path(self):
        path = '/foo/bar/../~/index.php'
        self.environ['PATH_INFO'] = path
        self.assertEquals(self.request(self.environ).get_url(), 'http://example.com:8000' + path)

    def test_big_ole_query_string(self):
        parameters = {
            'foo': 'snarf!',
            'BOo!)@#*': 'woot',
            'a_really_long_parameter_name': 'with an even longer value that has lots of white space and other special characters!!! ;-) oh, also some utf8 ' + unichr(420).encode('utf8'),
        }
        query = '&'.join('%s=%s' % (urllib.quote(k, safe='-_~'), urllib.quote(v, safe='-_~')) for k, v in parameters.iteritems())
        self.environ['QUERY_STRING'] = query
        request = self.request(self.environ)
        self.assertEquals(request.get_url(), 'http://example.com:8000/?' + query)
        for key, value in parameters.iteritems():
            self.assertEquals(request.url.parameters[key], value)

    def test_dict_or_list_of_headers(self):
        request = http.Response(200, [('x-spirit-animal', 'kangaroo')], '')
        self.assertEquals(len(request.headers), 2)
        self.assertEquals(dict(request.headers)['x-spirit-animal'], 'kangaroo')
        request = http.Response(200, {'x-spirit-animal': 'kangaroo'}, '')
        self.assertEquals(len(request.headers), 2)
        self.assertEquals(dict(request.headers)['x-spirit-animal'], 'kangaroo')

    def test_clone_request(self):
        this = self.request(self.environ)
        that = this._clone()
        self.assertFalse(this is that)
        self.assertEquals(this.method, that.method)
        self.assertFalse(this.url is that.url)
        self.assertEquals(this.url, that.url)
        self.assertFalse(this.url.parameters is that.url.parameters)
        for key, value in this.url.parameters.iteritems():
            self.assertEquals(that.url.parameters[key], value)
        self.assertFalse(this.headers is that.headers)
        for key, value in dict(this.headers).iteritems():
            self.assertEquals(dict(that.headers)[key], value)
        self.assertEquals(this.body, that.body)
        self.assertTrue(this.callback is that.callback)

    def test_to_dict(self):
        request = self.request(self.environ).to_dict()
        self.assertEquals(len(request), 4)
        self.assertEquals(request['url'], 'http://example.com:8000/')
        self.assertEquals(request['method'], 'POST')
        self.assertEquals(len(request['headers']), 2)
        self.assertEquals(dict(request['headers'])['host'], 'example.com:8000')
        self.assertEquals(dict(request['headers'])['content-type'], 'application/x-www-form-urlencoded')
        self.assertEquals(request['body'], '')

    def test_response(self):
        body = '{"name": "snarf"}'
        headers = [('x-favorite-vegetable', 'asparagus')]
        start_response = StartResponse()

        response = http.Response(headers=headers, body=body)
        response_body = response.send(start_response)
        self.assert_(isinstance(response_body, type(iter([]))))
        response_body = list(response_body)
        self.assert_(len(response_body) == 1)
        response_body = response_body[0]
        self.assertEquals(response_body, body)
        self.assertEquals(start_response.status, '200 OK')
        self.assertEquals(len(start_response.headers), len(headers))
        for name, value in headers:
            self.assertEquals(dict(start_response.headers)[name], value)

    def test_response_encode_headers(self):
        headers = [(u'x-foo', u'bar')]
        encoded = http.Response.encode_headers(headers)
        foo, bar = encoded[0]
        self.assertTrue(isinstance(foo, str))
        self.assertTrue(isinstance(bar, str))

    def test_http_exception(self):
        exception = http.HTTPException()
        self.assertHTTPExceptionEquals(exception, 400, [], '')
        self.assertEquals(exception.type, 'error')


class ProxyTests(GGTestCase):
    environ = {
        'PATH_INFO': '/foo/bar/',
        'REQUEST_METHOD': 'POST',
        'QUERY_STRING': 'monkey=wrench&foo=bar',
        'HTTP_HOST': 'example.com:8000',
        'CONTENT_TYPE': 'application/x-www-form-urlencoded',
        'wsgi.url_scheme': 'https',
        'wsgi.input': WSGIInput(),
    }

    class MockHttp(object):
        response = {'x-favorite-vegetable': 'asparagus', 'status': '200'}
        content = 'snarf!'
        def request(self, url, method, headers, body):
            self.url = url
            self.method = method
            self.headers = headers
            self.body = body
            return self.response, self.content

    def test_request(self):
        proxy = goldengate.Proxy()
        proxy.http = self.MockHttp()
        request = http.Request.from_wsgi(self.environ, StartResponse())
        response = proxy.request(request)
        self.assertEquals(proxy.http.url, request.get_url())
        self.assertEquals(proxy.http.method, request.method)
        for key, value in request.headers:
            self.assertEquals(proxy.http.headers[key], value)
        self.assertEquals(proxy.http.body, request.body)
        for key, value in response.headers:
            if key == 'Content-Length':
                continue
            self.assertEquals(proxy.http.response[key], value)
        self.assertEquals(response.body, proxy.http.content)


class AWSTests(GGTestCase):
    scheme = 'http'
    host = 'example.com:8000'
    path = '/'
    access_key = 'foo'
    signature_version = '2'
    timestamp = '2010-08-12T00:00:05'
    signature_method = 'HmacSHA256'
    version = '2010-06-15'
    signature = 'XXX'
    action = 'DescribeInstances'

    def setUp(self):
        super(AWSTests, self).setUp()
        self.input = WSGIInput()

    @property
    def environ(self):
        return {
            'PATH_INFO': self.path, 
            'REQUEST_METHOD': 'POST', 
            'QUERY_STRING': urllib.urlencode([
                ('SignatureVersion', self.signature_version),
                ('AWSAccessKeyId', self.access_key),
                ('Timestamp', self.timestamp),
                ('SignatureMethod', self.signature_method),
                ('Version', self.version),
                ('Signature', self.signature),
                ('Action', self.action),
            ]),
            'HTTP_HOST': self.host, 
            'CONTENT_TYPE': '',
            'wsgi.url_scheme': self.scheme,
            'wsgi.input': self.input,
        }


class AWSRequestTests(AWSTests):

    def test_action(self):
        request = auth.aws.Request.from_wsgi(self.environ, StartResponse())
        self.assertEquals(request.aws_action, self.action)

    def test_normalized_parameters(self):
        request = auth.aws.Request.from_wsgi(self.environ, StartResponse())
        parameters = request.get_normalized_parameters()
        self.assertEquals(parameters, urllib.urlencode([
            ('AWSAccessKeyId', self.access_key),
            ('Action', self.action),
            ('SignatureMethod', self.signature_method),
            ('SignatureVersion', self.signature_version),
            ('Timestamp', self.timestamp),
            ('Version', self.version)
        ]))

    def test_normalized_http_method(self):
        request = auth.aws.Request.from_wsgi(self.environ, StartResponse())
        self.assertEquals(request.get_normalized_http_method(), 'POST')

    def test_normalized_http_host(self):
        request = auth.aws.Request.from_wsgi(self.environ, StartResponse())
        self.assertEquals(request.get_normalized_http_host(), self.host)

    def test_normalized_http_path(self):
        request = auth.aws.Request.from_wsgi(self.environ, StartResponse())
        self.assertEquals(request.get_normalized_http_path(), '/')
        request.url = http.clone_url(request.url, path='')
        self.assertEquals(request.get_normalized_http_path(), '/')
        request.url = http.clone_url(request.url, path='/foo/bar/')
        self.assertEquals(request.get_normalized_http_path(), '/foo/bar/')
        request.url = http.clone_url(request.url, path='/foo/bar')
        self.assertEquals(request.get_normalized_http_path(), '/foo/bar')

    def test_signed_request(self):
        for signature_method in [auth.aws.SignatureMethod_HMAC_SHA1(), auth.aws.SignatureMethod_HMAC_SHA256()]:
            request = auth.aws.Request.from_wsgi(self.environ, StartResponse())
            signed = request.signed_request(signature_method, 'foo', 'bar')
            self.assertEquals(signed.url.parameters['AWSAccessKeyId'], 'foo')
            self.assertEquals(signed.url.parameters['SignatureVersion'], signature_method.version)
            self.assertEquals(signed.url.parameters['SignatureMethod'], signature_method.name)
            self.assertAlmostEquals(auth.aws.parse_timestamp(signed.url.parameters['Timestamp']), int(time.time()))
            self.assertEquals(signed.url.parameters['Signature'], signature_method.build_signature(signed, 'bar'))
            self.assertEquals(signed.url.parameters['Action'], request.url.parameters['Action'])
            self.assertEquals(signed.url.parameters['Version'], request.url.parameters['Version'])


class AuthTests(AWSTests):
    def test_unauthorized_exception(self):
        exception = auth.UnauthorizedException('dereks_mom@example.com', 'a message')
        self.assertHTTPExceptionEquals(exception, 403, [], 'a message')
        self.assertEquals(exception.entity, 'dereks_mom@example.com')
        self.assertEquals(exception.type, 'unauthorized')

    def test_unauthenticated_exception(self):
        exception = auth.UnauthenticatedException('a message')
        self.assertHTTPExceptionEquals(exception, 401, [], 'a message')
        self.assertEquals(exception.type, 'unauthenticated')


class AWSAuthTests(AWSTests):

    def setUp(self):
        self.aws_key = 'key'
        self.aws_secret = 'secret'
        self.entity = 'snarf@example.com'
        self.entity_key = 'snarf'
        self.entity_secret = 'sn4rf'
        self.credentials = credentials.StaticCredentialStore([credentials.Credential(self.entity, self.entity_key, self.entity_secret)])
        self.authenticator = auth.aws.Authenticator(self.credentials)
        self.authorizer = auth.aws.Authorizer(self.aws_key, self.aws_secret, policies=[policy.allow()])
        super(AWSAuthTests, self).setUp()

    def signed_request(self, request=None, signature_method=None, key=None, secret=None, timestamp=None):
        signature_method = signature_method if signature_method is not None else auth.aws.SignatureMethod_HMAC_SHA256()
        request = request if request is not None else auth.aws.Request.from_wsgi(self.environ, StartResponse())
        parameters = request.url.parameters.copy()
        parameters['AWSAccessKeyId'] = key if key else self.entity_key
        parameters['SignatureVersion'] = signature_method.version
        parameters['SignatureMethod'] = signature_method.name
        parameters['Timestamp'] = timestamp if timestamp is not None else auth.aws.generate_timestamp()
        prepared = request._clone(url=http.clone_url(request.url, parameters=parameters))

        parameters['Signature'] = signature_method.build_signature(prepared, secret if secret is not None else self.entity_secret)
        return request._clone(url=http.clone_url(prepared.url, parameters=parameters))

    # Authenticator tests

    def test_expired_timestamp(self):
        request = self.signed_request(timestamp=time.strftime(auth.aws.TIME_FORMAT, time.gmtime(time.time() - 301)))
        self.assertRaises(auth.UnauthenticatedException, self.authenticator.authenticate, request)

    def test_future_timestamp(self):
        request = self.signed_request(timestamp=time.strftime(auth.aws.TIME_FORMAT, time.gmtime(time.time() + 301)))
        self.assertRaises(auth.UnauthenticatedException, self.authenticator.authenticate, request)

    def test_bad_timestamp(self):
        request = self.signed_request(timestamp='ceci n\'est pas une timestamp.')
        self.assertRaises(auth.UnauthenticatedException, self.authenticator.authenticate, request)

    def test_missing_signature(self):
        request = self.signed_request()
        del request.url.parameters['Signature']
        self.assertRaises(auth.UnauthenticatedException, self.authenticator.authenticate, request)

    def test_missing_credentials(self):
        request = self.signed_request(key='not snarf')
        self.assertRaises(auth.UnauthenticatedException, self.authenticator.authenticate, request)

    def test_signature_mismatch(self):
        request = self.signed_request()
        request.url.parameters['Signature'] = 'wr0ngs1gn4tur3'
        self.assertRaises(auth.UnauthenticatedException, self.authenticator.authenticate, request)

    def test_get_signature_method(self):
        for name, version, expected in [('HmacSHA1', '2', auth.aws.SignatureMethod_HMAC_SHA1), ('HmacSHA256', '2', auth.aws.SignatureMethod_HMAC_SHA256)]:
            self.assertTrue(isinstance(auth.aws.Authenticator.get_signature_method(name, version), expected))
        self.assertRaises(auth.UnauthenticatedException, auth.aws.Authenticator.get_signature_method, 'HmacSHA1', '1')

    def test_sha1_signature_method(self):
        request = self.signed_request(signature_method=auth.aws.SignatureMethod_HMAC_SHA256())
        self.assertEquals(self.authenticator.authenticate(request), self.entity)

    def test_sha256_signature_method(self):
        request = self.signed_request(signature_method=auth.aws.SignatureMethod_HMAC_SHA1())
        self.assertEquals(self.authenticator.authenticate(request), self.entity)

    # Authorizer tests

    def test_prepare(self):
        request = self.signed_request()
        entity = self.authenticator.authenticate(request)
        authorized = self.authorizer.prepare(entity, request)
        self.assertEquals(authorized.url.host, settings.remote_host)
        request.url = http.clone_url(request.url, host=settings.remote_host)
        request.headers = [header if header[0] != 'host' else ('host', settings.remote_host) for header in request.headers]
        self.host = settings.remote_host
        self.assertEquals(
            authorized.url.parameters['Signature'],
            self.signed_request(request, key=self.aws_key, secret=self.aws_secret, timestamp=authorized.url.parameters['Timestamp']).url.parameters['Signature']
        )

    def test_authorized(self):
        request = self.signed_request()
        entity = self.authenticator.authenticate(request)
        authorized = self.authorizer.authorize(entity, request)
        request.url = http.clone_url(request.url, host=settings.remote_host)
        request.headers = [header if header[0] != 'host' else ('host', settings.remote_host) for header in request.headers]
        self.assertEquals(
            authorized.url.parameters['Signature'],
            self.signed_request(request, key=self.aws_key, secret=self.aws_secret, timestamp=authorized.url.parameters['Timestamp']).url.parameters['Signature']
        )

    def test_unauthorized(self):
        self.authorizer = auth.aws.Authorizer(self.aws_key, self.aws_secret, policies=[policy.deny()])
        request = self.signed_request()
        entity = self.authenticator.authenticate(request)
        authorized = self.assertRaises(auth.UnauthorizedException, self.authorizer.authorize, entity, request)


class CredentialTests(unittest.TestCase):
    pass


class PolicyTests(GGTestCase):
    def test_missing_policy(self):
        request = http.Request('get', 'http://example.com/', [], '', StartResponse())
        self.assertRaises(policy.MissingPolicyException, policy.Policy.for_request, 'foo',  request, [])


class MatcherTests(GGTestCase):
    class MockAWSRequest(object):
        def __init__(self, aws_action):
            self.aws_action = aws_action

    def test_aws_action_matcher(self):
        self.assertTrue(policy.AWSActionMatcher('DescribeInstances').matches(None, self.MockAWSRequest('DescribeInstances')))
        self.assertFalse(policy.AWSActionMatcher('DescribeInstances').matches(None, self.MockAWSRequest('TerminateInstance')))

    def test_entity_matcher(self):
        self.assertTrue(policy.EntityMatcher(['foo']).matches('foo', None))
        self.assertFalse(policy.EntityMatcher(['foo']).matches('bar', None))

    def test_all_matcher(self):
        self.assertTrue(policy.AllMatcher([policy.AlwaysMatcher(), policy.AlwaysMatcher()]).matches(None, None))
        self.assertFalse(policy.AllMatcher([policy.AlwaysMatcher(), policy.NotMatcher(policy.AlwaysMatcher())]).matches(None, None))
        self.assertFalse(policy.AllMatcher([policy.NotMatcher(policy.AlwaysMatcher())]).matches(None, None))

    def test_any_matcher(self):
        self.assertTrue(policy.AnyMatcher([policy.AlwaysMatcher(), policy.AlwaysMatcher()]).matches(None, None))
        self.assertTrue(policy.AnyMatcher([policy.AlwaysMatcher(), policy.NotMatcher(policy.AlwaysMatcher())]).matches(None, None))
        self.assertFalse(policy.AnyMatcher([policy.NotMatcher(policy.AlwaysMatcher())]).matches(None, None))
        self.assertTrue(policy.AnyMatcher([policy.NotMatcher(policy.AlwaysMatcher()), policy.AlwaysMatcher()]).matches(None, None))


class KVStoreTests(unittest.TestCase):
    def test_bad_backend_uri_raises(self):
        self.assertRaises(kvstore.InvalidKeyValueStoreBackend, kvstore.get_kvstore, '')

    def test_locmem_backend_uri_returns_locmem_backend(self):
        backend = kvstore.get_kvstore('locmem://')
        self.assertTrue(isinstance(backend, kvstore.backends.locmem.StorageClass))


class KVStoreBackendTests(object):
    """
    Abstract test for kvstore backends. Subclass this and set backend for each
    backend you want to test.

    """
    
    @property
    def kvstore(self):
        if 'kvstore' not in self.__dict__:
            try:
                self.__dict__['kvstore'] = kvstore.get_kvstore(self.backend)
            except kvstore.ImproperlyConfigured, e:
                raise SkipTest(str(e))
        return self.__dict__['kvstore']

    def wait(self):
        # Some storage backends aren't strongly consistent. This method is 
        # called after any operation that may operations that modify data.
        # Do whatcha need to.
        pass

    def test_get_nonexistent_key_returns_none(self):
        self.assertFalse(self.kvstore.has_key('__not_there__'))
        self.assertTrue(self.kvstore.get('__not_there__') is None)

    def test_set_and_get(self):
        self.kvstore.set('name', 'beezlebum')
        self.wait()
        self.assertEquals(self.kvstore.get('name'), 'beezlebum')

    def test_deleted_keys_are_gone(self):
        self.kvstore.set('_', True)
        self.wait()
        self.assertTrue(self.kvstore.has_key('_'))
        self.kvstore.delete('_')
        self.wait()
        self.assertFalse(self.kvstore.has_key('_'))
        self.assertTrue(self.kvstore.get('_') is None)


class LocalMemoryKVStoreTests(unittest.TestCase, KVStoreBackendTests):
    backend = 'locmem://'


class MemcachedKVStoreTests(unittest.TestCase, KVStoreBackendTests):
    backend = 'memcached://' + MEMCACHED_TEST_HOST


class SimpleDBKVStoreTests(unittest.TestCase, KVStoreBackendTests):
    from goldengate import settings
    backend = 'simpledb://' + SIMPLEDB_TEST_DOMAIN + '?aws_access_key=' + settings.aws_key + '&aws_secret_access_key=' + settings.aws_secret

    def wait(self):
        # TODO: Use SimpleDB consistency levels instead of sleeping.
        import time
        time.sleep(0.5)


if __name__ == '__main__':
    unittest.main()

