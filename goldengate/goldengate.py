# Golden Gate is a cloud gateway. More generally, it is a broker for an HTTP
# service that applies more granular authentication and authorization policies
# than may be provided by the backend service.


import httplib2
import auth
from http import Request, Response, HTTPException, clone_url
from sausagefactory import AuditTrail
from urlparse import urljoin
try:
    import settings
except ImportError:
    print 'Error: missing settings'
from credentials import StaticCredentialStore, Credential


class Proxy(object):
    """
    Proxy is basically an HTTP client that accepts Request objects, makes the
    HTTP request that it represents, and returns a Response object.

    """

    def __init__(self):
        self.http = httplib2.Http()

    def request(self, request):
        return self.http.request(request.get_url(), request.method, headers=request.headers, body=request.body)


class GoldenGate(object):
    def __init__(self, authenticator=auth.AWSAuthenticator, authorizer=lambda: auth.AWSAuthorizer(settings.AWS_KEY, settings.AWS_SECRET), auditor=None, proxy=Proxy):
        credentials = [Credential(*credential) for credential in settings.CREDENTIALS]
        self.authenticator = authenticator(StaticCredentialStore(credentials))
        self.authorizer = authorizer()
        if auditor is None:
            self.auditor = settings.AUDITOR
        else:
            self.auditor = auditor()
        self.proxy = proxy()

    def manage(self, request):
        "Handle Golden Gate management requests."
        if request.url.path.startswith('/~/cancel/'):
            uuid = request.url.path[10:]
            from policy import TimeLockPolicy
            try:
                TimeLockPolicy.cancel(uuid)
            except KeyError:
                return Response(404)
            return Response(body='okie dokie.')
        return Response(404)

    def handle(self, request):
        """
        The contract of the request handler is: accept a request, return a response.

        """
        if request.url.path.startswith('/~/'):
            return self.manage(request)

        entity = self.authenticator.authenticate(request)
        headers = dict(request.headers)
        headers['host'] = settings.REMOTE_HOST
        proxy_request = self.authorizer.sign(
            entity, 
            request._clone(
                url=clone_url(request.url, host=settings.REMOTE_HOST),
                headers=headers
            )
        )
        self.auditor.record(entity, ['applied', [request.to_dict(), proxy_request.to_dict()]])
        return self.proxy.request(proxy_request)


class Handler(object):
    def __init__(self, handler):
        self.handler = handler

    def __call__(self, environ, start_response):
        request = Request.from_wsgi(environ, start_response)
        try:
            return self.handler.handle(request).send(start_response)
        except HTTPException, e:
            self.handler.auditor.record(getattr(e, 'entity', None), [e.type, request.to_dict()])
            return e.to_response().send(start_response)
        except Exception:
            try:
                self.handler.auditor.record(None, ['error', request.to_dict()])
            finally:
                raise


application = Handler(GoldenGate())

