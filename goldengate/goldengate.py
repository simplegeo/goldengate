# Golden Gate is a cloud gateway. More generally, it is a broker for an HTTP
# service that applies more granular authentication and authorization policies
# than may be provided by the backend service.


import httplib2
from urlparse import urljoin
from . import settings
from .credentials import StaticCredentialStore, Credential
from .http import Request, Response, HTTPException, clone_url
from .sausagefactory import AuditTrail
from .auth import aws


class Proxy(object):
    """
    Proxy is basically an HTTP client that accepts Request objects, makes the
    HTTP request that it represents, and returns a Response object.

    """

    def __init__(self):
        self.http = httplib2.Http()

    def request(self, request):
        response, content = self.http.request(request.get_url(), request.method, headers=dict(request.headers), body=request.body)
        status = int(response.pop('status'))
        return Response(status, response, content)


class GoldenGate(object):
    def __init__(self, authenticator=aws.Authenticator, authorizer=aws.Authorizer, auditor=settings.auditor, proxy=Proxy):
        credentials = [Credential(*credential) for credential in settings.credentials]
        self.authenticator = authenticator(settings.credential_store(credentials))
        self.authorizer = authorizer()
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
        authorized_request = self.authorizer.authorize(entity, request)
        self.auditor.record(
            entity, [
                'applied',
                [request.to_dict(), authorized_request.to_dict()],
            ]
        )
        return self.proxy.request(authorized_request)


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
