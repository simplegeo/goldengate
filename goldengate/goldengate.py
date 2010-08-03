# Golden Gate is a cloud gateway. More generally, it is a broker for an HTTP
# service that applies more granular authentication and authorization policies
# than may be provided by the backend service.


import httplib2
import auth
from http import Request, Response, clone_url
from sausagefactory import AuditTrail
from urlparse import urljoin
try:
    import settings
except ImportError:
    print 'Error: missing settings'
from credentials import StaticCredentialStore, Credential


class Proxy(object):
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
        self.proxy = proxy()

    def manage(self, request):
        "Handle Golden Gate management requests."
        if request.url.path.startswith('/~/cancel/'):
            uuid = request.url.path[10:]
            from policy import TimeLockPolicy
            try:
                TimeLockPolicy.cancel(uuid)
            except KeyError:
                return Response('Not found', status=404, content_type='text/plain')
            return Response('OK', status=200, content_type='text/plain')
        return Response('Not found', status=404, content_type='text/plain')

    def handle(self, request):
        if request.url.path.startswith('/~/'):
            return self.manage(request)

        try:
            try:
                entity = self.authenticator.authenticate(request)
            except auth.UnauthenticatedException:
                self.auditor.record(None, ['attempted', request.to_dict()])
                return Response('Unauthenticated', status=403, content_type='text/plain')

            try:
                headers = request.headers.copy()
                headers['host'] = settings.REMOTE_HOST
                proxy_request = self.authorizer.sign(
                    entity, 
                    request._clone(
                        url=clone_url(request.url, host=settings.REMOTE_HOST),
                        headers=headers
                    )
                )
            except auth.UnauthorizedException:
                # HTTP response codes are misnamed. 403 Forbidden really means Unauthorized and
                # 401 Unauthorized really means unauthenticated. Amazon seems to return 403s for
                # both though.
                self.auditor.record(entity, ['attempted', request.to_dict()])
                return Response('Forbidden', status=403, content_type='text/plain')
            else:
                self.auditor.record(entity, ['applied', [request.to_dict(), proxy_request.to_dict()]])
                return self.response(*self.proxy.request(proxy_request))
        except Exception:
            try:
                self.auditor.record(None, ['error', request.to_dict()])
            finally:
                raise

    def response(self, headers, content):
        status = int(headers.pop('status'))
        content_type = 'application/x-www-form-urlencoded' # Amazon's Java client uses this as the default content-type. I guess that works.
        for name, value in headers.items():
            if name.lower() == 'content-type':
                content_type = headers.pop(name)
                break
        return Response(content, status=status, content_type=content_type, headers=headers.items())


class Handler(object):
    def __init__(self, handler):
        self.handler = handler

    def __call__(self, environ, start_response):
        return self.handler.handle(Request.from_wsgi(environ, start_response)).send(start_response)


application = Handler(GoldenGate())

