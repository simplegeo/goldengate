# Golden Gate is a cloud gateway. More generally, it is a broker for an HTTP
# service that applies more granular authentication and authorization policies
# than may be provided by the backend service.

# To do:
#  - Forbidden / unauthorized responses should be in the correct format.
#  - Rewrite 302s to make clients go through proxy (setup option?).


import httplib2
import auth
from http import Request, Response
from sausagefactory import AuditTrail
from urlparse import urljoin
try:
    import setup
except ImportError:
    print 'Error: missing setup'
try:
    import simplejson as json
except ImportError:
    import json


class Proxy(object):
    def __init__(self, base_uri=setup.REMOTE_BASE_URI):
        self.http = httplib2.Http()
        self.base_uri = base_uri

    def absolute_uri(self, relative_uri):
        return urljoin(self.base_uri, relative_uri)

    def request(self, request):
        return self.http.request(self.absolute_uri(request.relative_uri), request.method, headers=request.headers, body=request.body)


class AWSProxy(Proxy):
    def request(self, request):
        return super(AWSProxy, self).request(request)


class GoldenGate(object):
    def __init__(self, authenticator=auth.AWSAuthenticator, authorizer=auth.AWSAuthorizer, auditor=AuditTrail, proxy=AWSProxy):
        self.authenticator = authenticator()
        self.authorizer = authorizer()
        self.auditor = auditor()
        self.proxy = proxy()

    def handle(self, request):
        try:
            entity = self.authenticator.authenticate(request)
            proxy_request = self.authorizer.sign(entity, request)
        except auth.UnauthorizedException:
            # HTTP response codes are misnamed. 403 Forbidden really means Unauthorized and
            # 401 Unauthorized really means unauthenticated. That confusing translation is
            # done here.
            self.auditor.record(None, ['attempted', request.to_dict()])
            return Response('Forbidden', status=403, content_type='text/plain')
        except auth.UnauthenticatedException:
            self.auditor.record(None, ['attempted', request.to_dict()])
            return Response('Unauthorized', status=403, content_type='text/plain')
        except Exception:
            try:
                self.auditor.record(None, ['error', request.to_dict()])
            finally:
                raise
        else:
            self.auditor.record(entity, ['applied', request.to_dict()])
            return self.response(*self.proxy.request(proxy_request))

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
        return self.handler.handle(Request(environ, start_response)).send(start_response)


application = Handler(GoldenGate())

