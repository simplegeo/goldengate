from . import UnauthenticatedException, UnauthorizedException
from .. import policy, settings, http


class Authenticator(object):
    """
    If a request is authentic, the authenticate method will return the entity
    that made the request. If the request is not authentic an
    `UnauthenticatedException` will be raised.

    """
    def authenticate(self, request):
        raise UnauthenticatedException()


class Authorizer(object):
    """
    GoldenGate Authorizer that looks up the policy that should be applied for a
    particular request and dispatches to that policy's `grant` method to
    determine whether the request should be allowed (the entity is authorized to
    make the request). If the policy is allowed, an authorized request is returned,
    otherwise an UnauthorizedException is thrown.

    An authorized request is one that has been prepared to point at the real
    remote host that we're proxying to. This preparation is handled by
    dispatching to the `prepare` method.

    """
    def __init__(self, policies=None):
        self.policies = policies

    def prepare(self, entity, request):
        # Update the request to point to the real remote host.
        request = request._clone()
        request.url = http.clone_url(request.url, host=settings.remote_host)
        request.headers = [header if header[0] != 'host' else ('host', settings.remote_host) for header in request.headers]
        return request

    def authorize(self, entity, request):
        if policy.Policy.for_request(entity, request, policies=self.policies).grant(entity, request):
            return self.prepare(entity, request)
        else:
            raise UnauthorizedException(entity)
