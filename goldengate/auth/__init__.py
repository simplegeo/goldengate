from ..http import HTTPException


class UnauthorizedException(HTTPException):
    type = 'unauthorized'
    def __init__(self, entity, body=''):
        self.entity = entity
        super(UnauthorizedException, self).__init__(403, body=body)


class UnauthenticatedException(HTTPException):
    type = 'unauthenticated'
    def __init__(self, body=''):
        super(UnauthenticatedException, self).__init__(401, body=body)
