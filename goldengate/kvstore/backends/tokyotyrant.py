"""
Memcache key-value store backend

Just for testing. This isn't persistent. Don't actually use it.

Example configuration for Django settings:

    KEY_VALUE_STORE_BACKEND = 'tokyotyrant://hostname:port

"""

from base import BaseStorage, InvalidKeyValueStoreBackendError
from kvstore import ImproperlyConfigured
try:
    import simplejson as json
except ImportError:
    import json

try:
    import pytyrant
except ImportError:
    raise InvalidKeyValueStoreBackendError("Tokyotyrant key-value store backend requires the 'pytyrant' library")


def _utf8_str(s):
    if isinstance(s, unicode):
        return s.encode('utf-8')
    else:
        return str(s)


class StorageClass(BaseStorage):
    def __init__(self, server, params):
        BaseStorage.__init__(self, params)
        host, port = server.split(':')
        try:
            port = int(port)
        except ValueError:
            raise ImproperlyConfigured("Invalid port provided for tokyo-tyrant key-value store backend")
        self._db = pytyrant.PyTyrant.open(host, port)

    def set(self, key, value):
        if isinstance(value, unicode):
            value = value.encode('utf-8')
        self._db[_utf8_str(key)] = json.dumps(value)

    def get(self, key):
        val = self._db.get(_utf8_str(key))
        if isinstance(val, basestring):
            return json.loads(val)
        else:
            return val

    def delete(self, key):
        del self._db[_utf8_str(key)]

    def close(self, **kwargs):
        pass
        # Er, should be closing after each request..? But throws
        # a 'Bad File Descriptor' exception if we do (presumably because
        # something's trying to use a connection that's already been
        # closed...
        #self._db.close()
