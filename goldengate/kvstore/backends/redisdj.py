"""
Redis key-value store backend.

Example configuration for Django settings:

    KEY_VALUE_STORE_BACKEND = 'redis://hostname:port'

port is optional. If none is given, the port specified in redis.conf will be used.

"""
import base64
from base import BaseStorage, InvalidKeyValueStoreBackendError

try:
    import redis
except ImportError:
    raise InvalidKeyValueStoreBackendError("The Redis key-value store backend requires the Redis python client.")

try:
    import cPickle as pickle
except ImportError:
    import pickle

def _utf8_str(s):
    if isinstance(s, unicode):
        return s.encode('utf-8')
    else:
        return str(s)

class StorageClass(BaseStorage):

    def __init__(self, server, params):
        if ':' in server:
            host, port = server.split(':')
            port = int(port)
        else:
            host, port = server, None
        params['port'] = port
        BaseStorage.__init__(self, params)
        self._db = redis.Redis(host=host, **params)

    def set(self, key, value):
        encoded = base64.encodestring(pickle.dumps(value, 2)).strip()
        self._db.set(_utf8_str(key), encoded)

    def get(self, key):
        val = self._db.get(_utf8_str(key))
        if val is None:
            return None
        return pickle.loads(base64.decodestring(val))

    def delete(self, key):
        self._db.delete(_utf8_str(key))

    def close(self, **kwargs):
        pass
