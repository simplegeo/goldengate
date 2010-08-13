"""
Memcache key-value store backend

Just for testing. This isn't persistent. Don't actually use it.

Example configuration for Django settings:

    KEY_VALUE_STORE_BACKEND = 'memcached://hostname:port'

"""

from base import BaseStorage, InvalidKeyValueStoreBackendError

# Try pylibmc, cmemcache, and memcache in that order.
try:
    import pylibmc as memcache
except ImportError:
    try:
        import cmemcache as memcache
    except ImportError:
        try:
            import memcache
        except:
            raise InvalidKeyValueStoreBackendError("Memcached key-value store backend requires `pylibmc`, `memcache`, or `cmemcache` package.")


def _utf8_str(s):
    if isinstance(s, unicode):
        return s.encode('utf-8')
    else:
        return str(s)


class StorageClass(BaseStorage):
    def __init__(self, server, params):
        BaseStorage.__init__(self, params)
        self._db = memcache.Client(server.split(';'))

    def set(self, key, value):
        if isinstance(value, unicode):
            value = value.encode('utf-8')
        self._db.set(_utf8_str(key), value, 0)

    def get(self, key):
        val = self._db.get(_utf8_str(key))
        if isinstance(val, basestring):
            return val.decode('utf-8')
        else:
            return val

    def delete(self, key):
        self._db.delete(_utf8_str(key))

    def close(self, **kwargs):
        self._db.disconnect_all()
