"""
Amazon SimpleDB key-value store backend

Example configuration for Django settings:

    KEY_VALUE_STORE_BACKEND = 'sdb://<simpledb_domain>?aws_access_key=<access_key>&aws_secret_access_key=<secret_key>'

"""


from base import BaseStorage, InvalidKeyValueStoreBackendError
from goldengate.kvstore import ImproperlyConfigured
try:
    import simplejson as json
except ImportError:
    import json

try:
    import simpledb
except ImportError:
    raise InvalidKeyValueStoreBackendError("SipmleDB key-value store backend requires the 'python-simpledb' library")


def _utf8_str(s):
    if isinstance(s, unicode):
        return s.encode('utf-8')
    else:
        return str(s)


class StorageClass(BaseStorage):
    def __init__(self, domain, params):
        BaseStorage.__init__(self, params)
        params = dict(params)
        try:
            aws_access_key = params['aws_access_key']
            aws_secret_access_key = params['aws_secret_access_key']
        except KeyError:
            raise ImproperlyConfigured("Incomplete configuration of SimpleDB key-value store. Required parameters: 'aws_access_key', and 'aws_secret_access_key'.")
        self._db = simpledb.SimpleDB(aws_access_key, aws_secret_access_key)
        self._domain = self._db[domain]

    def set(self, key, value):
        if isinstance(value, unicode):
            value = value.encode('utf-8')
        self._domain[_utf8_str(key)] = {'value': json.dumps(value)}

    def get(self, key):
        val = self._domain[_utf8_str(key)].get('value', None)
        if isinstance(val, basestring):
            return json.loads(val)
        else:
            return val

    def delete(self, key):
        del self._domain[_utf8_str(key)]

    def close(self, **kwargs):
        pass
