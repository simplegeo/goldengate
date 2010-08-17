# Copyright (c) 2009 Six Apart Ltd.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice,
#   this list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of Six Apart Ltd. nor the names of its contributors may
#   be used to endorse or promote products derived from this software without
#   specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

# This module is borrowed with minor modifications from Six Apart's django-
# kvstore, available at http://github.com/sixapart/django-kvstore/.

"""
An extensible key-value store backend for Django applications.

This package defines a set of key-value store backends that all conform to a
simple API. A key-value store is a simple data storage backend that is similar
to a cache. Unlike a cache, items are persisted to disk, and are not lost when
the backend restarts."""

__version__ = '1.0'
__date__ = '26 December 2010'
__author__ = 'Six Apart Ltd.'
__credits__ = """Mike Malone
Brad Choate"""

from cgi import parse_qsl
from goldengate import settings

# Names for use in settings file --> name of module in "backends" directory.
# Any backend scheeme that is not in this dictionary is treated as a Python
# import path to a custom backend.
BACKENDS = {
    'memcached': 'memcached',
    'tokyotyrant': 'tokyotyrant',
    'locmem': 'locmem',
    'db': 'db',
    'simpledb': 'sdb',
    'googleappengine': 'googleappengine',
    'redis': 'redisdj',
}


class InvalidKeyValueStoreBackend(Exception): 
    pass


class ImproperlyConfigured(Exception):
    pass


def get_kvstore(backend_uri):
    if backend_uri.find(':') == -1:
        raise InvalidKeyValueStoreBackend("Backend URI must start with scheme://")
    scheme, rest = backend_uri.split(':', 1)
    if not rest.startswith('//'):
        raise InvalidKeyValueStoreBackend("Backend URI must start with scheme://")

    host = rest[2:]
    qpos = rest.find('?')
    if qpos != -1:
        params = dict(parse_qsl(rest[qpos+1:]))
        host = rest[2:qpos]
    else:
        params = {}
    if host.endswith('/'):
        host = host[:-1]

    if scheme in BACKENDS:
        module = __import__('goldengate.kvstore.backends.%s' % BACKENDS[scheme], {}, {}, [''])
    else:
        module = __import__(scheme, {}, {}, [''])
    return getattr(module, 'StorageClass')(host, params)

