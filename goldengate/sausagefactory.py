"""
Things go into sausage factory but they don't come back out.
"""
from __future__ import with_statement
import fcntl
import re
import time
try:
    import simplejson as json
except ImportError:
    import json


class AuditTrail(object):
    signature_pattern = re.compile('Signature=[^&]+')
    authorization_pattern = re.compile('"authorization", "AWS [^:]+:[^"]+"')

    @classmethod
    def sanitize(cls, record):
        from goldengate import settings
        # HACK HACK HACK
        record = re.sub(cls.signature_pattern, 'Signature=XXX', record) # remove Signature, if there is one.
        record = re.sub(cls.authorization_pattern, '"authorization", "XXX"', record)
        return record.replace(settings.aws_secret, 'XXX') # just in case

    def format(self, entity, action):
        # Might also want an optional transaction identifier
        return self.sanitize(json.dumps([time.strftime('%Y-%m-%d %H:%M:%S'), {'entity': entity, 'action': action}]))

    def record(self, entity, action):
        print self.format(entity, action)


class FileAuditTrail(AuditTrail):
    # This isn't really tested and probably doesn't work.

    def __init__(self, filename):
        self.filename = filename

    def record(self, entity, action):
        with open(self.filename, 'a+') as log_file:
            fcntl.lockf(log_file.fileno(), fcntl.LOCK_EX)
            log_file.write(self.format(entity, action))
            log_file.write("\n")
            log_file.flush()
            fcntl.lockf(log_file.fileno(), fcntl.LOCK_UN)

