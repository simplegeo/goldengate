"""
Things go into sausage factory but they don't come back out.
"""
try:
    import simplejson as json
except ImportError:
    import json


class AuditTrail(object):
    def record(self, entity, action):
        # Might also want an optional transaction identifier
        print json.dumps({'entity': entity, 'action': action}, indent=4)

