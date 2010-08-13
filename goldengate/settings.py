from policy import allow
from sausagefactory import AuditTrail
from notifications import NotificationBroker


REMOTE_HOST = 'ec2.amazonaws.com'
REMOTE_PORT = 80

# AWS Credentials.
AWS_KEY = '<key>'
AWS_SECRET = '<secret>'

AUDITOR = AuditTrail()

# List of (<entity>, <key>, <secret>) tuples.
CREDENTIALS = []

# Broker used to deliver notifications about requests.
NOTIFICATION_BROKER = NotificationBroker()

# Policies are evaluated in order. The first one that matches a request
# is applied.
POLICIES = [
    allow(),
]
STORAGE_BACKEND = 'locmem://'

try:
    from local_settings import *
except ImportError:
    import sys
    print >>sys.stderr, "Couldn't import local settings, starting anyways."

