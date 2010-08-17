__version__ = 0.1
__date__ = '30 July 2010'
__author__ = 'Mike Malone'
__credits__ = 'SimpleGeo'


import traceback
import os
import sys

from . import config

# Setup the default configuration
settings = config.Config()


# Try loading custom configuration
def load_config():
    filename = os.environ.get('GOLDENGATE_PATH')

    # Load up the config file if its found.
    if filename is not None:
        if not os.path.exists(filename):
            sys.stderr.write('Invalid filename: ' + filename)
            return
        environment = {
            '__builtins__': __builtins__,
            '__name__': '__config__',
            '__file__': filename,
            '__doc__': None,
            '__package__': None
        }
        try:
            execfile(filename, environment, environment)
        except Exception, e:
            print 'Unable to read configuration file: %s' % filename
            traceback.print_exc()
            sys.exit(1)

        for key, value in list(environment.items()):
            # Ignore unknown names
            if key.lower() not in settings.settings:
                continue
            try:
                settings.set(key.lower(), value)
            except:
                sys.stderr.write("Invalid value for %s: %s\n\n" % (key, value))
                raise
load_config()


from .goldengate import application


RANDOM_TOKEN_STRING_LENGTH = 16
RANDOM_TOKEN_ALPHABET = 'abcdefghjklmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'


def random_token(length=RANDOM_TOKEN_STRING_LENGTH, alphabet=RANDOM_TOKEN_ALPHABET):
    "Generate a random string with the given length and alphabet."
    import random
    return ''.join(random.choice(alphabet) for _ in xrange(length))


def generate_credentials():
    print ', '.join([random_token(), random_token(32)])
