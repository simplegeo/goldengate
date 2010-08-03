__version__ = 0.1
__date__ = '30 July 2010'
__author__ = 'Mike Malone'
__credits__ = 'SimpleGeo'

from goldengate import GoldenGate, application


RANDOM_TOKEN_STRING_LENGTH = 16
RANDOM_TOKEN_ALPHABET = 'abcdefghjklmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'


def random_token(length=RANDOM_TOKEN_STRING_LENGTH, alphabet=RANDOM_TOKEN_ALPHABET):
    "Generate a random string with the given length and alphabet."
    return ''.join(random.choice(alphabet) for _ in xrange(length))
