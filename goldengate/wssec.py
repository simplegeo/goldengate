# Playing around with WS-Security and xmldsig.

import base64
import hmac
import hashlib
from lxml import etree
from contextlib import contextmanager
try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO
from auth import SignatureMethod_HMAC_SHA1
from tlslite.utils import keyfactory


NAMESPACES = {
    'soap': 'http://schemas.xmlsoap.org/soap/envelope/',
    'xsd': 'http://www.w3.org/2001/XMLSchema',
    'xsi': 'http://www.w3.org/2001/XMLSchema-instance',
    'wsse': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
    'wsu': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd',
    'ds': 'http://www.w3.org/2000/09/xmldsig#',
}


class InvalidSignatureException(Exception):
    pass


class X509Certificate(object):
    def __init__(self, public_cert, private_cert):
        self.public_cert = public_cert
        self.private_cert = private_cert

    def sign(self, base_string):
        private_key = keyfactory.parsePrivateKey(self.private_cert)
        signature = private_key.hashAndSign(base_string)
        return base64.b64encode(signature)

    def verify(self, base_string, signature):
        decoded_sig = base64.b64decode(signature)
        public_key = keyfactory.parsePrivateKey(self.public_cert)
        return publickey.hashAndVerify(decoded_sig, base_string)


cert = X509Certificate(
    open('<publiccert>').read(),
    open('<privatecert>').read()
)


def find_element_by_id(element, id):
    if element.attrib.get(_('wsu:Id')) == id:
        return element
    else:
        for child in element.getchildren():
            child_element = find_element_by_id(child, id)
            if child_element is not None:
                return child_element
    return None


def _(path):
    # Fix namespaces.
    return '/'.join('{%s}%s' % (NAMESPACES.get(namespace), tag)
            for namespace, tag in [element.split(':') for element in path.split('/')])


def check_timestamp(timestamp):
    # Check that timestamp is within bounds. Raise exception if not.
    pass


def canonize(element):
    canonized = StringIO()
    element = etree.ElementTree(element)
    element.write_c14n(canonized, exclusive=True)
    return canonized.getvalue()


def check_reference(reference, envelope):
    referenced = find_element_by_id(envelope, reference.attrib['URI'][1:])
    canonized = canonize(referenced)
    hash = base64.b64encode(hashlib.sha1(canonized).digest())
    print
    print 'REFERENCE:', reference.tag, referenced.attrib[_('wsu:Id')]
    print '  canonized:', canonized
    print '  expected:', reference.find(_('ds:DigestValue')).text
    print '  actual:', hash


def parse_soap(content):
    envelope = etree.fromstring(content)

    # Some people seriously think SOAP is a good idea.
    certificate = envelope.find(_('soap:Header/wsse:Security/wsse:BinarySecurityToken'))
    if certificate is None:
        raise InvalidSignatureException("Couldn't find certificate in signature")

    # Make sure canonicalization mechanism is exc-c14n, DigestMethod is sha1, and
    # SignatureMethod is rsa-sha1.

    timestamp = envelope.find(_('soap:Header/wsse:Security/wsu:Timestamp'))
    check_timestamp(timestamp)

    signed = cert.sign(canonize(envelope.find(_('soap:Header/wsse:Security/ds:Signature/ds:SignedInfo'))))
    print 'SignatureValue', signed
    #assert cert.verify(canonize(envelope.find(_('soap:Header/wsse:Security/ds:Signature/ds:SignedInfo'))), signed)

    for reference in envelope.findall(_('soap:Header/wsse:Security/ds:Signature/ds:SignedInfo/ds:Reference')):
        check_reference(reference, envelope)


parse_soap(open('soapex2.xml').read())
