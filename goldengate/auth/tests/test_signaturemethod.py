# -*- coding: utf-8 -*-
#
# © 2010 SimpleGeo, Inc. All rights reserved.
# Author: Ian Eure <ian@simplegeo.com>
#

import unittest

from goldengate import settings
from goldengate.http import URL
from goldengate.auth import aws

class SignatureMethodTest(unittest.TestCase):

    def setUp(self):
        """"""
        self.object = aws.SignatureMethod()

    def test_build_signature_base_string(self):
        gg_host = "goldengate.simplegeo.com"
        request = aws.Request(
            "GET",
            URL(scheme="https", host=gg_host,
                     path="/describe/instances", parameters={}),
            {}, "This is the body", None)
        base_string = self.object.build_signature_base_string(request)
        self.assert_(gg_host not in base_string)
        self.assert_(settings.remote_host in base_string)


if __name__ == '__main__':
    unittest.main()
