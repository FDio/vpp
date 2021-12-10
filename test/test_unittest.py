#!/usr/bin/env python3

import unittest

from framework import VppTestCase, VppTestRunner


class TestUnittest(VppTestCase):
    """ Unittest plugin Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestUnittest, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestUnittest, cls).tearDownClass()

    def test_clib_socket(self):
        """ FIB Unit Tests """
        self.vapi.cli("test clib socket config /tmp/sometestsocket")
        self.vapi.cli("test clib socket config @thisisabstract")


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
