#!/usr/bin/env python3

import unittest

from config import config
from framework import VppTestCase, VppTestRunner
from vpp_ip_route import VppIpTable, VppIpRoute, VppRoutePath


class TestBihash(VppTestCase):
    """ Bihash Test Cases """

    @classmethod
    def setUpClass(cls):
        # increase vapi timeout, to avoid spurious "test bihash ..."
        # failures reported on aarch64 w/ test-debug
        cls.vapi_response_timeout = 20
        super(TestBihash, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestBihash, cls).tearDownClass()

    def setUp(self):
        super(TestBihash, self).setUp()

    def tearDown(self):
        super(TestBihash, self).tearDown()

    def test_bihash_unittest(self):
        """ Bihash Add/Del Test """
        error = self.vapi.cli("test bihash careful 0 verbose 0")

        if error:
            self.logger.critical(error)
            self.assertNotIn('failed', error)

    def test_bihash_thread(self):
        """ Bihash Thread Test """

        error = self.vapi.cli("test bihash threads 2 nbuckets" +
                              " 64000 careful 0 verbose 0")

        if error:
            self.logger.critical(error)
            self.assertNotIn('failed', error)

    def test_bihash_vec64(self):
        """ Bihash vec64 Test """

        error = self.vapi.cli("test bihash vec64")

        if error:
            self.logger.critical(error)
            self.assertNotIn('failed', error)

    @unittest.skipUnless(config.gcov, "part of code coverage tests")
    def test_bihash_coverage(self):
        """ Improve Code Coverage """

        error = self.vapi.cli("test bihash nitems 10 ncycles 3" +
                              "search 2 careful 1 verbose 2 non-random-keys")

        if error:
            self.logger.critical(error)
            self.assertNotIn('failed', error)

        error = self.vapi.cli("test bihash nitems 10 nbuckets 1 ncycles 3" +
                              "search 2 careful 1 verbose 2 non-random-keys")
        if error:
            self.logger.critical(error)
            self.assertNotIn('failed', error)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
