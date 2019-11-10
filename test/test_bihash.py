#!/usr/bin/env python3

import unittest

from framework import VppTestCase, VppTestRunner
from vpp_ip_route import (
    VppIpRoute,
    VppIpTable,
    VppRoutePath,
)


class TestBihash(VppTestCase):
    """ Bihash Test Cases """

    @classmethod
    def setUpClass(cls):
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

    def test_bihash_coverage(self):
        """ Improve Code Coverage """

        error = self.vapi.cli("test bihash nitems 10 ncycles 3" +
                              "search 2 careful 1 verbose 2 non-random-keys")

        if error:
            self.logger.critical(error)
            self.assertNotIn('failed', error)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
