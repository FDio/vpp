#!/usr/bin/env python

import unittest

from framework import VppTestCase, VppTestRunner
from vpp_ip_route import VppIpTable, VppIpRoute, VppRoutePath


class TestBihash(VppTestCase):
    """ Bihash Test Cases """

    def test_bihash_unittest(self):
        """ Bihash Add/Del Test """
        error = self.vapi.cli("test bihash ")

        if error:
            self.logger.critical(error)
            self.assertNotIn('failed', error)

    def test_bihash_thread(self):
        """ Bihash Thread Test """

        error = self.vapi.cli("test bihash threads 2 nbuckets 64000")

        if error:
            self.logger.critical(error)
            self.assertNotIn('failed', error)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
