#!/usr/bin/env python3

import unittest

from framework import VppTestCase, VppTestRunner
from vpp_ip_route import VppIpTable, VppIpRoute, VppRoutePath


class TestOsClock(VppTestCase):
    """ OS clock Test Cases """

    @classmethod
    def setUpClass(cls):
        super(TestOsClock, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestOsClock, cls).tearDownClass()

    def setUp(self):
        super(TestOsClock, self).setUp()

    def tearDown(self):
        super(TestOsClock, self).tearDown()

    def test_clock_unittest(self):
        """ OS clock unit tests """
        error = self.vapi.cli("test os-clock")
        if error.find("failed") != -1:
            self.logger.critical("FAILURE in the " + name + " test")
            self.assertNotIn("failed", error)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
