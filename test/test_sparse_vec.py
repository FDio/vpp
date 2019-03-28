#!/usr/bin/env python

import unittest

from framework import VppTestCase, VppTestRunner
from vpp_ip_route import VppIpTable, VppIpRoute, VppRoutePath


class TestSparseVec(VppTestCase):
    """ SparseVec Test Cases """

    @classmethod
    def setUpClass(cls):
        super(TestSparseVec, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestSparseVec, cls).tearDownClass()

    def setUp(self):
        super(TestSparseVec, self).setUp()

    def tearDown(self):
        super(TestSparseVec, self).tearDown()

    def test_string_unittest(self):
        """ SparseVec unit tests """
        error = self.vapi.cli("test sparse_vec")
        if error.find("failed") != -1:
            self.logger.critical("FAILURE in the sparse_vec test")
        self.assertNotIn("failed", error)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
