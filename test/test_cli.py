#!/usr/bin/env python3
"""CLI functional tests"""

import unittest

from framework import VppTestCase, VppTestRunner


class TestCLI(VppTestCase):
    """ CLI Test Case """
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        super(TestCLI, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestCLI, cls).tearDownClass()

    def setUp(self):
        super(TestCLI, self).setUp()

    def tearDown(self):
        super(TestCLI, self).tearDown()

    def test_cli_retval(self):
        """ CLI inband retval """
        rv = self.vapi.papi.cli_inband(cmd='this command does not exist')
        self.assertNotEqual(rv.retval, 0)

        rv = self.vapi.papi.cli_inband(cmd='show version')
        self.assertEqual(rv.retval, 0)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
