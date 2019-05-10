#!/usr/bin/env python
"""CLI functional tests"""

import unittest
from framework import VppTestCase, VppTestRunner


class TestCLI(VppTestCase):
    """ CLI Test Case """
    maxDiff = None

    # from api_errno.h
    SYNTAX_ERROR = -158

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

    def test_cli_retval_syntax_error(self):
        """ CLI inband retval returning SYNTAX_ERROR"""
        rv = self.vapi.papi.cli_inband(cmd='this command does not exist')
        self.assertEqual(rv.retval, self.SYNTAX_ERROR)

    def test_cli_retval_0(self):
        """ CLI inband retval returning 0"""
        rv = self.vapi.papi.cli_inband(cmd='show version')
        self.assertEqual(rv.retval, 0)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
