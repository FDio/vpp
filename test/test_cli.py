#!/usr/bin/env python3
"""CLI functional tests"""

import time
import unittest

from vpp_papi import vpp_transport_shmem

from framework import VppTestCase, VppTestRunner


class TestCLI(VppTestCase):
    """ CLI Test Case """
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        cls.vapi_response_timeout = 5
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

    def test_long_cli_delay(self):
        """ Test that VppApiClient raises VppTransportShmemIOError if timeout."""  # noqa
        with self.assertRaises(
                vpp_transport_shmem.VppTransportShmemIOError) as ctx:
            rv = self.vapi.papi.cli_inband(cmd='wait 10')


class TestCLIExtendedVapiTimeout(VppTestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        cls.vapi_response_timeout = 15
        cls.__doc__ = " CLI Test Case w/ Extended (%ssec) Vapi Timeout " \
                      % cls.vapi_response_timeout
        super(TestCLIExtendedVapiTimeout, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestCLIExtendedVapiTimeout, cls).tearDownClass()

    def setUp(self):
        super(TestCLIExtendedVapiTimeout, self).setUp()

    def tearDown(self):
        super(TestCLIExtendedVapiTimeout, self).tearDown()

    def test_long_cli_delay(self):
        """ Test that delayed result returns with extended timeout."""
        wait_secs = self.vapi_response_timeout - 1
        start = time.time()
        rv = self.vapi.papi.cli_inband(cmd='wait %s' % wait_secs)
        now = time.time()
        self.assertGreater(wait_secs, now - start)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
