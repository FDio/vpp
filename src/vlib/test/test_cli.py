#!/usr/bin/env python3
"""CLI functional tests"""

import datetime
import time
import unittest

from vpp_papi import vpp_transport_shmem

from framework import VppTestCase, VppTestRunner


class TestCLI(VppTestCase):
    """ CLI Test Case """
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        # using the framework default
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

    def test_long_cli_delay_override(self):
        """ Test per-command _timeout option."""  # noqa
        rv = self.vapi.papi.cli_inband(cmd='wait 10', _timeout=15)
        self.assertEqual(rv.retval, 0)

    def test_comment_logging(self):
        """ test comment logging """
        c1 = "this_is_comment_foo..."
        c1a = " baz"
        c2 = "this is comment bar..."
        rv = self.vapi.papi.cli_inband(cmd='cli log-comments on')
        rv = self.vapi.papi.cli_inband(cmd=f'comment {c1+c1a}')
        rv = self.vapi.papi.cli_inband(
            cmd=f'comment {{{c2}}}')
        log = self.vapi.papi.cli_inband(cmd="show log").reply

        # without braces, the first term should be logged.
        self.assertIn(c1, log)
        # but not the term following the space.
        self.assertNotIn(c1a, log)
        # inside {} the line with spaces should be logged.
        self.assertIn(c2, log)


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

        # get vpp time as float
        start = self.vapi.papi.show_vpe_system_time(
            _no_type_conversion=True).vpe_system_time
        rv = self.vapi.papi.cli_inband(cmd='wait %s' % wait_secs)
        now = self.vapi.papi.show_vpe_system_time(
            _no_type_conversion=True).vpe_system_time

        # assume that the overhead of the measurement is not more that .5 sec.
        self.assertEqual(round(now - start), wait_secs)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
