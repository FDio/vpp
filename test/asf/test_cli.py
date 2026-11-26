#!/usr/bin/env python3
"""CLI functional tests"""

import unittest

from vpp_papi import VPPIOError

from asfframework import VppAsfTestCase, VppTestRunner

# This command must outlast the standard five-second API timeout.
CLI_REPLY_DELAY = 7


class TestCLI(VppAsfTestCase):
    """CLI Test Case"""

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
        """CLI inband retval"""
        rv = self.vapi.papi.cli_inband(cmd="this command does not exist")
        self.assertNotEqual(rv.retval, 0)

        rv = self.vapi.papi.cli_inband(cmd="show version")
        self.assertEqual(rv.retval, 0)

    def test_long_cli_delay(self):
        """Test that VppApiClient raises VppIOError if timeout."""  # noqa
        with self.assertRaisesRegex(VPPIOError, "VPP API client: read failed"):
            self.vapi.papi.cli_inband(cmd="wait 10")

    def test_long_cli_delay_override(self):
        """Test per-command _timeout option."""  # noqa
        rv = self.vapi.papi.cli_inband(cmd=f"wait {CLI_REPLY_DELAY}", _timeout=15)
        self.assertEqual(rv.retval, 0)


class TestCLIExtendedVapiTimeout(VppAsfTestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        cls.vapi_response_timeout = 15
        cls.__doc__ = (
            " CLI Test Case w/ Extended (%ssec) Vapi Timeout "
            % cls.vapi_response_timeout
        )
        super(TestCLIExtendedVapiTimeout, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestCLIExtendedVapiTimeout, cls).tearDownClass()

    def setUp(self):
        super(TestCLIExtendedVapiTimeout, self).setUp()

    def tearDown(self):
        super(TestCLIExtendedVapiTimeout, self).tearDown()

    def test_long_cli_delay(self):
        """Test that delayed result returns with extended timeout."""
        # get vpp time as float
        start = self.vapi.papi.show_vpe_system_time(
            _no_type_conversion=True
        ).vpe_system_time
        rv = self.vapi.papi.cli_inband(cmd=f"wait {CLI_REPLY_DELAY}")
        self.assertEqual(rv.retval, 0)
        now = self.vapi.papi.show_vpe_system_time(
            _no_type_conversion=True
        ).vpe_system_time

        # assume that the overhead of the measurement is not more that .5 sec.
        self.assertEqual(round(now - start), CLI_REPLY_DELAY)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
