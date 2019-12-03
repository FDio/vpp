#!/usr/bin/env python3
"""CLI functional tests"""

import datetime
import time
import unittest

from vpp_papi import vpp_transport_shmem, vpp_transport_socket

from framework import VppTestCase, VppTestRunner


class TestCLI(VppTestCase):
    """ CLI Test Case over vapi shmem transport"""
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


class TestCLIoverVapiSocket(TestCLI):
    """ CLI Test Case over vapi socket transport"""
    vapi_transport = 'socket'

    def test_long_cli_delay(self):
        """ Test that VppApiClient raises VppTransportSocketIOError if timeout."""  # noqa
        with self.assertRaises(
                vpp_transport_socket.VppTransportSocketIOError) as ctx:
            rv = self.vapi.papi.cli_inband(cmd='wait 10')


class TestCLIExtendedVapiTimeout(VppTestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        cls.vapi_response_timeout = 15
        cls.__doc__ = " CLI Test Case (shmem) " \
                      "w/ Extended (%ssec) Vapi Timeout " \
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


class TestCLIExtendedVapiTimeoutoverVapiSocket(TestCLIExtendedVapiTimeout):
    vapi_transport = 'socket'

    @classmethod
    def setUpClass(cls):
        cls.vapi_response_timeout = 15
        cls.__doc__ = " CLI Test Case (socket) " \
                      "w/ Extended (%ssec) Vapi Timeout " \
                      % cls.vapi_response_timeout
        super(TestCLIExtendedVapiTimeout, cls).setUpClass()


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
