#!/usr/bin/env python3
"""CLI functional tests"""

import socket
import unittest

from vpp_papi import VPPIOError

from asfframework import VppAsfTestCase, VppTestRunner


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

    def test_interactive_control_sequence_preserves_next_character(self):
        """Buffered control sequences must not consume the start of show."""
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as cli:
            cli.settimeout(5)
            cli.connect(self.get_cli_sock_path())

            def read_prompt():
                output = b""
                while not output.endswith(b"# "):
                    chunk = cli.recv(4096)
                    self.assertTrue(chunk, "CLI closed before the prompt")
                    output += chunk
                return output

            # Advertise an interactive terminal, preserving character mode.
            cli.sendall(b"\xff\xfa\x18\x00xterm\xff\xf0")
            read_prompt()
            for control in (b"\x15", b"\x1b[H"):
                with self.subTest(control=control):
                    cli.sendall(control + b"show sr localsids\r")
                    output = read_prompt()
                    self.assertNotIn(b"unknown input", output)
                    self.assertIn(b"SRv6 - My LocalSID Table:", output)

    def test_long_cli_delay(self):
        """Test that VppApiClient raises VppIOError if timeout."""  # noqa
        with self.assertRaises(VPPIOError) as ctx:
            rv = self.vapi.papi.cli_inband(cmd="wait 10")

    def test_long_cli_delay_override(self):
        """Test per-command _timeout option."""  # noqa
        rv = self.vapi.papi.cli_inband(cmd="wait 10", _timeout=15)
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
        wait_secs = self.vapi_response_timeout - 1

        # get vpp time as float
        start = self.vapi.papi.show_vpe_system_time(
            _no_type_conversion=True
        ).vpe_system_time
        rv = self.vapi.papi.cli_inband(cmd="wait %s" % wait_secs)
        now = self.vapi.papi.show_vpe_system_time(
            _no_type_conversion=True
        ).vpe_system_time

        # assume that the overhead of the measurement is not more that .5 sec.
        self.assertEqual(round(now - start), wait_secs)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
