# SPDX-License-Identifier: Apache-2.0

import logging
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from asfframework import CPUInterface, VppTestRunner
import vpp_iperf


class TestIperfRetryWindow(CPUInterface, unittest.TestCase):
    """iPerf startup and connection retry timing"""

    @classmethod
    def is_tagged_run_solo(cls):
        return False

    @classmethod
    def has_tag(cls, tag):
        return False

    @classmethod
    def get_cores_required(cls):
        return 0

    def setUp(self):
        self.now = 0
        clock = SimpleNamespace(monotonic=lambda: self.now, sleep=self.advance)
        with patch.object(
            vpp_iperf.VppIperf, "get_iperf", return_value="/usr/bin/iperf3"
        ):
            self.iperf = vpp_iperf.VppIperf(
                "server", "client", "192.0.2.2", logging.getLogger(self.id())
            )
        for setting in (
            patch.object(vpp_iperf, "time", clock),
            patch.object(vpp_iperf.VppAsfTestCase, "sleep", self.advance),
        ):
            setting.start()
            self.addCleanup(setting.stop)
        command = patch.object(vpp_iperf.subprocess, "run")
        self.run_command = command.start()
        self.addCleanup(command.stop)

    def advance(self, delay):
        self.now += delay

    def test_early_refusal_keeps_all_regular_attempts(self):
        """A delayed TCP path still gets its last attempt at nine seconds."""
        attempts = []

        def connect(args, **kwargs):
            attempts.append(self.now)
            if self.now >= 7:
                return subprocess.CompletedProcess(args, 0, "transfer completed", "")
            return subprocess.CompletedProcess(
                args, 1, "", "iperf3: error - unable to connect to server"
            )

        self.run_command.side_effect = connect
        self.assertEqual(self.iperf.start_iperf_client(3).returncode, 0)
        self.assertEqual(attempts, [0, 3, 6, 9])

    def test_early_success_completes_immediately(self):
        """A completed early transfer is the test result."""
        result = subprocess.CompletedProcess([], 0, "transfer completed", "")
        self.run_command.return_value = result
        self.assertIs(self.iperf.start_iperf_client(3), result)
        self.assertEqual(self.now, 0)
        self.run_command.assert_called_once()

    def test_early_transfer_failure_is_decisive(self):
        """A failed attempt with transfer output remains a failure."""
        result = subprocess.CompletedProcess(
            [], 1, "transfer started", "iperf3: error - unable to connect to server"
        )
        self.run_command.return_value = result
        self.assertIs(self.iperf.start_iperf_client(3), result)
        self.run_command.assert_called_once()

    def test_early_client_timeout_is_decisive(self):
        """A timeout of uncertain provenance remains a failure."""
        self.run_command.side_effect = subprocess.TimeoutExpired(["iperf3"], 22)
        with self.assertRaises(subprocess.TimeoutExpired):
            self.iperf.start_iperf_client(3)
        self.run_command.assert_called_once()

    def test_expected_server_pid_allows_early_connection(self):
        """Only the expected server socket enables the early attempt."""
        server = Mock(pid=123)
        server.poll.return_value = None
        self.run_command.side_effect = [
            subprocess.CompletedProcess([], 0, "pid=999,", ""),
            subprocess.CompletedProcess([], 0, "pid=123,", ""),
        ]
        self.assertEqual(self.iperf.wait_for_iperf_server(server, ["ip"]), 3)
        self.assertEqual(self.now, 0.05)

    def test_probe_failure_waits_until_regular_start_time(self):
        """Unavailable socket discovery leaves the regular startup delay."""
        server = Mock(pid=123)
        server.poll.return_value = None
        self.run_command.side_effect = subprocess.CalledProcessError(127, ["ss"])
        self.assertIsNone(self.iperf.wait_for_iperf_server(server, ["ip"]))
        self.assertEqual(self.now, 3)

    def test_iperf2_waits_until_regular_start_time(self):
        """The legacy client retains its regular startup schedule."""
        self.iperf.iperf = "/usr/bin/iperf"
        server = Mock(pid=123)
        server.poll.return_value = None
        self.assertIsNone(self.iperf.wait_for_iperf_server(server, ["ip"]))
        self.assertEqual(self.now, 3)
        self.run_command.assert_not_called()


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
