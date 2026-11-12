# SPDX-License-Identifier: Apache-2.0

"""Unprivileged regression tests for iperf process launch and CPU affinity."""

import logging
import os
import subprocess
import sys
import unittest
from unittest.mock import patch

from asfframework import CPUInterface, VppTestRunner
import vpp_iperf


class TestIperf(CPUInterface, unittest.TestCase):
    """iPerf launch and CPU affinity helpers"""

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
        with patch.object(
            vpp_iperf.VppIperf, "get_iperf", return_value="/usr/bin/iperf3"
        ):
            self.iperf = vpp_iperf.VppIperf(
                server_ns="server-ns",
                client_ns="client-ns",
                server_ip="10.0.1.102",
                logger=logging.getLogger(self.id()),
            )
        self.iperf.cpus = [4, 2, 4]
        self.iperf.duration = 2

    def test_client_uses_taskset_without_preexec(self):
        """The client keeps its options without a Python pre-exec callback."""
        self.iperf.client_args = "-4 -p 5019"
        with patch.object(vpp_iperf.shutil, "which", return_value="/usr/bin/taskset"):
            with patch.object(vpp_iperf.subprocess, "run") as run:
                run.return_value = subprocess.CompletedProcess([], 0, "", "")
                self.iperf.start_iperf_client()
        run.assert_called_once_with(
            [
                "/usr/bin/taskset",
                "-c",
                "2,4",
                "ip",
                "netns",
                "exec",
                "client-ns",
                "/usr/bin/iperf3",
                "-c",
                "10.0.1.102",
                "-t",
                "2",
                "-4",
                "-p",
                "5019",
                "--connect-timeout",
                "3000",
            ],
            timeout=22,
            encoding="utf-8",
            capture_output=True,
        )

    def test_server_preserves_cleanup_arguments(self):
        """The taskset prefix must not enter the daemon's cleanup identity."""
        self.iperf.server_args = "-6 -p 5015"
        with patch.object(vpp_iperf.shutil, "which", return_value="/usr/bin/taskset"):
            with patch.object(vpp_iperf.subprocess, "run") as run:
                run.return_value = subprocess.CompletedProcess([], 0, "", "")
                with patch.object(vpp_iperf.VppAsfTestCase, "sleep"):
                    cleanup_args = self.iperf.start_iperf_server()
        self.assertEqual(
            cleanup_args, ["/usr/bin/iperf3", "-s", "-D", "-6", "-p", "5015"]
        )
        run.assert_called_once_with(
            [
                "/usr/bin/taskset",
                "-c",
                "2,4",
                "ip",
                "netns",
                "exec",
                "server-ns",
                *cleanup_args,
            ],
            timeout=22,
            encoding="utf-8",
            capture_output=True,
        )

    def test_missing_taskset_is_reported(self):
        """Missing affinity support fails clearly without an unsafe fallback."""
        with patch.object(vpp_iperf.shutil, "which", return_value=None):
            with patch.object(vpp_iperf.subprocess, "run") as run:
                for start in (
                    self.iperf.start_iperf_client,
                    self.iperf.start_iperf_server,
                ):
                    with self.subTest(start=start.__name__):
                        with self.assertRaisesRegex(
                            RuntimeError, "taskset is required"
                        ):
                            start()
                run.assert_not_called()

    def test_unspecified_affinity_does_not_keep_driver_pin(self):
        """Without helper CPUs, request the existing broad fallback mask."""
        with patch.object(vpp_iperf.shutil, "which", return_value="/usr/bin/taskset"):
            with patch.object(vpp_iperf.os, "cpu_count", return_value=4):
                for cpus in (None, []):
                    self.assertEqual(
                        vpp_iperf.iperf_command_with_affinity(["iperf3"], cpus),
                        ["/usr/bin/taskset", "-c", "0,1,2,3", "iperf3"],
                    )

    def test_real_child_uses_requested_affinity(self):
        """A child can move off the parent's VPP-main-style CPU pin."""
        original_cpus = os.sched_getaffinity(0)
        driver_cpu = min(original_cpus)
        helper_cpu = max(original_cpus)
        command = vpp_iperf.iperf_command_with_affinity(
            [sys.executable, "-c", "import os; print(sorted(os.sched_getaffinity(0)))"],
            [helper_cpu],
        )
        try:
            os.sched_setaffinity(0, {driver_cpu})
            result = subprocess.run(
                command, capture_output=True, text=True, check=True, timeout=5
            )
        finally:
            os.sched_setaffinity(0, original_cpus)
        self.assertEqual(result.stdout.strip(), str([helper_cpu]))

    def test_affinity_error_is_not_retried_or_hidden(self):
        """A taskset failure remains a client/server error, not a connect retry."""
        error = "taskset: failed to set pid 123's affinity: Invalid argument"
        with patch.object(vpp_iperf.shutil, "which", return_value="/usr/bin/taskset"):
            with patch.object(vpp_iperf.subprocess, "run") as run:
                run.return_value = subprocess.CompletedProcess([], 1, "", error)
                with self.assertLogs(self.iperf.logger, level="ERROR"):
                    self.assertFalse(self.iperf.start(client_only=True))
                self.assertEqual(run.call_count, 1)
                with self.assertRaisesRegex(Exception, "Failed to start iPerf server"):
                    self.iperf.start_iperf_server()
                self.assertEqual(run.call_count, 2)

    def test_connect_failure_still_retries(self):
        """Existing transient connection retry behavior is unchanged."""
        with patch.object(vpp_iperf.shutil, "which", return_value="/usr/bin/taskset"):
            with patch.object(vpp_iperf.subprocess, "run") as run:
                run.side_effect = [
                    subprocess.CompletedProcess(
                        [], 1, "", "unable to connect to server"
                    ),
                    subprocess.CompletedProcess([], 0, "", ""),
                ]
                with patch.object(vpp_iperf.VppAsfTestCase, "sleep") as sleep:
                    with self.assertLogs(self.iperf.logger, level="WARNING"):
                        self.assertEqual(self.iperf.start_iperf_client().returncode, 0)
                sleep.assert_called_once_with(self.iperf.client_retry_delay)
                self.assertEqual(run.call_count, 2)

    def test_client_timeout_still_exhausts_retries(self):
        """Timeouts stay bounded and retain the captured failure output."""
        with patch.object(vpp_iperf.shutil, "which", return_value="/usr/bin/taskset"):
            with patch.object(vpp_iperf.subprocess, "run") as run:
                run.side_effect = subprocess.TimeoutExpired(
                    ["taskset", "-c", "2,4", "ip"],
                    22,
                    output=b"partial",
                    stderr=b"error",
                )
                with patch.object(vpp_iperf.VppAsfTestCase, "sleep"):
                    with self.assertLogs(self.iperf.logger, level="WARNING"):
                        with self.assertRaisesRegex(Exception, "partialerror"):
                            self.iperf.start_iperf_client()
                self.assertEqual(run.call_count, self.iperf.client_retries)

    def test_ipv6_options_for_iperf_and_iperf3(self):
        """Legacy iperf retains -V, while iperf3 retains -6."""
        for executable, ipv6_option in (
            ("/usr/bin/iperf", "-V"),
            ("/usr/bin/iperf3", "-6"),
        ):
            with self.subTest(executable=executable):
                with patch.object(
                    vpp_iperf.VppIperf, "get_iperf", return_value=executable
                ):
                    with patch.object(
                        vpp_iperf.VppIperf, "start", autospec=True
                    ) as start:
                        vpp_iperf.start_iperf(ip_version=6, cpus=[2, 4])
                        iperf = start.call_args.args[0]
                        self.assertEqual(iperf.client_args.split(), [ipv6_option])
                        self.assertEqual(iperf.server_args.split(), [ipv6_option])
                        self.assertEqual(iperf.cpus, [2, 4])


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
