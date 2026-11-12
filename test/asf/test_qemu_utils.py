# SPDX-License-Identifier: Apache-2.0

"""Unprivileged regression tests for network helper command deadlines."""

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from asfframework import CPUInterface, VppTestRunner
from config import config
import vpp_qemu_utils as utils


class TestQemuUtils(CPUInterface, unittest.TestCase):
    """Network helper command deadlines"""

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
        directory = tempfile.TemporaryDirectory(prefix="vpp-qemu-lock-test-")
        self.addCleanup(directory.cleanup)
        for name, value in (
            ("net_helper_lock_path", str(Path(directory.name) / "helpers.lock")),
            ("net_helper_lock_timeout", 5),
        ):
            setting = patch.object(config, name, value)
            setting.start()
            self.addCleanup(setting.stop)

    def test_network_commands_have_timeout(self):
        """Network operations retain their options and gain a command deadline."""
        with patch.object(utils.subprocess, "run") as run:
            run.return_value = subprocess.CompletedProcess([], 0)
            self.assertTrue(utils.interface_exists("test-ns", "test-if"))
        run.assert_called_once_with(
            ["ip", "netns", "exec", "test-ns", "ip", "link", "show", "dev", "test-if"],
            timeout=utils.NETWORK_COMMAND_TIMEOUT,
            capture_output=True,
        )

    def test_command_timeout_releases_lock(self):
        """A real timed-out child does not prevent the next acquisition."""
        with patch.object(utils, "NETWORK_COMMAND_TIMEOUT", 0.05):
            with self.assertRaisesRegex(
                TimeoutError, "Network helper command timed out"
            ):
                with utils.net_helper_lock():
                    utils._run_network_command(
                        [sys.executable, "-c", "import time; time.sleep(30)"],
                        capture_output=True,
                    )
        with utils.net_helper_lock().acquire(timeout=0):
            pass

    def test_namespace_probe_does_not_hide_timeout(self):
        """A stuck capability probe is an error, not a reason to skip tests."""
        with patch.object(utils.subprocess, "run") as run:
            run.side_effect = subprocess.TimeoutExpired(
                ["ip", "netns", "add", "probe-ns"], utils.NETWORK_COMMAND_TIMEOUT
            )
            with self.assertRaisesRegex(TimeoutError, "ip netns add probe-ns"):
                utils.can_create_namespaces("probe-ns")
        with utils.net_helper_lock().acquire(timeout=0):
            pass


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
