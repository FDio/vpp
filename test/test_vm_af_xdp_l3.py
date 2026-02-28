#!/usr/bin/env python3

import unittest
from framework import VppTestCase
from vm_vpp_interfaces import (
    TestSelector,
    TestVPPInterfacesQemu,
    generate_vpp_interface_tests,
)
from asfframework import VppTestRunner
from vm_test_config import test_config
import fcntl
import time
import platform


def kernel_supports_xdp_multibuffer():
    """Check if kernel version >= 5.18 (required for XDP multi-buffer support)"""
    try:
        release = platform.release()
        # Parse kernel version string (e.g., "5.15.0-91-generic" -> (5, 15))
        parts = release.split("-")[0].split(".")
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
        return (major, minor) >= (5, 18)
    except (ValueError, IndexError):
        # If we can't parse the version, assume it doesn't support multi-buffer
        return False


@unittest.skipIf(
    not kernel_supports_xdp_multibuffer(),
    "Kernel version < 5.18 does not support XDP multi-buffer (required for AF_XDP jumbo frames)",
)
class TestVPPInterfacesQemuAfXDPL3(TestVPPInterfacesQemu, VppTestCase):
    """Test af_xdp interfaces in L3 mode for IPv4/v6."""

    # Set test_id(s) to run from vm_test_config
    # The expansion of these numbers are included in the test docstring
    tests_to_run = "29"

    @classmethod
    def setUpClass(cls):
        # Create lock file to prevent concurrent test runs of af_xdp tests
        # as they interfere with each other
        cls.lock_file_path = "/tmp/vpp_af_xdp_test.lock"
        cls.lock_file = open(cls.lock_file_path, "w")

        # Wait for lock
        attempt = 0
        while True:
            try:
                fcntl.flock(cls.lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except IOError:
                attempt += 1
                if attempt > 120:  # Wait up to 2 minutes
                    raise Exception("Could not acquire lock for AF_XDP tests")
                time.sleep(1)

        super(TestVPPInterfacesQemuAfXDPL3, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        try:
            super(TestVPPInterfacesQemuAfXDPL3, cls).tearDownClass()
        finally:
            # Release lock
            if hasattr(cls, "lock_file"):
                fcntl.flock(cls.lock_file, fcntl.LOCK_UN)
                cls.lock_file.close()

    def tearDown(self):
        super(TestVPPInterfacesQemuAfXDPL3, self).tearDown()


SELECTED_TESTS = TestVPPInterfacesQemuAfXDPL3.tests_to_run
tests = filter(TestSelector(SELECTED_TESTS).filter_tests, test_config["tests"])
generate_vpp_interface_tests(tests, TestVPPInterfacesQemuAfXDPL3)

if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
