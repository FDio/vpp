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


class TestVPPInterfacesQemuAfXDPL2Base(TestVPPInterfacesQemu, VppTestCase):
    """Test af_xdp interfaces in L2 mode for IPv4/v6."""

    tests_to_run = ""

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

        super(TestVPPInterfacesQemuAfXDPL2Base, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        try:
            super(TestVPPInterfacesQemuAfXDPL2Base, cls).tearDownClass()
        finally:
            # Release lock
            if hasattr(cls, "lock_file"):
                fcntl.flock(cls.lock_file, fcntl.LOCK_UN)
                cls.lock_file.close()

    def tearDown(self):
        super(TestVPPInterfacesQemuAfXDPL2Base, self).tearDown()


class TestVPPInterfacesQemuAfXDPL2Single(TestVPPInterfacesQemuAfXDPL2Base):
    """Test af_xdp interfaces in L2 mode for IPv4/v6."""

    tests_to_run = "28"


class TestVPPInterfacesQemuAfXDPL2Multi(TestVPPInterfacesQemuAfXDPL2Base):
    """Test af_xdp interfaces in L2 mode for IPv4/v6."""

    tests_to_run = "30"


for cls in (TestVPPInterfacesQemuAfXDPL2Single, TestVPPInterfacesQemuAfXDPL2Multi):
    tests = filter(TestSelector(cls.tests_to_run).filter_tests, test_config["tests"])
    generate_vpp_interface_tests(tests, cls)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
