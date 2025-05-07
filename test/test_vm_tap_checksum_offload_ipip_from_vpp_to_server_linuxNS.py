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


class TestVPPInterfacesQemuTapChecksumOffloadIPIPVppToServerLinux(
    TestVPPInterfacesQemu, VppTestCase
):
    """Test tap checksum offload w/ ipip tunnel from vpp to iperf server Linux."""

    # Set test_id(s) to run from vm_test_config
    # The expansion of these numbers are included in the test docstring
    tests_to_run = "28"
    ip_versions = [4]
    mtus = test_config["mtus"]

    @classmethod
    def setUpClass(cls):
        super(
            TestVPPInterfacesQemuTapChecksumOffloadIPIPVppToServerLinux, cls
        ).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(
            TestVPPInterfacesQemuTapChecksumOffloadIPIPVppToServerLinux, cls
        ).tearDownClass()

    def tearDown(self):
        super(
            TestVPPInterfacesQemuTapChecksumOffloadIPIPVppToServerLinux, self
        ).tearDown()


SELECTED_TESTS = (
    TestVPPInterfacesQemuTapChecksumOffloadIPIPVppToServerLinux.tests_to_run
)
tests = filter(TestSelector(SELECTED_TESTS).filter_tests, test_config["tests"])
generate_vpp_interface_tests(
    tests,
    TestVPPInterfacesQemuTapChecksumOffloadIPIPVppToServerLinux,
    ip_versions=TestVPPInterfacesQemuTapChecksumOffloadIPIPVppToServerLinux.ip_versions,
    mtus=TestVPPInterfacesQemuTapChecksumOffloadIPIPVppToServerLinux.mtus,
)

if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
