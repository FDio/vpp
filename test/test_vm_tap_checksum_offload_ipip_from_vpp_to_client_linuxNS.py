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


class TestVPPInterfacesQemuTapChecksumOffloadIPIPVppToClientLinux(
    TestVPPInterfacesQemu, VppTestCase
):
    """Test tap checksum offload w/ ipip tunnel from vpp to iperf client Linux."""

    # Set test_id(s) to run from vm_test_config
    # The expansion of these numbers are included in the test docstring
    tests_to_run = "29"
    ip_versions = [4]
    mtus = test_config["mtus"]

    @classmethod
    def setUpClass(cls):
        super(
            TestVPPInterfacesQemuTapChecksumOffloadIPIPVppToClientLinux, cls
        ).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(
            TestVPPInterfacesQemuTapChecksumOffloadIPIPVppToClientLinux, cls
        ).tearDownClass()

    def tearDown(self):
        super(
            TestVPPInterfacesQemuTapChecksumOffloadIPIPVppToClientLinux, self
        ).tearDown()


SELECTED_TESTS = (
    TestVPPInterfacesQemuTapChecksumOffloadIPIPVppToClientLinux.tests_to_run
)
tests = filter(TestSelector(SELECTED_TESTS).filter_tests, test_config["tests"])
generate_vpp_interface_tests(
    tests,
    TestVPPInterfacesQemuTapChecksumOffloadIPIPVppToClientLinux,
    ip_versions=TestVPPInterfacesQemuTapChecksumOffloadIPIPVppToClientLinux.ip_versions,
    mtus=TestVPPInterfacesQemuTapChecksumOffloadIPIPVppToClientLinux.mtus,
)

if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
