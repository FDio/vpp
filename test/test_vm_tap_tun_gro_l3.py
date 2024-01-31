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


class TestVPPInterfacesQemuTapTunGroL3(TestVPPInterfacesQemu, VppTestCase):
    """Test tap & tun interfaces with GRO in L3 mode for IPv4/v6."""

    # Set test_id(s) to run from vm_test_config
    tests_to_run = "10,11"

    @classmethod
    def setUpClass(cls):
        super(TestVPPInterfacesQemuTapTunGroL3, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestVPPInterfacesQemuTapTunGroL3, cls).tearDownClass()

    def tearDown(self):
        super(TestVPPInterfacesQemuTapTunGroL3, self).tearDown()


SELECTED_TESTS = TestVPPInterfacesQemuTapTunGroL3.tests_to_run
tests = filter(TestSelector(SELECTED_TESTS).filter_tests, test_config["tests"])
generate_vpp_interface_tests(tests, TestVPPInterfacesQemuTapTunGroL3)

if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
