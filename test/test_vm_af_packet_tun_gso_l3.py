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


class TestVPPInterfacesQemuAfPacketTunGsoL3(TestVPPInterfacesQemu, VppTestCase):
    """Test af_packet & tun interfaces with GSO in L3 mode for IPv4/v6."""

    # Set test_id(s) to run from vm_test_config
    tests_to_run = "18"

    @classmethod
    def setUpClass(cls):
        super(TestVPPInterfacesQemuAfPacketTunGsoL3, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestVPPInterfacesQemuAfPacketTunGsoL3, cls).tearDownClass()

    def tearDown(self):
        super(TestVPPInterfacesQemuAfPacketTunGsoL3, self).tearDown()


SELECTED_TESTS = TestVPPInterfacesQemuAfPacketTunGsoL3.tests_to_run
tests = filter(TestSelector(SELECTED_TESTS).filter_tests, test_config["tests"])
generate_vpp_interface_tests(tests, TestVPPInterfacesQemuAfPacketTunGsoL3)

if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
