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


class TestVPPInterfacesQemuAfPacketGsoL2(TestVPPInterfacesQemu, VppTestCase):
    """Test af_packet interfaces with GSO in L2 mode for IPv4/v6."""

    # Set test_id(s) to run from vm_test_config
    tests_to_run = "14,16,22,23"

    @classmethod
    def setUpClass(cls):
        super(TestVPPInterfacesQemuAfPacketGsoL2, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestVPPInterfacesQemuAfPacketGsoL2, cls).tearDownClass()

    def tearDown(self):
        super(TestVPPInterfacesQemuAfPacketGsoL2, self).tearDown()


SELECTED_TESTS = TestVPPInterfacesQemuAfPacketGsoL2.tests_to_run
tests = filter(TestSelector(SELECTED_TESTS).filter_tests, test_config["tests"])
generate_vpp_interface_tests(tests, TestVPPInterfacesQemuAfPacketGsoL2)

if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
