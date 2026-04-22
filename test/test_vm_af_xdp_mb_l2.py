#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

import unittest
from framework import VppTestCase
from vm_vpp_interfaces import (
    AfXDPTestLockMixin,
    TestSelector,
    TestVPPInterfacesQemu,
    generate_vpp_interface_tests,
)
from asfframework import VppTestRunner, has_kernel_af_xdp_multi_buffer
from vm_test_config import test_config


@unittest.skipUnless(
    has_kernel_af_xdp_multi_buffer,
    "kernel < 6.6: AF_XDP multi-buffer (XDP_USE_SG/XDP_PKT_CONTD) not supported",
)
class TestVPPInterfacesQemuAfXDPMBL2(
    AfXDPTestLockMixin, TestVPPInterfacesQemu, VppTestCase
):
    """Test af_xdp interfaces in multi-buffer L2 mode for IPv4/v6."""

    # Set test_id(s) to run from vm_test_config
    # The expansion of these numbers are included in the test docstring
    tests_to_run = "30"

    def tearDown(self):
        super(TestVPPInterfacesQemuAfXDPMBL2, self).tearDown()


SELECTED_TESTS = TestVPPInterfacesQemuAfXDPMBL2.tests_to_run
tests = filter(TestSelector(SELECTED_TESTS).filter_tests, test_config["tests"])
generate_vpp_interface_tests(tests, TestVPPInterfacesQemuAfXDPMBL2)

if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
