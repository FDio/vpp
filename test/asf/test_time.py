#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2026 Cisco Systems, Inc.

"""Time handling unit tests"""

import unittest

from asfframework import VppAsfTestCase, VppTestRunner


class TestTime(VppAsfTestCase):
    """Time Handling Unit Test Cases"""

    vpp_worker_count = 1

    @classmethod
    def setUpClass(cls):
        super(TestTime, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestTime, cls).tearDownClass()

    def setUp(self):
        super(TestTime, self).setUp()

    def tearDown(self):
        super(TestTime, self).tearDown()

    def test_time_monotonicity(self):
        """Test that time never goes backward after frequency verification"""
        self.vapi.cli("test time monotonicity")

    def test_time_discontinuity(self):
        """Test that CPU time discontinuities are handled correctly"""
        self.vapi.cli("test time discontinuity")

    def test_time_small_discontinuity(self):
        """Test a backward CPU counter within the verification interval"""
        self.vapi.cli("test time small-discontinuity")

    def test_time_accumulated_error(self):
        """Test that accumulated phase error controls the slew rate"""
        self.vapi.cli("test time accumulated-error")

    def test_time_wall_step(self):
        """Test that wall clock steps reanchor without erasing earlier phase error"""
        self.vapi.cli("test time wall-step")

    def test_time_virtual_offset(self):
        """Test that virtual time offsets do not affect physical clock slewing"""
        self.vapi.cli("test time virtual-offset")

    def test_time_barrier_monotonicity(self):
        """Test that barrier sync preserves time monotonicity on workers"""
        self.vapi.cli("test time barrier")


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
