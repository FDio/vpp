#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2026 Cisco Systems, Inc.

"""Time handling unit tests"""

import unittest

from asfframework import VppAsfTestCase, VppTestRunner


class TestTime(VppAsfTestCase):
    """Time Handling Unit Test Cases"""

    vpp_worker_count = 2

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
        error = self.vapi.cli("test time monotonicity")
        if error:
            self.logger.critical(error)
        self.assertNotIn("failed", error.lower())
        self.assertNotIn("error", error.lower())

    def test_time_discontinuity(self):
        """Test that CPU time discontinuities are handled correctly"""
        error = self.vapi.cli("test time discontinuity")
        if error:
            self.logger.critical(error)
        self.assertNotIn("failed", error.lower())
        self.assertNotIn("error", error.lower())

    def test_time_small_backward_jump(self):
        """Test that small backward CPU time jumps are handled correctly"""
        error = self.vapi.cli("test time small-backward")
        if error:
            self.logger.critical(error)
        self.assertNotIn("failed", error.lower())
        self.assertNotIn("error", error.lower())

    def test_barrier_time_monotonicity(self):
        """Test that barrier sync preserves time monotonicity on workers"""
        error = self.vapi.cli("test time barrier")
        if error:
            self.logger.critical(error)
        self.assertNotIn("failed", error.lower())
        self.assertNotIn("error", error.lower())

    def test_time_all(self):
        """Run all time tests"""
        error = self.vapi.cli("test time all")
        if error:
            self.logger.critical(error)
        self.assertNotIn("failed", error.lower())
        self.assertNotIn("error", error.lower())


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
