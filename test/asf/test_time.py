#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2026 Cisco Systems, Inc.

"""Time handling unit tests"""

import unittest

from asfframework import VppAsfTestCase, VppTestRunner


class TestTime(VppAsfTestCase):
    """Time Handling Unit Test Cases"""

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

    def test_timer_wheel_backward_time(self):
        """Test that timer wheel preserves high-water mark on backward time"""
        error = self.vapi.cli("test time timer-wheel")
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
