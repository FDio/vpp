#!/usr/bin/env python3
"""Temporary diagnostic: deliberately fail one test to check core logging."""

import unittest

from asfframework import VppTestRunner
from framework import VppTestCase


class TestCoreCrash(VppTestCase):
    """Core dump backtrace diagnostic"""

    def test_core_backtrace(self):
        """Deliberately crash VPP so the framework logs its core backtrace"""
        self.logger.error("Deliberately crashing VPP pid %s", self.vpp.pid)
        self.vapi.cli("test crash")
        self.fail("VPP unexpectedly survived 'test crash'")


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
