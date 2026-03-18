#!/usr/bin/env python3
"""Tests for global default rx-mode setting"""

import unittest

from framework import VppTestCase
from asfframework import VppTestRunner


class TestDefaultRxMode(VppTestCase):
    """Default RX Mode Test Case"""

    def test_show_default_rx_mode(self):
        """verify default rx-mode is polling at startup"""
        reply = self.vapi.cli("show interface default rx-mode")
        self.assertIn("polling", reply.lower())

    def test_set_default_rx_mode_interrupt(self):
        """set default rx-mode to interrupt and verify"""
        self.vapi.cli("set interface default rx-mode interrupt")
        reply = self.vapi.cli("show interface default rx-mode")
        self.assertIn("interrupt", reply.lower())

    def test_set_default_rx_mode_adaptive(self):
        """set default rx-mode to adaptive and verify"""
        self.vapi.cli("set interface default rx-mode adaptive")
        reply = self.vapi.cli("show interface default rx-mode")
        self.assertIn("adaptive", reply.lower())

    def test_set_default_rx_mode_polling(self):
        """set default rx-mode back to polling and verify"""
        self.vapi.cli("set interface default rx-mode interrupt")
        self.vapi.cli("set interface default rx-mode polling")
        reply = self.vapi.cli("show interface default rx-mode")
        self.assertIn("polling", reply.lower())

    def test_default_rx_mode_persists_across_changes(self):
        """setting rx-mode multiple times keeps the last value"""
        self.vapi.cli("set interface default rx-mode interrupt")
        self.vapi.cli("set interface default rx-mode adaptive")
        self.vapi.cli("set interface default rx-mode polling")
        reply = self.vapi.cli("show interface default rx-mode")
        self.assertIn("polling", reply.lower())

    def test_invalid_rx_mode(self):
        """reject invalid rx-mode value"""
        with self.assertRaises(Exception):
            self.vapi.cli("set interface default rx-mode test")


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
