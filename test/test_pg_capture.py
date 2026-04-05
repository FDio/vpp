# Copyright 2026 Rubicon Communications, LLC.
# SPDX-License-Identifier: Apache-2.0

#!/usr/bin/env python3
"""Tests for pg interface capture mechanics."""

import unittest

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from framework import VppTestCase
from asfframework import VppTestRunner
from vpp_pg_interface import CaptureTimeoutError, CaptureMismatchError
from util import UnexpectedPacketError


class TestPgCapture(VppTestCase):
    """Test pg interface capture"""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.create_pg_interfaces([0, 1])
        for i in cls.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()

    def _make_pkts(self, count):
        """Create *count* packets from pg0 to pg1."""
        return [
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4)
            / UDP(sport=1234, dport=1234)
            / Raw(b"x" * 64)
        ] * count

    # ------------------------------------------------------------------ #
    #  positive cases                                                     #
    # ------------------------------------------------------------------ #

    def test_forward_257_packets(self):
        """Forward 257 packets from pg0 to pg1 and verify capture"""
        pkts = self._make_pkts(257)
        rx = self.send_and_expect(self.pg0, pkts, self.pg1)
        self.assertEqual(len(rx), 257)

    def test_forward_single_packet(self):
        """Forward a single packet from pg0 to pg1"""
        pkts = self._make_pkts(1)
        rx = self.send_and_expect(self.pg0, pkts, self.pg1)
        self.assertEqual(len(rx), 1)

    def test_send_and_assert_no_replies(self):
        """Packets to unknown dest produce no output on pg1"""
        pkt = (
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / IP(src=self.pg0.remote_ip4, dst="203.0.113.1")
            / UDP(sport=1234, dport=1234)
            / Raw(b"x" * 64)
        )
        self.send_and_assert_no_replies(self.pg0, [pkt] * 10)

    def test_assert_nothing_captured_directly(self):
        """assert_nothing_captured succeeds when no packets arrive"""
        pkt = (
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / IP(src=self.pg0.remote_ip4, dst="203.0.113.1")
            / UDP(sport=1234, dport=1234)
        )
        self.pg0.add_stream([pkt])
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.assert_nothing_captured()

    def test_capture_timeout_error(self):
        """CaptureTimeoutError raised when expected packets never arrive"""
        pkt = (
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / IP(src=self.pg0.remote_ip4, dst="203.0.113.1")
            / UDP(sport=1234, dport=1234)
        )
        self.pg0.add_stream([pkt])
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        with self.assertRaises(CaptureTimeoutError):
            self.pg1.get_capture(expected_count=1)

    def test_capture_mismatch_fewer_expected(self):
        """CaptureMismatchError raised when more packets arrive than expected"""
        pkts = self._make_pkts(10)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        with self.assertRaises(CaptureMismatchError):
            self.pg1.get_capture(expected_count=5)

    def test_unexpected_packet_error(self):
        """UnexpectedPacketError raised when packets arrive but none expected"""
        pkts = self._make_pkts(3)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        with self.assertRaises(UnexpectedPacketError):
            self.pg1.assert_nothing_captured()

    def test_capture_mismatch_more_expected(self):
        """CaptureMismatchError raised when fewer packets arrive than expected"""
        pkts = self._make_pkts(5)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        with self.assertRaises(CaptureMismatchError):
            self.pg1.get_capture(expected_count=10)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
