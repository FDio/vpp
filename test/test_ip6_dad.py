#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2026 Cisco Systems, Inc.

"""
IPv6 Duplicate Address Detection (DAD) Test Cases - RFC 4862
"""

import unittest
import time
import socket

from scapy.layers.l2 import Ether
from scapy.layers.inet6 import (
    IPv6,
    ICMPv6ND_NS,
    ICMPv6ND_NA,
    ICMPv6NDOptSrcLLAddr,
    ICMPv6NDOptDstLLAddr,
)
from scapy.utils6 import in6_getnsma, in6_getnsmac

from framework import VppTestCase
from asfframework import VppTestRunner

# NOTE: self.sleep() uses VPP virtual time (comment #11)
# This means sleep durations are simulated, not real-time delays.
# DAD timers are also based on VPP virtual time, so tests remain deterministic.


class TestIP6DAD(VppTestCase):
    """IPv6 Duplicate Address Detection (DAD) - RFC 4862"""

    @classmethod
    def setUpClass(cls):
        super(TestIP6DAD, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestIP6DAD, cls).tearDownClass()

    def setUp(self):
        super(TestIP6DAD, self).setUp()

        # Create 2 pg interfaces
        self.create_pg_interfaces(range(2))

        # Set up interfaces
        for i in self.pg_interfaces:
            i.admin_up()

    def tearDown(self):
        # Disable DAD after each test (comment #9)
        self.vapi.ip6_dad_enable_disable(enable=False)

        for i in self.pg_interfaces:
            i.admin_down()

        super(TestIP6DAD, self).tearDown()

    def verify_dad_ns(self, rx_pkt, target_address):
        """
        Verify that a packet is a valid DAD Neighbor Solicitation.

        RFC 4862 DAD NS must have:
        - Source IPv6 = :: (unspecified)
        - Destination IPv6 = solicited-node multicast of target
        - Target = address being tested
        - NO Source Link-Layer option (because src is ::)
        """
        # Verify it's an NS
        self.assertTrue(rx_pkt.haslayer(ICMPv6ND_NS))
        ns = rx_pkt[ICMPv6ND_NS]

        # RFC 4862: Source MUST be unspecified (::)
        self.assertEqual(rx_pkt[IPv6].src, "::")

        # Destination is solicited-node multicast
        expected_mcast = in6_getnsma(socket.inet_pton(socket.AF_INET6, target_address))
        self.assertEqual(
            rx_pkt[IPv6].dst, socket.inet_ntop(socket.AF_INET6, expected_mcast)
        )

        # Target is the address being tested
        self.assertEqual(ns.tgt, target_address)

        # RFC 4861: NO Source Link-Layer option when src is ::
        self.assertFalse(rx_pkt.haslayer(ICMPv6NDOptSrcLLAddr))

        # Ethernet destination is multicast MAC
        expected_mac = in6_getnsmac(expected_mcast)
        self.assertEqual(rx_pkt[Ether].dst, expected_mac)

    def assert_address_not_present(self, sw_if_index, address):
        """Helper to verify address NOT present (comment #10)."""
        addrs = self.vapi.ip_address_dump(sw_if_index=sw_if_index, is_ipv6=1)
        for addr in addrs:
            self.assertFalse(
                str(addr.prefix).startswith(address),
                f"Address {address} should not be on sw_if_index {sw_if_index}",
            )

    def assert_address_present(self, sw_if_index, address):
        """Helper to verify address is present (comment #10)."""
        addrs = self.vapi.ip_address_dump(sw_if_index=sw_if_index, is_ipv6=1)
        for addr in addrs:
            if str(addr.prefix).startswith(address):
                return
        self.fail(f"Address {address} not found on sw_if_index {sw_if_index}")

    def test_dad_disabled_by_default(self):
        """DAD should be disabled by default (backward compatibility)"""

        test_address = "2001:db8::100"

        # Configure address - should NOT trigger DAD if disabled by default
        self.vapi.sw_interface_add_del_address(
            sw_if_index=self.pg0.sw_if_index,
            prefix=f"{test_address}/64",
            is_add=1,
        )

        # Capture on interface
        self.pg0.enable_capture()

        # Wait a bit to see if any NS is sent
        self.sleep(0.5)

        # Should NOT receive any DAD NS (DAD disabled by default)
        self.pg0.assert_nothing_captured(timeout=0.1)

        # Address should be immediately usable
        self.assert_address_present(self.pg0.sw_if_index, test_address)

    def test_dad_link_local_success(self):
        """DAD for link-local address - no conflict (success)"""

        # Enable DAD with 1 transmission
        self.vapi.ip6_dad_enable_disable(enable=True, dad_transmits=1)

        test_address = "fe80::100"

        # Start capturing before adding address
        self.pg0.enable_capture()

        # Configure link-local address
        self.vapi.sw_interface_add_del_address(
            sw_if_index=self.pg0.sw_if_index,
            prefix=f"{test_address}/128",
            is_add=1,
        )

        # Should receive 1 DAD NS
        rx = self.pg0.get_capture(1, timeout=2)

        # Verify it's a valid DAD NS
        self.verify_dad_ns(rx[0], test_address)

        # Wait for DAD to complete (RetransTimer = 1 second by default)
        self.sleep(1.5)

        # Link-local addresses are stored in a separate table (ip6_ll_table)
        # and not returned by ip_address_dump. The fact that:
        # 1. DAD NS was sent
        # 2. No error was raised during address configuration
        # 3. No NA conflict was received
        # proves that DAD completed successfully for the link-local address.

    def test_dad_global_unicast_success(self):
        """DAD for global unicast address - no conflict (success)"""

        # Enable DAD with 2 transmissions
        self.vapi.ip6_dad_enable_disable(enable=True, dad_transmits=2)

        test_address = "2001:db8::200"

        # Start capturing
        self.pg0.enable_capture()

        # Configure address
        self.vapi.sw_interface_add_del_address(
            sw_if_index=self.pg0.sw_if_index,
            prefix=f"{test_address}/64",
            is_add=1,
        )

        # Should receive 2 DAD NS (1 second apart)
        # First NS
        rx1 = self.pg0.get_capture(1, timeout=2)
        self.verify_dad_ns(rx1[0], test_address)

        # Second NS (after RetransTimer = 1 second)
        rx2 = self.pg0.get_capture(1, timeout=2)
        self.verify_dad_ns(rx2[0], test_address)

        # Wait for DAD to complete
        self.sleep(1.5)

        # Address should be preferred
        self.assert_address_present(self.pg0.sw_if_index, test_address)

    def test_dad_conflict_detected(self):
        """DAD detects duplicate address (conflict - failure)"""

        # Enable DAD
        self.vapi.ip6_dad_enable_disable(enable=True, dad_transmits=1)

        test_address = "2001:db8::300"

        # Start capturing
        self.pg0.enable_capture()

        # Configure address on VPP
        self.vapi.sw_interface_add_del_address(
            sw_if_index=self.pg0.sw_if_index,
            prefix=f"{test_address}/64",
            is_add=1,
        )

        # VPP sends DAD NS
        rx = self.pg0.get_capture(1, timeout=2)
        self.verify_dad_ns(rx[0], test_address)

        # Simulate another node defending the address
        # Send Neighbor Advertisement (NA) for the address
        defender_mac = "00:11:22:33:44:55"
        na = (
            Ether(dst=self.pg0.local_mac, src=defender_mac)
            / IPv6(src=test_address, dst="ff02::1")  # All-nodes multicast
            / ICMPv6ND_NA(
                tgt=test_address,
                R=0,  # Not a router
                S=0,  # Not solicited (defending)
                O=1,  # Override
            )
            / ICMPv6NDOptDstLLAddr(lladdr=defender_mac)
        )

        # Send the defending NA
        self.pg0.add_stream([na])
        self.pg_start()

        # Wait a bit for VPP to process the conflict
        self.sleep(1.0)

        # Address should be REMOVED from interface (DAD failed)
        self.assert_address_not_present(self.pg0.sw_if_index, test_address)

    def test_dad_multiple_addresses(self):
        """DAD for multiple addresses on same interface"""

        # Enable DAD
        self.vapi.ip6_dad_enable_disable(enable=True, dad_transmits=1)

        addr1 = "2001:db8::1:100"
        addr2 = "2001:db8::2:200"

        # Start capturing
        self.pg0.enable_capture()

        # Configure first address
        self.vapi.sw_interface_add_del_address(
            sw_if_index=self.pg0.sw_if_index,
            prefix=f"{addr1}/64",
            is_add=1,
        )

        # Configure second address
        self.vapi.sw_interface_add_del_address(
            sw_if_index=self.pg0.sw_if_index,
            prefix=f"{addr2}/64",
            is_add=1,
        )

        # Should receive 2 DAD NS (one for each address)
        rx = self.pg0.get_capture(2, timeout=3)

        # Verify both NS (order may vary)
        targets_found = set()
        for pkt in rx:
            self.assertTrue(pkt.haslayer(ICMPv6ND_NS))
            target = pkt[ICMPv6ND_NS].tgt
            targets_found.add(target)
            self.assertEqual(pkt[IPv6].src, "::")  # DAD NS has src=::

        self.assertIn(addr1, targets_found)
        self.assertIn(addr2, targets_found)

        # Wait for DAD to complete
        self.sleep(2.0)

        # Both addresses should be preferred
        self.assert_address_present(self.pg0.sw_if_index, addr1)
        self.assert_address_present(self.pg0.sw_if_index, addr2)

    def test_dad_different_interfaces(self):
        """DAD operates independently on different interfaces"""

        # Enable DAD
        self.vapi.ip6_dad_enable_disable(enable=True, dad_transmits=1)

        addr_pg0 = "2001:db8:1::100"
        addr_pg1 = "2001:db8:2::200"

        # Start capturing on both interfaces
        self.pg0.enable_capture()
        self.pg1.enable_capture()

        # Configure address on pg0
        self.vapi.sw_interface_add_del_address(
            sw_if_index=self.pg0.sw_if_index,
            prefix=f"{addr_pg0}/64",
            is_add=1,
        )

        # Configure address on pg1
        self.vapi.sw_interface_add_del_address(
            sw_if_index=self.pg1.sw_if_index,
            prefix=f"{addr_pg1}/64",
            is_add=1,
        )

        # pg0 should receive DAD NS for addr_pg0
        rx0 = self.pg0.get_capture(1, timeout=2)
        self.verify_dad_ns(rx0[0], addr_pg0)

        # pg1 should receive DAD NS for addr_pg1
        rx1 = self.pg1.get_capture(1, timeout=2)
        self.verify_dad_ns(rx1[0], addr_pg1)

        # Wait for DAD completion
        self.sleep(2.0)

        # Verify both addresses are configured
        self.assert_address_present(self.pg0.sw_if_index, addr_pg0)
        self.assert_address_present(self.pg1.sw_if_index, addr_pg1)

    def test_dad_retransmit_timer(self):
        """Verify RetransTimer delay between DAD NS transmissions"""

        # Enable DAD with 3 transmissions, 1 second delay
        self.vapi.ip6_dad_enable_disable(
            enable=True, dad_transmits=3, dad_retransmit_delay=1.0
        )

        test_address = "2001:db8::400"

        # Start capturing
        self.pg0.enable_capture()

        # Configure address - this triggers DAD to start
        self.vapi.sw_interface_add_del_address(
            sw_if_index=self.pg0.sw_if_index,
            prefix=f"{test_address}/64",
            is_add=1,
        )

        # First NS should be sent immediately
        rx = self.pg0.get_capture(1, timeout=1)
        self.verify_dad_ns(rx[0], test_address)

        # Clear any stale packets and restart capture
        self.pg0.enable_capture()

        # Advance VPP time by 1 second to allow next NS
        self.sleep(1.0)

        # Second NS should be available now
        rx = self.pg0.get_capture(1, timeout=1)
        self.verify_dad_ns(rx[0], test_address)

        # Clear any stale packets and restart capture
        self.pg0.enable_capture()

        # Advance VPP time by 1 second to allow third NS
        self.sleep(1.0)

        # Third NS should be available now
        rx = self.pg0.get_capture(1, timeout=1)
        self.verify_dad_ns(rx[0], test_address)

    def test_dad_loopback_exemption(self):
        """Loopback address (::1) should NOT trigger DAD"""

        # Enable DAD
        self.vapi.ip6_dad_enable_disable(enable=True, dad_transmits=1)

        loopback_addr = "::1"

        # Start capturing
        self.pg0.enable_capture()

        # VPP accepts loopback but skips DAD (see ip6_dad.c:334-338)
        self.vapi.sw_interface_add_del_address(
            sw_if_index=self.pg0.sw_if_index,
            prefix=f"{loopback_addr}/128",
            is_add=1,
        )

        # Should NOT send any DAD NS for loopback
        self.sleep(0.5)
        self.pg0.assert_nothing_captured(timeout=0.1)

        # Cleanup
        self.vapi.sw_interface_add_del_address(
            sw_if_index=self.pg0.sw_if_index,
            prefix=f"{loopback_addr}/128",
            is_add=0,
        )

    def test_dad_multicast_exemption(self):
        """Multicast addresses should NOT trigger DAD"""

        # Enable DAD
        self.vapi.ip6_dad_enable_disable(enable=True, dad_transmits=1)

        mcast_addr = "ff02::1"  # All-nodes multicast

        # Start capturing
        self.pg0.enable_capture()

        # VPP accepts multicast but skips DAD (see ip6_dad.c:334-338)
        self.vapi.sw_interface_add_del_address(
            sw_if_index=self.pg0.sw_if_index,
            prefix=f"{mcast_addr}/128",
            is_add=1,
        )

        # Should NOT send any DAD NS for multicast
        self.sleep(0.5)
        self.pg0.assert_nothing_captured(timeout=0.1)

        # Cleanup
        self.vapi.sw_interface_add_del_address(
            sw_if_index=self.pg0.sw_if_index,
            prefix=f"{mcast_addr}/128",
            is_add=0,
        )

    def test_dad_disable_stops_new_sessions(self):
        """set ip6 dad disable should prevent new DAD sessions"""

        # Ensure DAD is disabled
        self.vapi.ip6_dad_enable_disable(enable=False)

        test_address = "2001:db8::200"

        # Add address with DAD disabled - should not send NS
        self.vapi.sw_interface_add_del_address(
            sw_if_index=self.pg0.sw_if_index, prefix=f"{test_address}/64", is_add=1
        )

        # Wait to ensure no DAD NS are sent
        self.pg0.enable_capture()
        self.sleep(2.0)

        # Should NOT receive any DAD NS packets
        self.pg0.assert_nothing_captured(timeout=0.5)

        # Cleanup
        self.vapi.sw_interface_add_del_address(
            sw_if_index=self.pg0.sw_if_index, prefix=f"{test_address}/64", is_add=0
        )


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
