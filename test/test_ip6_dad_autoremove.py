#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2026 Cisco Systems, Inc.

"""
IPv6 DAD Auto-Remove Plugin Test Cases
"""

import unittest
import time

from scapy.layers.l2 import Ether
from scapy.layers.inet6 import (
    IPv6,
    ICMPv6ND_NS,
    ICMPv6ND_NA,
    ICMPv6NDOptDstLLAddr,
)

from framework import VppTestCase
from asfframework import VppTestRunner


class TestIP6DADAutoRemove(VppTestCase):
    """IPv6 DAD Auto-Remove Plugin Tests"""

    @classmethod
    def setUpClass(cls):
        super(TestIP6DADAutoRemove, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestIP6DADAutoRemove, cls).tearDownClass()

    def setUp(self):
        super(TestIP6DADAutoRemove, self).setUp()

        # Create 2 pg interfaces
        self.create_pg_interfaces(range(2))

        # Set up interfaces
        for i in self.pg_interfaces:
            i.admin_up()

    def tearDown(self):
        # Disable auto-remove plugin
        try:
            self.vapi.cli("set ip6 dad autoremove disable")
        except Exception:
            pass  # Plugin may not be loaded or already disabled

        # Disable DAD
        self.vapi.ip6_dad_enable_disable(enable=False)

        # Clean up all IPv6 addresses from interfaces
        for i in self.pg_interfaces:
            # Remove all IPv6 addresses configured during the test
            try:
                addrs = self.vapi.ip_address_dump(sw_if_index=i.sw_if_index, is_ipv6=1)
                for addr in addrs:
                    # Skip link-local addresses (they are auto-configured)
                    addr_str = str(addr.prefix)
                    if not addr_str.startswith("fe80::"):
                        try:
                            self.vapi.sw_interface_add_del_address(
                                sw_if_index=i.sw_if_index,
                                prefix=addr.prefix,
                                is_add=0,
                            )
                        except Exception:
                            pass  # Address may have been auto-removed by plugin
            except Exception:
                pass  # Interface may not have IPv6 enabled

            i.admin_down()

        super(TestIP6DADAutoRemove, self).tearDown()

    def assert_address_not_present(self, sw_if_index, address):
        """Verify that an address is NOT configured on the interface."""
        addrs = self.vapi.ip_address_dump(sw_if_index=sw_if_index, is_ipv6=1)
        for addr in addrs:
            self.assertFalse(
                str(addr.prefix).startswith(address),
                f"Address {address} should not be on sw_if_index {sw_if_index}",
            )

    def assert_address_present(self, sw_if_index, address):
        """Verify that an address IS configured on the interface."""
        addrs = self.vapi.ip_address_dump(sw_if_index=sw_if_index, is_ipv6=1)
        for addr in addrs:
            if str(addr.prefix).startswith(address):
                return
        self.fail(f"Address {address} not found on sw_if_index {sw_if_index}")

    def test_autoremove_plugin_enable_disable(self):
        """Test enabling and disabling the auto-remove plugin"""

        # Enable the plugin
        result = self.vapi.cli("set ip6 dad autoremove enable")
        self.logger.info(f"Enable result: {result}")

        # Check status
        status = self.vapi.cli("show ip6 dad autoremove")
        self.assertIn("Enabled: yes", status)
        self.logger.info(f"Status after enable: {status}")

        # Disable the plugin
        result = self.vapi.cli("set ip6 dad autoremove disable")
        self.logger.info(f"Disable result: {result}")

        # Check status
        status = self.vapi.cli("show ip6 dad autoremove")
        self.assertIn("Enabled: no", status)
        self.logger.info(f"Status after disable: {status}")

    def test_autoremove_enables_dad(self):
        """Enabling auto-remove should automatically enable DAD"""

        # Ensure DAD is disabled initially
        self.vapi.ip6_dad_enable_disable(enable=False)

        # Enable auto-remove plugin
        self.vapi.cli("set ip6 dad autoremove enable")

        # Check that DAD is now enabled
        status = self.vapi.cli("show ip6 dad")
        self.assertIn("Enabled: yes", status)
        self.logger.info(f"DAD status after plugin enable: {status}")

    def test_autoremove_duplicate_address_removed(self):
        """Auto-remove: duplicate address should be automatically removed"""

        # Enable the plugin
        self.vapi.cli("set ip6 dad autoremove enable")

        # Ensure DAD is enabled with 1 transmit
        self.vapi.ip6_dad_enable_disable(enable=True, dad_transmits=1)

        test_address = "2001:db8::500"

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
        self.assertTrue(rx[0].haslayer(ICMPv6ND_NS))

        # Verify address is initially configured
        self.assert_address_present(self.pg0.sw_if_index, test_address)

        # Simulate conflict: another node defends the address
        defender_mac = "00:11:22:33:44:66"
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

        # Wait for VPP to process the conflict and auto-remove
        self.sleep_on_vpp_time(1.0)

        # CRITICAL: Address should be REMOVED by the plugin
        self.assert_address_not_present(self.pg0.sw_if_index, test_address)

        self.logger.info(
            f"Address {test_address} was auto-removed after duplicate detection"
        )

    def test_autoremove_disabled_duplicate_remains(self):
        """Without auto-remove: duplicate address should remain configured"""

        # Ensure auto-remove plugin is DISABLED
        try:
            self.vapi.cli("set ip6 dad autoremove disable")
        except Exception:
            pass  # May already be disabled

        # Enable DAD
        self.vapi.ip6_dad_enable_disable(enable=True, dad_transmits=1)

        test_address = "2001:db8::600"

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
        self.assertTrue(rx[0].haslayer(ICMPv6ND_NS))

        # Simulate conflict: another node defends the address
        defender_mac = "00:11:22:33:44:77"
        na = (
            Ether(dst=self.pg0.local_mac, src=defender_mac)
            / IPv6(src=test_address, dst="ff02::1")
            / ICMPv6ND_NA(
                tgt=test_address,
                R=0,
                S=0,
                O=1,
            )
            / ICMPv6NDOptDstLLAddr(lladdr=defender_mac)
        )

        # Send the defending NA
        self.pg0.add_stream([na])
        self.pg_start()

        # Wait for VPP to process the conflict
        self.sleep_on_vpp_time(1.0)

        # WITHOUT auto-remove: Address should REMAIN configured
        self.assert_address_present(self.pg0.sw_if_index, test_address)

        self.logger.info(
            f"Address {test_address} remains configured (auto-remove disabled)"
        )

    def test_autoremove_multiple_addresses(self):
        """Auto-remove: multiple duplicate addresses are removed independently"""

        # Enable the plugin
        self.vapi.cli("set ip6 dad autoremove enable")

        # Enable DAD
        self.vapi.ip6_dad_enable_disable(enable=True, dad_transmits=1)

        addr1 = "2001:db8::1:500"
        addr2 = "2001:db8::2:500"

        # Configure addr2 first (this one will NOT have a conflict)
        self.pg0.enable_capture()
        self.vapi.sw_interface_add_del_address(
            sw_if_index=self.pg0.sw_if_index,
            prefix=f"{addr2}/64",
            is_add=1,
        )

        # Wait for addr2 DAD NS
        rx2 = self.pg0.get_capture(1, timeout=2)
        self.assertTrue(rx2[0].haslayer(ICMPv6ND_NS))

        # Wait for addr2 DAD to complete (no conflict)
        self.sleep_on_vpp_time(1.5)
        self.assert_address_present(self.pg0.sw_if_index, addr2)

        # Now configure addr1 (this one WILL have a conflict)
        self.pg0.enable_capture()
        self.vapi.sw_interface_add_del_address(
            sw_if_index=self.pg0.sw_if_index,
            prefix=f"{addr1}/64",
            is_add=1,
        )

        # Wait for addr1 DAD NS
        rx1 = self.pg0.get_capture(1, timeout=2)
        self.assertTrue(rx1[0].haslayer(ICMPv6ND_NS))

        # addr1 should be initially present
        self.assert_address_present(self.pg0.sw_if_index, addr1)

        # Simulate conflict for addr1
        defender_mac = "00:11:22:33:44:88"
        na1 = (
            Ether(dst=self.pg0.local_mac, src=defender_mac)
            / IPv6(src=addr1, dst="ff02::1")
            / ICMPv6ND_NA(tgt=addr1, R=0, S=0, O=1)
            / ICMPv6NDOptDstLLAddr(lladdr=defender_mac)
        )

        self.pg0.add_stream([na1])
        self.pg_start()

        # Wait for DAD conflict processing and auto-remove
        self.sleep_on_vpp_time(2.0)

        # addr1 should be removed by the plugin
        self.assert_address_not_present(self.pg0.sw_if_index, addr1)

        # addr2 should still be present (no conflict)
        self.assert_address_present(self.pg0.sw_if_index, addr2)

        self.logger.info(
            f"Address {addr1} removed (duplicate), {addr2} remains (no conflict)"
        )

    def test_autoremove_different_interfaces(self):
        """Auto-remove: works independently on different interfaces"""

        # Enable the plugin
        self.vapi.cli("set ip6 dad autoremove enable")

        # Enable DAD
        self.vapi.ip6_dad_enable_disable(enable=True, dad_transmits=1)

        addr_pg0 = "2001:db8:1::700"
        addr_pg1 = "2001:db8:2::700"

        # Start capturing on both interfaces
        self.pg0.enable_capture()
        self.pg1.enable_capture()

        # Configure addresses on both interfaces
        self.vapi.sw_interface_add_del_address(
            sw_if_index=self.pg0.sw_if_index,
            prefix=f"{addr_pg0}/64",
            is_add=1,
        )

        self.vapi.sw_interface_add_del_address(
            sw_if_index=self.pg1.sw_if_index,
            prefix=f"{addr_pg1}/64",
            is_add=1,
        )

        # Capture DAD NS on both interfaces
        rx0 = self.pg0.get_capture(1, timeout=2)
        rx1 = self.pg1.get_capture(1, timeout=2)

        # Simulate conflict on pg0 only
        defender_mac = "00:11:22:33:44:99"
        na0 = (
            Ether(dst=self.pg0.local_mac, src=defender_mac)
            / IPv6(src=addr_pg0, dst="ff02::1")
            / ICMPv6ND_NA(tgt=addr_pg0, R=0, S=0, O=1)
            / ICMPv6NDOptDstLLAddr(lladdr=defender_mac)
        )

        self.pg0.add_stream([na0])
        self.pg_start()

        # Wait for processing
        self.sleep_on_vpp_time(1.0)

        # pg0 address should be removed
        self.assert_address_not_present(self.pg0.sw_if_index, addr_pg0)

        # pg1 address should remain (no conflict)
        self.sleep_on_vpp_time(1.5)
        self.assert_address_present(self.pg1.sw_if_index, addr_pg1)

        self.logger.info(
            f"pg0 address removed (duplicate), pg1 address remains (no conflict)"
        )

    def test_autoremove_reenable_after_disable(self):
        """Auto-remove: can be re-enabled after being disabled"""

        # Enable plugin
        self.vapi.cli("set ip6 dad autoremove enable")
        status = self.vapi.cli("show ip6 dad autoremove")
        self.assertIn("Enabled: yes", status)

        # Disable plugin
        self.vapi.cli("set ip6 dad autoremove disable")
        status = self.vapi.cli("show ip6 dad autoremove")
        self.assertIn("Enabled: no", status)

        # Re-enable plugin
        self.vapi.cli("set ip6 dad autoremove enable")
        status = self.vapi.cli("show ip6 dad autoremove")
        self.assertIn("Enabled: yes", status)

        # Test that it works after re-enable
        self.vapi.ip6_dad_enable_disable(enable=True, dad_transmits=1)
        test_address = "2001:db8::800"

        self.pg0.enable_capture()

        self.vapi.sw_interface_add_del_address(
            sw_if_index=self.pg0.sw_if_index,
            prefix=f"{test_address}/64",
            is_add=1,
        )

        rx = self.pg0.get_capture(1, timeout=2)

        # Simulate conflict
        defender_mac = "00:11:22:33:44:aa"
        na = (
            Ether(dst=self.pg0.local_mac, src=defender_mac)
            / IPv6(src=test_address, dst="ff02::1")
            / ICMPv6ND_NA(tgt=test_address, R=0, S=0, O=1)
            / ICMPv6NDOptDstLLAddr(lladdr=defender_mac)
        )

        self.pg0.add_stream([na])
        self.pg_start()
        self.sleep_on_vpp_time(1.0)

        # Address should be removed (plugin is working)
        self.assert_address_not_present(self.pg0.sw_if_index, test_address)

        self.logger.info("Plugin works correctly after re-enable")


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
