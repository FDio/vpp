#!/usr/bin/env python3
"""VXLAN L2FIB Test Case - Test dynamic destination addressing for VXLAN tunnels"""

import unittest
from framework import VppTestCase
from asfframework import VppTestRunner
from vpp_vxlan_tunnel import VppVxlanTunnel
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_ip import INVALID_INDEX
from config import config

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.vxlan import VXLAN
from scapy.packet import Raw


@unittest.skipIf("vxlan" in config.excluded_plugins, "Exclude VXLAN plugin tests")
class TestVxlanL2fib(VppTestCase):
    """VXLAN L2FIB Test Case"""

    @classmethod
    def setUpClass(cls):
        super(TestVxlanL2fib, cls).setUpClass()

        try:
            # Create interfaces
            cls.create_pg_interfaces(range(2))
            for i in cls.pg_interfaces:
                i.admin_up()

            # Configure IPv4 addresses on VPP pg0
            cls.pg0.config_ip4()
            cls.pg0.resolve_arp()

            # Configure IPv4 addresses on VPP pg1
            cls.pg1.config_ip4()

        except Exception:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        super(TestVxlanL2fib, cls).tearDownClass()

    def setUp(self):
        super(TestVxlanL2fib, self).setUp()

        # Bridge domain
        self.bd_id = 1

        # VXLAN parameters
        self.vni = 100
        self.src_ip = self.pg0.local_ip4
        self.dst_ip = self.pg0.remote_ip4

        # Create VXLAN tunnel
        self.vxlan = VppVxlanTunnel(
            self,
            src=self.src_ip,
            dst=self.dst_ip,
            vni=self.vni,
        )
        self.vxlan.add_vpp_config()

        # Add tunnel to bridge domain
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.vxlan.sw_if_index, bd_id=self.bd_id
        )
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.pg1.sw_if_index, bd_id=self.bd_id
        )

        # Enable interfaces
        self.vxlan.admin_up()

    def tearDown(self):
        # Clean up
        try:
            # Remove from bridge domain
            self.vapi.sw_interface_set_l2_bridge(
                rx_sw_if_index=self.vxlan.sw_if_index,
                bd_id=self.bd_id,
                enable=0,
            )
            self.vapi.sw_interface_set_l2_bridge(
                rx_sw_if_index=self.pg1.sw_if_index,
                bd_id=self.bd_id,
                enable=0,
            )

            # Remove VXLAN tunnel
            self.vxlan.remove_vpp_config()
        except Exception:
            pass

        super(TestVxlanL2fib, self).tearDown()

    def test_l2fib_add_del(self):
        """Test VXLAN L2FIB add/delete operations"""

        # Test MAC addresses
        mac1 = "01:02:03:04:05:06"
        mac2 = "01:02:03:04:05:07"
        dst_ip1 = "192.168.1.10"
        dst_ip2 = "192.168.1.11"

        # Initially, L2FIB should be empty
        entries = self.vapi.vxlan_l2fib_dump()
        self.assertEqual(len(entries), 0, "L2FIB should be empty initially")

        # Add first entry
        self.vapi.vxlan_add_del_l2fib(
            sw_if_index=self.vxlan.sw_if_index,
            mac=mac1,
            dst_address=dst_ip1,
            is_add=True,
        )

        # Verify entry was added
        entries = self.vapi.vxlan_l2fib_dump()
        self.assertEqual(len(entries), 1, "Should have 1 entry after add")
        entry = entries[0]
        self.assertEqual(str(entry.mac), mac1)
        self.assertEqual(entry.sw_if_index, self.vxlan.sw_if_index)
        self.assertEqual(str(entry.dst_address), dst_ip1)

        # Add second entry
        self.vapi.vxlan_add_del_l2fib(
            sw_if_index=self.vxlan.sw_if_index,
            mac=mac2,
            dst_address=dst_ip2,
            is_add=True,
        )

        # Verify both entries exist
        entries = self.vapi.vxlan_l2fib_dump()
        self.assertEqual(len(entries), 2, "Should have 2 entries after second add")

        # Check that both MACs are present
        macs = [str(entry.mac) for entry in entries]
        self.assertIn(mac1, macs)
        self.assertIn(mac2, macs)

        # Delete first entry
        self.vapi.vxlan_add_del_l2fib(
            sw_if_index=self.vxlan.sw_if_index,
            mac=mac1,
            dst_address=dst_ip1,
            is_add=False,
        )

        # Verify only second entry remains
        entries = self.vapi.vxlan_l2fib_dump()
        self.assertEqual(len(entries), 1, "Should have 1 entry after delete")
        entry = entries[0]
        self.assertEqual(str(entry.mac), mac2)

        # Delete second entry
        self.vapi.vxlan_add_del_l2fib(
            sw_if_index=self.vxlan.sw_if_index,
            mac=mac2,
            dst_address=dst_ip2,
            is_add=False,
        )

        # Verify L2FIB is empty
        entries = self.vapi.vxlan_l2fib_dump()
        self.assertEqual(len(entries), 0, "L2FIB should be empty after deleting all")

    def test_l2fib_replace(self):
        """Test VXLAN L2FIB entry replacement"""

        mac = "01:02:03:04:05:08"
        dst_ip1 = "192.168.1.20"
        dst_ip2 = "192.168.1.21"

        # Add entry with first destination
        self.vapi.vxlan_add_del_l2fib(
            sw_if_index=self.vxlan.sw_if_index,
            mac=mac,
            dst_address=dst_ip1,
            is_add=True,
        )

        # Verify entry
        entries = self.vapi.vxlan_l2fib_dump()
        self.assertEqual(len(entries), 1)
        self.assertEqual(str(entries[0].dst_address), dst_ip1)

        # Add same MAC with different destination (should replace)
        self.vapi.vxlan_add_del_l2fib(
            sw_if_index=self.vxlan.sw_if_index,
            mac=mac,
            dst_address=dst_ip2,
            is_add=True,
        )

        # Verify entry was replaced
        entries = self.vapi.vxlan_l2fib_dump()
        self.assertEqual(len(entries), 1, "Should still have only 1 entry")
        self.assertEqual(str(entries[0].dst_address), dst_ip2)

    def test_l2fib_interface_cleanup(self):
        """Test automatic cleanup when VXLAN interface is deleted"""

        # Add some L2FIB entries
        for i in range(3):
            mac = f"01:02:03:04:05:{i:02x}"
            dst_ip = f"192.168.1.{30 + i}"
            self.vapi.vxlan_add_del_l2fib(
                sw_if_index=self.vxlan.sw_if_index,
                mac=mac,
                dst_address=dst_ip,
                is_add=True,
            )

        # Verify entries exist
        entries = self.vapi.vxlan_l2fib_dump()
        self.assertEqual(len(entries), 3, "Should have 3 entries")

        # Remove the VXLAN tunnel (this should trigger cleanup)
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.vxlan.sw_if_index,
            bd_id=self.bd_id,
            enable=0,
        )
        self.vxlan.remove_vpp_config()

        # Verify L2FIB entries were automatically cleaned up
        entries = self.vapi.vxlan_l2fib_dump()
        self.assertEqual(
            len(entries), 0, "L2FIB should be empty after interface deletion"
        )

        # Recreate tunnel for tearDown
        self.vxlan = VppVxlanTunnel(
            self,
            src=self.src_ip,
            dst=self.dst_ip,
            vni=self.vni,
        )
        self.vxlan.add_vpp_config()

    def test_l2fib_ipv6(self):
        """Test VXLAN L2FIB with IPv6 destinations"""

        # Create IPv6 VXLAN tunnel
        src_ip6 = "2001:db8::1"
        dst_ip6 = "2001:db8::2"

        # Configure IPv6 addresses on pg0
        try:
            self.pg0.config_ip6()
        except Exception:
            # IPv6 might already be configured, skip if so
            pass

        vxlan_v6 = VppVxlanTunnel(
            self,
            src=src_ip6,
            dst=dst_ip6,
            vni=200,
        )
        vxlan_v6.add_vpp_config()
        vxlan_v6.admin_up()

        # Add to bridge domain
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=vxlan_v6.sw_if_index, bd_id=self.bd_id + 1
        )

        try:
            # Test IPv6 destinations
            mac = "01:02:03:04:05:09"
            dst_ip6_dynamic = "2001:db8::10"

            self.vapi.vxlan_add_del_l2fib(
                sw_if_index=vxlan_v6.sw_if_index,
                mac=mac,
                dst_address=dst_ip6_dynamic,
                is_add=True,
            )

            # Verify entry
            entries = self.vapi.vxlan_l2fib_dump()
            found = False
            for entry in entries:
                if str(entry.mac) == mac and entry.sw_if_index == vxlan_v6.sw_if_index:
                    self.assertEqual(str(entry.dst_address), dst_ip6_dynamic)
                    found = True
                    break
            self.assertTrue(found, "IPv6 L2FIB entry not found")

        finally:
            # Cleanup
            try:
                self.vapi.sw_interface_set_l2_bridge(
                    rx_sw_if_index=vxlan_v6.sw_if_index,
                    bd_id=self.bd_id + 1,
                    enable=0,
                )
                vxlan_v6.remove_vpp_config()
                self.pg0.unconfig_ip6()
            except Exception:
                # Ignore cleanup errors
                pass

    def test_l2fib_validation(self):
        """Test VXLAN L2FIB validation (address family mismatch)"""

        mac = "01:02:03:04:05:0a"
        dst_ip6 = "2001:db8::20"

        # Try to add IPv6 destination to IPv4 VXLAN tunnel (should fail)
        try:
            reply = self.vapi.vxlan_add_del_l2fib(
                sw_if_index=self.vxlan.sw_if_index,
                mac=mac,
                dst_address=dst_ip6,
                is_add=True,
            )
            # If we get here, the API call succeeded when it should have failed
            self.fail("Expected API call to fail due to address family mismatch")
        except Exception as e:
            # This is expected - the API should reject mismatched address families
            pass

    def test_l2fib_dump_interface_filter(self):
        """Test VXLAN L2FIB dump with interface filtering"""

        # Create second VXLAN tunnel
        vxlan2 = VppVxlanTunnel(
            self,
            src=self.src_ip,
            dst=self.dst_ip,
            vni=self.vni + 1,
        )
        vxlan2.add_vpp_config()
        vxlan2.admin_up()

        # Add to bridge domain
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=vxlan2.sw_if_index, bd_id=self.bd_id + 2
        )

        try:
            # Add L2FIB entries to first tunnel
            self.vapi.vxlan_add_del_l2fib(
                sw_if_index=self.vxlan.sw_if_index,
                mac="01:02:03:04:05:10",
                dst_address="192.168.1.100",
                is_add=True,
            )
            self.vapi.vxlan_add_del_l2fib(
                sw_if_index=self.vxlan.sw_if_index,
                mac="01:02:03:04:05:11",
                dst_address="192.168.1.101",
                is_add=True,
            )

            # Add L2FIB entries to second tunnel
            self.vapi.vxlan_add_del_l2fib(
                sw_if_index=vxlan2.sw_if_index,
                mac="01:02:03:04:05:20",
                dst_address="192.168.1.200",
                is_add=True,
            )
            self.vapi.vxlan_add_del_l2fib(
                sw_if_index=vxlan2.sw_if_index,
                mac="01:02:03:04:05:21",
                dst_address="192.168.1.201",
                is_add=True,
            )

            # Test dump all interfaces (default behavior)
            all_entries = self.vapi.vxlan_l2fib_dump()
            self.assertEqual(len(all_entries), 4, "Should have 4 total entries")

            # Test dump with explicit ~0 (all interfaces)
            all_entries_explicit = self.vapi.vxlan_l2fib_dump(sw_if_index=0xFFFFFFFF)
            self.assertEqual(
                len(all_entries_explicit),
                4,
                "Should have 4 total entries with explicit ~0",
            )

            # Test dump filtered by first interface
            tunnel1_entries = self.vapi.vxlan_l2fib_dump(
                sw_if_index=self.vxlan.sw_if_index
            )
            self.assertEqual(
                len(tunnel1_entries), 2, "Should have 2 entries for first tunnel"
            )
            for entry in tunnel1_entries:
                self.assertEqual(entry.sw_if_index, self.vxlan.sw_if_index)
                self.assertIn(
                    str(entry.mac), ["01:02:03:04:05:10", "01:02:03:04:05:11"]
                )

            # Test dump filtered by second interface
            tunnel2_entries = self.vapi.vxlan_l2fib_dump(sw_if_index=vxlan2.sw_if_index)
            self.assertEqual(
                len(tunnel2_entries), 2, "Should have 2 entries for second tunnel"
            )
            for entry in tunnel2_entries:
                self.assertEqual(entry.sw_if_index, vxlan2.sw_if_index)
                self.assertIn(
                    str(entry.mac), ["01:02:03:04:05:20", "01:02:03:04:05:21"]
                )

            # Test dump with non-existent interface (should return empty)
            empty_entries = self.vapi.vxlan_l2fib_dump(sw_if_index=9999)
            self.assertEqual(
                len(empty_entries),
                0,
                "Should have no entries for non-existent interface",
            )

        finally:
            # Cleanup
            try:
                self.vapi.sw_interface_set_l2_bridge(
                    rx_sw_if_index=vxlan2.sw_if_index,
                    bd_id=self.bd_id + 2,
                    enable=0,
                )
                vxlan2.remove_vpp_config()
            except Exception:
                pass

    def test_l2fib_dynamic_encapsulation(self):
        """Test VXLAN dynamic destination encapsulation with L2FIB"""

        src_ip = self.pg0.local_ip4
        default_dst_ip = "192.0.2.254"  # Default tunnel destination
        dst_port = 4789
        vni = 8298
        target_mac = "01:02:03:82:98:01"
        dynamic_dst = "192.0.2.2"  # L2FIB will override to this destination

        # Create VXLAN tunnel with default destination (L2FIB will override)
        tunnel = VppVxlanTunnel(
            self, src=src_ip, dst=default_dst_ip, dst_port=dst_port, vni=vni
        )
        tunnel.add_vpp_config()
        tunnel.admin_up()

        # Put the tunnel interface in L2 mode (bridge domain)
        bd_id = 10
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=tunnel.sw_if_index, bd_id=bd_id
        )
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.pg1.sw_if_index, bd_id=bd_id
        )

        # Add L2FIB entry for dynamic destination
        self.vapi.vxlan_add_del_l2fib(
            sw_if_index=tunnel.sw_if_index,
            mac=target_mac,
            dst_address=dynamic_dst,
            is_add=True,
        )

        # Add routes for both default and dynamic destination IPs
        default_route = VppIpRoute(
            self,
            default_dst_ip,
            32,
            [VppRoutePath(self.pg0.remote_ip4, self.pg0.sw_if_index)],
        )
        default_route.add_vpp_config()

        dynamic_route = VppIpRoute(
            self,
            dynamic_dst,
            32,
            [VppRoutePath(self.pg0.remote_ip4, self.pg0.sw_if_index)],
        )
        dynamic_route.add_vpp_config()

        # Create an Ethernet frame targeting the MAC in L2FIB
        test_frame = (
            Ether(src="00:11:22:33:44:55", dst=target_mac)
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / UDP(sport=1234, dport=5678)
            / Raw(b"test payload")
        )

        # Send the frame into the tunnel (via pg1)
        self.pg1.add_stream([test_frame])

        # Enable capture on pg0 to see the encapsulated packet
        self.pg0.enable_capture()
        self.pg_start()

        # Capture and verify the encapsulated packet
        captured_packets = self.pg0.get_capture(1)
        encapped_packet = captured_packets[0]

        # Verify outer Ethernet header
        self.assertEqual(encapped_packet[Ether].src, self.pg0.local_mac)
        self.assertEqual(encapped_packet[Ether].dst, self.pg0.remote_mac)

        # Verify outer IP header - should use dynamic destination from L2FIB
        self.assertEqual(str(encapped_packet[IP].src), src_ip)
        self.assertEqual(str(encapped_packet[IP].dst), dynamic_dst)
        self.assertEqual(encapped_packet[IP].proto, 17)  # UDP

        # Verify UDP header
        self.assertEqual(encapped_packet[UDP].dport, dst_port)
        # Source port should be computed hash (don't check exact value)
        self.assertIsNotNone(encapped_packet[UDP].sport)

        # Verify VXLAN header
        self.assertEqual(encapped_packet[VXLAN].vni, vni)
        self.assertEqual(encapped_packet[VXLAN].flags, 0x8)  # I flag set

        # Verify inner payload is preserved
        inner_payload = encapped_packet[VXLAN].payload
        self.assertEqual(inner_payload[Ether].src, test_frame[Ether].src)
        self.assertEqual(inner_payload[Ether].dst, test_frame[Ether].dst)
        self.assertEqual(str(inner_payload[IP].src), str(test_frame[IP].src))
        self.assertEqual(str(inner_payload[IP].dst), str(test_frame[IP].dst))
        self.assertEqual(inner_payload[UDP].sport, test_frame[UDP].sport)
        self.assertEqual(inner_payload[UDP].dport, test_frame[UDP].dport)

        # Clean up
        try:
            self.vapi.sw_interface_set_l2_bridge(
                rx_sw_if_index=tunnel.sw_if_index,
                bd_id=bd_id,
                enable=0,
            )
            self.vapi.sw_interface_set_l2_bridge(
                rx_sw_if_index=self.pg1.sw_if_index,
                bd_id=bd_id,
                enable=0,
            )
            tunnel.remove_vpp_config()
            default_route.remove_vpp_config()
            dynamic_route.remove_vpp_config()
        except Exception:
            pass


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
