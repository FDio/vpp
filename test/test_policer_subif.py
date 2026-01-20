#!/usr/bin/env python3
# Test policer on sub-interfaces (L2 bridge-domain and L3 routed)
# SPDX-License-Identifier: Apache-2.0

import unittest
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether, Dot1Q
from scapy.packet import Raw
from framework import VppTestCase
from asfframework import VppTestRunner
from vpp_papi import VppEnum
from vpp_policer import VppPolicer, PolicerAction, Dir
from vpp_sub_interface import VppDot1QSubint

NUM_PKTS = 67


class TestPolicerSubinterface(VppTestCase):
    """Policer on Sub-interfaces (L2 and L3)"""

    def setUp(self):
        super(TestPolicerSubinterface, self).setUp()

        self.create_pg_interfaces(range(3))
        for i in self.pg_interfaces:
            i.admin_up()

    def tearDown(self):
        for i in self.pg_interfaces:
            i.admin_down()
        super(TestPolicerSubinterface, self).tearDown()

    def test_policer_l3_subif_input(self):
        """Input Policing on L3 routed sub-interface"""

        # Create VLAN 10 sub-interface on pg0 and pg1
        sub_if0 = VppDot1QSubint(self, self.pg0, 10)
        sub_if0.admin_up()
        sub_if0.config_ip4()
        sub_if0.resolve_arp()

        sub_if1 = VppDot1QSubint(self, self.pg1, 10)
        sub_if1.admin_up()
        sub_if1.config_ip4()
        sub_if1.resolve_arp()

        # Create policer
        action_tx = PolicerAction(
            VppEnum.vl_api_sse2_qos_action_type_t.SSE2_QOS_ACTION_API_TRANSMIT, 0
        )
        policer = VppPolicer(
            self,
            "subif_l3_pol",
            80,
            0,
            1000,
            0,
            conform_action=action_tx,
            exceed_action=action_tx,
            violate_action=action_tx,
        )
        policer.add_vpp_config()

        # Apply policer to sub-interface input on pg0
        policer.apply_vpp_config(sub_if0.sw_if_index, Dir.RX, True)

        # Debug: Check interface features
        self.logger.info(self.vapi.cli(f"show interface features pg0.10"))
        self.logger.info(self.vapi.cli(f"show interface pg0.10"))
        self.logger.info(self.vapi.cli(f"show policer"))
        self.logger.info(self.vapi.cli(f"clear node counters"))

        # Send packets with VLAN tag from sub_if0 to sub_if1
        pkts = []
        for i in range(NUM_PKTS):
            pkt = (
                Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
                / Dot1Q(vlan=10)
                / IP(src=sub_if0.remote_ip4, dst=sub_if1.remote_ip4)
                / UDP(sport=1234, dport=1234)
                / Raw(b"\xa5" * 100)
            )
            pkts.append(pkt)

        # Send and verify packets are policed and forwarded
        try:
            rx = self.send_and_expect(self.pg0, pkts, self.pg1)
        except:
            # Debug: Check what happened
            self.logger.info(self.vapi.cli(f"show node counters"))
            self.logger.info(self.vapi.cli(f"show errors"))
            self.logger.info(self.vapi.cli(f"show trace"))
            raise
        stats = policer.get_stats()

        # Verify policing happened
        self.assertGreater(stats["conform_packets"], 0)
        self.assertEqual(stats["exceed_packets"], 0)
        self.assertGreater(stats["violate_packets"], 0)

        self.logger.info(f"L3 sub-interface input policer stats: {stats}")

        # Cleanup
        policer.apply_vpp_config(sub_if0.sw_if_index, Dir.RX, False)
        policer.remove_vpp_config()
        sub_if0.unconfig_ip4()
        sub_if0.admin_down()
        sub_if0.remove_vpp_config()
        sub_if1.unconfig_ip4()
        sub_if1.admin_down()
        sub_if1.remove_vpp_config()

    def test_policer_l3_subif_output(self):
        """Output Policing on L3 routed sub-interface"""

        # Create VLAN 20 sub-interface on pg0 and pg1
        sub_if0 = VppDot1QSubint(self, self.pg0, 20)
        sub_if0.admin_up()
        sub_if0.config_ip4()
        sub_if0.resolve_arp()

        sub_if1 = VppDot1QSubint(self, self.pg1, 20)
        sub_if1.admin_up()
        sub_if1.config_ip4()
        sub_if1.resolve_arp()

        # Create policer
        action_tx = PolicerAction(
            VppEnum.vl_api_sse2_qos_action_type_t.SSE2_QOS_ACTION_API_TRANSMIT, 0
        )
        policer = VppPolicer(
            self,
            "subif_l3_out_pol",
            80,
            0,
            1000,
            0,
            conform_action=action_tx,
            exceed_action=action_tx,
            violate_action=action_tx,
        )
        policer.add_vpp_config()

        # Apply policer to sub-interface output on pg1
        policer.apply_vpp_config(sub_if1.sw_if_index, Dir.TX, True)

        # Send packets from sub_if0 to sub_if1 to trigger output policing
        pkts = []
        for i in range(NUM_PKTS):
            pkt = (
                Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
                / Dot1Q(vlan=20)
                / IP(src=sub_if0.remote_ip4, dst=sub_if1.remote_ip4)
                / UDP(sport=1234, dport=1234)
                / Raw(b"\xa5" * 100)
            )
            pkts.append(pkt)

        # Send and verify packets are policed on output
        rx = self.send_and_expect(self.pg0, pkts, self.pg1)
        stats = policer.get_stats()

        # Verify policing happened on output
        self.assertGreater(stats["conform_packets"], 0)
        self.assertEqual(stats["exceed_packets"], 0)
        self.assertGreater(stats["violate_packets"], 0)

        self.logger.info(f"L3 sub-interface output policer stats: {stats}")

        # Cleanup
        policer.apply_vpp_config(sub_if1.sw_if_index, Dir.TX, False)
        policer.remove_vpp_config()
        sub_if0.unconfig_ip4()
        sub_if0.admin_down()
        sub_if0.remove_vpp_config()
        sub_if1.unconfig_ip4()
        sub_if1.admin_down()
        sub_if1.remove_vpp_config()

    def test_policer_l2_subif_input(self):
        """Input Policing on L2 bridge-domain sub-interface"""

        # Create VLAN sub-interfaces on pg0 and pg1
        sub_if0 = VppDot1QSubint(self, self.pg0, 30)
        sub_if0.admin_up()

        sub_if1 = VppDot1QSubint(self, self.pg1, 30)
        sub_if1.admin_up()

        # Add both sub-interfaces to bridge domain 1
        self.vapi.sw_interface_set_l2_bridge(sub_if0.sw_if_index, bd_id=1)
        self.vapi.sw_interface_set_l2_bridge(sub_if1.sw_if_index, bd_id=1)

        # Create policer
        action_tx = PolicerAction(
            VppEnum.vl_api_sse2_qos_action_type_t.SSE2_QOS_ACTION_API_TRANSMIT, 0
        )
        policer = VppPolicer(
            self,
            "subif_l2_pol",
            80,
            0,
            1000,
            0,
            conform_action=action_tx,
            exceed_action=action_tx,
            violate_action=action_tx,
        )
        policer.add_vpp_config()

        # Apply policer to L2 sub-interface input
        policer.apply_vpp_config(sub_if0.sw_if_index, Dir.RX, True)

        # Send L2 packets with VLAN tag
        pkts = []
        for i in range(NUM_PKTS):
            pkt = (
                Ether(src=self.pg0.remote_mac, dst=self.pg1.remote_mac)
                / Dot1Q(vlan=30)
                / IP(src="10.0.0.1", dst="10.0.0.2")
                / UDP(sport=1234, dport=1234)
                / Raw(b"\xa5" * 100)
            )
            pkts.append(pkt)

        # Send and verify packets are bridged and policed
        rx = self.send_and_expect(self.pg0, pkts, self.pg1)
        stats = policer.get_stats()

        # Verify policing happened
        self.assertGreater(stats["conform_packets"], 0)
        self.assertEqual(stats["exceed_packets"], 0)
        self.assertGreater(stats["violate_packets"], 0)

        self.logger.info(f"L2 sub-interface input policer stats: {stats}")

        # Cleanup
        policer.apply_vpp_config(sub_if0.sw_if_index, Dir.RX, False)
        policer.remove_vpp_config()
        self.vapi.sw_interface_set_l2_bridge(sub_if0.sw_if_index, bd_id=1, enable=0)
        self.vapi.sw_interface_set_l2_bridge(sub_if1.sw_if_index, bd_id=1, enable=0)
        sub_if0.admin_down()
        sub_if0.remove_vpp_config()
        sub_if1.admin_down()
        sub_if1.remove_vpp_config()

    def test_policer_l2_subif_output(self):
        """Output Policing on L2 bridge-domain sub-interface"""

        # Create VLAN sub-interfaces on pg0 and pg1
        sub_if0 = VppDot1QSubint(self, self.pg0, 40)
        sub_if0.admin_up()

        sub_if1 = VppDot1QSubint(self, self.pg1, 40)
        sub_if1.admin_up()

        # Add both sub-interfaces to bridge domain 2
        self.vapi.sw_interface_set_l2_bridge(sub_if0.sw_if_index, bd_id=2)
        self.vapi.sw_interface_set_l2_bridge(sub_if1.sw_if_index, bd_id=2)

        # Create policer
        action_tx = PolicerAction(
            VppEnum.vl_api_sse2_qos_action_type_t.SSE2_QOS_ACTION_API_TRANSMIT, 0
        )
        policer = VppPolicer(
            self,
            "subif_l2_out_pol",
            80,
            0,
            1000,
            0,
            conform_action=action_tx,
            exceed_action=action_tx,
            violate_action=action_tx,
        )
        policer.add_vpp_config()

        # Apply policer to L2 sub-interface output
        policer.apply_vpp_config(sub_if1.sw_if_index, Dir.TX, True)

        # Send L2 packets with VLAN tag
        pkts = []
        for i in range(NUM_PKTS):
            pkt = (
                Ether(src=self.pg0.remote_mac, dst=self.pg1.remote_mac)
                / Dot1Q(vlan=40)
                / IP(src="10.0.0.1", dst="10.0.0.2")
                / UDP(sport=1234, dport=1234)
                / Raw(b"\xa5" * 100)
            )
            pkts.append(pkt)

        # Send and verify packets are bridged and policed on output
        rx = self.send_and_expect(self.pg0, pkts, self.pg1)
        stats = policer.get_stats()

        # Verify policing happened on output
        self.assertGreater(stats["conform_packets"], 0)
        self.assertEqual(stats["exceed_packets"], 0)
        self.assertGreater(stats["violate_packets"], 0)

        self.logger.info(f"L2 sub-interface output policer stats: {stats}")

        # Cleanup
        policer.apply_vpp_config(sub_if1.sw_if_index, Dir.TX, False)
        policer.remove_vpp_config()
        self.vapi.sw_interface_set_l2_bridge(sub_if0.sw_if_index, bd_id=2, enable=0)
        self.vapi.sw_interface_set_l2_bridge(sub_if1.sw_if_index, bd_id=2, enable=0)
        sub_if0.admin_down()
        sub_if0.remove_vpp_config()
        sub_if1.admin_down()
        sub_if1.remove_vpp_config()


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
