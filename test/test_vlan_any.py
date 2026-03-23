#!/usr/bin/env python3
"""Tests for wildcard (any) VLAN sub-interface matching."""

# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2026 Cisco Systems, Inc.

import unittest

from scapy.packet import Raw
from scapy.layers.l2 import Ether, Dot1Q
from scapy.layers.inet import IP, UDP

from framework import VppTestCase
from asfframework import VppTestRunner
from vpp_papi import VppEnum


class VppDot1QAnySubint:
    """Helper to create a dot1q sub-interface with outer_vlan_id_any."""

    def __init__(self, test, parent, sub_id):
        self.test = test
        self.parent = parent
        self.sub_id = sub_id
        flags = (
            VppEnum.vl_api_sub_if_flags_t.SUB_IF_API_FLAG_ONE_TAG
            | VppEnum.vl_api_sub_if_flags_t.SUB_IF_API_FLAG_EXACT_MATCH
            | VppEnum.vl_api_sub_if_flags_t.SUB_IF_API_FLAG_OUTER_VLAN_ID_ANY
        )
        r = test.vapi.create_subif(
            sw_if_index=parent.sw_if_index,
            sub_id=sub_id,
            outer_vlan_id=0,
            inner_vlan_id=0,
            sub_if_flags=flags,
        )
        self.sw_if_index = r.sw_if_index

    def remove_vpp_config(self):
        self.test.vapi.delete_subif(self.sw_if_index)


class VppDot1QAnyAnySubint:
    """Helper to create a dot1q sub-interface with any outer + any inner."""

    def __init__(self, test, parent, sub_id):
        self.test = test
        self.parent = parent
        self.sub_id = sub_id
        flags = (
            VppEnum.vl_api_sub_if_flags_t.SUB_IF_API_FLAG_TWO_TAGS
            | VppEnum.vl_api_sub_if_flags_t.SUB_IF_API_FLAG_EXACT_MATCH
            | VppEnum.vl_api_sub_if_flags_t.SUB_IF_API_FLAG_OUTER_VLAN_ID_ANY
            | VppEnum.vl_api_sub_if_flags_t.SUB_IF_API_FLAG_INNER_VLAN_ID_ANY
        )
        r = test.vapi.create_subif(
            sw_if_index=parent.sw_if_index,
            sub_id=sub_id,
            outer_vlan_id=0,
            inner_vlan_id=0,
            sub_if_flags=flags,
        )
        self.sw_if_index = r.sw_if_index

    def remove_vpp_config(self):
        self.test.vapi.delete_subif(self.sw_if_index)


class VppDot1QAnyOuterSpecificInnerSubint:
    """Helper for dot1q any outer + specific inner sub-interface."""

    def __init__(self, test, parent, sub_id, inner_vlan):
        self.test = test
        self.parent = parent
        self.sub_id = sub_id
        self.inner_vlan = inner_vlan
        flags = (
            VppEnum.vl_api_sub_if_flags_t.SUB_IF_API_FLAG_TWO_TAGS
            | VppEnum.vl_api_sub_if_flags_t.SUB_IF_API_FLAG_EXACT_MATCH
            | VppEnum.vl_api_sub_if_flags_t.SUB_IF_API_FLAG_OUTER_VLAN_ID_ANY
        )
        r = test.vapi.create_subif(
            sw_if_index=parent.sw_if_index,
            sub_id=sub_id,
            outer_vlan_id=0,
            inner_vlan_id=inner_vlan,
            sub_if_flags=flags,
        )
        self.sw_if_index = r.sw_if_index

    def remove_vpp_config(self):
        self.test.vapi.delete_subif(self.sw_if_index)


class VppDot1ADAnySubint:
    """Helper for dot1ad any outer (single tag) sub-interface."""

    def __init__(self, test, parent, sub_id):
        self.test = test
        self.parent = parent
        self.sub_id = sub_id
        flags = (
            VppEnum.vl_api_sub_if_flags_t.SUB_IF_API_FLAG_DOT1AD
            | VppEnum.vl_api_sub_if_flags_t.SUB_IF_API_FLAG_ONE_TAG
            | VppEnum.vl_api_sub_if_flags_t.SUB_IF_API_FLAG_EXACT_MATCH
            | VppEnum.vl_api_sub_if_flags_t.SUB_IF_API_FLAG_OUTER_VLAN_ID_ANY
        )
        r = test.vapi.create_subif(
            sw_if_index=parent.sw_if_index,
            sub_id=sub_id,
            outer_vlan_id=0,
            inner_vlan_id=0,
            sub_if_flags=flags,
        )
        self.sw_if_index = r.sw_if_index

    def remove_vpp_config(self):
        self.test.vapi.delete_subif(self.sw_if_index)


class VppDot1ADAnyAnySubint:
    """Helper for dot1ad any outer + any inner sub-interface."""

    def __init__(self, test, parent, sub_id):
        self.test = test
        self.parent = parent
        self.sub_id = sub_id
        flags = (
            VppEnum.vl_api_sub_if_flags_t.SUB_IF_API_FLAG_DOT1AD
            | VppEnum.vl_api_sub_if_flags_t.SUB_IF_API_FLAG_TWO_TAGS
            | VppEnum.vl_api_sub_if_flags_t.SUB_IF_API_FLAG_EXACT_MATCH
            | VppEnum.vl_api_sub_if_flags_t.SUB_IF_API_FLAG_OUTER_VLAN_ID_ANY
            | VppEnum.vl_api_sub_if_flags_t.SUB_IF_API_FLAG_INNER_VLAN_ID_ANY
        )
        r = test.vapi.create_subif(
            sw_if_index=parent.sw_if_index,
            sub_id=sub_id,
            outer_vlan_id=0,
            inner_vlan_id=0,
            sub_if_flags=flags,
        )
        self.sw_if_index = r.sw_if_index

    def remove_vpp_config(self):
        self.test.vapi.delete_subif(self.sw_if_index)


DOT1Q_TYPE = 0x8100
DOT1AD_TYPE = 0x88A8


def add_dot1q(pkt, vlan):
    """Add a dot1q tag to a packet."""
    payload = pkt.payload
    inner_type = pkt.type
    pkt.remove_payload()
    pkt.add_payload(Dot1Q(vlan=vlan) / payload)
    pkt.payload.type = inner_type
    pkt.payload.vlan = vlan
    pkt.type = DOT1Q_TYPE
    return pkt


def add_dot1ad_single(pkt, vlan):
    """Add a single dot1ad (0x88a8) tag to a packet."""
    payload = pkt.payload
    inner_type = pkt.type
    pkt.remove_payload()
    pkt.add_payload(Dot1Q(vlan=vlan) / payload)
    pkt.payload.type = inner_type
    pkt.payload.vlan = vlan
    pkt.type = DOT1AD_TYPE
    return pkt


def add_dot1ad_double(pkt, outer, inner):
    """Add dot1ad double tags (outer 0x88a8 + inner 0x8100) to a packet."""
    p = add_dot1q(pkt, inner)
    payload = p.payload
    inner_type = p.type
    p.remove_payload()
    p.add_payload(Dot1Q(vlan=outer) / payload)
    p.payload.type = inner_type
    p.payload.vlan = outer
    p.type = DOT1AD_TYPE
    return p


class TestVlanAny(VppTestCase):
    """Test wildcard (any) VLAN sub-interface matching with traffic."""

    @classmethod
    def setUpClass(cls):
        super(TestVlanAny, cls).setUpClass()
        cls.create_pg_interfaces(range(2))
        for i in cls.pg_interfaces:
            i.admin_up()

    @classmethod
    def tearDownClass(cls):
        super(TestVlanAny, cls).tearDownClass()

    def setUp(self):
        super(TestVlanAny, self).setUp()
        self.sub_ifs = []
        self.bd_id = 1

    def tearDown(self):
        for sw in self.sub_ifs:
            self.vapi.sw_interface_set_l2_bridge(
                rx_sw_if_index=sw, bd_id=self.bd_id, enable=False
            )
            self.vapi.delete_subif(sw)
        # Also remove pg1 from bridge domain
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.pg1.sw_if_index,
            bd_id=self.bd_id,
            enable=False,
        )
        self.sub_ifs = []
        super(TestVlanAny, self).tearDown()

    def _setup_sub_bridge(self, sw_if_index, vtr_op, tag1=0, tag2=0, push_dot1q=1):
        """Admin-up a sub-if, bridge it with pg1, and configure VTR."""
        self.sub_ifs.append(sw_if_index)
        self.vapi.sw_interface_set_flags(sw_if_index=sw_if_index, flags=1)
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=sw_if_index, bd_id=self.bd_id
        )
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.pg1.sw_if_index, bd_id=self.bd_id
        )
        self.vapi.l2_interface_vlan_tag_rewrite(
            sw_if_index=sw_if_index,
            vtr_op=vtr_op,
            push_dot1q=push_dot1q,
            tag1=tag1,
            tag2=tag2,
        )

    def _make_pkt(self, src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02"):
        return (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / UDP(sport=1234, dport=5678)
            / Raw(b"\xa5" * 64)
        )

    def test_dot1q_any_single_tag(self):
        """Dot1q any: single-tagged packets with various VLANs are bridged"""
        sub = VppDot1QAnySubint(self, self.pg0, 100)
        self._setup_sub_bridge(sub.sw_if_index, vtr_op=3)  # L2_POP_1

        pkt = self._make_pkt()
        tagged = add_dot1q(pkt, vlan=777)
        rx = self.send_and_expect(self.pg0, [tagged], self.pg1)
        self.assertEqual(rx[0][Ether].type, 0x0800)

    def test_dot1q_any_multiple_vlans(self):
        """Dot1q any: packets with different VLAN IDs all match"""
        sub = VppDot1QAnySubint(self, self.pg0, 100)
        self._setup_sub_bridge(sub.sw_if_index, vtr_op=3)  # L2_POP_1

        pkt = self._make_pkt()
        pkts = [add_dot1q(pkt.copy(), vlan=v) for v in [1, 100, 999, 4094]]
        rx = self.send_and_expect(self.pg0, pkts, self.pg1, n_rx=len(pkts))
        for p in rx:
            self.assertEqual(p[Ether].type, 0x0800)

    def test_dot1q_any_any_double_tag(self):
        """Dot1q any+any: double-tagged packets are bridged"""
        sub = VppDot1QAnyAnySubint(self, self.pg0, 101)
        self._setup_sub_bridge(sub.sw_if_index, vtr_op=4)  # L2_POP_2

        pkt = self._make_pkt()
        tagged = add_dot1q(pkt, vlan=500)
        tagged = add_dot1q(tagged, vlan=300)
        rx = self.send_and_expect(self.pg0, [tagged], self.pg1)
        self.assertEqual(rx[0][Ether].type, 0x0800)

    def test_dot1q_any_outer_specific_inner(self):
        """Dot1q any outer + specific inner: matches correct inner VLAN"""
        sub = VppDot1QAnyOuterSpecificInnerSubint(self, self.pg0, 102, 200)
        self._setup_sub_bridge(sub.sw_if_index, vtr_op=4)  # L2_POP_2

        pkt = self._make_pkt()
        # outer=999 (any), inner=200 (specific match)
        tagged = add_dot1q(pkt, vlan=200)
        tagged = add_dot1q(tagged, vlan=999)
        rx = self.send_and_expect(self.pg0, [tagged], self.pg1)
        self.assertEqual(rx[0][Ether].type, 0x0800)

    def test_dot1ad_any_single_tag(self):
        """Dot1ad any: single dot1ad-tagged packets are bridged"""
        sub = VppDot1ADAnySubint(self, self.pg0, 103)
        self._setup_sub_bridge(sub.sw_if_index, vtr_op=3)  # L2_POP_1

        pkt = self._make_pkt()
        tagged = add_dot1ad_single(pkt, vlan=555)
        rx = self.send_and_expect(self.pg0, [tagged], self.pg1)
        self.assertEqual(rx[0][Ether].type, 0x0800)

    def test_dot1ad_any_any_double_tag(self):
        """Dot1ad any+any: double dot1ad-tagged packets are bridged"""
        sub = VppDot1ADAnyAnySubint(self, self.pg0, 104)
        self._setup_sub_bridge(sub.sw_if_index, vtr_op=4)  # L2_POP_2

        pkt = self._make_pkt()
        tagged = add_dot1ad_double(pkt, outer=400, inner=600)
        rx = self.send_and_expect(self.pg0, [tagged], self.pg1)
        self.assertEqual(rx[0][Ether].type, 0x0800)

    def test_specific_vlan_wins_over_any(self):
        """Specific VLAN sub-interface takes priority over dot1q-any"""
        # Create specific VLAN 100
        r = self.vapi.create_vlan_subif(self.pg0.sw_if_index, 100)
        specific_sw = r.sw_if_index

        # Create dot1q any
        any_sub = VppDot1QAnySubint(self, self.pg0, 200)

        # Setup specific VLAN 100 bridged to pg1
        self._setup_sub_bridge(specific_sw, vtr_op=3)  # L2_POP_1

        # Admin-up the any sub but do NOT bridge it - just ensure
        # it doesn't steal traffic from specific VLAN 100
        self.vapi.sw_interface_set_flags(sw_if_index=any_sub.sw_if_index, flags=1)

        pkt = self._make_pkt()
        tagged = add_dot1q(pkt, vlan=100)
        rx = self.send_and_expect(self.pg0, [tagged], self.pg1)
        self.assertEqual(len(rx), 1)

        # Cleanup the any sub (not in self.sub_ifs since we didn't bridge it)
        any_sub.remove_vpp_config()

    def test_any_any_vs_any_specific_inner_priority(self):
        """Any outer+specific inner wins over any+any for matching inner"""
        # Create any outer + specific inner 200
        specific_inner_sub = VppDot1QAnyOuterSpecificInnerSubint(
            self, self.pg0, 110, 200
        )
        self._setup_sub_bridge(specific_inner_sub.sw_if_index, vtr_op=4)

        # Also create any+any on a different bridge domain so it exists
        # but doesn't interfere with traffic verification
        any_any_sub = VppDot1QAnyAnySubint(self, self.pg0, 111)
        self.vapi.sw_interface_set_flags(sw_if_index=any_any_sub.sw_if_index, flags=1)

        # Double-tagged packet with inner=200 should match specific-inner,
        # not any+any
        pkt = self._make_pkt()
        tagged = add_dot1q(pkt, vlan=200)
        tagged = add_dot1q(tagged, vlan=888)
        rx = self.send_and_expect(self.pg0, [tagged], self.pg1)
        self.assertEqual(rx[0][Ether].type, 0x0800)

        # Cleanup any_any (not bridged via _setup_sub_bridge)
        any_any_sub.remove_vpp_config()


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
