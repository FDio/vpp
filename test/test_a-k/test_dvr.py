#!/usr/bin/env python
import random
import socket
import unittest

from framework import VppTestCase, VppTestRunner
from vpp_sub_interface import VppSubInterface, VppDot1QSubint
from vpp_ip_route import VppIpRoute, VppRoutePath, DpoProto
from vpp_papi_provider import L2_VTR_OP

from scapy.packet import Raw
from scapy.layers.l2 import Ether, Dot1Q, ARP
from scapy.layers.inet import IP, UDP
from util import ppp


class TestDVR(VppTestCase):
    """ Distributed Virtual Router """

    def setUp(self):
        super(TestDVR, self).setUp()

        self.create_pg_interfaces(range(4))
        self.create_loopback_interfaces(range(1))

        for i in self.pg_interfaces:
            i.admin_up()

        self.loop0.config_ip4()

    def tearDown(self):
        for i in self.pg_interfaces:
            i.admin_down()
        self.loop0.unconfig_ip4()

        super(TestDVR, self).tearDown()

    def test_dvr(self):
        """ Distributed Virtual Router """

        #
        # A packet destined to an IP address that is L2 bridged via
        # a non-tag interface
        #
        ip_non_tag_bridged = "10.10.10.10"
        ip_tag_bridged = "10.10.10.11"
        any_src_addr = "1.1.1.1"

        pkt_no_tag = (Ether(src=self.pg0.remote_mac,
                            dst=self.loop0.local_mac) /
                      IP(src=any_src_addr,
                         dst=ip_non_tag_bridged) /
                      UDP(sport=1234, dport=1234) /
                      Raw('\xa5' * 100))
        pkt_tag = (Ether(src=self.pg0.remote_mac,
                         dst=self.loop0.local_mac) /
                   IP(src=any_src_addr,
                      dst=ip_tag_bridged) /
                   UDP(sport=1234, dport=1234) /
                   Raw('\xa5' * 100))

        #
        # Two sub-interfaces so we can test VLAN tag push/pop
        #
        sub_if_on_pg2 = VppDot1QSubint(self, self.pg2, 92)
        sub_if_on_pg3 = VppDot1QSubint(self, self.pg3, 93)
        sub_if_on_pg2.admin_up()
        sub_if_on_pg3.admin_up()

        #
        # Put all the interfaces into a new bridge domain
        #
        self.vapi.sw_interface_set_l2_bridge(self.pg0.sw_if_index, 1)
        self.vapi.sw_interface_set_l2_bridge(self.pg1.sw_if_index, 1)
        self.vapi.sw_interface_set_l2_bridge(sub_if_on_pg2.sw_if_index, 1)
        self.vapi.sw_interface_set_l2_bridge(sub_if_on_pg3.sw_if_index, 1)
        self.vapi.sw_interface_set_l2_bridge(self.loop0.sw_if_index, 1, bvi=1)

        self.vapi.sw_interface_set_l2_tag_rewrite(sub_if_on_pg2.sw_if_index,
                                                  L2_VTR_OP.L2_POP_1,
                                                  92)
        self.vapi.sw_interface_set_l2_tag_rewrite(sub_if_on_pg3.sw_if_index,
                                                  L2_VTR_OP.L2_POP_1,
                                                  93)

        #
        # Add routes to bridge the traffic via a tagged an nontagged interface
        #
        route_no_tag = VppIpRoute(
            self, ip_non_tag_bridged, 32,
            [VppRoutePath("0.0.0.0",
                          self.pg1.sw_if_index,
                          proto=DpoProto.DPO_PROTO_ETHERNET)])
        route_no_tag.add_vpp_config()

        #
        # Inject the packet that arrives and leaves on a non-tagged interface
        # Since it's 'bridged' expect that the MAC headed is unchanged.
        #
        self.pg0.add_stream(pkt_no_tag)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg1.get_capture(1)

        self.assertEqual(rx[0][Ether].dst, pkt_no_tag[Ether].dst)
        self.assertEqual(rx[0][Ether].src, pkt_no_tag[Ether].src)

        #
        # Add routes to bridge the traffic via a tagged interface
        #
        route_no_tag = VppIpRoute(
            self, ip_tag_bridged, 32,
            [VppRoutePath("0.0.0.0",
                          sub_if_on_pg3.sw_if_index,
                          proto=DpoProto.DPO_PROTO_ETHERNET)])
        route_no_tag.add_vpp_config()

        #
        # Inject the packet that arrives and leaves on a non-tagged interface
        # Since it's 'bridged' expect that the MAC headed is unchanged.
        #
        self.pg0.add_stream(pkt_tag)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg3.get_capture(1)

        self.assertEqual(rx[0][Ether].dst, pkt_tag[Ether].dst)
        self.assertEqual(rx[0][Ether].src, pkt_tag[Ether].src)
        self.assertEqual(rx[0][Dot1Q].vlan, 93)

        #
        # Tag to tag
        #
        pkt_tag_to_tag = (Ether(src=self.pg2.remote_mac,
                                dst=self.loop0.local_mac) /
                          Dot1Q(vlan=92) /
                          IP(src=any_src_addr,
                             dst=ip_tag_bridged) /
                          UDP(sport=1234, dport=1234) /
                          Raw('\xa5' * 100))

        self.pg2.add_stream(pkt_tag_to_tag)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = self.pg3.get_capture(1)

        self.assertEqual(rx[0][Ether].dst, pkt_tag_to_tag[Ether].dst)
        self.assertEqual(rx[0][Ether].src, pkt_tag_to_tag[Ether].src)
        self.assertEqual(rx[0][Dot1Q].vlan, 93)

        #
        # Tag to non-Tag
        #
        pkt_tag_to_non_tag = (Ether(src=self.pg2.remote_mac,
                                    dst=self.loop0.local_mac) /
                              Dot1Q(vlan=92) /
                              IP(src=any_src_addr,
                                 dst=ip_non_tag_bridged) /
                              UDP(sport=1234, dport=1234) /
                              Raw('\xa5' * 100))

        self.pg2.add_stream(pkt_tag_to_non_tag)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = self.pg1.get_capture(1)

        self.assertEqual(rx[0][Ether].dst, pkt_tag_to_tag[Ether].dst)
        self.assertEqual(rx[0][Ether].src, pkt_tag_to_tag[Ether].src)
        self.assertFalse(rx[0].haslayer(Dot1Q))

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
