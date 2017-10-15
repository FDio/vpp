#!/usr/bin/env python

import unittest

from scapy.packet import Raw
from scapy.layers.l2 import Ether, Dot1Q, GRE
from scapy.layers.inet import IP, UDP
from scapy.layers.vxlan import VXLAN

from framework import VppTestCase, VppTestRunner
from util import Host, ppp
from vpp_sub_interface import VppDot1QSubint, VppDot1ADSubint
from vpp_gre_interface import VppGreInterface, VppGre6Interface
from vpp_papi_provider import L2_VTR_OP
from collections import namedtuple

Tag = namedtuple('Tag', ['dot1', 'vlan'])
DOT1AD = 0x88A8
DOT1Q = 0x8100


class TestSpan(VppTestCase):
    """ SPAN Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestSpan, cls).setUpClass()
        # Test variables
        cls.pkts_per_burst = 257    # Number of packets per burst
        # create 3 pg interfaces
        cls.create_pg_interfaces(range(3))

        cls.bd_id = 55
        cls.sub_if = VppDot1QSubint(cls, cls.pg0, 100)
        cls.dst_sub_if = VppDot1QSubint(cls, cls.pg2, 300)
        cls.dst_sub_if.set_vtr(L2_VTR_OP.L2_POP_1, tag=300)
        # packet flows mapping pg0 -> pg1, pg2 -> pg3, etc.
        cls.flows = dict()
        cls.flows[cls.pg0] = [cls.pg1]
        cls.flows[cls.pg1] = [cls.pg0]

        # packet sizes
        cls.pg_if_packet_sizes = [64, 512]  # , 1518, 9018]

        cls.interfaces = list(cls.pg_interfaces)

        # setup all interfaces
        for i in cls.interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

        cls.vxlan = cls.vapi.vxlan_add_del_tunnel(
            src_addr=cls.pg2.local_ip4n,
            dst_addr=cls.pg2.remote_ip4n,
            vni=1111,
            is_add=1)

    def setUp(self):
        super(TestSpan, self).setUp()
        self.reset_packet_infos()

    def tearDown(self):
        super(TestSpan, self).tearDown()
        if not self.vpp_dead:
            self.logger.info(self.vapi.ppcli("show interface span"))

    def xconnect(self, a, b, is_add=1):
        self.vapi.sw_interface_set_l2_xconnect(a, b, enable=is_add)
        self.vapi.sw_interface_set_l2_xconnect(b, a, enable=is_add)

    def bridge(self, sw_if_index, is_add=1):
        self.vapi.sw_interface_set_l2_bridge(
            sw_if_index, bd_id=self.bd_id, enable=is_add)

    def _remove_tag(self, packet, vlan, tag_type):
        self.assertEqual(packet.type, tag_type)
        payload = packet.payload
        self.assertEqual(payload.vlan, vlan)
        inner_type = payload.type
        payload = payload.payload
        packet.remove_payload()
        packet.add_payload(payload)
        packet.type = inner_type

    def remove_tags(self, packet, tags):
        for t in tags:
            self._remove_tag(packet, t.vlan, t.dot1)
        return packet

    def decap_gre(self, pkt):
        """
        Decapsulate the original payload frame by removing GRE header
        """
        self.assertEqual(pkt[Ether].src, self.pg2.local_mac)
        self.assertEqual(pkt[Ether].dst, self.pg2.remote_mac)

        self.assertEqual(pkt[IP].src, self.pg2.local_ip4)
        self.assertEqual(pkt[IP].dst, self.pg2.remote_ip4)

        return pkt[GRE].payload

    def decap_vxlan(self, pkt):
        """
        Decapsulate the original payload frame by removing VXLAN header
        """
        self.assertEqual(pkt[Ether].src, self.pg2.local_mac)
        self.assertEqual(pkt[Ether].dst, self.pg2.remote_mac)

        self.assertEqual(pkt[IP].src, self.pg2.local_ip4)
        self.assertEqual(pkt[IP].dst, self.pg2.remote_ip4)

        return pkt[VXLAN].payload

    def create_stream(self, src_if, packet_sizes, do_dot1=False):
        pkts = []
        dst_if = self.flows[src_if][0]
        for i in range(0, self.pkts_per_burst):
            pkt_info = self.create_packet_info(src_if, dst_if)
            payload = self.info_to_payload(pkt_info)
            size = packet_sizes[(i / 2) % len(packet_sizes)]
            p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                 IP(src=src_if.remote_ip4, dst=dst_if.remote_ip4) /
                 UDP(sport=10000 + src_if.sw_if_index * 1000 + i, dport=1234) /
                 Raw(payload))
            if do_dot1:
                p = self.sub_if.add_dot1_layer(p)
            pkt_info.data = p.copy()
            self.extend_packet(p, size)
            pkts.append(p)
        return pkts

    def verify_capture(self, cap1, cap2):
        self.assertEqual(len(cap1), len(cap2),
                         "Different number of sent and mirrored packets :"
                         "%u != %u" % (len(cap1), len(cap2)))

        pkts1 = [(pkt[Ether] / pkt[IP] / pkt[UDP]) for pkt in cap1]
        pkts2 = [(pkt[Ether] / pkt[IP] / pkt[UDP]) for pkt in cap2]

        self.assertEqual(pkts1.sort(), pkts2.sort())

    def test_device_span(self):
        """ SPAN device rx mirror test

        Test scenario:
            1. config
               3 interfaces, pg0 l2xconnected with pg1
            2. sending l2 eth packets between 2 interfaces (pg0, pg1) and
               mirrored to pg2
               64B, 512B, 1518B, 9018B (ether_size)
               burst of packets per interface
        """

        # Create bi-directional cross-connects between pg0 and pg1
        self.xconnect(self.pg0.sw_if_index, self.pg1.sw_if_index)
        # Create incoming packet streams for packet-generator interfaces
        pkts = self.create_stream(self.pg0, self.pg_if_packet_sizes)
        self.pg0.add_stream(pkts)

        # Enable SPAN on pg0 (mirrored to pg2)
        self.vapi.sw_interface_span_enable_disable(
            self.pg0.sw_if_index, self.pg2.sw_if_index)

        self.logger.info(self.vapi.ppcli("show interface span"))
        # Enable packet capturing and start packet sending
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Verify packets outgoing packet streams on mirrored interface (pg2)
        self.logger.info("Verifying capture on interfaces %s and %s" %
                         (self.pg1.name, self.pg2.name))

        n_pkts = self.get_packet_count_for_if_idx(self.pg1.sw_if_index)
        pg1_pkts = self.pg1.get_capture(n_pkts)
        pg2_pkts = self.pg2.get_capture(n_pkts)

        # Disable SPAN on pg0 (mirrored to pg2)
        self.vapi.sw_interface_span_enable_disable(
            self.pg0.sw_if_index, self.pg2.sw_if_index, state=0)
        self.xconnect(self.pg0.sw_if_index, self.pg1.sw_if_index, is_add=0)

        self.verify_capture(pg1_pkts, pg2_pkts)

    def test_span_l2_rx(self):
        """ SPAN l2 rx mirror test """

        self.sub_if.admin_up()

        self.bridge(self.pg2.sw_if_index)
        # Create bi-directional cross-connects between pg0 and pg1
        self.xconnect(self.sub_if.sw_if_index, self.pg1.sw_if_index)
        # Create incoming packet streams for packet-generator interfaces
        pkts = self.create_stream(
            self.pg0, self.pg_if_packet_sizes, do_dot1=True)
        self.pg0.add_stream(pkts)

        # Enable SPAN on pg0 (mirrored to pg2)
        self.vapi.sw_interface_span_enable_disable(
            self.sub_if.sw_if_index, self.pg2.sw_if_index, is_l2=1)

        self.logger.info(self.vapi.ppcli("show interface span"))
        # Enable packet capturing and start packet sending
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Verify packets outgoing packet streams on mirrored interface (pg2)
        self.logger.info("Verifying capture on interfaces %s and %s" %
                         (self.pg1.name, self.pg2.name))
        pg2_expected = len(pkts)
        pg1_pkts = self.pg1.get_capture(pg2_expected)
        pg2_pkts = self.pg2.get_capture(pg2_expected)
        self.bridge(self.pg2.sw_if_index, is_add=0)

        # Disable SPAN on pg0 (mirrored to pg2)
        self.vapi.sw_interface_span_enable_disable(
            self.sub_if.sw_if_index, self.pg2.sw_if_index, state=0, is_l2=1)
        self.xconnect(self.sub_if.sw_if_index, self.pg1.sw_if_index, is_add=0)

        self.verify_capture(pg1_pkts, pg2_pkts)

    def test_span_l2_rx_dst_vxlan(self):
        """ SPAN l2 rx mirror into vxlan test """

        self.sub_if.admin_up()
        self.vapi.sw_interface_set_flags(self.vxlan.sw_if_index,
                                         admin_up_down=1)

        self.bridge(self.vxlan.sw_if_index, is_add=1)
        # Create bi-directional cross-connects between pg0 and pg1
        self.xconnect(self.sub_if.sw_if_index, self.pg1.sw_if_index)
        # Create incoming packet streams for packet-generator interfaces
        pkts = self.create_stream(
            self.pg0, self.pg_if_packet_sizes, do_dot1=True)
        self.pg0.add_stream(pkts)

        # Enable SPAN on pg0 sub if (mirrored to vxlan)
        self.vapi.sw_interface_span_enable_disable(
            self.sub_if.sw_if_index, self.vxlan.sw_if_index, is_l2=1)

        self.logger.info(self.vapi.ppcli("show interface span"))
        # Enable packet capturing and start packet sending
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Verify packets outgoing packet streams on mirrored interface (pg2)
        self.logger.info("Verifying capture on interfaces %s and %s" %
                         (self.pg1.name, self.pg2.name))
        pg2_expected = self.get_packet_count_for_if_idx(self.pg1.sw_if_index)
        pg1_pkts = self.pg1.get_capture()
        pg2_pkts = [self.decap_vxlan(p)
                    for p in self.pg2.get_capture(pg2_expected)]

        self.bridge(self.vxlan.sw_if_index, is_add=0)
        # Disable SPAN on pg0 sub if (mirrored to vxlan)
        self.vapi.sw_interface_span_enable_disable(
            self.sub_if.sw_if_index, self.vxlan.sw_if_index, state=0, is_l2=1)
        self.xconnect(self.sub_if.sw_if_index, self.pg1.sw_if_index, is_add=0)
        self.verify_capture(pg1_pkts, pg2_pkts)

    def test_span_l2_rx_dst_gre_subif_vtr(self):
        """ SPAN l2 rx mirror into gre-subif+vtr """

        self.sub_if.admin_up()

        gre_if = VppGreInterface(self, self.pg2.local_ip4,
                                 self.pg2.remote_ip4,
                                 is_teb=1)

        gre_if.add_vpp_config()
        gre_if.admin_up()

        gre_sub_if = VppDot1QSubint(self, gre_if, 500)
        gre_sub_if.set_vtr(L2_VTR_OP.L2_POP_1, tag=500)
        gre_sub_if.admin_up()

        self.bridge(gre_sub_if.sw_if_index)
        # Create bi-directional cross-connects between pg0 and pg1
        self.xconnect(self.sub_if.sw_if_index, self.pg1.sw_if_index, is_add=1)

        # Create incoming packet streams for packet-generator interfaces
        pkts = self.create_stream(
            self.pg0, self.pg_if_packet_sizes, do_dot1=True)
        self.pg0.add_stream(pkts)

        self.vapi.sw_interface_span_enable_disable(
            self.sub_if.sw_if_index, gre_sub_if.sw_if_index, is_l2=1)

        # Enable packet capturing and start packet sending
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Verify packets outgoing packet streams on mirrored interface (pg2)
        self.logger.info("Verifying capture on interfaces %s and %s" %
                         (self.pg1.name, self.pg2.name))
        pg2_expected = self.get_packet_count_for_if_idx(self.pg1.sw_if_index)
        pg1_pkts = self.pg1.get_capture()
        pg2_pkts = self.pg2.get_capture(pg2_expected)
        pg2_decaped = [self.remove_tags(self.decap_gre(
            p), [Tag(dot1=DOT1Q, vlan=500)]) for p in pg2_pkts]
        self.bridge(gre_sub_if.sw_if_index, is_add=0)

        # Disable SPAN on pg0 sub if
        self.vapi.sw_interface_span_enable_disable(
            self.sub_if.sw_if_index, gre_sub_if.sw_if_index, state=0, is_l2=1)
        gre_if.remove_vpp_config()
        self.xconnect(self.sub_if.sw_if_index, self.pg1.sw_if_index, is_add=0)

        self.verify_capture(pg1_pkts, pg2_decaped)

    def test_span_l2_rx_dst_vtr(self):
        """ SPAN l2 rx mirror into subif+vtr """

        self.sub_if.admin_up()
        self.dst_sub_if.admin_up()

        self.bridge(self.dst_sub_if.sw_if_index)
        # Create bi-directional cross-connects between pg0 and pg1
        self.xconnect(self.sub_if.sw_if_index, self.pg1.sw_if_index, is_add=1)

        # Create incoming packet streams for packet-generator interfaces
        pkts = self.create_stream(
            self.pg0, self.pg_if_packet_sizes, do_dot1=True)
        self.pg0.add_stream(pkts)

        self.vapi.sw_interface_span_enable_disable(
            self.sub_if.sw_if_index, self.dst_sub_if.sw_if_index, is_l2=1)

        # Enable packet capturing and start packet sending
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Verify packets outgoing packet streams on mirrored interface (pg2)
        self.logger.info("Verifying capture on interfaces %s and %s" %
                         (self.pg1.name, self.pg2.name))
        pg2_expected = self.get_packet_count_for_if_idx(self.pg1.sw_if_index)
        pg1_pkts = self.pg1.get_capture()
        pg2_pkts = self.pg2.get_capture(pg2_expected)
        pg2_untagged = [self.remove_tags(p, [Tag(dot1=DOT1Q, vlan=300)])
                        for p in pg2_pkts]

        self.bridge(self.dst_sub_if.sw_if_index, is_add=0)
        # Disable SPAN on pg0 sub if (mirrored to vxlan)
        self.vapi.sw_interface_span_enable_disable(
            self.sub_if.sw_if_index, self.dst_sub_if.sw_if_index, state=0,
            is_l2=1)
        self.xconnect(self.sub_if.sw_if_index, self.pg1.sw_if_index, is_add=0)

        self.verify_capture(pg1_pkts, pg2_untagged)

    def test_l2_tx_span(self):
        """ SPAN l2 tx mirror test """

        self.sub_if.admin_up()
        self.bridge(self.pg2.sw_if_index)
        # Create bi-directional cross-connects between pg0 and pg1
        self.xconnect(self.sub_if.sw_if_index, self.pg1.sw_if_index)
        # Create incoming packet streams for packet-generator interfaces
        pkts = self.create_stream(
            self.pg0, self.pg_if_packet_sizes, do_dot1=True)
        self.pg0.add_stream(pkts)

        # Enable SPAN on pg1 (mirrored to pg2)
        self.vapi.sw_interface_span_enable_disable(
            self.pg1.sw_if_index, self.pg2.sw_if_index, is_l2=1, state=2)

        self.logger.info(self.vapi.ppcli("show interface span"))
        # Enable packet capturing and start packet sending
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Verify packets outgoing packet streams on mirrored interface (pg2)
        self.logger.info("Verifying capture on interfaces %s and %s" %
                         (self.pg1.name, self.pg2.name))
        pg2_expected = self.get_packet_count_for_if_idx(self.pg1.sw_if_index)
        pg1_pkts = self.pg1.get_capture()
        pg2_pkts = self.pg2.get_capture(pg2_expected)
        self.bridge(self.pg2.sw_if_index, is_add=0)
        # Disable SPAN on pg0 (mirrored to pg2)
        self.vapi.sw_interface_span_enable_disable(
            self.pg1.sw_if_index, self.pg2.sw_if_index, state=0, is_l2=1)
        self.xconnect(self.sub_if.sw_if_index, self.pg1.sw_if_index, is_add=0)

        self.verify_capture(pg1_pkts, pg2_pkts)

    def test_l2_rx_tx_span(self):
        """ SPAN l2 rx tx mirror test """

        self.sub_if.admin_up()
        self.bridge(self.pg2.sw_if_index)
        # Create bi-directional cross-connects between pg0 and pg1
        self.xconnect(self.sub_if.sw_if_index, self.pg1.sw_if_index)

        # Create incoming packet streams for packet-generator interfaces
        pg0_pkts = self.create_stream(
            self.pg0, self.pg_if_packet_sizes, do_dot1=True)
        self.pg0.add_stream(pg0_pkts)
        pg1_pkts = self.create_stream(
            self.pg1, self.pg_if_packet_sizes, do_dot1=False)
        self.pg1.add_stream(pg1_pkts)

        # Enable SPAN on pg0 (mirrored to pg2)
        self.vapi.sw_interface_span_enable_disable(
            self.sub_if.sw_if_index, self.pg2.sw_if_index, is_l2=1, state=3)
        self.logger.info(self.vapi.ppcli("show interface span"))

        # Enable packet capturing and start packet sending
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Verify packets outgoing packet streams on mirrored interface (pg2)
        self.logger.info("Verifying capture on interfaces %s and %s" %
                         (self.pg1.name, self.pg2.name))
        pg0_expected = self.get_packet_count_for_if_idx(self.pg0.sw_if_index)
        pg1_expected = self.get_packet_count_for_if_idx(self.pg1.sw_if_index)
        pg2_expected = pg0_expected + pg1_expected

        pg0_pkts = self.pg0.get_capture(pg0_expected)
        pg1_pkts = self.pg1.get_capture(pg1_expected)
        pg2_pkts = self.pg2.get_capture(pg2_expected)

        self.bridge(self.pg2.sw_if_index, is_add=0)
        # Disable SPAN on pg0 (mirrored to pg2)
        self.vapi.sw_interface_span_enable_disable(
            self.sub_if.sw_if_index, self.pg2.sw_if_index, state=0, is_l2=1)
        self.xconnect(self.sub_if.sw_if_index, self.pg1.sw_if_index, is_add=0)

        self.verify_capture(pg0_pkts + pg1_pkts, pg2_pkts)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
