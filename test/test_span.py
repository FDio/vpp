#!/usr/bin/env python3

import unittest

from scapy.packet import Raw
from scapy.layers.l2 import Ether, Dot1Q, GRE, ERSPAN
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.vxlan import VXLAN

from framework import VppTestCase, VppTestRunner
from util import Host, ppp
from vpp_sub_interface import L2_VTR_OP, VppDot1QSubint, VppDot1ADSubint
from vpp_gre_interface import VppGreInterface
from vpp_vxlan_tunnel import VppVxlanTunnel
from collections import namedtuple
from vpp_papi import VppEnum
from vpp_ip_route import VppRoutePath
from test_l3xc import VppL3xc

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
        # create 4 pg interfaces
        cls.create_pg_interfaces(range(4))

        cls.bd_id = 55
        cls.sub_if = VppDot1QSubint(cls, cls.pg0, 100)
        cls.vlan_sub_if = VppDot1QSubint(cls, cls.pg2, 300)
        cls.vlan_sub_if.set_vtr(L2_VTR_OP.L2_POP_1, tag=300)

        cls.qinq_sub_if = VppDot1ADSubint(cls, cls.pg2, 33, 400, 500)
        cls.qinq_sub_if.set_vtr(L2_VTR_OP.L2_POP_2, outer=500, inner=400)

        # packet flows mapping pg0 -> pg1, pg2 -> pg3, etc.
        cls.flows = dict()
        cls.flows[cls.pg0] = [cls.pg1]
        cls.flows[cls.pg1] = [cls.pg0]

        # packet sizes
        cls.pg_if_packet_sizes = [64, 512, 1518]  # , 9018]

        # setup all interfaces
        for i in cls.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()
            i.config_ip6()
            i.resolve_ndp()

    def setUp(self):
        super(TestSpan, self).setUp()
        self.vxlan = VppVxlanTunnel(self, src=self.pg2.local_ip4,
                                    dst=self.pg2.remote_ip4, vni=1111)
        self.vxlan.add_vpp_config()
        self.reset_packet_infos()

    def tearDown(self):
        super(TestSpan, self).tearDown()

    def show_commands_at_teardown(self):
        self.logger.info(self.vapi.ppcli("show interface span"))

    def xconnect(self, a, b, is_add=1):
        self.vapi.sw_interface_set_l2_xconnect(a, b, enable=is_add)
        self.vapi.sw_interface_set_l2_xconnect(b, a, enable=is_add)

    def bridge(self, sw_if_index, is_add=1):
        self.vapi.sw_interface_set_l2_bridge(rx_sw_if_index=sw_if_index,
                                             bd_id=self.bd_id, enable=is_add)

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

    def decap_erspan(self, pkt, session):
        """
        Decapsulate the original payload frame by removing ERSPAN header
        """
        self.assertEqual(pkt[Ether].src, self.pg2.local_mac)
        self.assertEqual(pkt[Ether].dst, self.pg2.remote_mac)

        self.assertEqual(pkt[IP].src, self.pg2.local_ip4)
        self.assertEqual(pkt[IP].dst, self.pg2.remote_ip4)

        self.assertEqual(pkt[ERSPAN].ver, 1)
        self.assertEqual(pkt[ERSPAN].vlan, 0)
        self.assertEqual(pkt[ERSPAN].cos, 0)
        self.assertEqual(pkt[ERSPAN].en, 3)
        self.assertEqual(pkt[ERSPAN].t, 0)
        self.assertEqual(pkt[ERSPAN].session_id, session)
        self.assertEqual(pkt[ERSPAN].reserved, 0)
        self.assertEqual(pkt[ERSPAN].index, 0)

        return pkt[ERSPAN].payload

    def decap_vxlan(self, pkt):
        """
        Decapsulate the original payload frame by removing VXLAN header
        """
        self.assertEqual(pkt[Ether].src, self.pg2.local_mac)
        self.assertEqual(pkt[Ether].dst, self.pg2.remote_mac)

        self.assertEqual(pkt[IP].src, self.pg2.local_ip4)
        self.assertEqual(pkt[IP].dst, self.pg2.remote_ip4)

        return pkt[VXLAN].payload

    def create_stream(self, src_if, packet_sizes, do_dot1=False, bcast=False,
                      is_ip6=False):
        pkts = []
        dst_if = self.flows[src_if][0]
        dst_mac = src_if.remote_mac
        if bcast:
            dst_mac = "ff:ff:ff:ff:ff:ff"

        if is_ip6:
            ip = IPv6(src=src_if.remote_ip6, dst=dst_if.remote_ip6)
        else:
            ip = IP(src=src_if.remote_ip4, dst=dst_if.remote_ip4)

        for i in range(0, self.pkts_per_burst):
            payload = "span test"
            size = packet_sizes[int((i / 2) % len(packet_sizes))]
            p = (Ether(src=src_if.local_mac, dst=dst_mac) / ip /
                 UDP(sport=10000 + src_if.sw_if_index * 1000 + i, dport=1234) /
                 Raw(payload))
            if do_dot1:
                p = self.sub_if.add_dot1_layer(p)
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
        """ SPAN device rx mirror """

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
        n_pkts = len(pkts)
        pg1_pkts = self.pg1.get_capture(n_pkts)
        pg2_pkts = self.pg2.get_capture(n_pkts)

        # Disable SPAN on pg0 (mirrored to pg2)
        self.vapi.sw_interface_span_enable_disable(
            self.pg0.sw_if_index, self.pg2.sw_if_index, state=0)
        self.xconnect(self.pg0.sw_if_index, self.pg1.sw_if_index, is_add=0)

        self.verify_capture(pg1_pkts, pg2_pkts)

    def test_span_l2_rx(self):
        """ SPAN l2 rx mirror """

        self.sub_if.admin_up()

        self.bridge(self.pg2.sw_if_index)
        # Create bi-directional cross-connects between pg0 subif and pg1
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
        """ SPAN l2 rx mirror into vxlan """

        self.sub_if.admin_up()
        self.vapi.sw_interface_set_flags(self.vxlan.sw_if_index,
                                         flags=1)

        self.bridge(self.vxlan.sw_if_index, is_add=1)
        # Create bi-directional cross-connects between pg0 subif and pg1
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
        n_pkts = len(pkts)
        pg1_pkts = self.pg1.get_capture(n_pkts)
        pg2_pkts = [self.decap_vxlan(p) for p in self.pg2.get_capture(n_pkts)]

        self.bridge(self.vxlan.sw_if_index, is_add=0)
        # Disable SPAN on pg0 sub if (mirrored to vxlan)
        self.vapi.sw_interface_span_enable_disable(
            self.sub_if.sw_if_index, self.vxlan.sw_if_index, state=0, is_l2=1)
        self.xconnect(self.sub_if.sw_if_index, self.pg1.sw_if_index, is_add=0)
        self.verify_capture(pg1_pkts, pg2_pkts)

    def test_span_l2_rx_dst_gre_erspan(self):
        """ SPAN l2 rx mirror into gre-erspan """

        self.sub_if.admin_up()

        gre_if = VppGreInterface(self, self.pg2.local_ip4,
                                 self.pg2.remote_ip4,
                                 session=543,
                                 type=(VppEnum.vl_api_gre_tunnel_type_t.
                                       GRE_API_TUNNEL_TYPE_ERSPAN))

        gre_if.add_vpp_config()
        gre_if.admin_up()

        self.bridge(gre_if.sw_if_index)
        # Create bi-directional cross-connects between pg0 and pg1
        self.xconnect(self.sub_if.sw_if_index, self.pg1.sw_if_index, is_add=1)

        # Create incoming packet streams for packet-generator interfaces
        pkts = self.create_stream(
            self.pg0, self.pg_if_packet_sizes, do_dot1=True)
        self.pg0.add_stream(pkts)

        # Enable SPAN on pg0 sub if (mirrored to gre-erspan)
        self.vapi.sw_interface_span_enable_disable(
            self.sub_if.sw_if_index, gre_if.sw_if_index, is_l2=1)

        # Enable packet capturing and start packet sending
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Verify packets outgoing packet streams on mirrored interface (pg2)
        n_pkts = len(pkts)
        pg1_pkts = self.pg1.get_capture(n_pkts)
        pg2_pkts = self.pg2.get_capture(n_pkts)

        def decap(p): return self.decap_erspan(p, session=543)
        pg2_decaped = [decap(p) for p in pg2_pkts]

        self.bridge(gre_if.sw_if_index, is_add=0)

        # Disable SPAN on pg0 sub if
        self.vapi.sw_interface_span_enable_disable(
            self.sub_if.sw_if_index, gre_if.sw_if_index, state=0, is_l2=1)
        gre_if.remove_vpp_config()
        self.xconnect(self.sub_if.sw_if_index, self.pg1.sw_if_index, is_add=0)

        self.verify_capture(pg1_pkts, pg2_decaped)

    def test_span_l2_rx_dst_gre_subif_vtr(self):
        """ SPAN l2 rx mirror into gre-subif+vtr """

        self.sub_if.admin_up()

        gre_if = VppGreInterface(self, self.pg2.local_ip4,
                                 self.pg2.remote_ip4,
                                 type=(VppEnum.vl_api_gre_tunnel_type_t.
                                       GRE_API_TUNNEL_TYPE_TEB))

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

        # Enable SPAN on pg0 sub if (mirrored to gre sub if)
        self.vapi.sw_interface_span_enable_disable(
            self.sub_if.sw_if_index, gre_sub_if.sw_if_index, is_l2=1)

        # Enable packet capturing and start packet sending
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Verify packets outgoing packet streams on mirrored interface (pg2)
        n_pkts = len(pkts)
        pg1_pkts = self.pg1.get_capture(n_pkts)
        pg2_pkts = self.pg2.get_capture(n_pkts)

        def decap(p): return self.remove_tags(
            self.decap_gre(p), [Tag(dot1=DOT1Q, vlan=500)])
        pg2_decaped = [decap(p) for p in pg2_pkts]

        self.bridge(gre_sub_if.sw_if_index, is_add=0)

        # Disable SPAN on pg0 sub if
        self.vapi.sw_interface_span_enable_disable(
            self.sub_if.sw_if_index, gre_sub_if.sw_if_index, state=0, is_l2=1)
        gre_if.remove_vpp_config()
        self.xconnect(self.sub_if.sw_if_index, self.pg1.sw_if_index, is_add=0)

        self.verify_capture(pg1_pkts, pg2_decaped)

    def test_span_l2_rx_dst_1q_vtr(self):
        """ SPAN l2 rx mirror into 1q subif+vtr """

        self.sub_if.admin_up()
        self.vlan_sub_if.admin_up()

        self.bridge(self.vlan_sub_if.sw_if_index)
        # Create bi-directional cross-connects between pg0 and pg1
        self.xconnect(self.sub_if.sw_if_index, self.pg1.sw_if_index, is_add=1)

        # Create incoming packet streams for packet-generator interfaces
        pkts = self.create_stream(
            self.pg0, self.pg_if_packet_sizes, do_dot1=True)
        self.pg0.add_stream(pkts)

        self.vapi.sw_interface_span_enable_disable(
            self.sub_if.sw_if_index, self.vlan_sub_if.sw_if_index, is_l2=1)

        # Enable packet capturing and start packet sending
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Verify packets outgoing packet streams on mirrored interface (pg2)
        n_pkts = len(pkts)
        pg1_pkts = self.pg1.get_capture(n_pkts)
        pg2_pkts = self.pg2.get_capture(n_pkts)
        pg2_untagged = [self.remove_tags(p, [Tag(dot1=DOT1Q, vlan=300)])
                        for p in pg2_pkts]

        self.bridge(self.vlan_sub_if.sw_if_index, is_add=0)
        # Disable SPAN on pg0 sub if (mirrored to vxlan)
        self.vapi.sw_interface_span_enable_disable(
            self.sub_if.sw_if_index, self.vlan_sub_if.sw_if_index, state=0,
            is_l2=1)
        self.xconnect(self.sub_if.sw_if_index, self.pg1.sw_if_index, is_add=0)

        self.verify_capture(pg1_pkts, pg2_untagged)

    def test_span_l2_rx_dst_1ad_vtr(self):
        """ SPAN l2 rx mirror into 1ad subif+vtr """

        self.sub_if.admin_up()
        self.qinq_sub_if.admin_up()

        self.bridge(self.qinq_sub_if.sw_if_index)
        # Create bi-directional cross-connects between pg0 and pg1
        self.xconnect(self.sub_if.sw_if_index, self.pg1.sw_if_index, is_add=1)

        # Create incoming packet streams for packet-generator interfaces
        pkts = self.create_stream(
            self.pg0, self.pg_if_packet_sizes, do_dot1=True)
        self.pg0.add_stream(pkts)

        self.vapi.sw_interface_span_enable_disable(
            self.sub_if.sw_if_index, self.qinq_sub_if.sw_if_index, is_l2=1)

        # Enable packet capturing and start packet sending
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Verify packets outgoing packet streams on mirrored interface (pg2)
        n_pkts = len(pkts)
        pg1_pkts = self.pg1.get_capture(n_pkts)
        pg2_pkts = self.pg2.get_capture(n_pkts)
        pg2_untagged = [self.remove_tags(p, [Tag(dot1=DOT1AD, vlan=400),
                                             Tag(dot1=DOT1Q, vlan=500)])
                        for p in pg2_pkts]

        self.bridge(self.qinq_sub_if.sw_if_index, is_add=0)
        # Disable SPAN on pg0 sub if (mirrored to vxlan)
        self.vapi.sw_interface_span_enable_disable(
            self.sub_if.sw_if_index, self.qinq_sub_if.sw_if_index, state=0,
            is_l2=1)
        self.xconnect(self.sub_if.sw_if_index, self.pg1.sw_if_index, is_add=0)

        self.verify_capture(pg1_pkts, pg2_untagged)

    def test_l2_tx_span(self):
        """ SPAN l2 tx mirror """

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
        n_pkts = len(pkts)
        pg1_pkts = self.pg1.get_capture(n_pkts)
        pg2_pkts = self.pg2.get_capture(n_pkts)
        self.bridge(self.pg2.sw_if_index, is_add=0)
        # Disable SPAN on pg0 (mirrored to pg2)
        self.vapi.sw_interface_span_enable_disable(
            self.pg1.sw_if_index, self.pg2.sw_if_index, state=0, is_l2=1)
        self.xconnect(self.sub_if.sw_if_index, self.pg1.sw_if_index, is_add=0)

        self.verify_capture(pg1_pkts, pg2_pkts)

    def test_l2_rx_tx_span(self):
        """ SPAN l2 rx tx mirror """

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
        pg0_expected = len(pg1_pkts)
        pg1_expected = len(pg0_pkts)
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

    def test_l2_bcast_mirror(self):
        """ SPAN l2 broadcast mirror """

        self.sub_if.admin_up()
        self.bridge(self.pg2.sw_if_index)

        # Create bi-directional cross-connects between pg0 and pg1
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.sub_if.sw_if_index, bd_id=99, enable=1)
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.pg1.sw_if_index, bd_id=99, enable=1)

        # Create incoming packet streams for packet-generator interfaces
        pg0_pkts = self.create_stream(
            self.pg0, self.pg_if_packet_sizes, do_dot1=True, bcast=True)
        self.pg0.add_stream(pg0_pkts)
        pg1_pkts = self.create_stream(
            self.pg1, self.pg_if_packet_sizes, do_dot1=False, bcast=True)
        self.pg1.add_stream(pg1_pkts)

        # Enable SPAN on pg0 (mirrored to pg2)
        self.vapi.sw_interface_span_enable_disable(
            self.sub_if.sw_if_index, self.pg2.sw_if_index, is_l2=1, state=3)
        self.logger.info(self.vapi.ppcli("show interface span"))

        # Enable packet capturing and start packet sending
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Verify packets outgoing packet streams on mirrored interface (pg2)
        pg0_expected = len(pg1_pkts)
        pg1_expected = len(pg0_pkts)
        pg2_expected = pg0_expected + pg1_expected

        pg0_pkts = self.pg0.get_capture(pg0_expected)
        pg1_pkts = self.pg1.get_capture(pg1_expected)
        pg2_pkts = self.pg2.get_capture(pg2_expected)

        self.bridge(self.pg2.sw_if_index, is_add=0)
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.sub_if.sw_if_index, bd_id=99, enable=0)
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.pg1.sw_if_index, bd_id=99, enable=0)
        # Disable SPAN on pg0 (mirrored to pg2)
        self.vapi.sw_interface_span_enable_disable(
            self.sub_if.sw_if_index, self.pg2.sw_if_index, state=0, is_l2=1)

        self.verify_capture(pg0_pkts + pg1_pkts, pg2_pkts)

    def __test_ip_span(self, is_ip6):
        # test IP span:
        #  - traffic is forwarded between pg0 and pg1 via a l3xc
        #  - pg0 is spanned for both rx and tx to pg2. As there is no traffic
        #  sent through pg0, we are only going through the span-ipX-input (ie
        #  span rx) node
        #  - pg1 is spanned for both rx and tx to pg3. As there is no traffic
        #  received by pg1, we are only going through the span-ipX-output (ie
        #  span tx) node

        span_state = VppEnum.vl_api_span_state_t.SPAN_STATE_API_RX_TX
        if is_ip6:
            span_type = VppEnum.vl_api_span_type_t.SPAN_TYPE_API_IP6
            l3xc_rip = self.pg1.remote_ip6
            ip_layer = IPv6
        else:
            span_type = VppEnum.vl_api_span_type_t.SPAN_TYPE_API_IP4
            l3xc_rip = self.pg1.remote_ip4
            ip_layer = IP

        # Create l3xc pg0 -> pg1
        l3xc = VppL3xc(
            self, self.pg0, [
                VppRoutePath(
                    l3xc_rip, self.pg1.sw_if_index)])
        l3xc.add_vpp_config()

        # Create incoming packet streams for packet-generator interfaces
        pkts = self.create_stream(self.pg0, self.pg_if_packet_sizes,
                                  is_ip6=is_ip6)
        self.pg0.add_stream(pkts)

        # Enable SPAN on pg0 (mirrored to pg2)
        self.vapi.sw_interface_span_v2_enable_disable(
            self.pg0.sw_if_index, self.pg2.sw_if_index, span_state, span_type)

        # Enable SPAN on pg1 (mirrored to pg3)
        self.vapi.sw_interface_span_v2_enable_disable(
            self.pg1.sw_if_index, self.pg3.sw_if_index, span_state, span_type)

        # Enable packet capturing and start packet sending
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Verify packets outgoing packet streams on mirrored interfaces
        n_pkts = len(pkts)
        pg1_pkts = self.pg1.get_capture(n_pkts)
        pg2_pkts = self.pg2.get_capture(n_pkts)
        pg3_pkts = self.pg3.get_capture(n_pkts)

        # Disable SPAN and l3xc
        self.vapi.sw_interface_span_v2_enable_disable(
            self.pg0.sw_if_index, self.pg2.sw_if_index, 0, span_type)
        self.vapi.sw_interface_span_v2_enable_disable(
            self.pg1.sw_if_index, self.pg3.sw_if_index, 0, span_type)
        l3xc.remove_vpp_config()

        # compare outputs from pg1, pg2, pg3
        # we are capturing ip traffic on pg2 and pg3, but scapy thinks it is
        # ethernet
        self.assertEqual(len(pg1_pkts), len(pkts))
        self.assertEqual(len(pg1_pkts), len(pg2_pkts))
        self.assertEqual(len(pg1_pkts), len(pg3_pkts))
        for p1, p2, p3 in zip(pg1_pkts, pg2_pkts, pg3_pkts):
            # span happens at the IP layer, drop Ethernet
            p1 = p1[ip_layer]
            # cast p3 from Ethernet to IP
            p3 = ip_layer(bytes(p3))
            # span on pg3 happens after forwarding (pg1 tx) so the packets
            # should be identical on pg1 and pg3
            self.assertEqual(p1, p3)
            # span on pg2 happens before forwarding (pg0 rx) but the packet ttl
            # was decremented during forwarding, fix it
            if is_ip6:
                p1.hlim += 1
            else:
                p1.ttl += 1
                # force checksum update
                del p1.chksum
                p1 = ip_layer(p1.build())
            # cast p2 from Ethernet to IP
            p2 = ip_layer(bytes(p2))
            self.assertEqual(p1, p2)

    def test_ip4_span(self):
        """ SPAN IPv4 rx tx mirror """
        return self.__test_ip_span(is_ip6=False)

    def test_ip6_span(self):
        """ SPAN IPv6 rx tx mirror """
        return self.__test_ip_span(is_ip6=True)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
