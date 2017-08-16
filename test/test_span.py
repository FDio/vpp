#!/usr/bin/env python

import unittest

from scapy.packet import Raw
from scapy.layers.l2 import Ether, Dot1Q, GRE
from scapy.layers.inet import IP, UDP
from scapy.layers.vxlan import VXLAN

from framework import VppTestCase, VppTestRunner, VppMultiWorkerScenario
from util import Host, ppp
from vpp_sub_interface import VppDot1QSubint
from vpp_gre_interface import VppGreInterface
from vpp_papi_provider import L2_VTR_OP
from collections import namedtuple

Tag = namedtuple('Tag', ['dot1', 'vlan'])
DOT1AD = 0x88A8
DOT1Q = 0x8100


@VppMultiWorkerScenario.skip("test doesn't pass with multiple workers")
class TestSpan(VppTestCase):
    """ SPAN Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestSpan, cls).setUpClass()
        # Test variables
        cls.hosts_nr = 10           # Number of hosts
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

        # packet sizes
        cls.pg_if_packet_sizes = [64, 512]  # , 1518, 9018]

        cls.interfaces = list(cls.pg_interfaces)

        # Create host MAC and IPv4 lists
        # cls.MY_MACS = dict()
        # cls.MY_IP4S = dict()
        cls.create_host_lists(cls.hosts_nr)

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

    @classmethod
    def create_host_lists(self, count):
        """ Method to create required number of MAC and IPv4 addresses.
        Create required number of host MAC addresses and distribute them among
        interfaces. Create host IPv4 address for every host MAC address too.

        :param count: Number of hosts to create MAC and IPv4 addresses for.
        """
        # mapping between packet-generator index and lists of test hosts
        self.hosts_by_pg_idx = dict()

        for pg_if in self.pg_interfaces:
            # self.MY_MACS[i.sw_if_index] = []
            # self.MY_IP4S[i.sw_if_index] = []
            self.hosts_by_pg_idx[pg_if.sw_if_index] = []
            hosts = self.hosts_by_pg_idx[pg_if.sw_if_index]
            for j in range(0, count):
                host = Host(
                    "00:00:00:ff:%02x:%02x" % (pg_if.sw_if_index, j),
                    "172.17.1%02x.%u" % (pg_if.sw_if_index, j))
                hosts.append(host)

    def create_stream(self, src_if, packet_sizes, do_dot1=False):
        pkts = []
        for i in range(0, self.pkts_per_burst):
            dst_if = self.flows[src_if][0]
            pkt_info = self.create_packet_info(src_if, dst_if)
            payload = self.info_to_payload(pkt_info)
            p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                 IP(src=src_if.remote_ip4, dst=dst_if.remote_ip4) /
                 UDP(sport=1234, dport=1234) /
                 Raw(payload))
            if do_dot1:
                p = self.sub_if.add_dot1_layer(p)
            pkt_info.data = p.copy()
            size = packet_sizes[(i / 2) % len(packet_sizes)]
            self.extend_packet(p, size)
            pkts.append(p)
        return pkts

    def verify_capture(self, dst_if, capture_pg1, capture_pg2):
        last_info = dict()
        for i in self.interfaces:
            last_info[i.sw_if_index] = None
        dst_sw_if_index = dst_if.sw_if_index
        self.assertEqual(
            len(capture_pg1),
            len(capture_pg2),
            "Different number of outgoing and mirrored packets : %u != %u" %
            (len(capture_pg1),
             len(capture_pg2)))
        for pkt_pg1, pkt_pg2 in zip(capture_pg1, capture_pg2):
            try:
                ip1 = pkt_pg1[IP]
                udp1 = pkt_pg1[UDP]
                raw1 = pkt_pg1[Raw]

                if pkt_pg1[Ether] != pkt_pg2[Ether]:
                    self.logger.error("Different ethernet header of "
                                      "outgoing and mirrored packet")
                    raise
                if ip1 != pkt_pg2[IP]:
                    self.logger.error(
                        "Different ip header of outgoing and mirrored packet")
                    raise
                if udp1 != pkt_pg2[UDP]:
                    self.logger.error(
                        "Different udp header of outgoing and mirrored packet")
                    raise
                if raw1 != pkt_pg2[Raw]:
                    self.logger.error(
                        "Different raw data of outgoing and mirrored packet")
                    raise

                payload_info = self.payload_to_info(str(raw1))
                packet_index = payload_info.index
                self.assertEqual(payload_info.dst, dst_sw_if_index)
                self.logger.debug(
                    "Got packet on port %s: src=%u (id=%u)" %
                    (dst_if.name, payload_info.src, packet_index))
                next_info = self.get_next_packet_info_for_interface2(
                    payload_info.src, dst_sw_if_index,
                    last_info[payload_info.src])
                last_info[payload_info.src] = next_info
                self.assertTrue(next_info is not None)
                self.assertEqual(packet_index, next_info.index)
                saved_packet = next_info.data
                # Check standard fields
                self.assertEqual(ip1.src, saved_packet[IP].src)
                self.assertEqual(ip1.dst, saved_packet[IP].dst)
                self.assertEqual(udp1.sport, saved_packet[UDP].sport)
                self.assertEqual(udp1.dport, saved_packet[UDP].dport)
            except:
                self.logger.error("Unexpected or invalid packets:")
                self.logger.error(ppp("pg1 packet:", pkt_pg1))
                self.logger.error(ppp("pg2 packet:", pkt_pg2))
                raise
        for i in self.interfaces:
            remaining_packet = self.get_next_packet_info_for_interface2(
                i, dst_sw_if_index, last_info[i.sw_if_index])
            self.assertTrue(remaining_packet is None,
                            "Port %u: Packet expected from source %u didn't"
                            " arrive" % (dst_sw_if_index, i.sw_if_index))

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
        pg2_expected = self.get_packet_count_for_if_idx(self.pg1.sw_if_index)
        self.verify_capture(
            self.pg1,
            self.pg1.get_capture(),
            self.pg2.get_capture(pg2_expected))

        # Disable SPAN on pg0 (mirrored to pg2)
        self.vapi.sw_interface_span_enable_disable(
            self.pg0.sw_if_index, self.pg2.sw_if_index, state=0)
        self.xconnect(self.pg0.sw_if_index, self.pg1.sw_if_index, is_add=0)

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
        pg2_expected = self.get_packet_count_for_if_idx(self.pg1.sw_if_index)
        pg1_pkts = self.pg1.get_capture()
        pg2_pkts = self.pg2.get_capture(pg2_expected)
        self.verify_capture(
            self.pg1,
            pg1_pkts,
            pg2_pkts)

        self.bridge(self.pg2.sw_if_index, is_add=0)
        # Disable SPAN on pg0 (mirrored to pg2)
        self.vapi.sw_interface_span_enable_disable(
            self.sub_if.sw_if_index, self.pg2.sw_if_index, state=0, is_l2=1)
        self.xconnect(self.sub_if.sw_if_index, self.pg1.sw_if_index, is_add=0)

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
        self.verify_capture(
            self.pg1,
            pg1_pkts,
            pg2_pkts)

        self.bridge(self.vxlan.sw_if_index, is_add=0)
        # Disable SPAN on pg0 sub if (mirrored to vxlan)
        self.vapi.sw_interface_span_enable_disable(
            self.sub_if.sw_if_index, self.vxlan.sw_if_index, state=0, is_l2=1)
        self.xconnect(self.sub_if.sw_if_index, self.pg1.sw_if_index, is_add=0)

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
        self.verify_capture(
            self.pg1,
            pg1_pkts,
            pg2_decaped)

        self.bridge(gre_sub_if.sw_if_index, is_add=0)
        # Disable SPAN on pg0 sub if
        self.vapi.sw_interface_span_enable_disable(
            self.sub_if.sw_if_index, gre_sub_if.sw_if_index, state=0,
            is_l2=1)
        gre_if.remove_vpp_config()
        self.xconnect(self.sub_if.sw_if_index, self.pg1.sw_if_index, is_add=0)

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
        self.verify_capture(
            self.pg1,
            pg1_pkts,
            pg2_untagged)

        self.bridge(self.dst_sub_if.sw_if_index, is_add=0)
        # Disable SPAN on pg0 sub if (mirrored to vxlan)
        self.vapi.sw_interface_span_enable_disable(
            self.sub_if.sw_if_index, self.dst_sub_if.sw_if_index, state=0,
            is_l2=1)
        self.xconnect(self.sub_if.sw_if_index, self.pg1.sw_if_index, is_add=0)

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

        # Enable SPAN on pg0 (mirrored to pg2)
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
        self.verify_capture(
            self.pg1,
            pg1_pkts,
            pg2_pkts)

        self.bridge(self.pg2.sw_if_index, is_add=0)
        # Disable SPAN on pg0 (mirrored to pg2)
        self.vapi.sw_interface_span_enable_disable(
            self.pg1.sw_if_index, self.pg2.sw_if_index, state=0, is_l2=1)
        self.xconnect(self.sub_if.sw_if_index, self.pg1.sw_if_index, is_add=0)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
