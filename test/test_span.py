#!/usr/bin/env python

import unittest

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP

from framework import VppTestCase, VppTestRunner
from util import Host, ppp


class TestSpan(VppTestCase):
    """ SPAN Test Case """

    # Test variables
    hosts_nr = 10           # Number of hosts
    pkts_per_burst = 257    # Number of packets per burst

    @classmethod
    def setUpClass(cls):
        super(TestSpan, cls).setUpClass()

    def setUp(self):
        super(TestSpan, self).setUp()

        # create 3 pg interfaces
        self.create_pg_interfaces(range(3))

        # packet flows mapping pg0 -> pg1, pg2 -> pg3, etc.
        self.flows = dict()
        self.flows[self.pg0] = [self.pg1]

        # packet sizes
        self.pg_if_packet_sizes = [64, 512]  # , 1518, 9018]

        self.interfaces = list(self.pg_interfaces)

        # Create host MAC and IPv4 lists
        # self.MY_MACS = dict()
        # self.MY_IP4S = dict()
        self.create_host_lists(TestSpan.hosts_nr)

        # Create bi-directional cross-connects between pg0 and pg1
        self.vapi.sw_interface_set_l2_xconnect(
            self.pg0.sw_if_index, self.pg1.sw_if_index, enable=1)
        self.vapi.sw_interface_set_l2_xconnect(
            self.pg1.sw_if_index, self.pg0.sw_if_index, enable=1)

        # setup all interfaces
        for i in self.interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

        # Enable SPAN on pg0 (mirrored to pg2)
        self.vapi.sw_interface_span_enable_disable(
            self.pg0.sw_if_index, self.pg2.sw_if_index)

    def tearDown(self):
        super(TestSpan, self).tearDown()

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

    def create_stream(self, src_if, packet_sizes):
        pkts = []
        for i in range(0, TestSpan.pkts_per_burst):
            dst_if = self.flows[src_if][0]
            pkt_info = self.create_packet_info(src_if, dst_if)
            payload = self.info_to_payload(pkt_info)
            p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                 IP(src=src_if.remote_ip4, dst=dst_if.remote_ip4) /
                 UDP(sport=1234, dport=1234) /
                 Raw(payload))
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

    def test_span(self):
        """ SPAN test

        Test scenario:
            1. config
               3 interfaces, pg0 l2xconnected with pg1
            2. sending l2 eth packets between 2 interfaces (pg0, pg1) and
               mirrored to pg2
               64B, 512B, 1518B, 9018B (ether_size)
               burst of packets per interface
        """

        # Create incoming packet streams for packet-generator interfaces
        pkts = self.create_stream(self.pg0, self.pg_if_packet_sizes)
        self.pg0.add_stream(pkts)

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


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
