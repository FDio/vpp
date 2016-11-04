#!/usr/bin/env python

import unittest
import random

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from logging import *

from framework import VppTestCase, VppTestRunner
from util import Host


class TestL2xc(VppTestCase):
    """ L2XC Test Case """

    # Test variables
    hosts_nr = 10           # Number of hosts
    pkts_per_burst = 257    # Number of packets per burst

    @classmethod
    def setUpClass(cls):
        super(TestL2xc, cls).setUpClass()

    def setUp(self):
        super(TestL2xc, self).setUp()

        # create 4 pg interfaces
        self.create_pg_interfaces(range(4))

        # packet flows mapping pg0 -> pg1, pg2 -> pg3, etc.
        self.flows = dict()
        self.flows[self.pg0] = [self.pg1]
        self.flows[self.pg1] = [self.pg0]
        self.flows[self.pg2] = [self.pg3]
        self.flows[self.pg3] = [self.pg2]

        # packet sizes
        self.pg_if_packet_sizes = [64, 512, 1518, 9018]

        self.interfaces = list(self.pg_interfaces)

        # Create bi-directional cross-connects between pg0 and pg1
        self.vapi.sw_interface_set_l2_xconnect(
            self.pg0.sw_if_index, self.pg1.sw_if_index, enable=1)
        self.vapi.sw_interface_set_l2_xconnect(
            self.pg1.sw_if_index, self.pg0.sw_if_index, enable=1)

        # Create bi-directional cross-connects between pg2 and pg3
        self.vapi.sw_interface_set_l2_xconnect(
            self.pg2.sw_if_index, self.pg3.sw_if_index, enable=1)
        self.vapi.sw_interface_set_l2_xconnect(
            self.pg3.sw_if_index, self.pg2.sw_if_index, enable=1)

        info(self.vapi.cli("show l2patch"))

        # mapping between packet-generator index and lists of test hosts
        self.hosts_by_pg_idx = dict()

        # Create host MAC and IPv4 lists
        # self.MY_MACS = dict()
        # self.MY_IP4S = dict()
        self.create_host_lists(TestL2xc.hosts_nr)

        # setup all interfaces
        for i in self.interfaces:
            i.admin_up()

    def tearDown(self):
        super(TestL2xc, self).tearDown()
        if not self.vpp_dead:
            info(self.vapi.cli("show l2patch"))

    def create_host_lists(self, count):
        """ Method to create required number of MAC and IPv4 addresses.
        Create required number of host MAC addresses and distribute them among
        interfaces. Create host IPv4 address for every host MAC address too.

        :param count: Number of hosts to create MAC and IPv4 addresses for.
        """
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
        for i in range(0, TestL2xc.pkts_per_burst):
            dst_if = self.flows[src_if][0]
            dst_host = random.choice(self.hosts_by_pg_idx[dst_if.sw_if_index])
            src_host = random.choice(self.hosts_by_pg_idx[src_if.sw_if_index])
            pkt_info = self.create_packet_info(
                src_if.sw_if_index, dst_if.sw_if_index)
            payload = self.info_to_payload(pkt_info)
            p = (Ether(dst=dst_host.mac, src=src_host.mac) /
                 IP(src=src_host.ip4, dst=dst_host.ip4) /
                 UDP(sport=1234, dport=1234) /
                 Raw(payload))
            pkt_info.data = p.copy()
            size = packet_sizes[(i / 2) % len(packet_sizes)]
            self.extend_packet(p, size)
            pkts.append(p)
        return pkts

    def verify_capture(self, pg_if, capture):
        last_info = dict()
        for i in self.interfaces:
            last_info[i.sw_if_index] = None
        dst_sw_if_index = pg_if.sw_if_index
        for packet in capture:
            try:
                ip = packet[IP]
                udp = packet[UDP]
                payload_info = self.payload_to_info(str(packet[Raw]))
                packet_index = payload_info.index
                self.assertEqual(payload_info.dst, dst_sw_if_index)
                debug("Got packet on port %s: src=%u (id=%u)" %
                      (pg_if.name, payload_info.src, packet_index))
                next_info = self.get_next_packet_info_for_interface2(
                    payload_info.src, dst_sw_if_index,
                    last_info[payload_info.src])
                last_info[payload_info.src] = next_info
                self.assertTrue(next_info is not None)
                self.assertEqual(packet_index, next_info.index)
                saved_packet = next_info.data
                # Check standard fields
                self.assertEqual(ip.src, saved_packet[IP].src)
                self.assertEqual(ip.dst, saved_packet[IP].dst)
                self.assertEqual(udp.sport, saved_packet[UDP].sport)
                self.assertEqual(udp.dport, saved_packet[UDP].dport)
            except:
                error("Unexpected or invalid packet:")
                packet.show()
                raise
        for i in self.interfaces:
            remaining_packet = self.get_next_packet_info_for_interface2(
                i, dst_sw_if_index, last_info[i.sw_if_index])
            self.assertTrue(remaining_packet is None,
                            "Port %u: Packet expected from source %u didn't"
                            " arrive" % (dst_sw_if_index, i.sw_if_index))

    def test_l2xc(self):
        """ L2XC test

        Test scenario:
            1. config
               2 pairs of 2 interfaces, l2xconnected
            2. sending l2 eth packets between 4 interfaces
               64B, 512B, 1518B, 9018B (ether_size)
               burst of packets per interface
        """

        # Create incoming packet streams for packet-generator interfaces
        for i in self.interfaces:
            pkts = self.create_stream(i, self.pg_if_packet_sizes)
            i.add_stream(pkts)

        # Enable packet capturing and start packet sending
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Verify outgoing packet streams per packet-generator interface
        for i in self.pg_interfaces:
            capture = i.get_capture()
            info("Verifying capture on interface %s" % i.name)
            self.verify_capture(i, capture)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
