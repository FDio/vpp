#!/usr/bin/env python

import unittest
from logging import *
import random

from scapy.packet import Raw
from scapy.layers.l2 import Ether, Dot1Q
from scapy.layers.inet import IP, UDP

from framework import VppTestCase, VppTestRunner
from vpp_sub_interface import VppDot1QSubint
from util import Host


class TestL2bd(VppTestCase):
    """ L2BD Test Case """

    # Test variables
    bd_id = 1                 # Bridge domain ID
    mac_entries_count = 100   # Number of MAC entries for bridge-domain to learn
    dot1q_sub_id = 100        # SubID of dot1q sub-interface
    dot1q_tag = 100           # VLAN tag for dot1q sub-interface
    dot1ad_sub_id = 200       # SubID of dot1ad sub-interface
    dot1ad_outer_tag = 200    # VLAN S-tag for dot1ad sub-interface
    dot1ad_inner_tag = 300    # VLAN C-tag for dot1ad sub-interface
    pkts_per_burst = 257      # Number of packets per burst

    @classmethod
    def setUpClass(cls):
        super(TestL2bd, cls).setUpClass()

    def setUp(self):
        super(TestL2bd, self).setUp()

        # create 3 pg interfaces
        self.create_pg_interfaces(range(3))

        # create 2 sub-interfaces for pg1 and pg2
        self.sub_interfaces = [
            VppDot1QSubint(self, self.pg1, TestL2bd.dot1q_sub_id),
            VppDot1QSubint(self, self.pg2, TestL2bd.dot1ad_sub_id)]

        # packet flows mapping pg0 -> pg1, pg2, etc.
        self.flows = dict()
        self.flows[self.pg0] = [self.pg1, self.pg2]
        self.flows[self.pg1] = [self.pg0, self.pg2]
        self.flows[self.pg2] = [self.pg0, self.pg1]

        # packet sizes
        self.pg_if_packet_sizes = [64, 512, 1518, 9018]
        self.sub_if_packet_sizes = [64, 512, 1518 + 4, 9018 + 4]

        self.interfaces = list(self.pg_interfaces)
        self.interfaces.extend(self.sub_interfaces)

        # Create BD with MAC learning enabled and put interfaces and
        #  sub-interfaces to this BD
        for pg_if in self.pg_interfaces:
            sw_if_index = pg_if.sub_if.sw_if_index if hasattr(pg_if, 'sub_if') \
                else pg_if.sw_if_index
            self.vapi.sw_interface_set_l2_bridge(sw_if_index,
                                                 bd_id=TestL2bd.bd_id)

        # setup all interfaces
        for i in self.interfaces:
            i.admin_up()

        # mapping between packet-generator index and lists of test hosts
        self.hosts_by_pg_idx = dict()

        # create test host entries and inject packets to learn MAC entries in
        # the bridge-domain
        self.create_hosts_and_learn(TestL2bd.mac_entries_count)
        info(self.vapi.cli("show l2fib"))

    def tearDown(self):
        super(TestL2bd, self).tearDown()
        if not self.vpp_dead:
            info(self.vapi.cli("show l2fib verbose"))
            info(self.vapi.cli("show bridge-domain %s detail" % self.bd_id))

    def create_hosts_and_learn(self, count):
        """
        Create required number of host MAC addresses and distribute them among
        interfaces. Create host IPv4 address for every host MAC address. Create
        L2 MAC packet stream with host MAC addresses per interface to let
        the bridge domain learn these MAC addresses.

        :param count: Integer number of hosts to create MAC/IPv4 addresses for.
        """
        n_int = len(self.pg_interfaces)
        macs_per_if = count / n_int
        i = -1
        for pg_if in self.pg_interfaces:
            i += 1
            start_nr = macs_per_if * i
            end_nr = count if i == (n_int - 1) else macs_per_if * (i + 1)
            self.hosts_by_pg_idx[pg_if.sw_if_index] = []
            hosts = self.hosts_by_pg_idx[pg_if.sw_if_index]
            packets = []
            for j in range(start_nr, end_nr):
                host = Host(
                    "00:00:00:ff:%02x:%02x" % (pg_if.sw_if_index, j),
                    "172.17.1%02x.%u" % (pg_if.sw_if_index, j))
                packet = (Ether(dst="ff:ff:ff:ff:ff:ff", src=host.mac))
                hosts.append(host)
                if hasattr(pg_if, 'sub_if'):
                    packet = pg_if.sub_if.add_dot1_layer(packet)
                packets.append(packet)
            pg_if.add_stream(packets)
        info("Sending broadcast eth frames for MAC learning")
        self.pg_start()

    def create_stream(self, src_if, packet_sizes):
        pkts = []
        for i in range(0, TestL2bd.pkts_per_burst):
            dst_if = self.flows[src_if][i % 2]
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
            if hasattr(src_if, 'sub_if'):
                p = src_if.sub_if.add_dot1_layer(p)
            size = packet_sizes[(i / 2) % len(packet_sizes)]
            self.extend_packet(p, size)
            pkts.append(p)
        return pkts

    def verify_capture(self, pg_if, capture):
        last_info = dict()
        for i in self.pg_interfaces:
            last_info[i.sw_if_index] = None
        dst_sw_if_index = pg_if.sw_if_index
        for packet in capture:
            payload_info = self.payload_to_info(str(packet[Raw]))
            src_sw_if_index = payload_info.src
            src_if = None
            for ifc in self.pg_interfaces:
                if ifc != pg_if:
                    if ifc.sw_if_index == src_sw_if_index:
                        src_if = ifc
                        break
            if hasattr(src_if, 'sub_if'):
                # Check VLAN tags and Ethernet header
                packet = src_if.sub_if.remove_dot1_layer(packet)
            self.assertTrue(Dot1Q not in packet)
            try:
                ip = packet[IP]
                udp = packet[UDP]
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
                error(packet.show())
                raise
        for i in self.pg_interfaces:
            remaining_packet = self.get_next_packet_info_for_interface2(
                i, dst_sw_if_index, last_info[i.sw_if_index])
            self.assertTrue(
                remaining_packet is None,
                "Port %u: Packet expected from source %u didn't arrive" %
                (dst_sw_if_index, i.sw_if_index))

    def test_l2bd(self):
        """ L2BD MAC learning test

        1.config
            MAC learning enabled
            learn 100 MAC enries
            3 interfaces: untagged, dot1q, dot1ad (dot1q used instead of dot1ad
            in the first version)

        2.sending l2 eth pkts between 3 interface
            64B, 512B, 1518B, 9200B (ether_size)
            burst of 257 pkts per interface
        """

        # Create incoming packet streams for packet-generator interfaces
        for i in self.pg_interfaces:
            packet_sizes = self.sub_if_packet_sizes if hasattr(i, 'sub_if') \
                else self.pg_if_packet_sizes
            pkts = self.create_stream(i, packet_sizes)
            i.add_stream(pkts)

        # Enable packet capture and start packet sending
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Verify outgoing packet streams per packet-generator interface
        for i in self.pg_interfaces:
            capture = i.get_capture()
            info("Verifying capture on interface %s" % i.name)
            self.verify_capture(i, capture)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
