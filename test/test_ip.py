#!/usr/bin/env python

import unittest
import socket
from logging import *

from framework import VppTestCase, VppTestRunner
from vpp_sub_interface import VppSubInterface, VppDot1QSubint, VppDot1ADSubint

from scapy.packet import Raw
from scapy.layers.l2 import Ether, Dot1Q, ARP
from scapy.layers.inet import IP, UDP


class TestIPv4(VppTestCase):
    """ IPv4 Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestIPv4, cls).setUpClass()

    def setUp(self):
        super(TestIPv4, self).setUp()

        # create 3 pg interfaces
        self.create_pg_interfaces(range(3))

        # create 2 subinterfaces for pg1 and pg2
        self.sub_interfaces = [
            VppDot1QSubint(self, self.pg1, 100),
            VppDot1ADSubint(self, self.pg2, 200, 300, 400)]

        # packet flows mapping pg0 -> pg1.sub, pg2.sub, etc.
        self.flows = dict()
        self.flows[self.pg0] = [self.pg1.sub_if, self.pg2.sub_if]
        self.flows[self.pg1.sub_if] = [self.pg0, self.pg2.sub_if]
        self.flows[self.pg2.sub_if] = [self.pg0, self.pg1.sub_if]

        # packet sizes
        self.pg_if_packet_sizes = [64, 512, 1518, 9018]
        self.sub_if_packet_sizes = [64, 512, 1518 + 4, 9018 + 4]

        self.interfaces = list(self.pg_interfaces)
        self.interfaces.extend(self.sub_interfaces)

        # setup all interfaces
        for i in self.interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

        # config 2M FIB enries
        self.config_fib_entries(200)

    def tearDown(self):
        super(TestIPv4, self).tearDown()
        if not self.vpp_dead:
            info(self.vapi.cli("show ip arp"))
            # info(self.vapi.cli("show ip fib"))  # many entries

    def config_fib_entries(self, count):
        n_int = len(self.interfaces)
        percent = 0
        counter = 0.0
        dest_addr = socket.inet_pton(socket.AF_INET, "10.0.0.1")
        dest_addr_len = 32
        for i in self.interfaces:
            next_hop_address = i.local_ip4n
            for j in range(count / n_int):
                self.vapi.ip_add_del_route(
                    dest_addr, dest_addr_len, next_hop_address)
                counter = counter + 1
                if counter / count * 100 > percent:
                    info("Configure %d FIB entries .. %d%% done" %
                         (count, percent))
                    percent = percent + 1

    def create_stream(self, src_if, packet_sizes):
        pkts = []
        for i in range(0, 257):
            dst_if = self.flows[src_if][i % 2]
            info = self.create_packet_info(
                src_if.sw_if_index, dst_if.sw_if_index)
            payload = self.info_to_payload(info)
            p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                 IP(src=src_if.remote_ip4, dst=dst_if.remote_ip4) /
                 UDP(sport=1234, dport=1234) /
                 Raw(payload))
            info.data = p.copy()
            if isinstance(src_if, VppSubInterface):
                p = src_if.add_dot1_layer(p)
            size = packet_sizes[(i // 2) % len(packet_sizes)]
            self.extend_packet(p, size)
            pkts.append(p)
        return pkts

    def verify_capture(self, dst_if, capture):
        info("Verifying capture on interface %s" % dst_if.name)
        last_info = dict()
        for i in self.interfaces:
            last_info[i.sw_if_index] = None
        is_sub_if = False
        dst_sw_if_index = dst_if.sw_if_index
        if hasattr(dst_if, 'parent'):
            is_sub_if = True
        for packet in capture:
            if is_sub_if:
                # Check VLAN tags and Ethernet header
                packet = dst_if.remove_dot1_layer(packet)
            self.assertTrue(Dot1Q not in packet)
            try:
                ip = packet[IP]
                udp = packet[UDP]
                payload_info = self.payload_to_info(str(packet[Raw]))
                packet_index = payload_info.index
                self.assertEqual(payload_info.dst, dst_sw_if_index)
                debug("Got packet on port %s: src=%u (id=%u)" %
                      (dst_if.name, payload_info.src, packet_index))
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
        for i in self.interfaces:
            remaining_packet = self.get_next_packet_info_for_interface2(
                i.sw_if_index, dst_sw_if_index, last_info[i.sw_if_index])
            self.assertTrue(
                remaining_packet is None,
                "Interface %s: Packet expected from interface %s didn't arrive" %
                (dst_if.name, i.name))

    def test_fib(self):
        """ IPv4 FIB test """

        pkts = self.create_stream(self.pg0, self.pg_if_packet_sizes)
        self.pg0.add_stream(pkts)

        for i in self.sub_interfaces:
            pkts = self.create_stream(i, self.sub_if_packet_sizes)
            i.parent.add_stream(pkts)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        pkts = self.pg0.get_capture()
        self.verify_capture(self.pg0, pkts)

        for i in self.sub_interfaces:
            pkts = i.parent.get_capture()
            self.verify_capture(i, pkts)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
