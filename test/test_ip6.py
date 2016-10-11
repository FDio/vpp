#!/usr/bin/env python

import unittest
import socket
from logging import *

from framework import VppTestCase, VppTestRunner
from vpp_sub_interface import VppSubInterface, VppDot1QSubint

from scapy.packet import Raw
from scapy.layers.l2 import Ether, Dot1Q
from scapy.layers.inet6 import IPv6, UDP


class TestIPv6(VppTestCase):
    """ IPv6 Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestIPv6, cls).setUpClass()

        try:
            cls.interfaces = range(3)

            # create 3 pg interfaces
            cls.create_pg_interfaces(cls.interfaces)

            # create 2 subinterfaces for p1 and pg2
            cls.sub_interfaces = [
                VppDot1QSubint(cls, cls.pg1, 100),
                VppDot1QSubint(cls, cls.pg2, 200)]

            # packet flows mapping pg0 -> pg1.sub, pg2.sub, etc.
            cls.flows = dict()
            cls.flows[cls.pg0] = [cls.pg1.sub_if, cls.pg2.sub_if]
            cls.flows[cls.pg1.sub_if] = [cls.pg0, cls.pg2.sub_if]
            cls.flows[cls.pg2.sub_if] = [cls.pg0, cls.pg1.sub_if]

            # packet sizes
            cls.pg_if_packet_sizes = [64, 512, 1518, 9018]
            cls.sub_if_packet_sizes = [64, 512, 1518 + 4, 9018 + 4]

            cls.interfaces = list(cls.pg_interfaces)
            cls.interfaces.extend(cls.sub_interfaces)

            # setup all interfaces
            for i in cls.interfaces:
                i.admin_up()
                i.config_ip6()
                # i.resolve_arp() TODO: and rename arp to neighbor

            # config 2M FIB enries #TODO change to 2M
            cls.config_fib_entries(200)

        except:
            super(TestIPv6, cls).tearDownClass()
            raise

    def tearDown(self):
        super(TestIPv6, self).tearDown()
        if not self.vpp_dead:
            info(self.vapi.cli("show ip6 neighbors"))
            # info(vapi.cli("show ip6 fib"))  # 2M entries

    @classmethod
    def config_fib_entries(cls, count):
        n_int = len(cls.interfaces)
        percent = 0
        counter = 0.0
        dest_addr = socket.inet_pton(socket.AF_INET6, "fd02::1")
        dest_addr_len = 128
        for i in cls.interfaces:
            next_hop_address = i._local_ip6n
            for j in range(count / n_int):
                cls.vapi.ip_add_del_route(
                    dest_addr, dest_addr_len, next_hop_address, is_ipv6=1)
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
                 IPv6(src=src_if.remote_ip6, dst=dst_if.remote_ip6) /
                 UDP(sport=1234, dport=1234) /
                 Raw(payload))
            info.data = p.copy()
            if isinstance(src_if, VppSubInterface):
                p = src_if.add_dot1_layer(p)
            size = packet_sizes[(i / 2) % len(packet_sizes)]
            self.extend_packet(p, size)
            pkts.append(p)
        return pkts

    def verify_capture(self, pg_if, capture):
        last_info = dict()
        for i in self.interfaces:
            last_info[i.sw_if_index] = None
        has_sub_if = False
        dst_sw_if_index = pg_if.sw_if_index
        if hasattr(pg_if, 'sub_if'):
            has_sub_if = True
            dst_sw_if_index = pg_if.sub_if.sw_if_index
        for packet in capture:
            if has_sub_if:
                # Check VLAN tags and Ethernet header
                packet = pg_if.sub_if.remove_dot1_layer(packet)
            self.assertTrue(Dot1Q not in packet)
            try:
                ip = packet[IPv6]
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
                self.assertEqual(ip.src, saved_packet[IPv6].src)
                self.assertEqual(ip.dst, saved_packet[IPv6].dst)
                self.assertEqual(udp.sport, saved_packet[UDP].sport)
                self.assertEqual(udp.dport, saved_packet[UDP].dport)
            except:
                error("Unexpected or invalid packet:")
                error(packet.show())
                raise
        for i in self.interfaces:
            remaining_packet = self.get_next_packet_info_for_interface2(
                i, dst_sw_if_index, last_info[i.sw_if_index])
            self.assertTrue(
                remaining_packet is None,
                "Port %u: Packet expected from source %u didn't arrive" %
                (dst_sw_if_index, i.sw_if_index))

    def test_fib(self):
        """ IPv6 FIB test """

        pkts = self.create_stream(self.pg0, self.pg_if_packet_sizes)
        self.pg0.add_stream(pkts)

        for i in self.sub_interfaces:
            pkts = self.create_stream(i, self.sub_if_packet_sizes)
            i.parent.add_stream(pkts)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        for i in self.pg_interfaces:
            capture = i.get_capture()
            info("Verifying capture on interface %s" % i.name)
            self.verify_capture(i, capture)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
