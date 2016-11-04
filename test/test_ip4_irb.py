#!/usr/bin/env python

import unittest
from random import choice

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from logging import *

from framework import VppTestCase, VppTestRunner
from util import TestHost


class TestIpIrb(VppTestCase):
    """ IRB Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestIpIrb, cls).setUpClass()

        cls.pg_if_packet_sizes = [64, 512, 1518, 9018]  # packet sizes
        cls.bd_id = 10

        # create 3 pg interfaces, 1 loopback interface
        cls.create_pg_interfaces(range(3))
        cls.create_loopback_interfaces(range(1))

        cls.interfaces = list(cls.pg_interfaces)
        cls.interfaces.extend(cls.lo_interfaces)

        for i in cls.interfaces:
            i.admin_up()

        # Create BD with MAC learning enabled and put interfaces to this BD
        cls.vapi.sw_interface_set_l2_bridge(cls.loop0.sw_if_index, bd_id=cls.bd_id, bvi=1)
        cls.vapi.sw_interface_set_l2_bridge(cls.pg0.sw_if_index, bd_id=cls.bd_id)
        cls.vapi.sw_interface_set_l2_bridge(cls.pg1.sw_if_index, bd_id=cls.bd_id)

        cls.loop0.config_ip4()
        cls.pg2.config_ip4()

        # configure MAC address binding to IPv4 neighbors on loop0
        cls.loop0.configure_extend_ipv4_mac_binding()

        # maybe configure L2 MAC on BD ports
        # cls.pg0.configure mac nei
        # cls.pg1.configure mac nei

    def setUp(self):
        super(TestIpIrb, self).setUp()
        # clear fib or something delete if not needed

    def tearDown(self):
        super(TestIpIrb, self).tearDown()
        if not self.vpp_dead:
            info(self.vapi.cli("show l2patch"))
            info(self.vapi.cli("show l2fib verbose"))
            info(self.vapi.cli("show bridge-domain %s detail" % self.bd_id))
            info(self.vapi.cli("show ip arp"))
        # if not self.vpp_dead:

    def create_stream(self, src_if, dst_if, packet_sizes):
        pkts = []
        for i in range(0, 257):
            info = self.create_packet_info(
                src_if.sw_if_index, dst_if.sw_if_index)
            payload = self.info_to_payload(info)
            p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                 IP(src=src_if.remote_ip4, dst=choice(dst_if._remote_ip4_extend)) /
                 UDP(sport=1234, dport=1234) /
                 Raw(payload))
            info.data = p.copy()
            size = packet_sizes[(i // 2) % len(packet_sizes)]
            self.extend_packet(p, size)
            pkts.append(p)
        return pkts

    def verify_capture(self, dst_ip_if, src_ip_if, capture):
        last_info = dict()
        for i in self.interfaces:
            last_info[i.sw_if_index] = None

        dst_ip_sw_if_index = dst_ip_if.sw_if_index

        for packet in capture:
            ip = packet[IP]
            udp = packet[IP][UDP]
            payload_info = self.payload_to_info(str(packet[IP][UDP][Raw]))
            packet_index = payload_info.index

            self.assertEqual(payload_info.dst, dst_ip_sw_if_index)

            next_info = self.get_next_packet_info_for_interface2(
                payload_info.src, dst_ip_sw_if_index,
                last_info[payload_info.src])
            last_info[payload_info.src] = next_info
            self.assertTrue(next_info is not None)
            self.assertEqual(packet_index, next_info.index)
            saved_packet = next_info.data
            self.assertTrue(next_info is not None)

            # MAC: src, dst
            self.assertEqual(packet.src, dst_ip_if.local_mac)
            dst_mac_index = dst_ip_if._remote_ip4_extend.index(packet[IP].dst)
            self.assertEqual(packet.dst, dst_ip_if._remote_mac_extend[dst_mac_index])

            # IP: src, dst
            self.assertEqual(ip.src, src_ip_if.remote_ip4)
            self.assertEqual(ip.dst, saved_packet[IP].dst)
            self.assertIn(ip.dst, dst_ip_if._remote_ip4_extend)

            # UDP:
            self.assertEqual(udp.sport, saved_packet[UDP].sport)
            self.assertEqual(udp.dport, saved_packet[UDP].dport)

    @unittest.skip('Not finished yet')
    def test_ip4_irb_1(self):
        """ IPv4 IRB test

        Test scenario:
            l2 traffic from pg0 ends in pg1. vice versa
        """
        pass

    def test_ip4_irb_2(self):
        """ IPv4 IRB test

        Test scenario:
            ip traffic from pg2 interface must ends in both pg0 and pg1
            - arp entry present in loop0 interface for dst IP
            - no l2 entree configured, pg0 and pg1 are same
        """

        stream = self.create_stream(self.pg2, self.loop0, self.pg_if_packet_sizes)
        self.pg2.add_stream(stream)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rcvd1 = self.pg0.get_capture()
        rcvd2 = self.pg1.get_capture()

        self.verify_capture(self.loop0, self.pg2, rcvd1)
        self.verify_capture(self.loop0, self.pg2, rcvd2)

        self.assertListEqual(rcvd1.res, rcvd2.res)

    @unittest.skip('Not finished yet')
    def test_ip4_irb_3(self):
        """ IPv4 IRB test

        Test scenario:
            ip traffic from pg0 and pg1 ends on pg2
        """
        pass

    @unittest.skip('Not finished yet')
    def test_ip4_irb_4(self):
        """ IPv4 IRB test

        Test scenario:
            mac learned on pg0 and pg1, ip traffic ends only pg0 or pg1.
        """
        pass


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
