#!/usr/bin/env python

import unittest
import socket
from logging import *

from framework import VppTestCase, VppTestRunner
from vpp_sub_interface import VppSubInterface, VppDot1QSubint, VppDot1ADSubint

from scapy.packet import Raw
from scapy.layers.l2 import Ether, Dot1Q, ARP
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import ICMPv6ND_NS, IPv6, UDP
from scapy.contrib.mpls import MPLS

class TestMPLS(VppTestCase):
    """ MPLS Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestMPLS, cls).setUpClass()

    def setUp(self):
        super(TestMPLS, self).setUp()

        # create 2 pg interfaces
        self.create_pg_interfaces(range(3))

        # setup both interfaces
        # assign them different tables.
        table_id = 0

        for i in self.pg_interfaces:
            i.admin_up()
            i.set_table_ip4(table_id)
            i.set_table_ip6(table_id)
            i.config_ip4()
            i.config_ip6()
            i.enable_mpls()
            i.resolve_arp()
            i.resolve_ndp()
            table_id += 1

    def tearDown(self):
        super(TestMPLS, self).tearDown()

    def create_stream_ip4(self, src_if, mpls_label, mpls_ttl):
        pkts = []
        for i in range(0, 257):
            info = self.create_packet_info(src_if.sw_if_index,
                                           src_if.sw_if_index)
            payload = self.info_to_payload(info)
            p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                 MPLS(label=mpls_label, ttl=mpls_ttl) /
                 IP(src=src_if.remote_ip4, dst=src_if.remote_ip4) /
                 UDP(sport=1234, dport=1234) /
                 Raw(payload))
            info.data = p.copy()
            pkts.append(p)
        return pkts

    def create_stream_ip6(self, src_if, mpls_label, mpls_ttl):
        pkts = []
        for i in range(0, 257):
            info = self.create_packet_info(src_if.sw_if_index,
                                           src_if.sw_if_index)
            payload = self.info_to_payload(info)
            p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                 MPLS(label=mpls_label, ttl=mpls_ttl) /
                 IPv6(src=src_if.remote_ip6, dst=src_if.remote_ip6) /
                 UDP(sport=1234, dport=1234) /
                 Raw(payload))
            info.data = p.copy()
            pkts.append(p)
        return pkts

    def verify_capture_ip4(self, src_if, capture, sent):
        try:
            self.assertEqual(len(capture), len(sent))

            for i in range(len(capture)):
                tx = sent[i]
                rx = capture[i]

                # the rx'd packet has the MPLS label popped
                eth = rx[Ether];
                self.assertEqual(eth.type, 0x800);

                tx_ip = tx[IP]
                rx_ip = rx[IP]

                self.assertEqual(rx_ip.src, tx_ip.src)
                self.assertEqual(rx_ip.dst, tx_ip.dst)
                # IP processing post pop has decremented the TTL
                self.assertEqual(rx_ip.ttl+1, tx_ip.ttl)

        except:
            raise;

    def verify_capture_ip6(self, src_if, capture, sent):
        try:
            self.assertEqual(len(capture), len(sent))

            for i in range(len(capture)):
                tx = sent[i]
                rx = capture[i]

                # the rx'd packet has the MPLS label popped
                eth = rx[Ether];
                self.assertEqual(eth.type, 0x86DD);

                tx_ip = tx[IPv6]
                rx_ip = rx[IPv6]

                self.assertEqual(rx_ip.src, tx_ip.src)
                self.assertEqual(rx_ip.dst, tx_ip.dst)
                # IP processing post pop has decremented the TTL
                self.assertEqual(rx_ip.hlim + 1, tx_ip.hlim)

        except:
            raise;


    def test_v4_exp_null(self):
        """ MPLS V4 Explicit NULL test """

        #
        # The first test case has an MPLS TTL of 0
        # all packet should be dropped
        #
        tx = self.create_stream_ip4(self.pg0, 0, 0)
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg0.get_capture()

        try:
            self.assertEqual(0, len(rx));
        except:
            error("MPLS TTL=0 packets forwarded")
            error(packet.show())
            raise

        #
        # a stream with a non-zero MPLS TTL
        # PG0 is in the default table
        #
        self.vapi.cli("clear trace")
        tx = self.create_stream_ip4(self.pg0, 0, 2)
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg0.get_capture()
        self.verify_capture_ip4(self.pg0, rx, tx)

        #
        # a stream with a non-zero MPLS TTL
        # PG1 is in table 1
        # we are ensuring the post-pop lookup occurs in the VRF table
        #
        self.vapi.cli("clear trace")
        tx = self.create_stream_ip4(self.pg1, 0, 2)
        self.pg1.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg1.get_capture()
        self.verify_capture_ip4(self.pg0, rx, tx)

    def test_v6_exp_null(self):
        """ MPLS V6 Explicit NULL test """

        #
        # a stream with a non-zero MPLS TTL
        # PG0 is in the default table
        #
        self.vapi.cli("clear trace")
        tx = self.create_stream_ip6(self.pg0, 2, 2)
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg0.get_capture()
        self.verify_capture_ip6(self.pg0, rx, tx)

        #
        # a stream with a non-zero MPLS TTL
        # PG1 is in table 1
        # we are ensuring the post-pop lookup occurs in the VRF table
        #
        self.vapi.cli("clear trace")
        tx = self.create_stream_ip6(self.pg1, 2, 2)
        self.pg1.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg1.get_capture()
        self.verify_capture_ip6(self.pg0, rx, tx)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
