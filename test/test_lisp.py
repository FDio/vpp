#!/usr/bin/env python
import random
import socket
import unittest

from framework import VppTestCase, VppTestRunner
from vpp_sub_interface import VppSubInterface, VppDot1QSubint, VppDot1ADSubint

from scapy.packet import Raw
from scapy.layers.l2 import Ether, Dot1Q
from scapy.layers.inet import IP, UDP, Raw
from util import ppp


class TestLisp4o4(VppTestCase):
    """ Basic LISP test (IP4 over IP4) """

    @classmethod
    def setUpClass(self):
     super(TestLisp4o4, self).setUpClass()
     self.create_pg_interfaces(range(2))  #  create pg0 and pg1
     for i in self.pg_interfaces:
         i.admin_up()  # put the interface up
         i.config_ip4()  # configure IPv4 address on the interface
         i.resolve_arp()  # resolve ARP, so that we know VPP MAC

    def configure_4o4(self):
        self.deid = '172.16.3.3'
        self.vapi.cli("lisp enable")
        self.vapi.cli("lisp locator-set add ls1 iface pg1 p 1 w 1")
        self.vapi.cli("lisp eid-table eid 172.16.1.0/24 locator-set ls1")
        self.vapi.cli("lisp remote-mapping eid 172.16.3.0/24 rloc 172.16.2.2")
        self.vapi.cli("lisp adjacency leid 172.16.1.0/24 reid 172.16.3.0/24")

    def verify_capture(self, src_if, dst_if, capture):
        packet_info = None
        for packet in capture:
            try:
                ip = packet[IP]
                # assert the values match
                self.assert_equal(ip.src, self.pg1.local_ip4,
                                  "IP source address")
                self.assert_equal(ip.dst, self.pg1.remote_ip4,
                                  "IP destination address")
                lisp_data = packet[Raw]
                self.logger.info(ppp("LISP data", lisp_data))
                lisp_header = lisp_data.load[:8]

                self.assertEqual(lisp_header, '\x04\x00\x00\x01\x00\x00\x00\x00')
            except:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise

    def create_packet(self, src_if, dst_if):
        info = self.create_packet_info(src_if, dst_if)
        payload = self.info_to_payload(info)
        p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                IP(src=src_if.remote_ip4, dst=self.deid) /
                Raw(payload))
        info.data = p.copy()
        return p

    def test_lisp_4o4(self):
        self.configure_4o4()

        # create packet
        packet = self.create_packet(self.pg0, self.pg1)

        # add the stream to the source interface
        self.pg0.add_stream(packet)
        # enable capture on both interfaces
        self.pg0.enable_capture()
        self.pg1.enable_capture()
        # start the packet generator
        self.pg_start()
        capture = self.pg1.get_capture()
        self.pg0.assert_nothing_captured()
        # verify capture
        self.verify_capture(self.pg0, self.pg1, capture)
