#!/usr/bin/env python
import unittest
import socket

import ipaddress
from scapy.packet import Raw
from scapy.layers.inet import IP, UDP, Ether
from lisp import LISP_GPE_Header

from util import ppp
from framework import VppTestCase, VppTestRunner


class TestLisp4o4(VppTestCase):
    """ Basic LISP test (IP4 over IP4) """

    @classmethod
    def setUpClass(cls):
        super(TestLisp4o4, cls).setUpClass()
        cls.create_pg_interfaces(range(2))  # create pg0 and pg1
        for i in cls.pg_interfaces:
            i.admin_up()  # put the interface upsrc_if
            i.config_ip4()  # configure IPv4 address on the interface
            i.resolve_arp()  # resolve ARP, so that we know VPP MAC

    def configure_4o4(self):
        """ Configure VPP for basic ip4 over ip4 test scenario """

        self.rloc = self.pg1.remote_ip4n
        self.seid = self.pg0.remote_ip4
        self.deid_net = ipaddress.ip_network(u'10.10.10.0/24')
        self.deid = str(next(self.deid_net.hosts()))
        self.seid_len = 24
        self.deid_len = 24

        self.vapi.lisp_enable_disable(is_enabled=1)
        self.vapi.lisp_locator_set(ls_name="ls1")
        self.vapi.lisp_locator(ls_name="ls1",
                               sw_if_index=self.pg1.sw_if_index)
        self.vapi.lisp_local_mapping(ls_name="ls1",
                                     eid_type=0,
                                     eid=self.seid,
                                     prefix_len=self.seid_len)
        rlocs = [
            {
                "is_ip4": 1,
                "priority": 1,
                "weight": 1,
                "addr": self.rloc
            }
        ]
        self.vapi.lisp_remote_mapping(eid_type=0,
                                      eid=self.deid,
                                      eid_prefix_len=self.deid_len,
                                      rloc_num=len(rlocs),
                                      vni=0,
                                      rlocs=rlocs)
        self.vapi.lisp_adjacency(leid=self.seid,
                                 reid=self.deid,
                                 leid_len=self.seid_len,
                                 reid_len=self.deid_len,
                                 # EIDs are ipv4 prefixes
                                 eid_type=0)

    def verify_capture(self, src_loc, dst_loc, capture):
        """
        Verify captured packet

        :param src_loc: source locator address
        :param dst_loc: destination locator address
        :param capture: list of captured packets
        """
        self.assertEqual(len(capture), 1, "Unexpected number of packets!" +
                         "Expected 1 but {} received".format(len(capture)))
        packet = capture[0]
        try:
            ip_hdr = packet[IP]
            # assert the values match
            self.assertEqual(ip_hdr.src, src_loc, "IP source address")
            self.assertEqual(ip_hdr.dst, dst_loc,
                             "IP destination address")
            gpe_hdr = packet[LISP_GPE_Header]
            self.assertEqual(gpe_hdr.next_proto, 1,
                             "next_proto is not ipv4!")
            ih = gpe_hdr[IP]
            self.assertEqual(ih.src, self.seid, "unexpected source EID!")
            self.assertEqual(ih.dst, self.deid, "unexpected dest EID!")
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", packet))
            raise

    def create_packet(self, src_if, dst_if):
        """
        Create IPv4 packet

        param: src_if
        param: dst_if
        """
        info = self.create_packet_info(src_if, dst_if)
        payload = self.info_to_payload(info)
        lisp_ecm = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                    IP(src=src_if.remote_ip4, dst=self.deid) /
                    Raw(payload))
        info.data = lisp_ecm.copy()
        return lisp_ecm

    def test_lisp_4o4(self):
        """Test case for basic ip4 over ip4 encapsulation"""
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
        # verify capture
        self.verify_capture(self.pg1.local_ip4, self.pg1.remote_ip4, capture)
        self.pg0.assert_nothing_captured()


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
