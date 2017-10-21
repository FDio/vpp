#!/usr/bin/env python

import unittest
import socket

from framework import VppTestCase, VppTestRunner
from vpp_ip_route import VppIpRoute, VppRoutePath, VppMplsRoute, VppMplsIpBind, VppMplsTable
from vpp_bier import *

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.contrib.mpls import MPLS
from scapy.contrib.bier import *


class TestBFIB(VppTestCase):
    """ BIER FIB Test Case """

    def test_bfib(self):
        """ BFIB Unit Tests """
        error = self.vapi.cli("test bier")

        if error:
            self.logger.critical(error)
        self.assertEqual(error.find("Failed"), -1)


class TestBIER(VppTestCase):
    """ BIER Test Case """

    def setUp(self):
        super(TestBIER, self).setUp()

        # create 2 pg interfaces
        self.create_pg_interfaces(range(2))

        # create the default MPLS table
        self.tables = []
        tbl = VppMplsTable(self, 0)
        tbl.add_vpp_config()
        self.tables.append(tbl)

        # setup both interfaces
        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()
            i.enable_mpls()

    def tearDown(self):
        for i in self.pg_interfaces:
            i.disable_mpls()
            i.unconfig_ip4()
            i.admin_down()
        super(TestBIER, self).tearDown()

    def send_and_assert_no_replies(self, intf, pkts, remark):
        intf.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        for i in self.pg_interfaces:
            i.assert_nothing_captured(remark=remark)

    def test_bier_midpoint(self):
        """BIER midpoint"""

        #
        # Add a BIER table for sub-domain 0, set 0, and BSL 256
        #
        bti = VppBIERTable_ID(0, 0, BIERLength.BIER_LEN_256)
        bt = VppBIERTable(self, bti, 77)
        bt.add_vpp_config()

        #
        # A packet with no bits set gets dropped
        #
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             MPLS(label=77, ttl=255) /
             BIER(length=BIERLength.BIER_LEN_256,
                  BitString=chr(0)*64) /
             MPLS(label=99, ttl=255) /
             IPv6(src=self.pg0.remote_ip6, dst=self.pg0.remote_ip6) /
             UDP(sport=1234, dport=1234) /
             Raw())
        pkts = [p]

        self.send_and_assert_no_replies(self.pg0, pkts,
                                        "Empty Bit-String")

        #
        # Add a BIER route for each bit-position in the table via a different
        # next-hop. Testing whether the BIER walk and replicate forwarding
        # function works for all bit posisitons.
        #
        nh_routes = []
        bier_routes = []
        for i in range(1, 256):
            nh = "10.0.%d.%d" % (i / 255, i % 255)
            nh_routes.append(VppIpRoute(self, nh, 32,
                                        [VppRoutePath(self.pg1.remote_ip4,
                                                      self.pg1.sw_if_index,
                                                      labels=[2000+i])]))
            nh_routes[-1].add_vpp_config()

            bier_routes.append(VppBIERRoute(self, 0, 0,
                                            BIERLength.BIER_LEN_256,
                                            i, nh, 100+i))
            bier_routes[-1].add_vpp_config()

        #
        # A packet with all bits set gets spat out to BP:1
        #
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             MPLS(label=77, ttl=255) /
             BIER(length=BIERLength.BIER_LEN_256) /
             MPLS(label=99, ttl=255) /
             IPv6(src=self.pg0.remote_ip6, dst=self.pg0.remote_ip6) /
             UDP(sport=1234, dport=1234) /
             Raw())
        pkts = [p]

        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg1.get_capture(255)

        for rxp in rx:
            #
            # The packets are not required to be sent in bit-position order
            # when we setup the routes above we used the bit-position to
            # construct the out-label. so use that here to determine the BP
            #
            olabel = rxp[MPLS]
            bp = olabel.label - 2000

            blabel = olabel[MPLS].payload
            self.assertEqual(blabel.label, 100+bp)

            bier_hdr = blabel[MPLS].payload

            self.assertEqual(bier_hdr.id, 5)
            self.assertEqual(bier_hdr.version, 0)
            self.assertEqual(bier_hdr.length, BIERLength.BIER_LEN_256)
            self.assertEqual(bier_hdr.entropy, 0)
            self.assertEqual(bier_hdr.OAM, 0)
            self.assertEqual(bier_hdr.RSV, 0)
            self.assertEqual(bier_hdr.DSCP, 0)
            self.assertEqual(bier_hdr.Proto, 2)

            # The bit-string should consist only of the BP given by i.
            i = 0
            bitstring = ""
            bpi = bp - 1
            while (i < bpi/8):
                bitstring = chr(0) + bitstring
                i += 1
            bitstring = chr(1 << bpi % 8) + bitstring

            while len(bitstring) < 32:
                bitstring = chr(0) + bitstring

            self.assertEqual(len(bitstring), len(bier_hdr.BitString))
            self.assertEqual(bitstring, bier_hdr.BitString)

        #
        # Cleanup
        #
        for br in bier_routes:
            br.remove_vpp_config()
        for nh in nh_routes:
            nh.remove_vpp_config()
        bt.remove_vpp_config()

    def test_bier_head(self):
        """BIER head"""

        #
        # Add a BIER table for sub-domain 0, set 0, and BSL 256
        #
        bt = VppBIERTable(self, 0, 0, BIERLength.BIER_LEN_256, 77)
        bt.add_vpp_config()

        #
        # 2 bit positions via two next hops
        #
        ip_route_1 = VppIpRoute(self, nh, 32,
                                [VppRoutePath(self.pg1.remote_ip4,
                                              self.pg1.sw_if_index,
                                              labels=[2001])])
        ip_route_2 = VppIpRoute(self, nh, 32,
                                [VppRoutePath(self.pg1.remote_ip4,
                                              self.pg1.sw_if_index,
                                              labels=[2002])])
        ip_route_1.add_vpp_config()
        ip_route_2.add_vpp_config()

        bier_route_1 = VppBIERRoute(self, 0, 0,
                                    BIERLength.BIER_LEN_256,
                                    1, nh, 101))
        bier_route_2 = VppBIERRoute(self, 0, 0,
                                    BIERLength.BIER_LEN_256,
                                    2, nh, 102))
        bier_route_1.add_vpp_config()
        bier_route_2.add_vpp_config()

        #
        # An imposition object with both bit-positions set
        #

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
