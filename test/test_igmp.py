#!/usr/bin/env python

import unittest
import socket

from framework import VppTestCase, VppTestRunner, running_extended_tests
from vpp_igmp import *

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
""" outdated scapy module!!! """
from scapy.contrib.igmpv3 import *
from scapy.contrib.igmp import *


class IGMPv3mr(IGMPv3):
    """ IGMPv3 Membership Report """
    fields_desc = [ByteEnumField("type", 0x22, IGMPv3.igmpv3types),
                   ByteField("code", 0),
                   XShortField("chksum", None),
                   ShortField("rsvd", 0),
                   ShortField("numgrp", 0)]


class TestIgmp(VppTestCase):
    """ IGMP Test Case """

    def setUp(self):
        super(TestIgmp, self).setUp()

        self.create_pg_interfaces(range(2))
        self.sg_list = []
        self.config_list = []

        self.ip_addr = []
        for pg in self.pg_interfaces:
            pg.admin_up()
            pg.config_ip4()
            pg.resolve_arp()

    def tearDown(self):
        for pg in self.pg_interfaces:
            self.vapi.igmp_clear_interface(pg.sw_if_index)
            pg.unconfig_ip4()
            pg.admin_down()
        super(TestIgmp, self).tearDown()

    def send_expect_nothing(self, ti, pkts, ri):
        ti.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        ri.assert_nothing_captured()

    def send_expect_query(self, ti, pkts):
        ti.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.sleep(61)
        capture = ti.get_capture(2)
        ip = capture[1][IP]
        self.assertEqual(ip.dst, "224.0.0.1")
        self.assertEqual(ip.proto, 2)
        """ TODO: fix IGMP versions, this can be v2 or v3 query... """
        igmp = capture[1][IGMP]
        self.assertEqual(igmp.type, 0x11)
        self.assertEqual(igmp.gaddr, "0.0.0.0")

    def test_igmp_parse_report(self):
        """ IGMP parse Membership Report """
        eth = Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
        ip = IP(src=self.pg0.remote_ip4, dst='224.0.0.22', proto=2)
        igmp = IGMPv3mr()
        igmp.type = 0x22
        igmp.numgrp = 1
        g1 = IGMPv3gr()
        g1.rtype = 3
        g1.maddr = "224.1.1.1"
        g1.srcaddrs = ["10.1.1.1"]

        self.send_expect_nothing(self.pg0, eth / ip / igmp / g1, self.pg1)

        dump = self.vapi.igmp_dump()
        self.assertEqual(len(dump), 1)
        self.assertEqual(dump[0].sw_if_index, self.pg0.sw_if_index)
        self.assertEqual(
            dump[0].gaddr,
            socket.inet_pton(
                socket.AF_INET,
                "224.1.1.1"))
        self.assertEqual(
            dump[0].saddr,
            socket.inet_pton(
                socket.AF_INET,
                "10.1.1.1"))

    @unittest.skipUnless(running_extended_tests(), "part of extended tests")
    def test_igmp_send_query(self):
        """ IGMP send General Query """
        eth = Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
        ip = IP(src=self.pg0.remote_ip4, dst='224.0.0.22', proto=2)
        igmp = IGMPv3mr()
        igmp.type = 0x22
        igmp.numgrp = 1
        g1 = IGMPv3gr()
        g1.rtype = 3
        g1.maddr = "224.1.1.1"
        g1.srcaddrs = ["10.1.1.1"]

        self.send_expect_query(self.pg0, eth / ip / igmp / g1)

    def test_igmp_parse_query(self):
        """ IGMP parse General Query """
        self.config_list.append(
            VppIgmpConfig(
                self, self.pg0.sw_if_index, IgmpSG(
                    socket.inet_pton(
                        socket.AF_INET, "10.1.1.1"), socket.inet_pton(
                        socket.AF_INET, "224.1.1.1"))))
        self.config_list[0].add_vpp_config()

        self.assertTrue(self.vapi.igmp_dump(self.pg0.sw_if_index))

        eth = Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
        ip = IP(src=self.pg0.remote_ip4, dst='224.0.0.1', proto=2)
        igmp = IGMPv3()
        igmp.type = 0x11
        igmp.mrcode = 100
        igmp.gaddr = "0.0.0.0"

        self.pg0.add_stream(eth / ip / igmp)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.sleep(10)
        capture = self.pg0.get_capture(1)
        self.assertEqual(capture[0][IGMP].type, 0x22)

    def test_igmp_config(self):
        """ IGMP configure (S,G)s """
        for pg in self.pg_interfaces:
            self.sg_list.append(IgmpSG(socket.inet_pton(
                socket.AF_INET, "10.1.1.%d" % pg._sw_if_index),
                socket.inet_pton(socket.AF_INET, "224.1.1.1")))

        for pg in self.pg_interfaces:
            self.config_list.append(
                VppIgmpConfig(
                    self,
                    pg._sw_if_index,
                    self.sg_list))
            self.config_list[-1].add_vpp_config()

        self.sleep(2)

        for config in self.config_list:
            dump = self.vapi.igmp_dump(config.sw_if_index)
            self.assertTrue(dump)
            self.assertEqual(len(dump), len(config.sg_list))
            for idx, e in enumerate(dump):
                self.assertEqual(e.sw_if_index, config.sw_if_index)
                self.assertEqual(e.saddr, config.sg_list[idx].saddr)
                self.assertEqual(e.gaddr, config.sg_list[idx].gaddr)

        for config in self.config_list:
            config.remove_vpp_config()

        dump = self.vapi.igmp_dump()
        self.assertFalse(dump)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
