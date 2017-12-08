#!/usr/bin/env python

import unittest
import socket

from framework import VppTestCase, VppTestRunner, running_extended_tests
from vpp_igmp import *

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.contrib.igmpv3 import *
from scapy.contrib.igmp import *


def checkIGMPv3():
    try:
        tmp = IGMPv3()
        tmp = IGMPv3mr()
        tmp = IGMPv3gr()
        tmp = IGMPv3mq()
    except NameError:
        return False
    return True


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

    def send(self, ti, pkts):
        ti.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

    @unittest.skipUnless(checkIGMPv3(), "missing scapy igmpv3 implementation")
    def test_igmp_parse_report(self):
        """ IGMP parse Membership Report """
        eth = Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
        ip = IP(src=self.pg0.remote_ip4, dst='224.0.0.22', proto=2, tos=0xc0)
        igmp = IGMPv3()
        igmp.type = 0x22
        mr = IGMPv3mr()
        mr.numgrp = 1
        g1 = IGMPv3gr()
        g1.rtype = 3
        g1.maddr = "224.1.1.1"
        g1.srcaddrs = ["10.1.1.1"]

        self.send(self.pg0, eth / ip / igmp / mr / g1)

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

        eth = Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
        ip = IP(src=self.pg0.remote_ip4, dst='224.0.0.22', proto=2, tos=0xc0)
        igmp = IGMPv3()
        igmp.type = 0x22
        mr = IGMPv3mr()
        mr.numgrp = 1
        g1 = IGMPv3gr()
        g1.rtype = 4
        g1.maddr = "224.1.1.1"
        g1.srcaddrs = ["10.1.1.1"]

        self.send(self.pg0, eth / ip / igmp / mr / g1)

        dump = self.vapi.igmp_dump()
        self.assertFalse(dump)

        eth = Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
        ip = IP(src=self.pg0.remote_ip4, dst='224.0.0.22', proto=2, tos=0xc0)
        igmp = IGMPv3()
        igmp.type = 0x22
        mr = IGMPv3mr()
        mr.numgrp = 1
        g1 = IGMPv3gr()
        g1.rtype = 3
        g1.maddr = "224.1.1.1"
        g1.srcaddrs = ["10.1.1.1"]

        self.send(self.pg0, eth / ip / igmp / mr / g1)

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

        eth = Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
        ip = IP(src=self.pg0.remote_ip4, dst='224.0.0.22', proto=2, tos=0xc0)
        igmp = IGMPv3()
        igmp.type = 0x22
        mr = IGMPv3mr()
        mr.numgrp = 1
        g1 = IGMPv3gr()
        g1.rtype = 6
        g1.maddr = "224.1.1.1"
        g1.srcaddrs = ["10.1.1.1"]

        self.send(self.pg0, eth / ip / igmp / mr / g1)

        dump = self.vapi.igmp_dump()
        self.assertFalse(dump)

    @unittest.skipUnless(checkIGMPv3(), "missing scapy igmpv3 implementation")
    def test_igmp_send_query(self):
        """ IGMP send General Query """
        eth = Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
        ip = IP(src=self.pg0.remote_ip4, dst='224.0.0.22', proto=2, tos=0xc0)
        igmp = IGMPv3()
        igmp.type = 0x22
        mr = IGMPv3mr()
        mr.numgrp = 1
        g1 = IGMPv3gr()
        g1.rtype = 3
        g1.maddr = "224.1.1.1"
        g1.srcaddrs = ["10.1.1.1"]

        self.pg0.add_stream(eth / ip / igmp / mr / g1)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.sleep(61)
        capture = self.pg0.get_capture(2)
        ip = capture[1][IP]
        self.assertEqual(ip.dst, "224.0.0.1")
        self.assertEqual(ip.proto, 2)
        igmp = capture[1][IGMPv3]
        self.assertEqual(igmp.type, 0x11)
        self.assertEqual(igmp.gaddr, "0.0.0.0")

        self.sleep(10)
        self.assertFalse(self.vapi.igmp_dump())

    @unittest.skipUnless(checkIGMPv3(), "missing scapy igmpv3 implementation")
    def test_igmp_src_exp(self):
        """ IGMP per source timer """
        eth = Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
        ip = IP(src=self.pg0.remote_ip4, dst='224.0.0.22', proto=2, tos=0xc0)
        igmp = IGMPv3()
        igmp.type = 0x22
        mr = IGMPv3mr()
        mr.numgrp = 1
        g1 = IGMPv3gr()
        g1.rtype = 3
        g1.maddr = "224.1.1.1"
        g1.srcaddrs = ["10.1.1.1"]

        self.pg0.add_stream(eth / ip / igmp / mr / g1)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.sleep(61)
        capture = self.pg0.get_capture(2)
        ip = capture[1][IP]
        self.assertEqual(ip.dst, "224.0.0.1")
        self.assertEqual(ip.proto, 2)
        igmp = capture[1][IGMPv3]
        self.assertEqual(igmp.type, 0x11)
        self.assertEqual(igmp.gaddr, "0.0.0.0")

        eth = Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
        ip = IP(src=self.pg0.remote_ip4, dst='224.0.0.22', proto=2, tos=0xc0)
        igmp = IGMPv3()
        igmp.type = 0x22
        mr = IGMPv3mr()
        mr.numgrp = 1
        g1 = IGMPv3gr()
        g1.rtype = 2
        g1.maddr = "224.1.1.1"
        g1.srcaddrs = ["10.1.1.2"]

        self.pg0.add_stream(eth / ip / igmp / mr / g1)
        self.sleep(61)

        eth = Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
        ip = IP(src=self.pg0.remote_ip4, dst='224.0.0.22', proto=2, tos=0xc0)
        igmp = IGMPv3()
        igmp.type = 0x22
        mr = IGMPv3mr()
        mr.numgrp = 1
        g1 = IGMPv3gr()
        g1.rtype = 2
        g1.maddr = "224.1.1.1"
        g1.srcaddrs = ["10.1.1.2"]

        self.pg0.add_stream(eth / ip / igmp / mr / g1)
        self.sleep(61)

        self.assertFalse(self.vapi.igmp_dump())

    @unittest.skipUnless(checkIGMPv3(), "missing scapy igmpv3 implementation")
    def test_igmp_query_resp(self):
        """ IGMP General Query response """
        self.config_list.append(
            VppIgmpConfig(
                self, self.pg0.sw_if_index, IgmpSG(
                    socket.inet_pton(
                        socket.AF_INET, "10.1.1.1"), socket.inet_pton(
                        socket.AF_INET, "224.1.1.1"))))
        self.config_list[0].add_vpp_config()

        self.assertTrue(self.vapi.igmp_dump(self.pg0.sw_if_index))

        eth = Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
        ip = IP(src=self.pg0.remote_ip4, dst='224.0.0.1', tos=0xc0, proto=2)
        igmp = IGMPv3()
        igmp.type = 0x11
        igmp.mrcode = 100
        mq = IGMPv3mq()
        mq.gaddr = "0.0.0.0"

        self.pg0.add_stream(eth / ip / igmp / mq)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.sleep(10)
        capture = self.pg0.get_capture(1)
        self.assertEqual(capture[0][IGMPv3].type, 0x22)
        self.assertEqual(capture[0][IGMPv3mr].numgrp, 1)
        self.assertEqual(capture[0][IGMPv3gr].rtype, 1)
        self.assertEqual(capture[0][IGMPv3gr].numsrc, 1)
        self.assertEqual(capture[0][IGMPv3gr].maddr, "224.1.1.1")
        self.assertEqual(len(capture[0][IGMPv3gr].srcaddrs), 1)
        self.assertEqual(capture[0][IGMPv3gr].srcaddrs[0], "10.1.1.1")

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
