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

    def test_igmp_parse_report(self):
        """ IGMP parse Membership Report """

        #
        # VPP acts as a router
        #
        self.vapi.want_igmp_events(1)

        # hos sends join IGMP 'join'
        p_join = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                  IP(src=self.pg0.remote_ip4, dst='224.0.0.22', tos=0xc0) /
                  IGMPv3() /
                  IGMPv3mr(numgrp=1) /
                  IGMPv3gr(rtype=3, maddr="224.1.1.1", srcaddrs=["10.1.1.1"]))

        self.send(self.pg0, p_join)

        # search for the corresponding state created in VPP
        dump = self.vapi.igmp_dump()
        self.assertEqual(len(dump), 1)
        self.assertEqual(dump[0].sw_if_index, self.pg0.sw_if_index)
        self.assertEqual(dump[0].gaddr,
                         socket.inet_pton(socket.AF_INET,
                                          "224.1.1.1"))
        self.assertEqual(dump[0].saddr,
                         socket.inet_pton(socket.AF_INET,
                                          "10.1.1.1"))

        # VPP sends a notification that a new group has been joined
        ev = self.vapi.wait_for_event(2, "igmp_event")

        self.assertEqual(ev.saddr,
                         socket.inet_pton(socket.AF_INET,
                                          "10.1.1.1"))
        self.assertEqual(ev.gaddr,
                         socket.inet_pton(socket.AF_INET,
                                          "224.1.1.1"))
        self.assertEqual(ev.is_join, 1)

        # host sends IGMP leave
        p_leave = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                   IP(src=self.pg0.remote_ip4, dst='224.0.0.22', tos=0xc0) /
                   IGMPv3() /
                   IGMPv3mr(numgrp=1) /
                   IGMPv3gr(rtype=4, maddr="224.1.1.1", srcaddrs=["10.1.1.1"]))

        self.send(self.pg0, p_leave)

        # VPP sends a notification that a new group has been left
        ev = self.vapi.wait_for_event(2, "igmp_event")

        self.assertEqual(ev.saddr,
                         socket.inet_pton(socket.AF_INET,
                                          "10.1.1.1"))
        self.assertEqual(ev.gaddr,
                         socket.inet_pton(socket.AF_INET,
                                          "224.1.1.1"))
        self.assertEqual(ev.is_join, 0)

        # state gone
        dump = self.vapi.igmp_dump()
        self.assertFalse(dump)

        # resend the join
        self.send(self.pg0, p_join)
        dump = self.vapi.igmp_dump()
        self.assertEqual(len(dump), 1)
        self.assertEqual(dump[0].sw_if_index, self.pg0.sw_if_index)
        self.assertEqual(dump[0].gaddr,
                         socket.inet_pton(socket.AF_INET,
                                          "224.1.1.1"))
        self.assertEqual(dump[0].saddr,
                         socket.inet_pton(socket.AF_INET,
                                          "10.1.1.1"))

        # IGMP block
        p_block = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                   IP(src=self.pg0.remote_ip4, dst='224.0.0.22', tos=0xc0) /
                   IGMPv3() /
                   IGMPv3mr(numgrp=1) /
                   IGMPv3gr(rtype=6, maddr="224.1.1.1", srcaddrs=["10.1.1.1"]))

        self.send(self.pg0, p_block)

        dump = self.vapi.igmp_dump()
        self.assertFalse(dump)

    def verify_general_query(self, p):
        ip = p[IP]
        self.assertEqual(ip.dst, "224.0.0.1")
        self.assertEqual(ip.proto, 2)
        igmp = p[IGMPv3]
        self.assertEqual(igmp.type, 0x11)
        self.assertEqual(igmp.gaddr, "0.0.0.0")

    def test_igmp_send_query(self):
        """ IGMP send General Query """

        #
        # VPP acts as a router.
        #   Send a membership report so VPP builds state
        #
        p_mr = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                IP(src=self.pg0.remote_ip4, dst='224.0.0.22') /
                IGMPv3() /
                IGMPv3mr(numgrp=1) /
                IGMPv3gr(rtype=3, maddr="224.1.1.1", srcaddrs=["10.1.1.1"]))

        self.send(self.pg0, p_mr)
        self.logger.info(self.vapi.cli("sh igmp config"))

        #
        # wait for VPP to send out the General Query
        #
        capture = self.pg0.get_capture(1, timeout=61)

        self.verify_general_query(capture[0])

        #
        # the state will expire in 10 more seconds
        #
        self.sleep(10)
        self.assertFalse(self.vapi.igmp_dump())

    @unittest.skipUnless(running_extended_tests(), "part of extended tests")
    def test_igmp_src_exp(self):
        """ IGMP per source timer """

        #
        # VPP Acts as a router
        #

        # Host join for (10.1.1.1,224.1.1.1)
        p_mr1 = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                 IP(src=self.pg0.remote_ip4, dst='224.0.0.22') /
                 IGMPv3() /
                 IGMPv3mr(numgrp=1) /
                 IGMPv3gr(rtype=3, maddr="224.1.1.1", srcaddrs=["10.1.1.1"]))

        self.send(self.pg0, p_mr1)

        # VPP (router) sends General Query
        capture = self.pg0.get_capture(1, timeout=61)

        self.verify_general_query(capture[0])

        # host join for same G and another S: (10.1.1.2,224.1.1.1)
        # therefore leaving (10.1.1.1,224.1.1.1)
        p_mr2 = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                 IP(src=self.pg0.remote_ip4, dst='224.0.0.22') /
                 IGMPv3() /
                 IGMPv3mr(numgrp=1) /
                 IGMPv3gr(rtype=2, maddr="224.1.1.1", srcaddrs=["10.1.1.2"]))

        self.send(self.pg0, p_mr2)

        # wait for VPP to send general query
        capture = self.pg0.get_capture(1, timeout=61)
        self.verify_general_query(capture[0])

        # host leaves (10.1.1.2,224.1.1.1)
        p_l = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
               IP(src=self.pg0.remote_ip4, dst='224.0.0.22') /
               IGMPv3() /
               IGMPv3mr(numgrp=1) /
               IGMPv3gr(rtype=2, maddr="224.1.1.1", srcaddrs=["10.1.1.2"]))

        self.send(self.pg0, p_l)

        # FIXME BUG
        p_l = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
               IP(src=self.pg0.remote_ip4, dst='224.0.0.22') /
               IGMPv3() /
               IGMPv3mr(numgrp=1) /
               IGMPv3gr(rtype=2, maddr="224.1.1.1", srcaddrs=["10.1.1.1"]))
        self.send(self.pg0, p_l)

        #
        # host has left all groups, no state left.
        #
        self.sleep(10)
        self.logger.error(self.vapi.cli("sh igmp config"))
        self.assertFalse(self.vapi.igmp_dump())

    def test_igmp_query_resp(self):
        """ IGMP General Query response """

        #
        # VPP acting as a host.
        #  Add a listener in VPP for (10.1.1.1,244.1.1.1)
        #
        self.config_list.append(
            VppIgmpConfig(
                self, self.pg0.sw_if_index, IgmpSG(
                    socket.inet_pton(
                        socket.AF_INET, "10.1.1.1"), socket.inet_pton(
                        socket.AF_INET, "224.1.1.1"))))
        self.config_list[0].add_vpp_config()

        # verify state exists
        self.assertTrue(self.vapi.igmp_dump(self.pg0.sw_if_index))

        #
        # Send a general query (from a router)
        #
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=self.pg0.remote_ip4, dst='224.0.0.1', tos=0xc0) /
             IGMPv3(type=0x11, mrcode=100) /
             IGMPv3mq(gaddr="0.0.0.0"))

        self.send(self.pg0, p)

        #
        # expect VPP to respond with a membership report for the
        # (10.1.1.1, 224.1.1.1) state
        #
        capture = self.pg0.get_capture(1, timeout=10)

        self.assertEqual(capture[0][IGMPv3].type, 0x22)
        self.assertEqual(capture[0][IGMPv3mr].numgrp, 1)
        self.assertEqual(capture[0][IGMPv3gr].rtype, 1)
        self.assertEqual(capture[0][IGMPv3gr].numsrc, 1)
        self.assertEqual(capture[0][IGMPv3gr].maddr, "224.1.1.1")
        self.assertEqual(len(capture[0][IGMPv3gr].srcaddrs), 1)
        self.assertEqual(capture[0][IGMPv3gr].srcaddrs[0], "10.1.1.1")

    def test_igmp_listen(self):
        """ IGMP listen (S,G)s """

        #
        # VPP acts as a host
        #  Add IGMP group state to multiple interfaces and validate its
        #  presence
        #
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

        for config in self.config_list:
            cfg_dump = config.query_vpp_config()
            self.assertTrue(cfg_dump)
            self.assertEqual(cfg_dump[0].sw_if_index, config.sw_if_index)
            self.assertTrue(
                cfg_dump[0].flags, IgmpConfigFlags.CLI_API_CONFIGURED.value)
            dump = config.query_sg_config()
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


class TestIgmpProxy(VppTestCase):

    """ IGMP Proxy Test Case """

    def setUp(self):
        super(TestIgmpProxy, self).setUp()

        self.create_pg_interfaces(range(2))

        for pg in self.pg_interfaces:
            pg.admin_up()
            pg.config_ip4()
            pg.resolve_arp()

    def tearDown(self):
        for pg in self.pg_interfaces:
            self.vapi.igmp_clear_interface(pg.sw_if_index)
            pg.unconfig_ip4()
            pg.admin_down()
        super(TestIgmpProxy, self).tearDown()

    def send(self, ti, pkts):
        ti.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

    def verify_report(self, p, gaddr, saddr):
        ip = p[IP]
        self.assertEqual(ip.dst, "224.0.0.22")
        self.assertEqual(ip.proto, 2)
        igmp = p[IGMPv3]
        self.assertEqual(igmp.type, 0x22)
        self.assertEqual(igmp.gaddr, gaddr)
        group = igmp[IGMP3gr]
        self.assertEqual(igmp.saddr, saddr)

    def test_igmp_proxy(self):
        """ IGMP Poxy enable/disable """

        proxy = VppIgmpProxy(self, self.pg0._sw_if_index)
        proxy1 = VppIgmpProxy(self, self.pg1._sw_if_index)

        proxy.add_vpp_config()
        with self.vapi.expect_negative_api_retval():
            proxy1.add_vpp_config()

        cfg_dump = proxy.query_vpp_config()
        self.assertTrue(cfg_dump)
        self.assertEqual(len(cfg_dump), 1)
        dump = proxy.query_sg_config()
        self.assertFalse(dump)

        for idx, e in enumerate(cfg_dump):
            self.assertEqual(e.sw_if_index, proxy.sw_if_index)
            self.assertTrue(e.flags & IgmpConfigFlags.CLI_API_CONFIGURED.value)
            self.assertTrue(e.flags & IgmpConfigFlags.PROXY_ENABLED.value)
            self.assertEqual(e.proxy_addr, proxy.addr)

        proxy.remove_vpp_config()
        dump = proxy.query_vpp_config()
        self.assertFalse(dump)

    def test_igmp_proxy_join(self):
        """ IGMP send 'join/leave' upstream """

        #
        # pg0 -> proxy
        # pg1 -> send membership report
        #
        proxy = VppIgmpProxy(self, self.pg0._sw_if_index)
        proxy.add_vpp_config()

        # pg1 sends join IGMP 'join'
        p_join = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
                  IP(src=self.pg1.remote_ip4, dst='224.0.0.22', tos=0xc0) /
                  IGMPv3() /
                  IGMPv3mr(numgrp=1) /
                  IGMPv3gr(rtype=3, maddr="224.1.1.1", srcaddrs=["10.1.1.1"]))

        self.send(self.pg1, p_join)

        capture = self.pg0.get_capture(1, timeout=1)

        p = capture[0]
        ip = p[IP]
        self.assertEqual(ip.dst, "224.0.0.22")
        self.assertEqual(ip.proto, 2)
        igmp = p[IGMPv3]
        self.assertEqual(igmp.type, 0x22)
        self.assertEqual(len(igmp.records), 1)
        gr = igmp.records[0]
        self.assertEqual(gr.rtype, 3)
        self.assertEqual(gr.maddr, "224.1.1.1")
        self.assertEqual(len(gr.srcaddrs), 1)
        self.assertEqual(gr.srcaddrs[0], "10.0.1.1")

        # pg1 sends join IGMP 'join'
        p_join = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
                  IP(src=self.pg1.remote_ip4, dst='224.0.0.22', tos=0xc0) /
                  IGMPv3() /
                  IGMPv3mr(numgrp=1) /
                  IGMPv3gr(rtype=3, maddr="224.1.1.1", srcaddrs=["10.1.1.2"]))

        self.send(self.pg1, p_join)
        self.sleep(1)
        self.pg0.assert_nothing_captured()

        # pg2 sends IGMP 'leave'
        p_leave = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
                   IP(src=self.pg1.remote_ip4, dst='224.0.0.22', tos=0xc0) /
                   IGMPv3() /
                   IGMPv3mr(numgrp=1) /
                   IGMPv3gr(rtype=6, maddr="224.1.1.1", srcaddrs=["10.1.1.1"]))

        self.send(self.pg1, p_leave)
        self.sleep(1)
        self.pg0.assert_nothing_captured()

        # pg2 sends IGMP 'leave'
        p_leave = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
                   IP(src=self.pg1.remote_ip4, dst='224.0.0.22', tos=0xc0) /
                   IGMPv3() /
                   IGMPv3mr(numgrp=1) /
                   IGMPv3gr(rtype=6, maddr="224.1.1.1", srcaddrs=["10.1.1.2"]))

        self.send(self.pg1, p_leave)

        capture = self.pg0.get_capture(1, timeout=1)

        p = capture[0]
        ip = p[IP]
        self.assertEqual(ip.dst, "224.0.0.22")
        self.assertEqual(ip.proto, 2)
        igmp = p[IGMPv3]
        self.assertEqual(igmp.type, 0x22)
        self.assertEqual(len(igmp.records), 1)
        gr = igmp.records[0]
        self.assertEqual(gr.rtype, 6)
        self.assertEqual(gr.maddr, "224.1.1.1")
        self.assertEqual(len(gr.srcaddrs), 1)
        self.assertEqual(gr.srcaddrs[0], "10.0.1.1")

        proxy.remove_vpp_config()

    def test_igmp_proxy_mfib(self):
        """ IGMP add/del mfib entries """

        mfib_entries_n = len(self.vapi.ip_mfib_dump())

        #
        # pg0 -> proxy
        # pg1 -> send membership report
        #
        proxy = VppIgmpProxy(self, self.pg0._sw_if_index)
        proxy.add_vpp_config()
        grp_addr = socket.inet_pton(socket.AF_INET, "224.1.1.1")

        # pg1 sends join IGMP 'join'
        p_join = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
                  IP(src=self.pg1.remote_ip4, dst='224.0.0.22', tos=0xc0) /
                  IGMPv3() /
                  IGMPv3mr(numgrp=1) /
                  IGMPv3gr(rtype=3, maddr="224.1.1.1", srcaddrs=["10.1.1.1"]))

        self.send(self.pg1, p_join)

        #
        # new mfib entry was added
        #
        mfib_entries = self.vapi.ip_mfib_dump()
        self.assertTrue(mfib_entries_n + 1 == len(mfib_entries))
        mfib_entries_n = len(mfib_entries)
        #
        # check added entry
        #
        mfib_entry = mfib_entries[-1]
        self.assertEqual(mfib_entry.grp_address, grp_addr)

        # pg1 sends join IGMP 'join'
        p_join = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
                  IP(src=self.pg1.remote_ip4, dst='224.0.0.22', tos=0xc0) /
                  IGMPv3() /
                  IGMPv3mr(numgrp=1) /
                  IGMPv3gr(rtype=3, maddr="224.1.1.1", srcaddrs=["10.1.1.2"]))

        self.send(self.pg1, p_join)

        self.assertTrue(mfib_entries_n == len(self.vapi.ip_mfib_dump()))

        # pg1 sends IGMP 'leave'
        p_leave = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
                   IP(src=self.pg1.remote_ip4, dst='224.0.0.22', tos=0xc0) /
                   IGMPv3() /
                   IGMPv3mr(numgrp=1) /
                   IGMPv3gr(rtype=6, maddr="224.1.1.1", srcaddrs=["10.1.1.1"]))

        self.send(self.pg1, p_leave)

        self.assertTrue(mfib_entries_n == len(self.vapi.ip_mfib_dump()))

        # pg1 sends IGMP 'leave'
        p_leave = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
                   IP(src=self.pg1.remote_ip4, dst='224.0.0.22', tos=0xc0) /
                   IGMPv3() /
                   IGMPv3mr(numgrp=1) /
                   IGMPv3gr(rtype=6, maddr="224.1.1.1", srcaddrs=["10.1.1.2"]))

        self.send(self.pg1, p_leave)

        #
        # remove igmp entry
        #
        self.assertTrue(mfib_entries_n - 1 == len(self.vapi.ip_mfib_dump()))
        mfib_entries_n = len(self.vapi.ip_mfib_dump())

        proxy.remove_vpp_config()

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
