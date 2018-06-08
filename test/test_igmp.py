#!/usr/bin/env python

import unittest

from framework import VppTestCase, VppTestRunner, running_extended_tests
from vpp_igmp import *

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.contrib.igmpv3 import *
from scapy.contrib.igmp import *
from vpp_ip_route import find_mroute, VppIpTable


class IgmpMode:
    HOST = 1
    ROUTER = 0


class TestIgmp(VppTestCase):
    """ IGMP Test Case """

    def setUp(self):
        super(TestIgmp, self).setUp()

        self.create_pg_interfaces(range(4))
        self.sg_list = []
        self.config_list = []

        self.ip_addr = []
        self.ip_table = VppIpTable(self, 1)
        self.ip_table.add_vpp_config()

        for pg in self.pg_interfaces[2:]:
            pg.set_table_ip4(1)
        for pg in self.pg_interfaces:
            pg.admin_up()
            pg.config_ip4()
            pg.resolve_arp()

    def tearDown(self):
        for pg in self.pg_interfaces:
            self.vapi.igmp_clear_interface(pg.sw_if_index)
            pg.unconfig_ip4()
            pg.set_table_ip4(0)
            pg.admin_down()
        super(TestIgmp, self).tearDown()

    def send(self, ti, pkts):
        ti.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

    def test_igmp_not_enabled(self):
        """ IGMP parse Membership Report """

        #
        # VPP acts as a router
        # IGMP is not enabled so no state is learned.
        #
        # host sends join IGMP 'join'
        p_join = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                  IP(src=self.pg0.remote_ip4, dst='224.0.0.22', tos=0xc0) /
                  IGMPv3() /
                  IGMPv3mr(numgrp=1) /
                  IGMPv3gr(rtype=3, maddr="224.1.1.1", srcaddrs=["10.1.1.1"]))

        self.send(self.pg0, p_join)
        self.assertFalse(self.vapi.igmp_dump())

    def test_igmp_flush(self):
        """ IGMP Link Up/down and Flush """

        #
        # VPP acts as a router
        #
        self.vapi.igmp_enable_disable(self.pg0.sw_if_index, True,
                                      IgmpMode.ROUTER)

        # host sends join IGMP 'join'
        p_join = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                  IP(src=self.pg0.remote_ip4, dst='224.0.0.22', tos=0xc0) /
                  IGMPv3() /
                  IGMPv3mr(numgrp=1) /
                  IGMPv3gr(rtype=3, maddr="224.1.1.1", srcaddrs=["10.1.1.1"]))

        self.send(self.pg0, p_join)

        # search for the corresponding state created in VPP
        dump = self.vapi.igmp_dump(self.pg0.sw_if_index)
        self.assertEqual(len(dump), 1)
        self.assertTrue(find_igmp_state(dump, self.pg0.sw_if_index,
                                        "224.1.1.1", "10.1.1.1"))

        # A join sent on another interface does nothing
        self.send(self.pg1, p_join)
        dump = self.vapi.igmp_dump()
        self.assertEqual(len(dump), 1)
        self.assertTrue(find_igmp_state(dump, self.pg0.sw_if_index,
                                        "224.1.1.1", "10.1.1.1"))

        # setting admin down flushes learned state ...
        self.pg0.admin_down()
        self.assertFalse(self.vapi.igmp_dump())

        # .. but the IGMP config on the interface remains
        self.assertTrue(find_mroute(self, "224.0.0.1", "0.0.0.0", 32))

        # bring the interface back up, ensure we still relearn state
        self.pg0.admin_up()

        self.send(self.pg0, p_join)
        dump = self.vapi.igmp_dump()
        self.assertEqual(len(dump), 1)
        self.assertTrue(find_igmp_state(dump, self.pg0.sw_if_index,
                                        "224.1.1.1", "10.1.1.1"))

        # flush state from the API
        self.vapi.igmp_clear_interface(self.pg0.sw_if_index)
        self.assertFalse(self.vapi.igmp_dump())

        self.vapi.igmp_enable_disable(self.pg0.sw_if_index, 0,
                                      IgmpMode.ROUTER)

    def test_igmp_parse_report(self):
        """ IGMP parse Membership Report """

        #
        # VPP acts as a router
        #
        self.vapi.igmp_enable_disable(self.pg0.sw_if_index, 1)
        self.vapi.want_igmp_events(1)

        # host sends join IGMP 'join'
        p_join = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                  IP(src=self.pg0.remote_ip4, dst='224.0.0.22', tos=0xc0) /
                  IGMPv3() /
                  IGMPv3mr(numgrp=1) /
                  IGMPv3gr(rtype=3, maddr="224.1.1.1", srcaddrs=["10.1.1.1"]))

        self.send(self.pg0, p_join)

        # search for the corresponding state created in VPP
        dump = self.vapi.igmp_dump()
        self.assertEqual(len(dump), 1)
        self.assertTrue(find_igmp_state(dump, self.pg0.sw_if_index,
                                        "224.1.1.1", "10.1.1.1"))

        # VPP sends a notification that a new group has been joined
        ev = self.vapi.wait_for_event(2, "igmp_event")

        self.assertTrue(find_igmp_event(ev, self.pg0,
                                        "224.1.1.1", "10.1.1.1", True))

        # host sends IGMP leave
        p_leave = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                   IP(src=self.pg0.remote_ip4, dst='224.0.0.22', tos=0xc0) /
                   IGMPv3() /
                   IGMPv3mr(numgrp=1) /
                   IGMPv3gr(rtype=4, maddr="224.1.1.1", srcaddrs=["10.1.1.1"]))

        self.send(self.pg0, p_leave)

        # VPP sends a notification that a new group has been left
        ev = self.vapi.wait_for_event(2, "igmp_event")

        self.assertTrue(find_igmp_event(ev, self.pg0,
                                        "224.1.1.1", "10.1.1.1", False))

        # state gone
        dump = self.vapi.igmp_dump()
        self.assertFalse(dump)

        # resend the join
        self.send(self.pg0, p_join)
        dump = self.vapi.igmp_dump()
        self.assertEqual(len(dump), 1)
        self.assertTrue(find_igmp_state(dump, self.pg0.sw_if_index,
                                        "224.1.1.1", "10.1.1.1"))

        # IGMP block
        p_block = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                   IP(src=self.pg0.remote_ip4, dst='224.0.0.22', tos=0xc0) /
                   IGMPv3() /
                   IGMPv3mr(numgrp=1) /
                   IGMPv3gr(rtype=6, maddr="224.1.1.1", srcaddrs=["10.1.1.1"]))

        self.send(self.pg0, p_block)

        dump = self.vapi.igmp_dump()
        self.assertFalse(dump)
        self.vapi.igmp_enable_disable(self.pg0.sw_if_index, 0)
        self.vapi.want_igmp_events(0)

    def test_igmp_parse_big_report(self):
        """ IGMP parse Big Membership Report """

        #
        # VPP acts as a router
        #
        self.vapi.igmp_enable_disable(self.pg0.sw_if_index, 1)
        self.vapi.want_igmp_events(1)

        # host sends join IGMP 'join'
        p_join = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                  IP(src=self.pg0.remote_ip4, dst='224.0.0.22', tos=0xc0) /
                  IGMPv3() /
                  IGMPv3mr(numgrp=3) /
                  IGMPv3gr(rtype=3, maddr="224.1.1.1",
                           srcaddrs=["10.1.1.1"]) /
                  IGMPv3gr(rtype=3, maddr="224.1.1.2",
                           srcaddrs=["10.1.1.1", "10.1.1.2"]) /
                  IGMPv3gr(rtype=3, maddr="224.1.1.3",
                           srcaddrs=["10.0.0.1", "10.0.0.2", "10.0.0.3"]))

        self.send(self.pg0, p_join)

        # search for the corresponding state created in VPP
        dump = self.vapi.igmp_dump()
        self.assertEqual(len(dump), 6)
        self.assertTrue(find_igmp_state(dump, self.pg0.sw_if_index,
                                        "224.1.1.1", "10.1.1.1"))
        self.assertTrue(find_igmp_state(dump, self.pg0.sw_if_index,
                                        "224.1.1.2", "10.1.1.1"))
        self.assertTrue(find_igmp_state(dump, self.pg0.sw_if_index,
                                        "224.1.1.2", "10.1.1.2"))
        self.assertTrue(find_igmp_state(dump, self.pg0.sw_if_index,
                                        "224.1.1.3", "10.0.0.1"))
        self.assertTrue(find_igmp_state(dump, self.pg0.sw_if_index,
                                        "224.1.1.3", "10.0.0.2"))
        self.assertTrue(find_igmp_state(dump, self.pg0.sw_if_index,
                                        "224.1.1.3", "10.0.0.3"))

        ev = self.vapi.wait_for_event(2, "igmp_event")
        self.assertTrue(find_igmp_event(ev, self.pg0,
                                        "224.1.1.1", "10.1.1.1", True))

        ev = self.vapi.wait_for_event(2, "igmp_event")
        self.assertTrue(find_igmp_event(ev, self.pg0,
                                        "224.1.1.2", "10.1.1.1", True))
        ev = self.vapi.wait_for_event(2, "igmp_event")
        self.assertTrue(find_igmp_event(ev, self.pg0,
                                        "224.1.1.2", "10.1.1.2", True))

        ev = self.vapi.wait_for_event(2, "igmp_event")
        self.assertTrue(find_igmp_event(ev, self.pg0,
                                        "224.1.1.3", "10.0.0.1", True))
        ev = self.vapi.wait_for_event(2, "igmp_event")
        self.assertTrue(find_igmp_event(ev, self.pg0,
                                        "224.1.1.3", "10.0.0.2", True))

        ev = self.vapi.wait_for_event(2, "igmp_event")
        self.assertTrue(find_igmp_event(ev, self.pg0,
                                        "224.1.1.3", "10.0.0.3", True))

        # leave a source, router send gourp-source specific query
        # to check for other hosts 6.1
        self.assertTrue(0)

        # leave a group, router send gourp specific query
        # to check for other hosts 6.1
        self.assertTrue(0)

        # IGMP disable link, except state flushed
        self.vapi.igmp_enable_disable(self.pg0.sw_if_index, 0)
        self.assertFalse(self.vapi.igmp_dump())
        self.vapi.want_igmp_events(0)

    def test_igmp_enable(self):
        """ IGMP enable/disable on an interface

        check for the addition/removal of the IGMP  mroutes """

        self.vapi.igmp_enable_disable(self.pg0.sw_if_index, 1)
        self.vapi.igmp_enable_disable(self.pg1.sw_if_index, 1)

        self.assertTrue(find_mroute(self, "224.0.0.1", "0.0.0.0", 32))
        self.assertTrue(find_mroute(self, "224.0.0.22", "0.0.0.0", 32))

        self.vapi.igmp_enable_disable(self.pg2.sw_if_index, 1)
        self.vapi.igmp_enable_disable(self.pg3.sw_if_index, 1)

        self.assertTrue(find_mroute(self, "224.0.0.1", "0.0.0.0", 32,
                                    table_id=1))
        self.assertTrue(find_mroute(self, "224.0.0.22", "0.0.0.0", 32,
                                    table_id=1))
        self.vapi.igmp_enable_disable(self.pg0.sw_if_index, 0)
        self.vapi.igmp_enable_disable(self.pg1.sw_if_index, 0)
        self.vapi.igmp_enable_disable(self.pg2.sw_if_index, 0)
        self.vapi.igmp_enable_disable(self.pg3.sw_if_index, 0)

        self.assertFalse(find_mroute(self, "224.0.0.1", "0.0.0.0", 32))
        self.assertFalse(find_mroute(self, "224.0.0.22", "0.0.0.0", 32))
        self.assertFalse(find_mroute(self, "224.0.0.1", "0.0.0.0", 32,
                                     table_id=1))
        self.assertFalse(find_mroute(self, "224.0.0.22", "0.0.0.0", 32,
                                     table_id=1))

    def verify_general_query(self, p):
        ip = p[IP]
        self.assertEqual(ip.dst, "224.0.0.1")
        self.assertEqual(ip.proto, 2)
        igmp = p[IGMPv3]
        self.assertEqual(igmp.type, 0x11)
        self.assertEqual(igmp.gaddr, "0.0.0.0")

    @unittest.skipUnless(running_extended_tests(), "part of extended tests")
    def test_igmp_send_query(self):
        """ IGMP send General Query """

        #
        # VPP acts as a router.
        #   Send a membership report so VPP builds state
        #
        self.vapi.igmp_enable_disable(self.pg0.sw_if_index, 1)

        p_mr = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                IP(src=self.pg0.remote_ip4, dst='224.0.0.22') /
                IGMPv3() /
                IGMPv3mr(numgrp=1) /
                IGMPv3gr(rtype=3, maddr="224.1.1.1", srcaddrs=["10.1.1.1"]))

        self.send(self.pg0, p_mr)
        self.logger.info(self.vapi.cli("sh igmp config"))

        states = self.vapi.igmp_dump()
        self.assertEqual(len(states), 1)
        self.assertTrue(find_igmp_state(states, self.pg0.sw_if_index,
                                        "224.1.1.1", "10.1.1.1"))

        #
        # wait for VPP to send out the General Query
        #
        capture = self.pg0.get_capture(1, timeout=61)

        self.verify_general_query(capture[0])

        #
        # the state will expire in 10 more seconds
        #
        self.sleep(11)
        self.assertFalse(self.vapi.igmp_dump())
        self.vapi.igmp_enable_disable(self.pg0.sw_if_index, 0)

    @unittest.skipUnless(running_extended_tests(), "part of extended tests")
    def test_igmp_src_exp(self):
        """ IGMP per source timer """

        #
        # VPP Acts as a router
        #
        self.vapi.igmp_enable_disable(self.pg0.sw_if_index, 1)

        # Host join for (10.1.1.1,224.1.1.1)
        p_mr1 = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                 IP(src=self.pg0.remote_ip4, dst='224.0.0.22') /
                 IGMPv3() /
                 IGMPv3mr(numgrp=1) /
                 IGMPv3gr(rtype="Change To Include Mode",
                          maddr="224.1.1.1",
                          srcaddrs=["10.1.1.1"]))

        self.send(self.pg0, p_mr1)

        # VPP sends General Query
        # capture = self.pg0.get_capture(1, timeout=61)
        # self.verify_general_query(capture[0])

        #
        # Host replies to query
        #
        p_mr1 = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                 IP(src=self.pg0.remote_ip4, dst='224.0.0.22') /
                 IGMPv3() /
                 IGMPv3mr(numgrp=1) /
                 IGMPv3gr(rtype="Mode Is Include",
                          maddr="224.1.1.1",
                          srcaddrs=["10.1.1.1"]))

        #
        # host join for same G and another S: (10.1.1.2,224.1.1.1)
        # therefore leaving (10.1.1.1,224.1.1.1)
        #
        p_mr2 = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                 IP(src=self.pg0.remote_ip4, dst='224.0.0.22') /
                 IGMPv3() /
                 IGMPv3mr(numgrp=1) /
                 IGMPv3gr(rtype="Change To Include Mode",
                          maddr="224.1.1.1",
                          srcaddrs=["10.1.1.2"]))

        self.send(self.pg0, p_mr2)

        # wait for VPP to send general query
        # capture = self.pg0.get_capture(1, timeout=61)
        # self.verify_general_query(capture[0])
        # capture[0].show()

        # host leaves (10.1.1.2,224.1.1.1)
        p_l = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
               IP(src=self.pg0.remote_ip4, dst='224.0.0.22') /
               IGMPv3() /
               IGMPv3mr(numgrp=1) /
               IGMPv3gr(rtype="Change To Exclude Mode",
                        maddr="224.1.1.1", srcaddrs=["10.1.1.2"]))

        self.send(self.pg0, p_l)

        #
        # host has left all groups, no state left.
        #
        self.logger.info(self.vapi.cli("sh igmp config"))
        self.assertFalse(self.vapi.igmp_dump())
        self.vapi.igmp_enable_disable(self.pg0.sw_if_index, 0)

    def verify_qeury_response(self, rx, grp, srcs):
        self.assertEqual(rx[IP].dst, "224.0.0.22")
        self.assertEqual(rx[IGMPv3].type, 0x22)
        self.assertEqual(rx[IGMPv3mr].numgrp, 1)
        self.assertEqual(rx[IGMPv3gr].rtype, 1)
        self.assertEqual(rx[IGMPv3gr].numsrc, len(srcs))
        self.assertEqual(rx[IGMPv3gr].maddr, grp)
        self.assertEqual(len(rx[IGMPv3gr].srcaddrs), len(srcs))
        for i in range(len(srcs)):
            self.assertEqual(rx[IGMPv3gr].srcaddrs[i], srcs[i])

    def test_igmp_query_resp(self):
        """ IGMP Query response """

        #
        # VPP acting as a host.
        #  Add a listener in VPP for (10.1.1.1,244.1.1.1)
        #
        self.vapi.igmp_enable_disable(self.pg0.sw_if_index, 1)

        c1 = VppIgmpConfig(self, self.pg0.sw_if_index,
                           IgmpSG("10.1.1.1", "224.1.1.1"))
        c1.add_vpp_config()

        # verify state exists
        self.assertTrue(self.vapi.igmp_dump(self.pg0.sw_if_index))

        #
        # Send a general query (to the all router's address)
        #
        p_g = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
               IP(src=self.pg0.remote_ip4, dst='224.0.0.1', tos=0xc0) /
               IGMPv3(type=0x11, mrcode=100) /
               IGMPv3mq(gaddr="0.0.0.0"))

        self.send(self.pg0, p_g)

        #
        # expect VPP to respond with a membership report for the
        # (10.1.1.1, 224.1.1.1) state
        #
        capture = self.pg0.get_capture(1, timeout=10)
        self.verify_query_response(capture[0], '224.0.0.1', ["10.1.1.1"])

        #
        # Send a group-specific query (sent to the gourp address)
        #
        p_g = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
               IP(src=self.pg0.remote_ip4, dst='224.1.1.1', tos=0xc0) /
               IGMPv3(type=0x11, mrcode=100) /
               IGMPv3mq(gaddr="224.1.1.1"))

        self.send(self.pg0, p_g)
        capture = self.pg0.get_capture(1, timeout=10)
        self.verify_query_response(capture[0], '224.0.0.1', ["10.1.1.1"])

        #
        # Send a source-group-specific query
        #
        p_g_s = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                 IP(src=self.pg0.remote_ip4, dst='224.1.1.1', tos=0xc0) /
                 IGMPv3(type=0x11, mrcode=100) /
                 IGMPv3mq(gaddr="224.1.1.1", srcaddrs=["10.1.1.1"]))

        self.send(self.pg0, p_g_s)
        capture = self.pg0.get_capture(1, timeout=10)
        self.verify_query_response(capture[0], '224.0.0.1', ["10.1.1.1"])

        #
        # add more state, so VPP has more groups and source to report
        #
        c2 = VppIgmpConfig(self, self.pg0.sw_if_index,
                           IgmpSG("10.1.1.2", "224.1.1.1"))
        c3 = VppIgmpConfig(self, self.pg0.sw_if_index,
                           IgmpSG("10.1.1.1", "224.1.1.2"))
        c4 = VppIgmpConfig(self, self.pg0.sw_if_index,
                           IgmpSG("10.1.1.1", "224.1.1.3"))
        c2.add_vpp_config()
        c3.add_vpp_config()
        c4.add_vpp_config()

        # general query
        self.send(self.pg0, p)
        capture = self.pg0.get_capture(1, timeout=10)
        self.verify_query_response(capture[0], '224.0.0.1', ["10.1.1.1"])
        # group query
        self.send(self.pg0, p_g)
        capture = self.pg0.get_capture(1, timeout=10)
        self.verify_query_response(capture[0], '224.0.0.1', ["10.1.1.1"])
        # source-group query
        self.send(self.pg0, p_g_s)
        capture = self.pg0.get_capture(1, timeout=10)
        self.verify_query_response(capture[0], '224.0.0.1', ["10.1.1.1"])

        self.vapi.igmp_enable_disable(self.pg0.sw_if_index, 0)

    def test_igmp_listen(self):
        """ IGMP listen (S,G)s """

        #
        # VPP acts as a host
        #  Add IGMP group state to multiple interfaces and validate its
        #  presence
        #
        for pg in self.pg_interfaces:
            self.vapi.igmp_enable_disable(pg.sw_if_index, 1, 1)

        for pg in self.pg_interfaces:
            sg_list = []
            for i in range(4):
                sg_list.append(IgmpSG("10.1.%d.%d" % (pg._sw_if_index, i),
                                      "224.1.1.1"))
            self.config_list.append(VppIgmpConfig(self,
                                                  pg._sw_if_index,
                                                  sg_list))
            self.config_list[-1].add_vpp_config()

        for config in self.config_list:
            dump = self.vapi.igmp_dump(config.sw_if_index)
            self.assertEqual(len(dump), 4)
            for sg in config.sg_list:
                self.assertTrue(find_igmp_state(dump,
                                                config.sw_if_index,
                                                sg.gaddr,
                                                sg.saddr))

        for config in self.config_list:
            config.remove_vpp_config()

        dump = self.vapi.igmp_dump()
        self.assertFalse(dump)

        for pg in self.pg_interfaces:
            self.vapi.igmp_enable_disable(pg.sw_if_index, 0)

    def verify_report(self, rx, type, grp, srcs):
        self.assertEqual(rx[IP].dst, "224.0.0.22")
        self.assertEqual(rx[IGMPv3].type, 0x22)
        self.assertEqual(rx[IGMPv3mr].numgrp, 1)
        self.assertEqual(IGMPv3gr.igmpv3grtypes[rx[IGMPv3gr].rtype], type)
        self.assertEqual(rx[IGMPv3gr].numsrc, len(srcs))
        self.assertEqual(rx[IGMPv3gr].maddr, grp)
        self.assertEqual(len(rx[IGMPv3gr].srcaddrs), len(srcs))
        for i in range(len(srcs)):
            self.assertEqual(rx[IGMPv3gr].srcaddrs[i], srcs[i])

    def add_group(self, itf, grp, srcs):
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        hs = VppHostState(self,
                          IGMP_FILTER.INCLUDE,
                          itf.sw_if_index,
                          srcs, grp)
        hs.add_vpp_config()

        capture = itf.get_capture(1, timeout=10)
        capture[0].show()

        self.verify_report(capture[0],
                           "Allow New Sources",
                           grp, srcs)
        return hs

    def remove_group(self, hs):
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        hs.remove_vpp_config()

        capture = self.pg0.get_capture(1, timeout=10)
        capture[0].show()

        self.verify_report(capture[0],
                           "Block Old Sources",
                           hs.gaddr, hs.saddrs)

    def test_igmp_host(self):
        """ IGMP Host functions """

        #
        # Enable interface for host functions
        #
        self.vapi.igmp_enable_disable(self.pg0.sw_if_index,
                                      1,
                                      IGMP_MODE.HOST)

        #
        # Add one S,G of state and expect a state-change event report
        # indicating the addition of the S,G
        #
        h1 = self.add_group(self.pg0, "239.1.1.1", ["1.1.1.1"]);

        # search for the corresponding state created in VPP
        dump = self.vapi.igmp_dump(self.pg0.sw_if_index)
        self.assertEqual(len(dump), 1)
        self.assertTrue(find_igmp_state(dump, self.pg0.sw_if_index,
                                        "239.1.1.1", "1.1.1.1"))

        #
        # remove state, expect the report for the removal
        #
        self.remove_group(h1)

        dump = self.vapi.igmp_dump()
        self.assertFalse(dump)

        #
        # A group with multiple sources
        #
        h2 = self.add_group(self.pg0, "239.1.1.1",
                            ["1.1.1.1", "1.1.1.2", "1.1.1.3"]);

        # search for the corresponding state created in VPP
        dump = self.vapi.igmp_dump(self.pg0.sw_if_index)
        self.assertEqual(len(dump), 3)
        for s in h2.saddrs:
            self.assertTrue(find_igmp_state(dump, self.pg0.sw_if_index,
                                            "239.1.1.1", s))

        #
        # remove state, expect the report for the removal
        # the dump should be empty
        #
        self.remove_group(h2)

        self.assertFalse(self.vapi.igmp_dump())



if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
