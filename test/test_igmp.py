#!/usr/bin/env python

import unittest

from framework import VppTestCase, VppTestRunner, running_extended_tests
from vpp_igmp import *

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.contrib.igmpv3 import *
from scapy.contrib.igmp import *
from vpp_ip_route import find_mroute, VppIpTable, VppIpMRoute, VppMRoutePath, \
    MRouteEntryFlags, MRouteItfFlags


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

    def verify_report(self, rx, records):
        self.assertEqual(rx[IP].dst, "224.0.0.22")
        self.assertEqual(IGMPv3.igmpv3types[rx[IGMPv3].type],
                         "Version 3 Membership Report")
        self.assertEqual(rx[IGMPv3mr].numgrp, len(records))

        received = rx[IGMPv3mr].records

        for ii in range(len(records)):
            gr = received[ii]
            r = records[ii]
            self.assertEqual(IGMPv3gr.igmpv3grtypes[gr.rtype], r.type)
            self.assertEqual(gr.numsrc, len(r.sg.saddrs))
            self.assertEqual(gr.maddr, r.sg.gaddr)
            self.assertEqual(len(gr.srcaddrs), len(r.sg.saddrs))

            self.assertEqual(sorted(gr.srcaddrs),
                             sorted(r.sg.saddrs))

    def add_group(self, itf, sg, n_pkts=1):
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        hs = VppHostState(self,
                          IGMP_FILTER.INCLUDE,
                          itf.sw_if_index,
                          sg)
        hs.add_vpp_config()

        capture = itf.get_capture(n_pkts, timeout=10)

        self.verify_report(capture[0],
                           [IgmpRecord(sg, "Allow New Sources")]),

        return hs

    def remove_group(self, hs):
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        hs.remove_vpp_config()

        capture = self.pg0.get_capture(1, timeout=10)

        self.verify_report(capture[0],
                           [IgmpRecord(hs.sg, "Block Old Sources")])

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
        h1 = self.add_group(self.pg0, IgmpSG("239.1.1.1", ["1.1.1.1"]))

        # search for the corresponding state created in VPP
        dump = self.vapi.igmp_dump(self.pg0.sw_if_index)
        self.assertEqual(len(dump), 1)
        self.assertTrue(find_igmp_state(dump, self.pg0.sw_if_index,
                                        "239.1.1.1", "1.1.1.1"))

        #
        # Send a general query (to the all router's address)
        # expect VPP to respond with a membership report
        #
        p_g = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
               IP(src=self.pg0.remote_ip4, dst='224.0.0.1', tos=0xc0) /
               IGMPv3(type="Membership Query", mrcode=100) /
               IGMPv3mq(gaddr="0.0.0.0"))

        self.send(self.pg0, p_g)

        capture = self.pg0.get_capture(1, timeout=10)
        self.verify_report(capture[0],
                           [IgmpRecord(h1.sg, "Mode Is Include")])

        #
        # Group specific query
        #  In order to respond to this query, VPP needs a IP mroute
        #  which we expect the client to also add
        #
        mr = VppIpMRoute(
            self,
            "0.0.0.0",
            "239.1.1.1", 32,
            MRouteEntryFlags.MFIB_ENTRY_FLAG_NONE,
            paths=[VppMRoutePath(self.pg0.sw_if_index,
                                 MRouteItfFlags.MFIB_ITF_FLAG_ACCEPT)])
        mr.add_vpp_config()

        p_gs = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                IP(src=self.pg0.remote_ip4, dst='239.1.1.1', tos=0xc0) /
                IGMPv3(type="Membership Query", mrcode=100) /
                IGMPv3mq(gaddr="239.1.1.1"))

        self.send(self.pg0, p_gs)

        capture = self.pg0.get_capture(1, timeout=10)
        self.verify_report(capture[0],
                           [IgmpRecord(h1.sg, "Mode Is Include")])

        #
        # A group and source specific query, with the source matching
        # the source VPP has
        #
        p_gs1 = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                 IP(src=self.pg0.remote_ip4, dst='239.1.1.1', tos=0xc0) /
                 IGMPv3(type="Membership Query", mrcode=100) /
                 IGMPv3mq(gaddr="239.1.1.1", srcaddrs=["1.1.1.1"]))

        self.send(self.pg0, p_gs1)

        capture = self.pg0.get_capture(1, timeout=10)
        self.verify_report(capture[0],
                           [IgmpRecord(h1.sg, "Mode Is Include")])

        #
        # A group and source specific query, with the source NOT matching
        # the source VPP has. There should be no response.
        #
        p_gs2 = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                 IP(src=self.pg0.remote_ip4, dst='239.1.1.1', tos=0xc0) /
                 IGMPv3(type="Membership Query", mrcode=100) /
                 IGMPv3mq(gaddr="239.1.1.1", srcaddrs=["1.1.1.2"]))

        self.send_and_assert_no_replies(self.pg0, p_gs2, timeout=10)

        #
        # A group and source specific query, with the multiple sources
        # one of which matches the source VPP has.
        # The report should contain only the source VPP has.
        #
        p_gs3 = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                 IP(src=self.pg0.remote_ip4, dst='239.1.1.1', tos=0xc0) /
                 IGMPv3(type="Membership Query", mrcode=100) /
                 IGMPv3mq(gaddr="239.1.1.1",
                          srcaddrs=["1.1.1.1", "1.1.1.2", "1.1.1.3"]))

        self.send(self.pg0, p_gs3)

        capture = self.pg0.get_capture(1, timeout=10)
        self.verify_report(capture[0],
                           [IgmpRecord(h1.sg, "Mode Is Include")])

        #
        # Two source and group specific queires in qucik sucession, the
        # first does not have VPPs source the second does. then vice-versa
        #
        self.send(self.pg0, [p_gs2, p_gs1])
        capture = self.pg0.get_capture(1, timeout=10)
        self.verify_report(capture[0],
                           [IgmpRecord(h1.sg, "Mode Is Include")])

        self.send(self.pg0, [p_gs1, p_gs2])
        capture = self.pg0.get_capture(1, timeout=10)
        self.verify_report(capture[0],
                           [IgmpRecord(h1.sg, "Mode Is Include")])

        #
        # remove state, expect the report for the removal
        #
        self.remove_group(h1)

        dump = self.vapi.igmp_dump()
        self.assertFalse(dump)

        #
        # A group with multiple sources
        #
        h2 = self.add_group(self.pg0,
                            IgmpSG("239.1.1.1",
                                   ["1.1.1.1", "1.1.1.2", "1.1.1.3"]))

        # search for the corresponding state created in VPP
        dump = self.vapi.igmp_dump(self.pg0.sw_if_index)
        self.assertEqual(len(dump), 3)
        for s in h2.sg.saddrs:
            self.assertTrue(find_igmp_state(dump, self.pg0.sw_if_index,
                                            "239.1.1.1", s))
        #
        # Send a general query (to the all router's address)
        # expect VPP to respond with a membership report will all sources
        #
        self.send(self.pg0, p_g)

        capture = self.pg0.get_capture(1, timeout=10)
        self.verify_report(capture[0],
                           [IgmpRecord(h2.sg, "Mode Is Include")])

        #
        # Group and source specific query; some present some not
        #
        p_gs = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                IP(src=self.pg0.remote_ip4, dst='239.1.1.1', tos=0xc0) /
                IGMPv3(type="Membership Query", mrcode=100) /
                IGMPv3mq(gaddr="239.1.1.1",
                         srcaddrs=["1.1.1.1", "1.1.1.2", "1.1.1.4"]))

        self.send(self.pg0, p_gs)

        capture = self.pg0.get_capture(1, timeout=10)
        self.verify_report(capture[0],
                           [IgmpRecord(
                               IgmpSG('239.1.1.1', ["1.1.1.1", "1.1.1.2"]),
                               "Mode Is Include")])

        #
        # add loads more groups
        #
        h3 = self.add_group(self.pg0,
                            IgmpSG("239.1.1.2",
                                   ["2.1.1.1", "2.1.1.2", "2.1.1.3"]))
        h4 = self.add_group(self.pg0,
                            IgmpSG("239.1.1.3",
                                   ["3.1.1.1", "3.1.1.2", "3.1.1.3"]))
        h5 = self.add_group(self.pg0,
                            IgmpSG("239.1.1.4",
                                   ["4.1.1.1", "4.1.1.2", "4.1.1.3"]))
        h6 = self.add_group(self.pg0,
                            IgmpSG("239.1.1.5",
                                   ["5.1.1.1", "5.1.1.2", "5.1.1.3"]))
        h7 = self.add_group(self.pg0,
                            IgmpSG("239.1.1.6",
                                   ["6.1.1.1", "6.1.1.2",
                                    "6.1.1.3", "6.1.1.4",
                                    "6.1.1.5", "6.1.1.6",
                                    "6.1.1.7", "6.1.1.8",
                                    "6.1.1.9", "6.1.1.10",
                                    "6.1.1.11", "6.1.1.12",
                                    "6.1.1.13", "6.1.1.14",
                                    "6.1.1.15", "6.1.1.16"]))

        #
        # general query.
        # the order the groups come in is not important, so what is
        # checked for is what VPP is sending today.
        #
        self.send(self.pg0, p_g)

        capture = self.pg0.get_capture(1, timeout=10)

        self.verify_report(capture[0],
                           [IgmpRecord(h3.sg, "Mode Is Include"),
                            IgmpRecord(h2.sg, "Mode Is Include"),
                            IgmpRecord(h6.sg, "Mode Is Include"),
                            IgmpRecord(h4.sg, "Mode Is Include"),
                            IgmpRecord(h5.sg, "Mode Is Include"),
                            IgmpRecord(h7.sg, "Mode Is Include")])

        #
        # modify a group to add and remove some sources
        #
        h7.sg = IgmpSG("239.1.1.6",
                       ["6.1.1.1", "6.1.1.2",
                        "6.1.1.5", "6.1.1.6",
                        "6.1.1.7", "6.1.1.8",
                        "6.1.1.9", "6.1.1.10",
                        "6.1.1.11", "6.1.1.12",
                        "6.1.1.13", "6.1.1.14",
                        "6.1.1.15", "6.1.1.16",
                        "6.1.1.17", "6.1.1.18"])

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        h7.add_vpp_config()

        capture = self.pg0.get_capture(1, timeout=10)
        self.verify_report(capture[0],
                           [IgmpRecord(IgmpSG("239.1.1.6",
                                              ["6.1.1.17", "6.1.1.18"]),
                                       "Allow New Sources"),
                            IgmpRecord(IgmpSG("239.1.1.6",
                                              ["6.1.1.3", "6.1.1.4"]),
                                       "Block Old Sources")])

        #
        # add an additional groups with many sources so that each group
        # consumes the link MTU. We should therefore see multiple state
        # state reports when queried.
        #
        self.vapi.sw_interface_set_mtu(self.pg0.sw_if_index, [560, 0, 0, 0])

        src_list = []
        for i in range(128):
            src_list.append("10.1.1.%d" % i)

        h8 = self.add_group(self.pg0,
                            IgmpSG("238.1.1.1", src_list))
        h9 = self.add_group(self.pg0,
                            IgmpSG("238.1.1.2", src_list))

        self.send(self.pg0, p_g)

        capture = self.pg0.get_capture(4, timeout=10)

        self.verify_report(capture[0],
                           [IgmpRecord(h3.sg, "Mode Is Include"),
                            IgmpRecord(h2.sg, "Mode Is Include"),
                            IgmpRecord(h6.sg, "Mode Is Include"),
                            IgmpRecord(h4.sg, "Mode Is Include"),
                            IgmpRecord(h5.sg, "Mode Is Include")])
        self.verify_report(capture[1],
                           [IgmpRecord(h8.sg, "Mode Is Include")])
        self.verify_report(capture[2],
                           [IgmpRecord(h7.sg, "Mode Is Include")])
        self.verify_report(capture[3],
                           [IgmpRecord(h9.sg, "Mode Is Include")])

        #
        # drop the MTU further (so a 128 sized group won't fit)
        #
        self.vapi.sw_interface_set_mtu(self.pg0.sw_if_index, [512, 0, 0, 0])

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        h10 = VppHostState(self,
                           IGMP_FILTER.INCLUDE,
                           self.pg0.sw_if_index,
                           IgmpSG("238.1.1.3", src_list))
        h10.add_vpp_config()

        capture = self.pg0.get_capture(2, timeout=10)

        #
        # remove state, expect the report for the removal
        # the dump should be empty
        #
        self.vapi.sw_interface_set_mtu(self.pg0.sw_if_index, [600, 0, 0, 0])
        self.remove_group(h8)
        self.remove_group(h9)
        self.remove_group(h2)
        self.remove_group(h3)
        self.remove_group(h4)
        self.remove_group(h5)
        self.remove_group(h6)
        self.remove_group(h7)
        self.remove_group(h10)

        self.logger.error(self.vapi.cli("sh igmp config"))
        self.assertFalse(self.vapi.igmp_dump())

        self.vapi.igmp_enable_disable(self.pg0.sw_if_index,
                                      0,
                                      IGMP_MODE.HOST)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
