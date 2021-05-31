#!/usr/bin/env python3

import unittest

from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.layers.inet import IP, IPOption
from scapy.contrib.igmpv3 import IGMPv3, IGMPv3gr, IGMPv3mq, IGMPv3mr

from framework import tag_fixme_vpp_workers
from framework import VppTestCase, VppTestRunner
from vpp_igmp import find_igmp_state, IGMP_FILTER, IgmpRecord, IGMP_MODE, \
    IgmpSG, VppHostState, wait_for_igmp_event
from vpp_ip_route import find_mroute, VppIpTable


class IgmpMode:
    HOST = 1
    ROUTER = 0


@tag_fixme_vpp_workers
class TestIgmp(VppTestCase):
    """ IGMP Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestIgmp, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestIgmp, cls).tearDownClass()

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

    def test_igmp_flush(self):
        """ IGMP Link Up/down and Flush """

        #
        # FIX THIS. Link down.
        #

    def test_igmp_enable(self):
        """ IGMP enable/disable on an interface

        check for the addition/removal of the IGMP mroutes """

        self.vapi.igmp_enable_disable(self.pg0.sw_if_index, 1, IGMP_MODE.HOST)
        self.vapi.igmp_enable_disable(self.pg1.sw_if_index, 1, IGMP_MODE.HOST)

        self.assertTrue(find_mroute(self, "224.0.0.1", "0.0.0.0", 32))
        self.assertTrue(find_mroute(self, "224.0.0.22", "0.0.0.0", 32))

        self.vapi.igmp_enable_disable(self.pg2.sw_if_index, 1, IGMP_MODE.HOST)
        self.vapi.igmp_enable_disable(self.pg3.sw_if_index, 1, IGMP_MODE.HOST)

        self.assertTrue(find_mroute(self, "224.0.0.1", "0.0.0.0", 32,
                                    table_id=1))
        self.assertTrue(find_mroute(self, "224.0.0.22", "0.0.0.0", 32,
                                    table_id=1))
        self.vapi.igmp_enable_disable(self.pg0.sw_if_index, 0, IGMP_MODE.HOST)
        self.vapi.igmp_enable_disable(self.pg1.sw_if_index, 0, IGMP_MODE.HOST)
        self.vapi.igmp_enable_disable(self.pg2.sw_if_index, 0, IGMP_MODE.HOST)
        self.vapi.igmp_enable_disable(self.pg3.sw_if_index, 0, IGMP_MODE.HOST)

        self.assertTrue(find_mroute(self, "224.0.0.1", "0.0.0.0", 32))
        self.assertFalse(find_mroute(self, "224.0.0.22", "0.0.0.0", 32))
        self.assertTrue(find_mroute(self, "224.0.0.1", "0.0.0.0", 32,
                                    table_id=1))
        self.assertFalse(find_mroute(self, "224.0.0.22", "0.0.0.0", 32,
                                     table_id=1))

    def verify_general_query(self, p):
        ip = p[IP]
        self.assertEqual(len(ip.options), 1)
        self.assertEqual(ip.options[0].option, 20)
        self.assertEqual(ip.dst, "224.0.0.1")
        self.assertEqual(ip.proto, 2)
        igmp = p[IGMPv3]
        self.assertEqual(igmp.type, 0x11)
        self.assertEqual(igmp.gaddr, "0.0.0.0")

    def verify_group_query(self, p, grp, srcs):
        ip = p[IP]
        self.assertEqual(ip.dst, grp)
        self.assertEqual(ip.proto, 2)
        self.assertEqual(len(ip.options), 1)
        self.assertEqual(ip.options[0].option, 20)
        self.assertEqual(ip.proto, 2)
        igmp = p[IGMPv3]
        self.assertEqual(igmp.type, 0x11)
        self.assertEqual(igmp.gaddr, grp)

    def verify_report(self, rx, records):
        ip = rx[IP]
        self.assertEqual(rx[IP].dst, "224.0.0.22")
        self.assertEqual(len(ip.options), 1)
        self.assertEqual(ip.options[0].option, 20)
        self.assertEqual(ip.proto, 2)
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

    def add_group(self, itf, sg, n_pkts=2):
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        hs = VppHostState(self,
                          IGMP_FILTER.INCLUDE,
                          itf.sw_if_index,
                          sg)
        hs.add_vpp_config()

        capture = itf.get_capture(n_pkts, timeout=10)

        # reports are transmitted twice due to default rebostness value=2
        self.verify_report(capture[0],
                           [IgmpRecord(sg, "Allow New Sources")]),
        self.verify_report(capture[1],
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
        self.assertTrue(find_igmp_state(dump, self.pg0,
                                        "239.1.1.1", "1.1.1.1"))

        #
        # Send a general query (to the all router's address)
        # expect VPP to respond with a membership report.
        # Pad the query with 0 - some devices in the big wild
        # internet are prone to this.
        #
        p_g = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
               IP(src=self.pg0.remote_ip4, dst='224.0.0.1', tos=0xc0) /
               IGMPv3(type="Membership Query", mrcode=100) /
               IGMPv3mq(gaddr="0.0.0.0") /
               Raw(b'\x00' * 10))

        self.send(self.pg0, p_g)

        capture = self.pg0.get_capture(1, timeout=10)
        self.verify_report(capture[0],
                           [IgmpRecord(h1.sg, "Mode Is Include")])

        #
        # Group specific query
        #
        p_gs = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                IP(src=self.pg0.remote_ip4, dst='239.1.1.1', tos=0xc0,
                   options=[IPOption(copy_flag=1, optclass="control",
                                     option="router_alert")]) /
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
                 IP(src=self.pg0.remote_ip4, dst='239.1.1.1', tos=0xc0,
                    options=[IPOption(copy_flag=1, optclass="control",
                                      option="router_alert")]) /
                 IGMPv3(type="Membership Query", mrcode=100) /
                 IGMPv3mq(gaddr="239.1.1.1", srcaddrs=["1.1.1.1"]))

        self.send(self.pg0, p_gs1)

        capture = self.pg0.get_capture(1, timeout=10)
        self.verify_report(capture[0],
                           [IgmpRecord(h1.sg, "Mode Is Include")])

        #
        # A group and source specific query that reports more sources
        # than the packet actually has.
        #
        p_gs2 = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                 IP(src=self.pg0.remote_ip4, dst='239.1.1.1', tos=0xc0,
                    options=[IPOption(copy_flag=1, optclass="control",
                                      option="router_alert")]) /
                 IGMPv3(type="Membership Query", mrcode=100) /
                 IGMPv3mq(gaddr="239.1.1.1", numsrc=4, srcaddrs=["1.1.1.1"]))

        self.send_and_assert_no_replies(self.pg0, p_gs2, timeout=10)

        #
        # A group and source specific query, with the source NOT matching
        # the source VPP has. There should be no response.
        #
        p_gs2 = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                 IP(src=self.pg0.remote_ip4, dst='239.1.1.1', tos=0xc0,
                    options=[IPOption(copy_flag=1, optclass="control",
                                      option="router_alert")]) /
                 IGMPv3(type="Membership Query", mrcode=100) /
                 IGMPv3mq(gaddr="239.1.1.1", srcaddrs=["1.1.1.2"]))

        self.send_and_assert_no_replies(self.pg0, p_gs2, timeout=10)

        #
        # A group and source specific query, with the multiple sources
        # one of which matches the source VPP has.
        # The report should contain only the source VPP has.
        #
        p_gs3 = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                 IP(src=self.pg0.remote_ip4, dst='239.1.1.1', tos=0xc0,
                    options=[IPOption(copy_flag=1, optclass="control",
                                      option="router_alert")]) /
                 IGMPv3(type="Membership Query", mrcode=100) /
                 IGMPv3mq(gaddr="239.1.1.1",
                          srcaddrs=["1.1.1.1", "1.1.1.2", "1.1.1.3"]))

        self.send(self.pg0, p_gs3)

        capture = self.pg0.get_capture(1, timeout=10)
        self.verify_report(capture[0],
                           [IgmpRecord(h1.sg, "Mode Is Include")])

        #
        # Two source and group specific queries in quick succession, the
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
            self.assertTrue(find_igmp_state(dump, self.pg0,
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
                IP(src=self.pg0.remote_ip4, dst='239.1.1.1', tos=0xc0,
                   options=[IPOption(copy_flag=1, optclass="control",
                                     option="router_alert")]) /
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
        # wait for a little bit
        self.sleep(1)

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

        self.logger.info(self.vapi.cli("sh igmp config"))
        self.assertFalse(self.vapi.igmp_dump())

        #
        # TODO
        #  ADD STATE ON MORE INTERFACES
        #

        self.vapi.igmp_enable_disable(self.pg0.sw_if_index,
                                      0,
                                      IGMP_MODE.HOST)

    def test_igmp_router(self):
        """ IGMP Router Functions """

        #
        # Drop reports when not enabled
        #
        p_j = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
               IP(src=self.pg0.remote_ip4, dst="224.0.0.22", tos=0xc0, ttl=1,
                  options=[IPOption(copy_flag=1, optclass="control",
                                    option="router_alert")]) /
               IGMPv3(type="Version 3 Membership Report") /
               IGMPv3mr(numgrp=1) /
               IGMPv3gr(rtype="Allow New Sources",
                        maddr="239.1.1.1", srcaddrs=["10.1.1.1", "10.1.1.2"]))
        p_l = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
               IP(src=self.pg0.remote_ip4, dst="224.0.0.22", tos=0xc0,
                  options=[IPOption(copy_flag=1, optclass="control",
                                    option="router_alert")]) /
               IGMPv3(type="Version 3 Membership Report") /
               IGMPv3mr(numgrp=1) /
               IGMPv3gr(rtype="Block Old Sources",
                        maddr="239.1.1.1", srcaddrs=["10.1.1.1", "10.1.1.2"]))

        self.send(self.pg0, p_j)
        self.assertFalse(self.vapi.igmp_dump())

        #
        # drop the default timer values so these tests execute in a
        # reasonable time frame
        #
        self.vapi.cli("test igmp timers query 1 src 3 leave 1")

        #
        # enable router functions on the interface
        #
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.vapi.igmp_enable_disable(self.pg0.sw_if_index,
                                      1,
                                      IGMP_MODE.ROUTER)
        self.vapi.want_igmp_events(1)

        #
        # wait for router to send general query
        #
        for ii in range(3):
            capture = self.pg0.get_capture(1, timeout=2)
            self.verify_general_query(capture[0])
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()

        #
        # re-send the report. VPP should now hold state for the new group
        # VPP sends a notification that a new group has been joined
        #
        self.send(self.pg0, p_j)

        self.assertTrue(wait_for_igmp_event(self, 1, self.pg0,
                                            "239.1.1.1", "10.1.1.1", 1))
        self.assertTrue(wait_for_igmp_event(self, 1, self.pg0,
                                            "239.1.1.1", "10.1.1.2", 1))
        dump = self.vapi.igmp_dump(self.pg0.sw_if_index)
        self.assertEqual(len(dump), 2)
        self.assertTrue(find_igmp_state(dump, self.pg0,
                                        "239.1.1.1", "10.1.1.1"))
        self.assertTrue(find_igmp_state(dump, self.pg0,
                                        "239.1.1.1", "10.1.1.2"))

        #
        # wait for the per-source timer to expire
        # the state should be reaped
        # VPP sends a notification that the group has been left
        #
        self.assertTrue(wait_for_igmp_event(self, 4, self.pg0,
                                            "239.1.1.1", "10.1.1.1", 0))
        self.assertTrue(wait_for_igmp_event(self, 1, self.pg0,
                                            "239.1.1.1", "10.1.1.2", 0))
        self.assertFalse(self.vapi.igmp_dump())

        #
        # resend the join. wait for two queries and then send a current-state
        # record to include all sources. this should reset the expiry time
        # on the sources and thus they will still be present in 2 seconds time.
        # If the source timer was not refreshed, then the state would have
        # expired in 3 seconds.
        #
        self.send(self.pg0, p_j)
        self.assertTrue(wait_for_igmp_event(self, 1, self.pg0,
                                            "239.1.1.1", "10.1.1.1", 1))
        self.assertTrue(wait_for_igmp_event(self, 1, self.pg0,
                                            "239.1.1.1", "10.1.1.2", 1))
        dump = self.vapi.igmp_dump(self.pg0.sw_if_index)
        self.assertEqual(len(dump), 2)

        capture = self.pg0.get_capture(2, timeout=3)
        self.verify_general_query(capture[0])
        self.verify_general_query(capture[1])

        p_cs = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                IP(src=self.pg0.remote_ip4, dst="224.0.0.22", tos=0xc0,
                   options=[IPOption(copy_flag=1, optclass="control",
                                     option="router_alert")]) /
                IGMPv3(type="Version 3 Membership Report") /
                IGMPv3mr(numgrp=1) /
                IGMPv3gr(rtype="Mode Is Include",
                         maddr="239.1.1.1", srcaddrs=["10.1.1.1", "10.1.1.2"]))

        self.send(self.pg0, p_cs)

        self.sleep(2)
        dump = self.vapi.igmp_dump(self.pg0.sw_if_index)
        self.assertEqual(len(dump), 2)
        self.assertTrue(find_igmp_state(dump, self.pg0,
                                        "239.1.1.1", "10.1.1.1"))
        self.assertTrue(find_igmp_state(dump, self.pg0,
                                        "239.1.1.1", "10.1.1.2"))

        #
        # wait for the per-source timer to expire
        # the state should be reaped
        #
        self.assertTrue(wait_for_igmp_event(self, 4, self.pg0,
                                            "239.1.1.1", "10.1.1.1", 0))
        self.assertTrue(wait_for_igmp_event(self, 1, self.pg0,
                                            "239.1.1.1", "10.1.1.2", 0))
        self.assertFalse(self.vapi.igmp_dump())

        #
        # resend the join, then a leave. Router sends a group+source
        # specific query containing both sources
        #
        self.send(self.pg0, p_j)

        self.assertTrue(wait_for_igmp_event(self, 1, self.pg0,
                                            "239.1.1.1", "10.1.1.1", 1))
        self.assertTrue(wait_for_igmp_event(self, 1, self.pg0,
                                            "239.1.1.1", "10.1.1.2", 1))
        dump = self.vapi.igmp_dump(self.pg0.sw_if_index)
        self.assertEqual(len(dump), 2)

        self.send(self.pg0, p_l)
        capture = self.pg0.get_capture(1, timeout=3)
        self.verify_group_query(capture[0], "239.1.1.1",
                                ["10.1.1.1", "10.1.1.2"])

        #
        # the group specific query drops the timeout to leave (=1) seconds
        #
        self.assertTrue(wait_for_igmp_event(self, 2, self.pg0,
                                            "239.1.1.1", "10.1.1.1", 0))
        self.assertTrue(wait_for_igmp_event(self, 1, self.pg0,
                                            "239.1.1.1", "10.1.1.2", 0))
        self.assertFalse(self.vapi.igmp_dump())
        self.assertFalse(self.vapi.igmp_dump())

        #
        # a TO_EX({}) / IN_EX({}) is treated like a (*,G) join
        #
        p_j = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
               IP(src=self.pg0.remote_ip4, dst="224.0.0.22", tos=0xc0, ttl=1,
                  options=[IPOption(copy_flag=1, optclass="control",
                                    option="router_alert")]) /
               IGMPv3(type="Version 3 Membership Report") /
               IGMPv3mr(numgrp=1) /
               IGMPv3gr(rtype="Change To Exclude Mode", maddr="239.1.1.2"))

        self.send(self.pg0, p_j)

        self.assertTrue(wait_for_igmp_event(self, 1, self.pg0,
                                            "239.1.1.2", "0.0.0.0", 1))

        p_j = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
               IP(src=self.pg0.remote_ip4, dst="224.0.0.22", tos=0xc0, ttl=1,
                  options=[IPOption(copy_flag=1, optclass="control",
                                    option="router_alert")]) /
               IGMPv3(type="Version 3 Membership Report") /
               IGMPv3mr(numgrp=1) /
               IGMPv3gr(rtype="Mode Is Exclude", maddr="239.1.1.3"))

        self.send(self.pg0, p_j)

        self.assertTrue(wait_for_igmp_event(self, 1, self.pg0,
                                            "239.1.1.3", "0.0.0.0", 1))

        #
        # A 'allow sources' for {} should be ignored as it should
        # never be sent.
        #
        p_j = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
               IP(src=self.pg0.remote_ip4, dst="224.0.0.22", tos=0xc0, ttl=1,
                  options=[IPOption(copy_flag=1, optclass="control",
                                    option="router_alert")]) /
               IGMPv3(type="Version 3 Membership Report") /
               IGMPv3mr(numgrp=1) /
               IGMPv3gr(rtype="Allow New Sources", maddr="239.1.1.4"))

        self.send(self.pg0, p_j)

        dump = self.vapi.igmp_dump(self.pg0.sw_if_index)
        self.assertTrue(find_igmp_state(dump, self.pg0,
                                        "239.1.1.2", "0.0.0.0"))
        self.assertTrue(find_igmp_state(dump, self.pg0,
                                        "239.1.1.3", "0.0.0.0"))
        self.assertFalse(find_igmp_state(dump, self.pg0,
                                         "239.1.1.4", "0.0.0.0"))

        #
        # a TO_IN({}) and IS_IN({}) are treated like a (*,G) leave
        #
        self.vapi.cli("set logging class igmp level debug")
        p_l = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
               IP(src=self.pg0.remote_ip4, dst="224.0.0.22", tos=0xc0, ttl=1,
                  options=[IPOption(copy_flag=1, optclass="control",
                                    option="router_alert")]) /
               IGMPv3(type="Version 3 Membership Report") /
               IGMPv3mr(numgrp=1) /
               IGMPv3gr(rtype="Change To Include Mode", maddr="239.1.1.2"))

        self.send(self.pg0, p_l)
        self.assertTrue(wait_for_igmp_event(self, 2, self.pg0,
                                            "239.1.1.2", "0.0.0.0", 0))

        p_l = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
               IP(src=self.pg0.remote_ip4, dst="224.0.0.22", tos=0xc0, ttl=1,
                  options=[IPOption(copy_flag=1, optclass="control",
                                    option="router_alert")]) /
               IGMPv3(type="Version 3 Membership Report") /
               IGMPv3mr(numgrp=1) /
               IGMPv3gr(rtype="Mode Is Include", maddr="239.1.1.3"))

        self.send(self.pg0, p_l)

        self.assertTrue(wait_for_igmp_event(self, 2, self.pg0,
                                            "239.1.1.3", "0.0.0.0", 0))
        self.assertFalse(self.vapi.igmp_dump(self.pg0.sw_if_index))

        #
        # disable router config
        #
        self.vapi.igmp_enable_disable(self.pg0.sw_if_index,
                                      0,
                                      IGMP_MODE.ROUTER)

    def _create_igmpv3_pck(self, itf, rtype, maddr, srcaddrs):
        p = (Ether(dst=itf.local_mac, src=itf.remote_mac) /
             IP(src=itf.remote_ip4, dst="224.0.0.22", tos=0xc0, ttl=1,
                options=[IPOption(copy_flag=1, optclass="control",
                                  option="router_alert")]) /
             IGMPv3(type="Version 3 Membership Report") /
             IGMPv3mr(numgrp=1) /
             IGMPv3gr(rtype=rtype,
                      maddr=maddr, srcaddrs=srcaddrs))
        return p

    def test_igmp_proxy_device(self):
        """ IGMP proxy device """
        self.pg2.admin_down()
        self.pg2.unconfig_ip4()
        self.pg2.set_table_ip4(0)
        self.pg2.config_ip4()
        self.pg2.admin_up()

        self.vapi.cli('test igmp timers query 10 src 3 leave 1')

        # enable IGMP
        self.vapi.igmp_enable_disable(self.pg0.sw_if_index, 1, IGMP_MODE.HOST)
        self.vapi.igmp_enable_disable(self.pg1.sw_if_index, 1,
                                      IGMP_MODE.ROUTER)
        self.vapi.igmp_enable_disable(self.pg2.sw_if_index, 1,
                                      IGMP_MODE.ROUTER)

        # create IGMP proxy device
        self.vapi.igmp_proxy_device_add_del(0, self.pg0.sw_if_index, 1)
        self.vapi.igmp_proxy_device_add_del_interface(0,
                                                      self.pg1.sw_if_index, 1)
        self.vapi.igmp_proxy_device_add_del_interface(0,
                                                      self.pg2.sw_if_index, 1)

        # send join on pg1. join should be proxied by pg0
        p_j = self._create_igmpv3_pck(self.pg1, "Allow New Sources",
                                      "239.1.1.1", ["10.1.1.1", "10.1.1.2"])
        self.send(self.pg1, p_j)

        capture = self.pg0.get_capture(1, timeout=1)
        self.verify_report(capture[0], [IgmpRecord(IgmpSG("239.1.1.1",
                           ["10.1.1.1", "10.1.1.2"]), "Allow New Sources")])
        self.assertTrue(find_mroute(self, "239.1.1.1", "0.0.0.0", 32))

        # send join on pg2. join should be proxied by pg0.
        # the group should contain only 10.1.1.3 as
        # 10.1.1.1 was already reported
        p_j = self._create_igmpv3_pck(self.pg2, "Allow New Sources",
                                      "239.1.1.1", ["10.1.1.1", "10.1.1.3"])
        self.send(self.pg2, p_j)

        capture = self.pg0.get_capture(1, timeout=1)
        self.verify_report(capture[0], [IgmpRecord(IgmpSG("239.1.1.1",
                           ["10.1.1.3"]), "Allow New Sources")])
        self.assertTrue(find_mroute(self, "239.1.1.1", "0.0.0.0", 32))

        # send leave on pg2. leave for 10.1.1.3 should be proxyed
        # as pg2 was the only interface interested in 10.1.1.3
        p_l = self._create_igmpv3_pck(self.pg2, "Block Old Sources",
                                      "239.1.1.1", ["10.1.1.3"])
        self.send(self.pg2, p_l)

        capture = self.pg0.get_capture(1, timeout=2)
        self.verify_report(capture[0], [IgmpRecord(IgmpSG("239.1.1.1",
                           ["10.1.1.3"]), "Block Old Sources")])
        self.assertTrue(find_mroute(self, "239.1.1.1", "0.0.0.0", 32))

        # disable igmp on pg1 (also removes interface from proxy device)
        # proxy leave for 10.1.1.2. pg2 is still interested in 10.1.1.1
        self.pg_enable_capture(self.pg_interfaces)
        self.vapi.igmp_enable_disable(self.pg1.sw_if_index, 0,
                                      IGMP_MODE.ROUTER)

        capture = self.pg0.get_capture(1, timeout=1)
        self.verify_report(capture[0], [IgmpRecord(IgmpSG("239.1.1.1",
                           ["10.1.1.2"]), "Block Old Sources")])
        self.assertTrue(find_mroute(self, "239.1.1.1", "0.0.0.0", 32))

        # disable IGMP on pg0 and pg1.
        #   disabling IGMP on pg0 (proxy device upstream interface)
        #   removes this proxy device
        self.vapi.igmp_enable_disable(self.pg0.sw_if_index, 0, IGMP_MODE.HOST)
        self.vapi.igmp_enable_disable(self.pg2.sw_if_index, 0,
                                      IGMP_MODE.ROUTER)
        self.assertFalse(find_mroute(self, "239.1.1.1", "0.0.0.0", 32))


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
