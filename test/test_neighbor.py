#!/usr/bin/env python3

import unittest
import os
from socket import AF_INET, AF_INET6, inet_pton

from framework import VppTestCase, VppTestRunner
from vpp_neighbor import VppNeighbor, find_nbr
from vpp_ip_route import VppIpRoute, VppRoutePath, find_route, \
    VppIpTable, DpoProto, FibPathType
from vpp_papi import VppEnum
from vpp_ip import VppIpPuntRedirect

import scapy.compat
from scapy.packet import Raw
from scapy.layers.l2 import Ether, ARP, Dot1Q
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.inet6 import IPv6
from scapy.contrib.mpls import MPLS
from scapy.layers.inet6 import IPv6


NUM_PKTS = 67

# not exported by scapy, so redefined here
arp_opts = {"who-has": 1, "is-at": 2}


class ARPTestCase(VppTestCase):
    """ ARP Test Case """

    @classmethod
    def setUpClass(cls):
        super(ARPTestCase, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(ARPTestCase, cls).tearDownClass()

    def setUp(self):
        super(ARPTestCase, self).setUp()

        # create 3 pg interfaces
        self.create_pg_interfaces(range(4))

        # pg0 configured with ip4 and 6 addresses used for input
        # pg1 configured with ip4 and 6 addresses used for output
        # pg2 is unnumbered to pg0
        for i in self.pg_interfaces:
            i.admin_up()

        self.pg0.config_ip4()
        self.pg0.config_ip6()
        self.pg0.resolve_arp()

        self.pg1.config_ip4()
        self.pg1.config_ip6()

        # pg3 in a different VRF
        self.tbl = VppIpTable(self, 1)
        self.tbl.add_vpp_config()

        self.pg3.set_table_ip4(1)
        self.pg3.config_ip4()

    def tearDown(self):
        self.pg0.unconfig_ip4()
        self.pg0.unconfig_ip6()

        self.pg1.unconfig_ip4()
        self.pg1.unconfig_ip6()

        self.pg3.unconfig_ip4()
        self.pg3.set_table_ip4(0)

        for i in self.pg_interfaces:
            i.admin_down()

        super(ARPTestCase, self).tearDown()

    def verify_arp_req(self, rx, smac, sip, dip):
        ether = rx[Ether]
        self.assertEqual(ether.dst, "ff:ff:ff:ff:ff:ff")
        self.assertEqual(ether.src, smac)

        arp = rx[ARP]
        self.assertEqual(arp.hwtype, 1)
        self.assertEqual(arp.ptype, 0x800)
        self.assertEqual(arp.hwlen, 6)
        self.assertEqual(arp.plen, 4)
        self.assertEqual(arp.op, arp_opts["who-has"])
        self.assertEqual(arp.hwsrc, smac)
        self.assertEqual(arp.hwdst, "00:00:00:00:00:00")
        self.assertEqual(arp.psrc, sip)
        self.assertEqual(arp.pdst, dip)

    def verify_arp_resp(self, rx, smac, dmac, sip, dip):
        ether = rx[Ether]
        self.assertEqual(ether.dst, dmac)
        self.assertEqual(ether.src, smac)

        arp = rx[ARP]
        self.assertEqual(arp.hwtype, 1)
        self.assertEqual(arp.ptype, 0x800)
        self.assertEqual(arp.hwlen, 6)
        self.assertEqual(arp.plen, 4)
        self.assertEqual(arp.op, arp_opts["is-at"])
        self.assertEqual(arp.hwsrc, smac)
        self.assertEqual(arp.hwdst, dmac)
        self.assertEqual(arp.psrc, sip)
        self.assertEqual(arp.pdst, dip)

    def verify_arp_vrrp_resp(self, rx, smac, dmac, sip, dip):
        ether = rx[Ether]
        self.assertEqual(ether.dst, dmac)
        self.assertEqual(ether.src, smac)

        arp = rx[ARP]
        self.assertEqual(arp.hwtype, 1)
        self.assertEqual(arp.ptype, 0x800)
        self.assertEqual(arp.hwlen, 6)
        self.assertEqual(arp.plen, 4)
        self.assertEqual(arp.op, arp_opts["is-at"])
        self.assertNotEqual(arp.hwsrc, smac)
        self.assertTrue("00:00:5e:00:01" in arp.hwsrc or
                        "00:00:5E:00:01" in arp.hwsrc)
        self.assertEqual(arp.hwdst, dmac)
        self.assertEqual(arp.psrc, sip)
        self.assertEqual(arp.pdst, dip)

    def verify_ip(self, rx, smac, dmac, sip, dip):
        ether = rx[Ether]
        self.assertEqual(ether.dst, dmac)
        self.assertEqual(ether.src, smac)

        ip = rx[IP]
        self.assertEqual(ip.src, sip)
        self.assertEqual(ip.dst, dip)

    def verify_ip_o_mpls(self, rx, smac, dmac, label, sip, dip):
        ether = rx[Ether]
        self.assertEqual(ether.dst, dmac)
        self.assertEqual(ether.src, smac)

        mpls = rx[MPLS]
        self.assertTrue(mpls.label, label)

        ip = rx[IP]
        self.assertEqual(ip.src, sip)
        self.assertEqual(ip.dst, dip)

    def test_arp(self):
        """ ARP """

        #
        # Generate some hosts on the LAN
        #
        self.pg1.generate_remote_hosts(11)

        #
        # watch for:
        #  - all neighbour events
        #  - all neighbor events on pg1
        #  - neighbor events for host[1] on pg1
        #
        self.vapi.want_ip_neighbor_events(enable=1,
                                          pid=os.getpid())
        self.vapi.want_ip_neighbor_events(enable=1,
                                          pid=os.getpid(),
                                          sw_if_index=self.pg1.sw_if_index)
        self.vapi.want_ip_neighbor_events(enable=1,
                                          pid=os.getpid(),
                                          sw_if_index=self.pg1.sw_if_index,
                                          ip=self.pg1.remote_hosts[1].ip4)

        self.logger.info(self.vapi.cli("sh ip neighbor-watcher"))

        #
        # Send IP traffic to one of these unresolved hosts.
        #  expect the generation of an ARP request
        #
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1._remote_hosts[1].ip4) /
             UDP(sport=1234, dport=1234) /
             Raw())

        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg1.get_capture(1)

        self.verify_arp_req(rx[0],
                            self.pg1.local_mac,
                            self.pg1.local_ip4,
                            self.pg1._remote_hosts[1].ip4)

        #
        # And a dynamic ARP entry for host 1
        #
        dyn_arp = VppNeighbor(self,
                              self.pg1.sw_if_index,
                              self.pg1.remote_hosts[1].mac,
                              self.pg1.remote_hosts[1].ip4)
        dyn_arp.add_vpp_config()
        self.assertTrue(dyn_arp.query_vpp_config())

        self.logger.info(self.vapi.cli("show ip neighbor-watcher"))

        # this matches all of the listnerers
        es = [self.vapi.wait_for_event(1, "ip_neighbor_event")
              for i in range(3)]
        for e in es:
            self.assertEqual(str(e.neighbor.ip_address),
                             self.pg1.remote_hosts[1].ip4)

        #
        # now we expect IP traffic forwarded
        #
        dyn_p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                 IP(src=self.pg0.remote_ip4,
                    dst=self.pg1._remote_hosts[1].ip4) /
                 UDP(sport=1234, dport=1234) /
                 Raw())

        self.pg0.add_stream(dyn_p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg1.get_capture(1)

        self.verify_ip(rx[0],
                       self.pg1.local_mac,
                       self.pg1.remote_hosts[1].mac,
                       self.pg0.remote_ip4,
                       self.pg1._remote_hosts[1].ip4)

        #
        # And a Static ARP entry for host 2
        #
        static_arp = VppNeighbor(self,
                                 self.pg1.sw_if_index,
                                 self.pg1.remote_hosts[2].mac,
                                 self.pg1.remote_hosts[2].ip4,
                                 is_static=1)
        static_arp.add_vpp_config()
        es = [self.vapi.wait_for_event(1, "ip_neighbor_event")
              for i in range(2)]
        for e in es:
            self.assertEqual(str(e.neighbor.ip_address),
                             self.pg1.remote_hosts[2].ip4)

        static_p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                    IP(src=self.pg0.remote_ip4,
                       dst=self.pg1._remote_hosts[2].ip4) /
                    UDP(sport=1234, dport=1234) /
                    Raw())

        self.pg0.add_stream(static_p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg1.get_capture(1)

        self.verify_ip(rx[0],
                       self.pg1.local_mac,
                       self.pg1.remote_hosts[2].mac,
                       self.pg0.remote_ip4,
                       self.pg1._remote_hosts[2].ip4)

        #
        # remove all the listeners
        #
        self.vapi.want_ip_neighbor_events(enable=0,
                                          pid=os.getpid())
        self.vapi.want_ip_neighbor_events(enable=0,
                                          pid=os.getpid(),
                                          sw_if_index=self.pg1.sw_if_index)
        self.vapi.want_ip_neighbor_events(enable=0,
                                          pid=os.getpid(),
                                          sw_if_index=self.pg1.sw_if_index,
                                          ip=self.pg1.remote_hosts[1].ip4)

        #
        # flap the link. dynamic ARPs get flush, statics don't
        #
        self.pg1.admin_down()
        self.pg1.admin_up()

        self.pg0.add_stream(static_p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = self.pg1.get_capture(1)

        self.verify_ip(rx[0],
                       self.pg1.local_mac,
                       self.pg1.remote_hosts[2].mac,
                       self.pg0.remote_ip4,
                       self.pg1._remote_hosts[2].ip4)

        self.pg0.add_stream(dyn_p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg1.get_capture(1)
        self.verify_arp_req(rx[0],
                            self.pg1.local_mac,
                            self.pg1.local_ip4,
                            self.pg1._remote_hosts[1].ip4)

        self.assertFalse(dyn_arp.query_vpp_config())
        self.assertTrue(static_arp.query_vpp_config())
        #
        # Send an ARP request from one of the so-far unlearned remote hosts
        #
        p = (Ether(dst="ff:ff:ff:ff:ff:ff",
                   src=self.pg1._remote_hosts[3].mac) /
             ARP(op="who-has",
                 hwsrc=self.pg1._remote_hosts[3].mac,
                 pdst=self.pg1.local_ip4,
                 psrc=self.pg1._remote_hosts[3].ip4))

        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg1.get_capture(1)
        self.verify_arp_resp(rx[0],
                             self.pg1.local_mac,
                             self.pg1._remote_hosts[3].mac,
                             self.pg1.local_ip4,
                             self.pg1._remote_hosts[3].ip4)

        #
        # VPP should have learned the mapping for the remote host
        #
        self.assertTrue(find_nbr(self,
                                 self.pg1.sw_if_index,
                                 self.pg1._remote_hosts[3].ip4))
        #
        # Fire in an ARP request before the interface becomes IP enabled
        #
        self.pg2.generate_remote_hosts(4)

        p = (Ether(dst="ff:ff:ff:ff:ff:ff", src=self.pg2.remote_mac) /
             ARP(op="who-has",
                 hwsrc=self.pg2.remote_mac,
                 pdst=self.pg1.local_ip4,
                 psrc=self.pg2.remote_hosts[3].ip4))
        pt = (Ether(dst="ff:ff:ff:ff:ff:ff", src=self.pg2.remote_mac) /
              Dot1Q(vlan=0) /
              ARP(op="who-has",
                  hwsrc=self.pg2.remote_mac,
                  pdst=self.pg1.local_ip4,
                  psrc=self.pg2.remote_hosts[3].ip4))
        self.send_and_assert_no_replies(self.pg2, p,
                                        "interface not IP enabled")

        #
        # Make pg2 un-numbered to pg1
        #
        self.pg2.set_unnumbered(self.pg1.sw_if_index)

        #
        # test the unnumbered dump both by all interfaces and just the enabled
        # one
        #
        unnum = self.vapi.ip_unnumbered_dump()
        self.assertTrue(len(unnum))
        self.assertEqual(unnum[0].ip_sw_if_index, self.pg1.sw_if_index)
        self.assertEqual(unnum[0].sw_if_index, self.pg2.sw_if_index)
        unnum = self.vapi.ip_unnumbered_dump(self.pg2.sw_if_index)
        self.assertTrue(len(unnum))
        self.assertEqual(unnum[0].ip_sw_if_index, self.pg1.sw_if_index)
        self.assertEqual(unnum[0].sw_if_index, self.pg2.sw_if_index)

        #
        # We should respond to ARP requests for the unnumbered to address
        # once an attached route to the source is known
        #
        self.send_and_assert_no_replies(
            self.pg2, p,
            "ARP req for unnumbered address - no source")

        attached_host = VppIpRoute(self, self.pg2.remote_hosts[3].ip4, 32,
                                   [VppRoutePath("0.0.0.0",
                                                 self.pg2.sw_if_index)])
        attached_host.add_vpp_config()

        self.pg2.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg2.get_capture(1)
        self.verify_arp_resp(rx[0],
                             self.pg2.local_mac,
                             self.pg2.remote_mac,
                             self.pg1.local_ip4,
                             self.pg2.remote_hosts[3].ip4)

        self.pg2.add_stream(pt)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg2.get_capture(1)
        self.verify_arp_resp(rx[0],
                             self.pg2.local_mac,
                             self.pg2.remote_mac,
                             self.pg1.local_ip4,
                             self.pg2.remote_hosts[3].ip4)

        #
        # A neighbor entry that has no associated FIB-entry
        #
        arp_no_fib = VppNeighbor(self,
                                 self.pg1.sw_if_index,
                                 self.pg1.remote_hosts[4].mac,
                                 self.pg1.remote_hosts[4].ip4,
                                 is_no_fib_entry=1)
        arp_no_fib.add_vpp_config()

        #
        # check we have the neighbor, but no route
        #
        self.assertTrue(find_nbr(self,
                                 self.pg1.sw_if_index,
                                 self.pg1._remote_hosts[4].ip4))
        self.assertFalse(find_route(self,
                                    self.pg1._remote_hosts[4].ip4,
                                    32))
        #
        # pg2 is unnumbered to pg1, so we can form adjacencies out of pg2
        # from within pg1's subnet
        #
        arp_unnum = VppNeighbor(self,
                                self.pg2.sw_if_index,
                                self.pg1.remote_hosts[5].mac,
                                self.pg1.remote_hosts[5].ip4)
        arp_unnum.add_vpp_config()

        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=self.pg0.remote_ip4,
                dst=self.pg1._remote_hosts[5].ip4) /
             UDP(sport=1234, dport=1234) /
             Raw())

        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg2.get_capture(1)

        self.verify_ip(rx[0],
                       self.pg2.local_mac,
                       self.pg1.remote_hosts[5].mac,
                       self.pg0.remote_ip4,
                       self.pg1._remote_hosts[5].ip4)

        #
        # ARP requests from hosts in pg1's subnet sent on pg2 are replied to
        # with the unnumbered interface's address as the source
        #
        p = (Ether(dst="ff:ff:ff:ff:ff:ff", src=self.pg2.remote_mac) /
             ARP(op="who-has",
                 hwsrc=self.pg2.remote_mac,
                 pdst=self.pg1.local_ip4,
                 psrc=self.pg1.remote_hosts[6].ip4))

        self.pg2.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg2.get_capture(1)
        self.verify_arp_resp(rx[0],
                             self.pg2.local_mac,
                             self.pg2.remote_mac,
                             self.pg1.local_ip4,
                             self.pg1.remote_hosts[6].ip4)

        #
        # An attached host route out of pg2 for an undiscovered hosts generates
        # an ARP request with the unnumbered address as the source
        #
        att_unnum = VppIpRoute(self, self.pg1.remote_hosts[7].ip4, 32,
                               [VppRoutePath("0.0.0.0",
                                             self.pg2.sw_if_index)])
        att_unnum.add_vpp_config()

        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=self.pg0.remote_ip4,
                dst=self.pg1._remote_hosts[7].ip4) /
             UDP(sport=1234, dport=1234) /
             Raw())

        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg2.get_capture(1)

        self.verify_arp_req(rx[0],
                            self.pg2.local_mac,
                            self.pg1.local_ip4,
                            self.pg1._remote_hosts[7].ip4)

        p = (Ether(dst="ff:ff:ff:ff:ff:ff", src=self.pg2.remote_mac) /
             ARP(op="who-has",
                 hwsrc=self.pg2.remote_mac,
                 pdst=self.pg1.local_ip4,
                 psrc=self.pg1.remote_hosts[7].ip4))

        self.pg2.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg2.get_capture(1)
        self.verify_arp_resp(rx[0],
                             self.pg2.local_mac,
                             self.pg2.remote_mac,
                             self.pg1.local_ip4,
                             self.pg1.remote_hosts[7].ip4)

        #
        # An attached host route as yet unresolved out of pg2 for an
        # undiscovered host, an ARP requests begets a response.
        #
        att_unnum1 = VppIpRoute(self, self.pg1.remote_hosts[8].ip4, 32,
                                [VppRoutePath("0.0.0.0",
                                              self.pg2.sw_if_index)])
        att_unnum1.add_vpp_config()

        p = (Ether(dst="ff:ff:ff:ff:ff:ff", src=self.pg2.remote_mac) /
             ARP(op="who-has",
                 hwsrc=self.pg2.remote_mac,
                 pdst=self.pg1.local_ip4,
                 psrc=self.pg1.remote_hosts[8].ip4))

        self.pg2.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg2.get_capture(1)
        self.verify_arp_resp(rx[0],
                             self.pg2.local_mac,
                             self.pg2.remote_mac,
                             self.pg1.local_ip4,
                             self.pg1.remote_hosts[8].ip4)

        #
        # Send an ARP request from one of the so-far unlearned remote hosts
        # with a VLAN0 tag
        #
        p = (Ether(dst="ff:ff:ff:ff:ff:ff",
                   src=self.pg1._remote_hosts[9].mac) /
             Dot1Q(vlan=0) /
             ARP(op="who-has",
                 hwsrc=self.pg1._remote_hosts[9].mac,
                 pdst=self.pg1.local_ip4,
                 psrc=self.pg1._remote_hosts[9].ip4))

        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg1.get_capture(1)
        self.verify_arp_resp(rx[0],
                             self.pg1.local_mac,
                             self.pg1._remote_hosts[9].mac,
                             self.pg1.local_ip4,
                             self.pg1._remote_hosts[9].ip4)

        #
        # Add a hierarchy of routes for a host in the sub-net.
        # Should still get an ARP resp since the cover is attached
        #
        p = (Ether(dst="ff:ff:ff:ff:ff:ff", src=self.pg1.remote_mac) /
             ARP(op="who-has",
                 hwsrc=self.pg1.remote_mac,
                 pdst=self.pg1.local_ip4,
                 psrc=self.pg1.remote_hosts[10].ip4))

        r1 = VppIpRoute(self, self.pg1.remote_hosts[10].ip4, 30,
                        [VppRoutePath(self.pg1.remote_hosts[10].ip4,
                                      self.pg1.sw_if_index)])
        r1.add_vpp_config()

        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = self.pg1.get_capture(1)
        self.verify_arp_resp(rx[0],
                             self.pg1.local_mac,
                             self.pg1.remote_mac,
                             self.pg1.local_ip4,
                             self.pg1.remote_hosts[10].ip4)

        r2 = VppIpRoute(self, self.pg1.remote_hosts[10].ip4, 32,
                        [VppRoutePath(self.pg1.remote_hosts[10].ip4,
                                      self.pg1.sw_if_index)])
        r2.add_vpp_config()

        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = self.pg1.get_capture(1)
        self.verify_arp_resp(rx[0],
                             self.pg1.local_mac,
                             self.pg1.remote_mac,
                             self.pg1.local_ip4,
                             self.pg1.remote_hosts[10].ip4)

        #
        # add an ARP entry that's not on the sub-net and so whose
        # adj-fib fails the refinement check. then send an ARP request
        # from that source
        #
        a1 = VppNeighbor(self,
                         self.pg0.sw_if_index,
                         self.pg0.remote_mac,
                         "100.100.100.50")
        a1.add_vpp_config()

        p = (Ether(dst="ff:ff:ff:ff:ff:ff", src=self.pg0.remote_mac) /
             ARP(op="who-has",
                 hwsrc=self.pg0.remote_mac,
                 psrc="100.100.100.50",
                 pdst=self.pg0.remote_ip4))
        self.send_and_assert_no_replies(self.pg0, p,
                                        "ARP req for from failed adj-fib")

        #
        # ERROR Cases
        #  1 - don't respond to ARP request for address not within the
        #      interface's sub-net
        #  1b - nor within the unnumbered subnet
        #  1c - nor within the subnet of a different interface
        #
        p = (Ether(dst="ff:ff:ff:ff:ff:ff", src=self.pg0.remote_mac) /
             ARP(op="who-has",
                 hwsrc=self.pg0.remote_mac,
                 pdst="10.10.10.3",
                 psrc=self.pg0.remote_ip4))
        self.send_and_assert_no_replies(self.pg0, p,
                                        "ARP req for non-local destination")
        self.assertFalse(find_nbr(self,
                                  self.pg0.sw_if_index,
                                  "10.10.10.3"))

        p = (Ether(dst="ff:ff:ff:ff:ff:ff", src=self.pg2.remote_mac) /
             ARP(op="who-has",
                 hwsrc=self.pg2.remote_mac,
                 pdst="10.10.10.3",
                 psrc=self.pg1.remote_hosts[7].ip4))
        self.send_and_assert_no_replies(
            self.pg0, p,
            "ARP req for non-local destination - unnum")

        p = (Ether(dst="ff:ff:ff:ff:ff:ff", src=self.pg0.remote_mac) /
             ARP(op="who-has",
                 hwsrc=self.pg0.remote_mac,
                 pdst=self.pg1.local_ip4,
                 psrc=self.pg1.remote_ip4))
        self.send_and_assert_no_replies(self.pg0, p,
                                        "ARP req diff sub-net")
        self.assertFalse(find_nbr(self,
                                  self.pg0.sw_if_index,
                                  self.pg1.remote_ip4))

        #
        #  2 - don't respond to ARP request from an address not within the
        #      interface's sub-net
        #   2b - to a proxied address
        #   2c - not within a different interface's sub-net
        p = (Ether(dst="ff:ff:ff:ff:ff:ff", src=self.pg0.remote_mac) /
             ARP(op="who-has",
                 hwsrc=self.pg0.remote_mac,
                 psrc="10.10.10.3",
                 pdst=self.pg0.local_ip4))
        self.send_and_assert_no_replies(self.pg0, p,
                                        "ARP req for non-local source")
        p = (Ether(dst="ff:ff:ff:ff:ff:ff", src=self.pg2.remote_mac) /
             ARP(op="who-has",
                 hwsrc=self.pg2.remote_mac,
                 psrc="10.10.10.3",
                 pdst=self.pg0.local_ip4))
        self.send_and_assert_no_replies(
            self.pg0, p,
            "ARP req for non-local source - unnum")
        p = (Ether(dst="ff:ff:ff:ff:ff:ff", src=self.pg0.remote_mac) /
             ARP(op="who-has",
                 hwsrc=self.pg0.remote_mac,
                 psrc=self.pg1.remote_ip4,
                 pdst=self.pg0.local_ip4))
        self.send_and_assert_no_replies(self.pg0, p,
                                        "ARP req for non-local source 2c")

        #
        #  3 - don't respond to ARP request from an address that belongs to
        #      the router
        #
        p = (Ether(dst="ff:ff:ff:ff:ff:ff", src=self.pg0.remote_mac) /
             ARP(op="who-has",
                 hwsrc=self.pg0.remote_mac,
                 psrc=self.pg0.local_ip4,
                 pdst=self.pg0.local_ip4))
        self.send_and_assert_no_replies(self.pg0, p,
                                        "ARP req for non-local source")

        #
        #  4 - don't respond to ARP requests that has mac source different
        #      from ARP request HW source
        #
        p = (Ether(dst="ff:ff:ff:ff:ff:ff", src=self.pg0.remote_mac) /
             ARP(op="who-has",
                 hwsrc="00:00:00:DE:AD:BE",
                 psrc=self.pg0.remote_ip4,
                 pdst=self.pg0.local_ip4))
        self.send_and_assert_no_replies(self.pg0, p,
                                        "ARP req for non-local source")

        #
        #  5 - don't respond to ARP requests for address within the
        #      interface's sub-net but not the interface's address
        #
        self.pg0.generate_remote_hosts(2)
        p = (Ether(dst="ff:ff:ff:ff:ff:ff", src=self.pg0.remote_mac) /
             ARP(op="who-has",
                 hwsrc=self.pg0.remote_mac,
                 psrc=self.pg0.remote_hosts[0].ip4,
                 pdst=self.pg0.remote_hosts[1].ip4))
        self.send_and_assert_no_replies(self.pg0, p,
                                        "ARP req for non-local destination")

        #
        # cleanup
        #
        static_arp.remove_vpp_config()
        self.pg2.unset_unnumbered(self.pg1.sw_if_index)

        # need this to flush the adj-fibs
        self.pg2.unset_unnumbered(self.pg1.sw_if_index)
        self.pg2.admin_down()
        self.pg1.admin_down()

    def test_proxy_mirror_arp(self):
        """ Interface Mirror Proxy ARP """

        #
        # When VPP has an interface whose address is also applied to a TAP
        # interface on the host, then VPP's TAP interface will be unnumbered
        # to the 'real' interface and do proxy ARP from the host.
        # the curious aspect of this setup is that ARP requests from the host
        # will come from the VPP's own address.
        #
        self.pg0.generate_remote_hosts(2)

        arp_req_from_me = (Ether(src=self.pg2.remote_mac,
                                 dst="ff:ff:ff:ff:ff:ff") /
                           ARP(op="who-has",
                               hwsrc=self.pg2.remote_mac,
                               pdst=self.pg0.remote_hosts[1].ip4,
                               psrc=self.pg0.local_ip4))

        #
        # Configure Proxy ARP for the subnet on PG0addresses on pg0
        #
        self.vapi.proxy_arp_add_del(proxy={'table_id': 0,
                                           'low': self.pg0._local_ip4_subnet,
                                           'hi': self.pg0._local_ip4_bcast},
                                    is_add=1)

        # Make pg2 un-numbered to pg0
        #
        self.pg2.set_unnumbered(self.pg0.sw_if_index)

        #
        # Enable pg2 for proxy ARP
        #
        self.pg2.set_proxy_arp()

        #
        # Send the ARP request with an originating address that
        # is VPP's own address
        #
        rx = self.send_and_expect(self.pg2, [arp_req_from_me], self.pg2)
        self.verify_arp_resp(rx[0],
                             self.pg2.local_mac,
                             self.pg2.remote_mac,
                             self.pg0.remote_hosts[1].ip4,
                             self.pg0.local_ip4)

        #
        # validate we have not learned an ARP entry as a result of this
        #
        self.assertFalse(find_nbr(self,
                                  self.pg2.sw_if_index,
                                  self.pg0.local_ip4))

        #
        # setup a punt redirect so packets from the uplink go to the tap
        #
        redirect = VppIpPuntRedirect(self, self.pg0.sw_if_index,
                                     self.pg2.sw_if_index, self.pg0.local_ip4)
        redirect.add_vpp_config()

        p_tcp = (Ether(src=self.pg0.remote_mac,
                       dst=self.pg0.local_mac,) /
                 IP(src=self.pg0.remote_ip4,
                    dst=self.pg0.local_ip4) /
                 TCP(sport=80, dport=80) /
                 Raw())
        rx = self.send_and_expect(self.pg0, [p_tcp], self.pg2)

        # there's no ARP entry so this is an ARP req
        self.assertTrue(rx[0].haslayer(ARP))

        # and ARP entry for VPP's pg0 address on the host interface
        n1 = VppNeighbor(self,
                         self.pg2.sw_if_index,
                         self.pg2.remote_mac,
                         self.pg0.local_ip4,
                         is_no_fib_entry=True).add_vpp_config()
        # now the packets shold forward
        rx = self.send_and_expect(self.pg0, [p_tcp], self.pg2)
        self.assertFalse(rx[0].haslayer(ARP))
        self.assertEqual(rx[0][Ether].dst, self.pg2.remote_mac)

        #
        # flush the neighbor cache on the uplink
        #
        af = VppEnum.vl_api_address_family_t
        self.vapi.ip_neighbor_flush(af.ADDRESS_IP4, self.pg0.sw_if_index)

        # ensure we can still resolve the ARPs on the uplink
        self.pg0.resolve_arp()

        self.assertTrue(find_nbr(self,
                                 self.pg0.sw_if_index,
                                 self.pg0.remote_ip4))

        #
        # cleanup
        #
        self.vapi.proxy_arp_add_del(proxy={'table_id': 0,
                                           'low': self.pg0._local_ip4_subnet,
                                           'hi': self.pg0._local_ip4_bcast},
                                    is_add=0)
        redirect.remove_vpp_config()

    def test_proxy_arp(self):
        """ Proxy ARP """

        self.pg1.generate_remote_hosts(2)

        #
        # Proxy ARP request packets for each interface
        #
        arp_req_pg0 = (Ether(src=self.pg0.remote_mac,
                             dst="ff:ff:ff:ff:ff:ff") /
                       ARP(op="who-has",
                           hwsrc=self.pg0.remote_mac,
                           pdst="10.10.10.3",
                           psrc=self.pg0.remote_ip4))
        arp_req_pg0_tagged = (Ether(src=self.pg0.remote_mac,
                                    dst="ff:ff:ff:ff:ff:ff") /
                              Dot1Q(vlan=0) /
                              ARP(op="who-has",
                                  hwsrc=self.pg0.remote_mac,
                                  pdst="10.10.10.3",
                                  psrc=self.pg0.remote_ip4))
        arp_req_pg1 = (Ether(src=self.pg1.remote_mac,
                             dst="ff:ff:ff:ff:ff:ff") /
                       ARP(op="who-has",
                           hwsrc=self.pg1.remote_mac,
                           pdst="10.10.10.3",
                           psrc=self.pg1.remote_ip4))
        arp_req_pg2 = (Ether(src=self.pg2.remote_mac,
                             dst="ff:ff:ff:ff:ff:ff") /
                       ARP(op="who-has",
                           hwsrc=self.pg2.remote_mac,
                           pdst="10.10.10.3",
                           psrc=self.pg1.remote_hosts[1].ip4))
        arp_req_pg3 = (Ether(src=self.pg3.remote_mac,
                             dst="ff:ff:ff:ff:ff:ff") /
                       ARP(op="who-has",
                           hwsrc=self.pg3.remote_mac,
                           pdst="10.10.10.3",
                           psrc=self.pg3.remote_ip4))

        #
        # Configure Proxy ARP for 10.10.10.0 -> 10.10.10.124
        #
        self.vapi.proxy_arp_add_del(proxy={'table_id': 0,
                                           'low': "10.10.10.2",
                                           'hi': "10.10.10.124"},
                                    is_add=1)

        #
        # No responses are sent when the interfaces are not enabled for proxy
        # ARP
        #
        self.send_and_assert_no_replies(self.pg0, arp_req_pg0,
                                        "ARP req from unconfigured interface")
        self.send_and_assert_no_replies(self.pg2, arp_req_pg2,
                                        "ARP req from unconfigured interface")

        #
        # Make pg2 un-numbered to pg1
        #  still won't reply.
        #
        self.pg2.set_unnumbered(self.pg1.sw_if_index)

        self.send_and_assert_no_replies(self.pg2, arp_req_pg2,
                                        "ARP req from unnumbered interface")

        #
        # Enable each interface to reply to proxy ARPs
        #
        for i in self.pg_interfaces:
            i.set_proxy_arp()

        #
        # Now each of the interfaces should reply to a request to a proxied
        # address
        #
        self.pg0.add_stream(arp_req_pg0)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg0.get_capture(1)
        self.verify_arp_resp(rx[0],
                             self.pg0.local_mac,
                             self.pg0.remote_mac,
                             "10.10.10.3",
                             self.pg0.remote_ip4)

        self.pg0.add_stream(arp_req_pg0_tagged)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg0.get_capture(1)
        self.verify_arp_resp(rx[0],
                             self.pg0.local_mac,
                             self.pg0.remote_mac,
                             "10.10.10.3",
                             self.pg0.remote_ip4)

        self.pg1.add_stream(arp_req_pg1)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg1.get_capture(1)
        self.verify_arp_resp(rx[0],
                             self.pg1.local_mac,
                             self.pg1.remote_mac,
                             "10.10.10.3",
                             self.pg1.remote_ip4)

        self.pg2.add_stream(arp_req_pg2)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg2.get_capture(1)
        self.verify_arp_resp(rx[0],
                             self.pg2.local_mac,
                             self.pg2.remote_mac,
                             "10.10.10.3",
                             self.pg1.remote_hosts[1].ip4)

        #
        # A request for an address out of the configured range
        #
        arp_req_pg1_hi = (Ether(src=self.pg1.remote_mac,
                                dst="ff:ff:ff:ff:ff:ff") /
                          ARP(op="who-has",
                              hwsrc=self.pg1.remote_mac,
                              pdst="10.10.10.125",
                              psrc=self.pg1.remote_ip4))
        self.send_and_assert_no_replies(self.pg1, arp_req_pg1_hi,
                                        "ARP req out of range HI")
        arp_req_pg1_low = (Ether(src=self.pg1.remote_mac,
                                 dst="ff:ff:ff:ff:ff:ff") /
                           ARP(op="who-has",
                               hwsrc=self.pg1.remote_mac,
                               pdst="10.10.10.1",
                               psrc=self.pg1.remote_ip4))
        self.send_and_assert_no_replies(self.pg1, arp_req_pg1_low,
                                        "ARP req out of range Low")

        #
        # Request for an address in the proxy range but from an interface
        # in a different VRF
        #
        self.send_and_assert_no_replies(self.pg3, arp_req_pg3,
                                        "ARP req from different VRF")

        #
        # Disable Each interface for proxy ARP
        #  - expect none to respond
        #
        for i in self.pg_interfaces:
            i.set_proxy_arp(0)

        self.send_and_assert_no_replies(self.pg0, arp_req_pg0,
                                        "ARP req from disable")
        self.send_and_assert_no_replies(self.pg1, arp_req_pg1,
                                        "ARP req from disable")
        self.send_and_assert_no_replies(self.pg2, arp_req_pg2,
                                        "ARP req from disable")

        #
        # clean up on interface 2
        #
        self.pg2.unset_unnumbered(self.pg1.sw_if_index)

    def test_mpls(self):
        """ MPLS """

        #
        # Interface 2 does not yet have ip4 config
        #
        self.pg2.config_ip4()
        self.pg2.generate_remote_hosts(2)

        #
        # Add a route with out going label via an ARP unresolved next-hop
        #
        ip_10_0_0_1 = VppIpRoute(self, "10.0.0.1", 32,
                                 [VppRoutePath(self.pg2.remote_hosts[1].ip4,
                                               self.pg2.sw_if_index,
                                               labels=[55])])
        ip_10_0_0_1.add_vpp_config()

        #
        # packets should generate an ARP request
        #
        p = (Ether(src=self.pg0.remote_mac,
                   dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst="10.0.0.1") /
             UDP(sport=1234, dport=1234) /
             Raw(b'\xa5' * 100))

        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg2.get_capture(1)
        self.verify_arp_req(rx[0],
                            self.pg2.local_mac,
                            self.pg2.local_ip4,
                            self.pg2._remote_hosts[1].ip4)

        #
        # now resolve the neighbours
        #
        self.pg2.configure_ipv4_neighbors()

        #
        # Now packet should be properly MPLS encapped.
        #  This verifies that MPLS link-type adjacencies are completed
        #  when the ARP entry resolves
        #
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg2.get_capture(1)
        self.verify_ip_o_mpls(rx[0],
                              self.pg2.local_mac,
                              self.pg2.remote_hosts[1].mac,
                              55,
                              self.pg0.remote_ip4,
                              "10.0.0.1")
        self.pg2.unconfig_ip4()

    def test_arp_vrrp(self):
        """ ARP reply with VRRP virtual src hw addr """

        #
        # IP packet destined for pg1 remote host arrives on pg0 resulting
        # in an ARP request for the address of the remote host on pg1
        #
        p0 = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
              IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
              UDP(sport=1234, dport=1234) /
              Raw())

        rx1 = self.send_and_expect(self.pg0, [p0], self.pg1)

        self.verify_arp_req(rx1[0],
                            self.pg1.local_mac,
                            self.pg1.local_ip4,
                            self.pg1.remote_ip4)

        #
        # ARP reply for address of pg1 remote host arrives on pg1 with
        # the hw src addr set to a value in the VRRP IPv4 range of
        # MAC addresses
        #
        p1 = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
              ARP(op="is-at", hwdst=self.pg1.local_mac,
                  hwsrc="00:00:5e:00:01:09", pdst=self.pg1.local_ip4,
                  psrc=self.pg1.remote_ip4))

        self.send_and_assert_no_replies(self.pg1, p1, "ARP reply")

        #
        # IP packet destined for pg1 remote host arrives on pg0 again.
        # VPP should have an ARP entry for that address now and the packet
        # should be sent out pg1.
        #
        rx1 = self.send_and_expect(self.pg0, [p0], self.pg1)

        self.verify_ip(rx1[0],
                       self.pg1.local_mac,
                       "00:00:5e:00:01:09",
                       self.pg0.remote_ip4,
                       self.pg1.remote_ip4)

        self.pg1.admin_down()
        self.pg1.admin_up()

    def test_arp_duplicates(self):
        """ ARP Duplicates"""

        #
        # Generate some hosts on the LAN
        #
        self.pg1.generate_remote_hosts(3)

        #
        # Add host 1 on pg1 and pg2
        #
        arp_pg1 = VppNeighbor(self,
                              self.pg1.sw_if_index,
                              self.pg1.remote_hosts[1].mac,
                              self.pg1.remote_hosts[1].ip4)
        arp_pg1.add_vpp_config()
        arp_pg2 = VppNeighbor(self,
                              self.pg2.sw_if_index,
                              self.pg2.remote_mac,
                              self.pg1.remote_hosts[1].ip4)
        arp_pg2.add_vpp_config()

        #
        # IP packet destined for pg1 remote host arrives on pg1 again.
        #
        p = (Ether(dst=self.pg0.local_mac,
                   src=self.pg0.remote_mac) /
             IP(src=self.pg0.remote_ip4,
                dst=self.pg1.remote_hosts[1].ip4) /
             UDP(sport=1234, dport=1234) /
             Raw())

        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx1 = self.pg1.get_capture(1)

        self.verify_ip(rx1[0],
                       self.pg1.local_mac,
                       self.pg1.remote_hosts[1].mac,
                       self.pg0.remote_ip4,
                       self.pg1.remote_hosts[1].ip4)

        #
        # remove the duplicate on pg1
        # packet stream should generate ARPs out of pg1
        #
        arp_pg1.remove_vpp_config()

        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx1 = self.pg1.get_capture(1)

        self.verify_arp_req(rx1[0],
                            self.pg1.local_mac,
                            self.pg1.local_ip4,
                            self.pg1.remote_hosts[1].ip4)

        #
        # Add it back
        #
        arp_pg1.add_vpp_config()

        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx1 = self.pg1.get_capture(1)

        self.verify_ip(rx1[0],
                       self.pg1.local_mac,
                       self.pg1.remote_hosts[1].mac,
                       self.pg0.remote_ip4,
                       self.pg1.remote_hosts[1].ip4)

    def test_arp_static(self):
        """ ARP Static"""
        self.pg2.generate_remote_hosts(3)

        #
        # Add a static ARP entry
        #
        static_arp = VppNeighbor(self,
                                 self.pg2.sw_if_index,
                                 self.pg2.remote_hosts[1].mac,
                                 self.pg2.remote_hosts[1].ip4,
                                 is_static=1)
        static_arp.add_vpp_config()

        #
        # Add the connected prefix to the interface
        #
        self.pg2.config_ip4()

        #
        # We should now find the adj-fib
        #
        self.assertTrue(find_nbr(self,
                                 self.pg2.sw_if_index,
                                 self.pg2.remote_hosts[1].ip4,
                                 is_static=1))
        self.assertTrue(find_route(self,
                                   self.pg2.remote_hosts[1].ip4,
                                   32))

        #
        # remove the connected
        #
        self.pg2.unconfig_ip4()

        #
        # put the interface into table 1
        #
        self.pg2.set_table_ip4(1)

        #
        # configure the same connected and expect to find the
        # adj fib in the new table
        #
        self.pg2.config_ip4()
        self.assertTrue(find_route(self,
                                   self.pg2.remote_hosts[1].ip4,
                                   32,
                                   table_id=1))

        #
        # clean-up
        #
        self.pg2.unconfig_ip4()
        static_arp.remove_vpp_config()
        self.pg2.set_table_ip4(0)

    def test_arp_static_replace_dynamic_same_mac(self):
        """ ARP Static can replace Dynamic (same mac) """
        self.pg2.generate_remote_hosts(1)

        dyn_arp = VppNeighbor(self,
                              self.pg2.sw_if_index,
                              self.pg2.remote_hosts[0].mac,
                              self.pg2.remote_hosts[0].ip4)
        static_arp = VppNeighbor(self,
                                 self.pg2.sw_if_index,
                                 self.pg2.remote_hosts[0].mac,
                                 self.pg2.remote_hosts[0].ip4,
                                 is_static=1)

        #
        # Add a dynamic ARP entry
        #
        dyn_arp.add_vpp_config()

        #
        # We should find the dynamic nbr
        #
        self.assertFalse(find_nbr(self,
                                  self.pg2.sw_if_index,
                                  self.pg2.remote_hosts[0].ip4,
                                  is_static=1))
        self.assertTrue(find_nbr(self,
                                 self.pg2.sw_if_index,
                                 self.pg2.remote_hosts[0].ip4,
                                 is_static=0,
                                 mac=self.pg2.remote_hosts[0].mac))

        #
        # Add a static ARP entry with the same mac
        #
        static_arp.add_vpp_config()

        #
        # We should now find the static nbr with the same mac
        #
        self.assertFalse(find_nbr(self,
                                  self.pg2.sw_if_index,
                                  self.pg2.remote_hosts[0].ip4,
                                  is_static=0))
        self.assertTrue(find_nbr(self,
                                 self.pg2.sw_if_index,
                                 self.pg2.remote_hosts[0].ip4,
                                 is_static=1,
                                 mac=self.pg2.remote_hosts[0].mac))

        #
        # clean-up
        #
        static_arp.remove_vpp_config()

    def test_arp_static_replace_dynamic_diff_mac(self):
        """ ARP Static can replace Dynamic (diff mac) """
        self.pg2.generate_remote_hosts(2)

        dyn_arp = VppNeighbor(self,
                              self.pg2.sw_if_index,
                              self.pg2.remote_hosts[0].mac,
                              self.pg2.remote_hosts[0].ip4)
        static_arp = VppNeighbor(self,
                                 self.pg2.sw_if_index,
                                 self.pg2.remote_hosts[1].mac,
                                 self.pg2.remote_hosts[0].ip4,
                                 is_static=1)

        #
        # Add a dynamic ARP entry
        #
        dyn_arp.add_vpp_config()

        #
        # We should find the dynamic nbr
        #
        self.assertFalse(find_nbr(self,
                                  self.pg2.sw_if_index,
                                  self.pg2.remote_hosts[0].ip4,
                                  is_static=1))
        self.assertTrue(find_nbr(self,
                                 self.pg2.sw_if_index,
                                 self.pg2.remote_hosts[0].ip4,
                                 is_static=0,
                                 mac=self.pg2.remote_hosts[0].mac))

        #
        # Add a static ARP entry with a changed mac
        #
        static_arp.add_vpp_config()

        #
        # We should now find the static nbr with a changed mac
        #
        self.assertFalse(find_nbr(self,
                                  self.pg2.sw_if_index,
                                  self.pg2.remote_hosts[0].ip4,
                                  is_static=0))
        self.assertTrue(find_nbr(self,
                                 self.pg2.sw_if_index,
                                 self.pg2.remote_hosts[0].ip4,
                                 is_static=1,
                                 mac=self.pg2.remote_hosts[1].mac))

        #
        # clean-up
        #
        static_arp.remove_vpp_config()

    def test_arp_incomplete(self):
        """ ARP Incomplete"""
        self.pg1.generate_remote_hosts(3)

        p0 = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
              IP(src=self.pg0.remote_ip4,
                 dst=self.pg1.remote_hosts[1].ip4) /
              UDP(sport=1234, dport=1234) /
              Raw())
        p1 = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
              IP(src=self.pg0.remote_ip4,
                 dst=self.pg1.remote_hosts[2].ip4) /
              UDP(sport=1234, dport=1234) /
              Raw())

        #
        # a packet to an unresolved destination generates an ARP request
        #
        rx = self.send_and_expect(self.pg0, [p0], self.pg1)
        self.verify_arp_req(rx[0],
                            self.pg1.local_mac,
                            self.pg1.local_ip4,
                            self.pg1._remote_hosts[1].ip4)

        #
        # add a neighbour for remote host 1
        #
        static_arp = VppNeighbor(self,
                                 self.pg1.sw_if_index,
                                 self.pg1.remote_hosts[1].mac,
                                 self.pg1.remote_hosts[1].ip4,
                                 is_static=1)
        static_arp.add_vpp_config()

        #
        # change the interface's MAC
        #
        self.vapi.sw_interface_set_mac_address(self.pg1.sw_if_index,
                                               "00:00:00:33:33:33")

        #
        # now ARP requests come from the new source mac
        #
        rx = self.send_and_expect(self.pg0, [p1], self.pg1)
        self.verify_arp_req(rx[0],
                            "00:00:00:33:33:33",
                            self.pg1.local_ip4,
                            self.pg1._remote_hosts[2].ip4)

        #
        # packets to the resolved host also have the new source mac
        #
        rx = self.send_and_expect(self.pg0, [p0], self.pg1)
        self.verify_ip(rx[0],
                       "00:00:00:33:33:33",
                       self.pg1.remote_hosts[1].mac,
                       self.pg0.remote_ip4,
                       self.pg1.remote_hosts[1].ip4)

        #
        # set the mac address on the interface that does not have a
        # configured subnet and thus no glean
        #
        self.vapi.sw_interface_set_mac_address(self.pg2.sw_if_index,
                                               "00:00:00:33:33:33")

    def test_garp(self):
        """ GARP """

        #
        # Generate some hosts on the LAN
        #
        self.pg1.generate_remote_hosts(4)
        self.pg2.generate_remote_hosts(4)

        #
        # And an ARP entry
        #
        arp = VppNeighbor(self,
                          self.pg1.sw_if_index,
                          self.pg1.remote_hosts[1].mac,
                          self.pg1.remote_hosts[1].ip4)
        arp.add_vpp_config()

        self.assertTrue(find_nbr(self,
                                 self.pg1.sw_if_index,
                                 self.pg1.remote_hosts[1].ip4,
                                 mac=self.pg1.remote_hosts[1].mac))

        #
        # Send a GARP (request) to swap the host 1's address to that of host 2
        #
        p1 = (Ether(dst="ff:ff:ff:ff:ff:ff",
                    src=self.pg1.remote_hosts[2].mac) /
              ARP(op="who-has",
                  hwdst=self.pg1.local_mac,
                  hwsrc=self.pg1.remote_hosts[2].mac,
                  pdst=self.pg1.remote_hosts[1].ip4,
                  psrc=self.pg1.remote_hosts[1].ip4))

        self.pg1.add_stream(p1)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        self.assertTrue(find_nbr(self,
                                 self.pg1.sw_if_index,
                                 self.pg1.remote_hosts[1].ip4,
                                 mac=self.pg1.remote_hosts[2].mac))

        #
        # Send a GARP (reply) to swap the host 1's address to that of host 3
        #
        p1 = (Ether(dst="ff:ff:ff:ff:ff:ff",
                    src=self.pg1.remote_hosts[3].mac) /
              ARP(op="is-at",
                  hwdst=self.pg1.local_mac,
                  hwsrc=self.pg1.remote_hosts[3].mac,
                  pdst=self.pg1.remote_hosts[1].ip4,
                  psrc=self.pg1.remote_hosts[1].ip4))

        self.pg1.add_stream(p1)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        self.assertTrue(find_nbr(self,
                                 self.pg1.sw_if_index,
                                 self.pg1.remote_hosts[1].ip4,
                                 mac=self.pg1.remote_hosts[3].mac))

        #
        # GARPs (request nor replies) for host we don't know yet
        # don't result in new neighbour entries
        #
        p1 = (Ether(dst="ff:ff:ff:ff:ff:ff",
                    src=self.pg1.remote_hosts[3].mac) /
              ARP(op="who-has",
                  hwdst=self.pg1.local_mac,
                  hwsrc=self.pg1.remote_hosts[3].mac,
                  pdst=self.pg1.remote_hosts[2].ip4,
                  psrc=self.pg1.remote_hosts[2].ip4))

        self.pg1.add_stream(p1)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        self.assertFalse(find_nbr(self,
                                  self.pg1.sw_if_index,
                                  self.pg1.remote_hosts[2].ip4))

        p1 = (Ether(dst="ff:ff:ff:ff:ff:ff",
                    src=self.pg1.remote_hosts[3].mac) /
              ARP(op="is-at",
                  hwdst=self.pg1.local_mac,
                  hwsrc=self.pg1.remote_hosts[3].mac,
                  pdst=self.pg1.remote_hosts[2].ip4,
                  psrc=self.pg1.remote_hosts[2].ip4))

        self.pg1.add_stream(p1)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        self.assertFalse(find_nbr(self,
                                  self.pg1.sw_if_index,
                                  self.pg1.remote_hosts[2].ip4))

        #
        # IP address in different subnets are not learnt
        #
        self.pg2.configure_ipv4_neighbors()

        for op in ["is-at", "who-has"]:
            p1 = [(Ether(dst="ff:ff:ff:ff:ff:ff",
                         src=self.pg2.remote_hosts[1].mac) /
                   ARP(op=op,
                       hwdst=self.pg2.local_mac,
                       hwsrc=self.pg2.remote_hosts[1].mac,
                       pdst=self.pg2.remote_hosts[1].ip4,
                       psrc=self.pg2.remote_hosts[1].ip4)),
                  (Ether(dst="ff:ff:ff:ff:ff:ff",
                         src=self.pg2.remote_hosts[1].mac) /
                   ARP(op=op,
                       hwdst="ff:ff:ff:ff:ff:ff",
                       hwsrc=self.pg2.remote_hosts[1].mac,
                       pdst=self.pg2.remote_hosts[1].ip4,
                       psrc=self.pg2.remote_hosts[1].ip4))]

            self.send_and_assert_no_replies(self.pg1, p1)
            self.assertFalse(find_nbr(self,
                                      self.pg1.sw_if_index,
                                      self.pg2.remote_hosts[1].ip4))

        # they are all dropped because the subnet's don't match
        self.assertEqual(4, self.statistics.get_err_counter(
            "/err/arp-reply/IP4 destination address not local to subnet"))

    def test_arp_incomplete2(self):
        """ Incomplete Entries """

        #
        # ensure that we throttle the ARP and ND requests
        #
        self.pg0.generate_remote_hosts(2)

        #
        # IPv4/ARP
        #
        ip_10_0_0_1 = VppIpRoute(self, "10.0.0.1", 32,
                                 [VppRoutePath(self.pg0.remote_hosts[1].ip4,
                                               self.pg0.sw_if_index)])
        ip_10_0_0_1.add_vpp_config()

        p1 = (Ether(dst=self.pg1.local_mac,
                    src=self.pg1.remote_mac) /
              IP(src=self.pg1.remote_ip4,
                 dst="10.0.0.1") /
              UDP(sport=1234, dport=1234) /
              Raw())

        self.pg1.add_stream(p1 * 257)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = self.pg0._get_capture(1)

        #
        # how many we get is going to be dependent on the time for packet
        # processing but it should be small
        #
        self.assertLess(len(rx), 64)

        #
        # IPv6/ND
        #
        ip_10_1 = VppIpRoute(self, "10::1", 128,
                             [VppRoutePath(self.pg0.remote_hosts[1].ip6,
                                           self.pg0.sw_if_index,
                                           proto=DpoProto.DPO_PROTO_IP6)])
        ip_10_1.add_vpp_config()

        p1 = (Ether(dst=self.pg1.local_mac,
                    src=self.pg1.remote_mac) /
              IPv6(src=self.pg1.remote_ip6,
                   dst="10::1") /
              UDP(sport=1234, dport=1234) /
              Raw())

        self.pg1.add_stream(p1 * 257)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = self.pg0._get_capture(1)

        #
        # how many we get is going to be dependent on the time for packet
        # processing but it should be small
        #
        self.assertLess(len(rx), 64)

    def test_arp_forus(self):
        """ ARP for for-us """

        #
        # Test that VPP responds with ARP requests to addresses that
        # are connected and local routes.
        # Use one of the 'remote' addresses in the subnet as a local address
        # The intention of this route is that it then acts like a secondary
        # address added to an interface
        #
        self.pg0.generate_remote_hosts(2)

        forus = VppIpRoute(
            self, self.pg0.remote_hosts[1].ip4, 32,
            [VppRoutePath("0.0.0.0",
                          self.pg0.sw_if_index,
                          type=FibPathType.FIB_PATH_TYPE_LOCAL)])
        forus.add_vpp_config()

        p = (Ether(dst="ff:ff:ff:ff:ff:ff",
                   src=self.pg0.remote_mac) /
             ARP(op="who-has",
                 hwdst=self.pg0.local_mac,
                 hwsrc=self.pg0.remote_mac,
                 pdst=self.pg0.remote_hosts[1].ip4,
                 psrc=self.pg0.remote_ip4))

        rx = self.send_and_expect(self.pg0, [p], self.pg0)

        self.verify_arp_resp(rx[0],
                             self.pg0.local_mac,
                             self.pg0.remote_mac,
                             self.pg0.remote_hosts[1].ip4,
                             self.pg0.remote_ip4)

    def test_arp_table_swap(self):
        #
        # Generate some hosts on the LAN
        #
        N_NBRS = 4
        self.pg1.generate_remote_hosts(N_NBRS)

        for n in range(N_NBRS):
            # a route thru each neighbour
            VppIpRoute(self, "10.0.0.%d" % n, 32,
                       [VppRoutePath(self.pg1.remote_hosts[n].ip4,
                                     self.pg1.sw_if_index)]).add_vpp_config()

            # resolve each neighbour
            p1 = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
                  ARP(op="is-at", hwdst=self.pg1.local_mac,
                      hwsrc="00:00:5e:00:01:09", pdst=self.pg1.local_ip4,
                      psrc=self.pg1.remote_hosts[n].ip4))

            self.send_and_assert_no_replies(self.pg1, p1, "ARP reply")

        self.logger.info(self.vapi.cli("sh ip neighbors"))

        #
        # swap the table pg1 is in
        #
        table = VppIpTable(self, 100).add_vpp_config()

        self.pg1.unconfig_ip4()
        self.pg1.set_table_ip4(100)
        self.pg1.config_ip4()

        #
        # all neighbours are cleared
        #
        for n in range(N_NBRS):
            self.assertFalse(find_nbr(self,
                                      self.pg1.sw_if_index,
                                      self.pg1.remote_hosts[n].ip4))

        #
        # packets to all neighbours generate ARP requests
        #
        for n in range(N_NBRS):
            # a route thru each neighbour
            VppIpRoute(self, "10.0.0.%d" % n, 32,
                       [VppRoutePath(self.pg1.remote_hosts[n].ip4,
                                     self.pg1.sw_if_index)],
                       table_id=100).add_vpp_config()

            p = (Ether(src=self.pg1.remote_hosts[n].mac,
                       dst=self.pg1.local_mac) /
                 IP(src=self.pg1.remote_hosts[n].ip4,
                    dst="10.0.0.%d" % n) /
                 Raw(b'0x5' * 100))
            rxs = self.send_and_expect(self.pg1, [p], self.pg1)
            for rx in rxs:
                self.verify_arp_req(rx,
                                    self.pg1.local_mac,
                                    self.pg1.local_ip4,
                                    self.pg1.remote_hosts[n].ip4)

        self.pg1.unconfig_ip4()
        self.pg1.set_table_ip4(0)


class NeighborStatsTestCase(VppTestCase):
    """ ARP/ND Counters """

    @classmethod
    def setUpClass(cls):
        super(NeighborStatsTestCase, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(NeighborStatsTestCase, cls).tearDownClass()

    def setUp(self):
        super(NeighborStatsTestCase, self).setUp()

        self.create_pg_interfaces(range(2))

        # pg0 configured with ip4 and 6 addresses used for input
        # pg1 configured with ip4 and 6 addresses used for output
        # pg2 is unnumbered to pg0
        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.config_ip6()
            i.resolve_arp()
            i.resolve_ndp()

    def tearDown(self):
        super(NeighborStatsTestCase, self).tearDown()

        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.admin_down()

    def test_arp_stats(self):
        """ ARP Counters """

        self.vapi.cli("adj counters enable")
        self.pg1.generate_remote_hosts(2)

        arp1 = VppNeighbor(self,
                           self.pg1.sw_if_index,
                           self.pg1.remote_hosts[0].mac,
                           self.pg1.remote_hosts[0].ip4)
        arp1.add_vpp_config()
        arp2 = VppNeighbor(self,
                           self.pg1.sw_if_index,
                           self.pg1.remote_hosts[1].mac,
                           self.pg1.remote_hosts[1].ip4)
        arp2.add_vpp_config()

        p1 = (Ether(dst=self.pg0.local_mac,
                    src=self.pg0.remote_mac) /
              IP(src=self.pg0.remote_ip4,
                 dst=self.pg1.remote_hosts[0].ip4) /
              UDP(sport=1234, dport=1234) /
              Raw())
        p2 = (Ether(dst=self.pg0.local_mac,
                    src=self.pg0.remote_mac) /
              IP(src=self.pg0.remote_ip4,
                 dst=self.pg1.remote_hosts[1].ip4) /
              UDP(sport=1234, dport=1234) /
              Raw())

        rx = self.send_and_expect(self.pg0, p1 * NUM_PKTS, self.pg1)
        rx = self.send_and_expect(self.pg0, p2 * NUM_PKTS, self.pg1)

        self.assertEqual(NUM_PKTS, arp1.get_stats()['packets'])
        self.assertEqual(NUM_PKTS, arp2.get_stats()['packets'])

        rx = self.send_and_expect(self.pg0, p1 * NUM_PKTS, self.pg1)
        self.assertEqual(NUM_PKTS*2, arp1.get_stats()['packets'])

    def test_nd_stats(self):
        """ ND Counters """

        self.vapi.cli("adj counters enable")
        self.pg0.generate_remote_hosts(3)

        nd1 = VppNeighbor(self,
                          self.pg0.sw_if_index,
                          self.pg0.remote_hosts[1].mac,
                          self.pg0.remote_hosts[1].ip6)
        nd1.add_vpp_config()
        nd2 = VppNeighbor(self,
                          self.pg0.sw_if_index,
                          self.pg0.remote_hosts[2].mac,
                          self.pg0.remote_hosts[2].ip6)
        nd2.add_vpp_config()

        p1 = (Ether(dst=self.pg1.local_mac,
                    src=self.pg1.remote_mac) /
              IPv6(src=self.pg1.remote_ip6,
                   dst=self.pg0.remote_hosts[1].ip6) /
              UDP(sport=1234, dport=1234) /
              Raw())
        p2 = (Ether(dst=self.pg1.local_mac,
                    src=self.pg1.remote_mac) /
              IPv6(src=self.pg1.remote_ip6,
                   dst=self.pg0.remote_hosts[2].ip6) /
              UDP(sport=1234, dport=1234) /
              Raw())

        rx = self.send_and_expect(self.pg1, p1 * 16, self.pg0)
        rx = self.send_and_expect(self.pg1, p2 * 16, self.pg0)

        self.assertEqual(16, nd1.get_stats()['packets'])
        self.assertEqual(16, nd2.get_stats()['packets'])

        rx = self.send_and_expect(self.pg1, p1 * NUM_PKTS, self.pg0)
        self.assertEqual(NUM_PKTS+16, nd1.get_stats()['packets'])


class NeighborAgeTestCase(VppTestCase):
    """ ARP/ND Aging """

    @classmethod
    def setUpClass(cls):
        super(NeighborAgeTestCase, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(NeighborAgeTestCase, cls).tearDownClass()

    def setUp(self):
        super(NeighborAgeTestCase, self).setUp()

        self.create_pg_interfaces(range(1))

        # pg0 configured with ip4 and 6 addresses used for input
        # pg1 configured with ip4 and 6 addresses used for output
        # pg2 is unnumbered to pg0
        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.config_ip6()
            i.resolve_arp()
            i.resolve_ndp()

    def tearDown(self):
        super(NeighborAgeTestCase, self).tearDown()

        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.admin_down()

    def wait_for_no_nbr(self, intf, address,
                        n_tries=50, s_time=1):
        while (n_tries):
            if not find_nbr(self, intf, address):
                return True
            n_tries = n_tries - 1
            self.sleep(s_time)

        return False

    def verify_arp_req(self, rx, smac, sip, dip):
        ether = rx[Ether]
        self.assertEqual(ether.dst, "ff:ff:ff:ff:ff:ff")
        self.assertEqual(ether.src, smac)

        arp = rx[ARP]
        self.assertEqual(arp.hwtype, 1)
        self.assertEqual(arp.ptype, 0x800)
        self.assertEqual(arp.hwlen, 6)
        self.assertEqual(arp.plen, 4)
        self.assertEqual(arp.op, arp_opts["who-has"])
        self.assertEqual(arp.hwsrc, smac)
        self.assertEqual(arp.hwdst, "00:00:00:00:00:00")
        self.assertEqual(arp.psrc, sip)
        self.assertEqual(arp.pdst, dip)

    def test_age(self):
        """ Aging/Recycle """

        self.vapi.cli("set logging unthrottle 0")
        self.vapi.cli("set logging size %d" % 0xffff)

        self.pg0.generate_remote_hosts(201)

        vaf = VppEnum.vl_api_address_family_t

        #
        # start listening on all interfaces
        #
        self.pg_enable_capture(self.pg_interfaces)

        #
        # Set the neighbor configuration:
        #   limi = 200
        #   age  = 0 seconds
        #   recycle = false
        #
        self.vapi.ip_neighbor_config(af=vaf.ADDRESS_IP4,
                                     max_number=200,
                                     max_age=0,
                                     recycle=False)

        self.vapi.cli("sh ip neighbor-config")

        # add the 198 neighbours that should pass (-1 for one created in setup)
        for ii in range(200):
            VppNeighbor(self,
                        self.pg0.sw_if_index,
                        self.pg0.remote_hosts[ii].mac,
                        self.pg0.remote_hosts[ii].ip4).add_vpp_config()

        # one more neighbor over the limit should fail
        with self.vapi.assert_negative_api_retval():
            VppNeighbor(self,
                        self.pg0.sw_if_index,
                        self.pg0.remote_hosts[200].mac,
                        self.pg0.remote_hosts[200].ip4).add_vpp_config()

        #
        # change the config to allow recycling the old neighbors
        #
        self.vapi.ip_neighbor_config(af=vaf.ADDRESS_IP4,
                                     max_number=200,
                                     max_age=0,
                                     recycle=True)

        # now new additions are allowed
        VppNeighbor(self,
                    self.pg0.sw_if_index,
                    self.pg0.remote_hosts[200].mac,
                    self.pg0.remote_hosts[200].ip4).add_vpp_config()

        # add the first neighbor we configured has been re-used
        self.assertFalse(find_nbr(self,
                                  self.pg0.sw_if_index,
                                  self.pg0.remote_hosts[0].ip4))
        self.assertTrue(find_nbr(self,
                                 self.pg0.sw_if_index,
                                 self.pg0.remote_hosts[200].ip4))

        #
        # change the config to age old neighbors
        #
        self.vapi.ip_neighbor_config(af=vaf.ADDRESS_IP4,
                                     max_number=200,
                                     max_age=2,
                                     recycle=True)

        self.vapi.cli("sh ip4 neighbor-sorted")

        #
        # expect probes from all these ARP entries as they age
        # 3 probes for each neighbor 3*200 = 600
        rxs = self.pg0.get_capture(600, timeout=8)

        for ii in range(3):
            for jj in range(200):
                rx = rxs[ii*200 + jj]
                # rx.show()

        #
        # 3 probes sent then 1 more second to see if a reply comes, before
        # they age out
        #
        for jj in range(1, 201):
            self.wait_for_no_nbr(self.pg0.sw_if_index,
                                 self.pg0.remote_hosts[jj].ip4)

        self.assertFalse(self.vapi.ip_neighbor_dump(sw_if_index=0xffffffff,
                                                    af=vaf.ADDRESS_IP4))

        #
        # load up some neighbours again with 2s aging enabled
        # they should be removed after 10s (2s age + 4s for probes + gap)
        # check for the add and remove events
        #
        enum = VppEnum.vl_api_ip_neighbor_event_flags_t

        self.vapi.want_ip_neighbor_events_v2(enable=1)
        for ii in range(10):
            VppNeighbor(self,
                        self.pg0.sw_if_index,
                        self.pg0.remote_hosts[ii].mac,
                        self.pg0.remote_hosts[ii].ip4).add_vpp_config()

            e = self.vapi.wait_for_event(1, "ip_neighbor_event_v2")
            self.assertEqual(e.flags,
                             enum.IP_NEIGHBOR_API_EVENT_FLAG_ADDED)
            self.assertEqual(str(e.neighbor.ip_address),
                             self.pg0.remote_hosts[ii].ip4)
            self.assertEqual(e.neighbor.mac_address,
                             self.pg0.remote_hosts[ii].mac)

        self.sleep(10)
        self.assertFalse(self.vapi.ip_neighbor_dump(sw_if_index=0xffffffff,
                                                    af=vaf.ADDRESS_IP4))

        evs = []
        for ii in range(10):
            e = self.vapi.wait_for_event(1, "ip_neighbor_event_v2")
            self.assertEqual(e.flags,
                             enum.IP_NEIGHBOR_API_EVENT_FLAG_REMOVED)
            evs.append(e)

        # check we got the correct mac/ip pairs - done separately
        # because we don't care about the order the remove notifications
        # arrive
        for ii in range(10):
            found = False
            mac = self.pg0.remote_hosts[ii].mac
            ip = self.pg0.remote_hosts[ii].ip4

            for e in evs:
                if (e.neighbor.mac_address == mac and
                   str(e.neighbor.ip_address) == ip):
                    found = True
                    break
            self.assertTrue(found)

        #
        # check if we can set age and recycle with empty neighbor list
        #
        self.vapi.ip_neighbor_config(af=vaf.ADDRESS_IP4,
                                     max_number=200,
                                     max_age=1000,
                                     recycle=True)

        #
        # load up some neighbours again, then disable the aging
        # they should still be there in 10 seconds time
        #
        for ii in range(10):
            VppNeighbor(self,
                        self.pg0.sw_if_index,
                        self.pg0.remote_hosts[ii].mac,
                        self.pg0.remote_hosts[ii].ip4).add_vpp_config()
        self.vapi.ip_neighbor_config(af=vaf.ADDRESS_IP4,
                                     max_number=200,
                                     max_age=0,
                                     recycle=False)

        self.sleep(10)
        self.assertTrue(find_nbr(self,
                                 self.pg0.sw_if_index,
                                 self.pg0.remote_hosts[0].ip4))


class NeighborReplaceTestCase(VppTestCase):
    """ ARP/ND Replacement """

    @classmethod
    def setUpClass(cls):
        super(NeighborReplaceTestCase, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(NeighborReplaceTestCase, cls).tearDownClass()

    def setUp(self):
        super(NeighborReplaceTestCase, self).setUp()

        self.create_pg_interfaces(range(4))

        # pg0 configured with ip4 and 6 addresses used for input
        # pg1 configured with ip4 and 6 addresses used for output
        # pg2 is unnumbered to pg0
        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.config_ip6()
            i.resolve_arp()
            i.resolve_ndp()

    def tearDown(self):
        super(NeighborReplaceTestCase, self).tearDown()

        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.admin_down()

    def test_replace(self):
        """ replace """

        N_HOSTS = 16

        for i in self.pg_interfaces:
            i.generate_remote_hosts(N_HOSTS)
            i.configure_ipv4_neighbors()
            i.configure_ipv6_neighbors()

        # replace them all
        self.vapi.ip_neighbor_replace_begin()
        self.vapi.ip_neighbor_replace_end()

        for i in self.pg_interfaces:
            for h in range(N_HOSTS):
                self.assertFalse(find_nbr(self,
                                          self.pg0.sw_if_index,
                                          self.pg0.remote_hosts[h].ip4))
                self.assertFalse(find_nbr(self,
                                          self.pg0.sw_if_index,
                                          self.pg0.remote_hosts[h].ip6))

        #
        # and them all back via the API
        #
        for i in self.pg_interfaces:
            for h in range(N_HOSTS):
                VppNeighbor(self,
                            i.sw_if_index,
                            i.remote_hosts[h].mac,
                            i.remote_hosts[h].ip4).add_vpp_config()
                VppNeighbor(self,
                            i.sw_if_index,
                            i.remote_hosts[h].mac,
                            i.remote_hosts[h].ip6).add_vpp_config()

        #
        # begin the replacement again, this time touch some
        # the neighbours on pg1 so they are not deleted
        #
        self.vapi.ip_neighbor_replace_begin()

        # update from the API all neighbours on pg1
        for h in range(N_HOSTS):
            VppNeighbor(self,
                        self.pg1.sw_if_index,
                        self.pg1.remote_hosts[h].mac,
                        self.pg1.remote_hosts[h].ip4).add_vpp_config()
            VppNeighbor(self,
                        self.pg1.sw_if_index,
                        self.pg1.remote_hosts[h].mac,
                        self.pg1.remote_hosts[h].ip6).add_vpp_config()

        # update from the data-plane all neighbours on pg3
        self.pg3.configure_ipv4_neighbors()
        self.pg3.configure_ipv6_neighbors()

        # complete the replacement
        self.logger.info(self.vapi.cli("sh ip neighbors"))
        self.vapi.ip_neighbor_replace_end()

        for i in self.pg_interfaces:
            if i == self.pg1 or i == self.pg3:
                # neighbours on pg1 and pg3 are still present
                for h in range(N_HOSTS):
                    self.assertTrue(find_nbr(self,
                                             i.sw_if_index,
                                             i.remote_hosts[h].ip4))
                    self.assertTrue(find_nbr(self,
                                             i.sw_if_index,
                                             i.remote_hosts[h].ip6))
            else:
                # all other neighbours are toast
                for h in range(N_HOSTS):
                    self.assertFalse(find_nbr(self,
                                              i.sw_if_index,
                                              i.remote_hosts[h].ip4))
                    self.assertFalse(find_nbr(self,
                                              i.sw_if_index,
                                              i.remote_hosts[h].ip6))


class NeighborFlush(VppTestCase):
    """ Neighbor Flush """

    @classmethod
    def setUpClass(cls):
        super(NeighborFlush, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(NeighborFlush, cls).tearDownClass()

    def setUp(self):
        super(NeighborFlush, self).setUp()

        self.create_pg_interfaces(range(2))

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.config_ip6()
            i.resolve_arp()
            i.resolve_ndp()

    def tearDown(self):
        super(NeighborFlush, self).tearDown()

        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.admin_down()

    def test_flush(self):
        """ Neighbour Flush """

        e = VppEnum
        nf = e.vl_api_ip_neighbor_flags_t
        af = e.vl_api_address_family_t
        N_HOSTS = 16
        static = [False, True]
        self.pg0.generate_remote_hosts(N_HOSTS)
        self.pg1.generate_remote_hosts(N_HOSTS)

        for s in static:
            # a few v4 and v6 dynamic neoghbors
            for n in range(N_HOSTS):
                VppNeighbor(self,
                            self.pg0.sw_if_index,
                            self.pg0.remote_hosts[n].mac,
                            self.pg0.remote_hosts[n].ip4,
                            is_static=s).add_vpp_config()
                VppNeighbor(self,
                            self.pg1.sw_if_index,
                            self.pg1.remote_hosts[n].mac,
                            self.pg1.remote_hosts[n].ip6,
                            is_static=s).add_vpp_config()

            # flush the interfaces individually
            self.vapi.ip_neighbor_flush(af.ADDRESS_IP4, self.pg0.sw_if_index)

            # check we haven't flushed that which we shouldn't
            for n in range(N_HOSTS):
                self.assertTrue(find_nbr(self,
                                         self.pg1.sw_if_index,
                                         self.pg1.remote_hosts[n].ip6,
                                         is_static=s))

            self.vapi.ip_neighbor_flush(af.ADDRESS_IP6, self.pg1.sw_if_index)

            for n in range(N_HOSTS):
                self.assertFalse(find_nbr(self,
                                          self.pg0.sw_if_index,
                                          self.pg0.remote_hosts[n].ip4))
                self.assertFalse(find_nbr(self,
                                          self.pg1.sw_if_index,
                                          self.pg1.remote_hosts[n].ip6))

            # add the nieghbours back
            for n in range(N_HOSTS):
                VppNeighbor(self,
                            self.pg0.sw_if_index,
                            self.pg0.remote_hosts[n].mac,
                            self.pg0.remote_hosts[n].ip4,
                            is_static=s).add_vpp_config()
                VppNeighbor(self,
                            self.pg1.sw_if_index,
                            self.pg1.remote_hosts[n].mac,
                            self.pg1.remote_hosts[n].ip6,
                            is_static=s).add_vpp_config()

            self.logger.info(self.vapi.cli("sh ip neighbor"))

            # flush both interfaces at the same time
            self.vapi.ip_neighbor_flush(af.ADDRESS_IP6, 0xffffffff)

            # check we haven't flushed that which we shouldn't
            for n in range(N_HOSTS):
                self.assertTrue(find_nbr(self,
                                         self.pg0.sw_if_index,
                                         self.pg0.remote_hosts[n].ip4,
                                         is_static=s))

            self.vapi.ip_neighbor_flush(af.ADDRESS_IP4, 0xffffffff)

            for n in range(N_HOSTS):
                self.assertFalse(find_nbr(self,
                                          self.pg0.sw_if_index,
                                          self.pg0.remote_hosts[n].ip4))
                self.assertFalse(find_nbr(self,
                                          self.pg1.sw_if_index,
                                          self.pg1.remote_hosts[n].ip6))


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
