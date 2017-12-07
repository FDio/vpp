#!/usr/bin/env python

import unittest
from socket import AF_INET, AF_INET6, inet_pton

from framework import VppTestCase, VppTestRunner
from vpp_neighbor import VppNeighbor, find_nbr
from vpp_ip_route import VppIpRoute, VppRoutePath, find_route, \
    VppIpTable

from scapy.packet import Raw
from scapy.layers.l2 import Ether, ARP, Dot1Q
from scapy.layers.inet import IP, UDP
from scapy.contrib.mpls import MPLS

# not exported by scapy, so redefined here
arp_opts = {"who-has": 1, "is-at": 2}


class ARPTestCase(VppTestCase):
    """ ARP Test Case """

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

    def send_and_assert_no_replies(self, intf, pkts, remark):
        intf.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        timeout = 1
        for i in self.pg_interfaces:
            i.get_capture(0, timeout=timeout)
            i.assert_nothing_captured(remark=remark)
            timeout = 0.1

    def test_arp(self):
        """ ARP """

        #
        # Generate some hosts on the LAN
        #
        self.pg1.generate_remote_hosts(11)

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
        # Add a hierachy of routes for a host in the sub-net.
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
        #   2b - to a prxied address
        #   2c - not within a differents interface's sub-net
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
        #      the router
        #
        p = (Ether(dst="ff:ff:ff:ff:ff:ff", src=self.pg0.remote_mac) /
             ARP(op="who-has",
                 hwsrc="00:00:00:DE:AD:BE",
                 psrc=self.pg0.remote_ip4,
                 pdst=self.pg0.local_ip4))
        self.send_and_assert_no_replies(self.pg0, p,
                                        "ARP req for non-local source")

        #
        # cleanup
        #
        dyn_arp.remove_vpp_config()
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
        self.vapi.proxy_arp_add_del(self.pg0._local_ip4n_subnet,
                                    self.pg0._local_ip4n_bcast)

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
        self.pg2.add_stream(arp_req_from_me)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg2.get_capture(1)
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
        # cleanup
        #
        self.pg2.set_proxy_arp(0)
        self.vapi.proxy_arp_add_del(self.pg0._local_ip4n_subnet,
                                    self.pg0._local_ip4n_bcast,
                                    is_add=0)

    def test_proxy_arp(self):
        """ Proxy ARP """

        self.pg1.generate_remote_hosts(2)

        #
        # Proxy ARP rewquest packets for each interface
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
        self.vapi.proxy_arp_add_del(inet_pton(AF_INET, "10.10.10.2"),
                                    inet_pton(AF_INET, "10.10.10.124"))

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
        # Add a reoute with out going label via an ARP unresolved next-hop
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
             Raw('\xa5' * 100))

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

        self.pg0.add_stream(p0)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx1 = self.pg1.get_capture(1)

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

        self.pg1.add_stream(p1)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        #
        # IP packet destined for pg1 remote host arrives on pg0 again.
        # VPP should have an ARP entry for that address now and the packet
        # should be sent out pg1.
        #
        self.pg0.add_stream(p0)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx1 = self.pg1.get_capture(1)

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
        # packet stream shoud generate ARPs out of pg1
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
        self.pg2.set_table_ip4(0)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
