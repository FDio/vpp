#!/usr/bin/env python

import unittest
from socket import AF_INET, AF_INET6, inet_pton

from framework import VppTestCase, VppTestRunner
from vpp_neighbor import VppNeighbor, find_nbr
from vpp_ip_route import VppIpRoute, VppRoutePath, find_route

from scapy.packet import Raw
from scapy.layers.l2 import Ether, ARP
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
        self.pg3.set_table_ip4(1)
        self.pg3.config_ip4()

    def tearDown(self):
        super(ARPTestCase, self).tearDown()
        self.pg0.unconfig_ip4()
        self.pg0.unconfig_ip6()

        self.pg1.unconfig_ip4()
        self.pg1.unconfig_ip6()

        self.pg3.unconfig_ip4()

        for i in self.pg_interfaces:
            i.admin_down()

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
        for i in self.pg_interfaces:
            i.assert_nothing_captured(remark=remark)

    def test_arp(self):
        """ ARP """

        #
        # Generate some hosts on the LAN
        #
        self.pg1.generate_remote_hosts(9)

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
        # ERROR Cases
        #  1 - don't respond to ARP request for address not within the
        #      interface's sub-net
        #  1a - nor within the unnumbered subnet
        p = (Ether(dst="ff:ff:ff:ff:ff:ff", src=self.pg0.remote_mac) /
             ARP(op="who-has",
                 hwsrc=self.pg0.remote_mac,
                 pdst="10.10.10.3",
                 psrc=self.pg0.remote_ip4))
        self.send_and_assert_no_replies(self.pg0, p,
                                        "ARP req for non-local destination")
        p = (Ether(dst="ff:ff:ff:ff:ff:ff", src=self.pg2.remote_mac) /
             ARP(op="who-has",
                 hwsrc=self.pg2.remote_mac,
                 pdst="10.10.10.3",
                 psrc=self.pg1.remote_hosts[7].ip4))
        self.send_and_assert_no_replies(
            self.pg0, p,
            "ARP req for non-local destination - unnum")

        #
        #  2 - don't respond to ARP request from an address not within the
        #      interface's sub-net
        #
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

    def test_proxy_arp(self):
        """ Proxy ARP """

        #
        # Proxy ARP rewquest packets for each interface
        #
        arp_req_pg2 = (Ether(src=self.pg2.remote_mac,
                             dst="ff:ff:ff:ff:ff:ff") /
                       ARP(op="who-has",
                           hwsrc=self.pg2.remote_mac,
                           pdst="10.10.10.3",
                           psrc=self.pg1.remote_ip4))
        arp_req_pg0 = (Ether(src=self.pg0.remote_mac,
                             dst="ff:ff:ff:ff:ff:ff") /
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
                             self.pg1.remote_ip4)

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

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
