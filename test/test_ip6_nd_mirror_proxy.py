#!/usr/bin/env python3

import unittest
import os
from socket import AF_INET6, inet_pton, inet_ntop

from framework import tag_fixme_vpp_workers
from framework import VppTestCase, VppTestRunner
from vpp_neighbor import VppNeighbor, find_nbr
from vpp_ip_route import (
    VppIpRoute,
    VppRoutePath,
    find_route,
    VppIpTable,
    DpoProto,
    FibPathType,
    VppIpInterfaceAddress,
)
from vpp_papi import VppEnum
from vpp_ip import VppIpPuntRedirect

import scapy.compat
from scapy.packet import Raw
from scapy.layers.l2 import Ether, ARP, Dot1Q
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.inet6 import (
    IPv6,
    ipv6nh,
    ICMPv6ND_NS,
    ICMPv6ND_NA,
    ICMPv6NDOptSrcLLAddr,
    ICMPv6NDOptDstLLAddr,
    ICMPv6EchoRequest,
    ICMPv6EchoReply,
)
from scapy.utils6 import in6_ptop, in6_getnsma, in6_getnsmac, in6_ismaddr


class TestNDPROXY(VppTestCase):
    """IP6 ND (mirror) Proxy Test Case"""

    @classmethod
    def setUpClass(self):
        super(TestNDPROXY, self).setUpClass()
        self.create_pg_interfaces(range(2))

    @classmethod
    def tearDownClass(self):
        super(TestNDPROXY, self).tearDownClass()

    def setUp(self):
        super(TestNDPROXY, self).setUp()
        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip6()
            i.disable_ipv6_ra()

    def tearDown(self):
        super(TestNDPROXY, self).tearDown()
        if not self.vpp_dead:
            for i in self.pg_interfaces:
                i.unconfig_ip6()
                i.admin_down()

    def test_nd_mirror_proxy(self):
        """Interface (Mirror) Proxy ND"""

        #
        # When VPP has an interface whose address is also applied to a TAP
        # interface on the host, then VPP's TAP interface will be unnumbered
        # to the 'real' interface and do proxy ND from the host.
        # the curious aspect of this setup is that ND requests from the host
        # will come from the VPP's own address.
        #
        addr = self.pg0.remote_ip6
        nsma = in6_getnsma(inet_pton(socket.AF_INET6, addr))
        d = inet_ntop(socket.AF_INET6, nsma)

        # Make pg1 un-numbered to pg0
        #
        self.pg1.unconfig_ip6()
        self.pg1.set_unnumbered(self.pg0.sw_if_index)

        #
        # Enable ND proxy on pg1
        #
        self.vapi.ip6nd_proxy_enable_disable(
            sw_if_index=self.pg1.sw_if_index, is_enable=1
        )
        #
        # Send the ND request with an originating address that
        # is VPP's own address
        #
        nd_req_from_host = (
            Ether(src=self.pg1.remote_mac, dst=in6_getnsmac(nsma))
            / IPv6(dst=d, src=self.pg0.local_ip6)
            / ICMPv6ND_NS(tgt=addr)
            / ICMPv6NDOptSrcLLAddr(lladdr=self.pg1.remote_mac)
        )

        rx = self.send_and_expect(self.pg1, [nd_req_from_host], self.pg1)
        self.assertEqual(rx[0][Ether].src, self.pg1.local_mac)
        self.assertEqual(rx[0][Ether].dst, self.pg1.remote_mac)
        self.assertEqual(rx[0][IPv6].src, self.pg0.remote_ip6)
        self.assertEqual(rx[0][IPv6].dst, self.pg0.local_ip6)
        self.assertEqual(ipv6nh[rx[0][IPv6].nh], "ICMPv6")
        self.assertEqual(rx[0][ICMPv6ND_NA].tgt, self.pg0.remote_ip6)
        self.assertTrue(rx[0].haslayer(ICMPv6NDOptDstLLAddr))
        self.assertEqual(rx[0][ICMPv6NDOptDstLLAddr].lladdr, self.pg1.local_mac)

        #
        # Send the unicast ND request
        #
        unicast_nd_req_from_host = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IPv6(dst=self.pg0.remote_ip6, src=self.pg1.remote_ip6_ll)
            / ICMPv6ND_NS(tgt=self.pg0.remote_ip6)
            / ICMPv6NDOptSrcLLAddr(lladdr=self.pg1.remote_mac)
        )

        rx = self.send_and_expect(self.pg1, [unicast_nd_req_from_host], self.pg0)
        self.assertEqual(rx[0][Ether].src, self.pg0.local_mac)
        self.assertEqual(rx[0][Ether].dst, in6_getnsmac(nsma))
        self.assertEqual(rx[0][IPv6].src, self.pg0.local_ip6)
        self.assertEqual(rx[0][IPv6].dst, d)
        self.assertEqual(ipv6nh[rx[0][IPv6].nh], "ICMPv6")
        self.assertEqual(rx[0][ICMPv6ND_NS].tgt, self.pg0.remote_ip6)
        self.assertTrue(rx[0].haslayer(ICMPv6NDOptSrcLLAddr))
        self.assertEqual(rx[0][ICMPv6NDOptSrcLLAddr].lladdr, self.pg0.local_mac)

        # Resolve the NDs on the uplink
        self.pg0.resolve_ndp()

        #
        # Again send the unicast ND request, this time dst address should be
        # in local cache
        #
        rx = self.send_and_expect(self.pg1, [unicast_nd_req_from_host], self.pg1)
        self.assertEqual(rx[0][Ether].src, self.pg1.local_mac)
        self.assertEqual(rx[0][Ether].dst, self.pg1.remote_mac)
        self.assertEqual(rx[0][IPv6].src, self.pg0.remote_ip6)
        self.assertEqual(in6_ptop(rx[0][IPv6].dst), in6_ptop(self.pg1.remote_ip6_ll))
        self.assertEqual(ipv6nh[rx[0][IPv6].nh], "ICMPv6")
        self.assertEqual(rx[0][ICMPv6ND_NA].tgt, self.pg0.remote_ip6)
        self.assertTrue(rx[0].haslayer(ICMPv6NDOptDstLLAddr))
        self.assertEqual(rx[0][ICMPv6NDOptDstLLAddr].lladdr, self.pg1.local_mac)

        #
        # Send the Echo Request from host to remote (of uplink)
        #
        id = self.pg1.sw_if_index
        seq = 0x1
        echo_request = (
            Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac)
            / IPv6(dst=self.pg0.remote_ip6, src=self.pg0.local_ip6)
            / ICMPv6EchoRequest(seq=seq, id=id)
        )

        rx = self.send_and_expect(self.pg1, [echo_request], self.pg0)
        self.assertEqual(rx[0][Ether].src, self.pg0.local_mac)
        self.assertEqual(rx[0][Ether].dst, self.pg0.remote_mac)
        self.assertEqual(rx[0][IPv6].src, self.pg0.local_ip6)
        self.assertEqual(rx[0][IPv6].dst, self.pg0.remote_ip6)
        self.assertEqual(ipv6nh[rx[0][IPv6].nh], "ICMPv6")
        self.assertTrue(rx[0].haslayer(ICMPv6EchoRequest))
        self.assertEqual(rx[0][ICMPv6EchoRequest].id, id)
        self.assertEqual(rx[0][ICMPv6EchoRequest].seq, seq)

        #
        # setup a punt redirect so packets from the uplink go to the tap
        #
        redirect = VppIpPuntRedirect(
            self, self.pg0.sw_if_index, self.pg1.sw_if_index, self.pg0.local_ip6
        )
        redirect.add_vpp_config()

        echo_reply = (
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / IPv6(dst=self.pg0.local_ip6, src=self.pg0.remote_ip6)
            / ICMPv6EchoReply(seq=1, id=id)
        )

        rx = self.send_and_expect(self.pg0, [echo_reply], self.pg1)
        self.assertEqual(rx[0][Ether].src, self.pg1.local_mac)
        self.assertEqual(rx[0][Ether].dst, self.pg1.remote_mac)
        self.assertEqual(rx[0][IPv6].src, self.pg0.remote_ip6)
        self.assertEqual(rx[0][IPv6].dst, self.pg0.local_ip6)
        self.assertEqual(ipv6nh[rx[0][IPv6].nh], "ICMPv6")
        self.assertTrue(rx[0].haslayer(ICMPv6EchoReply))
        self.assertEqual(rx[0][ICMPv6EchoReply].id, id)
        self.assertEqual(rx[0][ICMPv6EchoReply].seq, seq)

        #
        # cleanup
        #
        self.vapi.ip6nd_proxy_enable_disable(
            sw_if_index=self.pg1.sw_if_index, is_enable=0
        )
        redirect.remove_vpp_config()


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
