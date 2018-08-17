#!/usr/bin/env python

import unittest
import socket

from framework import VppTestCase, VppTestRunner
from vpp_ip_route import VppIpRoute, VppRoutePath, DpoProto

from scapy.layers.l2 import Ether, Raw
from scapy.layers.inet import IP, UDP, ICMP, TCP
from scapy.layers.inet6 import IPv6


class TestMAP(VppTestCase):
    """ MAP Test Case """

    def setUp(self):
        super(TestMAP, self).setUp()

        # create 2 pg interfaces
        self.create_pg_interfaces(range(4))

        # pg0 is 'inside' IPv4
        self.pg0.admin_up()
        self.pg0.config_ip4()
        self.pg0.resolve_arp()

        # pg1 is 'outside' IPv6
        self.pg1.admin_up()
        self.pg1.config_ip6()
        self.pg1.generate_remote_hosts(4)
        self.pg1.configure_ipv6_neighbors()

    def tearDown(self):
        super(TestMAP, self).tearDown()
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.admin_down()

    def send_and_assert_encapped(self, tx, ip6_src, ip6_dst, dmac=None):
        if not dmac:
            dmac = self.pg1.remote_mac

        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg1.get_capture(1)
        rx = rx[0]

        self.assertEqual(rx[Ether].dst, dmac)
        self.assertEqual(rx[IP].src, tx[IP].src)
        self.assertEqual(rx[IPv6].src, ip6_src)
        self.assertEqual(rx[IPv6].dst, ip6_dst)

    def test_map_e(self):
        """ MAP-E """

        #
        # Add a route to the MAP-BR
        #
        map_br_pfx = "2001::"
        map_br_pfx_len = 64
        map_route = VppIpRoute(self,
                               map_br_pfx,
                               map_br_pfx_len,
                               [VppRoutePath(self.pg1.remote_ip6,
                                             self.pg1.sw_if_index,
                                             proto=DpoProto.DPO_PROTO_IP6)],
                               is_ip6=1)
        map_route.add_vpp_config()

        #
        # Add a domain that maps from pg0 to pg1
        #
        map_dst = socket.inet_pton(socket.AF_INET6, map_br_pfx)
        map_src = "3001::1"
        map_src_n = socket.inet_pton(socket.AF_INET6, map_src)
        client_pfx = socket.inet_pton(socket.AF_INET, "192.168.0.0")

        self.vapi.map_add_domain(map_dst,
                                 map_br_pfx_len,
                                 map_src_n,
                                 128,
                                 client_pfx,
                                 16)

        # Enable MAP on interface.
        self.vapi.map_if_enable_disable(1, self.pg0.sw_if_index, 0)

        #
        # Fire in a v4 packet that will be encapped to the BR
        #
        v4 = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
              IP(src=self.pg0.remote_ip4, dst='192.168.1.1') /
              UDP(sport=20000, dport=10000) /
              Raw('\xa5' * 100))

        self.send_and_assert_encapped(v4, map_src, "2001::c0a8:0:0")

        #
        # Fire in a V6 encapped packet.
        #  expect a decapped packet on the inside ip4 link
        #
        # Enable MAP on interface.
        self.vapi.map_if_enable_disable(1, self.pg1.sw_if_index, 0)

        p = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
             IPv6(dst=map_src, src="2001::1") /
             IP(dst=self.pg0.remote_ip4, src='192.168.1.1') /
             UDP(sport=20000, dport=10000) /
             Raw('\xa5' * 100))

        self.pg1.add_stream(p)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg0.get_capture(1)
        rx = rx[0]

        self.assertFalse(rx.haslayer(IPv6))
        self.assertEqual(rx[IP].src, p[IP].src)
        self.assertEqual(rx[IP].dst, p[IP].dst)

        #
        # Pre-resolve. No API for this!!
        #
        self.vapi.ppcli("map params pre-resolve ip6-nh 4001::1")

        self.send_and_assert_no_replies(self.pg0, v4,
                                        "resovled via default route")

        #
        # Add a route to 4001::1. Expect the encapped traffic to be
        # sent via that routes next-hop
        #
        pre_res_route = VppIpRoute(
            self, "4001::1", 128,
            [VppRoutePath(self.pg1.remote_hosts[2].ip6,
                          self.pg1.sw_if_index,
                          proto=DpoProto.DPO_PROTO_IP6)],
            is_ip6=1)
        pre_res_route.add_vpp_config()

        self.send_and_assert_encapped(v4, map_src,
                                      "2001::c0a8:0:0",
                                      dmac=self.pg1.remote_hosts[2].mac)

        #
        # change the route to the pre-solved next-hop
        #
        pre_res_route.modify([VppRoutePath(self.pg1.remote_hosts[3].ip6,
                                           self.pg1.sw_if_index,
                                           proto=DpoProto.DPO_PROTO_IP6)])
        pre_res_route.add_vpp_config()

        self.send_and_assert_encapped(v4, map_src,
                                      "2001::c0a8:0:0",
                                      dmac=self.pg1.remote_hosts[3].mac)

        #
        # cleanup. The test infra's object registry will ensure
        # the route is really gone and thus that the unresolve worked.
        #
        pre_res_route.remove_vpp_config()
        self.vapi.ppcli("map params pre-resolve del ip6-nh 4001::1")

    def validate(self, rx, expected):
        self.assertEqual(rx, expected.__class__(str(expected)))

    def test_map_t(self):
        """ MAP-T """

        #
        # Add a domain that maps from pg0 to pg1
        #
        map_dst = socket.inet_pton(socket.AF_INET6, "2001:db8::")
        map_src = socket.inet_pton(socket.AF_INET6, "1234:5678:90ab:cdef::")
        ip4_pfx = socket.inet_pton(socket.AF_INET, "192.168.0.0")

        self.vapi.map_add_domain(map_dst, 32, map_src, 64, ip4_pfx,
                                 24, 16, 0, 8, 1)

        # Enable MAP-T on interfaces.
        self.vapi.map_if_enable_disable(1, self.pg0.sw_if_index, 1)
        self.vapi.map_if_enable_disable(1, self.pg1.sw_if_index, 1)

        map_route = VppIpRoute(self,
                               "2001:db8::",
                               32,
                               [VppRoutePath(self.pg1.remote_ip6,
                                             self.pg1.sw_if_index,
                                             proto=DpoProto.DPO_PROTO_IP6)],
                               is_ip6=1)
        map_route.add_vpp_config()

        #
        # Send a v4 packet that will be translated
        #
        p_ether = Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
        p_ip4 = IP(src=self.pg0.remote_ip4, dst='192.168.0.1')
        payload = TCP(sport=0xabcd, dport=0xabcd)

        p4 = (p_ether / p_ip4 / payload)
        p6_translated = (IPv6(src="1234:5678:90ab:cdef:ac:1001:200:0",
                              dst="2001:db8:1ab::c0a8:1:ab") / payload)
        p6_translated.hlim -= 1
        rx = self.send_and_expect(self.pg0, p4*1, self.pg1)
        for p in rx:
            self.validate(p[1], p6_translated)

        # Send back an IPv6 packet that will be "untranslated"
        p_ether6 = Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac)
        p_ip6 = IPv6(src='2001:db8:1ab::c0a8:1:ab',
                     dst='1234:5678:90ab:cdef:ac:1001:200:0')
        p6 = (p_ether6 / p_ip6 / payload)
        p4_translated = (IP(src='192.168.0.1',
                            dst=self.pg0.remote_ip4) / payload)
        p4_translated.id = 0
        p4_translated.ttl -= 1
        rx = self.send_and_expect(self.pg1, p6*1, self.pg0)
        for p in rx:
            self.validate(p[1], p4_translated)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
