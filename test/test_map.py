#!/usr/bin/env python

import unittest
import socket

from framework import VppTestCase, VppTestRunner
from vpp_ip import *
from vpp_ip_route import VppIpRoute, VppRoutePath
from ipaddress import IPv6Network, IPv4Network
from scapy.layers.l2 import Ether, Raw
from scapy.layers.inet import IP, UDP, ICMP, TCP, fragment
from scapy.layers.inet6 import IPv6, ICMPv6TimeExceeded


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
                                             proto=DPO_PROTO.IP6)],
                               is_ip6=1)
        map_route.add_vpp_config()

        #
        # Add a domain that maps from pg0 to pg1
        #
        map_dst = '2001::/64'
        map_src = '3000::1/128'
        client_pfx = '192.168.0.0/16'
        self.vapi.map_add_domain(map_dst, map_src, client_pfx)

        # Enable MAP on interface.
        self.vapi.map_if_enable_disable(1, self.pg0.sw_if_index, 0)

        # Ensure MAP doesn't steal all packets!
        v4 = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
              IP(src=self.pg0.remote_ip4, dst=self.pg0.remote_ip4) /
              UDP(sport=20000, dport=10000) /
              Raw('\xa5' * 100))
        rx = self.send_and_expect(self.pg0, v4*1, self.pg0)
        v4_reply = v4[1]
        v4_reply.ttl -= 1
        for p in rx:
            self.validate(p[1], v4_reply)

        #
        # Fire in a v4 packet that will be encapped to the BR
        #
        v4 = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
              IP(src=self.pg0.remote_ip4, dst='192.168.1.1') /
              UDP(sport=20000, dport=10000) /
              Raw('\xa5' * 100))

        self.send_and_assert_encapped(v4, "3000::1", "2001::c0a8:0:0")

        # Enable MAP on interface.
        self.vapi.map_if_enable_disable(1, self.pg1.sw_if_index, 0)

        # Ensure MAP doesn't steal all packets
        v6 = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
              IPv6(src=self.pg1.remote_ip6, dst=self.pg1.remote_ip6) /
              UDP(sport=20000, dport=10000) /
              Raw('\xa5' * 100))
        rx = self.send_and_expect(self.pg1, v6*1, self.pg1)
        v6_reply = v6[1]
        v6_reply.hlim -= 1
        for p in rx:
            self.validate(p[1], v6_reply)

        #
        # Fire in a V6 encapped packet.
        #  expect a decapped packet on the inside ip4 link
        #
        p = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
             IPv6(dst='3000::1', src="2001::1") /
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
                          proto=DPO_PROTO.IP6)],
            is_ip6=1)
        pre_res_route.add_vpp_config()

        self.send_and_assert_encapped(v4, "3000::1",
                                      "2001::c0a8:0:0",
                                      dmac=self.pg1.remote_hosts[2].mac)

        #
        # change the route to the pre-solved next-hop
        #
        pre_res_route.modify([VppRoutePath(self.pg1.remote_hosts[3].ip6,
                                           self.pg1.sw_if_index,
                                           proto=DPO_PROTO.IP6)])
        pre_res_route.add_vpp_config()

        self.send_and_assert_encapped(v4, "3000::1",
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

    def payload(self, len):
        return 'x' * len

    def test_map_t(self):
        """ MAP-T """

        #
        # Add a domain that maps from pg0 to pg1
        #
        map_dst = '2001:db8::/32'
        map_src = '1234:5678:90ab:cdef::/64'
        ip4_pfx = '192.168.0.0/24'

        self.vapi.map_add_domain(map_dst, map_src, ip4_pfx,
                                 16, 6, 4)

        # Enable MAP-T on interfaces.
        self.vapi.map_if_enable_disable(1, self.pg0.sw_if_index, 1)
        self.vapi.map_if_enable_disable(1, self.pg1.sw_if_index, 1)

        # Ensure MAP doesn't steal all packets!
        v4 = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
              IP(src=self.pg0.remote_ip4, dst=self.pg0.remote_ip4) /
              UDP(sport=20000, dport=10000) /
              Raw('\xa5' * 100))
        rx = self.send_and_expect(self.pg0, v4*1, self.pg0)
        v4_reply = v4[1]
        v4_reply.ttl -= 1
        for p in rx:
            self.validate(p[1], v4_reply)
        # Ensure MAP doesn't steal all packets
        v6 = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
              IPv6(src=self.pg1.remote_ip6, dst=self.pg1.remote_ip6) /
              UDP(sport=20000, dport=10000) /
              Raw('\xa5' * 100))
        rx = self.send_and_expect(self.pg1, v6*1, self.pg1)
        v6_reply = v6[1]
        v6_reply.hlim -= 1
        for p in rx:
            self.validate(p[1], v6_reply)

        map_route = VppIpRoute(self,
                               "2001:db8::",
                               32,
                               [VppRoutePath(self.pg1.remote_ip6,
                                             self.pg1.sw_if_index,
                                             proto=DPO_PROTO.IP6)],
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
                              dst="2001:db8:1f0::c0a8:1:f") / payload)
        p6_translated.hlim -= 1
        rx = self.send_and_expect(self.pg0, p4*1, self.pg1)
        for p in rx:
            self.validate(p[1], p6_translated)

        # Send back an IPv6 packet that will be "untranslated"
        p_ether6 = Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac)
        p_ip6 = IPv6(src='2001:db8:1f0::c0a8:1:f',
                     dst='1234:5678:90ab:cdef:ac:1001:200:0')
        p6 = (p_ether6 / p_ip6 / payload)
        p4_translated = (IP(src='192.168.0.1',
                            dst=self.pg0.remote_ip4) / payload)
        p4_translated.id = 0
        p4_translated.ttl -= 1
        rx = self.send_and_expect(self.pg1, p6*1, self.pg0)
        for p in rx:
            self.validate(p[1], p4_translated)

        # IPv4 TTL
        ip4_ttl_expired = IP(src=self.pg0.remote_ip4, dst='192.168.0.1', ttl=0)
        p4 = (p_ether / ip4_ttl_expired / payload)

        icmp4_reply = (IP(id=0, ttl=254, src=self.pg0.local_ip4,
                          dst=self.pg0.remote_ip4) /
                       ICMP(type='time-exceeded',
                            code='ttl-zero-during-transit') /
                       IP(src=self.pg0.remote_ip4,
                          dst='192.168.0.1', ttl=0) / payload)
        rx = self.send_and_expect(self.pg0, p4*1, self.pg0)
        for p in rx:
            self.validate(p[1], icmp4_reply)

        '''
        This one is broken, cause it would require hairpinning...
        # IPv4 TTL TTL1
        ip4_ttl_expired = IP(src=self.pg0.remote_ip4, dst='192.168.0.1', ttl=1)
        p4 = (p_ether / ip4_ttl_expired / payload)

        icmp4_reply = IP(id=0, ttl=254, src=self.pg0.local_ip4,
        dst=self.pg0.remote_ip4) / \
        ICMP(type='time-exceeded', code='ttl-zero-during-transit' ) / \
        IP(src=self.pg0.remote_ip4, dst='192.168.0.1', ttl=0) / payload
        rx = self.send_and_expect(self.pg0, p4*1, self.pg0)
        for p in rx:
            self.validate(p[1], icmp4_reply)
        '''

        # IPv6 Hop limit
        ip6_hlim_expired = IPv6(hlim=0, src='2001:db8:1ab::c0a8:1:ab',
                                dst='1234:5678:90ab:cdef:ac:1001:200:0')
        p6 = (p_ether6 / ip6_hlim_expired / payload)

        icmp6_reply = (IPv6(hlim=255, src=self.pg1.local_ip6,
                            dst="2001:db8:1ab::c0a8:1:ab") /
                       ICMPv6TimeExceeded(code=0) /
                       IPv6(src="2001:db8:1ab::c0a8:1:ab",
                            dst='1234:5678:90ab:cdef:ac:1001:200:0',
                            hlim=0) / payload)
        rx = self.send_and_expect(self.pg1, p6*1, self.pg1)
        for p in rx:
            self.validate(p[1], icmp6_reply)

        # IPv4 Well-known port
        p_ip4 = IP(src=self.pg0.remote_ip4, dst='192.168.0.1')
        payload = UDP(sport=200, dport=200)
        p4 = (p_ether / p_ip4 / payload)
        self.send_and_assert_no_replies(self.pg0, p4*1)

        # IPv6 Well-known port
        payload = UDP(sport=200, dport=200)
        p6 = (p_ether6 / p_ip6 / payload)
        self.send_and_assert_no_replies(self.pg1, p6*1)

        # Packet fragmentation
        payload = UDP(sport=40000, dport=4000) / self.payload(1453)
        p4 = (p_ether / p_ip4 / payload)
        self.pg_enable_capture()
        self.pg0.add_stream(p4)
        self.pg_start()
        rx = self.pg1.get_capture(2)
        for p in rx:
            pass
            # TODO: Manual validation
            # self.validate(p[1], icmp4_reply)

        # Packet fragmentation send fragments
        payload = UDP(sport=40000, dport=4000) / self.payload(1453)
        p4 = (p_ether / p_ip4 / payload)
        frags = fragment(p4, fragsize=1000)
        self.pg_enable_capture()
        self.pg0.add_stream(frags)
        self.pg_start()
        rx = self.pg1.get_capture(2)
        for p in rx:
            pass
            # p.show2()
        # reass_pkt = reassemble(rx)
        # p4_reply.ttl -= 1
        # p4_reply.id = 256
        # self.validate(reass_pkt, p4_reply)

        # TCP MSS clamping
        self.vapi.map_param_set_tcp(1300)

        #
        # Send a v4 TCP SYN packet that will be translated and MSS clamped
        #
        p_ether = Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
        p_ip4 = IP(src=self.pg0.remote_ip4, dst='192.168.0.1')
        payload = TCP(sport=0xabcd, dport=0xabcd, flags="S",
                      options=[('MSS', 1460)])

        p4 = (p_ether / p_ip4 / payload)
        p6_translated = (IPv6(src="1234:5678:90ab:cdef:ac:1001:200:0",
                              dst="2001:db8:1f0::c0a8:1:f") / payload)
        p6_translated.hlim -= 1
        p6_translated['TCP'].options = [('MSS', 1300)]
        rx = self.send_and_expect(self.pg0, p4*1, self.pg1)
        for p in rx:
            self.validate(p[1], p6_translated)

        # Send back an IPv6 packet that will be "untranslated"
        p_ether6 = Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac)
        p_ip6 = IPv6(src='2001:db8:1f0::c0a8:1:f',
                     dst='1234:5678:90ab:cdef:ac:1001:200:0')
        p6 = (p_ether6 / p_ip6 / payload)
        p4_translated = (IP(src='192.168.0.1',
                            dst=self.pg0.remote_ip4) / payload)
        p4_translated.id = 0
        p4_translated.ttl -= 1
        p4_translated['TCP'].options = [('MSS', 1300)]
        rx = self.send_and_expect(self.pg1, p6*1, self.pg0)
        for p in rx:
            self.validate(p[1], p4_translated)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
