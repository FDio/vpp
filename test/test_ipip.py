#!/usr/bin/env python
"""IP{4,6} over IP{v,6} tunnel functional tests"""

import unittest
from scapy.layers.inet6 import IPv6, Ether, IP, UDP
from framework import VppTestCase, VppTestRunner
from vpp_ip_route import VppIpRoute, VppRoutePath, DpoProto
from socket import AF_INET, AF_INET6, inet_pton

""" Testipip is a subclass of  VPPTestCase classes.

IPIP tests.

"""


class TestIPIP(VppTestCase):
    """ IPIP Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestIPIP, cls).setUpClass()
        cls.create_pg_interfaces(range(2))
        cls.interfaces = list(cls.pg_interfaces)

    def setUp(cls):
        super(TestIPIP, cls).setUp()
        for i in cls.interfaces:
            i.admin_up()
            i.config_ip4()
            i.config_ip6()
            i.disable_ipv6_ra()
            i.resolve_arp()
            i.resolve_ndp()

    def tearDown(self):
        super(TestIPIP, self).tearDown()
        if not self.vpp_dead:
            for i in self.pg_interfaces:
                i.unconfig_ip4()
                i.unconfig_ip6()
                i.admin_down()

    def validate(self, rx, expected):
        self.assertEqual(rx, expected.__class__(str(expected)))

    def test_ipip4(self):
        """ ip{v4,v6} over ip4 test """
        p_ether = Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
        p_ip6 = IPv6(src="1::1", dst="DEAD::1", nh='UDP')
        p_ip4 = IP(src="1.2.3.4", dst="130.67.0.1")
        p_payload = UDP(sport=1234, dport=1234)

        # IPv4 transport
        rv = self.vapi.ipip_add_tunnel(
            src_address=self.pg0.local_ip4n,
            dst_address=self.pg1.remote_ip4n,
            is_ipv6=0)
        sw_if_index = rv.sw_if_index

        # Set interface up and enable IP on it
        self.vapi.sw_interface_set_flags(sw_if_index, 1)
        self.vapi.sw_interface_set_unnumbered(
            ip_sw_if_index=self.pg0.sw_if_index,
            sw_if_index=sw_if_index)

        # Add IPv4 and IPv6 routes via tunnel interface
        ip4_via_tunnel = VppIpRoute(
            self, "130.67.0.0", 16,
            [VppRoutePath("0.0.0.0",
                          sw_if_index,
                          proto=DpoProto.DPO_PROTO_IP4)], is_ip6=0)
        ip4_via_tunnel.add_vpp_config()

        ip6_via_tunnel = VppIpRoute(
            self, "dead::", 16,
            [VppRoutePath("::",
                          sw_if_index,
                          proto=DpoProto.DPO_PROTO_IP6)], is_ip6=1)
        ip6_via_tunnel.add_vpp_config()

        # IPv6 in to IPv4 tunnel
        p6 = (p_ether / p_ip6 / p_payload)
        p_inner_ip6 = p_ip6
        p_inner_ip6.hlim -= 1
        p6_reply = (IP(src=self.pg0.local_ip4, dst=self.pg1.remote_ip4,
                       proto='ipv6', id=0) / p_inner_ip6 / p_payload)
        p6_reply.ttl -= 1
        rx = self.send_and_expect(self.pg0, p6*10, self.pg1)
        for p in rx:
            self.validate(p[1], p6_reply)

        # IPv4 in to IPv4 tunnel
        p4 = (p_ether / p_ip4 / p_payload)
        p_ip4_inner = p_ip4
        p_ip4_inner.ttl -= 1
        p4_reply = (IP(src=self.pg0.local_ip4,
                       dst=self.pg1.remote_ip4) / p_ip4_inner / p_payload)
        p4_reply.ttl -= 1
        p4_reply.id = 0
        rx = self.send_and_expect(self.pg0, p4*10, self.pg1)
        for p in rx:
            self.validate(p[1], p4_reply)

        # Decapsulation
        p_ether = Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)

        # IPv4 tunnel to IPv4
        p_ip4 = IP(src="1.2.3.4", dst=self.pg0.remote_ip4)
        p4 = (p_ether / IP(src=self.pg1.remote_ip4,
                           dst=self.pg0.local_ip4) / p_ip4 / p_payload)
        p4_reply = (p_ip4 / p_payload)
        p4_reply.ttl -= 1
        rx = self.send_and_expect(self.pg1, p4*10, self.pg0)
        for p in rx:
            self.validate(p[1], p4_reply)

        # IPv4 tunnel to IPv6
        p_ip6 = IPv6(src="1:2:3::4", dst=self.pg0.remote_ip6)
        p6 = (p_ether / IP(src=self.pg1.remote_ip4,
                           dst=self.pg0.local_ip4) / p_ip6 / p_payload)
        p6_reply = (p_ip6 / p_payload)
        p6_reply.hlim = 63
        rx = self.send_and_expect(self.pg1, p6*10, self.pg0)
        for p in rx:
            self.validate(p[1], p6_reply)

    def test_ipip6(self):
        """ ip{v4,v6} over ip6 test """
        p_ether = Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
        p_ip6 = IPv6(src="1::1", dst="DEAD::1", nh='UDP')
        p_ip4 = IP(src="1.2.3.4", dst="130.67.0.1")
        p_payload = UDP(sport=1234, dport=1234)

        # IPv6 transport
        rv = self.vapi.ipip_add_tunnel(
            src_address=self.pg0.local_ip6n,
            dst_address=self.pg1.remote_ip6n)

        sw_if_index = rv.sw_if_index

        self.vapi.sw_interface_set_flags(sw_if_index, 1)
        self.vapi.sw_interface_set_unnumbered(
            ip_sw_if_index=self.pg0.sw_if_index, sw_if_index=sw_if_index)

        # Add IPv4 and IPv6 routes via tunnel interface
        ip4_via_tunnel = VppIpRoute(
            self, "130.67.0.0", 16,
            [VppRoutePath("0.0.0.0",
                          sw_if_index,
                          proto=DpoProto.DPO_PROTO_IP4)], is_ip6=0)
        ip4_via_tunnel.add_vpp_config()

        ip6_via_tunnel = VppIpRoute(
            self, "dead::", 16,
            [VppRoutePath("::",
                          sw_if_index,
                          proto=DpoProto.DPO_PROTO_IP6)], is_ip6=1)
        ip6_via_tunnel.add_vpp_config()

        # Encapsulation

        # IPv6 in to IPv6 tunnel
        p6 = (p_ether / p_ip6 / p_payload)
        p6_reply = (IPv6(src=self.pg0.local_ip6,
                         dst=self.pg1.remote_ip6, hlim=63) / p_ip6 / p_payload)
        p6_reply[1].hlim -= 1
        rx = self.send_and_expect(self.pg0, p6*10, self.pg1)
        for p in rx:
            self.validate(p[1], p6_reply)

        # IPv4 in to IPv6 tunnel
        p4 = (p_ether / p_ip4 / p_payload)
        p4_reply = (IPv6(src=self.pg0.local_ip6,
                         dst=self.pg1.remote_ip6, hlim=63) / p_ip4 / p_payload)
        p4_reply[1].ttl -= 1
        rx = self.send_and_expect(self.pg0, p4*10, self.pg1)
        for p in rx:
            self.validate(p[1], p4_reply)

        # Decapsulation

        p_ether = Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)

        # IPv6 tunnel to IPv4
        p_ip4 = IP(src="1.2.3.4", dst=self.pg0.remote_ip4)
        p4 = (p_ether / IPv6(src=self.pg1.remote_ip6,
                             dst=self.pg0.local_ip6) / p_ip4 / p_payload)
        p4_reply = (p_ip4 / p_payload)
        p4_reply.ttl -= 1
        rx = self.send_and_expect(self.pg1, p4*10, self.pg0)
        for p in rx:
            self.validate(p[1], p4_reply)

        # IPv6 tunnel to IPv6
        p_ip6 = IPv6(src="1:2:3::4", dst=self.pg0.remote_ip6)
        p6 = (p_ether / IPv6(src=self.pg1.remote_ip6,
                             dst=self.pg0.local_ip6) / p_ip6 / p_payload)
        p6_reply = (p_ip6 / p_payload)
        p6_reply.hlim = 63
        rx = self.send_and_expect(self.pg1, p6*10, self.pg0)
        for p in rx:
            self.validate(p[1], p6_reply)

    def test_ipip_create(self):
        """ ipip create / delete interface test """
        rv = self.vapi.ipip_add_tunnel(
            src_address=inet_pton(AF_INET, '1.2.3.4'),
            dst_address=inet_pton(AF_INET, '2.3.4.5'), is_ipv6=0)
        sw_if_index = rv.sw_if_index
        self.vapi.ipip_del_tunnel(sw_if_index)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
