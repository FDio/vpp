#
# IP{4,6} over IP{v,6} tunnel functional tests
#

import unittest
from scapy.layers.inet import IP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, GRE
from scapy.packet import Raw

from framework import VppTestCase
from vpp_ip_route import VppIpRoute, VppRoutePath, DpoProto
from util import ppp
from ipaddress import *

""" Testipip is a subclass of  VPPTestCase classes.

IPIP tests.

"""


class TestIPIP(VppTestCase):
    """ IPIP Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestIPIP, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(2))
            cls.interfaces = list(cls.pg_interfaces)
        except Exception:
            super(TestIPIP, cls).tearDownClass()
            raise

    def setUp(cls):
        super(TestIPIP, cls).setUp()
        try:
            for i in cls.interfaces:
                i.admin_up()
                i.config_ip4()
                i.config_ip6()
                i.disable_ipv6_ra()
                i.resolve_arp()
                i.resolve_ndp()
        except Exception:
            super(TestIPIP, cls).tearDown()
            raise

    def tearDown(self):
        super(TestIPIP, self).tearDown()
        if not self.vpp_dead:
            self.vapi.cli("show hardware")
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.admin_down()
        self.vapi.cli("show error")

    def validate(self, rx, expected):
        expected = expected.__class__(str(expected))
        if rx != expected:
            print('RX packet:')
            print(rx.show())
            print('EXPECTED packet:')
            print(expected.show())
            self.assertDictEqual(rx, expected)

    def payload(self, len):
        return 'x' * len

    def test_ipip4(self):
        """ ip{v4,v6} over ip4 test """
        p_ether = Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
        p_ip6 = IPv6(src="1::1", dst="DEAD::1", nh='UDP')
        p_ip4 = IP(src="1.2.3.4", dst="130.67.0.1")
        p_payload = UDP(sport=1234, dport=1234)

        # IPv4 transport
        rv = self.vapi.ipip_add_tunnel(
            src_address=str(ip_address(self.pg0.local_ip4).packed),
            dst_address=str(ip_address(self.pg1.remote_ip4).packed),
            is_ipv6=0)
        self.assertEqual(rv.retval, 0)
        sw_if_index = rv.sw_if_index

        # Set interface up and enable IP on it
        rv = self.vapi.sw_interface_set_flags(sw_if_index, 1)
        self.assertEqual(rv.retval, 0)
        rv = self.vapi.sw_interface_set_unnumbered(
            ip_sw_if_index=self.pg0.sw_if_index,
            sw_if_index=sw_if_index)
        self.assertEqual(rv.retval, 0)

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
            src_address=str(ip_address(self.pg0.local_ip6).packed),
            dst_address=str(ip_address(self.pg1.remote_ip6).packed))
        self.assertEqual(rv.retval, 0)

        sw_if_index = rv.sw_if_index

        rv = self.vapi.sw_interface_set_flags(sw_if_index, 1)
        self.assertEqual(rv.retval, 0)
        rv = self.vapi.sw_interface_set_unnumbered(
            ip_sw_if_index=self.pg0.sw_if_index, sw_if_index=sw_if_index)
        self.assertEqual(rv.retval, 0)

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
            src_address=str(ip_address('1.2.3.4').packed),
            dst_address=str(ip_address('2.3.4.5').packed), is_ipv6=0)
        self.assertEqual(rv.retval, 0)
        sw_if_index = rv.sw_if_index
        rv = self.vapi.ipip_del_tunnel(sw_if_index)
        self.assertEqual(rv.retval, 0)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
