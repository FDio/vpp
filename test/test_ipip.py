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

    def validate_6in4(self, rx, expected):
        if IP not in rx:
            self.fail()
        if IPv6 not in rx:
            self.fail()

        self.assertEqual(rx[IP].src, expected[IP].src)
        self.assertEqual(rx[IP].dst, expected[IP].dst)
        self.assertEqual(rx[IP].proto, expected[IP].proto)
        self.assertEqual(rx[IPv6].src, expected[IPv6].src)
        self.assertEqual(rx[IPv6].dst, expected[IPv6].dst)

    def validate_4in4(self, rx, expected):
        if IP not in rx:
            self.fail()
        self.assertEqual(rx[IP].src, expected[IP].src)
        self.assertEqual(rx[IP].dst, expected[IP].dst)
        self.assertEqual(rx[IP].proto, expected[IP].proto)
        self.assertEqual(rx[IP][IP].src, expected[IP][IP].src)
        self.assertEqual(rx[IP][IP].dst, expected[IP][IP].dst)

    def validate_4in6(self, rx, expected):
        if IPv6 not in rx:
            self.fail()
        if IP in rx:
            self.fail()

        self.assertTrue(rx[IPv6].src == expected[IPv6].src)
        self.assertTrue(rx[IPv6].dst == expected[IPv6].dst)
        self.assertTrue(rx[IPv6].nh == expected[IPv6].nh)

    def payload(self, len):
        return 'x' * len

    def test_ipip4_encap(self):
        """ ip{v4,v6} over ip4 encap test """
        p_ether = Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
        p_ip6 = IPv6(src="1::1", dst="DEAD::1", nh='UDP')
        p_ip4 = IP(src="1.2.3.4", dst="130.67.0.1")
        p_payload = UDP(sport=1234, dport=1234)

        # IPv4 transport
        rv = self.vapi.ipip_add_del_tunnel(1, 0, 0,
                                           str(ip_address(self.pg0.local_ip4).packed),
                                           str(ip_address(self.pg1.remote_ip4).packed),
                                           0)
        self.assertEqual(rv.retval, 0)
        sw_if_index = rv.sw_if_index

        rv = self.vapi.sw_interface_set_flags(sw_if_index, 1)
        self.assertEqual(rv.retval, 0)
        
        # Add IPv4 and IPv6 routes via tunnel interface
        ip4_via_tunnel = VppIpRoute(
            self, "130.67.0.0", 16, [VppRoutePath("0.0.0.0",
                                                  sw_if_index,
                                                  proto=DpoProto.DPO_PROTO_IP4)], is_ip6=0)
        ip4_via_tunnel.add_vpp_config()

        ip6_via_tunnel = VppIpRoute(
            self, "dead::", 16, [VppRoutePath("::",
                                              sw_if_index,
                                              proto=DpoProto.DPO_PROTO_IP6)], is_ip6=1)
        ip6_via_tunnel.add_vpp_config()


        p6 = (p_ether / p_ip6 / p_payload)
        p6_reply = (IP(src=self.pg0.local_ip4, dst=self.pg1.remote_ip4,
                       proto='ipv6') / p_ip6)
        #rx = self.send_and_expect(self.pg0, p6*10, self.pg1)
        #for p in rx:
        #    self.validate_6in4(p, p6_reply)

        p4 = (p_ether / p_ip4 / p_payload)
        p4_reply = (IP(src=self.pg0.local_ip4, dst=self.pg1.remote_ip4) / p_ip4)
        rx = self.send_and_expect(self.pg0, p4*10, self.pg1)
        for p in rx:
            self.validate_4in4(p, p4_reply)

        self.vapi.cli("show errors")

    def test_ipip6_encap(self):
        """ ip{v4,v6} over ip6 encap test """
        p_ether = Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
        p_ip6 = IPv6(src="1::1", dst="DEAD::1", nh='UDP')
        p_ip4 = IP(src="1.2.3.4", dst="130.67.0.1")
        p_payload = UDP(sport=1234, dport=1234)

        # IPv4 transport
        rv = self.vapi.ipip_add_del_tunnel(1, 0, 0,
                                           str(ip_address(self.pg0.local_ip6).packed),
                                           str(ip_address(self.pg1.remote_ip6).packed),
                                           0)
        self.assertEqual(rv.retval, 0)
        sw_if_index = rv.sw_if_index

        rv = self.vapi.sw_interface_set_flags(sw_if_index, 1)
        self.assertEqual(rv.retval, 0)
        
        # Add IPv4 and IPv6 routes via tunnel interface
        ip4_via_tunnel = VppIpRoute(
            self, "130.67.0.0", 16, [VppRoutePath("0.0.0.0",
                                                  sw_if_index,
                                                  proto=DpoProto.DPO_PROTO_IP4)], is_ip6=0)
        ip4_via_tunnel.add_vpp_config()

        ip6_via_tunnel = VppIpRoute(
            self, "dead::", 16, [VppRoutePath("::",
                                              sw_if_index,
                                              proto=DpoProto.DPO_PROTO_IP6)], is_ip6=1)
        ip6_via_tunnel.add_vpp_config()


        p6 = (p_ether / p_ip6 / p_payload)
        p6_reply = (IP(src=self.pg0.local_ip4, dst=self.pg1.remote_ip4,
                       proto='ipv6') / p_ip6)
        rx = self.send_and_expect(self.pg0, p6*10, self.pg1)
        for p in rx:
            self.validate_6in4(p, p6_reply)

        #p4 = (p_ether / p_ip4 / p_payload)
        #p4_reply = (IP(src=self.pg0.local_ip4, dst=self.pg1.remote_ip4) / p_ip4)
        #rx = self.send_and_expect(self.pg0, p4*10, self.pg1)
        #for p in rx:
        #    self.validate_4in4(p, p4_reply)

        self.vapi.cli("show errors")
        
    def test_ipip_decap(self):
        """ ipip decap test """

        rv = self.vapi.ipip_add_del_tunnel(1, 0, 0,
                                           str(ip_address(self.pg0.local_ip4).packed),
                                           str(ip_address(self.pg0.remote_ip4).packed),
                                           0)
        self.assertEqual(rv.retval, 0)
        self.tunnel_index = rv.sw_if_index
        self.vapi.cli("show ip6 fib")
        p_ip6 = (IPv6(src="2002:AC10:0202::1", dst=self.pg1.remote_ip6) /
                 UDP(sport=1234, dport=1234))

        p = (Ether(src=self.pg0.remote_mac,
                   dst=self.pg0.local_mac) /
             IP(src=self.pg1.remote_ip4, dst=self.pg0.local_ip4) /
             p_ip6)

        p_reply = p_ip6

        rx = self.send_and_expect(self.pg0, p*10, self.pg1)
        for p in rx:
            self.validate_4in6(p, p_reply)
        self.vapi.cli("show error")

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
