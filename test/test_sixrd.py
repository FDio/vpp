#
# 6RD RFC5969 functional tests
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

""" Test6rd is a subclass of  VPPTestCase classes.

6RD tests.

"""


class Test6RD(VppTestCase):
    """ 6RD Test Case """

    @classmethod
    def setUpClass(cls):
        super(Test6RD, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(2))
            cls.interfaces = list(cls.pg_interfaces)
        except Exception:
            super(Test6RD, cls).tearDownClass()
            raise

    def setUp(cls):
        super(Test6RD, cls).setUp()
        try:
            for i in cls.interfaces:
                i.admin_up()
                i.config_ip4()
                i.config_ip6()
                i.disable_ipv6_ra()
                i.resolve_arp()
                i.resolve_ndp()
        except Exception:
            super(Test6RD, cls).tearDown()
            raise

    def tearDown(self):
        super(Test6RD, self).tearDown()
        if not self.vpp_dead:
            self.vapi.cli("show hardware")
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.admin_down()
        if type(self.tunnel_index) is list:
            for sw_if_index in self.tunnel_index:
                self.vapi.sixrd_del_tunnel(sw_if_index)
        else:
            self.vapi.sixrd_del_tunnel(self.tunnel_index)
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

    def test_6rd_ip6_to_ip4(self):
        """ ip6 -> ip4 (encap) 6rd test """
        p_ether = Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
        p_ip6 = IPv6(src="1::1", dst="2002:AC10:0202::1", nh='UDP')

        rv = self.vapi.sixrd_add_tunnel(
            0, str(ip_address('2002::').packed), 16,
            str(ip_address('0.0.0.0').packed), 0,
            str(ip_address(self.pg0.local_ip4).packed), 0, True)

        self.assertEqual(rv.retval, 0)
        self.tunnel_index = rv.sw_if_index
        self.vapi.cli("show ip6 fib")
        p_payload = UDP(sport=1234, dport=1234)
        p = (p_ether / p_ip6 / p_payload)

        p_reply = (IP(src=self.pg0.local_ip4, dst=self.pg1.remote_ip4,
                      proto='ipv6') / p_ip6)

        rx = self.send_and_expect(self.pg0, p*10, self.pg1)
        for p in rx:
            self.validate_6in4(p, p_reply)

        # MTU tests (default is 1480)
        plen = 1481 - 40 - 8
        p_ip6 = IPv6(src="1::1", dst="2002:AC10:0202::1")
        p_payload = UDP(sport=1234, dport=1234) / Raw(self.payload(plen))
        p = (p_ether / p_ip6 / p_payload)

        p_reply = (IP(src=self.pg0.local_ip4, dst=self.pg1.remote_ip4,
                      proto='ipv6') / p_ip6)

        rx = self.send_and_assert_no_replies(self.pg0, p*10)

    def test_6rd_ip4_to_ip6(self):
        """ ip4 -> ip6 (decap) 6rd test """

        rv = self.vapi.sixrd_add_tunnel(
            0, str(ip_address('2002::').packed),
            16, str(ip_address('0.0.0.0').packed),
            0, str(ip_address(self.pg0.local_ip4).packed), 0, True)
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

    def test_6rd_ip4_to_ip6_multiple(self):
        """ ip4 -> ip6 (decap) 6rd test """

        self.tunnel_index = []
        rv = self.vapi.sixrd_add_tunnel(
            0, str(ip_address('2002::').packed),
            16, str(ip_address('0.0.0.0').packed),
            0, str(ip_address(self.pg0.local_ip4).packed), 0, True)
        self.assertEqual(rv.retval, 0)
        self.tunnel_index.append(rv.sw_if_index)
        rv = self.vapi.sixrd_add_tunnel(
            0, str(ip_address('2003::').packed),
            16, str(ip_address('0.0.0.0').packed),
            0, str(ip_address(self.pg1.local_ip4).packed), 0, True)
        self.assertEqual(rv.retval, 0)

        self.tunnel_index.append(rv.sw_if_index)

        self.vapi.cli("show ip6 fib")
        p_ether = Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
        p_ip4 = IP(src=self.pg1.remote_ip4, dst=self.pg0.local_ip4)
        p_ip6_1 = (IPv6(src="2002:AC10:0202::1", dst=self.pg1.remote_ip6) /
                   UDP(sport=1234, dport=1234))
        p_ip6_2 = (IPv6(src="2003:AC10:0202::1", dst=self.pg1.remote_ip6) /
                   UDP(sport=1234, dport=1234))

        p = (p_ether / p_ip4 / p_ip6_1)
        rx = self.send_and_expect(self.pg0, p*10, self.pg1)
        for p in rx:
            self.validate_4in6(p, p_ip6_1)

        p = (p_ether / p_ip4 / p_ip6_2)
        rx = self.send_and_expect(self.pg0, p*10, self.pg1)
        for p in rx:
            self.validate_4in6(p, p_ip6_2)

    def test_6rd_ip4_to_ip6_suffix(self):
        """ ip4 -> ip6 (decap) 6rd test """

        rv = self.vapi.sixrd_add_tunnel(
            0, str(ip_address('2002::').packed), 16,
            str(ip_address('172.0.0.0').packed), 8,
            str(ip_address(self.pg0.local_ip4).packed), 0, True)
        self.assertEqual(rv.retval, 0)

        self.tunnel_index = rv.sw_if_index

        self.vapi.cli("show ip6 fib")
        p_ether = Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
        p_ip4 = IP(src=self.pg1.remote_ip4, dst=self.pg0.local_ip4)
        p_ip6 = (IPv6(src="2002:1002:0200::1", dst=self.pg1.remote_ip6) /
                 UDP(sport=1234, dport=1234))

        p = (p_ether / p_ip4 / p_ip6)
        rx = self.send_and_expect(self.pg0, p*10, self.pg1)
        for p in rx:
            self.validate_4in6(p, p_ip6)

    def test_6rd_ip4_to_ip6_sec_check(self):
        """ ip4 -> ip6 (decap) security check 6rd test """

        rv = self.vapi.sixrd_add_tunnel(
            0, str(ip_address('2002::').packed),
            16, str(ip_address('0.0.0.0').packed),
            0, str(ip_address(self.pg0.local_ip4).packed), 0, True)
        self.assertEqual(rv.retval, 0)
        self.tunnel_index = rv.sw_if_index
        self.vapi.cli("show ip6 fib")
        p_ip6 = (IPv6(src="2002:AC10:0202::1", dst=self.pg1.remote_ip6) /
                 UDP(sport=1234, dport=1234))
        p_ip6_fail = (IPv6(src="2002:DEAD:0202::1", dst=self.pg1.remote_ip6) /
                      UDP(sport=1234, dport=1234))

        p = (Ether(src=self.pg0.remote_mac,
                   dst=self.pg0.local_mac) /
             IP(src=self.pg1.remote_ip4, dst=self.pg0.local_ip4) /
             p_ip6)

        p_reply = p_ip6

        rx = self.send_and_expect(self.pg0, p*10, self.pg1)
        for p in rx:
            self.validate_4in6(p, p_reply)

        p = (Ether(src=self.pg0.remote_mac,
                   dst=self.pg0.local_mac) /
             IP(src=self.pg1.remote_ip4, dst=self.pg0.local_ip4) /
             p_ip6_fail)
        rx = self.send_and_assert_no_replies(self.pg0, p*10)

    def test_6rd_bgp_tunnel(self):
        """ 6rd BGP tunnel """

        rv = self.vapi.sixrd_add_tunnel(
            0, str(ip_address('2002::').packed),
            16, str(ip_address('0.0.0.0').packed),
            0, str(ip_address(self.pg0.local_ip4).packed), 0, False)
        self.assertEqual(rv.retval, 0)
        self.tunnel_index = rv.sw_if_index

        default_route = VppIpRoute(
            self, "DEAD::", 16, [VppRoutePath("2002:0808:0808::",
                                              self.tunnel_index,
                                              proto=DpoProto.DPO_PROTO_IP6)],
            is_ip6=1)
        default_route.add_vpp_config()

        ip4_route = VppIpRoute(self, "8.0.0.0", 8,
                               [VppRoutePath(self.pg1.remote_ip4, 0xFFFFFFFF)])
        ip4_route.add_vpp_config()

        # Via recursive route 6 -> 4
        p = (Ether(src=self.pg0.remote_mac,
                   dst=self.pg0.local_mac) /
             IPv6(src="1::1", dst="DEAD:BEEF::1") /
             UDP(sport=1234, dport=1234))

        p_reply = (IP(src=self.pg0.local_ip4, dst="8.8.8.8",
                      proto='ipv6') /
                   IPv6(src='1::1', dst='DEAD:BEEF::1', nh='UDP'))

        rx = self.send_and_expect(self.pg0, p*10, self.pg1)
        for p in rx:
            self.validate_6in4(p, p_reply)

        # Via recursive route 4 -> 6 (Security check must be disabled)
        p_ip6 = (IPv6(src="DEAD:BEEF::1", dst=self.pg1.remote_ip6) /
                 UDP(sport=1234, dport=1234))
        p = (Ether(src=self.pg0.remote_mac,
                   dst=self.pg0.local_mac) /
             IP(src="8.8.8.8", dst=self.pg0.local_ip4) /
             p_ip6)

        p_reply = p_ip6

        rx = self.send_and_expect(self.pg0, p*10, self.pg1)
        for p in rx:
            self.validate_4in6(p, p_reply)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
