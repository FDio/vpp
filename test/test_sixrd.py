#
# Test plan
# - configure sixrd
# - configure ip4 interface and ip6 interface
# - encap 6to4:
#   - send ip6 packet verify on ip4 interface
# - decap 6to4:
#   - send ip4 packet verify on ip6 interface
# - encap recursive
#   - send ip6 packet verify on ip4 interface
# - decap recursive
#   - send ip4 packet verify on ip6 interface
#
#
# TODO:
#  Add API
#  Recursive route handling
#

from scapy.layers.inet import IP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, GRE
from scapy.packet import Raw

from framework import VppTestCase
from vpp_ip_route import VppIpRoute, VppRoutePath
from util import ppp
from ipaddress import *

""" Test6rd is a subclass of  VPPTestCase classes.

Basic test for sanity check.

"""


class Test6RD(VppTestCase):
    """ 6RD Test Case """

    @classmethod
    def setUpClass(cls):
        super(Test6RD, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(2))
            cls.interfaces = list(cls.pg_interfaces)

            for i in cls.interfaces:
                i.admin_up()
                i.config_ip4()
                i.config_ip6()
                i.disable_ipv6_ra()
                i.resolve_arp()
                i.resolve_ndp()
        except Exception:
            super(Test6RD, cls).tearDownClass()
            raise

    def tearDown(self):
        super(Test6RD, self).tearDown()
        if not self.vpp_dead:
            self.vapi.cli("show hardware")

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

    def test_6rd_ip6_to_ip4(self):
        """ ip6 -> ip4 (encap) 6rd test """

        rv = self.vapi.sixrd_add_tunnel(
            0, str(ip_address('2002::').packed),
            16, str(ip_address('0.0.0.0').packed),
            0, str(ip_address(self.pg0.local_ip4).packed))

        self.assertEqual(rv.retval, 0)
        tunnel_index = rv.sw_if_index
        self.vapi.cli("show ip6 fib")
        p = (Ether(src=self.pg0.remote_mac,
                   dst=self.pg0.local_mac) /
             IPv6(src="1::1", dst="2002:AC10:0202::1") /
             UDP(sport=1234, dport=1234))

        p_reply = (IP(src=self.pg0.local_ip4, dst=self.pg1.remote_ip4,
                      proto='ipv6') /
                   IPv6(src='1::1', dst='2002:AC10:0202::1', nh='UDP'))

        rx = self.send_and_expect(self.pg0, p*10, self.pg1)
        for p in rx:
            self.validate_6in4(p, p_reply)

        self.vapi.cli("show error")
        self.vapi.sixrd_del_tunnel(tunnel_index)

    def test_6rd_ip4_to_ip6(self):
        """ ip4 -> ip6 (decap) 6rd test """

        rv = self.vapi.sixrd_add_tunnel(
            0, str(ip_address('2002::').packed),
            16, str(ip_address('0.0.0.0').packed),
            0, str(ip_address(self.pg0.local_ip4).packed))
        self.assertEqual(rv.retval, 0)
        tunnel_index = rv.sw_if_index
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
        self.vapi.sixrd_del_tunnel(tunnel_index)

    def test_6rd_ip6_to_native_ip6(self):
        """ ip6 -> native ip6 (encap) 6rd test """

        rv = self.vapi.sixrd_add_tunnel(
            0, str(ip_address('2002::').packed),
            16, str(ip_address('0.0.0.0').packed),
            0, str(ip_address(self.pg0.local_ip4).packed))
        self.assertEqual(rv.retval, 0)
        tunnel_index = rv.sw_if_index

        default_route = VppIpRoute(self, "::/0", 0,
                                   [VppRoutePath("2002:0808:0808::",
                                                 0xFFFFFFFF, next_hop_id=0)])
        self.vapi.cli("show ip6 fib")
        p = (Ether(src=self.pg0.remote_mac,
                   dst=self.pg0.local_mac) /
             IPv6(src="1::1", dst="DEAD:BEEF::1") /
             UDP(sport=1234, dport=1234))

        p_reply = (IP(src=self.pg0.local_ip4, dst=self.pg1.remote_ip4,
                      proto='ipv6') /
                   IPv6(src='1::1', dst='DEAD:BEEF::1', nh='UDP'))

        rx = self.send_and_expect(self.pg0, p*10, self.pg1)
        for p in rx:
            self.validate_6in4(p, p_reply)

        self.vapi.cli("show error")
        self.vapi.sixrd_del_tunnel(tunnel_index)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
