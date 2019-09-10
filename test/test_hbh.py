#!/usr/bin/env python
"""IPv6 HBH MTU record"""

import unittest
from scapy.layers.inet6 import IPv6, Ether, IP, UDP, ICMPv6PacketTooBig, IPv6ExtHdrHopByHop
from scapy.layers.inet import ICMP
from framework import VppTestCase, VppTestRunner
from vpp_ip import DpoProto
from vpp_ip_route import VppIpRoute, VppRoutePath
from socket import AF_INET, AF_INET6, inet_pton
from util import reassemble4
from scapy.all import *
from scapy.layers.inet6 import _OTypeField, _hbhopts, _hbhoptcls
""" Test_mtu is a subclass of VPPTestCase classes.
    MTU tests.
"""

class MTURecord(Packet):  # RFC 2711 - IPv6 Hop-By-Hop Option
    name = "HBH MTU record"
    fields_desc = [_OTypeField("otype", 0x30, _hbhopts),
                   ByteField("optlen", 4),
                   ShortField("mtu1", 0),
                   ShortField("mtu2", 0),]

    def alignment_delta(self, curpos):  # alignment requirement : 2n+0
        x = 2
        y = 0
        delta = x * ((curpos - y + x - 1) // x) + y - curpos
        return delta

    def extract_padding(self, p):
        return b"", p

_hbhoptcls[0x30] = MTURecord

class TestHBHMTU(VppTestCase):
    """ HBH MTU Test Case """
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        super(TestHBHMTU, cls).setUpClass()
        cls.create_pg_interfaces(range(2))
        cls.interfaces = list(cls.pg_interfaces)

    def setUp(self):
        super(TestHBHMTU, self).setUp()
        for i in self.interfaces:
            i.admin_up()
            i.config_ip4()
            i.config_ip6()
            i.disable_ipv6_ra()
            i.resolve_arp()
            i.resolve_ndp()

    def tearDown(self):
        super(TestHBHMTU, self).tearDown()
        if not self.vpp_dead:
            for i in self.pg_interfaces:
                i.unconfig_ip4()
                i.unconfig_ip6()
                i.admin_down()

    def validate(self, rx, expected):
        self.assertEqual(rx, expected.__class__(expected))

    def validate_bytes(self, rx, expected):
        self.assertEqual(rx, expected)

    def payload(self, len):
        return 'x' * len

    def get_mtu(self, sw_if_index):
        rv = self.vapi.sw_interface_dump()
        for i in rv:
            if i.sw_if_index == sw_if_index:
                return i.mtu[0]
        return 0

    def test_ip6_mtu(self):
        """ IP6 MTU test """

        # Send small packet with HBH option. Verify that router modifies it.

        current_mtu = self.get_mtu(self.pg1.sw_if_index)

        # MTU (only checked on encap)
        self.vapi.sw_interface_set_mtu(self.pg1.sw_if_index, [1280, 0, 0, 0])
        self.assertEqual(1280, self.get_mtu(self.pg1.sw_if_index))

        p_ether = Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
        p_ip6 = IPv6(src=self.pg0.remote_ip6, dst=self.pg1.remote_ip6)

        hbh_mtu_option = MTURecord(mtu1=9000)
        p_hbh = IPv6ExtHdrHopByHop(len=0, nh=17, options=hbh_mtu_option)

        p_payload = UDP(sport=1234, dport=1234)
        p6 = p_ether / p_ip6 / p_hbh / p_payload
        p6.show2()
        p6_reply = p_ip6 / IPv6ExtHdrHopByHop(len=0, nh=17, options=MTURecord(mtu1=1280)) / p_payload
        p6_reply.hlim -= 1
        rx = self.send_and_expect(self.pg0, p6*1, self.pg1)
        for p in rx:
            p.show2()
            self.validate(p[1], p6_reply)


        '''
        # Should fail. Too large MTU
        p_icmp6 = ICMPv6PacketTooBig(mtu=1280, cksum=0x4c7a)
        icmp6_reply = (IPv6(src=self.pg0.local_ip6,
                            dst=self.pg0.remote_ip6,
                            hlim=255, plen=1240) /
                       p_icmp6 / p_ip6 / p_payload)
        icmp6_reply[2].hlim -= 1
        n = icmp6_reply.__class__(icmp6_reply)
        s = bytes(icmp6_reply)
        icmp6_reply_str = s[0:1280]

        rx = self.send_and_expect(self.pg0, p6*9, self.pg0)
        for p in rx:
            self.validate_bytes(bytes(p[1]), icmp6_reply_str)
        '''
        # Reset MTU
        self.vapi.sw_interface_set_mtu(self.pg1.sw_if_index,
                                       [current_mtu, 0, 0, 0])


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
