#!/usr/bin/env python
"""IP4 and IP6 MTU functional tests"""

#
# Add tests for:
# - sub interfaces
# - Verify that adjacencies inherit MTU correctly
# - Verify that sub-interfaces inherit MTU correctly
# - Different types of interfaces?
#
import unittest
from scapy.layers.inet6 import IPv6, Ether, IP, UDP, ICMPv6PacketTooBig
from scapy.layers.inet import ICMP
from framework import VppTestCase, VppTestRunner
from vpp_ip import DPO_PROTO
from vpp_ip_route import VppIpRoute, VppRoutePath
from socket import AF_INET, AF_INET6, inet_pton
from util import reassemble4


""" Test_mtu is a subclass of VPPTestCase classes.
    MTU tests.
"""


class TestMTU(VppTestCase):
    """ MTU Test Case """
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        super(TestMTU, cls).setUpClass()
        cls.create_pg_interfaces(range(2))
        cls.interfaces = list(cls.pg_interfaces)

    def setUp(self):
        super(TestMTU, self).setUp()
        for i in self.interfaces:
            i.admin_up()
            i.config_ip4()
            i.config_ip6()
            i.disable_ipv6_ra()
            i.resolve_arp()
            i.resolve_ndp()

    def tearDown(self):
        super(TestMTU, self).tearDown()
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

    def test_ip4_mtu(self):
        """ IP4 MTU test """

        p_ether = Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
        p_ip4 = IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4,
                   flags='DF')

        current_mtu = self.get_mtu(self.pg1.sw_if_index)

        p_payload = UDP(sport=1234, dport=1234) / self.payload(
            current_mtu - 20 - 8)

        p4 = p_ether / p_ip4 / p_payload
        p4_reply = p_ip4 / p_payload
        p4_reply.ttl -= 1
        rx = self.send_and_expect(self.pg0, p4*11, self.pg1)
        for p in rx:
            self.validate(p[1], p4_reply)

        # MTU
        self.vapi.sw_interface_set_mtu(self.pg1.sw_if_index, [576, 0, 0, 0])
        self.assertEqual(576, self.get_mtu(self.pg1.sw_if_index))

        # Should fail. Too large MTU
        p_icmp4 = ICMP(type='dest-unreach', code='fragmentation-needed',
                       nexthopmtu=576, chksum=0x2dbb)
        icmp4_reply = (IP(src=self.pg0.local_ip4,
                          dst=self.pg0.remote_ip4,
                          ttl=254, len=576, id=0) /
                       p_icmp4 / p_ip4 / p_payload)
        icmp4_reply[1].ttl -= 1
        n = icmp4_reply.__class__(icmp4_reply)
        s = bytes(icmp4_reply)
        icmp4_reply = s[0:576]
        rx = self.send_and_expect(self.pg0, p4*11, self.pg0)
        for p in rx:
            # p.show2()
            # n.show2()
            self.validate_bytes(bytes(p[1]), icmp4_reply)

        # Now with DF off. Expect fragments.
        # First go with 1500 byte packets.
        p_payload = UDP(sport=1234, dport=1234) / self.payload(
            1500 - 20 - 8)
        p4 = p_ether / p_ip4 / p_payload
        p4.flags = 0
        p4_reply = p_ip4 / p_payload
        p4_reply.ttl = 62  # check this
        p4_reply.flags = 0
        p4_reply.id = 256
        self.pg_enable_capture()
        self.pg0.add_stream(p4*1)
        self.pg_start()
        rx = self.pg1.get_capture(3)
        reass_pkt = reassemble4(rx)
        self.validate(reass_pkt, p4_reply)

        '''
        # Now what happens with a 9K frame
        p_payload = UDP(sport=1234, dport=1234) / self.payload(
            current_mtu - 20 - 8)
        p4 = p_ether / p_ip4 / p_payload
        p4.flags = 0
        p4_reply = p_ip4 / p_payload
        p4_reply.ttl = 62 # check this
        p4_reply.flags = 0
        p4_reply.id = 512

        self.pg_enable_capture()
        self.pg0.add_stream(p4*1)
        self.pg_start()
        rx = self.pg1.get_capture(16)
        reass_pkt = reassemble4(rx)
        reass_pkt.show2()
        p4_reply.show2()
        self.validate(reass_pkt, p4_reply)
        '''

        # Reset MTU
        self.vapi.sw_interface_set_mtu(self.pg1.sw_if_index,
                                       [current_mtu, 0, 0, 0])

    def test_ip6_mtu(self):
        """ IP6 MTU test """

        current_mtu = self.get_mtu(self.pg1.sw_if_index)

        p_ether = Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
        p_ip6 = IPv6(src=self.pg0.remote_ip6, dst=self.pg1.remote_ip6)

        p_payload = UDP(sport=1234, dport=1234) / self.payload(
            current_mtu - 40 - 8)

        p6 = p_ether / p_ip6 / p_payload
        p6_reply = p_ip6 / p_payload
        p6_reply.hlim -= 1
        rx = self.send_and_expect(self.pg0, p6*9, self.pg1)
        for p in rx:
            self.validate(p[1], p6_reply)

        # MTU (only checked on encap)
        self.vapi.sw_interface_set_mtu(self.pg1.sw_if_index, [1280, 0, 0, 0])
        self.assertEqual(1280, self.get_mtu(self.pg1.sw_if_index))

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

        # Reset MTU
        self.vapi.sw_interface_set_mtu(self.pg1.sw_if_index,
                                       [current_mtu, 0, 0, 0])


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
