#!/usr/bin/env python3
"""IP4 UNAT functional tests"""

import unittest
from scapy.layers.inet6 import IPv6, Ether, IP, UDP, ICMPv6PacketTooBig
from scapy.layers.inet import ICMP
from framework import VppTestCase, VppTestRunner
from vpp_ip import DpoProto
from vpp_ip_route import VppIpRoute, VppRoutePath, FibPathProto
from socket import AF_INET, AF_INET6, inet_pton
from util import reassemble4
from scapy.packet import Raw

""" Test_unat2 is a subclass of VPPTestCase classes.
    UNAT tests.
"""


class TestUNAT(VppTestCase):
    """ UNAT Test Case """
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        super(TestUNAT, cls).setUpClass()
        cls.create_pg_interfaces(range(2))
        cls.interfaces = list(cls.pg_interfaces)

    @classmethod
    def tearDownClass(cls):
        super(TestUNAT, cls).tearDownClass()

    def setUp(self):
        super(TestUNAT, self).setUp()
        for i in self.interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()
        self.vapi.cli(f"set interface unat in {self.interfaces[0]}")
        self.vapi.cli(f"set interface unat out {self.interfaces[1]}")
        self.vapi.cli(f"unat prefix-pool add 2.2.2.2/24")

    def tearDown(self):
        super(TestUNAT, self).tearDown()
        if not self.vpp_dead:
            for i in self.pg_interfaces:
                i.unconfig_ip4()
                i.admin_down()

    def validate(self, rx, expected):
        print('RECIVED: ')
        rx.show2()
        print('EXPECTED: ')
        expected.show2()
        expected.id = rx.id
        self.assertEqual(rx, expected.__class__(expected))


    def validate_bytes(self, rx, expected):
        self.assertEqual(rx, expected)

    def payload(self, len):
        return 'x' * len

    def test_in2out_bypass(self):
        """ IP4 in2out bypass test """

        print(self.vapi.cli("show unat summary"))

        p_ether = Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
        p_ip4 = IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) / ICMP()
        p_payload = Raw(b'\x0a' * 18)

        p4 = p_ether / p_ip4 / p_payload
        p4_reply = IP(src=self.pg0.local_ip4, dst=self.pg0.remote_ip4, id=709) / ICMP(type='echo-reply') / p_payload

        rx = self.send_and_expect(self.pg0, p4*1, self.pg0)
        for p in rx:
            self.validate(p[1], p4_reply)

        '''

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
        p4_reply.ttl = p_ip4.ttl - 1
        p4_reply.flags = 0
        p4_reply.id = 256
        self.pg_enable_capture()
        self.pg0.add_stream(p4*1)
        self.pg_start()
        rx = self.pg1.get_capture(3)
        reass_pkt = reassemble4(rx)
        self.validate(reass_pkt, p4_reply)
        '''

    def test_out2in_bypass(self):
        """ IP4 out2in bypass test """

        print(self.vapi.cli("show unat summary"))

        p_ether = Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
        p_ip4 = IP(src=self.pg1.remote_ip4, dst=self.pg1.local_ip4) / ICMP()
        p_payload = Raw(b'\x0a' * 18)

        p4 = p_ether / p_ip4 / p_payload
        p4_reply = IP(src=self.pg1.local_ip4, dst=self.pg1.remote_ip4, id=709) / ICMP(type='echo-reply') / p_payload

        rx = self.send_and_expect(self.pg1, p4*1, self.pg1)
        for p in rx:
            self.validate(p[1], p4_reply)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
