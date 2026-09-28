#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Ethernet trailer is not forwarded"""

import unittest

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrHopByHop
from scapy.compat import raw

from framework import VppTestCase
from asfframework import VppTestRunner

N = 5


class TestEthTrailer(VppTestCase):
    """Ethernet trailer is not forwarded"""

    @classmethod
    def setUpClass(cls):
        super(TestEthTrailer, cls).setUpClass()
        cls.create_pg_interfaces(range(2))

    def setUp(self):
        super(TestEthTrailer, self).setUp()
        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.config_ip6()
            i.disable_ipv6_ra()
            i.resolve_arp()
            i.resolve_ndp()

    def tearDown(self):
        super(TestEthTrailer, self).tearDown()
        if not self.vpp_dead:
            for i in self.pg_interfaces:
                i.unconfig_ip4()
                i.unconfig_ip6()
                i.admin_down()

    def ip(self, af):
        if af == 4:
            return IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) / TCP()
        return IPv6(src=self.pg0.remote_ip6, dst=self.pg1.remote_ip6) / TCP()

    def frame(self, l3, trailer):
        e = Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
        return Ether(raw(e / l3) + b"\x00" * trailer)

    def forwarded(self, l3):
        exp = l3.copy()
        if IP in exp:
            exp[IP].ttl -= 1
            del exp[IP].chksum
        else:
            exp[IPv6].hlim -= 1
        return raw(exp)

    def check(self, af, trailer):
        l3 = self.ip(af)
        rx = self.send_and_expect(self.pg0, [self.frame(l3, trailer)] * N, self.pg1)
        for p in rx:
            self.assertEqual(raw(p)[14:], self.forwarded(l3))

    def test_ip4_trailer(self):
        """IP4 trailer is trimmed: min-frame pad, one buffer, chained"""
        for trailer in (6, 1400, 2060):
            self.check(4, trailer)

    def test_ip6_trailer(self):
        """IP6 trailer is trimmed: one buffer, chained"""
        for trailer in (6, 1400, 2060):
            self.check(6, trailer)

    def test_trailer_mtu(self):
        """Trailer does not count against the egress MTU"""
        idx = self.pg1.sw_if_index
        old = list(self.vapi.sw_interface_dump(sw_if_index=idx)[0].mtu)
        self.vapi.sw_interface_set_mtu(idx, [1500, 0, 0, 0])
        try:
            self.check(4, 2060)
            self.check(6, 2060)
            self.assert_error_counter_equal("/err/ip4-input/mtu_exceeded", 0)
            self.assert_error_counter_equal("/err/ip6-input/mtu_exceeded", 0)
        finally:
            self.vapi.sw_interface_set_mtu(idx, old)

    def test_ip6_truncated(self):
        """IP6 payload length past the buffer is dropped"""
        l3 = self.ip(6)
        l3[IPv6].plen = 100
        self.send_and_assert_no_replies(self.pg0, [self.frame(l3, 0)] * N)
        self.assert_error_counter_equal("/err/ip6-input/bad_length", N)

    def test_ip6_plen_zero(self):
        """IP6 payload length 0 without hop-by-hop is the bare header"""
        l3 = self.ip(6)
        l3[IPv6].plen = 0
        rx = self.send_and_expect(self.pg0, [self.frame(l3, 6)] * N, self.pg1)
        for p in rx:
            self.assertEqual(len(raw(p)), 14 + 40)

    def test_ip6_jumbo(self):
        """IP6 payload length 0 with hop-by-hop is not length-checked"""
        l3 = (
            IPv6(src=self.pg0.remote_ip6, dst=self.pg1.remote_ip6, plen=0)
            / IPv6ExtHdrHopByHop()
            / TCP()
        )
        for trailer in (6, 2060):
            self.pg_send(self.pg0, [self.frame(l3, trailer)] * N)
        self.assert_error_counter_equal("/err/ip6-input/bad_length", 0)
        self.assert_error_counter_equal("/err/ip6-input/too_short", 0)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
