#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2026 Cisco Systems, Inc.
"""RFC 7112 compliance tests for IPv6 fragment reassembly

RFC 7112 Section 5 requires that the first fragment of an IPv6 datagram
must contain the entire IPv6 Header Chain, including the complete
upper-layer protocol header (UDP, TCP, ICMPv6, etc.).

This test suite validates that VPP correctly handles first fragments
with complete upper-layer headers for UDP, TCP, and ICMPv6.
"""

import unittest
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment, ICMPv6EchoRequest
from scapy.layers.inet import UDP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from framework import VppTestCase
from asfframework import VppTestRunner


class TestRFC7112(VppTestCase):
    """RFC 7112 - IPv6 Fragment Header Chain Validation"""

    @classmethod
    def setUpClass(cls):
        super(TestRFC7112, cls).setUpClass()
        cls.create_pg_interfaces(range(2))
        cls.src_if = cls.pg0
        cls.dst_if = cls.pg1

        for i in cls.pg_interfaces:
            i.admin_up()
            i.config_ip6()
            i.resolve_ndp()

    @classmethod
    def tearDownClass(cls):
        super(TestRFC7112, cls).tearDownClass()

    def setUp(self):
        super(TestRFC7112, self).setUp()
        self.vapi.ip_reassembly_enable_disable(
            sw_if_index=self.src_if.sw_if_index, enable_ip6=True
        )

    def tearDown(self):
        self.vapi.ip_reassembly_enable_disable(
            sw_if_index=self.src_if.sw_if_index, enable_ip6=False
        )
        super(TestRFC7112, self).tearDown()

    def test_rfc7112_udp_complete_header(self):
        """RFC 7112: UDP first fragment with complete header (8 bytes)"""

        # First fragment with complete UDP header
        frag1 = (
            Ether(src=self.src_if.remote_mac, dst=self.src_if.local_mac)
            / IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6)
            / IPv6ExtHdrFragment(offset=0, m=1, id=3000, nh=17)
            / UDP(sport=1234, dport=5678, len=16, chksum=0)
            / Raw(b"AAAA")
        )

        # Second fragment
        frag2 = (
            Ether(src=self.src_if.remote_mac, dst=self.src_if.local_mac)
            / IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6)
            / IPv6ExtHdrFragment(offset=1, m=0, id=3000, nh=17)
            / Raw(b"BBBB")
        )

        self.src_if.add_stream([frag1, frag2])
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.dst_if.get_capture(1, timeout=2)
        self.assertEqual(len(rx), 1)
        self.logger.info("PASS: UDP with complete 8-byte header reassembled")

    def test_rfc7112_tcp_complete_header(self):
        """RFC 7112: TCP first fragment with complete header (20 bytes)"""

        # First fragment with complete TCP header (20 bytes minimum)
        frag1 = (
            Ether(src=self.src_if.remote_mac, dst=self.src_if.local_mac)
            / IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6)
            / IPv6ExtHdrFragment(offset=0, m=1, id=3001, nh=6)
            / TCP(sport=1234, dport=80, flags="S", seq=1000)
            / Raw(b"X" * 50)
        )

        # Second fragment
        frag2 = (
            Ether(src=self.src_if.remote_mac, dst=self.src_if.local_mac)
            / IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6)
            / IPv6ExtHdrFragment(offset=9, m=0, id=3001, nh=6)
            / Raw(b"Y" * 50)
        )

        self.src_if.add_stream([frag1, frag2])
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.dst_if.get_capture(1, timeout=2)
        self.assertEqual(len(rx), 1)
        self.logger.info("PASS: TCP with complete 20-byte header reassembled")

    def test_rfc7112_icmpv6_complete_header(self):
        """RFC 7112: ICMPv6 first fragment with complete header (8 bytes)"""

        # First fragment with complete ICMPv6 Echo header (8 bytes)
        frag1 = (
            Ether(src=self.src_if.remote_mac, dst=self.src_if.local_mac)
            / IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6)
            / IPv6ExtHdrFragment(offset=0, m=1, id=3002, nh=58)
            / ICMPv6EchoRequest(id=100, seq=1)
            / Raw(b"PING")
        )

        # Second fragment
        frag2 = (
            Ether(src=self.src_if.remote_mac, dst=self.src_if.local_mac)
            / IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6)
            / IPv6ExtHdrFragment(offset=2, m=0, id=3002, nh=58)
            / Raw(b"DATA")
        )

        self.src_if.add_stream([frag1, frag2])
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.dst_if.get_capture(1, timeout=2)
        self.assertEqual(len(rx), 1)
        self.logger.info("PASS: ICMPv6 with complete 8-byte header reassembled")


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
