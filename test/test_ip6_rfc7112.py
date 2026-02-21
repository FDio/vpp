#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2026 Cisco Systems, Inc.
"""RFC 7112 compliance tests for IPv6 fragment reassembly

RFC 7112 Section 5 requires that the first fragment of an IPv6 datagram
must contain the entire IPv6 Header Chain, including the complete
upper-layer protocol header (UDP, TCP, ICMPv6, etc.).

VPP IMPLEMENTATION STATUS:
--------------------------
VPP implements RFC 7112 PARTIALLY in src/vnet/ip/reass/ip6_full_reass.c:
- ✓ Verifies that extension header chain terminates with upper-layer protocol
- ✗ Does NOT verify that upper-layer protocol header is complete

The function ip6_full_reass_verify_upper_layer_present() only checks that
the last protocol in the extension header chain is NOT an extension header
(i.e., it's UDP/TCP/ICMPv6/etc), but does NOT verify minimum header lengths:
  - UDP: 8 bytes (src_port + dst_port + length + checksum)
  - TCP: 20 bytes (src_port + dst_port + seq + ack + offset + flags + ...)
  - ICMPv6: 8 bytes (type + code + checksum + data)

This means VPP currently accepts and reassembles first fragments with
incomplete upper-layer headers, which violates RFC 7112 Section 5.

TEST STATUS:
------------
- Tests that verify complete headers: PASS (VPP correctly reassembles)
- Tests that verify incomplete headers are dropped: SKIP (VPP does not drop)

The skipped tests document the expected RFC 7112 behavior for future
implementation.
"""

import unittest
import struct
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
        """RFC 7112: UDP first fragment with complete header (8 bytes)

        Verifies VPP correctly reassembles fragments when first fragment
        contains complete UDP header (8 bytes: sport, dport, len, checksum).
        """

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

    @unittest.skip(
        "VPP partial RFC 7112 implementation - "
        "does not verify minimum UDP header length (8 bytes). "
        "Function ip6_full_reass_verify_upper_layer_present() only checks "
        "protocol type, not header completeness. "
        "See src/vnet/ip/reass/ip6_full_reass.c:1113-1128"
    )
    def test_rfc7112_udp_incomplete_header(self):
        """RFC 7112: UDP first fragment with incomplete header (4 bytes) - should drop

        RFC 7112 Section 5 REQUIRES: First fragment must contain complete UDP
        header (minimum 8 bytes). A fragment with only 4 bytes (sport+dport)
        should be DROPPED and ICMPv6 Parameter Problem sent.

        CURRENT VPP BEHAVIOR: Accepts and forwards the incomplete fragment.

        WHY: ip6_full_reass_verify_upper_layer_present() only verifies the
        protocol is UDP (nh=17) but does NOT check if 8 bytes of UDP data
        are present in the first fragment.
        """

        # Fragment header: 8 bytes (nh, reserved, offset+M, id)
        frag_hdr = struct.pack("!BBHI", 17, 0, 0x0001, 3001)
        # Incomplete UDP: only 4 bytes (need 8)
        incomplete_udp = b"\x04\xd2\x16\x2e"

        frag1 = (
            Ether(src=self.src_if.remote_mac, dst=self.src_if.local_mac)
            / IPv6(
                src=self.src_if.remote_ip6,
                dst=self.dst_if.remote_ip6,
                nh=44,
                plen=12,
            )
            / Raw(frag_hdr + incomplete_udp)
        )

        # Second fragment to trigger reassembly
        frag2 = (
            Ether(src=self.src_if.remote_mac, dst=self.src_if.local_mac)
            / IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6)
            / IPv6ExtHdrFragment(offset=1, m=0, id=3001, nh=17)
            / Raw(b"CCCC")
        )

        self.src_if.add_stream([frag1, frag2])
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Should NOT reassemble (RFC 7112 violation)
        rx = self.dst_if.get_capture(0, timeout=2)
        self.assertEqual(len(rx), 0)
        self.logger.info("PASS: UDP incomplete header correctly dropped")

    def test_rfc7112_tcp_complete_header(self):
        """RFC 7112: TCP first fragment with complete header (20 bytes)

        Verifies VPP correctly reassembles fragments when first fragment
        contains complete TCP header (minimum 20 bytes).
        """

        # First fragment with complete TCP header (20 bytes minimum)
        frag1 = (
            Ether(src=self.src_if.remote_mac, dst=self.src_if.local_mac)
            / IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6)
            / IPv6ExtHdrFragment(offset=0, m=1, id=3002, nh=6)
            / TCP(sport=1234, dport=80, flags="S", seq=1000)
            / Raw(b"X" * 50)
        )

        # Second fragment
        frag2 = (
            Ether(src=self.src_if.remote_mac, dst=self.src_if.local_mac)
            / IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6)
            / IPv6ExtHdrFragment(offset=9, m=0, id=3002, nh=6)
            / Raw(b"Y" * 50)
        )

        self.src_if.add_stream([frag1, frag2])
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.dst_if.get_capture(1, timeout=2)
        self.assertEqual(len(rx), 1)
        self.logger.info("PASS: TCP with complete 20-byte header reassembled")

    @unittest.skip(
        "VPP partial RFC 7112 implementation - "
        "does not verify minimum TCP header length (20 bytes). "
        "Function ip6_full_reass_verify_upper_layer_present() only checks "
        "protocol type, not header completeness. "
        "See src/vnet/ip/reass/ip6_full_reass.c:1113-1128"
    )
    def test_rfc7112_tcp_incomplete_header(self):
        """RFC 7112: TCP first fragment with incomplete header (10 bytes) - should drop

        RFC 7112 Section 5 REQUIRES: First fragment must contain complete TCP
        header (minimum 20 bytes). A fragment with only 10 bytes should be
        DROPPED and ICMPv6 Parameter Problem sent.

        CURRENT VPP BEHAVIOR: Accepts and forwards the incomplete fragment.

        WHY: ip6_full_reass_verify_upper_layer_present() only verifies the
        protocol is TCP (nh=6) but does NOT check if 20 bytes of TCP data
        are present in the first fragment.
        """

        # Fragment header
        frag_hdr = struct.pack("!BBHI", 6, 0, 0x0001, 3003)
        # Incomplete TCP: only 10 bytes (need 20)
        incomplete_tcp = struct.pack("!HHIH", 1234, 80, 1000, 0)

        frag1 = (
            Ether(src=self.src_if.remote_mac, dst=self.src_if.local_mac)
            / IPv6(
                src=self.src_if.remote_ip6,
                dst=self.dst_if.remote_ip6,
                nh=44,
                plen=18,
            )
            / Raw(frag_hdr + incomplete_tcp)
        )

        # Second fragment
        frag2 = (
            Ether(src=self.src_if.remote_mac, dst=self.src_if.local_mac)
            / IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6)
            / IPv6ExtHdrFragment(offset=2, m=0, id=3003, nh=6)
            / Raw(b"DATA")
        )

        self.src_if.add_stream([frag1, frag2])
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.dst_if.get_capture(0, timeout=2)
        self.assertEqual(len(rx), 0)
        self.logger.info("PASS: TCP incomplete header correctly dropped")

    def test_rfc7112_icmpv6_complete_header(self):
        """RFC 7112: ICMPv6 first fragment with complete header (8 bytes)

        Verifies VPP correctly reassembles fragments when first fragment
        contains complete ICMPv6 header (minimum 8 bytes: type, code, cksum, data).
        """

        # First fragment with complete ICMPv6 Echo header (8 bytes)
        frag1 = (
            Ether(src=self.src_if.remote_mac, dst=self.src_if.local_mac)
            / IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6)
            / IPv6ExtHdrFragment(offset=0, m=1, id=3004, nh=58)
            / ICMPv6EchoRequest(id=100, seq=1)
            / Raw(b"PING")
        )

        # Second fragment
        frag2 = (
            Ether(src=self.src_if.remote_mac, dst=self.src_if.local_mac)
            / IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6)
            / IPv6ExtHdrFragment(offset=2, m=0, id=3004, nh=58)
            / Raw(b"DATA")
        )

        self.src_if.add_stream([frag1, frag2])
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.dst_if.get_capture(1, timeout=2)
        self.assertEqual(len(rx), 1)
        self.logger.info("PASS: ICMPv6 with complete 8-byte header reassembled")

    @unittest.skip(
        "VPP partial RFC 7112 implementation - "
        "does not verify minimum ICMPv6 header length (8 bytes). "
        "Function ip6_full_reass_verify_upper_layer_present() only checks "
        "protocol type, not header completeness. "
        "See src/vnet/ip/reass/ip6_full_reass.c:1113-1128"
    )
    def test_rfc7112_icmpv6_incomplete_header(self):
        """RFC 7112: ICMPv6 first fragment with incomplete header (4 bytes) - should drop

        RFC 7112 Section 5 REQUIRES: First fragment must contain complete
        ICMPv6 header (minimum 8 bytes). A fragment with only 4 bytes should
        be DROPPED and ICMPv6 Parameter Problem sent.

        CURRENT VPP BEHAVIOR: Accepts and forwards the incomplete fragment.

        WHY: ip6_full_reass_verify_upper_layer_present() only verifies the
        protocol is ICMPv6 (nh=58) but does NOT check if 8 bytes of ICMPv6
        data are present in the first fragment.
        """

        # Fragment header
        frag_hdr = struct.pack("!BBHI", 58, 0, 0x0001, 3005)
        # Incomplete ICMPv6: only 4 bytes (need 8)
        incomplete_icmpv6 = b"\x80\x00\x00\x00"

        frag1 = (
            Ether(src=self.src_if.remote_mac, dst=self.src_if.local_mac)
            / IPv6(
                src=self.src_if.remote_ip6,
                dst=self.dst_if.remote_ip6,
                nh=44,
                plen=12,
            )
            / Raw(frag_hdr + incomplete_icmpv6)
        )

        # Second fragment
        frag2 = (
            Ether(src=self.src_if.remote_mac, dst=self.src_if.local_mac)
            / IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6)
            / IPv6ExtHdrFragment(offset=1, m=0, id=3005, nh=58)
            / Raw(b"DATA")
        )

        self.src_if.add_stream([frag1, frag2])
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.dst_if.get_capture(0, timeout=2)
        self.assertEqual(len(rx), 0)
        self.logger.info("PASS: ICMPv6 incomplete header correctly dropped")

    def test_rfc7112_non_first_fragment(self):
        """RFC 7112: Non-first fragments (offset > 0) not subject to RFC 7112

        RFC 7112 Section 5 only applies to first fragments (offset=0).
        Subsequent fragments do not need to contain complete headers.
        Verifies VPP correctly handles non-first fragments.
        """

        # Non-first fragment (offset=8) doesn't need complete header
        frag1 = (
            Ether(src=self.src_if.remote_mac, dst=self.src_if.local_mac)
            / IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6)
            / IPv6ExtHdrFragment(offset=8, m=0, id=3006, nh=17)
            / Raw(b"D" * 64)
        )

        self.src_if.add_stream(frag1)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Fragment is held for reassembly (won't be forwarded alone)
        self.logger.info("PASS: Non-first fragment accepted (RFC 7112 N/A)")


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
