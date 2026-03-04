#!/usr/bin/env python3

import struct
import unittest

from framework import VppTestCase
from asfframework import VppTestRunner
from ipaddress import *
from config import config

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw


@unittest.skipIf("dns" in config.excluded_plugins, "Exclude DNS plugin tests")
class TestDns(VppTestCase):
    """Dns Test Cases"""

    @classmethod
    def setUpClass(cls):
        super(TestDns, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestDns, cls).tearDownClass()

    def setUp(self):
        super(TestDns, self).setUp()

        self.create_pg_interfaces(range(1))

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    def tearDown(self):
        for i in self.pg_interfaces:
            i.unconfig_ip4()
        super(TestDns, self).tearDown()

    def create_stream(self, src_if):
        """Create input packet stream for defined interface.

        :param VppInterface src_if: Interface to create packet stream for.
        """
        good_request = (
            Ether(dst=src_if.local_mac, src=src_if.remote_mac)
            / IP(src=src_if.remote_ip4)
            / UDP(sport=1234, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="bozo.clown.org"))
        )

        bad_request = (
            Ether(dst=src_if.local_mac, src=src_if.remote_mac)
            / IP(src=src_if.remote_ip4)
            / UDP(sport=1234, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="no.clown.org"))
        )
        pkts = [good_request, bad_request]
        return pkts

    def verify_capture(self, dst_if, capture):
        """Verify captured input packet stream for defined interface.

        :param VppInterface dst_if: Interface to verify captured packet stream
            for.
        :param list capture: Captured packet stream.
        """
        self.logger.info("Verifying capture on interface %s" % dst_if.name)
        for packet in capture:
            dns = packet[DNS]
            self.assertEqual(dns.an[0].rdata, "1.2.3.4")

    def test_dns_unittest(self):
        """DNS Name Resolver Basic Functional Test"""

        # Set up an upstream name resolver. We won't actually go there
        self.vapi.dns_name_server_add_del(
            is_ip6=0, is_add=1, server_address=IPv4Address("8.8.8.8").packed
        )

        # Enable name resolution
        self.vapi.dns_enable_disable(enable=1)

        # Manually add a static dns cache entry
        self.logger.info(self.vapi.cli("dns cache add bozo.clown.org 1.2.3.4"))

        # Test the binary API
        rv = self.vapi.dns_resolve_name(name=b"bozo.clown.org")
        self.assertEqual(rv.ip4_address, IPv4Address("1.2.3.4").packed)

        # Configure 127.0.0.1/8 on the pg interface
        self.vapi.sw_interface_add_del_address(
            sw_if_index=self.pg0.sw_if_index, prefix="127.0.0.1/8"
        )

        # Send a couple of DNS request packets, one for bozo.clown.org
        # and one for no.clown.org which won't resolve

        pkts = self.create_stream(self.pg0)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)

        self.pg_start()
        pkts = self.pg0.get_capture(1)
        self.verify_capture(self.pg0, pkts)

        # Make sure that the cache contents are correct
        str = self.vapi.cli("show dns cache verbose")
        self.assertIn("1.2.3.4", str)
        self.assertIn("[P] no.clown.org:", str)

    def _build_raw_dns_request(self, src_if, qname_bytes):
        """Build an Ethernet/IP/UDP frame carrying a hand-crafted DNS request.

        qname_bytes is the raw QNAME field (no QTYPE/QCLASS — those are
        appended here).  The DNS header has RD set and qdcount=1.
        """
        # DNS header: id, flags (RD), qdcount=1, ancount=0, nscount=0, arcount=0
        dns_hdr = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        # Question: QNAME + QTYPE=A(1) + QCLASS=IN(1)
        dns_payload = dns_hdr + qname_bytes + struct.pack("!HH", 1, 1)
        return (
            Ether(dst=src_if.local_mac, src=src_if.remote_mac)
            / IP(src=src_if.remote_ip4)
            / UDP(sport=1234, dport=53)
            / Raw(load=dns_payload)
        )

    def _dns_enable(self):
        self.vapi.dns_name_server_add_del(
            is_ip6=0, is_add=1, server_address=IPv4Address("8.8.8.8").packed
        )
        self.vapi.dns_enable_disable(enable=1)

    def test_dns_cyclic_pointer(self):
        """DNS: cyclic compressed pointer must not cause an infinite loop"""
        self._dns_enable()

        # QNAME at offset 12 (right after the 12-byte DNS header).
        # \xc0\x0c is a pointer to offset 12, i.e. it points back to
        # itself, creating an A→A cycle.
        qname = b"\x03foo\xc0\x0c"
        pkt = self._build_raw_dns_request(self.pg0, qname)

        self.pg0.add_stream([pkt])
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # VPP must drop the malformed packet — no DNS reply expected.
        capture = self.pg0.get_capture(0)
        self.assertEqual(len(capture), 0)

    def test_dns_oob_pointer(self):
        """DNS: compressed pointer with out-of-bounds offset must be rejected"""
        self._dns_enable()

        # \xc0\xff → pointer to offset 255.  The whole packet is ~22 bytes,
        # so offset 255 is well past the end of the buffer.
        qname = b"\xc0\xff"
        pkt = self._build_raw_dns_request(self.pg0, qname)

        self.pg0.add_stream([pkt])
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        capture = self.pg0.get_capture(0)
        self.assertEqual(len(capture), 0)

    def test_dns_oversized_name(self):
        """DNS: name expanding beyond 253 chars must be rejected"""
        self._dns_enable()

        # 50 segments of 5 chars → "aaaaa.aaaaa.…" = 299 chars > 253.
        # The check vec_len(reply) + len > DNS_MAX_NAME_LEN triggers at
        # segment 43 (cumulative length would reach 257).
        qname = b"\x05aaaaa" * 50 + b"\x00"
        pkt = self._build_raw_dns_request(self.pg0, qname)

        self.pg0.add_stream([pkt])
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        capture = self.pg0.get_capture(0)
        self.assertEqual(len(capture), 0)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
