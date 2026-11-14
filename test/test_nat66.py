#!/usr/bin/env python3

import unittest

from framework import VppTestCase
from asfframework import VppTestRunner
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import (
    HBHOptUnknown,
    IPv6,
    IPv6ExtHdrFragment,
    IPv6ExtHdrHopByHop,
    IPv6ExtHdrDestOpt,
    IPv6ExtHdrRouting,
    ICMPv6EchoRequest,
    ICMPv6EchoReply,
)
from scapy.layers.l2 import Ether, GRE
from scapy.packet import Raw
from util import ppp, fragment_rfc8200
from vpp_papi import VppEnum
from config import config


def chain_beyond_depth_packet(src_if, src, dst):
    """A packet whose L4 header lies beyond the extension-header scan depth

    The 224-byte hop-by-hop header is followed by UDP at offset 264, so
    ip6_ext_header_walk() stops at its 256-byte depth limit before reaching
    the UDP header.
    """
    return (
        Ether(dst=src_if.local_mac, src=src_if.remote_mac)
        / IPv6(src=src, dst=dst)
        / IPv6ExtHdrHopByHop(nh=17, options=[HBHOptUnknown(otype=0xFF, optlen=0)] * 108)
        / UDP(sport=1234, dport=5678)
        / Raw(b"X" * 16)
    )


@unittest.skipIf("nat" in config.excluded_plugins, "Exclude NAT plugin tests")
class TestNAT66(VppTestCase):
    """NAT66 Test Cases"""

    @classmethod
    def setUpClass(cls):
        super(TestNAT66, cls).setUpClass()

        cls.nat_addr = "fd01:ff::2"
        cls.create_pg_interfaces(range(2))
        cls.interfaces = list(cls.pg_interfaces)

        for i in cls.interfaces:
            i.admin_up()
            i.config_ip6()
            i.configure_ipv6_neighbors()

    @property
    def config_flags(self):
        return VppEnum.vl_api_nat_config_flags_t

    def plugin_enable(self):
        self.vapi.nat66_plugin_enable_disable(enable=1)

    def plugin_disable(self):
        self.vapi.nat66_plugin_enable_disable(enable=0)

    def setUp(self):
        super(TestNAT66, self).setUp()
        self.plugin_enable()

    def tearDown(self):
        super(TestNAT66, self).tearDown()
        if not self.vpp_dead:
            self.plugin_disable()

    def test_static(self):
        """1:1 NAT66 test"""
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat66_add_del_interface(
            is_add=1, flags=flags, sw_if_index=self.pg0.sw_if_index
        )
        self.vapi.nat66_add_del_interface(is_add=1, sw_if_index=self.pg1.sw_if_index)
        self.vapi.nat66_add_del_static_mapping(
            local_ip_address=self.pg0.remote_ip6,
            external_ip_address=self.nat_addr,
            is_add=1,
        )

        # in2out
        pkts = []
        p = (
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / IPv6(src=self.pg0.remote_ip6, dst=self.pg1.remote_ip6)
            / TCP()
        )
        pkts.append(p)
        p = (
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / IPv6(src=self.pg0.remote_ip6, dst=self.pg1.remote_ip6)
            / UDP()
        )
        pkts.append(p)
        p = (
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / IPv6(src=self.pg0.remote_ip6, dst=self.pg1.remote_ip6)
            / ICMPv6EchoRequest()
        )
        pkts.append(p)
        p = (
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / IPv6(src=self.pg0.remote_ip6, dst=self.pg1.remote_ip6)
            / GRE()
            / IP()
            / TCP()
        )
        pkts.append(p)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))

        for packet in capture:
            try:
                self.assertEqual(packet[IPv6].src, self.nat_addr)
                self.assertEqual(packet[IPv6].dst, self.pg1.remote_ip6)
                self.assert_packet_checksums_valid(packet)
            except:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise

        # out2in
        pkts = []
        p = (
            Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac)
            / IPv6(src=self.pg1.remote_ip6, dst=self.nat_addr)
            / TCP()
        )
        pkts.append(p)
        p = (
            Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac)
            / IPv6(src=self.pg1.remote_ip6, dst=self.nat_addr)
            / UDP()
        )
        pkts.append(p)
        p = (
            Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac)
            / IPv6(src=self.pg1.remote_ip6, dst=self.nat_addr)
            / ICMPv6EchoReply()
        )
        pkts.append(p)
        p = (
            Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac)
            / IPv6(src=self.pg1.remote_ip6, dst=self.nat_addr)
            / GRE()
            / IP()
            / TCP()
        )
        pkts.append(p)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(len(pkts))
        for packet in capture:
            try:
                self.assertEqual(packet[IPv6].src, self.pg1.remote_ip6)
                self.assertEqual(packet[IPv6].dst, self.pg0.remote_ip6)
                self.assert_packet_checksums_valid(packet)
            except:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise

        sm = self.vapi.nat66_static_mapping_dump()
        self.assertEqual(len(sm), 1)
        self.assertEqual(sm[0].total_pkts, 8)

    def test_non_first_fragment(self):
        """NAT66 does not treat a non-first fragment's payload as an L4 header

        A non-first fragment carries no L4 header. The node must translate
        the address without writing a checksum over the fragment payload.

        The first fragment is sent with the non-first fragment because the
        interface's shallow virtual reassembly caches non-first fragments
        until it has seen the first one."""
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat66_add_del_interface(
            is_add=1, flags=flags, sw_if_index=self.pg0.sw_if_index
        )
        self.vapi.nat66_add_del_interface(is_add=1, sw_if_index=self.pg1.sw_if_index)
        self.vapi.nat66_add_del_static_mapping(
            local_ip_address=self.pg0.remote_ip6,
            external_ip_address=self.nat_addr,
            is_add=1,
        )

        # The second fragment starts with the first eight payload bytes.
        # Bytes 6 and 7 would be the UDP checksum field if the payload were
        # mistaken for a UDP header.
        payload = b"\x00" * 8 + b"\xaa" * 64

        p = (
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / IPv6(src=self.pg0.remote_ip6, dst=self.pg1.remote_ip6)
            / UDP(sport=1234, dport=5678)
            / Raw(payload)
        )
        fragments = fragment_rfc8200(p, 1, 70)
        self.assertGreater(len(fragments), 1)
        first, second = fragments[0], fragments[1]
        self.assertNotEqual(second[IPv6ExtHdrFragment].offset, 0)

        # in2out
        recvd = self.send_and_expect(self.pg0, [first, second], self.pg1)
        packet = next(p for p in recvd if p[IPv6ExtHdrFragment].offset != 0)
        self.assertEqual(packet[IPv6].src, self.nat_addr)
        self.assertEqual(packet[IPv6].dst, self.pg1.remote_ip6)
        self.assertEqual(bytes(packet[Raw].load), bytes(second[Raw].load))

        # out2in
        p = (
            Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac)
            / IPv6(src=self.pg1.remote_ip6, dst=self.nat_addr)
            / UDP(sport=1234, dport=5678)
            / Raw(payload)
        )
        fragments = fragment_rfc8200(p, 2, 70)
        first, second = fragments[0], fragments[1]

        recvd = self.send_and_expect(self.pg1, [first, second], self.pg0)
        packet = next(p for p in recvd if p[IPv6ExtHdrFragment].offset != 0)
        self.assertEqual(packet[IPv6].src, self.pg1.remote_ip6)
        self.assertEqual(packet[IPv6].dst, self.pg0.remote_ip6)
        self.assertEqual(bytes(packet[Raw].load), bytes(second[Raw].load))

    def test_l4_header_after_chain_limit(self):
        """NAT66 updates the L4 checksum when four chain headers fill the limit

        Four extension headers fill the chain and the next protocol is UDP.
        The walk must recognise the L4 header instead of stopping at the
        entry limit. Only a complete L4 header updates the checksum, so a
        limit stop would leave the translated packet's UDP checksum invalid.
        """
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat66_add_del_interface(
            is_add=1, flags=flags, sw_if_index=self.pg0.sw_if_index
        )
        self.vapi.nat66_add_del_interface(is_add=1, sw_if_index=self.pg1.sw_if_index)
        self.vapi.nat66_add_del_static_mapping(
            local_ip_address=self.pg0.remote_ip6,
            external_ip_address=self.nat_addr,
            is_add=1,
        )

        p = (
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / IPv6(src=self.pg0.remote_ip6, dst=self.pg1.remote_ip6)
            / IPv6ExtHdrHopByHop(nh=60)
            / IPv6ExtHdrDestOpt(nh=43)
            / IPv6ExtHdrRouting(nh=60)
            / IPv6ExtHdrDestOpt(nh=17)
            / UDP(sport=1234, dport=5678)
            / Raw(b"X" * 16)
        )

        recvd = self.send_and_expect(self.pg0, [p], self.pg1)
        packet = recvd[0]
        self.assertEqual(packet[IPv6].src, self.nat_addr)
        self.assertEqual(packet[IPv6].dst, self.pg1.remote_ip6)
        self.assertEqual(bytes(packet[Raw].load), b"X" * 16)
        self.assert_packet_checksums_valid(packet)

    def test_chain_beyond_depth_dropped(self):
        """NAT66 drops an in2out packet whose L4 header is beyond the scan depth

        The hop-by-hop header ends past the 256-byte scan depth, so the walk
        stops before the UDP header. Translating the source address without
        updating the UDP checksum would corrupt the packet, so the node must
        drop it.
        """
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat66_add_del_interface(
            is_add=1, flags=flags, sw_if_index=self.pg0.sw_if_index
        )
        self.vapi.nat66_add_del_interface(is_add=1, sw_if_index=self.pg1.sw_if_index)
        self.vapi.nat66_add_del_static_mapping(
            local_ip_address=self.pg0.remote_ip6,
            external_ip_address=self.nat_addr,
            is_add=1,
        )

        error_cnt_str = "/err/nat66-in2out/unknown"
        error_cnt = self.statistics.get_err_counter(error_cnt_str)
        p = chain_beyond_depth_packet(
            self.pg0, self.pg0.remote_ip6, self.pg1.remote_ip6
        )

        self.send_and_assert_no_replies(self.pg0, [p])
        self.assert_error_counter_equal(error_cnt_str, error_cnt + 1)

    def test_chain_beyond_depth_dropped_out2in(self):
        """NAT66 drops an out2in packet whose L4 header is beyond the scan depth

        The hop-by-hop header ends past the 256-byte scan depth, so the walk
        stops before the UDP header. Translating the destination address
        without updating the UDP checksum would corrupt the packet, so the
        node must drop it.
        """
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat66_add_del_interface(
            is_add=1, flags=flags, sw_if_index=self.pg0.sw_if_index
        )
        self.vapi.nat66_add_del_interface(is_add=1, sw_if_index=self.pg1.sw_if_index)
        self.vapi.nat66_add_del_static_mapping(
            local_ip_address=self.pg0.remote_ip6,
            external_ip_address=self.nat_addr,
            is_add=1,
        )

        error_cnt_str = "/err/nat66-out2in/unknown"
        error_cnt = self.statistics.get_err_counter(error_cnt_str)
        p = chain_beyond_depth_packet(self.pg1, self.pg1.remote_ip6, self.nat_addr)

        self.send_and_assert_no_replies(self.pg1, [p])
        self.assert_error_counter_equal(error_cnt_str, error_cnt + 1)

    def test_check_no_translate(self):
        """NAT66 translate only when egress interface is outside interface"""
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat66_add_del_interface(
            is_add=1, flags=flags, sw_if_index=self.pg0.sw_if_index
        )
        self.vapi.nat66_add_del_interface(
            is_add=1, flags=flags, sw_if_index=self.pg1.sw_if_index
        )
        self.vapi.nat66_add_del_static_mapping(
            local_ip_address=self.pg0.remote_ip6,
            external_ip_address=self.nat_addr,
            is_add=1,
        )

        # in2out
        p = (
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / IPv6(src=self.pg0.remote_ip6, dst=self.pg1.remote_ip6)
            / UDP()
        )
        self.pg0.add_stream([p])
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(1)
        packet = capture[0]
        try:
            self.assertEqual(packet[IPv6].src, self.pg0.remote_ip6)
            self.assertEqual(packet[IPv6].dst, self.pg1.remote_ip6)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", packet))
            raise


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
