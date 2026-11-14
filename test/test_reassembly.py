#!/usr/bin/env python3

import struct
import unittest
from random import shuffle, randrange

from framework import VppTestCase, Send, Expect
from asfframework import VppTestRunner

from scapy.packet import Raw
from scapy.layers.l2 import Ether, GRE
from scapy.layers.inet import IP, UDP, ICMP, icmptypes
from scapy.layers.inet6 import (
    HBHOptUnknown,
    ICMPv6ParamProblem,
    ICMPv6TimeExceeded,
    IPv6,
    IPv6ExtHdrFragment,
    IPv6ExtHdrHopByHop,
    IPv6ExtHdrDestOpt,
    IPv6ExtHdrRouting,
    ICMPv6EchoRequest,
    ICMPv6EchoReply,
    ICMPv6ND_RS,
    getmacbyip6,
)
from scapy.layers.sctp import SCTP
from util import ppp, fragment_rfc791, fragment_rfc8200
from vpp_gre_interface import VppGreInterface
from vpp_ip_route import (
    FibPathProto,
    FibPathType,
    VppIpMRoute,
    VppMRoutePath,
    VppIpRoute,
    VppRoutePath,
)
from vpp_papi import VppEnum
from config import config

# 35 is enough to have >257 400-byte fragments
test_packet_count = 35


def chain_limit_first_fragment(src_if, dst_if, payload):
    """A first fragment with the fragment header in the fourth chain slot.

    The fragment header names a destination options header, so the walk
    stops at the entry limit with an extension header last.
    """
    return (
        Ether(dst=src_if.local_mac, src=src_if.remote_mac)
        / IPv6(src=src_if.remote_ip6, dst=dst_if.remote_ip6)
        / IPv6ExtHdrHopByHop(nh=60)
        / IPv6ExtHdrDestOpt(nh=43)
        / IPv6ExtHdrRouting(nh=44)
        / IPv6ExtHdrFragment(offset=0, m=1, nh=60)
        / IPv6ExtHdrDestOpt(nh=17)
        / UDP(sport=1234, dport=5678)
        / Raw(payload)
    )


def entry_limit_l4_fragments(src_if, dst_if, payload_first, payload_last):
    """First and last fragments with a terminating UDP header in the fifth slot.

    Four extension headers fill the chain and the next protocol is UDP, so
    the walk recognises the L4 header at the entry limit.
    """
    first = (
        Ether(dst=src_if.local_mac, src=src_if.remote_mac)
        / IPv6(src=src_if.remote_ip6, dst=dst_if.remote_ip6)
        / IPv6ExtHdrHopByHop(nh=60)
        / IPv6ExtHdrDestOpt(nh=43)
        / IPv6ExtHdrRouting(nh=44)
        / IPv6ExtHdrFragment(offset=0, m=1, nh=17)
        / UDP(sport=1234, dport=5678)
        / Raw(payload_first)
    )
    last = (
        Ether(dst=src_if.local_mac, src=src_if.remote_mac)
        / IPv6(src=src_if.remote_ip6, dst=dst_if.remote_ip6)
        / IPv6ExtHdrHopByHop(nh=60)
        / IPv6ExtHdrDestOpt(nh=43)
        / IPv6ExtHdrRouting(nh=44)
        / IPv6ExtHdrFragment(offset=3, m=0, nh=17)
        / Raw(payload_last)
    )
    return first, last


def first_fragment_beyond_depth(src_if, dst_if, payload):
    """A first fragment whose UDP header lies beyond the scan depth.

    The 300-byte destination options header pushes the UDP header past the
    256-byte scan depth, so the walk stops at the limit before it.
    """
    return (
        Ether(dst=src_if.local_mac, src=src_if.remote_mac)
        / IPv6(src=src_if.remote_ip6, dst=dst_if.remote_ip6)
        / IPv6ExtHdrFragment(offset=0, m=1, nh=60)
        / IPv6ExtHdrDestOpt(nh=17, options=[HBHOptUnknown(otype=0xFF, optlen=0)] * 150)
        / UDP(sport=1234, dport=5678)
        / Raw(payload)
    )


class IPv6ParamProblemTests:
    """Parameter Problem tests shared by the IPv6 reassembly classes

    The full and shallow virtual reassembly nodes answer the same invalid
    upper layer cases with a Parameter Problem, so both test classes share
    these tests.
    """

    def test_first_fragment_truncated_ext_header(self):
        """A first fragment with a truncated extension header gets code 3

        The destination options header after the fragment header does not
        fit in the datagram, so the fragment's upper layer is incomplete."""
        pkt = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IPv6(
                src=self.src_if.remote_ip6,
                dst=self.dst_if.remote_ip6,
                nh=44,
                plen=12,
            )
            / IPv6ExtHdrFragment(offset=0, m=1, nh=60)
            / IPv6ExtHdrDestOpt(nh=17)
        )

        rx = self.send_and_expect(self.src_if, [pkt], self.src_if)
        self.assertIn(ICMPv6ParamProblem, rx[0])
        self.assertEqual(rx[0][ICMPv6ParamProblem].code, 3)
        self.assertEqual(rx[0][ICMPv6ParamProblem].ptr, 0)
        self.dst_if.assert_nothing_captured()

    def test_first_fragment_truncated_l4_header(self):
        """A first fragment whose L4 header does not fit gets code 3

        The fragment header names UDP, but the UDP header does not fit in
        the declared payload, so the fragment's upper layer is incomplete."""
        pkt = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IPv6(
                src=self.src_if.remote_ip6,
                dst=self.dst_if.remote_ip6,
                nh=44,
                plen=12,
            )
            / IPv6ExtHdrFragment(offset=0, m=1, nh=17)
            / UDP(sport=1234, dport=5678)
        )

        rx = self.send_and_expect(self.src_if, [pkt], self.src_if)
        self.assertIn(ICMPv6ParamProblem, rx[0])
        self.assertEqual(rx[0][ICMPv6ParamProblem].code, 3)
        self.assertEqual(rx[0][ICMPv6ParamProblem].ptr, 0)
        self.dst_if.assert_nothing_captured()

    def test_unfragmented_truncated_l4_header(self):
        """An unfragmented packet with a truncated L4 header gets no ICMP error

        The packet has no fragment header, so the reassembly nodes do not
        classify it for a Parameter Problem."""
        pkt = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IPv6(
                src=self.src_if.remote_ip6,
                dst=self.dst_if.remote_ip6,
                nh=17,
                plen=4,
            )
            / UDP(sport=1234, dport=5678)
        )

        self.send_and_assert_no_replies(self.src_if, [pkt])
        self.dst_if.assert_nothing_captured()

    def test_icmp6_offender_dropped(self):
        """A malformed ICMPv6 first fragment is dropped without a Parameter Problem

        RFC 4443 sections 2.4(e.1) and 2.4(e.2) forbid answering an ICMPv6
        error message or a redirect message with another ICMPv6 error. The
        plain fragment identifies ICMPv6 from the fragment header's next
        protocol; the extension header fragment identifies it from the
        walk's terminating protocol. Both must be dropped and accounted
        instead of answered."""
        error_cnt_str = "/err/%s/reass_missing_upper" % self.reass_err_node
        error_cnt = self.statistics.get_err_counter(error_cnt_str)

        plain = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IPv6(
                src=self.src_if.remote_ip6,
                dst=self.dst_if.remote_ip6,
                nh=44,
                plen=10,
            )
            / IPv6ExtHdrFragment(offset=0, m=1, nh=58)
            / Raw(b"\x01\x00")
        )
        ext = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IPv6(
                src=self.src_if.remote_ip6,
                dst=self.dst_if.remote_ip6,
                nh=44,
                plen=18,
            )
            / IPv6ExtHdrFragment(offset=0, m=1, nh=60)
            / IPv6ExtHdrDestOpt(nh=58)
            / Raw(b"\x01\x00")
        )

        self.send_and_assert_no_replies(self.src_if, [plain, ext])
        self.dst_if.assert_nothing_captured()
        self.assert_error_counter_equal(error_cnt_str, error_cnt + 2)


class TestIPv4Reassembly(VppTestCase):
    """IPv4 Reassembly"""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        cls.create_pg_interfaces([0, 1])
        cls.src_if = cls.pg0
        cls.dst_if = cls.pg1

        # setup all interfaces
        for i in cls.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

        # packet sizes
        cls.packet_sizes = [64, 512, 1518, 9018]
        cls.padding = " abcdefghijklmn"
        cls.create_stream(cls.packet_sizes)
        cls.create_fragments()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()

    def setUp(self):
        """Test setup - force timeout on existing reassemblies"""
        super().setUp()
        self.vapi.ip_reassembly_enable_disable(
            sw_if_index=self.src_if.sw_if_index, enable_ip4=True
        )
        self.vapi.ip_reassembly_set(
            timeout_ms=0,
            max_reassemblies=1000,
            max_reassembly_length=1000,
            expire_walk_interval_ms=10,
        )
        self.virtual_sleep(0.25)
        self.vapi.ip_reassembly_set(
            timeout_ms=1000000,
            max_reassemblies=1000,
            max_reassembly_length=1000,
            expire_walk_interval_ms=10000,
        )

    def tearDown(self):
        self.vapi.ip_reassembly_enable_disable(
            sw_if_index=self.src_if.sw_if_index, enable_ip4=False
        )
        super().tearDown()

    def show_commands_at_teardown(self):
        self.logger.debug(self.vapi.ppcli("show ip4-full-reassembly details"))
        self.logger.debug(self.vapi.ppcli("show buffers"))

    @classmethod
    def create_stream(cls, packet_sizes, packet_count=test_packet_count):
        """Create input packet stream

        :param list packet_sizes: Required packet sizes.
        """
        for i in range(0, packet_count):
            info = cls.create_packet_info(cls.src_if, cls.src_if)
            payload = cls.info_to_payload(info)
            p = (
                Ether(dst=cls.src_if.local_mac, src=cls.src_if.remote_mac)
                / IP(
                    id=info.index, src=cls.src_if.remote_ip4, dst=cls.dst_if.remote_ip4
                )
                / UDP(sport=1234, dport=5678)
                / Raw(payload)
            )
            size = packet_sizes[(i // 2) % len(packet_sizes)]
            cls.extend_packet(p, size, cls.padding)
            info.data = p

    @classmethod
    def create_fragments(cls):
        infos = cls._packet_infos
        cls.pkt_infos = []
        for index, info in infos.items():
            p = info.data
            # cls.logger.debug(ppp("Packet:",
            #                      p.__class__(scapy.compat.raw(p))))
            fragments_400 = fragment_rfc791(p, 400)
            fragments_300 = fragment_rfc791(p, 300)
            fragments_200 = [x for f in fragments_400 for x in fragment_rfc791(f, 200)]
            cls.pkt_infos.append((index, fragments_400, fragments_300, fragments_200))
        cls.fragments_400 = [x for (_, frags, _, _) in cls.pkt_infos for x in frags]
        cls.fragments_300 = [x for (_, _, frags, _) in cls.pkt_infos for x in frags]
        cls.fragments_200 = [x for (_, _, _, frags) in cls.pkt_infos for x in frags]
        cls.logger.debug(
            "Fragmented %s packets into %s 400-byte fragments, "
            "%s 300-byte fragments and %s 200-byte fragments"
            % (
                len(infos),
                len(cls.fragments_400),
                len(cls.fragments_300),
                len(cls.fragments_200),
            )
        )

    def verify_capture(self, capture, dropped_packet_indexes=[]):
        """Verify captured packet stream.

        :param list capture: Captured packet stream.
        """
        info = None
        seen = set()
        for packet in capture:
            try:
                self.logger.debug(ppp("Got packet:", packet))
                ip = packet[IP]
                udp = packet[UDP]
                payload_info = self.payload_to_info(packet[Raw])
                packet_index = payload_info.index
                self.assertTrue(
                    packet_index not in dropped_packet_indexes,
                    ppp("Packet received, but should be dropped:", packet),
                )
                if packet_index in seen:
                    raise Exception(ppp("Duplicate packet received", packet))
                seen.add(packet_index)
                self.assertEqual(payload_info.dst, self.src_if.sw_if_index)
                info = self._packet_infos[packet_index]
                self.assertTrue(info is not None)
                self.assertEqual(packet_index, info.index)
                saved_packet = info.data
                self.assertEqual(ip.src, saved_packet[IP].src)
                self.assertEqual(ip.dst, saved_packet[IP].dst)
                self.assertEqual(udp.payload, saved_packet[UDP].payload)
            except Exception:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise
        for index in self._packet_infos:
            self.assertTrue(
                index in seen or index in dropped_packet_indexes,
                "Packet with packet_index %d not received" % index,
            )

    def test_reassembly(self):
        """basic reassembly"""

        packets = self.send_and_expect_multi(
            send=[Send(self.src_if, self.fragments_200)],
            expect=[Expect(self.dst_if, len(self.pkt_infos))],
        )[0].packets
        self.verify_capture(packets)

        # run it all again to verify correctness
        packets = self.send_and_expect_multi(
            send=[Send(self.src_if, self.fragments_200)],
            expect=[Expect(self.dst_if, len(self.pkt_infos))],
        )[0].packets
        self.verify_capture(packets)

    def test_verify_clear_trace_mid_reassembly(self):
        """verify clear trace works mid-reassembly"""

        self.pg_enable_capture()
        self.src_if.add_stream(self.fragments_200[0:-1])
        self.pg_start()

        self.logger.debug(self.vapi.cli("show trace"))
        self.vapi.cli("clear trace")

        self.src_if.add_stream(self.fragments_200[-1])
        self.pg_start()
        packets = self.dst_if.get_capture(len(self.pkt_infos))
        self.verify_capture(packets)

    def test_reversed(self):
        """reverse order reassembly"""

        fragments = list(self.fragments_200)
        fragments.reverse()

        packets = self.send_and_expect_multi(
            send=[Send(self.src_if, fragments)],
            expect=[Expect(self.dst_if, len(self.packet_infos))],
        )[0].packets
        self.verify_capture(packets)

        # run it all again to verify correctness
        packets = self.send_and_expect_multi(
            send=[Send(self.src_if, fragments)],
            expect=[Expect(self.dst_if, len(self.packet_infos))],
        )[0].packets
        self.verify_capture(packets)

    def test_long_fragment_chain(self):
        """long fragment chain"""

        error_cnt_str = "/err/ip4-full-reassembly-feature/reass_fragment_chain_too_long"

        error_cnt = self.statistics.get_err_counter(error_cnt_str)

        self.vapi.ip_reassembly_set(
            timeout_ms=100,
            max_reassemblies=1000,
            max_reassembly_length=3,
            expire_walk_interval_ms=50,
        )

        p1 = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IP(id=1000, src=self.src_if.remote_ip4, dst=self.dst_if.remote_ip4)
            / UDP(sport=1234, dport=5678)
            / Raw(b"X" * 1000)
        )
        p2 = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IP(id=1001, src=self.src_if.remote_ip4, dst=self.dst_if.remote_ip4)
            / UDP(sport=1234, dport=5678)
            / Raw(b"X" * 1000)
        )
        frags = fragment_rfc791(p1, 200) + fragment_rfc791(p2, 500)

        self.pg_enable_capture()
        self.src_if.add_stream(frags)
        self.pg_start()

        self.dst_if.get_capture(1)
        self.assert_error_counter_equal(error_cnt_str, error_cnt + 1)

    def test_5737(self):
        """fragment length + ip header size > 65535"""
        self.vapi.cli("clear errors")
        raw = b"""E\x00\x00\x88,\xf8\x1f\xfe@\x01\x98\x00\xc0\xa8\n-\xc0\xa8\n\
\x01\x08\x00\xf0J\xed\xcb\xf1\xf5Test-group: IPv4.IPv4.ipv4-message.\
Ethernet-Payload.IPv4-Packet.IPv4-Header.Fragment-Offset; Test-case: 5737"""
        malformed_packet = Ether(
            dst=self.src_if.local_mac, src=self.src_if.remote_mac
        ) / IP(raw)
        p = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IP(id=1000, src=self.src_if.remote_ip4, dst=self.dst_if.remote_ip4)
            / UDP(sport=1234, dport=5678)
            / Raw(b"X" * 1000)
        )
        valid_fragments = fragment_rfc791(p, 400)

        counter = "/err/ip4-full-reassembly-feature/reass_malformed_packet"
        error_counter = self.statistics.get_err_counter(counter)
        self.pg_enable_capture()
        self.src_if.add_stream([malformed_packet] + valid_fragments)
        self.pg_start()

        self.dst_if.get_capture(1)
        self.logger.debug(self.vapi.ppcli("show error"))
        self.assertEqual(self.statistics.get_err_counter(counter), error_counter + 1)

    def test_44924(self):
        """compress tiny fragments"""
        packets = [
            (
                Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
                / IP(
                    id=24339,
                    flags="MF",
                    frag=0,
                    ttl=64,
                    src=self.src_if.remote_ip4,
                    dst=self.dst_if.remote_ip4,
                )
                / ICMP(type="echo-request", code=0, id=0x1FE6, seq=0x2407)
                / Raw(load="Test-group: IPv4")
            ),
            (
                Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
                / IP(
                    id=24339,
                    flags="MF",
                    frag=3,
                    ttl=64,
                    src=self.src_if.remote_ip4,
                    dst=self.dst_if.remote_ip4,
                )
                / ICMP(type="echo-request", code=0, id=0x1FE6, seq=0x2407)
                / Raw(load=".IPv4.Fragmentation.vali")
            ),
            (
                Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
                / IP(
                    id=24339,
                    frag=6,
                    ttl=64,
                    src=self.src_if.remote_ip4,
                    dst=self.dst_if.remote_ip4,
                )
                / ICMP(type="echo-request", code=0, id=0x1FE6, seq=0x2407)
                / Raw(load="d; Test-case: 44924")
            ),
        ]

        self.pg_enable_capture()
        self.src_if.add_stream(packets)
        self.pg_start()

        self.dst_if.get_capture(1)

    def test_frag_1(self):
        """fragment of size 1"""
        self.vapi.cli("clear errors")
        malformed_packets = [
            (
                Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
                / IP(
                    id=7,
                    len=21,
                    flags="MF",
                    frag=0,
                    ttl=64,
                    src=self.src_if.remote_ip4,
                    dst=self.dst_if.remote_ip4,
                )
                / ICMP(type="echo-request")
            ),
            (
                Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
                / IP(
                    id=7,
                    len=21,
                    frag=1,
                    ttl=64,
                    src=self.src_if.remote_ip4,
                    dst=self.dst_if.remote_ip4,
                )
                / Raw(load=b"\x08")
            ),
        ]

        p = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IP(id=1000, src=self.src_if.remote_ip4, dst=self.dst_if.remote_ip4)
            / UDP(sport=1234, dport=5678)
            / Raw(b"X" * 1000)
        )
        valid_fragments = fragment_rfc791(p, 400)

        self.pg_enable_capture()
        self.src_if.add_stream(malformed_packets + valid_fragments)
        self.pg_start()

        self.dst_if.get_capture(1)

        self.assert_packet_counter_equal("ip4-full-reassembly-feature", 1)
        # TODO remove above, uncomment below once clearing of counters
        # is supported
        # self.assert_packet_counter_equal(
        #     "/err/ip4-full-reassembly-feature/reass_malformed_packet", 1)

    def test_random(self):
        """random order reassembly"""

        fragments = list(self.fragments_200)
        shuffle(fragments)

        packets = self.send_and_expect_multi(
            send=[Send(self.src_if, fragments)],
            expect=[Expect(self.dst_if, len(self.packet_infos))],
        )[0].packets

        self.verify_capture(packets)

        # run it all again to verify correctness
        packets = self.send_and_expect_multi(
            send=[Send(self.src_if, fragments)],
            expect=[Expect(self.dst_if, len(self.packet_infos))],
        )[0].packets

        self.verify_capture(packets)

    def test_duplicates(self):
        """duplicate fragments"""

        fragments = [
            x
            for (_, frags, _, _) in self.pkt_infos
            for x in frags
            for _ in range(0, min(2, len(frags)))
        ]

        packets = self.send_and_expect_multi(
            send=[Send(self.src_if, fragments)],
            expect=[Expect(self.dst_if, len(self.pkt_infos))],
        )[0].packets
        self.verify_capture(packets)

    def test_overlap1(self):
        """overlapping fragments case #1"""

        fragments = []
        for _, _, frags_300, frags_200 in self.pkt_infos:
            if len(frags_300) == 1:
                fragments.extend(frags_300)
            else:
                for i, j in zip(frags_200, frags_300):
                    fragments.extend(i)
                    fragments.extend(j)

        packets = self.send_and_expect_multi(
            send=[Send(self.src_if, fragments)],
            expect=[Expect(self.dst_if, len(self.pkt_infos))],
        )[0].packets
        self.verify_capture(packets)

        # run it all to verify correctness
        packets = self.send_and_expect_multi(
            send=[Send(self.src_if, fragments)],
            expect=[Expect(self.dst_if, len(self.pkt_infos))],
        )[0].packets
        self.verify_capture(packets)

    def test_overlap2(self):
        """overlapping fragments case #2"""

        fragments = []
        for _, _, frags_300, frags_200 in self.pkt_infos:
            if len(frags_300) == 1:
                fragments.extend(frags_300)
            else:
                # care must be taken here so that there are no fragments
                # received by vpp after reassembly is finished, otherwise
                # new reassemblies will be started and packet generator will
                # freak out when it detects unfreed buffers
                zipped = zip(frags_300, frags_200)
                for i, j in zipped:
                    fragments.extend(i)
                    fragments.extend(j)
                fragments.pop()

        packets = self.send_and_expect_multi(
            send=[Send(self.src_if, fragments)],
            expect=[Expect(self.dst_if, len(self.pkt_infos))],
        )[0].packets
        self.verify_capture(packets)

        # run it all to verify correctness
        packets = self.send_and_expect_multi(
            send=[Send(self.src_if, fragments)],
            expect=[Expect(self.dst_if, len(self.pkt_infos))],
        )[0].packets
        self.verify_capture(packets)

    def test_timeout_inline(self):
        """timeout (inline)"""

        dropped_packet_indexes = set(
            index for (index, frags, _, _) in self.pkt_infos if len(frags) > 1
        )

        self.vapi.ip_reassembly_set(
            timeout_ms=0,
            max_reassemblies=1000,
            max_reassembly_length=3,
            expire_walk_interval_ms=10000,
        )

        packets = self.send_and_expect_multi(
            send=[Send(self.src_if, self.fragments_400)],
            expect=[
                Expect(self.dst_if, len(self.pkt_infos) - len(dropped_packet_indexes))
            ],
        )[0].packets
        self.verify_capture(packets, dropped_packet_indexes)

    def test_timeout_cleanup(self):
        """timeout (cleanup)"""

        # whole packets + fragmented packets sans last fragment
        fragments = [
            x
            for (_, frags_400, _, _) in self.pkt_infos
            for x in frags_400[: -1 if len(frags_400) > 1 else None]
        ]

        # last fragments for fragmented packets
        fragments2 = [
            frags_400[-1]
            for (_, frags_400, _, _) in self.pkt_infos
            if len(frags_400) > 1
        ]

        dropped_packet_indexes = set(
            index for (index, frags_400, _, _) in self.pkt_infos if len(frags_400) > 1
        )

        self.vapi.ip_reassembly_set(
            timeout_ms=100,
            max_reassemblies=1000,
            max_reassembly_length=1000,
            expire_walk_interval_ms=50,
        )

        self.pg_enable_capture()
        self.src_if.add_stream(fragments)
        self.pg_start()

        self.virtual_sleep(0.25, "wait before sending rest of fragments")

        self.src_if.add_stream(fragments2)
        self.pg_start()

        packets = self.dst_if.get_capture(
            len(self.pkt_infos) - len(dropped_packet_indexes)
        )
        self.verify_capture(packets, dropped_packet_indexes)
        self.src_if.assert_nothing_captured()

    def test_disabled(self):
        """reassembly disabled"""

        dropped_packet_indexes = set(
            index for (index, frags_400, _, _) in self.pkt_infos if len(frags_400) > 1
        )

        self.vapi.ip_reassembly_set(
            timeout_ms=1000,
            max_reassemblies=0,
            max_reassembly_length=3,
            expire_walk_interval_ms=10000,
        )

        packets = self.send_and_expect_multi(
            send=[Send(self.src_if, self.fragments_400)],
            expect=[
                Expect(self.dst_if, len(self.pkt_infos) - len(dropped_packet_indexes))
            ],
        )[0].packets
        self.verify_capture(packets, dropped_packet_indexes)

    def test_duplicate_fragment_dos(self):
        """duplicate fragments should not inflate fragment count"""

        error_cnt_str = "/err/ip4-full-reassembly-feature/reass_fragment_chain_too_long"
        error_cnt = self.statistics.get_err_counter(error_cnt_str)

        self.vapi.ip_reassembly_set(
            timeout_ms=1000000,
            max_reassemblies=1000,
            max_reassembly_length=3,
            expire_walk_interval_ms=10000,
        )

        # create a packet that fragments into exactly 3 pieces
        p = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IP(id=2000, src=self.src_if.remote_ip4, dst=self.dst_if.remote_ip4)
            / UDP(sport=1234, dport=5678)
            / Raw(b"X" * 1000)
        )
        frags = fragment_rfc791(p, 400)
        self.assertEqual(len(frags), 3)

        # send first fragment, then 10 duplicates, then remaining fragments
        # with correct behavior: duplicates don't inflate fragments_n,
        # reassembly completes successfully
        duplicates = frags[0:1] * 10
        packets = [frags[0]] + duplicates + frags[1:]

        self.pg_enable_capture()
        self.src_if.add_stream(packets)
        self.pg_start()

        self.dst_if.get_capture(1)
        self.assert_error_counter_equal(error_cnt_str, error_cnt)

    def test_one_byte_last_fragment(self):
        """reassembly with 1-byte last fragment"""

        error_cnt_str = "/err/ip4-full-reassembly-feature/reass_internal_error"
        error_cnt = self.statistics.get_err_counter(error_cnt_str)

        # craft a packet whose last fragment has exactly 1 byte of data
        # use 169 bytes of raw payload so fragment_rfc791 at fragsize=200
        # produces: frag1=[0,175] (176 bytes), frag2=[176,176] (1 byte)
        # frag2 offset = 176/8 = 22, avoiding ip4-input offset==1 check
        p = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IP(
                id=3000,
                src=self.src_if.remote_ip4,
                dst=self.dst_if.remote_ip4,
            )
            / UDP(sport=1234, dport=5678)
            / Raw(b"X" * 169)
        )
        frags = fragment_rfc791(p, 200)
        # verify last fragment has 1 byte of data
        self.assertEqual(len(frags), 2)

        self.pg_enable_capture()
        self.src_if.add_stream(frags)
        self.pg_start()

        self.dst_if.get_capture(1)
        self.assert_error_counter_equal(error_cnt_str, error_cnt)

    @unittest.skipIf(
        "ping" in config.excluded_plugins, "Exclude tests requiring Ping plugin"
    )
    def test_local_enable_disable(self):
        """local reassembly enabled/disable"""
        self.vapi.ip_reassembly_enable_disable(
            sw_if_index=self.src_if.sw_if_index, enable_ip4=False
        )
        self.vapi.ip_local_reass_enable_disable(enable_ip4=True)
        p = (
            Ether(src=self.src_if.remote_mac, dst=self.src_if.local_mac)
            / IP(src=self.src_if.remote_ip4, dst=self.src_if.local_ip4)
            / ICMP(id=1234, type="echo-request")
            / Raw("x" * 1000)
        )
        frags = fragment_rfc791(p, 400)
        r = self.send_and_expect(self.src_if, frags, self.src_if, n_rx=1)[0]
        self.assertEqual(1234, r[ICMP].id)
        self.assertEqual(icmptypes[r[ICMP].type], "echo-reply")
        self.vapi.ip_local_reass_enable_disable()

        self.send_and_assert_no_replies(self.src_if, frags)
        self.vapi.ip_local_reass_enable_disable(enable_ip4=True)


class TestIPv4SVReassembly(VppTestCase):
    """IPv4 Shallow Virtual Reassembly"""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        cls.create_pg_interfaces([0, 1])
        cls.src_if = cls.pg0
        cls.dst_if = cls.pg1

        # setup all interfaces
        for i in cls.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    def setUp(self):
        """Test setup - force timeout on existing reassemblies"""
        super().setUp()
        self.vapi.ip_reassembly_enable_disable(
            sw_if_index=self.src_if.sw_if_index,
            enable_ip4=True,
            type=VppEnum.vl_api_ip_reass_type_t.IP_REASS_TYPE_SHALLOW_VIRTUAL,
        )
        self.vapi.ip_reassembly_set(
            timeout_ms=0,
            max_reassemblies=1000,
            max_reassembly_length=1000,
            type=VppEnum.vl_api_ip_reass_type_t.IP_REASS_TYPE_SHALLOW_VIRTUAL,
            expire_walk_interval_ms=10,
        )
        self.virtual_sleep(0.25)
        self.vapi.ip_reassembly_set(
            timeout_ms=1000000,
            max_reassemblies=1000,
            max_reassembly_length=1000,
            type=VppEnum.vl_api_ip_reass_type_t.IP_REASS_TYPE_SHALLOW_VIRTUAL,
            expire_walk_interval_ms=10000,
        )

    def tearDown(self):
        super().tearDown()
        self.logger.debug(self.vapi.ppcli("show ip4-sv-reassembly details"))
        self.logger.debug(self.vapi.ppcli("show buffers"))

    def test_basic(self):
        """basic reassembly"""
        payload_len = 1000
        payload = ""
        counter = 0
        while len(payload) < payload_len:
            payload += "%u " % counter
            counter += 1

        p = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IP(id=1, src=self.src_if.remote_ip4, dst=self.dst_if.remote_ip4)
            / UDP(sport=1234, dport=5678)
            / Raw(payload)
        )
        fragments = fragment_rfc791(p, payload_len / 4)

        # send fragment #2 - should be cached inside reassembly
        self.pg_enable_capture()
        self.src_if.add_stream(fragments[1])
        self.pg_start()
        self.logger.debug(self.vapi.ppcli("show ip4-sv-reassembly details"))
        self.logger.debug(self.vapi.ppcli("show buffers"))
        self.logger.debug(self.vapi.ppcli("show trace"))
        self.dst_if.assert_nothing_captured()

        # send fragment #1 - reassembly is finished now and both fragments
        # forwarded
        self.pg_enable_capture()
        self.src_if.add_stream(fragments[0])
        self.pg_start()
        self.logger.debug(self.vapi.ppcli("show ip4-sv-reassembly details"))
        self.logger.debug(self.vapi.ppcli("show buffers"))
        self.logger.debug(self.vapi.ppcli("show trace"))
        c = self.dst_if.get_capture(2)
        for sent, recvd in zip([fragments[1], fragments[0]], c):
            self.assertEqual(sent[IP].src, recvd[IP].src)
            self.assertEqual(sent[IP].dst, recvd[IP].dst)
            self.assertEqual(sent[Raw].payload, recvd[Raw].payload)

        # send rest of fragments - should be immediately forwarded
        self.pg_enable_capture()
        self.src_if.add_stream(fragments[2:])
        self.pg_start()
        c = self.dst_if.get_capture(len(fragments[2:]))
        for sent, recvd in zip(fragments[2:], c):
            self.assertEqual(sent[IP].src, recvd[IP].src)
            self.assertEqual(sent[IP].dst, recvd[IP].dst)
            self.assertEqual(sent[Raw].payload, recvd[Raw].payload)

    def test_verify_clear_trace_mid_reassembly(self):
        """verify clear trace works mid-reassembly"""
        payload_len = 1000
        payload = ""
        counter = 0
        while len(payload) < payload_len:
            payload += "%u " % counter
            counter += 1

        p = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IP(id=1, src=self.src_if.remote_ip4, dst=self.dst_if.remote_ip4)
            / UDP(sport=1234, dport=5678)
            / Raw(payload)
        )
        fragments = fragment_rfc791(p, payload_len / 4)

        self.pg_enable_capture()
        self.src_if.add_stream(fragments[1])
        self.pg_start()

        self.logger.debug(self.vapi.cli("show trace"))
        self.vapi.cli("clear trace")

        self.pg_enable_capture()
        self.src_if.add_stream(fragments[0])
        self.pg_start()
        self.dst_if.get_capture(2)

        self.logger.debug(self.vapi.cli("show trace"))
        self.vapi.cli("clear trace")

        self.pg_enable_capture()
        self.src_if.add_stream(fragments[2:])
        self.pg_start()
        self.dst_if.get_capture(len(fragments[2:]))

    def test_timeout(self):
        """reassembly timeout"""
        payload_len = 1000
        payload = ""
        counter = 0
        while len(payload) < payload_len:
            payload += "%u " % counter
            counter += 1

        p = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IP(id=1, src=self.src_if.remote_ip4, dst=self.dst_if.remote_ip4)
            / UDP(sport=1234, dport=5678)
            / Raw(payload)
        )
        fragments = fragment_rfc791(p, payload_len / 4)

        self.vapi.ip_reassembly_set(
            timeout_ms=100,
            max_reassemblies=1000,
            max_reassembly_length=1000,
            expire_walk_interval_ms=50,
            type=VppEnum.vl_api_ip_reass_type_t.IP_REASS_TYPE_SHALLOW_VIRTUAL,
        )

        # send fragments #2 and #1 - should be forwarded
        self.pg_enable_capture()
        self.src_if.add_stream(fragments[0:2])
        self.pg_start()
        self.logger.debug(self.vapi.ppcli("show ip4-sv-reassembly details"))
        self.logger.debug(self.vapi.ppcli("show buffers"))
        self.logger.debug(self.vapi.ppcli("show trace"))
        c = self.dst_if.get_capture(2)
        for sent, recvd in zip([fragments[1], fragments[0]], c):
            self.assertEqual(sent[IP].src, recvd[IP].src)
            self.assertEqual(sent[IP].dst, recvd[IP].dst)
            self.assertEqual(sent[Raw].payload, recvd[Raw].payload)

        # wait for cleanup
        self.virtual_sleep(0.25, "wait before sending rest of fragments")

        # send rest of fragments - shouldn't be forwarded
        self.pg_enable_capture()
        self.src_if.add_stream(fragments[2:])
        self.pg_start()
        self.dst_if.assert_nothing_captured()

    def test_lru(self):
        """reassembly reuses LRU element"""

        self.vapi.ip_reassembly_set(
            timeout_ms=1000000,
            max_reassemblies=1,
            max_reassembly_length=1000,
            type=VppEnum.vl_api_ip_reass_type_t.IP_REASS_TYPE_SHALLOW_VIRTUAL,
            expire_walk_interval_ms=10000,
        )

        payload_len = 1000
        payload = ""
        counter = 0
        while len(payload) < payload_len:
            payload += "%u " % counter
            counter += 1

        packet_count = 10

        fragments = [
            f
            for i in range(packet_count)
            for p in (
                Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
                / IP(id=i, src=self.src_if.remote_ip4, dst=self.dst_if.remote_ip4)
                / UDP(sport=1234, dport=5678)
                / Raw(payload)
            )
            for f in fragment_rfc791(p, payload_len / 4)
        ]

        self.pg_enable_capture()
        self.src_if.add_stream(fragments)
        self.pg_start()
        c = self.dst_if.get_capture(len(fragments))
        for sent, recvd in zip(fragments, c):
            self.assertEqual(sent[IP].src, recvd[IP].src)
            self.assertEqual(sent[IP].dst, recvd[IP].dst)
            self.assertEqual(sent[Raw].payload, recvd[Raw].payload)

    def send_mixed_and_verify_capture(self, traffic):
        stream = []
        for t in traffic:
            for c in range(t["count"]):
                stream.append(
                    (
                        Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
                        / IP(
                            id=self.counter,
                            flags=t["flags"],
                            src=self.src_if.remote_ip4,
                            dst=self.dst_if.remote_ip4,
                        )
                        / UDP(sport=1234, dport=5678)
                        / Raw("abcdef")
                    )
                )
                self.counter = self.counter + 1

        self.pg_enable_capture()
        self.src_if.add_stream(stream)
        self.pg_start()
        self.logger.debug(self.vapi.ppcli("show ip4-sv-reassembly details"))
        self.logger.debug(self.vapi.ppcli("show buffers"))
        self.logger.debug(self.vapi.ppcli("show trace"))
        self.dst_if.get_capture(len(stream))

    def test_mixed(self):
        """mixed traffic correctly passes through SVR"""
        self.counter = 1

        self.send_mixed_and_verify_capture([{"count": 1, "flags": ""}])
        self.send_mixed_and_verify_capture([{"count": 2, "flags": ""}])
        self.send_mixed_and_verify_capture([{"count": 3, "flags": ""}])
        self.send_mixed_and_verify_capture([{"count": 8, "flags": ""}])
        self.send_mixed_and_verify_capture([{"count": 257, "flags": ""}])

        self.send_mixed_and_verify_capture([{"count": 1, "flags": "MF"}])
        self.send_mixed_and_verify_capture([{"count": 2, "flags": "MF"}])
        self.send_mixed_and_verify_capture([{"count": 3, "flags": "MF"}])
        self.send_mixed_and_verify_capture([{"count": 8, "flags": "MF"}])
        self.send_mixed_and_verify_capture([{"count": 257, "flags": "MF"}])

        self.send_mixed_and_verify_capture(
            [{"count": 1, "flags": ""}, {"count": 1, "flags": "MF"}]
        )
        self.send_mixed_and_verify_capture(
            [{"count": 2, "flags": ""}, {"count": 2, "flags": "MF"}]
        )
        self.send_mixed_and_verify_capture(
            [{"count": 3, "flags": ""}, {"count": 3, "flags": "MF"}]
        )
        self.send_mixed_and_verify_capture(
            [{"count": 8, "flags": ""}, {"count": 8, "flags": "MF"}]
        )
        self.send_mixed_and_verify_capture(
            [{"count": 129, "flags": ""}, {"count": 129, "flags": "MF"}]
        )

        self.send_mixed_and_verify_capture(
            [
                {"count": 1, "flags": ""},
                {"count": 1, "flags": "MF"},
                {"count": 1, "flags": ""},
                {"count": 1, "flags": "MF"},
            ]
        )
        self.send_mixed_and_verify_capture(
            [
                {"count": 2, "flags": ""},
                {"count": 2, "flags": "MF"},
                {"count": 2, "flags": ""},
                {"count": 2, "flags": "MF"},
            ]
        )
        self.send_mixed_and_verify_capture(
            [
                {"count": 3, "flags": ""},
                {"count": 3, "flags": "MF"},
                {"count": 3, "flags": ""},
                {"count": 3, "flags": "MF"},
            ]
        )
        self.send_mixed_and_verify_capture(
            [
                {"count": 8, "flags": ""},
                {"count": 8, "flags": "MF"},
                {"count": 8, "flags": ""},
                {"count": 8, "flags": "MF"},
            ]
        )
        self.send_mixed_and_verify_capture(
            [
                {"count": 65, "flags": ""},
                {"count": 65, "flags": "MF"},
                {"count": 65, "flags": ""},
                {"count": 65, "flags": "MF"},
            ]
        )

    def _get_buffers_used(self):
        r = self.vapi.cli_return_response("show buffers")
        self.assertTrue(r.retval == 0)
        return int(r.reply.strip().split("\n")[-1].split()[-1])

    def test_extended_clone_buffer_leak(self):
        """extended SV reassembly: duplicate first fragment must not leak clone buffer"""

        self.vapi.cli("set ip reassembly extended ip4 on")

        self.vapi.ip_reassembly_set(
            timeout_ms=100,
            max_reassemblies=1000,
            max_reassembly_length=1000,
            type=VppEnum.vl_api_ip_reass_type_t.IP_REASS_TYPE_SHALLOW_VIRTUAL,
            expire_walk_interval_ms=50,
        )

        bufs_before = self._get_buffers_used()

        # send many reassemblies where the first fragment arrives twice,
        # triggering a second clone - the old clone must be freed
        num_flows = 50
        fragments = []
        for i in range(num_flows):
            # first fragment (offset=0, MF=1) - triggers clone
            frag1 = (
                Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
                / IP(
                    id=5000 + i,
                    flags="MF",
                    frag=0,
                    src=self.src_if.remote_ip4,
                    dst=self.dst_if.remote_ip4,
                )
                / UDP(sport=1234, dport=5678)
                / Raw(b"X" * 200)
            )
            # duplicate first fragment - should free old clone before new one
            frag1_dup = frag1.copy()
            fragments.extend([frag1, frag1_dup])

        self.pg_enable_capture()
        self.src_if.add_stream(fragments)
        self.pg_start()
        # in extended mode, need both first and last to forward, so these
        # stay cached; don't expect captures
        self.logger.debug(self.vapi.ppcli("show ip4-sv-reassembly details"))

        # wait for timeout to expire all reassemblies (frees clone buffers)
        self.virtual_sleep(0.25)

        bufs_after = self._get_buffers_used()
        self.assertGreaterEqual(
            bufs_before,
            bufs_after,
            "Buffer leak detected: %d used before, %d after"
            % (bufs_before, bufs_after),
        )

        self.vapi.cli("set ip reassembly extended ip4 off")

    def _get_buffer_count(self):
        """Get the number of allocated buffers from 'show buffers'"""
        output = self.vapi.ppcli("show buffers")
        # Parse the total buffer count from output like "Total buffers: 1234"
        for line in output.split("\n"):
            if "Total buffers:" in line:
                return int(line.split(":")[1].strip())
        return 0

    def test_l4_protocol_sctp(self):
        """SCTP packets pass through SVR"""
        payload = "x " * 500

        p = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IP(
                id=100,
                src=self.src_if.remote_ip4,
                dst=self.dst_if.remote_ip4,
            )
            / SCTP(sport=21, dport=22)
            / Raw(payload.encode())
        )
        fragments = fragment_rfc791(p, 300)

        buffers_before = self._get_buffer_count()
        self.pg_enable_capture()
        self.src_if.add_stream(fragments)
        self.pg_start()
        c = self.dst_if.get_capture(len(fragments))
        self.assertEqual(len(c), len(fragments))
        for sent, recvd in zip(fragments, c):
            self.assertEqual(sent[IP].src, recvd[IP].src)
            self.assertEqual(sent[IP].dst, recvd[IP].dst)
            self.assertEqual(sent[IP].proto, recvd[IP].proto)
        buffers_after = self._get_buffer_count()
        self.assertLessEqual(
            buffers_after,
            buffers_before + len(fragments),
            "Buffer leak detected: before=%d, after=%d"
            % (buffers_before, buffers_after),
        )

    def test_l4_protocol_dccp(self):
        """DCCP packets pass through SVR"""
        # DCCP protocol number is 33
        # DCCP header: src_port(2), dst_port(2), seq(4), ...
        dccp_header = b"\x04\xd2\x12\x34" + b"\x00" * 4 + b"\x00" * 100
        payload = "y " * 500

        p = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IP(
                id=200,
                proto=33,  # DCCP
                src=self.src_if.remote_ip4,
                dst=self.dst_if.remote_ip4,
            )
            / Raw(dccp_header + payload.encode())
        )
        fragments = fragment_rfc791(p, 300)
        self.assertGreater(len(fragments), 1, "Expected fragments, got single packet")

        buffers_before = self._get_buffer_count()
        self.pg_enable_capture()
        self.src_if.add_stream(fragments)
        self.pg_start()
        c = self.dst_if.get_capture(len(fragments))
        self.assertEqual(len(c), len(fragments))
        for sent, recvd in zip(fragments, c):
            self.assertEqual(sent[IP].src, recvd[IP].src)
            self.assertEqual(sent[IP].dst, recvd[IP].dst)
            self.assertEqual(sent[IP].proto, recvd[IP].proto)
            self.assertEqual(bytes(sent[Raw].load), bytes(recvd[Raw].load))
        buffers_after = self._get_buffer_count()
        self.assertLessEqual(
            buffers_after,
            buffers_before + len(fragments),
            "Buffer leak detected: before=%d, after=%d"
            % (buffers_before, buffers_after),
        )

    def test_l4_protocol_udplite(self):
        """UDP-Lite packets pass through SVR"""
        # UDP-Lite protocol number is 136
        # UDP-Lite header: src_port(2), dst_port(2), length(2), cksum_len(2)
        udplite_header = b"\x05\xdd\x06\xde" + b"\x00\x80" + b"\x00\x08"
        payload = "z " * 500

        p = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IP(
                id=300,
                proto=136,  # UDP-Lite
                src=self.src_if.remote_ip4,
                dst=self.dst_if.remote_ip4,
            )
            / Raw(udplite_header + payload.encode())
        )
        fragments = fragment_rfc791(p, 300)
        self.assertGreater(len(fragments), 1, "Expected fragments, got single packet")

        buffers_before = self._get_buffer_count()
        self.pg_enable_capture()
        self.src_if.add_stream(fragments)
        self.pg_start()
        c = self.dst_if.get_capture(len(fragments))
        self.assertEqual(len(c), len(fragments))
        for sent, recvd in zip(fragments, c):
            self.assertEqual(sent[IP].src, recvd[IP].src)
            self.assertEqual(sent[IP].dst, recvd[IP].dst)
            self.assertEqual(sent[IP].proto, recvd[IP].proto)
            self.assertEqual(bytes(sent[Raw].load), bytes(recvd[Raw].load))
        buffers_after = self._get_buffer_count()
        self.assertLessEqual(
            buffers_after,
            buffers_before + len(fragments),
            "Buffer leak detected: before=%d, after=%d"
            % (buffers_before, buffers_after),
        )

    def test_unsupported_proto_passthrough(self):
        """GRE packets (unfragmented and fragmented) pass through SVR"""
        payload = "z " * 500

        # unfragmented GRE - unsupported L4 protocol must pass through
        p = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IP(src=self.src_if.remote_ip4, dst=self.dst_if.remote_ip4)
            / GRE()
            / Raw(payload.encode())
        )
        buffers_before = self._get_buffer_count()
        self.pg_enable_capture()
        self.src_if.add_stream([p])
        self.pg_start()
        c = self.dst_if.get_capture(1)
        self.assertEqual(len(c), 1)
        self.assertEqual(c[0][IP].proto, p[IP].proto)
        self.assertEqual(bytes(c[0][GRE]), bytes(p[GRE]))
        self.assertEqual(bytes(c[0][Raw].load), payload.encode())

        # fragmented GRE - reassembly must complete despite unsupported L4
        p = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IP(
                id=300,
                src=self.src_if.remote_ip4,
                dst=self.dst_if.remote_ip4,
            )
            / GRE()
            / Raw(payload.encode())
        )
        fragments = fragment_rfc791(p, 300)
        self.assertGreater(len(fragments), 1, "Expected fragments, got single packet")
        self.pg_enable_capture()
        self.src_if.add_stream(fragments)
        self.pg_start()
        c = self.dst_if.get_capture(len(fragments))
        self.assertEqual(len(c), len(fragments))
        for sent, recvd in zip(fragments, c):
            self.assertEqual(sent[IP].proto, recvd[IP].proto)
        buffers_after = self._get_buffer_count()
        self.assertLessEqual(
            buffers_after,
            buffers_before + len(fragments),
            "Buffer leak detected: before=%d, after=%d"
            % (buffers_before, buffers_after),
        )


class TestIPv4MWReassembly(VppTestCase):
    """IPv4 Reassembly (multiple workers)"""

    vpp_worker_count = 3

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        cls.create_pg_interfaces(range(cls.get_vpp_worker_count() + 1))
        cls.src_if = cls.pg0
        cls.send_ifs = cls.pg_interfaces[:-1]
        cls.dst_if = cls.pg_interfaces[-1]

        # setup all interfaces
        for i in cls.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

        # packets sizes reduced here because we are generating packets without
        # Ethernet headers, which are added later (diff fragments go via
        # different interfaces)
        cls.packet_sizes = [
            64 - len(Ether()),
            512 - len(Ether()),
            1518 - len(Ether()),
            9018 - len(Ether()),
        ]
        cls.padding = " abcdefghijklmn"
        cls.create_stream(cls.packet_sizes)
        cls.create_fragments()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()

    def setUp(self):
        """Test setup - force timeout on existing reassemblies"""
        super().setUp()
        for intf in self.send_ifs:
            self.vapi.ip_reassembly_enable_disable(
                sw_if_index=intf.sw_if_index, enable_ip4=True
            )
        self.vapi.ip_reassembly_set(
            timeout_ms=0,
            max_reassemblies=1000,
            max_reassembly_length=1000,
            expire_walk_interval_ms=10,
        )
        self.virtual_sleep(0.25)
        self.vapi.ip_reassembly_set(
            timeout_ms=1000000,
            max_reassemblies=1000,
            max_reassembly_length=1000,
            expire_walk_interval_ms=10000,
        )

    def tearDown(self):
        for intf in self.send_ifs:
            self.vapi.ip_reassembly_enable_disable(
                sw_if_index=intf.sw_if_index, enable_ip4=False
            )
        super().tearDown()

    def show_commands_at_teardown(self):
        self.logger.debug(self.vapi.ppcli("show ip4-full-reassembly details"))
        self.logger.debug(self.vapi.ppcli("show buffers"))

    @classmethod
    def create_stream(cls, packet_sizes, packet_count=test_packet_count):
        """Create input packet stream

        :param list packet_sizes: Required packet sizes.
        """
        for i in range(0, packet_count):
            info = cls.create_packet_info(cls.src_if, cls.src_if)
            payload = cls.info_to_payload(info)
            p = (
                IP(id=info.index, src=cls.src_if.remote_ip4, dst=cls.dst_if.remote_ip4)
                / UDP(sport=1234, dport=5678)
                / Raw(payload)
            )
            size = packet_sizes[(i // 2) % len(packet_sizes)]
            cls.extend_packet(p, size, cls.padding)
            info.data = p

    @classmethod
    def create_fragments(cls):
        infos = cls._packet_infos
        cls.pkt_infos = []
        for index, info in infos.items():
            p = info.data
            # cls.logger.debug(ppp("Packet:",
            #                      p.__class__(scapy.compat.raw(p))))
            fragments_400 = fragment_rfc791(p, 400)
            cls.pkt_infos.append((index, fragments_400))
        cls.fragments_400 = [x for (_, frags) in cls.pkt_infos for x in frags]
        cls.logger.debug(
            "Fragmented %s packets into %s 400-byte fragments, "
            % (len(infos), len(cls.fragments_400))
        )

    def verify_capture(self, capture, dropped_packet_indexes=[]):
        """Verify captured packet stream.

        :param list capture: Captured packet stream.
        """
        info = None
        seen = set()
        for packet in capture:
            try:
                self.logger.debug(ppp("Got packet:", packet))
                ip = packet[IP]
                udp = packet[UDP]
                payload_info = self.payload_to_info(packet[Raw])
                packet_index = payload_info.index
                self.assertTrue(
                    packet_index not in dropped_packet_indexes,
                    ppp("Packet received, but should be dropped:", packet),
                )
                if packet_index in seen:
                    raise Exception(ppp("Duplicate packet received", packet))
                seen.add(packet_index)
                self.assertEqual(payload_info.dst, self.src_if.sw_if_index)
                info = self._packet_infos[packet_index]
                self.assertTrue(info is not None)
                self.assertEqual(packet_index, info.index)
                saved_packet = info.data
                self.assertEqual(ip.src, saved_packet[IP].src)
                self.assertEqual(ip.dst, saved_packet[IP].dst)
                self.assertEqual(udp.payload, saved_packet[UDP].payload)
            except Exception:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise
        for index in self._packet_infos:
            self.assertTrue(
                index in seen or index in dropped_packet_indexes,
                "Packet with packet_index %d not received" % index,
            )

    def send_packets(self, packets):
        for counter in range(self.get_vpp_worker_count()):
            if 0 == len(packets[counter]):
                continue
            send_if = self.send_ifs[counter]
            send_if.add_stream(
                (
                    Ether(dst=send_if.local_mac, src=send_if.remote_mac) / x
                    for x in packets[counter]
                ),
                worker=counter,
            )
        self.pg_start()

    def test_worker_conflict(self):
        """1st and FO=0 fragments on different workers"""

        # in first wave we send fragments which don't start at offset 0
        # then we send fragments with offset 0 on a different thread
        # then the rest of packets on a random thread
        first_packets = [[] for n in range(self.get_vpp_worker_count())]
        second_packets = [[] for n in range(self.get_vpp_worker_count())]
        rest_of_packets = [[] for n in range(self.get_vpp_worker_count())]
        for _, p in self.pkt_infos:
            wi = randrange(self.get_vpp_worker_count())
            second_packets[wi].append(p[0])
            if len(p) <= 1:
                continue
            wi2 = wi
            while wi2 == wi:
                wi2 = randrange(self.get_vpp_worker_count())
            first_packets[wi2].append(p[1])
            wi3 = randrange(self.get_vpp_worker_count())
            rest_of_packets[wi3].extend(p[2:])

        self.pg_enable_capture()
        self.send_packets(first_packets)
        self.send_packets(second_packets)
        self.send_packets(rest_of_packets)

        packets = self.dst_if.get_capture(len(self.pkt_infos))
        self.verify_capture(packets)
        for send_if in self.send_ifs:
            send_if.assert_nothing_captured()

        self.logger.debug(self.vapi.ppcli("show trace"))
        self.logger.debug(self.vapi.ppcli("show ip4-full-reassembly details"))
        self.logger.debug(self.vapi.ppcli("show buffers"))
        self.vapi.cli("clear trace")

        self.pg_enable_capture()
        self.send_packets(first_packets)
        self.send_packets(second_packets)
        self.send_packets(rest_of_packets)

        packets = self.dst_if.get_capture(len(self.pkt_infos))
        self.verify_capture(packets)
        for send_if in self.send_ifs:
            send_if.assert_nothing_captured()


class TestIPv6Reassembly(IPv6ParamProblemTests, VppTestCase):
    """IPv6 Reassembly"""

    reass_err_node = "ip6-full-reassembly-feature"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        cls.create_pg_interfaces([0, 1])
        cls.src_if = cls.pg0
        cls.dst_if = cls.pg1

        # setup all interfaces
        for i in cls.pg_interfaces:
            i.admin_up()
            i.config_ip6()
            i.resolve_ndp()

        # packet sizes
        cls.packet_sizes = [64, 512, 1518, 9018]
        cls.padding = " abcdefghijklmn"
        cls.create_stream(cls.packet_sizes)
        cls.create_fragments()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()

    def setUp(self):
        """Test setup - force timeout on existing reassemblies"""
        super().setUp()
        self.vapi.ip_reassembly_enable_disable(
            sw_if_index=self.src_if.sw_if_index, enable_ip6=True
        )
        self.vapi.ip_reassembly_set(
            timeout_ms=0,
            max_reassemblies=1000,
            max_reassembly_length=1000,
            expire_walk_interval_ms=10,
            is_ip6=1,
        )
        self.virtual_sleep(0.25)
        self.vapi.ip_reassembly_set(
            timeout_ms=1000000,
            max_reassemblies=1000,
            max_reassembly_length=1000,
            expire_walk_interval_ms=10000,
            is_ip6=1,
        )
        self.logger.debug(self.vapi.ppcli("show ip6-full-reassembly details"))
        self.logger.debug(self.vapi.ppcli("show buffers"))

    def tearDown(self):
        self.vapi.ip_reassembly_enable_disable(
            sw_if_index=self.src_if.sw_if_index, enable_ip6=False
        )
        super().tearDown()

    def show_commands_at_teardown(self):
        self.logger.debug(self.vapi.ppcli("show ip6-full-reassembly details"))
        self.logger.debug(self.vapi.ppcli("show buffers"))

    @classmethod
    def create_stream(cls, packet_sizes, packet_count=test_packet_count):
        """Create input packet stream for defined interface.

        :param list packet_sizes: Required packet sizes.
        """
        for i in range(0, packet_count):
            info = cls.create_packet_info(cls.src_if, cls.src_if)
            payload = cls.info_to_payload(info)
            p = (
                Ether(dst=cls.src_if.local_mac, src=cls.src_if.remote_mac)
                / IPv6(src=cls.src_if.remote_ip6, dst=cls.dst_if.remote_ip6)
                / UDP(sport=1234, dport=5678)
                / Raw(payload)
            )
            size = packet_sizes[(i // 2) % len(packet_sizes)]
            cls.extend_packet(p, size, cls.padding)
            info.data = p

    @classmethod
    def create_fragments(cls):
        infos = cls._packet_infos
        cls.pkt_infos = []
        for index, info in infos.items():
            p = info.data
            # cls.logger.debug(ppp("Packet:",
            #                      p.__class__(scapy.compat.raw(p))))
            fragments_400 = fragment_rfc8200(p, info.index, 400)
            fragments_300 = fragment_rfc8200(p, info.index, 300)
            cls.pkt_infos.append((index, fragments_400, fragments_300))
        cls.fragments_400 = [x for _, frags, _ in cls.pkt_infos for x in frags]
        cls.fragments_300 = [x for _, _, frags in cls.pkt_infos for x in frags]
        cls.logger.debug(
            "Fragmented %s packets into %s 400-byte fragments, "
            "and %s 300-byte fragments"
            % (len(infos), len(cls.fragments_400), len(cls.fragments_300))
        )

    def verify_capture(self, capture, dropped_packet_indexes=[]):
        """Verify captured packet strea .

        :param list capture: Captured packet stream.
        """
        info = None
        seen = set()
        for packet in capture:
            try:
                self.logger.debug(ppp("Got packet:", packet))
                ip = packet[IPv6]
                udp = packet[UDP]
                payload_info = self.payload_to_info(packet[Raw])
                packet_index = payload_info.index
                self.assertTrue(
                    packet_index not in dropped_packet_indexes,
                    ppp("Packet received, but should be dropped:", packet),
                )
                if packet_index in seen:
                    raise Exception(ppp("Duplicate packet received", packet))
                seen.add(packet_index)
                self.assertEqual(payload_info.dst, self.src_if.sw_if_index)
                info = self._packet_infos[packet_index]
                self.assertTrue(info is not None)
                self.assertEqual(packet_index, info.index)
                saved_packet = info.data
                self.assertEqual(ip.src, saved_packet[IPv6].src)
                self.assertEqual(ip.dst, saved_packet[IPv6].dst)
                self.assertEqual(udp.payload, saved_packet[UDP].payload)
            except Exception:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise
        for index in self._packet_infos:
            self.assertTrue(
                index in seen or index in dropped_packet_indexes,
                "Packet with packet_index %d not received" % index,
            )

    def test_reassembly(self):
        """basic reassembly"""

        packets = self.send_and_expect_multi(
            send=[Send(self.src_if, self.fragments_400)],
            expect=[Expect(self.dst_if, len(self.pkt_infos))],
        )[0].packets
        self.verify_capture(packets)

        # run it all again to verify correctness
        packets = self.send_and_expect_multi(
            send=[Send(self.src_if, self.fragments_400)],
            expect=[Expect(self.dst_if, len(self.pkt_infos))],
        )[0].packets
        self.verify_capture(packets)

    def test_buffer_boundary(self):
        """A fragment header crosses the buffer boundary

        The hop-by-hop header runs past the buffer, so the walk cannot
        reach the fragment header. The packet is dropped without an ICMP
        error."""

        p = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IPv6(src=self.src_if.remote_ip6, dst=self.src_if.local_ip6)
            / IPv6ExtHdrHopByHop(options=[HBHOptUnknown(otype=0xFF, optlen=0)] * 1000)
            / IPv6ExtHdrFragment(m=1)
            / UDP(sport=1234, dport=5678)
            / Raw()
        )
        self.send_and_assert_no_replies(self.src_if, [p])
        self.dst_if.assert_nothing_captured()

    def test_verify_clear_trace_mid_reassembly(self):
        """verify clear trace works mid-reassembly"""

        self.pg_enable_capture()
        self.src_if.add_stream(self.fragments_400[0:-1])
        self.pg_start()

        self.logger.debug(self.vapi.cli("show trace"))
        self.vapi.cli("clear trace")

        self.src_if.add_stream(self.fragments_400[-1])
        self.pg_start()
        packets = self.dst_if.get_capture(len(self.pkt_infos))
        self.verify_capture(packets)

    def test_reversed(self):
        """reverse order reassembly"""

        fragments = list(self.fragments_400)
        fragments.reverse()

        packets = self.send_and_expect_multi(
            send=[Send(self.src_if, fragments)],
            expect=[Expect(self.dst_if, len(self.pkt_infos))],
        )[0].packets
        self.verify_capture(packets)

        # run it all again to verify correctness
        packets = self.send_and_expect_multi(
            send=[Send(self.src_if, fragments)],
            expect=[Expect(self.dst_if, len(self.pkt_infos))],
        )[0].packets
        self.verify_capture(packets)

    def test_random(self):
        """random order reassembly"""

        fragments = list(self.fragments_400)
        shuffle(fragments)

        packets = self.send_and_expect_multi(
            send=[Send(self.src_if, fragments)],
            expect=[Expect(self.dst_if, len(self.pkt_infos))],
        )[0].packets

        self.verify_capture(packets)

        # run it all again to verify correctness

        packets = self.send_and_expect_multi(
            send=[Send(self.src_if, fragments)],
            expect=[Expect(self.dst_if, len(self.pkt_infos))],
        )[0].packets

        self.verify_capture(packets)

    def test_duplicates(self):
        """duplicate fragments"""

        fragments = [
            x
            for (_, frags, _) in self.pkt_infos
            for x in frags
            for _ in range(0, min(2, len(frags)))
        ]

        packets = self.send_and_expect_multi(
            send=[Send(self.src_if, fragments)],
            expect=[Expect(self.dst_if, len(self.pkt_infos))],
        )[0].packets
        self.verify_capture(packets)

    def test_long_fragment_chain(self):
        """long fragment chain"""

        error_cnt_str = "/err/ip6-full-reassembly-feature/reass_fragment_chain_too_long"

        error_cnt = self.statistics.get_err_counter(error_cnt_str)

        self.vapi.ip_reassembly_set(
            timeout_ms=100,
            max_reassemblies=1000,
            max_reassembly_length=3,
            expire_walk_interval_ms=50,
            is_ip6=1,
        )

        p = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6)
            / UDP(sport=1234, dport=5678)
            / Raw(b"X" * 1000)
        )
        frags = fragment_rfc8200(p, 1, 300) + fragment_rfc8200(p, 2, 500)

        self.pg_enable_capture()
        self.src_if.add_stream(frags)
        self.pg_start()

        self.dst_if.get_capture(1)
        self.assert_error_counter_equal(error_cnt_str, error_cnt + 1)

    def test_overlap1(self):
        """overlapping fragments case #1"""

        fragments = []
        for _, frags_400, frags_300 in self.pkt_infos:
            if len(frags_300) == 1:
                fragments.extend(frags_400)
            else:
                for i, j in zip(frags_300, frags_400):
                    fragments.extend(i)
                    fragments.extend(j)

        dropped_packet_indexes = set(
            index for (index, _, frags) in self.pkt_infos if len(frags) > 1
        )

        packets = self.send_and_expect_multi(
            send=[Send(self.src_if, fragments)],
            expect=[
                Expect(self.dst_if, len(self.pkt_infos) - len(dropped_packet_indexes))
            ],
        )[0].packets
        self.verify_capture(packets, dropped_packet_indexes)

    def test_overlap2(self):
        """overlapping fragments case #2"""

        fragments = []
        for _, frags_400, frags_300 in self.pkt_infos:
            if len(frags_400) == 1:
                fragments.extend(frags_400)
            else:
                # care must be taken here so that there are no fragments
                # received by vpp after reassembly is finished, otherwise
                # new reassemblies will be started and packet generator will
                # freak out when it detects unfreed buffers
                zipped = zip(frags_400, frags_300)
                for i, j in zipped:
                    fragments.extend(i)
                    fragments.extend(j)
                fragments.pop()

        dropped_packet_indexes = set(
            index for (index, _, frags) in self.pkt_infos if len(frags) > 1
        )

        packets = self.send_and_expect_multi(
            send=[Send(self.src_if, fragments)],
            expect=[
                Expect(self.dst_if, len(self.pkt_infos) - len(dropped_packet_indexes))
            ],
        )[0].packets
        self.verify_capture(packets, dropped_packet_indexes)

    def test_timeout_inline(self):
        """timeout (inline)"""

        dropped_packet_indexes = set(
            index for (index, frags, _) in self.pkt_infos if len(frags) > 1
        )

        self.vapi.ip_reassembly_set(
            timeout_ms=0,
            max_reassemblies=1000,
            max_reassembly_length=3,
            expire_walk_interval_ms=10000,
            is_ip6=1,
        )

        self.pg_enable_capture()
        self.src_if.add_stream(self.fragments_400)
        self.pg_start()

        packets = self.dst_if.get_capture(
            len(self.pkt_infos) - len(dropped_packet_indexes)
        )
        self.verify_capture(packets, dropped_packet_indexes)
        pkts = self.src_if._get_capture()
        for icmp in pkts:
            self.assertIn(ICMPv6TimeExceeded, icmp)
            self.assertIn(IPv6ExtHdrFragment, icmp)
            self.assertIn(icmp[IPv6ExtHdrFragment].id, dropped_packet_indexes)
            dropped_packet_indexes.remove(icmp[IPv6ExtHdrFragment].id)

    def test_timeout_cleanup(self):
        """timeout (cleanup)"""

        # whole packets + fragmented packets sans last fragment
        fragments = [
            x
            for (_, frags_400, _) in self.pkt_infos
            for x in frags_400[: -1 if len(frags_400) > 1 else None]
        ]

        # last fragments for fragmented packets
        fragments2 = [
            frags_400[-1] for (_, frags_400, _) in self.pkt_infos if len(frags_400) > 1
        ]

        dropped_packet_indexes = set(
            index for (index, frags_400, _) in self.pkt_infos if len(frags_400) > 1
        )

        self.vapi.ip_reassembly_set(
            timeout_ms=100,
            max_reassemblies=1000,
            max_reassembly_length=1000,
            expire_walk_interval_ms=50,
        )

        self.vapi.ip_reassembly_set(
            timeout_ms=100,
            max_reassemblies=1000,
            max_reassembly_length=1000,
            expire_walk_interval_ms=50,
            is_ip6=1,
        )

        self.pg_enable_capture()
        self.src_if.add_stream(fragments)
        self.pg_start()

        self.virtual_sleep(0.25, "wait before sending rest of fragments")

        self.src_if.add_stream(fragments2)
        self.pg_start()

        packets = self.dst_if.get_capture(
            len(self.pkt_infos) - len(dropped_packet_indexes)
        )
        self.verify_capture(packets, dropped_packet_indexes)
        pkts = self.src_if._get_capture()
        for icmp in pkts:
            self.assertIn(ICMPv6TimeExceeded, icmp)
            self.assertIn(IPv6ExtHdrFragment, icmp)
            self.assertIn(icmp[IPv6ExtHdrFragment].id, dropped_packet_indexes)
            dropped_packet_indexes.remove(icmp[IPv6ExtHdrFragment].id)

    def test_disabled(self):
        """reassembly disabled"""

        dropped_packet_indexes = set(
            index for (index, frags_400, _) in self.pkt_infos if len(frags_400) > 1
        )

        self.vapi.ip_reassembly_set(
            timeout_ms=1000,
            max_reassemblies=0,
            max_reassembly_length=3,
            expire_walk_interval_ms=10000,
            is_ip6=1,
        )

        packets = self.send_and_expect_multi(
            send=[Send(self.src_if, self.fragments_400)],
            expect=[
                Expect(self.dst_if, len(self.pkt_infos) - len(dropped_packet_indexes))
            ],
        )[0].packets
        self.verify_capture(packets, dropped_packet_indexes)

    def test_duplicate_fragment_dos(self):
        """duplicate fragments should not inflate fragment count"""

        error_cnt_str = "/err/ip6-full-reassembly-feature/reass_fragment_chain_too_long"
        error_cnt = self.statistics.get_err_counter(error_cnt_str)

        self.vapi.ip_reassembly_set(
            timeout_ms=1000000,
            max_reassemblies=1000,
            max_reassembly_length=3,
            expire_walk_interval_ms=10000,
            is_ip6=1,
        )

        # create a packet that fragments into exactly 3 pieces
        p = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6)
            / UDP(sport=1234, dport=5678)
            / Raw(b"X" * 1000)
        )
        frags = fragment_rfc8200(p, 1, 400)
        self.assertEqual(len(frags), 3)

        # send first fragment, then 10 duplicates, then remaining fragments
        # with correct behavior: duplicates don't inflate fragments_n,
        # reassembly completes successfully
        duplicates = frags[0:1] * 10
        packets = [frags[0]] + duplicates + frags[1:]

        self.pg_enable_capture()
        self.src_if.add_stream(packets)
        self.pg_start()

        self.dst_if.get_capture(1)
        self.assert_error_counter_equal(error_cnt_str, error_cnt)

    def test_one_byte_last_fragment(self):
        """reassembly with 1-byte last fragment"""

        error_cnt_str = "/err/ip6-full-reassembly-feature/reass_internal_error"
        error_cnt = self.statistics.get_err_counter(error_cnt_str)

        # fragment 1: offset=0, m=1, 8 bytes of UDP data
        # fragment 2: offset=1 (=8 bytes), m=0, 1 byte of data
        frag1 = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6)
            / IPv6ExtHdrFragment(id=3000, nh=17, offset=0, m=1)
            / Raw(b"\x04\xd2\x16\x2e\x00\x09\x00\x00")
        )
        frag2 = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6)
            / IPv6ExtHdrFragment(id=3000, nh=17, offset=1, m=0)
            / Raw(b"X")
        )

        self.pg_enable_capture()
        self.src_if.add_stream([frag1, frag2])
        self.pg_start()

        self.dst_if.get_capture(1)
        self.assert_error_counter_equal(error_cnt_str, error_cnt)

    def test_first_fragment_at_chain_limit(self):
        """A first fragment at the entry limit is reassembled

        The fragment header fills the last chain slot and names a
        destination options header. The walk stops at the entry limit,
        but the fragment is valid. The node must complete the reassembly
        and forward the packet."""
        payload_first = b"A" * 16
        payload_last = b"B" * 16
        first = chain_limit_first_fragment(self.src_if, self.dst_if, payload_first)
        last = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6)
            / IPv6ExtHdrHopByHop(nh=60)
            / IPv6ExtHdrDestOpt(nh=43)
            / IPv6ExtHdrRouting(nh=44)
            / IPv6ExtHdrFragment(offset=4, m=0, nh=60)
            / Raw(payload_last)
        )

        recvd = self.send_and_expect(self.src_if, [first, last], self.dst_if, n_rx=1)
        self.src_if.assert_nothing_captured()
        self.assertNotIn(IPv6ExtHdrFragment, recvd[0])
        self.assertEqual(bytes(recvd[0][UDP].payload), payload_first + payload_last)

    def test_l4_header_after_chain_limit(self):
        """A terminating L4 header after four chain headers is recognised

        Four extension headers fill the chain and the next protocol is UDP,
        so the walk must report the L4 header instead of stopping at the
        entry limit. The first fragment must be reassembled, not rejected."""
        payload_first = b"A" * 16
        payload_last = b"B" * 16
        first, last = entry_limit_l4_fragments(
            self.src_if, self.dst_if, payload_first, payload_last
        )

        recvd = self.send_and_expect(self.src_if, [first, last], self.dst_if, n_rx=1)
        self.src_if.assert_nothing_captured()
        self.assertNotIn(IPv6ExtHdrFragment, recvd[0])
        self.assertEqual(bytes(recvd[0][UDP].payload), payload_first + payload_last)

    def test_first_fragment_beyond_depth(self):
        """A first fragment whose L4 header is past the scan depth is reassembled

        The destination options header pushes the UDP header beyond the
        256-byte scan depth. The walk stops at the limit, but the fragment
        is valid. The node must complete the reassembly and forward the
        packet."""
        payload_first = b"A" * 16
        payload_last = b"B" * 16
        first = first_fragment_beyond_depth(self.src_if, self.dst_if, payload_first)
        fragment_payload_len = len(bytes(first[IPv6].payload)) - 8
        self.assertEqual(fragment_payload_len % 8, 0)
        last = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6)
            / IPv6ExtHdrFragment(offset=fragment_payload_len // 8, m=0, nh=17)
            / Raw(payload_last)
        )

        recvd = self.send_and_expect(self.src_if, [first, last], self.dst_if, n_rx=1)
        self.src_if.assert_nothing_captured()
        self.assertNotIn(IPv6ExtHdrFragment, recvd[0])
        self.assertEqual(bytes(recvd[0][UDP].payload), payload_first + payload_last)

    def test_invalid_frag_size(self):
        """fragment size not a multiple of 8"""
        p = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IPv6(src=self.src_if.remote_ip6, dst=self.src_if.local_ip6)
            / UDP(sport=1234, dport=5678)
            / Raw()
        )
        self.extend_packet(p, 1000, self.padding)
        fragments = fragment_rfc8200(p, 1, 500)
        bad_fragment = fragments[0]
        self.extend_packet(bad_fragment, len(bad_fragment) + 5)
        self.pg_enable_capture()
        self.src_if.add_stream([bad_fragment])
        self.pg_start()
        pkts = self.src_if.get_capture(expected_count=1)
        icmp = pkts[0]
        self.assertIn(ICMPv6ParamProblem, icmp)
        self.assert_equal(icmp[ICMPv6ParamProblem].code, 0, "ICMP code")

    def test_invalid_packet_size(self):
        """total packet size > 65535"""
        p = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IPv6(src=self.src_if.remote_ip6, dst=self.src_if.local_ip6)
            / UDP(sport=1234, dport=5678)
            / Raw()
        )
        self.extend_packet(p, 1000, self.padding)
        fragments = fragment_rfc8200(p, 1, 500)
        bad_fragment = fragments[1]
        bad_fragment[IPv6ExtHdrFragment].offset = 65500
        self.pg_enable_capture()
        self.src_if.add_stream([bad_fragment])
        self.pg_start()
        pkts = self.src_if.get_capture(expected_count=1)
        icmp = pkts[0]
        self.assertIn(ICMPv6ParamProblem, icmp)
        self.assert_equal(icmp[ICMPv6ParamProblem].code, 0, "ICMP code")

    def test_invalid_frag_size_multicast(self):
        """A malformed multicast fragment gets no Parameter Problem

        The fragment payload length is not a multiple of 8, so the local
        full reassembly node's fragment length check fails. RFC 4443
        section 2.4(e.3) forbids an ICMPv6 error for a packet destined to a
        multicast address, so the node must drop and account the packet
        instead of answering."""
        MRouteItfFlags = VppEnum.vl_api_mfib_itf_flags_t
        MRouteEntryFlags = VppEnum.vl_api_mfib_entry_flags_t

        VppIpMRoute(
            self,
            "::",
            "ff02::1234",
            128,
            MRouteEntryFlags.MFIB_API_ENTRY_FLAG_NONE,
            [
                VppMRoutePath(
                    self.src_if.sw_if_index,
                    MRouteItfFlags.MFIB_API_ITF_FLAG_ACCEPT,
                    proto=FibPathProto.FIB_PATH_NH_PROTO_IP6,
                ),
                VppMRoutePath(
                    0xFFFFFFFF,
                    MRouteItfFlags.MFIB_API_ITF_FLAG_FORWARD,
                    proto=FibPathProto.FIB_PATH_NH_PROTO_IP6,
                    type=FibPathType.FIB_PATH_TYPE_LOCAL,
                ),
            ],
        ).add_vpp_config()

        error_cnt_str = "/err/ip6-local-full-reassembly/reass_invalid_frag_size"
        error_cnt = self.statistics.get_err_counter(error_cnt_str)

        # The fragment payload after the fragment header is 12 bytes, not a
        # multiple of 8, so the fragment length check fails. The multicast
        # destination must suppress the Parameter Problem.
        pkt = (
            Ether(dst=getmacbyip6("ff02::1234"), src=self.src_if.remote_mac)
            / IPv6(src=self.src_if.remote_ip6, dst="ff02::1234")
            / IPv6ExtHdrFragment(m=1, nh=17)
            / UDP(sport=1234, dport=5678)
            / Raw(b"X" * 4)
        )

        self.send_and_assert_no_replies(self.src_if, [pkt])
        self.assert_error_counter_equal(error_cnt_str, error_cnt + 1)

    def test_invalid_frag_size_transit(self):
        """A transit fragment with a bad fragment length gets a Parameter Problem

        The packet is not addressed to the router, so the full reassembly
        feature node, not the local node, must answer it."""
        error_cnt_str = "/err/ip6-full-reassembly-feature/reass_invalid_frag_size"
        error_cnt = self.statistics.get_err_counter(error_cnt_str)

        # The fragment payload after the fragment header is 12 bytes, not a
        # multiple of 8, so the fragment length check fails. The feature node
        # must answer the packet instead of continuing it along the arc.
        pkt = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6)
            / IPv6ExtHdrFragment(m=1, nh=17)
            / UDP(sport=1234, dport=5678)
            / Raw(b"X" * 4)
        )

        rx = self.send_and_expect(self.src_if, [pkt], self.src_if)
        self.assertIn(ICMPv6ParamProblem, rx[0])
        self.assertEqual(rx[0][ICMPv6ParamProblem].code, 0)
        self.assertEqual(rx[0][ICMPv6ParamProblem].ptr, 4)
        self.dst_if.assert_nothing_captured()
        self.assert_error_counter_equal(error_cnt_str, error_cnt + 1)

    def test_atomic_fragment(self):
        """IPv6 atomic fragment"""
        pkt = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IPv6(src=self.pg0.remote_ip6, dst=self.pg0.local_ip6, nh=44, plen=65535)
            / IPv6ExtHdrFragment(
                offset=8191, m=1, res1=0xFF, res2=0xFF, nh=255, id=0xFFFF
            )
            / ("X" * 1452)
        )

        rx = self.send_and_expect(self.pg0, [pkt], self.pg0)
        self.assertIn(ICMPv6ParamProblem, rx[0])

    def test_truncated_fragment(self):
        """IPv6 truncated fragment header"""
        pkt = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IPv6(src=self.pg0.remote_ip6, dst=self.pg0.local_ip6, nh=44, plen=2)
            / IPv6ExtHdrFragment(nh=6)
        )

        rx = self.send_and_expect(self.pg0, [pkt], self.pg0)
        self.assertIn(ICMPv6ParamProblem, rx[0])
        self.assertEqual(rx[0][ICMPv6ParamProblem].code, 0)
        self.assertEqual(rx[0][ICMPv6ParamProblem].ptr, 40)
        self.dst_if.assert_nothing_captured()

        pkt = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IPv6(src=self.pg0.remote_ip6, dst=self.pg0.remote_ip6)
            / ICMPv6EchoRequest()
        )
        rx = self.send_and_expect(self.pg0, [pkt], self.pg0)

    @unittest.skipIf(
        "ping" in config.excluded_plugins, "Exclude tests requiring Ping plugin"
    )
    def test_one_fragment(self):
        """whole packet in one fragment processed independently"""
        pkt = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IPv6(src=self.pg0.remote_ip6, dst=self.pg0.local_ip6)
            / ICMPv6EchoRequest()
            / Raw("X" * 1600)
        )
        frags = fragment_rfc8200(pkt, 1, 400)

        # send a fragment with known id
        self.send_and_assert_no_replies(self.pg0, [frags[0]])

        # send an atomic fragment with same id - should be reassembled
        pkt = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IPv6(src=self.pg0.remote_ip6, dst=self.pg0.local_ip6)
            / IPv6ExtHdrFragment(id=1)
            / ICMPv6EchoRequest()
        )
        rx = self.send_and_expect(self.pg0, [pkt], self.pg0)
        self.assertNotIn(IPv6ExtHdrFragment, rx)

        # now finish the original reassembly, this should still be possible
        rx = self.send_and_expect(self.pg0, frags[1:], self.pg0, n_rx=1)
        self.assertNotIn(IPv6ExtHdrFragment, rx)

    @unittest.skipIf(
        "ping" in config.excluded_plugins, "Exclude tests requiring Ping plugin"
    )
    def test_bunch_of_fragments(self):
        """valid fragments followed by rogue fragments and atomic fragment"""
        pkt = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IPv6(src=self.pg0.remote_ip6, dst=self.pg0.local_ip6)
            / ICMPv6EchoRequest()
            / Raw("X" * 1600)
        )
        frags = fragment_rfc8200(pkt, 1, 400)
        self.send_and_expect(self.pg0, frags, self.pg0, n_rx=1)

        inc_frag = (
            Ether(src=self.pg0.local_mac, dst=self.pg0.remote_mac)
            / IPv6(src=self.pg0.remote_ip6, dst=self.pg0.local_ip6)
            / IPv6ExtHdrFragment(id=1, nh=58, offset=608)
            / Raw("X" * 308)
        )

        self.send_and_assert_no_replies(self.pg0, inc_frag * 604)

        pkt = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IPv6(src=self.pg0.remote_ip6, dst=self.pg0.local_ip6)
            / IPv6ExtHdrFragment(id=1)
            / ICMPv6EchoRequest()
        )
        rx = self.send_and_expect(self.pg0, [pkt], self.pg0)
        self.assertNotIn(IPv6ExtHdrFragment, rx)

    @unittest.skipIf(
        "ping" in config.excluded_plugins, "Exclude tests requiring Ping plugin"
    )
    def test_local_enable_disable(self):
        """local reassembly enabled/disable"""
        self.vapi.ip_reassembly_enable_disable(
            sw_if_index=self.src_if.sw_if_index, enable_ip6=False
        )
        self.vapi.ip_local_reass_enable_disable(enable_ip6=True)
        pkt = (
            Ether(src=self.src_if.remote_mac, dst=self.src_if.local_mac)
            / IPv6(src=self.src_if.remote_ip6, dst=self.src_if.local_ip6)
            / ICMPv6EchoRequest(id=1234)
            / Raw("X" * 1600)
        )
        frags = fragment_rfc8200(pkt, 1, 400)
        r = self.send_and_expect(self.src_if, frags, self.src_if, n_rx=1)[0]
        self.assertEqual(1234, r[ICMPv6EchoReply].id)
        self.vapi.ip_local_reass_enable_disable()

        self.send_and_assert_no_replies(self.src_if, frags)
        self.vapi.ip_local_reass_enable_disable(enable_ip6=True)

    def _get_buffers_used(self):
        r = self.vapi.cli_return_response("show buffers")
        self.assertTrue(r.retval == 0)
        return int(r.reply.strip().split("\n")[-1].split()[-1])

    def test_invalid_overlap(self):
        """invalid overlapping fragments"""
        error_cnt_str = "/err/ip6-full-reassembly-feature/reass_overlapping_fragment"
        error_cnt = self.statistics.get_err_counter(error_cnt_str)
        bufs_before = self._get_buffers_used()

        # For each pair: frag1 starts a reassembly (range [0,199]), frag2
        # has the same id and offset but shorter payload (range [0,191]),
        # reliably triggering REASS_OVERLAPPING_FRAGMENT.
        num_pairs = 50
        fragments = []
        for i in range(num_pairs):
            frag1 = (
                Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
                / IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6)
                / IPv6ExtHdrFragment(id=i, nh=17, offset=0, m=1)
                / Raw(b"X" * 200)
            )
            frag2 = (
                Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
                / IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6)
                / IPv6ExtHdrFragment(id=i, nh=17, offset=0, m=1)
                / Raw(b"Y" * 192)
            )
            fragments.extend([frag1, frag2])

        self.send_and_assert_no_replies(self.src_if, fragments)
        self.assert_error_counter_equal(error_cnt_str, error_cnt + num_pairs)

        bufs_after = self._get_buffers_used()
        self.assertGreaterEqual(
            bufs_before,
            bufs_after,
            "Buffer leak detected: %d used before, %d after"
            % (bufs_before, bufs_after),
        )

    def test_invalid_frag_len(self):
        """invalid fragment length"""
        error_cnt_str = "/err/ip6-full-reassembly-feature/reass_invalid_frag_len"
        error_cnt = self.statistics.get_err_counter(error_cnt_str)
        bufs_before = self._get_buffers_used()

        # Each fragment has a fragment header but no payload after it, so
        # fragment_length == 0, triggering REASS_INVALID_FRAG_LEN.
        num_frags = 50
        fragments = []
        for i in range(num_frags):
            frag = (
                Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
                / IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6)
                / IPv6ExtHdrFragment(id=i, nh=17, offset=0, m=1)
            )
            fragments.append(frag)

        self.send_and_assert_no_replies(self.src_if, fragments)
        self.assert_error_counter_equal(error_cnt_str, error_cnt + num_frags)

        bufs_after = self._get_buffers_used()
        self.assertGreaterEqual(
            bufs_before,
            bufs_after,
            "Buffer leak detected: %d used before, %d after"
            % (bufs_before, bufs_after),
        )


class TestIPv6MWReassembly(VppTestCase):
    """IPv6 Reassembly (multiple workers)"""

    vpp_worker_count = 3

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        cls.create_pg_interfaces(range(cls.get_vpp_worker_count() + 1))
        cls.src_if = cls.pg0
        cls.send_ifs = cls.pg_interfaces[:-1]
        cls.dst_if = cls.pg_interfaces[-1]

        # setup all interfaces
        for i in cls.pg_interfaces:
            i.admin_up()
            i.config_ip6()
            i.resolve_ndp()

        # packets sizes reduced here because we are generating packets without
        # Ethernet headers, which are added later (diff fragments go via
        # different interfaces)
        cls.packet_sizes = [
            64 - len(Ether()),
            512 - len(Ether()),
            1518 - len(Ether()),
            9018 - len(Ether()),
        ]
        cls.padding = " abcdefghijklmn"
        cls.create_stream(cls.packet_sizes)
        cls.create_fragments()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()

    def setUp(self):
        """Test setup - force timeout on existing reassemblies"""
        super().setUp()
        for intf in self.send_ifs:
            self.vapi.ip_reassembly_enable_disable(
                sw_if_index=intf.sw_if_index, enable_ip6=True
            )
        self.vapi.ip_reassembly_set(
            timeout_ms=0,
            max_reassemblies=1000,
            max_reassembly_length=1000,
            expire_walk_interval_ms=10,
            is_ip6=1,
        )
        self.virtual_sleep(0.25)
        self.vapi.ip_reassembly_set(
            timeout_ms=1000000,
            max_reassemblies=1000,
            max_reassembly_length=1000,
            expire_walk_interval_ms=1000,
            is_ip6=1,
        )

    def tearDown(self):
        for intf in self.send_ifs:
            self.vapi.ip_reassembly_enable_disable(
                sw_if_index=intf.sw_if_index, enable_ip6=False
            )
        super().tearDown()

    def show_commands_at_teardown(self):
        self.logger.debug(self.vapi.ppcli("show ip6-full-reassembly details"))
        self.logger.debug(self.vapi.ppcli("show buffers"))

    @classmethod
    def create_stream(cls, packet_sizes, packet_count=test_packet_count):
        """Create input packet stream

        :param list packet_sizes: Required packet sizes.
        """
        for i in range(0, packet_count):
            info = cls.create_packet_info(cls.src_if, cls.src_if)
            payload = cls.info_to_payload(info)
            p = (
                IPv6(src=cls.src_if.remote_ip6, dst=cls.dst_if.remote_ip6)
                / UDP(sport=1234, dport=5678)
                / Raw(payload)
            )
            size = packet_sizes[(i // 2) % len(packet_sizes)]
            cls.extend_packet(p, size, cls.padding)
            info.data = p

    @classmethod
    def create_fragments(cls):
        infos = cls._packet_infos
        cls.pkt_infos = []
        for index, info in infos.items():
            p = info.data
            # cls.logger.debug(ppp("Packet:",
            #                      p.__class__(scapy.compat.raw(p))))
            fragments_400 = fragment_rfc8200(p, index, 400)
            cls.pkt_infos.append((index, fragments_400))
        cls.fragments_400 = [x for (_, frags) in cls.pkt_infos for x in frags]
        cls.logger.debug(
            "Fragmented %s packets into %s 400-byte fragments, "
            % (len(infos), len(cls.fragments_400))
        )

    def verify_capture(self, capture, dropped_packet_indexes=[]):
        """Verify captured packet strea .

        :param list capture: Captured packet stream.
        """
        info = None
        seen = set()
        for packet in capture:
            try:
                self.logger.debug(ppp("Got packet:", packet))
                ip = packet[IPv6]
                udp = packet[UDP]
                payload_info = self.payload_to_info(packet[Raw])
                packet_index = payload_info.index
                self.assertTrue(
                    packet_index not in dropped_packet_indexes,
                    ppp("Packet received, but should be dropped:", packet),
                )
                if packet_index in seen:
                    raise Exception(ppp("Duplicate packet received", packet))
                seen.add(packet_index)
                self.assertEqual(payload_info.dst, self.src_if.sw_if_index)
                info = self._packet_infos[packet_index]
                self.assertTrue(info is not None)
                self.assertEqual(packet_index, info.index)
                saved_packet = info.data
                self.assertEqual(ip.src, saved_packet[IPv6].src)
                self.assertEqual(ip.dst, saved_packet[IPv6].dst)
                self.assertEqual(udp.payload, saved_packet[UDP].payload)
            except Exception:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise
        for index in self._packet_infos:
            self.assertTrue(
                index in seen or index in dropped_packet_indexes,
                "Packet with packet_index %d not received" % index,
            )

    def send_packets(self, packets):
        for counter in range(self.get_vpp_worker_count()):
            if 0 == len(packets[counter]):
                continue
            send_if = self.send_ifs[counter]
            send_if.add_stream(
                (
                    Ether(dst=send_if.local_mac, src=send_if.remote_mac) / x
                    for x in packets[counter]
                ),
                worker=counter,
            )
        self.pg_start()

    def test_worker_conflict(self):
        """1st and FO=0 fragments on different workers"""

        # in first wave we send fragments which don't start at offset 0
        # then we send fragments with offset 0 on a different thread
        # then the rest of packets on a random thread
        first_packets = [[] for n in range(self.get_vpp_worker_count())]
        second_packets = [[] for n in range(self.get_vpp_worker_count())]
        rest_of_packets = [[] for n in range(self.get_vpp_worker_count())]
        for _, p in self.pkt_infos:
            wi = randrange(self.get_vpp_worker_count())
            second_packets[wi].append(p[0])
            if len(p) <= 1:
                continue
            wi2 = wi
            while wi2 == wi:
                wi2 = randrange(self.get_vpp_worker_count())
            first_packets[wi2].append(p[1])
            wi3 = randrange(self.get_vpp_worker_count())
            rest_of_packets[wi3].extend(p[2:])

        self.pg_enable_capture()
        self.send_packets(first_packets)
        self.send_packets(second_packets)
        self.send_packets(rest_of_packets)

        packets = self.dst_if.get_capture(len(self.pkt_infos))
        self.verify_capture(packets)
        for send_if in self.send_ifs:
            send_if.assert_nothing_captured()

        self.logger.debug(self.vapi.ppcli("show trace"))
        self.logger.debug(self.vapi.ppcli("show ip6-full-reassembly details"))
        self.logger.debug(self.vapi.ppcli("show buffers"))
        self.vapi.cli("clear trace")

        self.pg_enable_capture()
        self.send_packets(first_packets)
        self.send_packets(second_packets)
        self.send_packets(rest_of_packets)

        packets = self.dst_if.get_capture(len(self.pkt_infos))
        self.verify_capture(packets)
        for send_if in self.send_ifs:
            send_if.assert_nothing_captured()


class TestIPv6SVReassembly(IPv6ParamProblemTests, VppTestCase):
    """IPv6 Shallow Virtual Reassembly"""

    reass_err_node = "ip6-sv-reassembly-feature"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        cls.create_pg_interfaces([0, 1])
        cls.src_if = cls.pg0
        cls.dst_if = cls.pg1

        # setup all interfaces
        for i in cls.pg_interfaces:
            i.admin_up()
            i.config_ip6()
            i.resolve_ndp()

    def setUp(self):
        """Test setup - force timeout on existing reassemblies"""
        super().setUp()
        self.vapi.ip_reassembly_enable_disable(
            sw_if_index=self.src_if.sw_if_index,
            enable_ip6=True,
            type=VppEnum.vl_api_ip_reass_type_t.IP_REASS_TYPE_SHALLOW_VIRTUAL,
        )
        self.vapi.ip_reassembly_set(
            timeout_ms=0,
            max_reassemblies=1000,
            max_reassembly_length=1000,
            type=VppEnum.vl_api_ip_reass_type_t.IP_REASS_TYPE_SHALLOW_VIRTUAL,
            expire_walk_interval_ms=10,
            is_ip6=1,
        )
        self.virtual_sleep(0.25)
        self.vapi.ip_reassembly_set(
            timeout_ms=1000000,
            max_reassemblies=1000,
            max_reassembly_length=1000,
            type=VppEnum.vl_api_ip_reass_type_t.IP_REASS_TYPE_SHALLOW_VIRTUAL,
            expire_walk_interval_ms=10000,
            is_ip6=1,
        )

    def tearDown(self):
        super().tearDown()
        self.logger.debug(self.vapi.ppcli("show ip6-sv-reassembly details"))
        self.logger.debug(self.vapi.ppcli("show buffers"))

    def test_basic(self):
        """basic reassembly"""
        payload_len = 1000
        payload = ""
        counter = 0
        while len(payload) < payload_len:
            payload += "%u " % counter
            counter += 1

        p = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6)
            / UDP(sport=1234, dport=5678)
            / Raw(payload)
        )
        fragments = fragment_rfc8200(p, 1, payload_len / 4)

        # send fragment #2 - should be cached inside reassembly
        self.pg_enable_capture()
        self.src_if.add_stream(fragments[1])
        self.pg_start()
        self.logger.debug(self.vapi.ppcli("show ip6-sv-reassembly details"))
        self.logger.debug(self.vapi.ppcli("show buffers"))
        self.logger.debug(self.vapi.ppcli("show trace"))
        self.dst_if.assert_nothing_captured()

        # send fragment #1 - reassembly is finished now and both fragments
        # forwarded
        self.pg_enable_capture()
        self.src_if.add_stream(fragments[0])
        self.pg_start()
        self.logger.debug(self.vapi.ppcli("show ip6-sv-reassembly details"))
        self.logger.debug(self.vapi.ppcli("show buffers"))
        self.logger.debug(self.vapi.ppcli("show trace"))
        c = self.dst_if.get_capture(2)
        for sent, recvd in zip([fragments[1], fragments[0]], c):
            self.assertEqual(sent[IPv6].src, recvd[IPv6].src)
            self.assertEqual(sent[IPv6].dst, recvd[IPv6].dst)
            self.assertEqual(sent[Raw].payload, recvd[Raw].payload)

        # send rest of fragments - should be immediately forwarded
        self.pg_enable_capture()
        self.src_if.add_stream(fragments[2:])
        self.pg_start()
        c = self.dst_if.get_capture(len(fragments[2:]))
        for sent, recvd in zip(fragments[2:], c):
            self.assertEqual(sent[IPv6].src, recvd[IPv6].src)
            self.assertEqual(sent[IPv6].dst, recvd[IPv6].dst)
            self.assertEqual(sent[Raw].payload, recvd[Raw].payload)

    def test_verify_clear_trace_mid_reassembly(self):
        """verify clear trace works mid-reassembly"""
        payload_len = 1000
        payload = ""
        counter = 0
        while len(payload) < payload_len:
            payload += "%u " % counter
            counter += 1

        p = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6)
            / UDP(sport=1234, dport=5678)
            / Raw(payload)
        )
        fragments = fragment_rfc8200(p, 1, payload_len / 4)

        self.pg_enable_capture()
        self.src_if.add_stream(fragments[1])
        self.pg_start()

        self.logger.debug(self.vapi.cli("show trace"))
        self.vapi.cli("clear trace")

        self.pg_enable_capture()
        self.src_if.add_stream(fragments[0])
        self.pg_start()
        self.dst_if.get_capture(2)

        self.logger.debug(self.vapi.cli("show trace"))
        self.vapi.cli("clear trace")

        self.pg_enable_capture()
        self.src_if.add_stream(fragments[2:])
        self.pg_start()
        self.dst_if.get_capture(len(fragments[2:]))

    def test_timeout(self):
        """reassembly timeout"""
        payload_len = 1000
        payload = ""
        counter = 0
        while len(payload) < payload_len:
            payload += "%u " % counter
            counter += 1

        p = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6)
            / UDP(sport=1234, dport=5678)
            / Raw(payload)
        )
        fragments = fragment_rfc8200(p, 1, payload_len / 4)

        self.vapi.ip_reassembly_set(
            timeout_ms=100,
            max_reassemblies=1000,
            max_reassembly_length=1000,
            expire_walk_interval_ms=50,
            is_ip6=1,
            type=VppEnum.vl_api_ip_reass_type_t.IP_REASS_TYPE_SHALLOW_VIRTUAL,
        )

        # send fragments #2 and #1 - should be forwarded
        self.pg_enable_capture()
        self.src_if.add_stream(fragments[0:2])
        self.pg_start()
        self.logger.debug(self.vapi.ppcli("show ip6-sv-reassembly details"))
        self.logger.debug(self.vapi.ppcli("show buffers"))
        self.logger.debug(self.vapi.ppcli("show trace"))
        c = self.dst_if.get_capture(2)
        for sent, recvd in zip([fragments[1], fragments[0]], c):
            self.assertEqual(sent[IPv6].src, recvd[IPv6].src)
            self.assertEqual(sent[IPv6].dst, recvd[IPv6].dst)
            self.assertEqual(sent[Raw].payload, recvd[Raw].payload)

        # wait for cleanup
        self.virtual_sleep(0.25, "wait before sending rest of fragments")

        # send rest of fragments - shouldn't be forwarded
        self.pg_enable_capture()
        self.src_if.add_stream(fragments[2:])
        self.pg_start()
        self.dst_if.assert_nothing_captured()

    def test_lru(self):
        """reassembly reuses LRU element"""

        self.vapi.ip_reassembly_set(
            timeout_ms=1000000,
            max_reassemblies=1,
            max_reassembly_length=1000,
            type=VppEnum.vl_api_ip_reass_type_t.IP_REASS_TYPE_SHALLOW_VIRTUAL,
            is_ip6=1,
            expire_walk_interval_ms=10000,
        )

        payload_len = 1000
        payload = ""
        counter = 0
        while len(payload) < payload_len:
            payload += "%u " % counter
            counter += 1

        packet_count = 10

        fragments = [
            f
            for i in range(packet_count)
            for p in (
                Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
                / IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6)
                / UDP(sport=1234, dport=5678)
                / Raw(payload)
            )
            for f in fragment_rfc8200(p, i, payload_len / 4)
        ]

        self.pg_enable_capture()
        self.src_if.add_stream(fragments)
        self.pg_start()
        c = self.dst_if.get_capture(len(fragments))
        for sent, recvd in zip(fragments, c):
            self.assertEqual(sent[IPv6].src, recvd[IPv6].src)
            self.assertEqual(sent[IPv6].dst, recvd[IPv6].dst)
            self.assertEqual(sent[Raw].payload, recvd[Raw].payload)

    def test_one_fragment(self):
        """whole packet in one fragment processed independently"""
        pkt = (
            Ether(src=self.src_if.remote_mac, dst=self.src_if.local_mac)
            / IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6)
            / ICMPv6EchoRequest()
            / Raw("X" * 1600)
        )
        frags = fragment_rfc8200(pkt, 1, 400)

        # send a fragment with known id
        self.send_and_expect(self.src_if, [frags[0]], self.dst_if)

        # send an atomic fragment with same id - should be reassembled
        pkt = (
            Ether(src=self.src_if.remote_mac, dst=self.src_if.local_mac)
            / IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6)
            / IPv6ExtHdrFragment(id=1)
            / ICMPv6EchoRequest()
        )
        rx = self.send_and_expect(self.src_if, [pkt], self.dst_if)

        # now forward packets matching original reassembly, should still work
        rx = self.send_and_expect(self.src_if, frags[1:], self.dst_if)

    def test_bunch_of_fragments(self):
        """valid fragments followed by rogue fragments and atomic fragment"""
        pkt = (
            Ether(src=self.src_if.remote_mac, dst=self.src_if.local_mac)
            / IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6)
            / ICMPv6EchoRequest()
            / Raw("X" * 1600)
        )
        frags = fragment_rfc8200(pkt, 1, 400)
        rx = self.send_and_expect(self.src_if, frags, self.dst_if)

        rogue = (
            Ether(src=self.src_if.remote_mac, dst=self.src_if.local_mac)
            / IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6)
            / IPv6ExtHdrFragment(id=1, nh=58, offset=608)
            / Raw("X" * 308)
        )

        self.send_and_expect(self.src_if, rogue * 604, self.dst_if)

        pkt = (
            Ether(src=self.src_if.remote_mac, dst=self.src_if.local_mac)
            / IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6)
            / IPv6ExtHdrFragment(id=1)
            / ICMPv6EchoRequest()
        )
        rx = self.send_and_expect(self.src_if, [pkt], self.dst_if)

    def test_truncated_fragment(self):
        """truncated fragment"""
        pkt = (
            Ether(src=self.src_if.remote_mac, dst=self.src_if.local_mac)
            / IPv6(
                src=self.src_if.remote_ip6,
                dst=self.src_if.local_ip6,
                nh=44,
                plen=2,
            )
            / IPv6ExtHdrFragment(nh=6)
        )

        rx = self.send_and_expect(self.src_if, [pkt], self.src_if)
        self.assertIn(ICMPv6ParamProblem, rx[0])
        self.assertEqual(rx[0][ICMPv6ParamProblem].code, 0)
        self.assertEqual(rx[0][ICMPv6ParamProblem].ptr, 40)
        self.dst_if.assert_nothing_captured()

    def _get_buffers_used(self):
        r = self.vapi.cli_return_response("show buffers")
        self.assertTrue(r.retval == 0)
        return int(r.reply.strip().split("\n")[-1].split()[-1])

    def test_extended_clone_buffer_leak(self):
        """extended SV reassembly: duplicate first fragment must not leak clone buffer"""

        self.vapi.cli("set ip reassembly extended ip6 on")

        self.vapi.ip_reassembly_set(
            timeout_ms=100,
            max_reassemblies=1000,
            max_reassembly_length=1000,
            type=VppEnum.vl_api_ip_reass_type_t.IP_REASS_TYPE_SHALLOW_VIRTUAL,
            is_ip6=1,
            expire_walk_interval_ms=50,
        )

        bufs_before = self._get_buffers_used()

        # send many reassemblies where the first fragment arrives twice,
        # triggering a second clone - the old clone must be freed
        num_flows = 50
        fragments = []
        for i in range(num_flows):
            # first fragment (offset=0, m=1) - triggers clone
            frag1 = (
                Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
                / IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6)
                / IPv6ExtHdrFragment(id=5000 + i, nh=17, offset=0, m=1)
                / Raw(b"\x04\xd2\x16\x2e\x00\xd0\x00\x00" + b"X" * 200)
            )
            # duplicate first fragment - should free old clone before new one
            frag1_dup = frag1.copy()
            fragments.extend([frag1, frag1_dup])

        self.pg_enable_capture()
        self.src_if.add_stream(fragments)
        self.pg_start()
        # in extended mode, need both first and last to forward, so these
        # stay cached; don't expect captures
        self.logger.debug(self.vapi.ppcli("show ip6-sv-reassembly details"))

        # wait for timeout to expire all reassemblies (frees clone buffers)
        self.virtual_sleep(0.25)

        bufs_after = self._get_buffers_used()
        self.assertGreaterEqual(
            bufs_before,
            bufs_after,
            "Buffer leak detected: %d used before, %d after"
            % (bufs_before, bufs_after),
        )

        self.vapi.cli("set ip reassembly extended ip6 off")

    def test_truncated_ext_header_chain(self):
        """hop-by-hop options followed by truncated fragment header"""

        IP_PROTOCOL_IP6_FRAGMENT_HEADER = 44

        # 8-byte Hop-by-Hop header: next = Fragment Header, Hdr Ext Len = 0
        # Followed by 1-byte (truncated) Fragment Header
        hbh = struct.pack("BB", IP_PROTOCOL_IP6_FRAGMENT_HEADER, 0) + b"\x00" * 7

        pkt = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IPv6(
                src=self.src_if.remote_ip6,
                dst=self.dst_if.remote_ip6,
                nh="Hop-by-Hop Option Header",
            )
            / Raw(load=hbh)
        )

        rx = self.send_and_expect(
            self.src_if,
            [pkt],
            self.src_if,
        )
        self.assertIn(ICMPv6ParamProblem, rx[0])
        self.assertEqual(rx[0][ICMPv6ParamProblem].code, 0)

    def _get_buffer_count(self):
        """Get the number of allocated buffers from 'show buffers'"""
        output = self.vapi.ppcli("show buffers")
        # Parse the total buffer count from output like "Total buffers: 1234"
        for line in output.split("\n"):
            if "Total buffers:" in line:
                return int(line.split(":")[1].strip())
        return 0

    def test_l4_protocol_sctp(self):
        """SCTP packets pass through IPv6 SVR"""
        payload = "a " * 800

        p = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6)
            / SCTP(sport=21, dport=22)
            / Raw(payload.encode())
        )
        fragments = fragment_rfc8200(p, 100, 1400)
        self.assertGreater(len(fragments), 1, "Expected fragments, got single packet")

        buffers_before = self._get_buffer_count()
        self.pg_enable_capture()
        self.src_if.add_stream(fragments)
        self.pg_start()
        c = self.dst_if.get_capture(len(fragments))
        self.assertEqual(len(c), len(fragments))
        for sent, recvd in zip(fragments, c):
            self.assertEqual(sent[IPv6].src, recvd[IPv6].src)
            self.assertEqual(sent[IPv6].dst, recvd[IPv6].dst)
        buffers_after = self._get_buffer_count()
        self.assertLessEqual(
            buffers_after,
            buffers_before + len(fragments),
            "Buffer leak detected: before=%d, after=%d"
            % (buffers_before, buffers_after),
        )

    def test_l4_protocol_dccp(self):
        """DCCP packets pass through IPv6 SVR"""
        # DCCP protocol number is 33
        # Scapy has no DCCP layer, so we use Raw.
        dccp_header = b"\x04\xd2\x12\x34" + b"\x00" * 4
        payload = "b " * 800

        p = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IPv6(
                src=self.src_if.remote_ip6,
                dst=self.dst_if.remote_ip6,
                nh=33,  # DCCP
            )
            / Raw(dccp_header + payload.encode())
        )
        fragments = fragment_rfc8200(p, identification=200, fragsize=1400)
        self.assertGreater(len(fragments), 1, "Expected fragments, got single packet")

        buffers_before = self._get_buffer_count()
        self.pg_enable_capture()
        self.src_if.add_stream(fragments)
        self.pg_start()
        c = self.dst_if.get_capture(len(fragments))
        self.assertEqual(len(c), len(fragments))
        for sent, recvd in zip(fragments, c):
            self.assertEqual(sent[IPv6].src, recvd[IPv6].src)
            self.assertEqual(sent[IPv6].dst, recvd[IPv6].dst)
        buffers_after = self._get_buffer_count()
        self.assertLessEqual(
            buffers_after,
            buffers_before + len(fragments),
            "Buffer leak detected: before=%d, after=%d"
            % (buffers_before, buffers_after),
        )

    def test_l4_protocol_udplite(self):
        """UDP-Lite packets pass through IPv6 SVR"""
        # UDP-Lite protocol number is 136
        # Scapy has no UDPLite layer, so we use Raw.
        udplite_header = b"\x05\xdd\x06\xde" + b"\x00\x80" + b"\x00\x08"
        payload = "c " * 800

        p = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IPv6(
                src=self.src_if.remote_ip6,
                dst=self.dst_if.remote_ip6,
                nh=136,  # UDP-Lite
            )
            / Raw(udplite_header + payload.encode())
        )
        fragments = fragment_rfc8200(p, identification=300, fragsize=1400)
        self.assertGreater(len(fragments), 1, "Expected fragments, got single packet")

        buffers_before = self._get_buffer_count()
        self.pg_enable_capture()
        self.src_if.add_stream(fragments)
        self.pg_start()
        c = self.dst_if.get_capture(len(fragments))
        self.assertEqual(len(c), len(fragments))
        for sent, recvd in zip(fragments, c):
            self.assertEqual(sent[IPv6].src, recvd[IPv6].src)
            self.assertEqual(sent[IPv6].dst, recvd[IPv6].dst)
        buffers_after = self._get_buffer_count()
        self.assertLessEqual(
            buffers_after,
            buffers_before + len(fragments),
            "Buffer leak detected: before=%d, after=%d"
            % (buffers_before, buffers_after),
        )

    def test_unsupported_proto_passthrough(self):
        """GRE and ICMPv6 ND packets pass through IPv6 SVR"""
        payload = "w " * 800

        # unfragmented GRE - unsupported L4 protocol must pass through
        p = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6)
            / GRE()
            / Raw(payload.encode())
        )
        buffers_before = self._get_buffer_count()
        self.pg_enable_capture()
        self.src_if.add_stream([p])
        self.pg_start()
        c = self.dst_if.get_capture(1)
        self.assertEqual(len(c), 1)
        self.assertEqual(c[0][IPv6].nh, p[IPv6].nh)
        self.assertEqual(bytes(c[0][Raw].load), payload.encode())

        # unfragmented ICMPv6 router solicitation - unsupported ICMP6 type
        # (non-echo, non-error) must pass through
        p = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6)
            / ICMPv6ND_RS()
        )
        self.pg_enable_capture()
        self.src_if.add_stream([p])
        self.pg_start()
        c = self.dst_if.get_capture(1)
        self.assertEqual(len(c), 1)
        self.assertEqual(c[0][IPv6].nh, p[IPv6].nh)

        # fragmented GRE - reassembly must complete despite unsupported L4
        p = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IPv6(
                src=self.src_if.remote_ip6,
                dst=self.dst_if.remote_ip6,
                nh=47,  # GRE
            )
            / GRE()
            / Raw(payload.encode())
        )
        fragments = fragment_rfc8200(p, identification=300, fragsize=1400)
        self.assertGreater(len(fragments), 1, "Expected fragments, got single packet")
        self.pg_enable_capture()
        self.src_if.add_stream(fragments)
        self.pg_start()
        c = self.dst_if.get_capture(len(fragments))
        self.assertEqual(len(c), len(fragments))
        for sent, recvd in zip(fragments, c):
            self.assertEqual(recvd[IPv6].nh, 44)  # fragment header
        buffers_after = self._get_buffer_count()
        self.assertLessEqual(
            buffers_after,
            buffers_before + len(fragments),
            "Buffer leak detected: before=%d, after=%d"
            % (buffers_before, buffers_after),
        )

    def test_truncated_ext_header_pointer(self):
        """A truncated extension header reports the erroneous header pointer

        The hop-by-hop header ends before the destination options header,
        whose length byte is not present. The node must report a Parameter
        Problem with the erroneous header field code and point at the
        truncated header."""
        IP_PROTOCOL_IP6_DESTINATION_HEADER = 60

        hbh = struct.pack("BB", IP_PROTOCOL_IP6_DESTINATION_HEADER, 0) + b"\x00" * 7

        pkt = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IPv6(
                src=self.src_if.remote_ip6,
                dst=self.dst_if.remote_ip6,
                nh="Hop-by-Hop Option Header",
            )
            / Raw(load=hbh)
        )

        rx = self.send_and_expect(
            self.src_if,
            [pkt],
            self.src_if,
        )
        self.assertIn(ICMPv6ParamProblem, rx[0])
        self.assertEqual(rx[0][ICMPv6ParamProblem].code, 0)
        self.assertEqual(rx[0][ICMPv6ParamProblem].ptr, 48)

    def test_ext_header_chain_over_limit(self):
        """A packet with more extension headers than the chain limit is forwarded

        The walk records at most four extension headers, so it cannot
        classify a longer chain. The packet is valid, so the node must
        pass it through instead of dropping it with an ICMP error."""
        p = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6)
            / IPv6ExtHdrHopByHop(nh=60)
            / IPv6ExtHdrDestOpt(nh=43)
            / IPv6ExtHdrRouting(nh=60)
            / IPv6ExtHdrDestOpt(nh=60)
            / IPv6ExtHdrDestOpt(nh=17)
            / UDP(sport=1234, dport=5678)
            / Raw(b"X" * 16)
        )

        recvd = self.send_and_expect(self.src_if, [p], self.dst_if)
        self.src_if.assert_nothing_captured()
        self.assertEqual(recvd[0][IPv6].src, p[IPv6].src)
        self.assertEqual(recvd[0][IPv6].dst, p[IPv6].dst)
        self.assertEqual(bytes(recvd[0][IPv6].payload), bytes(p[IPv6].payload))

    def test_first_fragment_at_chain_limit(self):
        """A first fragment at the entry limit is not rejected

        The fragment header fills the last chain slot and names a
        destination options header. The walk stops at the entry limit,
        but the fragment is valid and must not be answered with a
        Parameter Problem."""
        payload_first = b"A" * 16
        first = chain_limit_first_fragment(self.src_if, self.dst_if, payload_first)

        recvd = self.send_and_expect(self.src_if, [first], self.dst_if)
        self.src_if.assert_nothing_captured()
        self.assertIn(IPv6ExtHdrFragment, recvd[0])
        self.assertEqual(bytes(recvd[0][UDP].payload), payload_first)

    def test_l4_header_after_chain_limit(self):
        """A terminating L4 header after four chain headers is forwarded

        Four extension headers fill the chain and the next protocol is UDP,
        so the walk must report the L4 header instead of stopping at the
        entry limit. The fragments must be forwarded, not rejected."""
        payload_first = b"A" * 16
        payload_last = b"B" * 16
        first, last = entry_limit_l4_fragments(
            self.src_if, self.dst_if, payload_first, payload_last
        )

        recvd = self.send_and_expect(self.src_if, [first, last], self.dst_if)
        self.src_if.assert_nothing_captured()
        for pkt in recvd:
            self.assertIn(IPv6ExtHdrFragment, pkt)
        payloads = [bytes(pkt[Raw].load) for pkt in recvd]
        self.assertIn(payload_first, payloads)
        self.assertIn(payload_last, payloads)

    def test_first_fragment_beyond_depth(self):
        """A first fragment whose L4 header is past the scan depth is dropped

        The destination options header pushes the UDP header beyond the
        256-byte scan depth. The walk stops at the limit, so the node
        cannot classify the L4 header and drops the fragment."""
        error_cnt_str = "/err/%s/reass_missing_upper" % self.reass_err_node
        error_cnt = self.statistics.get_err_counter(error_cnt_str)

        payload_first = b"A" * 16
        first = first_fragment_beyond_depth(self.src_if, self.dst_if, payload_first)

        self.send_and_assert_no_replies(self.src_if, [first])
        self.dst_if.assert_nothing_captured()
        self.assert_error_counter_equal(error_cnt_str, error_cnt + 1)

    def test_atomic_fragment_beyond_depth(self):
        """An atomic fragment whose L4 header is past the scan depth is forwarded

        RFC 6946 asks a node to process an atomic fragment as an
        unfragmented packet. The walk stops at the limit, so the fragment
        follows the unfragmented path instead of the first-fragment drop."""
        payload = b"A" * 16
        pkt = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6)
            / IPv6ExtHdrFragment(offset=0, m=0, nh=60)
            / IPv6ExtHdrDestOpt(
                nh=17, options=[HBHOptUnknown(otype=0xFF, optlen=0)] * 150
            )
            / UDP(sport=1234, dport=5678)
            / Raw(payload)
        )

        recvd = self.send_and_expect(self.src_if, [pkt], self.dst_if)
        self.src_if.assert_nothing_captured()
        self.assertIn(IPv6ExtHdrFragment, recvd[0])
        self.assertEqual(bytes(recvd[0][UDP].payload), payload)

    def test_unfragmented_header_beyond_depth(self):
        """An unfragmented packet with one chain header past the scan depth is forwarded

        The hop-by-hop header ends past the 256-byte scan depth, so the
        walk stops at the limit with one recorded header. The packet is not
        a fragment, so it follows the unfragmented path."""
        pkt = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6)
            / IPv6ExtHdrHopByHop(
                nh=17, options=[HBHOptUnknown(otype=0xFF, optlen=0)] * 108
            )
            / UDP(sport=1234, dport=5678)
            / Raw(b"X" * 16)
        )

        recvd = self.send_and_expect(self.src_if, [pkt], self.dst_if)
        self.src_if.assert_nothing_captured()
        self.assertEqual(bytes(recvd[0][UDP].payload), b"X" * 16)

    def test_unfragmented_header_crosses_buffer(self):
        """An unfragmented packet with a chain header crossing the buffer is forwarded

        The hop-by-hop header runs past the first buffer but still fits in
        the datagram, so the walk cannot see further but the packet is not
        malformed. It follows the unfragmented path."""
        pkt = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6)
            / IPv6ExtHdrHopByHop(
                nh=17, options=[HBHOptUnknown(otype=0xFF, optlen=0)] * 1000
            )
            / UDP(sport=1234, dport=5678)
            / Raw(b"X" * 16)
        )

        recvd = self.send_and_expect(self.src_if, [pkt], self.dst_if)
        self.src_if.assert_nothing_captured()
        self.assertEqual(bytes(recvd[0][UDP].payload), b"X" * 16)

    def test_malformed_multicast_no_icmp(self):
        """A malformed multicast first fragment is dropped without an ICMPv6 error

        RFC 4443 section 2.4(e) forbids an ICMPv6 error for a packet
        destined to a multicast address. The node must drop the packet
        instead of answering with a Parameter Problem."""
        self.vapi.feature_enable_disable(
            enable=1,
            arc_name="ip6-multicast",
            feature_name="ip6-sv-reassembly-mcast-feature",
            sw_if_index=self.src_if.sw_if_index,
        )
        self.addCleanup(
            self.vapi.feature_enable_disable,
            enable=0,
            arc_name="ip6-multicast",
            feature_name="ip6-sv-reassembly-mcast-feature",
            sw_if_index=self.src_if.sw_if_index,
        )

        error_cnt_str = "/err/ip6-sv-reassembly-mcast-feature/reass_missing_upper"
        error_cnt = self.statistics.get_err_counter(error_cnt_str)

        # The UDP header does not fit in the declared payload, so the walk
        # reports a truncated L4 header. The multicast destination must
        # suppress the Parameter Problem.
        pkt = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IPv6(src=self.src_if.remote_ip6, dst="ff02::1", nh=44, plen=12)
            / IPv6ExtHdrFragment(offset=0, m=1, nh=17)
            / Raw(b"\x00" * 4)
        )
        self.send_and_assert_no_replies(self.src_if, [pkt])
        self.dst_if.assert_nothing_captured()
        self.assert_error_counter_equal(error_cnt_str, error_cnt + 1)

    def test_multicast_invalid_frag_len_no_icmp(self):
        """A multicast fragment with a bad fragment length gets no ICMPv6 error

        RFC 4443 section 2.4(e) forbids an ICMPv6 error for a packet
        destined to a multicast address. The invalid-fragment-length path
        must apply the same check as the classifier."""
        self.vapi.feature_enable_disable(
            enable=1,
            arc_name="ip6-multicast",
            feature_name="ip6-sv-reassembly-mcast-feature",
            sw_if_index=self.src_if.sw_if_index,
        )
        self.addCleanup(
            self.vapi.feature_enable_disable,
            enable=0,
            arc_name="ip6-multicast",
            feature_name="ip6-sv-reassembly-mcast-feature",
            sw_if_index=self.src_if.sw_if_index,
        )

        error_cnt_str = "/err/ip6-sv-reassembly-mcast-feature/reass_invalid_frag_len"
        error_cnt = self.statistics.get_err_counter(error_cnt_str)

        # The fragment payload after the fragment header is 12 bytes, not a
        # multiple of 8, so verify_fragment_multiple_8 fails. The multicast
        # destination must suppress the Parameter Problem.
        pkt = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IPv6(src=self.src_if.remote_ip6, dst="ff02::1")
            / IPv6ExtHdrFragment(m=1, nh=17)
            / UDP(sport=1234, dport=5678)
            / Raw(b"X" * 4)
        )
        self.send_and_assert_no_replies(self.src_if, [pkt])
        self.dst_if.assert_nothing_captured()
        self.assert_error_counter_equal(error_cnt_str, error_cnt + 1)

    def test_icmp6_echo_invalid_frag_len_gets_icmp(self):
        """An ICMPv6 echo fragment with a bad fragment length gets a Parameter Problem

        The offender check only suppresses an ICMPv6 error for an ICMPv6
        error or redirect message. An echo request is informational, so the
        invalid fragment length is reported."""
        error_cnt_str = "/err/ip6-sv-reassembly-feature/reass_invalid_frag_len"
        error_cnt = self.statistics.get_err_counter(error_cnt_str)

        # The fragment payload after the fragment header is 12 bytes, not a
        # multiple of 8, so verify_fragment_multiple_8 fails. The ICMPv6
        # echo request is informational, so the node answers with a
        # Parameter Problem.
        pkt = (
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6)
            / IPv6ExtHdrFragment(m=1, nh=58)
            / ICMPv6EchoRequest()
            / Raw(b"X" * 4)
        )

        rx = self.send_and_expect(self.src_if, [pkt], self.src_if)
        self.assertIn(ICMPv6ParamProblem, rx[0])
        self.assertEqual(rx[0][ICMPv6ParamProblem].code, 0)
        self.assertEqual(rx[0][ICMPv6ParamProblem].ptr, 4)
        self.dst_if.assert_nothing_captured()
        self.assert_error_counter_equal(error_cnt_str, error_cnt + 1)


class TestIPv4ReassemblyLocalNode(VppTestCase):
    """IPv4 Reassembly for packets coming to ip4-local node"""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        cls.create_pg_interfaces([0])
        cls.src_dst_if = cls.pg0

        # setup all interfaces
        for i in cls.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

        cls.padding = " abcdefghijklmn"
        cls.create_stream()
        cls.create_fragments()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()

    def setUp(self):
        """Test setup - force timeout on existing reassemblies"""
        super().setUp()
        self.vapi.ip_reassembly_set(
            timeout_ms=0,
            max_reassemblies=1000,
            max_reassembly_length=1000,
            expire_walk_interval_ms=10,
        )
        self.virtual_sleep(0.25)
        self.vapi.ip_reassembly_set(
            timeout_ms=1000000,
            max_reassemblies=1000,
            max_reassembly_length=1000,
            expire_walk_interval_ms=10000,
        )

    def tearDown(self):
        super().tearDown()

    def show_commands_at_teardown(self):
        self.logger.debug(self.vapi.ppcli("show ip4-full-reassembly details"))
        self.logger.debug(self.vapi.ppcli("show buffers"))

    @classmethod
    def create_stream(cls, packet_count=test_packet_count):
        """Create input packet stream for defined interface.

        :param list packet_sizes: Required packet sizes.
        """
        for i in range(0, packet_count):
            info = cls.create_packet_info(cls.src_dst_if, cls.src_dst_if)
            payload = cls.info_to_payload(info)
            p = (
                Ether(dst=cls.src_dst_if.local_mac, src=cls.src_dst_if.remote_mac)
                / IP(
                    id=info.index,
                    src=cls.src_dst_if.remote_ip4,
                    dst=cls.src_dst_if.local_ip4,
                )
                / ICMP(type="echo-request", id=1234)
                / Raw(payload)
            )
            cls.extend_packet(p, 1518, cls.padding)
            info.data = p

    @classmethod
    def create_fragments(cls):
        infos = cls._packet_infos
        cls.pkt_infos = []
        for index, info in infos.items():
            p = info.data
            # cls.logger.debug(ppp("Packet:",
            #                      p.__class__(scapy.compat.raw(p))))
            fragments_300 = fragment_rfc791(p, 300)
            cls.pkt_infos.append((index, fragments_300))
        cls.fragments_300 = [x for (_, frags) in cls.pkt_infos for x in frags]
        cls.logger.debug(
            "Fragmented %s packets into %s 300-byte fragments"
            % (len(infos), len(cls.fragments_300))
        )

    def verify_capture(self, capture):
        """Verify captured packet stream.

        :param list capture: Captured packet stream.
        """
        info = None
        seen = set()
        for packet in capture:
            try:
                self.logger.debug(ppp("Got packet:", packet))
                ip = packet[IP]
                icmp = packet[ICMP]
                payload_info = self.payload_to_info(packet[Raw])
                packet_index = payload_info.index
                if packet_index in seen:
                    raise Exception(ppp("Duplicate packet received", packet))
                seen.add(packet_index)
                self.assertEqual(payload_info.dst, self.src_dst_if.sw_if_index)
                info = self._packet_infos[packet_index]
                self.assertIsNotNone(info)
                self.assertEqual(packet_index, info.index)
                saved_packet = info.data
                self.assertEqual(ip.src, saved_packet[IP].dst)
                self.assertEqual(ip.dst, saved_packet[IP].src)
                self.assertEqual(icmp.type, 0)  # echo reply
                self.assertEqual(icmp.id, saved_packet[ICMP].id)
                self.assertEqual(icmp.payload, saved_packet[ICMP].payload)
            except Exception:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise
        for index in self._packet_infos:
            self.assertIn(
                index, seen, "Packet with packet_index %d not received" % index
            )

    @unittest.skipIf(
        "ping" in config.excluded_plugins, "Exclude tests requiring Ping plugin"
    )
    def test_reassembly(self):
        """basic reassembly"""

        self.pg_enable_capture()
        self.src_dst_if.add_stream(self.fragments_300)
        self.pg_start()

        packets = self.src_dst_if.get_capture(len(self.pkt_infos))
        self.verify_capture(packets)

        # run it all again to verify correctness
        self.pg_enable_capture()
        self.src_dst_if.add_stream(self.fragments_300)
        self.pg_start()

        packets = self.src_dst_if.get_capture(len(self.pkt_infos))
        self.verify_capture(packets)


class TestFIFReassembly(VppTestCase):
    """Fragments in fragments reassembly"""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        cls.create_pg_interfaces([0, 1])
        cls.src_if = cls.pg0
        cls.dst_if = cls.pg1
        for i in cls.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()
            i.config_ip6()
            i.resolve_ndp()

        cls.packet_sizes = [64, 512, 1518, 9018]
        cls.padding = " abcdefghijklmn"

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()

    def setUp(self):
        """Test setup - force timeout on existing reassemblies"""
        super().setUp()
        self.vapi.ip_reassembly_enable_disable(
            sw_if_index=self.src_if.sw_if_index, enable_ip4=True, enable_ip6=True
        )
        self.vapi.ip_reassembly_enable_disable(
            sw_if_index=self.dst_if.sw_if_index, enable_ip4=True, enable_ip6=True
        )
        self.vapi.ip_reassembly_set(
            timeout_ms=0,
            max_reassemblies=1000,
            max_reassembly_length=1000,
            expire_walk_interval_ms=10,
        )
        self.vapi.ip_reassembly_set(
            timeout_ms=0,
            max_reassemblies=1000,
            max_reassembly_length=1000,
            expire_walk_interval_ms=10,
            is_ip6=1,
        )
        self.virtual_sleep(0.25)
        self.vapi.ip_reassembly_set(
            timeout_ms=1000000,
            max_reassemblies=1000,
            max_reassembly_length=1000,
            expire_walk_interval_ms=10000,
        )
        self.vapi.ip_reassembly_set(
            timeout_ms=1000000,
            max_reassemblies=1000,
            max_reassembly_length=1000,
            expire_walk_interval_ms=10000,
            is_ip6=1,
        )

    def tearDown(self):
        super().tearDown()

    def show_commands_at_teardown(self):
        self.logger.debug(self.vapi.ppcli("show ip4-full-reassembly details"))
        self.logger.debug(self.vapi.ppcli("show ip6-full-reassembly details"))
        self.logger.debug(self.vapi.ppcli("show buffers"))

    def verify_capture(self, capture, ip_class, dropped_packet_indexes=[]):
        """Verify captured packet stream.

        :param list capture: Captured packet stream.
        """
        info = None
        seen = set()
        for packet in capture:
            try:
                self.logger.debug(ppp("Got packet:", packet))
                ip = packet[ip_class]
                udp = packet[UDP]
                payload_info = self.payload_to_info(packet[Raw])
                packet_index = payload_info.index
                self.assertTrue(
                    packet_index not in dropped_packet_indexes,
                    ppp("Packet received, but should be dropped:", packet),
                )
                if packet_index in seen:
                    raise Exception(ppp("Duplicate packet received", packet))
                seen.add(packet_index)
                self.assertEqual(payload_info.dst, self.dst_if.sw_if_index)
                info = self._packet_infos[packet_index]
                self.assertTrue(info is not None)
                self.assertEqual(packet_index, info.index)
                saved_packet = info.data
                self.assertEqual(ip.src, saved_packet[ip_class].src)
                self.assertEqual(ip.dst, saved_packet[ip_class].dst)
                self.assertEqual(udp.payload, saved_packet[UDP].payload)
            except Exception:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise
        for index in self._packet_infos:
            self.assertTrue(
                index in seen or index in dropped_packet_indexes,
                "Packet with packet_index %d not received" % index,
            )

    @unittest.skipIf(
        "gre" in config.excluded_plugins, "Exclude tests requiring GRE plugin"
    )
    def test_fif4(self):
        """Fragments in fragments (4o4)"""

        # TODO this should be ideally in setUpClass, but then we hit a bug
        # with VppIpRoute incorrectly reporting it's present when it's not
        # so we need to manually remove the vpp config, thus we cannot have
        # it shared for multiple test cases
        self.tun_ip4 = "1.1.1.2"

        self.gre4 = VppGreInterface(self, self.src_if.local_ip4, self.tun_ip4)
        self.gre4.add_vpp_config()
        self.gre4.admin_up()
        self.gre4.config_ip4()

        self.vapi.ip_reassembly_enable_disable(
            sw_if_index=self.gre4.sw_if_index, enable_ip4=True
        )

        self.route4 = VppIpRoute(
            self,
            self.tun_ip4,
            32,
            [VppRoutePath(self.src_if.remote_ip4, self.src_if.sw_if_index)],
        )
        self.route4.add_vpp_config()

        self.reset_packet_infos()
        for i in range(test_packet_count):
            info = self.create_packet_info(self.src_if, self.dst_if)
            payload = self.info_to_payload(info)
            # Ethernet header here is only for size calculation, thus it
            # doesn't matter how it's initialized. This is to ensure that
            # reassembled packet is not > 9000 bytes, so that it's not dropped
            p = (
                Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02")
                / IP(id=i, src=self.src_if.remote_ip4, dst=self.dst_if.remote_ip4)
                / UDP(sport=1234, dport=5678)
                / Raw(payload)
            )
            size = self.packet_sizes[(i // 2) % len(self.packet_sizes)]
            self.extend_packet(p, size, self.padding)
            info.data = p[IP]  # use only IP part, without ethernet header

        fragments = [
            x
            for _, p in self._packet_infos.items()
            for x in fragment_rfc791(p.data, 400)
        ]

        encapped_fragments = [
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IP(src=self.tun_ip4, dst=self.src_if.local_ip4)
            / GRE()
            / p
            for p in fragments
        ]

        fragmented_encapped_fragments = [
            x for p in encapped_fragments for x in fragment_rfc791(p, 200)
        ]

        packets = self.send_and_expect_multi(
            send=[Send(self.src_if, fragmented_encapped_fragments)],
            expect=[Expect(self.dst_if, len(self._packet_infos))],
        )[0].packets
        self.verify_capture(packets, IP)

        # TODO remove gre vpp config by hand until VppIpRoute gets fixed
        # so that it's query_vpp_config() works as it should
        self.gre4.remove_vpp_config()
        self.logger.debug(self.vapi.ppcli("show interface"))

    @unittest.skipIf(
        "gre" in config.excluded_plugins, "Exclude tests requiring GRE plugin"
    )
    def test_fif6(self):
        """Fragments in fragments (6o6)"""
        # TODO this should be ideally in setUpClass, but then we hit a bug
        # with VppIpRoute incorrectly reporting it's present when it's not
        # so we need to manually remove the vpp config, thus we cannot have
        # it shared for multiple test cases
        self.tun_ip6 = "1002::1"

        self.gre6 = VppGreInterface(self, self.src_if.local_ip6, self.tun_ip6)
        self.gre6.add_vpp_config()
        self.gre6.admin_up()
        self.gre6.config_ip6()

        self.vapi.ip_reassembly_enable_disable(
            sw_if_index=self.gre6.sw_if_index, enable_ip6=True
        )

        self.route6 = VppIpRoute(
            self,
            self.tun_ip6,
            128,
            [VppRoutePath(self.src_if.remote_ip6, self.src_if.sw_if_index)],
        )
        self.route6.add_vpp_config()

        self.reset_packet_infos()
        for i in range(test_packet_count):
            info = self.create_packet_info(self.src_if, self.dst_if)
            payload = self.info_to_payload(info)
            # Ethernet header here is only for size calculation, thus it
            # doesn't matter how it's initialized. This is to ensure that
            # reassembled packet is not > 9000 bytes, so that it's not dropped
            p = (
                Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02")
                / IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6)
                / UDP(sport=1234, dport=5678)
                / Raw(payload)
            )
            size = self.packet_sizes[(i // 2) % len(self.packet_sizes)]
            self.extend_packet(p, size, self.padding)
            info.data = p[IPv6]  # use only IPv6 part, without ethernet header

        fragments = [
            x
            for _, i in self._packet_infos.items()
            for x in fragment_rfc8200(i.data, i.index, 400)
        ]

        encapped_fragments = [
            Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac)
            / IPv6(src=self.tun_ip6, dst=self.src_if.local_ip6)
            / GRE()
            / p
            for p in fragments
        ]

        fragmented_encapped_fragments = [
            x
            for p in encapped_fragments
            for x in (
                fragment_rfc8200(
                    p, 2 * len(self._packet_infos) + p[IPv6ExtHdrFragment].id, 200
                )
                if IPv6ExtHdrFragment in p
                else [p]
            )
        ]

        packets = self.send_and_expect_multi(
            send=[Send(self.src_if, fragmented_encapped_fragments)],
            expect=[Expect(self.dst_if, len(self._packet_infos))],
        )[0].packets
        self.verify_capture(packets, IPv6)

        # TODO remove gre vpp config by hand until VppIpRoute gets fixed
        # so that it's query_vpp_config() works as it should
        self.gre6.remove_vpp_config()


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
