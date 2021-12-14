#!/usr/bin/env python3

import unittest
from random import shuffle, choice, randrange

from framework import VppTestCase, VppTestRunner

import scapy.compat
from scapy.packet import Raw
from scapy.layers.l2 import Ether, GRE
from scapy.layers.inet import IP, UDP, ICMP, icmptypes
from scapy.layers.inet6 import HBHOptUnknown, ICMPv6ParamProblem,\
    ICMPv6TimeExceeded, IPv6, IPv6ExtHdrFragment,\
    IPv6ExtHdrHopByHop, IPv6ExtHdrDestOpt, PadN, ICMPv6EchoRequest,\
    ICMPv6EchoReply
from framework import VppTestCase, VppTestRunner
from util import ppp, ppc, fragment_rfc791, fragment_rfc8200
from vpp_gre_interface import VppGreInterface
from vpp_ip import DpoProto
from vpp_ip_route import VppIpRoute, VppRoutePath, FibPathProto
from vpp_papi import VppEnum

# 35 is enough to have >257 400-byte fragments
test_packet_count = 35


class TestIPv4Reassembly(VppTestCase):
    """ IPv4 Reassembly """

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
        """ Test setup - force timeout on existing reassemblies """
        super().setUp()
        self.vapi.ip_reassembly_enable_disable(
            sw_if_index=self.src_if.sw_if_index, enable_ip4=True)
        self.vapi.ip_reassembly_set(timeout_ms=0, max_reassemblies=1000,
                                    max_reassembly_length=1000,
                                    expire_walk_interval_ms=10)
        self.virtual_sleep(.25)
        self.vapi.ip_reassembly_set(timeout_ms=1000000, max_reassemblies=1000,
                                    max_reassembly_length=1000,
                                    expire_walk_interval_ms=10000)

    def tearDown(self):
        self.vapi.ip_reassembly_enable_disable(
            sw_if_index=self.src_if.sw_if_index, enable_ip4=False)
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
            p = (Ether(dst=cls.src_if.local_mac, src=cls.src_if.remote_mac) /
                 IP(id=info.index, src=cls.src_if.remote_ip4,
                    dst=cls.dst_if.remote_ip4) /
                 UDP(sport=1234, dport=5678) /
                 Raw(payload))
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
            fragments_200 = [
                x for f in fragments_400 for x in fragment_rfc791(f, 200)]
            cls.pkt_infos.append(
                (index, fragments_400, fragments_300, fragments_200))
        cls.fragments_400 = [
            x for (_, frags, _, _) in cls.pkt_infos for x in frags]
        cls.fragments_300 = [
            x for (_, _, frags, _) in cls.pkt_infos for x in frags]
        cls.fragments_200 = [
            x for (_, _, _, frags) in cls.pkt_infos for x in frags]
        cls.logger.debug("Fragmented %s packets into %s 400-byte fragments, "
                         "%s 300-byte fragments and %s 200-byte fragments" %
                         (len(infos), len(cls.fragments_400),
                             len(cls.fragments_300), len(cls.fragments_200)))

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
                    ppp("Packet received, but should be dropped:", packet))
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
            self.assertTrue(index in seen or index in dropped_packet_indexes,
                            "Packet with packet_index %d not received" % index)

    def test_reassembly(self):
        """ basic reassembly """

        self.pg_enable_capture()
        self.src_if.add_stream(self.fragments_200)
        self.pg_start()

        packets = self.dst_if.get_capture(len(self.pkt_infos))
        self.verify_capture(packets)
        self.src_if.assert_nothing_captured()

        # run it all again to verify correctness
        self.pg_enable_capture()
        self.src_if.add_stream(self.fragments_200)
        self.pg_start()

        packets = self.dst_if.get_capture(len(self.pkt_infos))
        self.verify_capture(packets)
        self.src_if.assert_nothing_captured()

    def test_verify_clear_trace_mid_reassembly(self):
        """ verify clear trace works mid-reassembly """

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
        """ reverse order reassembly """

        fragments = list(self.fragments_200)
        fragments.reverse()

        self.pg_enable_capture()
        self.src_if.add_stream(fragments)
        self.pg_start()

        packets = self.dst_if.get_capture(len(self.packet_infos))
        self.verify_capture(packets)
        self.src_if.assert_nothing_captured()

        # run it all again to verify correctness
        self.pg_enable_capture()
        self.src_if.add_stream(fragments)
        self.pg_start()

        packets = self.dst_if.get_capture(len(self.packet_infos))
        self.verify_capture(packets)
        self.src_if.assert_nothing_captured()

    def test_long_fragment_chain(self):
        """ long fragment chain """

        error_cnt_str = \
            "/err/ip4-full-reassembly-feature/fragment chain too long (drop)"

        error_cnt = self.statistics.get_err_counter(error_cnt_str)

        self.vapi.ip_reassembly_set(timeout_ms=100, max_reassemblies=1000,
                                    max_reassembly_length=3,
                                    expire_walk_interval_ms=50)

        p1 = (Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac) /
              IP(id=1000, src=self.src_if.remote_ip4,
                 dst=self.dst_if.remote_ip4) /
              UDP(sport=1234, dport=5678) /
              Raw(b"X" * 1000))
        p2 = (Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac) /
              IP(id=1001, src=self.src_if.remote_ip4,
                 dst=self.dst_if.remote_ip4) /
              UDP(sport=1234, dport=5678) /
              Raw(b"X" * 1000))
        frags = fragment_rfc791(p1, 200) + fragment_rfc791(p2, 500)

        self.pg_enable_capture()
        self.src_if.add_stream(frags)
        self.pg_start()

        self.dst_if.get_capture(1)
        self.assert_error_counter_equal(error_cnt_str, error_cnt + 1)

    def test_5737(self):
        """ fragment length + ip header size > 65535 """
        self.vapi.cli("clear errors")
        raw = b'''E\x00\x00\x88,\xf8\x1f\xfe@\x01\x98\x00\xc0\xa8\n-\xc0\xa8\n\
\x01\x08\x00\xf0J\xed\xcb\xf1\xf5Test-group: IPv4.IPv4.ipv4-message.\
Ethernet-Payload.IPv4-Packet.IPv4-Header.Fragment-Offset; Test-case: 5737'''
        malformed_packet = (Ether(dst=self.src_if.local_mac,
                                  src=self.src_if.remote_mac) /
                            IP(raw))
        p = (Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac) /
             IP(id=1000, src=self.src_if.remote_ip4,
                dst=self.dst_if.remote_ip4) /
             UDP(sport=1234, dport=5678) /
             Raw(b"X" * 1000))
        valid_fragments = fragment_rfc791(p, 400)

        counter = "/err/ip4-full-reassembly-feature/malformed packets"
        error_counter = self.statistics.get_err_counter(counter)
        self.pg_enable_capture()
        self.src_if.add_stream([malformed_packet] + valid_fragments)
        self.pg_start()

        self.dst_if.get_capture(1)
        self.logger.debug(self.vapi.ppcli("show error"))
        self.assertEqual(self.statistics.get_err_counter(counter),
                         error_counter + 1)

    def test_44924(self):
        """ compress tiny fragments """
        packets = [(Ether(dst=self.src_if.local_mac,
                          src=self.src_if.remote_mac) /
                    IP(id=24339, flags="MF", frag=0, ttl=64,
                       src=self.src_if.remote_ip4,
                       dst=self.dst_if.remote_ip4) /
                    ICMP(type="echo-request", code=0, id=0x1fe6, seq=0x2407) /
                    Raw(load='Test-group: IPv4')),
                   (Ether(dst=self.src_if.local_mac,
                          src=self.src_if.remote_mac) /
                    IP(id=24339, flags="MF", frag=3, ttl=64,
                       src=self.src_if.remote_ip4,
                       dst=self.dst_if.remote_ip4) /
                    ICMP(type="echo-request", code=0, id=0x1fe6, seq=0x2407) /
                    Raw(load='.IPv4.Fragmentation.vali')),
                   (Ether(dst=self.src_if.local_mac,
                          src=self.src_if.remote_mac) /
                    IP(id=24339, frag=6, ttl=64,
                       src=self.src_if.remote_ip4,
                       dst=self.dst_if.remote_ip4) /
                    ICMP(type="echo-request", code=0, id=0x1fe6, seq=0x2407) /
                    Raw(load='d; Test-case: 44924'))
                   ]

        self.pg_enable_capture()
        self.src_if.add_stream(packets)
        self.pg_start()

        self.dst_if.get_capture(1)

    def test_frag_1(self):
        """ fragment of size 1 """
        self.vapi.cli("clear errors")
        malformed_packets = [(Ether(dst=self.src_if.local_mac,
                                    src=self.src_if.remote_mac) /
                              IP(id=7, len=21, flags="MF", frag=0, ttl=64,
                                 src=self.src_if.remote_ip4,
                                 dst=self.dst_if.remote_ip4) /
                              ICMP(type="echo-request")),
                             (Ether(dst=self.src_if.local_mac,
                                    src=self.src_if.remote_mac) /
                              IP(id=7, len=21, frag=1, ttl=64,
                                 src=self.src_if.remote_ip4,
                                 dst=self.dst_if.remote_ip4) /
                              Raw(load=b'\x08')),
                             ]

        p = (Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac) /
             IP(id=1000, src=self.src_if.remote_ip4,
                dst=self.dst_if.remote_ip4) /
             UDP(sport=1234, dport=5678) /
             Raw(b"X" * 1000))
        valid_fragments = fragment_rfc791(p, 400)

        self.pg_enable_capture()
        self.src_if.add_stream(malformed_packets + valid_fragments)
        self.pg_start()

        self.dst_if.get_capture(1)

        self.assert_packet_counter_equal("ip4-full-reassembly-feature", 1)
        # TODO remove above, uncomment below once clearing of counters
        # is supported
        # self.assert_packet_counter_equal(
        #     "/err/ip4-full-reassembly-feature/malformed packets", 1)

    def test_random(self):
        """ random order reassembly """

        fragments = list(self.fragments_200)
        shuffle(fragments)

        self.pg_enable_capture()
        self.src_if.add_stream(fragments)
        self.pg_start()

        packets = self.dst_if.get_capture(len(self.packet_infos))
        self.verify_capture(packets)
        self.src_if.assert_nothing_captured()

        # run it all again to verify correctness
        self.pg_enable_capture()
        self.src_if.add_stream(fragments)
        self.pg_start()

        packets = self.dst_if.get_capture(len(self.packet_infos))
        self.verify_capture(packets)
        self.src_if.assert_nothing_captured()

    def test_duplicates(self):
        """ duplicate fragments """

        fragments = [
            x for (_, frags, _, _) in self.pkt_infos
            for x in frags
            for _ in range(0, min(2, len(frags)))
        ]

        self.pg_enable_capture()
        self.src_if.add_stream(fragments)
        self.pg_start()

        packets = self.dst_if.get_capture(len(self.pkt_infos))
        self.verify_capture(packets)
        self.src_if.assert_nothing_captured()

    def test_overlap1(self):
        """ overlapping fragments case #1 """

        fragments = []
        for _, _, frags_300, frags_200 in self.pkt_infos:
            if len(frags_300) == 1:
                fragments.extend(frags_300)
            else:
                for i, j in zip(frags_200, frags_300):
                    fragments.extend(i)
                    fragments.extend(j)

        self.pg_enable_capture()
        self.src_if.add_stream(fragments)
        self.pg_start()

        packets = self.dst_if.get_capture(len(self.pkt_infos))
        self.verify_capture(packets)
        self.src_if.assert_nothing_captured()

        # run it all to verify correctness
        self.pg_enable_capture()
        self.src_if.add_stream(fragments)
        self.pg_start()

        packets = self.dst_if.get_capture(len(self.pkt_infos))
        self.verify_capture(packets)
        self.src_if.assert_nothing_captured()

    def test_overlap2(self):
        """ overlapping fragments case #2 """

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

        self.pg_enable_capture()
        self.src_if.add_stream(fragments)
        self.pg_start()

        packets = self.dst_if.get_capture(len(self.pkt_infos))
        self.verify_capture(packets)
        self.src_if.assert_nothing_captured()

        # run it all to verify correctness
        self.pg_enable_capture()
        self.src_if.add_stream(fragments)
        self.pg_start()

        packets = self.dst_if.get_capture(len(self.pkt_infos))
        self.verify_capture(packets)
        self.src_if.assert_nothing_captured()

    def test_timeout_inline(self):
        """ timeout (inline) """

        dropped_packet_indexes = set(
            index for (index, frags, _, _) in self.pkt_infos if len(frags) > 1
        )

        self.vapi.ip_reassembly_set(timeout_ms=0, max_reassemblies=1000,
                                    max_reassembly_length=3,
                                    expire_walk_interval_ms=10000)

        self.pg_enable_capture()
        self.src_if.add_stream(self.fragments_400)
        self.pg_start()

        packets = self.dst_if.get_capture(
            len(self.pkt_infos) - len(dropped_packet_indexes))
        self.verify_capture(packets, dropped_packet_indexes)
        self.src_if.assert_nothing_captured()

    def test_timeout_cleanup(self):
        """ timeout (cleanup) """

        # whole packets + fragmented packets sans last fragment
        fragments = [
            x for (_, frags_400, _, _) in self.pkt_infos
            for x in frags_400[:-1 if len(frags_400) > 1 else None]
        ]

        # last fragments for fragmented packets
        fragments2 = [frags_400[-1]
                      for (_, frags_400, _, _) in self.pkt_infos
                      if len(frags_400) > 1]

        dropped_packet_indexes = set(
            index for (index, frags_400, _, _) in self.pkt_infos
            if len(frags_400) > 1)

        self.vapi.ip_reassembly_set(timeout_ms=100, max_reassemblies=1000,
                                    max_reassembly_length=1000,
                                    expire_walk_interval_ms=50)

        self.pg_enable_capture()
        self.src_if.add_stream(fragments)
        self.pg_start()

        self.virtual_sleep(.25, "wait before sending rest of fragments")

        self.src_if.add_stream(fragments2)
        self.pg_start()

        packets = self.dst_if.get_capture(
            len(self.pkt_infos) - len(dropped_packet_indexes))
        self.verify_capture(packets, dropped_packet_indexes)
        self.src_if.assert_nothing_captured()

    def test_disabled(self):
        """ reassembly disabled """

        dropped_packet_indexes = set(
            index for (index, frags_400, _, _) in self.pkt_infos
            if len(frags_400) > 1)

        self.vapi.ip_reassembly_set(timeout_ms=1000, max_reassemblies=0,
                                    max_reassembly_length=3,
                                    expire_walk_interval_ms=10000)

        self.pg_enable_capture()
        self.src_if.add_stream(self.fragments_400)
        self.pg_start()

        packets = self.dst_if.get_capture(
            len(self.pkt_infos) - len(dropped_packet_indexes))
        self.verify_capture(packets, dropped_packet_indexes)
        self.src_if.assert_nothing_captured()

    def test_forus_enable_disable(self):
        """ forus reassembly enabled/disable """
        self.vapi.ip_reassembly_enable_disable(
            sw_if_index=self.src_if.sw_if_index, enable_ip4=False)
        self.vapi.ip_forus_reass_enable_disable(enable_ip4=True)
        p = (Ether(src=self.src_if.remote_mac, dst=self.src_if.local_mac) /
             IP(src=self.src_if.remote_ip4, dst=self.src_if.local_ip4) /
             ICMP(id=1234, type='echo-request') /
             Raw('x' * 1000))
        frags = fragment_rfc791(p, 400)
        r = self.send_and_expect(self.src_if, frags, self.src_if,
                                 n_rx=1)[0]
        self.assertEqual(1234, r[ICMP].id)
        self.assertEqual(icmptypes[r[ICMP].type], 'echo-reply')
        self.vapi.ip_forus_reass_enable_disable()

        self.send_and_assert_no_replies(self.src_if, frags)
        self.vapi.ip_forus_reass_enable_disable(enable_ip4=True)


class TestIPv4SVReassembly(VppTestCase):
    """ IPv4 Shallow Virtual Reassembly """

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
        """ Test setup - force timeout on existing reassemblies """
        super().setUp()
        self.vapi.ip_reassembly_enable_disable(
            sw_if_index=self.src_if.sw_if_index, enable_ip4=True,
            type=VppEnum.vl_api_ip_reass_type_t.IP_REASS_TYPE_SHALLOW_VIRTUAL)
        self.vapi.ip_reassembly_set(
            timeout_ms=0, max_reassemblies=1000,
            max_reassembly_length=1000,
            type=VppEnum.vl_api_ip_reass_type_t.IP_REASS_TYPE_SHALLOW_VIRTUAL,
            expire_walk_interval_ms=10)
        self.virtual_sleep(.25)
        self.vapi.ip_reassembly_set(
            timeout_ms=1000000, max_reassemblies=1000,
            max_reassembly_length=1000,
            type=VppEnum.vl_api_ip_reass_type_t.IP_REASS_TYPE_SHALLOW_VIRTUAL,
            expire_walk_interval_ms=10000)

    def tearDown(self):
        super().tearDown()
        self.logger.debug(self.vapi.ppcli("show ip4-sv-reassembly details"))
        self.logger.debug(self.vapi.ppcli("show buffers"))

    def test_basic(self):
        """ basic reassembly """
        payload_len = 1000
        payload = ""
        counter = 0
        while len(payload) < payload_len:
            payload += "%u " % counter
            counter += 1

        p = (Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac) /
             IP(id=1, src=self.src_if.remote_ip4,
                dst=self.dst_if.remote_ip4) /
             UDP(sport=1234, dport=5678) /
             Raw(payload))
        fragments = fragment_rfc791(p, payload_len/4)

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
        """ verify clear trace works mid-reassembly """
        payload_len = 1000
        payload = ""
        counter = 0
        while len(payload) < payload_len:
            payload += "%u " % counter
            counter += 1

        p = (Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac) /
             IP(id=1, src=self.src_if.remote_ip4,
                dst=self.dst_if.remote_ip4) /
             UDP(sport=1234, dport=5678) /
             Raw(payload))
        fragments = fragment_rfc791(p, payload_len/4)

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
        """ reassembly timeout """
        payload_len = 1000
        payload = ""
        counter = 0
        while len(payload) < payload_len:
            payload += "%u " % counter
            counter += 1

        p = (Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac) /
             IP(id=1, src=self.src_if.remote_ip4,
                dst=self.dst_if.remote_ip4) /
             UDP(sport=1234, dport=5678) /
             Raw(payload))
        fragments = fragment_rfc791(p, payload_len/4)

        self.vapi.ip_reassembly_set(
            timeout_ms=100, max_reassemblies=1000,
            max_reassembly_length=1000,
            expire_walk_interval_ms=50,
            type=VppEnum.vl_api_ip_reass_type_t.IP_REASS_TYPE_SHALLOW_VIRTUAL)

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
        self.virtual_sleep(.25, "wait before sending rest of fragments")

        # send rest of fragments - shouldn't be forwarded
        self.pg_enable_capture()
        self.src_if.add_stream(fragments[2:])
        self.pg_start()
        self.dst_if.assert_nothing_captured()

    def test_lru(self):
        """ reassembly reuses LRU element """

        self.vapi.ip_reassembly_set(
            timeout_ms=1000000, max_reassemblies=1,
            max_reassembly_length=1000,
            type=VppEnum.vl_api_ip_reass_type_t.IP_REASS_TYPE_SHALLOW_VIRTUAL,
            expire_walk_interval_ms=10000)

        payload_len = 1000
        payload = ""
        counter = 0
        while len(payload) < payload_len:
            payload += "%u " % counter
            counter += 1

        packet_count = 10

        fragments = [f
                     for i in range(packet_count)
                     for p in (Ether(dst=self.src_if.local_mac,
                                     src=self.src_if.remote_mac) /
                               IP(id=i, src=self.src_if.remote_ip4,
                                   dst=self.dst_if.remote_ip4) /
                               UDP(sport=1234, dport=5678) /
                               Raw(payload))
                     for f in fragment_rfc791(p, payload_len/4)]

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
            for c in range(t['count']):
                stream.append(
                    (Ether(dst=self.src_if.local_mac,
                           src=self.src_if.remote_mac) /
                     IP(id=self.counter,
                        flags=t['flags'],
                        src=self.src_if.remote_ip4,
                        dst=self.dst_if.remote_ip4) /
                     UDP(sport=1234, dport=5678) /
                     Raw("abcdef")))
                self.counter = self.counter + 1

        self.pg_enable_capture()
        self.src_if.add_stream(stream)
        self.pg_start()
        self.logger.debug(self.vapi.ppcli("show ip4-sv-reassembly details"))
        self.logger.debug(self.vapi.ppcli("show buffers"))
        self.logger.debug(self.vapi.ppcli("show trace"))
        self.dst_if.get_capture(len(stream))

    def test_mixed(self):
        """ mixed traffic correctly passes through SVR """
        self.counter = 1

        self.send_mixed_and_verify_capture([{'count': 1, 'flags': ''}])
        self.send_mixed_and_verify_capture([{'count': 2, 'flags': ''}])
        self.send_mixed_and_verify_capture([{'count': 3, 'flags': ''}])
        self.send_mixed_and_verify_capture([{'count': 8, 'flags': ''}])
        self.send_mixed_and_verify_capture([{'count': 257, 'flags': ''}])

        self.send_mixed_and_verify_capture([{'count': 1, 'flags': 'MF'}])
        self.send_mixed_and_verify_capture([{'count': 2, 'flags': 'MF'}])
        self.send_mixed_and_verify_capture([{'count': 3, 'flags': 'MF'}])
        self.send_mixed_and_verify_capture([{'count': 8, 'flags': 'MF'}])
        self.send_mixed_and_verify_capture([{'count': 257, 'flags': 'MF'}])

        self.send_mixed_and_verify_capture(
            [{'count': 1, 'flags': ''}, {'count': 1, 'flags': 'MF'}])
        self.send_mixed_and_verify_capture(
            [{'count': 2, 'flags': ''}, {'count': 2, 'flags': 'MF'}])
        self.send_mixed_and_verify_capture(
            [{'count': 3, 'flags': ''}, {'count': 3, 'flags': 'MF'}])
        self.send_mixed_and_verify_capture(
            [{'count': 8, 'flags': ''}, {'count': 8, 'flags': 'MF'}])
        self.send_mixed_and_verify_capture(
            [{'count': 129, 'flags': ''}, {'count': 129, 'flags': 'MF'}])

        self.send_mixed_and_verify_capture(
            [{'count': 1, 'flags': ''}, {'count': 1, 'flags': 'MF'},
             {'count': 1, 'flags': ''}, {'count': 1, 'flags': 'MF'}])
        self.send_mixed_and_verify_capture(
            [{'count': 2, 'flags': ''}, {'count': 2, 'flags': 'MF'},
             {'count': 2, 'flags': ''}, {'count': 2, 'flags': 'MF'}])
        self.send_mixed_and_verify_capture(
            [{'count': 3, 'flags': ''}, {'count': 3, 'flags': 'MF'},
             {'count': 3, 'flags': ''}, {'count': 3, 'flags': 'MF'}])
        self.send_mixed_and_verify_capture(
            [{'count': 8, 'flags': ''}, {'count': 8, 'flags': 'MF'},
             {'count': 8, 'flags': ''}, {'count': 8, 'flags': 'MF'}])
        self.send_mixed_and_verify_capture(
            [{'count': 65, 'flags': ''}, {'count': 65, 'flags': 'MF'},
             {'count': 65, 'flags': ''}, {'count': 65, 'flags': 'MF'}])


class TestIPv4MWReassembly(VppTestCase):
    """ IPv4 Reassembly (multiple workers) """
    vpp_worker_count = 3

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        cls.create_pg_interfaces(range(cls.vpp_worker_count+1))
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
        cls.packet_sizes = [64-len(Ether()), 512-len(Ether()),
                            1518-len(Ether()), 9018-len(Ether())]
        cls.padding = " abcdefghijklmn"
        cls.create_stream(cls.packet_sizes)
        cls.create_fragments()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()

    def setUp(self):
        """ Test setup - force timeout on existing reassemblies """
        super().setUp()
        for intf in self.send_ifs:
            self.vapi.ip_reassembly_enable_disable(
                sw_if_index=intf.sw_if_index, enable_ip4=True)
        self.vapi.ip_reassembly_set(timeout_ms=0, max_reassemblies=1000,
                                    max_reassembly_length=1000,
                                    expire_walk_interval_ms=10)
        self.virtual_sleep(.25)
        self.vapi.ip_reassembly_set(timeout_ms=1000000, max_reassemblies=1000,
                                    max_reassembly_length=1000,
                                    expire_walk_interval_ms=10000)

    def tearDown(self):
        for intf in self.send_ifs:
            self.vapi.ip_reassembly_enable_disable(
                sw_if_index=intf.sw_if_index, enable_ip4=False)
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
            p = (IP(id=info.index, src=cls.src_if.remote_ip4,
                    dst=cls.dst_if.remote_ip4) /
                 UDP(sport=1234, dport=5678) /
                 Raw(payload))
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
        cls.fragments_400 = [
            x for (_, frags) in cls.pkt_infos for x in frags]
        cls.logger.debug("Fragmented %s packets into %s 400-byte fragments, " %
                         (len(infos), len(cls.fragments_400)))

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
                    ppp("Packet received, but should be dropped:", packet))
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
            self.assertTrue(index in seen or index in dropped_packet_indexes,
                            "Packet with packet_index %d not received" % index)

    def send_packets(self, packets):
        for counter in range(self.vpp_worker_count):
            if 0 == len(packets[counter]):
                continue
            send_if = self.send_ifs[counter]
            send_if.add_stream(
                (Ether(dst=send_if.local_mac, src=send_if.remote_mac) / x
                 for x in packets[counter]),
                worker=counter)
        self.pg_start()

    def test_worker_conflict(self):
        """ 1st and FO=0 fragments on different workers """

        # in first wave we send fragments which don't start at offset 0
        # then we send fragments with offset 0 on a different thread
        # then the rest of packets on a random thread
        first_packets = [[] for n in range(self.vpp_worker_count)]
        second_packets = [[] for n in range(self.vpp_worker_count)]
        rest_of_packets = [[] for n in range(self.vpp_worker_count)]
        for (_, p) in self.pkt_infos:
            wi = randrange(self.vpp_worker_count)
            second_packets[wi].append(p[0])
            if len(p) <= 1:
                continue
            wi2 = wi
            while wi2 == wi:
                wi2 = randrange(self.vpp_worker_count)
            first_packets[wi2].append(p[1])
            wi3 = randrange(self.vpp_worker_count)
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


class TestIPv6Reassembly(VppTestCase):
    """ IPv6 Reassembly """

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
        """ Test setup - force timeout on existing reassemblies """
        super().setUp()
        self.vapi.ip_reassembly_enable_disable(
            sw_if_index=self.src_if.sw_if_index, enable_ip6=True)
        self.vapi.ip_reassembly_set(timeout_ms=0, max_reassemblies=1000,
                                    max_reassembly_length=1000,
                                    expire_walk_interval_ms=10, is_ip6=1)
        self.virtual_sleep(.25)
        self.vapi.ip_reassembly_set(timeout_ms=1000000, max_reassemblies=1000,
                                    max_reassembly_length=1000,
                                    expire_walk_interval_ms=10000, is_ip6=1)
        self.logger.debug(self.vapi.ppcli("show ip6-full-reassembly details"))
        self.logger.debug(self.vapi.ppcli("show buffers"))

    def tearDown(self):
        self.vapi.ip_reassembly_enable_disable(
            sw_if_index=self.src_if.sw_if_index, enable_ip6=False)
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
            p = (Ether(dst=cls.src_if.local_mac, src=cls.src_if.remote_mac) /
                 IPv6(src=cls.src_if.remote_ip6,
                      dst=cls.dst_if.remote_ip6) /
                 UDP(sport=1234, dport=5678) /
                 Raw(payload))
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
        cls.fragments_400 = [
            x for _, frags, _ in cls.pkt_infos for x in frags]
        cls.fragments_300 = [
            x for _, _, frags in cls.pkt_infos for x in frags]
        cls.logger.debug("Fragmented %s packets into %s 400-byte fragments, "
                         "and %s 300-byte fragments" %
                         (len(infos), len(cls.fragments_400),
                             len(cls.fragments_300)))

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
                    ppp("Packet received, but should be dropped:", packet))
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
            self.assertTrue(index in seen or index in dropped_packet_indexes,
                            "Packet with packet_index %d not received" % index)

    def test_reassembly(self):
        """ basic reassembly """

        self.pg_enable_capture()
        self.src_if.add_stream(self.fragments_400)
        self.pg_start()

        packets = self.dst_if.get_capture(len(self.pkt_infos))
        self.verify_capture(packets)
        self.src_if.assert_nothing_captured()

        # run it all again to verify correctness
        self.pg_enable_capture()
        self.src_if.add_stream(self.fragments_400)
        self.pg_start()

        packets = self.dst_if.get_capture(len(self.pkt_infos))
        self.verify_capture(packets)
        self.src_if.assert_nothing_captured()

    def test_buffer_boundary(self):
        """ fragment header crossing buffer boundary """

        p = (Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac) /
             IPv6(src=self.src_if.remote_ip6,
                  dst=self.src_if.local_ip6) /
             IPv6ExtHdrHopByHop(
                 options=[HBHOptUnknown(otype=0xff, optlen=0)] * 1000) /
             IPv6ExtHdrFragment(m=1) /
             UDP(sport=1234, dport=5678) /
             Raw())
        self.pg_enable_capture()
        self.src_if.add_stream([p])
        self.pg_start()
        self.src_if.assert_nothing_captured()
        self.dst_if.assert_nothing_captured()

    def test_verify_clear_trace_mid_reassembly(self):
        """ verify clear trace works mid-reassembly """

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
        """ reverse order reassembly """

        fragments = list(self.fragments_400)
        fragments.reverse()

        self.pg_enable_capture()
        self.src_if.add_stream(fragments)
        self.pg_start()

        packets = self.dst_if.get_capture(len(self.pkt_infos))
        self.verify_capture(packets)
        self.src_if.assert_nothing_captured()

        # run it all again to verify correctness
        self.pg_enable_capture()
        self.src_if.add_stream(fragments)
        self.pg_start()

        packets = self.dst_if.get_capture(len(self.pkt_infos))
        self.verify_capture(packets)
        self.src_if.assert_nothing_captured()

    def test_random(self):
        """ random order reassembly """

        fragments = list(self.fragments_400)
        shuffle(fragments)

        self.pg_enable_capture()
        self.src_if.add_stream(fragments)
        self.pg_start()

        packets = self.dst_if.get_capture(len(self.pkt_infos))
        self.verify_capture(packets)
        self.src_if.assert_nothing_captured()

        # run it all again to verify correctness
        self.pg_enable_capture()
        self.src_if.add_stream(fragments)
        self.pg_start()

        packets = self.dst_if.get_capture(len(self.pkt_infos))
        self.verify_capture(packets)
        self.src_if.assert_nothing_captured()

    def test_duplicates(self):
        """ duplicate fragments """

        fragments = [
            x for (_, frags, _) in self.pkt_infos
            for x in frags
            for _ in range(0, min(2, len(frags)))
        ]

        self.pg_enable_capture()
        self.src_if.add_stream(fragments)
        self.pg_start()

        packets = self.dst_if.get_capture(len(self.pkt_infos))
        self.verify_capture(packets)
        self.src_if.assert_nothing_captured()

    def test_long_fragment_chain(self):
        """ long fragment chain """

        error_cnt_str = \
            "/err/ip6-full-reassembly-feature/fragment chain too long (drop)"

        error_cnt = self.statistics.get_err_counter(error_cnt_str)

        self.vapi.ip_reassembly_set(timeout_ms=100, max_reassemblies=1000,
                                    max_reassembly_length=3,
                                    expire_walk_interval_ms=50, is_ip6=1)

        p = (Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac) /
             IPv6(src=self.src_if.remote_ip6,
                  dst=self.dst_if.remote_ip6) /
             UDP(sport=1234, dport=5678) /
             Raw(b"X" * 1000))
        frags = fragment_rfc8200(p, 1, 300) + fragment_rfc8200(p, 2, 500)

        self.pg_enable_capture()
        self.src_if.add_stream(frags)
        self.pg_start()

        self.dst_if.get_capture(1)
        self.assert_error_counter_equal(error_cnt_str, error_cnt + 1)

    def test_overlap1(self):
        """ overlapping fragments case #1 """

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

        self.pg_enable_capture()
        self.src_if.add_stream(fragments)
        self.pg_start()

        packets = self.dst_if.get_capture(
            len(self.pkt_infos) - len(dropped_packet_indexes))
        self.verify_capture(packets, dropped_packet_indexes)
        self.src_if.assert_nothing_captured()

    def test_overlap2(self):
        """ overlapping fragments case #2 """

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

        self.pg_enable_capture()
        self.src_if.add_stream(fragments)
        self.pg_start()

        packets = self.dst_if.get_capture(
            len(self.pkt_infos) - len(dropped_packet_indexes))
        self.verify_capture(packets, dropped_packet_indexes)
        self.src_if.assert_nothing_captured()

    def test_timeout_inline(self):
        """ timeout (inline) """

        dropped_packet_indexes = set(
            index for (index, frags, _) in self.pkt_infos if len(frags) > 1
        )

        self.vapi.ip_reassembly_set(timeout_ms=0, max_reassemblies=1000,
                                    max_reassembly_length=3,
                                    expire_walk_interval_ms=10000, is_ip6=1)

        self.pg_enable_capture()
        self.src_if.add_stream(self.fragments_400)
        self.pg_start()

        packets = self.dst_if.get_capture(
            len(self.pkt_infos) - len(dropped_packet_indexes))
        self.verify_capture(packets, dropped_packet_indexes)
        pkts = self.src_if.get_capture(
            expected_count=len(dropped_packet_indexes))
        for icmp in pkts:
            self.assertIn(ICMPv6TimeExceeded, icmp)
            self.assertIn(IPv6ExtHdrFragment, icmp)
            self.assertIn(icmp[IPv6ExtHdrFragment].id, dropped_packet_indexes)
            dropped_packet_indexes.remove(icmp[IPv6ExtHdrFragment].id)

    def test_timeout_cleanup(self):
        """ timeout (cleanup) """

        # whole packets + fragmented packets sans last fragment
        fragments = [
            x for (_, frags_400, _) in self.pkt_infos
            for x in frags_400[:-1 if len(frags_400) > 1 else None]
        ]

        # last fragments for fragmented packets
        fragments2 = [frags_400[-1]
                      for (_, frags_400, _) in self.pkt_infos
                      if len(frags_400) > 1]

        dropped_packet_indexes = set(
            index for (index, frags_400, _) in self.pkt_infos
            if len(frags_400) > 1)

        self.vapi.ip_reassembly_set(timeout_ms=100, max_reassemblies=1000,
                                    max_reassembly_length=1000,
                                    expire_walk_interval_ms=50)

        self.vapi.ip_reassembly_set(timeout_ms=100, max_reassemblies=1000,
                                    max_reassembly_length=1000,
                                    expire_walk_interval_ms=50, is_ip6=1)

        self.pg_enable_capture()
        self.src_if.add_stream(fragments)
        self.pg_start()

        self.virtual_sleep(.25, "wait before sending rest of fragments")

        self.src_if.add_stream(fragments2)
        self.pg_start()

        packets = self.dst_if.get_capture(
            len(self.pkt_infos) - len(dropped_packet_indexes))
        self.verify_capture(packets, dropped_packet_indexes)
        pkts = self.src_if.get_capture(
            expected_count=len(dropped_packet_indexes))
        for icmp in pkts:
            self.assertIn(ICMPv6TimeExceeded, icmp)
            self.assertIn(IPv6ExtHdrFragment, icmp)
            self.assertIn(icmp[IPv6ExtHdrFragment].id, dropped_packet_indexes)
            dropped_packet_indexes.remove(icmp[IPv6ExtHdrFragment].id)

    def test_disabled(self):
        """ reassembly disabled """

        dropped_packet_indexes = set(
            index for (index, frags_400, _) in self.pkt_infos
            if len(frags_400) > 1)

        self.vapi.ip_reassembly_set(timeout_ms=1000, max_reassemblies=0,
                                    max_reassembly_length=3,
                                    expire_walk_interval_ms=10000, is_ip6=1)

        self.pg_enable_capture()
        self.src_if.add_stream(self.fragments_400)
        self.pg_start()

        packets = self.dst_if.get_capture(
            len(self.pkt_infos) - len(dropped_packet_indexes))
        self.verify_capture(packets, dropped_packet_indexes)
        self.src_if.assert_nothing_captured()

    def test_missing_upper(self):
        """ missing upper layer """
        optdata = '\x00' * 100
        p = (Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac) /
             IPv6(src=self.src_if.remote_ip6,
                  dst=self.src_if.local_ip6) /
             IPv6ExtHdrFragment(m=1) /
             IPv6ExtHdrDestOpt(nh=17, options=PadN(optdata='\101' * 255) /
             PadN(optdata='\102'*255)))

        self.pg_enable_capture()
        self.src_if.add_stream([p])
        self.pg_start()
        pkts = self.src_if.get_capture(expected_count=1)
        icmp = pkts[0]
        self.assertIn(ICMPv6ParamProblem, icmp)
        self.assert_equal(icmp[ICMPv6ParamProblem].code, 3, "ICMP code")

    def test_truncated_fragment(self):
        """ truncated fragment """
        pkt = (Ether(src=self.pg0.local_mac, dst=self.pg0.remote_mac) /
               IPv6(src=self.pg0.remote_ip6, dst=self.pg0.local_ip6,
                    nh=44, plen=2) /
               IPv6ExtHdrFragment(nh=6))

        self.send_and_assert_no_replies(self.pg0, [pkt], self.pg0)

    def test_invalid_frag_size(self):
        """ fragment size not a multiple of 8 """
        p = (Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac) /
             IPv6(src=self.src_if.remote_ip6,
                  dst=self.src_if.local_ip6) /
             UDP(sport=1234, dport=5678) /
             Raw())
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
        """ total packet size > 65535 """
        p = (Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac) /
             IPv6(src=self.src_if.remote_ip6,
                  dst=self.src_if.local_ip6) /
             UDP(sport=1234, dport=5678) /
             Raw())
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

    def test_atomic_fragment(self):
        """ IPv6 atomic fragment """
        pkt = (Ether(src=self.pg0.local_mac, dst=self.pg0.remote_mac) /
               IPv6(src=self.pg0.remote_ip6, dst=self.pg0.local_ip6,
                    nh=44, plen=65535) /
               IPv6ExtHdrFragment(offset=8191, m=1, res1=0xFF, res2=0xFF,
                                  nh=255, id=0xffff)/('X'*1452))

        rx = self.send_and_expect(self.pg0, [pkt], self.pg0)
        self.assertIn(ICMPv6ParamProblem, rx[0])

    def test_truncated_fragment(self):
        """ IPv6 truncated fragment header """
        pkt = (Ether(src=self.pg0.local_mac, dst=self.pg0.remote_mac) /
               IPv6(src=self.pg0.remote_ip6, dst=self.pg0.local_ip6,
                    nh=44, plen=2) /
               IPv6ExtHdrFragment(nh=6))

        self.send_and_assert_no_replies(self.pg0, [pkt])

        pkt = (Ether(src=self.pg0.local_mac, dst=self.pg0.remote_mac) /
               IPv6(src=self.pg0.remote_ip6, dst=self.pg0.remote_ip6) /
               ICMPv6EchoRequest())
        rx = self.send_and_expect(self.pg0, [pkt], self.pg0)

    def test_one_fragment(self):
        """ whole packet in one fragment processed independently """
        pkt = (Ether(src=self.pg0.local_mac, dst=self.pg0.remote_mac) /
               IPv6(src=self.pg0.remote_ip6, dst=self.pg0.local_ip6) /
               ICMPv6EchoRequest()/Raw('X' * 1600))
        frags = fragment_rfc8200(pkt, 1, 400)

        # send a fragment with known id
        self.send_and_assert_no_replies(self.pg0, [frags[0]])

        # send an atomic fragment with same id - should be reassembled
        pkt = (Ether(src=self.pg0.local_mac, dst=self.pg0.remote_mac) /
               IPv6(src=self.pg0.remote_ip6, dst=self.pg0.local_ip6) /
               IPv6ExtHdrFragment(id=1)/ICMPv6EchoRequest())
        rx = self.send_and_expect(self.pg0, [pkt], self.pg0)
        self.assertNotIn(IPv6ExtHdrFragment, rx)

        # now finish the original reassembly, this should still be possible
        rx = self.send_and_expect(self.pg0, frags[1:], self.pg0, n_rx=1)
        self.assertNotIn(IPv6ExtHdrFragment, rx)

    def test_bunch_of_fragments(self):
        """ valid fragments followed by rogue fragments and atomic fragment"""
        pkt = (Ether(src=self.pg0.local_mac, dst=self.pg0.remote_mac) /
               IPv6(src=self.pg0.remote_ip6, dst=self.pg0.local_ip6) /
               ICMPv6EchoRequest()/Raw('X' * 1600))
        frags = fragment_rfc8200(pkt, 1, 400)
        self.send_and_expect(self.pg0, frags, self.pg0, n_rx=1)

        inc_frag = (Ether(src=self.pg0.local_mac, dst=self.pg0.remote_mac) /
                    IPv6(src=self.pg0.remote_ip6, dst=self.pg0.local_ip6) /
                    IPv6ExtHdrFragment(id=1, nh=58, offset=608)/Raw('X'*308))

        self.send_and_assert_no_replies(self.pg0, inc_frag*604)

        pkt = (Ether(src=self.pg0.local_mac, dst=self.pg0.remote_mac) /
               IPv6(src=self.pg0.remote_ip6, dst=self.pg0.local_ip6) /
               IPv6ExtHdrFragment(id=1)/ICMPv6EchoRequest())
        rx = self.send_and_expect(self.pg0, [pkt], self.pg0)
        self.assertNotIn(IPv6ExtHdrFragment, rx)

    def test_forus_enable_disable(self):
        """ forus reassembly enabled/disable """
        self.vapi.ip_reassembly_enable_disable(
            sw_if_index=self.src_if.sw_if_index, enable_ip6=False)
        self.vapi.ip_forus_reass_enable_disable(enable_ip6=True)
        pkt = (Ether(src=self.src_if.local_mac, dst=self.src_if.remote_mac) /
               IPv6(src=self.src_if.remote_ip6, dst=self.src_if.local_ip6) /
               ICMPv6EchoRequest(id=1234)/Raw('X' * 1600))
        frags = fragment_rfc8200(pkt, 1, 400)
        r = self.send_and_expect(self.src_if, frags, self.src_if,
                                 n_rx=1)[0]
        self.assertEqual(1234, r[ICMPv6EchoReply].id)
        self.vapi.ip_forus_reass_enable_disable()

        self.send_and_assert_no_replies(self.src_if, frags)
        self.vapi.ip_forus_reass_enable_disable(enable_ip6=True)


class TestIPv6MWReassembly(VppTestCase):
    """ IPv6 Reassembly (multiple workers) """
    vpp_worker_count = 3

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        cls.create_pg_interfaces(range(cls.vpp_worker_count+1))
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
        cls.packet_sizes = [64-len(Ether()), 512-len(Ether()),
                            1518-len(Ether()), 9018-len(Ether())]
        cls.padding = " abcdefghijklmn"
        cls.create_stream(cls.packet_sizes)
        cls.create_fragments()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()

    def setUp(self):
        """ Test setup - force timeout on existing reassemblies """
        super().setUp()
        for intf in self.send_ifs:
            self.vapi.ip_reassembly_enable_disable(
                sw_if_index=intf.sw_if_index, enable_ip6=True)
        self.vapi.ip_reassembly_set(timeout_ms=0, max_reassemblies=1000,
                                    max_reassembly_length=1000,
                                    expire_walk_interval_ms=10, is_ip6=1)
        self.virtual_sleep(.25)
        self.vapi.ip_reassembly_set(timeout_ms=1000000, max_reassemblies=1000,
                                    max_reassembly_length=1000,
                                    expire_walk_interval_ms=1000, is_ip6=1)

    def tearDown(self):
        for intf in self.send_ifs:
            self.vapi.ip_reassembly_enable_disable(
                sw_if_index=intf.sw_if_index, enable_ip6=False)
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
            p = (IPv6(src=cls.src_if.remote_ip6,
                      dst=cls.dst_if.remote_ip6) /
                 UDP(sport=1234, dport=5678) /
                 Raw(payload))
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
        cls.fragments_400 = [
            x for (_, frags) in cls.pkt_infos for x in frags]
        cls.logger.debug("Fragmented %s packets into %s 400-byte fragments, " %
                         (len(infos), len(cls.fragments_400)))

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
                    ppp("Packet received, but should be dropped:", packet))
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
            self.assertTrue(index in seen or index in dropped_packet_indexes,
                            "Packet with packet_index %d not received" % index)

    def send_packets(self, packets):
        for counter in range(self.vpp_worker_count):
            if 0 == len(packets[counter]):
                continue
            send_if = self.send_ifs[counter]
            send_if.add_stream(
                (Ether(dst=send_if.local_mac, src=send_if.remote_mac) / x
                 for x in packets[counter]),
                worker=counter)
        self.pg_start()

    def test_worker_conflict(self):
        """ 1st and FO=0 fragments on different workers """

        # in first wave we send fragments which don't start at offset 0
        # then we send fragments with offset 0 on a different thread
        # then the rest of packets on a random thread
        first_packets = [[] for n in range(self.vpp_worker_count)]
        second_packets = [[] for n in range(self.vpp_worker_count)]
        rest_of_packets = [[] for n in range(self.vpp_worker_count)]
        for (_, p) in self.pkt_infos:
            wi = randrange(self.vpp_worker_count)
            second_packets[wi].append(p[0])
            if len(p) <= 1:
                continue
            wi2 = wi
            while wi2 == wi:
                wi2 = randrange(self.vpp_worker_count)
            first_packets[wi2].append(p[1])
            wi3 = randrange(self.vpp_worker_count)
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


class TestIPv6SVReassembly(VppTestCase):
    """ IPv6 Shallow Virtual Reassembly """

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
        """ Test setup - force timeout on existing reassemblies """
        super().setUp()
        self.vapi.ip_reassembly_enable_disable(
            sw_if_index=self.src_if.sw_if_index, enable_ip6=True,
            type=VppEnum.vl_api_ip_reass_type_t.IP_REASS_TYPE_SHALLOW_VIRTUAL)
        self.vapi.ip_reassembly_set(
            timeout_ms=0, max_reassemblies=1000,
            max_reassembly_length=1000,
            type=VppEnum.vl_api_ip_reass_type_t.IP_REASS_TYPE_SHALLOW_VIRTUAL,
            expire_walk_interval_ms=10, is_ip6=1)
        self.virtual_sleep(.25)
        self.vapi.ip_reassembly_set(
            timeout_ms=1000000, max_reassemblies=1000,
            max_reassembly_length=1000,
            type=VppEnum.vl_api_ip_reass_type_t.IP_REASS_TYPE_SHALLOW_VIRTUAL,
            expire_walk_interval_ms=10000, is_ip6=1)

    def tearDown(self):
        super().tearDown()
        self.logger.debug(self.vapi.ppcli("show ip6-sv-reassembly details"))
        self.logger.debug(self.vapi.ppcli("show buffers"))

    def test_basic(self):
        """ basic reassembly """
        payload_len = 1000
        payload = ""
        counter = 0
        while len(payload) < payload_len:
            payload += "%u " % counter
            counter += 1

        p = (Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac) /
             IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6) /
             UDP(sport=1234, dport=5678) /
             Raw(payload))
        fragments = fragment_rfc8200(p, 1, payload_len/4)

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
        """ verify clear trace works mid-reassembly """
        payload_len = 1000
        payload = ""
        counter = 0
        while len(payload) < payload_len:
            payload += "%u " % counter
            counter += 1

        p = (Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac) /
             IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6) /
             UDP(sport=1234, dport=5678) /
             Raw(payload))
        fragments = fragment_rfc8200(p, 1, payload_len/4)

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
        """ reassembly timeout """
        payload_len = 1000
        payload = ""
        counter = 0
        while len(payload) < payload_len:
            payload += "%u " % counter
            counter += 1

        p = (Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac) /
             IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6) /
             UDP(sport=1234, dport=5678) /
             Raw(payload))
        fragments = fragment_rfc8200(p, 1, payload_len/4)

        self.vapi.ip_reassembly_set(
            timeout_ms=100, max_reassemblies=1000,
            max_reassembly_length=1000,
            expire_walk_interval_ms=50,
            is_ip6=1,
            type=VppEnum.vl_api_ip_reass_type_t.IP_REASS_TYPE_SHALLOW_VIRTUAL)

        # send fragments #2 and #1 - should be forwarded
        self.pg_enable_capture()
        self.src_if.add_stream(fragments[0:2])
        self.pg_start()
        self.logger.debug(self.vapi.ppcli("show ip4-sv-reassembly details"))
        self.logger.debug(self.vapi.ppcli("show buffers"))
        self.logger.debug(self.vapi.ppcli("show trace"))
        c = self.dst_if.get_capture(2)
        for sent, recvd in zip([fragments[1], fragments[0]], c):
            self.assertEqual(sent[IPv6].src, recvd[IPv6].src)
            self.assertEqual(sent[IPv6].dst, recvd[IPv6].dst)
            self.assertEqual(sent[Raw].payload, recvd[Raw].payload)

        # wait for cleanup
        self.virtual_sleep(.25, "wait before sending rest of fragments")

        # send rest of fragments - shouldn't be forwarded
        self.pg_enable_capture()
        self.src_if.add_stream(fragments[2:])
        self.pg_start()
        self.dst_if.assert_nothing_captured()

    def test_lru(self):
        """ reassembly reuses LRU element """

        self.vapi.ip_reassembly_set(
            timeout_ms=1000000, max_reassemblies=1,
            max_reassembly_length=1000,
            type=VppEnum.vl_api_ip_reass_type_t.IP_REASS_TYPE_SHALLOW_VIRTUAL,
            is_ip6=1, expire_walk_interval_ms=10000)

        payload_len = 1000
        payload = ""
        counter = 0
        while len(payload) < payload_len:
            payload += "%u " % counter
            counter += 1

        packet_count = 10

        fragments = [f
                     for i in range(packet_count)
                     for p in (Ether(dst=self.src_if.local_mac,
                                     src=self.src_if.remote_mac) /
                               IPv6(src=self.src_if.remote_ip6,
                                    dst=self.dst_if.remote_ip6) /
                               UDP(sport=1234, dport=5678) /
                               Raw(payload))
                     for f in fragment_rfc8200(p, i, payload_len/4)]

        self.pg_enable_capture()
        self.src_if.add_stream(fragments)
        self.pg_start()
        c = self.dst_if.get_capture(len(fragments))
        for sent, recvd in zip(fragments, c):
            self.assertEqual(sent[IPv6].src, recvd[IPv6].src)
            self.assertEqual(sent[IPv6].dst, recvd[IPv6].dst)
            self.assertEqual(sent[Raw].payload, recvd[Raw].payload)

    def test_one_fragment(self):
        """ whole packet in one fragment processed independently """
        pkt = (Ether(src=self.src_if.local_mac, dst=self.src_if.remote_mac) /
               IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6) /
               ICMPv6EchoRequest()/Raw('X' * 1600))
        frags = fragment_rfc8200(pkt, 1, 400)

        # send a fragment with known id
        self.send_and_expect(self.src_if, [frags[0]], self.dst_if)

        # send an atomic fragment with same id - should be reassembled
        pkt = (Ether(src=self.src_if.local_mac, dst=self.src_if.remote_mac) /
               IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6) /
               IPv6ExtHdrFragment(id=1)/ICMPv6EchoRequest())
        rx = self.send_and_expect(self.src_if, [pkt], self.dst_if)

        # now forward packets matching original reassembly, should still work
        rx = self.send_and_expect(self.src_if, frags[1:], self.dst_if)

    def test_bunch_of_fragments(self):
        """ valid fragments followed by rogue fragments and atomic fragment"""
        pkt = (Ether(src=self.src_if.local_mac, dst=self.src_if.remote_mac) /
               IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6) /
               ICMPv6EchoRequest()/Raw('X' * 1600))
        frags = fragment_rfc8200(pkt, 1, 400)
        rx = self.send_and_expect(self.src_if, frags, self.dst_if)

        rogue = (Ether(src=self.src_if.local_mac, dst=self.src_if.remote_mac) /
                 IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6) /
                 IPv6ExtHdrFragment(id=1, nh=58, offset=608)/Raw('X'*308))

        self.send_and_expect(self.src_if, rogue*604, self.dst_if)

        pkt = (Ether(src=self.src_if.local_mac, dst=self.src_if.remote_mac) /
               IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6) /
               IPv6ExtHdrFragment(id=1)/ICMPv6EchoRequest())
        rx = self.send_and_expect(self.src_if, [pkt], self.dst_if)

    def test_truncated_fragment(self):
        """ truncated fragment """
        pkt = (Ether(src=self.pg0.local_mac, dst=self.pg0.remote_mac) /
               IPv6(src=self.pg0.remote_ip6, dst=self.pg0.local_ip6,
                    nh=44, plen=2) /
               IPv6ExtHdrFragment(nh=6))

        self.send_and_assert_no_replies(self.pg0, [pkt], self.pg0)


class TestIPv4ReassemblyLocalNode(VppTestCase):
    """ IPv4 Reassembly for packets coming to ip4-local node """

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
        """ Test setup - force timeout on existing reassemblies """
        super().setUp()
        self.vapi.ip_reassembly_set(timeout_ms=0, max_reassemblies=1000,
                                    max_reassembly_length=1000,
                                    expire_walk_interval_ms=10)
        self.virtual_sleep(.25)
        self.vapi.ip_reassembly_set(timeout_ms=1000000, max_reassemblies=1000,
                                    max_reassembly_length=1000,
                                    expire_walk_interval_ms=10000)

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
            p = (Ether(dst=cls.src_dst_if.local_mac,
                       src=cls.src_dst_if.remote_mac) /
                 IP(id=info.index, src=cls.src_dst_if.remote_ip4,
                    dst=cls.src_dst_if.local_ip4) /
                 ICMP(type='echo-request', id=1234) /
                 Raw(payload))
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
        cls.logger.debug("Fragmented %s packets into %s 300-byte fragments" %
                         (len(infos), len(cls.fragments_300)))

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
            self.assertIn(index, seen,
                          "Packet with packet_index %d not received" % index)

    def test_reassembly(self):
        """ basic reassembly """

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
    """ Fragments in fragments reassembly """

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
        """ Test setup - force timeout on existing reassemblies """
        super().setUp()
        self.vapi.ip_reassembly_enable_disable(
            sw_if_index=self.src_if.sw_if_index, enable_ip4=True,
            enable_ip6=True)
        self.vapi.ip_reassembly_enable_disable(
            sw_if_index=self.dst_if.sw_if_index, enable_ip4=True,
            enable_ip6=True)
        self.vapi.ip_reassembly_set(timeout_ms=0, max_reassemblies=1000,
                                    max_reassembly_length=1000,
                                    expire_walk_interval_ms=10)
        self.vapi.ip_reassembly_set(timeout_ms=0, max_reassemblies=1000,
                                    max_reassembly_length=1000,
                                    expire_walk_interval_ms=10, is_ip6=1)
        self.virtual_sleep(.25)
        self.vapi.ip_reassembly_set(timeout_ms=1000000, max_reassemblies=1000,
                                    max_reassembly_length=1000,
                                    expire_walk_interval_ms=10000)
        self.vapi.ip_reassembly_set(timeout_ms=1000000, max_reassemblies=1000,
                                    max_reassembly_length=1000,
                                    expire_walk_interval_ms=10000, is_ip6=1)

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
                    ppp("Packet received, but should be dropped:", packet))
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
            self.assertTrue(index in seen or index in dropped_packet_indexes,
                            "Packet with packet_index %d not received" % index)

    def test_fif4(self):
        """ Fragments in fragments (4o4) """

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
            sw_if_index=self.gre4.sw_if_index, enable_ip4=True)

        self.route4 = VppIpRoute(self, self.tun_ip4, 32,
                                 [VppRoutePath(self.src_if.remote_ip4,
                                               self.src_if.sw_if_index)])
        self.route4.add_vpp_config()

        self.reset_packet_infos()
        for i in range(test_packet_count):
            info = self.create_packet_info(self.src_if, self.dst_if)
            payload = self.info_to_payload(info)
            # Ethernet header here is only for size calculation, thus it
            # doesn't matter how it's initialized. This is to ensure that
            # reassembled packet is not > 9000 bytes, so that it's not dropped
            p = (Ether() /
                 IP(id=i, src=self.src_if.remote_ip4,
                    dst=self.dst_if.remote_ip4) /
                 UDP(sport=1234, dport=5678) /
                 Raw(payload))
            size = self.packet_sizes[(i // 2) % len(self.packet_sizes)]
            self.extend_packet(p, size, self.padding)
            info.data = p[IP]  # use only IP part, without ethernet header

        fragments = [x for _, p in self._packet_infos.items()
                     for x in fragment_rfc791(p.data, 400)]

        encapped_fragments = \
            [Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac) /
             IP(src=self.tun_ip4, dst=self.src_if.local_ip4) /
                GRE() /
                p
                for p in fragments]

        fragmented_encapped_fragments = \
            [x for p in encapped_fragments
             for x in fragment_rfc791(p, 200)]

        self.src_if.add_stream(fragmented_encapped_fragments)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        self.src_if.assert_nothing_captured()
        packets = self.dst_if.get_capture(len(self._packet_infos))
        self.verify_capture(packets, IP)

        # TODO remove gre vpp config by hand until VppIpRoute gets fixed
        # so that it's query_vpp_config() works as it should
        self.gre4.remove_vpp_config()
        self.logger.debug(self.vapi.ppcli("show interface"))

    def test_fif6(self):
        """ Fragments in fragments (6o6) """
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
            sw_if_index=self.gre6.sw_if_index, enable_ip6=True)

        self.route6 = VppIpRoute(self, self.tun_ip6, 128,
                                 [VppRoutePath(
                                     self.src_if.remote_ip6,
                                     self.src_if.sw_if_index)])
        self.route6.add_vpp_config()

        self.reset_packet_infos()
        for i in range(test_packet_count):
            info = self.create_packet_info(self.src_if, self.dst_if)
            payload = self.info_to_payload(info)
            # Ethernet header here is only for size calculation, thus it
            # doesn't matter how it's initialized. This is to ensure that
            # reassembled packet is not > 9000 bytes, so that it's not dropped
            p = (Ether() /
                 IPv6(src=self.src_if.remote_ip6, dst=self.dst_if.remote_ip6) /
                 UDP(sport=1234, dport=5678) /
                 Raw(payload))
            size = self.packet_sizes[(i // 2) % len(self.packet_sizes)]
            self.extend_packet(p, size, self.padding)
            info.data = p[IPv6]  # use only IPv6 part, without ethernet header

        fragments = [x for _, i in self._packet_infos.items()
                     for x in fragment_rfc8200(
                         i.data, i.index, 400)]

        encapped_fragments = \
            [Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac) /
             IPv6(src=self.tun_ip6, dst=self.src_if.local_ip6) /
                GRE() /
                p
                for p in fragments]

        fragmented_encapped_fragments = \
            [x for p in encapped_fragments for x in (
                fragment_rfc8200(
                    p,
                    2 * len(self._packet_infos) + p[IPv6ExtHdrFragment].id,
                    200)
                if IPv6ExtHdrFragment in p else [p]
            )
            ]

        self.src_if.add_stream(fragmented_encapped_fragments)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        self.src_if.assert_nothing_captured()
        packets = self.dst_if.get_capture(len(self._packet_infos))
        self.verify_capture(packets, IPv6)

        # TODO remove gre vpp config by hand until VppIpRoute gets fixed
        # so that it's query_vpp_config() works as it should
        self.gre6.remove_vpp_config()


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
