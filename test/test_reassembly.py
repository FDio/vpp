#!/usr/bin/env python

import six
import unittest
from random import shuffle

from framework import VppTestCase, VppTestRunner, is_skip_aarch64_set,\
    is_platform_aarch64
from vpp_capture import CaptureInvalidPacketError
from scapy.packet import Raw
from scapy.layers.l2 import Ether, GRE
from scapy.layers.inet import IP, UDP, ICMP
from util import ppp, fragment_rfc791, fragment_rfc8200
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment, ICMPv6ParamProblem,\
    ICMPv6TimeExceeded
from vpp_gre_interface import VppGreInterface, VppGre6Interface
from vpp_ip import DpoProto
from vpp_ip_route import VppIpRoute, VppRoutePath

# 35 is enough to have >257 400-byte fragments
test_packet_count = 35


class TestIPv4Reassembly(VppTestCase):
    """ IPv4 Reassembly """

    @classmethod
    def setUpClass(cls):
        super(TestIPv4Reassembly, cls).setUpClass()

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

    def setUp(self):
        """ Test setup - force timeout on existing reassemblies """
        super(TestIPv4Reassembly, self).setUp()
        self.vapi.ip_reassembly_enable_disable(
            sw_if_index=self.src_if.sw_if_index, enable_ip4=True)
        self.vapi.ip_reassembly_set(timeout_ms=0, max_reassemblies=1000,
                                    expire_walk_interval_ms=10)
        self.sleep(.25)
        self.vapi.ip_reassembly_set(timeout_ms=1000000, max_reassemblies=1000,
                                    expire_walk_interval_ms=10000)

    def tearDown(self):
        super(TestIPv4Reassembly, self).tearDown()
        self.logger.debug(self.vapi.ppcli("show ip4-reassembly details"))

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
        for index, info in six.iteritems(infos):
            p = info.data
            # cls.logger.debug(ppp("Packet:", p.__class__(str(p))))
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
                payload_info = self.payload_to_info(str(packet[Raw]))
                packet_index = payload_info.index
                self.assertTrue(
                    packet_index not in dropped_packet_indexes,
                    ppp("Packet received, but should be dropped:", packet))
                if packet_index in seen:
                    raise (ppp("Duplicate packet received", packet))
                seen.add(packet_index)
                self.assertEqual(payload_info.dst, self.src_if.sw_if_index)
                info = self._packet_infos[packet_index]
                self.assertTrue(info is not None)
                self.assertEqual(packet_index, info.index)
                saved_packet = info.data
                self.assertEqual(ip.src, saved_packet[IP].src)
                self.assertEqual(ip.dst, saved_packet[IP].dst)
                self.assertEqual(udp.payload, saved_packet[UDP].payload)
            except (IndexError, AssertionError):
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

    def test_5737(self):
        """ fragment length + ip header size > 65535 """
        self.vapi.cli("clear errors")
        raw = ('E\x00\x00\x88,\xf8\x1f\xfe@\x01\x98\x00\xc0\xa8\n-\xc0\xa8\n'
               '\x01\x08\x00\xf0J\xed\xcb\xf1\xf5Test-group: IPv4.IPv4.ipv4-'
               'message.Ethernet-Payload.IPv4-Packet.IPv4-Header.Fragment-Of'
               'fset; Test-case: 5737')

        malformed_packet = (Ether(dst=self.src_if.local_mac,
                                  src=self.src_if.remote_mac) /
                            IP(raw))
        p = (Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac) /
             IP(id=1000, src=self.src_if.remote_ip4,
                dst=self.dst_if.remote_ip4) /
             UDP(sport=1234, dport=5678) /
             Raw("X" * 1000))
        valid_fragments = fragment_rfc791(p, 400)

        self.pg_enable_capture()
        self.src_if.add_stream([malformed_packet] + valid_fragments)
        self.pg_start()

        self.dst_if.get_capture(1)
        self.assert_packet_counter_equal("ip4-reassembly-feature", 1)
        # TODO remove above, uncomment below once clearing of counters
        # is supported
        # self.assert_packet_counter_equal(
        #     "/err/ip4-reassembly-feature/malformed packets", 1)

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
                              Raw(load='\x08')),
                             ]

        p = (Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac) /
             IP(id=1000, src=self.src_if.remote_ip4,
                dst=self.dst_if.remote_ip4) /
             UDP(sport=1234, dport=5678) /
             Raw("X" * 1000))
        valid_fragments = fragment_rfc791(p, 400)

        self.pg_enable_capture()
        self.src_if.add_stream(malformed_packets + valid_fragments)
        self.pg_start()

        self.dst_if.get_capture(1)

        self.assert_packet_counter_equal("ip4-reassembly-feature", 1)
        # TODO remove above, uncomment below once clearing of counters
        # is supported
        # self.assert_packet_counter_equal(
        #     "/err/ip4-reassembly-feature/malformed packets", 1)

    @unittest.skipIf(is_skip_aarch64_set and is_platform_aarch64,
                     "test doesn't work on aarch64")
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
                for i, j in zipped[:-1]:
                    fragments.extend(i)
                    fragments.extend(j)
                fragments.append(zipped[-1][0])

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
                                    expire_walk_interval_ms=50)

        self.pg_enable_capture()
        self.src_if.add_stream(fragments)
        self.pg_start()

        self.sleep(.25, "wait before sending rest of fragments")

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
                                    expire_walk_interval_ms=10000)

        self.pg_enable_capture()
        self.src_if.add_stream(self.fragments_400)
        self.pg_start()

        packets = self.dst_if.get_capture(
            len(self.pkt_infos) - len(dropped_packet_indexes))
        self.verify_capture(packets, dropped_packet_indexes)
        self.src_if.assert_nothing_captured()


class TestIPv6Reassembly(VppTestCase):
    """ IPv6 Reassembly """

    @classmethod
    def setUpClass(cls):
        super(TestIPv6Reassembly, cls).setUpClass()

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

    def setUp(self):
        """ Test setup - force timeout on existing reassemblies """
        super(TestIPv6Reassembly, self).setUp()
        self.vapi.ip_reassembly_enable_disable(
            sw_if_index=self.src_if.sw_if_index, enable_ip6=True)
        self.vapi.ip_reassembly_set(timeout_ms=0, max_reassemblies=1000,
                                    expire_walk_interval_ms=10, is_ip6=1)
        self.sleep(.25)
        self.vapi.ip_reassembly_set(timeout_ms=1000000, max_reassemblies=1000,
                                    expire_walk_interval_ms=10000, is_ip6=1)
        self.logger.debug(self.vapi.ppcli("show ip6-reassembly details"))

    def tearDown(self):
        super(TestIPv6Reassembly, self).tearDown()
        self.logger.debug(self.vapi.ppcli("show ip6-reassembly details"))

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
        for index, info in six.iteritems(infos):
            p = info.data
            # cls.logger.debug(ppp("Packet:", p.__class__(str(p))))
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
                payload_info = self.payload_to_info(str(packet[Raw]))
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
                for i, j in zipped[:-1]:
                    fragments.extend(i)
                    fragments.extend(j)
                fragments.append(zipped[-1][0])

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
                                    expire_walk_interval_ms=50)

        self.vapi.ip_reassembly_set(timeout_ms=100, max_reassemblies=1000,
                                    expire_walk_interval_ms=50, is_ip6=1)

        self.pg_enable_capture()
        self.src_if.add_stream(fragments)
        self.pg_start()

        self.sleep(.25, "wait before sending rest of fragments")

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
        p = (Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac) /
             IPv6(src=self.src_if.remote_ip6,
                  dst=self.src_if.local_ip6) /
             UDP(sport=1234, dport=5678) /
             Raw())
        self.extend_packet(p, 1000, self.padding)
        fragments = fragment_rfc8200(p, 1, 500)
        bad_fragment = p.__class__(str(fragments[1]))
        bad_fragment[IPv6ExtHdrFragment].nh = 59
        bad_fragment[IPv6ExtHdrFragment].offset = 0
        self.pg_enable_capture()
        self.src_if.add_stream([bad_fragment])
        self.pg_start()
        pkts = self.src_if.get_capture(expected_count=1)
        icmp = pkts[0]
        self.assertIn(ICMPv6ParamProblem, icmp)
        self.assert_equal(icmp[ICMPv6ParamProblem].code, 3, "ICMP code")

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


class TestIPv4ReassemblyLocalNode(VppTestCase):
    """ IPv4 Reassembly for packets coming to ip4-local node """

    @classmethod
    def setUpClass(cls):
        super(TestIPv4ReassemblyLocalNode, cls).setUpClass()

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

    def setUp(self):
        """ Test setup - force timeout on existing reassemblies """
        super(TestIPv4ReassemblyLocalNode, self).setUp()
        self.vapi.ip_reassembly_set(timeout_ms=0, max_reassemblies=1000,
                                    expire_walk_interval_ms=10)
        self.sleep(.25)
        self.vapi.ip_reassembly_set(timeout_ms=1000000, max_reassemblies=1000,
                                    expire_walk_interval_ms=10000)

    def tearDown(self):
        super(TestIPv4ReassemblyLocalNode, self).tearDown()
        self.logger.debug(self.vapi.ppcli("show ip4-reassembly details"))

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
        for index, info in six.iteritems(infos):
            p = info.data
            # cls.logger.debug(ppp("Packet:", p.__class__(str(p))))
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
                payload_info = self.payload_to_info(str(packet[Raw]))
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
        super(TestFIFReassembly, cls).setUpClass()

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

    def setUp(self):
        """ Test setup - force timeout on existing reassemblies """
        super(TestFIFReassembly, self).setUp()
        self.vapi.ip_reassembly_enable_disable(
            sw_if_index=self.src_if.sw_if_index, enable_ip4=True,
            enable_ip6=True)
        self.vapi.ip_reassembly_enable_disable(
            sw_if_index=self.dst_if.sw_if_index, enable_ip4=True,
            enable_ip6=True)
        self.vapi.ip_reassembly_set(timeout_ms=0, max_reassemblies=1000,
                                    expire_walk_interval_ms=10)
        self.vapi.ip_reassembly_set(timeout_ms=0, max_reassemblies=1000,
                                    expire_walk_interval_ms=10, is_ip6=1)
        self.sleep(.25)
        self.vapi.ip_reassembly_set(timeout_ms=1000000, max_reassemblies=1000,
                                    expire_walk_interval_ms=10000)
        self.vapi.ip_reassembly_set(timeout_ms=1000000, max_reassemblies=1000,
                                    expire_walk_interval_ms=10000, is_ip6=1)

    def tearDown(self):
        self.logger.debug(self.vapi.ppcli("show ip4-reassembly details"))
        self.logger.debug(self.vapi.ppcli("show ip6-reassembly details"))
        super(TestFIFReassembly, self).tearDown()

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
                payload_info = self.payload_to_info(str(packet[Raw]))
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

        fragments = [x for _, p in six.iteritems(self._packet_infos)
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

        self.gre6 = VppGre6Interface(self, self.src_if.local_ip6, self.tun_ip6)
        self.gre6.add_vpp_config()
        self.gre6.admin_up()
        self.gre6.config_ip6()

        self.vapi.ip_reassembly_enable_disable(
            sw_if_index=self.gre6.sw_if_index, enable_ip6=True)

        self.route6 = VppIpRoute(self, self.tun_ip6, 128,
                                 [VppRoutePath(self.src_if.remote_ip6,
                                               self.src_if.sw_if_index,
                                               proto=DpoProto.DPO_PROTO_IP6)],
                                 is_ip6=1)
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

        fragments = [x for _, i in six.iteritems(self._packet_infos)
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
