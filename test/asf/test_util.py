#!/usr/bin/env python3
"""Test framework utility functions tests"""

import unittest
from struct import pack
from asfframework import VppTestRunner, CPUInterface
from framework import VppTestCase
from scapy.contrib.wireguard import Wireguard
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.layers.vxlan import VXLAN
from scapy.packet import Raw
from vpp_papi import mac_pton, mac_ntop


class TestUtil(CPUInterface, unittest.TestCase):
    """Test framework utility tests"""

    @classmethod
    def is_tagged_run_solo(cls):
        """if the test case class is timing-sensitive - return true"""
        return False

    @classmethod
    def has_tag(cls, tag):
        """if the test case has a given tag - return true"""
        try:
            return tag in cls.test_tags
        except AttributeError:
            pass
        return False

    @classmethod
    def get_cores_required(cls):
        return 0

    def test_mac_to_binary(self):
        """MAC to binary and back"""
        mac = "aa:bb:cc:dd:ee:ff"
        b = mac_pton(mac)
        mac2 = mac_ntop(b)
        self.assertEqual(type(mac), type(mac2))
        self.assertEqual(mac2, mac)

    def assert_packet_info(self, packet, index=4):
        info = VppTestCase.udp_packet_to_info(packet)
        self.assertEqual(
            (info.index, info.src, info.dst, info.ip, info.proto), (index, 1, 2, 4, 17)
        )

    def test_udp_packet_info(self):
        """Decode packet info from constructed and captured IPv4/IPv6 packets"""
        for ip in (IP(), IPv6()):
            with self.subTest(ip=type(ip).__name__):
                packet = (
                    Ether()
                    / ip
                    / UDP(sport=12345, dport=5678)
                    / Raw(pack("iiiih", 4, 1, 2, 4, 17))
                )
                self.assert_packet_info(packet)
                self.assert_packet_info(Ether(bytes(packet)))

    def test_udp_packet_info_wireguard(self):
        """UDP dissection must not consume packet info bytes"""
        for ip in (IP(), IPv6()):
            for sport, dport in ((51820, 5678), (12345, 51820)):
                for index in (0, 4):
                    with self.subTest(
                        ip=type(ip).__name__, sport=sport, dport=dport, index=index
                    ):
                        packet = Ether(
                            bytes(
                                Ether()
                                / ip
                                / UDP(sport=sport, dport=dport)
                                / Raw(pack("iiiih", index, 1, 2, 4, 17) + bytes(64))
                            )
                        )
                        self.assertIsInstance(packet[UDP].payload, Wireguard)
                        self.assertEqual(bool(packet.haslayer(Raw)), index == 0)
                        self.assert_packet_info(packet, index)

    def test_udp_packet_info_encapsulated(self):
        """Decode the explicitly selected inner packet of a UDP tunnel"""
        for ip in (IP(), IPv6()):
            with self.subTest(ip=type(ip).__name__):
                inner = (
                    Ether()
                    / ip
                    / UDP(sport=51820, dport=5678)
                    / Raw(pack("iiiih", 4, 1, 2, 4, 17) + bytes(64))
                )
                packet = Ether(
                    bytes(
                        Ether()
                        / IP()
                        / UDP(sport=12345, dport=4789)
                        / VXLAN(vni=10)
                        / inner
                    )
                )
                self.assert_packet_info(packet[VXLAN].payload)
                self.assert_packet_info(packet.getlayer(UDP, 2))

    def test_udp_packet_info_short(self):
        """Reject a packet info record shorter than 18 bytes"""
        for size in (0, 1, 17):
            with self.subTest(size=size):
                packet = Ether(
                    bytes(
                        Ether() / IP() / UDP(sport=12345, dport=5678) / Raw(bytes(size))
                    )
                )
                with self.assertRaisesRegex(ValueError, "Short packet info"):
                    VppTestCase.udp_packet_to_info(packet)

    def test_udp_packet_info_truncated(self):
        """Capture truncation must not produce a partial packet info record"""
        packet = (
            Ether()
            / IP()
            / UDP(sport=51820, dport=5678)
            / Raw(pack("iiiih", 4, 1, 2, 4, 17))
        )
        packet = Ether(bytes(packet)[:-1])
        with self.assertRaisesRegex(ValueError, "Short packet info"):
            VppTestCase.udp_packet_to_info(packet)

    def test_udp_packet_info_padding(self):
        """Ethernet padding must not complete a short UDP payload"""
        packet = Ether() / IP() / UDP(sport=12345, dport=5678) / Raw(bytes(17))
        packet = Ether(bytes(packet) + bytes(32))
        with self.assertRaisesRegex(ValueError, "Short packet info"):
            VppTestCase.udp_packet_to_info(packet)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
