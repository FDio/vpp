#!/usr/bin/env python3

import ipaddress
import random
import socket
import struct
import unittest
from io import BytesIO
from time import sleep

import scapy.compat
from framework import VppTestCase, VppTestRunner, running_extended_tests
from ipfix import IPFIX, Set, Template, Data, IPFIXDecoder
from scapy.all import bind_layers, Packet, ByteEnumField, ShortField, \
    IPField, IntField, LongField, XByteField, FlagsField, FieldLenField, \
    PacketListField
from scapy.data import IP_PROTOS
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet import IPerror, TCPerror, UDPerror, ICMPerror
from scapy.layers.inet6 import ICMPv6DestUnreach, IPerror6, IPv6ExtHdrFragment
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply, \
    ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, fragment6
from scapy.layers.l2 import Ether, ARP, GRE
from scapy.packet import Raw
from syslog_rfc5424_parser import SyslogMessage, ParseError
from syslog_rfc5424_parser.constants import SyslogSeverity
from vpp_pom.util import ip4_range
from vpp_pom.util import ppc, ppp
from vpp_pom.plugins.vpp_acl import AclRule, VppAcl, VppAclInterface
from vpp_pom.vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_pom.vpp_neighbor import VppNeighbor
from vpp_papi import VppEnum


class MethodHolder(VppTestCase):
    """ NAT create capture and verify method holder """
    @property
    def config_flags(self):
        return VppEnum.vl_api_nat_config_flags_t


class TestNAT66(MethodHolder):
    """ NAT66 Test Cases """

    @classmethod
    def setUpClass(cls):
        super(TestNAT66, cls).setUpClass()

        cls.nat_addr = 'fd01:ff::2'

        cls.create_pg_interfaces(range(2))
        cls.interfaces = list(cls.pg_interfaces)

        for i in cls.interfaces:
            i.admin_up()
            i.config_ip6()
            i.configure_ipv6_neighbors()

    @classmethod
    def tearDownClass(cls):
        super(TestNAT66, cls).tearDownClass()

    def test_static(self):
        """ 1:1 NAT66 test """
        flags = self.config_flags.NAT_IS_INSIDE
        self.vclient.nat66_add_del_interface(is_add=1, flags=flags,
                                             sw_if_index=self.pg0.sw_if_index)
        self.vclient.nat66_add_del_interface(is_add=1,
                                             sw_if_index=self.pg1.sw_if_index)
        self.vclient.nat66_add_del_static_mapping(
            local_ip_address=self.pg0.remote_ip6,
            external_ip_address=self.nat_addr,
            is_add=1)

        # in2out
        pkts = []
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IPv6(src=self.pg0.remote_ip6, dst=self.pg1.remote_ip6) /
             TCP())
        pkts.append(p)
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IPv6(src=self.pg0.remote_ip6, dst=self.pg1.remote_ip6) /
             UDP())
        pkts.append(p)
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IPv6(src=self.pg0.remote_ip6, dst=self.pg1.remote_ip6) /
             ICMPv6EchoRequest())
        pkts.append(p)
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IPv6(src=self.pg0.remote_ip6, dst=self.pg1.remote_ip6) /
             GRE() / IP() / TCP())
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
            except BaseException:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise

        # out2in
        pkts = []
        p = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
             IPv6(src=self.pg1.remote_ip6, dst=self.nat_addr) /
             TCP())
        pkts.append(p)
        p = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
             IPv6(src=self.pg1.remote_ip6, dst=self.nat_addr) /
             UDP())
        pkts.append(p)
        p = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
             IPv6(src=self.pg1.remote_ip6, dst=self.nat_addr) /
             ICMPv6EchoReply())
        pkts.append(p)
        p = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
             IPv6(src=self.pg1.remote_ip6, dst=self.nat_addr) /
             GRE() / IP() / TCP())
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
            except BaseException:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise

        sm = self.vclient.nat66_static_mapping_dump()
        self.assertEqual(len(sm), 1)
        self.assertEqual(sm[0].total_pkts, 8)

    def test_check_no_translate(self):
        """ NAT66 translate only when egress interface is outside interface """
        flags = self.config_flags.NAT_IS_INSIDE
        self.vclient.nat66_add_del_interface(is_add=1, flags=flags,
                                             sw_if_index=self.pg0.sw_if_index)
        self.vclient.nat66_add_del_interface(is_add=1, flags=flags,
                                             sw_if_index=self.pg1.sw_if_index)
        self.vclient.nat66_add_del_static_mapping(
            local_ip_address=self.pg0.remote_ip6,
            external_ip_address=self.nat_addr,
            is_add=1)

        # in2out
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IPv6(src=self.pg0.remote_ip6, dst=self.pg1.remote_ip6) /
             UDP())
        self.pg0.add_stream([p])
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(1)
        packet = capture[0]
        try:
            self.assertEqual(packet[IPv6].src, self.pg0.remote_ip6)
            self.assertEqual(packet[IPv6].dst, self.pg1.remote_ip6)
        except BaseException:
            self.logger.error(ppp("Unexpected or invalid packet:", packet))
            raise

    def clear_nat66(self):
        """
        Clear NAT66 configuration.
        """
        interfaces = self.vclient.nat66_interface_dump()
        for intf in interfaces:
            self.vclient.nat66_add_del_interface(is_add=0, flags=intf.flags,
                                                 sw_if_index=intf.sw_if_index)

        static_mappings = self.vclient.nat66_static_mapping_dump()
        for sm in static_mappings:
            self.vclient.nat66_add_del_static_mapping(
                local_ip_address=sm.local_ip_address,
                external_ip_address=sm.external_ip_address, vrf_id=sm.vrf_id,
                is_add=0)

    def tearDown(self):
        super(TestNAT66, self).tearDown()
        self.clear_nat66()

    def show_commands_at_teardown(self):
        self.logger.info(self.vclient.cli("show nat66 interfaces"))
        self.logger.info(self.vclient.cli("show nat66 static mappings"))


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
