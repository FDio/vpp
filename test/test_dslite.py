#!/usr/bin/env python3
# Copyright (c) 2021 Cisco and/or its affiliates.
#
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#
# Licensed under the Apache License 2.0 or
# GNU General Public License v2.0 or later;  you may not use this file
# except in compliance with one of these Licenses. You
# may obtain a copy of the Licenses at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#     https://www.gnu.org/licenses/old-licenses/gpl-2.0-standalone.html
#
# Note: If this file is linked with Scapy, which is GPLv2+, your use of it
# must be under GPLv2+.  If at any point in the future it is no longer linked
# with Scapy (or other GPLv2+ licensed software), you are free to choose
# Apache 2.
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import socket
import unittest
import struct
import random

from framework import tag_fixme_vpp_workers
from framework import VppTestCase, VppTestRunner, running_extended_tests

import scapy.compat
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet import IPerror, TCPerror, UDPerror, ICMPerror
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply, \
    ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, fragment6
from scapy.layers.inet6 import ICMPv6DestUnreach, IPerror6, IPv6ExtHdrFragment
from scapy.layers.l2 import Ether, ARP, GRE
from scapy.data import IP_PROTOS
from scapy.packet import bind_layers, Raw
from util import ppp
from ipfix import IPFIX, Set, Template, Data, IPFIXDecoder
from time import sleep
from util import ip4_range
from vpp_papi import mac_pton
from syslog_rfc5424_parser import SyslogMessage, ParseError
from syslog_rfc5424_parser.constants import SyslogFacility, SyslogSeverity
from io import BytesIO
from vpp_papi import VppEnum
from vpp_ip_route import VppIpRoute, VppRoutePath, FibPathType
from vpp_neighbor import VppNeighbor
from scapy.all import bind_layers, Packet, ByteEnumField, ShortField, \
    IPField, IntField, LongField, XByteField, FlagsField, FieldLenField, \
    PacketListField
from ipaddress import IPv6Network


@tag_fixme_vpp_workers
class TestDSlite(VppTestCase):
    """ DS-Lite Test Cases """

    @classmethod
    def setUpClass(cls):
        super(TestDSlite, cls).setUpClass()

        try:
            cls.nat_addr = '10.0.0.3'

            cls.create_pg_interfaces(range(3))
            cls.pg0.admin_up()
            cls.pg0.config_ip4()
            cls.pg0.resolve_arp()
            cls.pg1.admin_up()
            cls.pg1.config_ip6()
            cls.pg1.generate_remote_hosts(2)
            cls.pg1.configure_ipv6_neighbors()
            cls.pg2.admin_up()
            cls.pg2.config_ip4()
            cls.pg2.resolve_arp()

        except Exception:
            super(TestDSlite, cls).tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        super(TestDSlite, cls).tearDownClass()

    def verify_syslog_apmadd(self, data, isaddr, isport, xsaddr, xsport,
                             sv6enc, proto):
        message = data.decode('utf-8')
        try:
            message = SyslogMessage.parse(message)
        except ParseError as e:
            self.logger.error(e)
        else:
            self.assertEqual(message.severity, SyslogSeverity.info)
            self.assertEqual(message.appname, 'NAT')
            self.assertEqual(message.msgid, 'APMADD')
            sd_params = message.sd.get('napmap')
            self.assertTrue(sd_params is not None)
            self.assertEqual(sd_params.get('IATYP'), 'IPv4')
            self.assertEqual(sd_params.get('ISADDR'), isaddr)
            self.assertEqual(sd_params.get('ISPORT'), "%d" % isport)
            self.assertEqual(sd_params.get('XATYP'), 'IPv4')
            self.assertEqual(sd_params.get('XSADDR'), xsaddr)
            self.assertEqual(sd_params.get('XSPORT'), "%d" % xsport)
            self.assertEqual(sd_params.get('PROTO'), "%d" % proto)
            self.assertTrue(sd_params.get('SSUBIX') is not None)
            self.assertEqual(sd_params.get('SV6ENC'), sv6enc)

    def test_dslite(self):
        """ Test DS-Lite """
        nat_config = self.vapi.nat_show_config()
        self.assertEqual(0, nat_config.dslite_ce)

        self.vapi.dslite_add_del_pool_addr_range(start_addr=self.nat_addr,
                                                 end_addr=self.nat_addr,
                                                 is_add=1)
        aftr_ip4 = '192.0.0.1'
        aftr_ip6 = '2001:db8:85a3::8a2e:370:1'
        self.vapi.dslite_set_aftr_addr(ip4_addr=aftr_ip4, ip6_addr=aftr_ip6)
        self.vapi.syslog_set_sender(self.pg2.local_ip4, self.pg2.remote_ip4)

        # UDP
        p = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
             IPv6(dst=aftr_ip6, src=self.pg1.remote_hosts[0].ip6) /
             IP(dst=self.pg0.remote_ip4, src='192.168.1.1') /
             UDP(sport=20000, dport=10000))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(1)
        capture = capture[0]
        self.assertFalse(capture.haslayer(IPv6))
        self.assertEqual(capture[IP].src, self.nat_addr)
        self.assertEqual(capture[IP].dst, self.pg0.remote_ip4)
        self.assertNotEqual(capture[UDP].sport, 20000)
        self.assertEqual(capture[UDP].dport, 10000)
        self.assert_packet_checksums_valid(capture)
        out_port = capture[UDP].sport
        capture = self.pg2.get_capture(1)
        self.verify_syslog_apmadd(capture[0][Raw].load, '192.168.1.1',
                                  20000, self.nat_addr, out_port,
                                  self.pg1.remote_hosts[0].ip6, IP_PROTOS.udp)

        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(dst=self.nat_addr, src=self.pg0.remote_ip4) /
             UDP(sport=10000, dport=out_port))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(1)
        capture = capture[0]
        self.assertEqual(capture[IPv6].src, aftr_ip6)
        self.assertEqual(capture[IPv6].dst, self.pg1.remote_hosts[0].ip6)
        self.assertEqual(capture[IP].src, self.pg0.remote_ip4)
        self.assertEqual(capture[IP].dst, '192.168.1.1')
        self.assertEqual(capture[UDP].sport, 10000)
        self.assertEqual(capture[UDP].dport, 20000)
        self.assert_packet_checksums_valid(capture)

        # TCP
        p = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
             IPv6(dst=aftr_ip6, src=self.pg1.remote_hosts[1].ip6) /
             IP(dst=self.pg0.remote_ip4, src='192.168.1.1') /
             TCP(sport=20001, dport=10001))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(1)
        capture = capture[0]
        self.assertFalse(capture.haslayer(IPv6))
        self.assertEqual(capture[IP].src, self.nat_addr)
        self.assertEqual(capture[IP].dst, self.pg0.remote_ip4)
        self.assertNotEqual(capture[TCP].sport, 20001)
        self.assertEqual(capture[TCP].dport, 10001)
        self.assert_packet_checksums_valid(capture)
        out_port = capture[TCP].sport

        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(dst=self.nat_addr, src=self.pg0.remote_ip4) /
             TCP(sport=10001, dport=out_port))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(1)
        capture = capture[0]
        self.assertEqual(capture[IPv6].src, aftr_ip6)
        self.assertEqual(capture[IPv6].dst, self.pg1.remote_hosts[1].ip6)
        self.assertEqual(capture[IP].src, self.pg0.remote_ip4)
        self.assertEqual(capture[IP].dst, '192.168.1.1')
        self.assertEqual(capture[TCP].sport, 10001)
        self.assertEqual(capture[TCP].dport, 20001)
        self.assert_packet_checksums_valid(capture)

        # ICMP
        p = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
             IPv6(dst=aftr_ip6, src=self.pg1.remote_hosts[1].ip6) /
             IP(dst=self.pg0.remote_ip4, src='192.168.1.1') /
             ICMP(id=4000, type='echo-request'))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(1)
        capture = capture[0]
        self.assertFalse(capture.haslayer(IPv6))
        self.assertEqual(capture[IP].src, self.nat_addr)
        self.assertEqual(capture[IP].dst, self.pg0.remote_ip4)
        self.assertNotEqual(capture[ICMP].id, 4000)
        self.assert_packet_checksums_valid(capture)
        out_id = capture[ICMP].id

        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(dst=self.nat_addr, src=self.pg0.remote_ip4) /
             ICMP(id=out_id, type='echo-reply'))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(1)
        capture = capture[0]
        self.assertEqual(capture[IPv6].src, aftr_ip6)
        self.assertEqual(capture[IPv6].dst, self.pg1.remote_hosts[1].ip6)
        self.assertEqual(capture[IP].src, self.pg0.remote_ip4)
        self.assertEqual(capture[IP].dst, '192.168.1.1')
        self.assertEqual(capture[ICMP].id, 4000)
        self.assert_packet_checksums_valid(capture)

        # ping DS-Lite AFTR tunnel endpoint address
        p = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
             IPv6(src=self.pg1.remote_hosts[1].ip6, dst=aftr_ip6) /
             ICMPv6EchoRequest())
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(1)
        capture = capture[0]
        self.assertEqual(capture[IPv6].src, aftr_ip6)
        self.assertEqual(capture[IPv6].dst, self.pg1.remote_hosts[1].ip6)
        self.assertTrue(capture.haslayer(ICMPv6EchoReply))

        b4s = self.statistics.get_counter('/dslite/total-b4s')
        self.assertEqual(b4s[0][0], 2)
        sessions = self.statistics.get_counter('/dslite/total-sessions')
        self.assertEqual(sessions[0][0], 3)

    def tearDown(self):
        super(TestDSlite, self).tearDown()

    def show_commands_at_teardown(self):
        self.logger.info(self.vapi.cli("show dslite pool"))
        self.logger.info(
            self.vapi.cli("show dslite aftr-tunnel-endpoint-address"))
        self.logger.info(self.vapi.cli("show dslite sessions"))


class TestDSliteCE(VppTestCase):
    """ DS-Lite CE Test Cases """

    @classmethod
    def setUpConstants(cls):
        super(TestDSliteCE, cls).setUpConstants()
        cls.vpp_cmdline.extend(["dslite", "{", "ce", "}"])

    @classmethod
    def setUpClass(cls):
        super(TestDSliteCE, cls).setUpClass()

        try:
            cls.create_pg_interfaces(range(2))
            cls.pg0.admin_up()
            cls.pg0.config_ip4()
            cls.pg0.resolve_arp()
            cls.pg1.admin_up()
            cls.pg1.config_ip6()
            cls.pg1.generate_remote_hosts(1)
            cls.pg1.configure_ipv6_neighbors()

        except Exception:
            super(TestDSliteCE, cls).tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        super(TestDSliteCE, cls).tearDownClass()

    def test_dslite_ce(self):
        """ Test DS-Lite CE """

        # TODO: add message to retrieve dslite config
        # nat_config = self.vapi.nat_show_config()
        # self.assertEqual(1, nat_config.dslite_ce)

        b4_ip4 = '192.0.0.2'
        b4_ip6 = '2001:db8:62aa::375e:f4c1:1'
        self.vapi.dslite_set_b4_addr(ip4_addr=b4_ip4, ip6_addr=b4_ip6)

        aftr_ip4 = '192.0.0.1'
        aftr_ip6 = '2001:db8:85a3::8a2e:370:1'
        aftr_ip6_n = socket.inet_pton(socket.AF_INET6, aftr_ip6)
        self.vapi.dslite_set_aftr_addr(ip4_addr=aftr_ip4, ip6_addr=aftr_ip6)

        r1 = VppIpRoute(self, aftr_ip6, 128,
                        [VppRoutePath(self.pg1.remote_ip6,
                                      self.pg1.sw_if_index)])
        r1.add_vpp_config()

        # UDP encapsulation
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(dst=self.pg1.remote_ip4, src=self.pg0.remote_ip4) /
             UDP(sport=10000, dport=20000))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(1)
        capture = capture[0]
        self.assertEqual(capture[IPv6].src, b4_ip6)
        self.assertEqual(capture[IPv6].dst, aftr_ip6)
        self.assertEqual(capture[IP].src, self.pg0.remote_ip4)
        self.assertEqual(capture[IP].dst, self.pg1.remote_ip4)
        self.assertEqual(capture[UDP].sport, 10000)
        self.assertEqual(capture[UDP].dport, 20000)
        self.assert_packet_checksums_valid(capture)

        # UDP decapsulation
        p = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
             IPv6(dst=b4_ip6, src=aftr_ip6) /
             IP(dst=self.pg0.remote_ip4, src=self.pg1.remote_ip4) /
             UDP(sport=20000, dport=10000))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(1)
        capture = capture[0]
        self.assertFalse(capture.haslayer(IPv6))
        self.assertEqual(capture[IP].src, self.pg1.remote_ip4)
        self.assertEqual(capture[IP].dst, self.pg0.remote_ip4)
        self.assertEqual(capture[UDP].sport, 20000)
        self.assertEqual(capture[UDP].dport, 10000)
        self.assert_packet_checksums_valid(capture)

        # ping DS-Lite B4 tunnel endpoint address
        p = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
             IPv6(src=self.pg1.remote_hosts[0].ip6, dst=b4_ip6) /
             ICMPv6EchoRequest())
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(1)
        capture = capture[0]
        self.assertEqual(capture[IPv6].src, b4_ip6)
        self.assertEqual(capture[IPv6].dst, self.pg1.remote_hosts[0].ip6)
        self.assertTrue(capture.haslayer(ICMPv6EchoReply))

    def tearDown(self):
        super(TestDSliteCE, self).tearDown()

    def show_commands_at_teardown(self):
        self.logger.info(
            self.vapi.cli("show dslite aftr-tunnel-endpoint-address"))
        self.logger.info(
            self.vapi.cli("show dslite b4-tunnel-endpoint-address"))
