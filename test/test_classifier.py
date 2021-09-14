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

import binascii
import socket
import unittest

from framework import VppTestCase, VppTestRunner
from scapy.packet import Raw, Packet

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP
from util import ppp
from template_classifier import TestClassifier, VarMask, VarMatch
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_ip import INVALID_INDEX
from vpp_papi import VppEnum


# Tests split to different test case classes because of issue reported in
# ticket VPP-1336
class TestClassifierIP(TestClassifier):
    """ Classifier IP Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestClassifierIP, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestClassifierIP, cls).tearDownClass()

    def test_iacl_src_ip(self):
        """ Source IP iACL test

        Test scenario for basic IP ACL with source IP
            - Create IPv4 stream for pg0 -> pg1 interface.
            - Create iACL with source IP address.
            - Send and verify received packets on pg1 interface.
        """

        # Basic iACL testing with source IP
        pkts = self.create_stream(self.pg0, self.pg1, self.pg_if_packet_sizes)
        self.pg0.add_stream(pkts)

        key = 'ip_src'
        self.create_classify_table(key, self.build_ip_mask(src_ip='ffffffff'))
        self.create_classify_session(
            self.acl_tbl_idx.get(key),
            self.build_ip_match(src_ip=self.pg0.remote_ip4))
        self.input_acl_set_interface(self.pg0, self.acl_tbl_idx.get(key))
        self.acl_active_table = key

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        pkts = self.pg1.get_capture(len(pkts))
        self.verify_capture(self.pg1, pkts)
        self.pg0.assert_nothing_captured(remark="packets forwarded")
        self.pg2.assert_nothing_captured(remark="packets forwarded")
        self.pg3.assert_nothing_captured(remark="packets forwarded")

    def test_iacl_dst_ip(self):
        """ Destination IP iACL test

        Test scenario for basic IP ACL with destination IP
            - Create IPv4 stream for pg0 -> pg1 interface.
            - Create iACL with destination IP address.
            - Send and verify received packets on pg1 interface.
        """

        # Basic iACL testing with destination IP
        pkts = self.create_stream(self.pg0, self.pg1, self.pg_if_packet_sizes)
        self.pg0.add_stream(pkts)

        key = 'ip_dst'
        self.create_classify_table(key, self.build_ip_mask(dst_ip='ffffffff'))
        self.create_classify_session(
            self.acl_tbl_idx.get(key),
            self.build_ip_match(dst_ip=self.pg1.remote_ip4))
        self.input_acl_set_interface(self.pg0, self.acl_tbl_idx.get(key))
        self.acl_active_table = key

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        pkts = self.pg1.get_capture(len(pkts))
        self.verify_capture(self.pg1, pkts)
        self.pg0.assert_nothing_captured(remark="packets forwarded")
        self.pg2.assert_nothing_captured(remark="packets forwarded")
        self.pg3.assert_nothing_captured(remark="packets forwarded")

    def test_iacl_src_dst_ip(self):
        """ Source and destination IP iACL test

        Test scenario for basic IP ACL with source and destination IP
            - Create IPv4 stream for pg0 -> pg1 interface.
            - Create iACL with source and destination IP addresses.
            - Send and verify received packets on pg1 interface.
        """

        # Basic iACL testing with source and destination IP
        pkts = self.create_stream(self.pg0, self.pg1, self.pg_if_packet_sizes)
        self.pg0.add_stream(pkts)

        key = 'ip'
        self.create_classify_table(
            key, self.build_ip_mask(src_ip='ffffffff', dst_ip='ffffffff'))
        self.create_classify_session(
            self.acl_tbl_idx.get(key),
            self.build_ip_match(src_ip=self.pg0.remote_ip4,
                                dst_ip=self.pg1.remote_ip4))
        self.input_acl_set_interface(self.pg0, self.acl_tbl_idx.get(key))
        self.acl_active_table = key

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        pkts = self.pg1.get_capture(len(pkts))
        self.verify_capture(self.pg1, pkts)
        self.pg0.assert_nothing_captured(remark="packets forwarded")
        self.pg2.assert_nothing_captured(remark="packets forwarded")
        self.pg3.assert_nothing_captured(remark="packets forwarded")


class TestClassifierUDP(TestClassifier):
    """ Classifier UDP proto Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestClassifierUDP, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestClassifierUDP, cls).tearDownClass()

    def test_iacl_proto_udp(self):
        """ UDP protocol iACL test

        Test scenario for basic protocol ACL with UDP protocol
            - Create IPv4 stream for pg0 -> pg1 interface.
            - Create iACL with UDP IP protocol.
            - Send and verify received packets on pg1 interface.
        """

        # Basic iACL testing with UDP protocol
        pkts = self.create_stream(self.pg0, self.pg1, self.pg_if_packet_sizes)
        self.pg0.add_stream(pkts)

        key = 'proto_udp'
        self.create_classify_table(key, self.build_ip_mask(proto='ff'))
        self.create_classify_session(
            self.acl_tbl_idx.get(key),
            self.build_ip_match(proto=socket.IPPROTO_UDP))
        self.input_acl_set_interface(
            self.pg0, self.acl_tbl_idx.get(key))
        self.acl_active_table = key

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        pkts = self.pg1.get_capture(len(pkts))
        self.verify_capture(self.pg1, pkts)
        self.pg0.assert_nothing_captured(remark="packets forwarded")
        self.pg2.assert_nothing_captured(remark="packets forwarded")
        self.pg3.assert_nothing_captured(remark="packets forwarded")

    def test_iacl_proto_udp_sport(self):
        """ UDP source port iACL test

        Test scenario for basic protocol ACL with UDP and sport
            - Create IPv4 stream for pg0 -> pg1 interface.
            - Create iACL with UDP IP protocol and defined sport.
            - Send and verify received packets on pg1 interface.
        """

        # Basic iACL testing with UDP and sport
        sport = 38
        pkts = self.create_stream(self.pg0, self.pg1, self.pg_if_packet_sizes,
                                  UDP(sport=sport, dport=5678))
        self.pg0.add_stream(pkts)

        key = 'proto_udp_sport'
        self.create_classify_table(
            key, self.build_ip_mask(proto='ff', src_port='ffff'))
        self.create_classify_session(
            self.acl_tbl_idx.get(key),
            self.build_ip_match(proto=socket.IPPROTO_UDP, src_port=sport))
        self.input_acl_set_interface(
            self.pg0, self.acl_tbl_idx.get(key))
        self.acl_active_table = key

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        pkts = self.pg1.get_capture(len(pkts))
        self.verify_capture(self.pg1, pkts)
        self.pg0.assert_nothing_captured(remark="packets forwarded")
        self.pg2.assert_nothing_captured(remark="packets forwarded")
        self.pg3.assert_nothing_captured(remark="packets forwarded")

    def test_iacl_proto_udp_dport(self):
        """ UDP destination port iACL test

        Test scenario for basic protocol ACL with UDP and dport
            - Create IPv4 stream for pg0 -> pg1 interface.
            - Create iACL with UDP IP protocol and defined dport.
            - Send and verify received packets on pg1 interface.
        """

        # Basic iACL testing with UDP and dport
        dport = 427
        pkts = self.create_stream(self.pg0, self.pg1, self.pg_if_packet_sizes,
                                  UDP(sport=1234, dport=dport))
        self.pg0.add_stream(pkts)

        key = 'proto_udp_dport'
        self.create_classify_table(
            key, self.build_ip_mask(proto='ff', dst_port='ffff'))
        self.create_classify_session(
            self.acl_tbl_idx.get(key),
            self.build_ip_match(proto=socket.IPPROTO_UDP, dst_port=dport))
        self.input_acl_set_interface(
            self.pg0, self.acl_tbl_idx.get(key))
        self.acl_active_table = key

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        pkts = self.pg1.get_capture(len(pkts))
        self.verify_capture(self.pg1, pkts)
        self.pg0.assert_nothing_captured(remark="packets forwarded")
        self.pg2.assert_nothing_captured(remark="packets forwarded")
        self.pg3.assert_nothing_captured(remark="packets forwarded")

    def test_iacl_proto_udp_sport_dport(self):
        """ UDP source and destination ports iACL test

        Test scenario for basic protocol ACL with UDP and sport and dport
            - Create IPv4 stream for pg0 -> pg1 interface.
            - Create iACL with UDP IP protocol and defined sport and dport.
            - Send and verify received packets on pg1 interface.
        """

        # Basic iACL testing with UDP and sport and dport
        sport = 13720
        dport = 9080
        pkts = self.create_stream(self.pg0, self.pg1, self.pg_if_packet_sizes,
                                  UDP(sport=sport, dport=dport))
        self.pg0.add_stream(pkts)

        key = 'proto_udp_ports'
        self.create_classify_table(
            key,
            self.build_ip_mask(proto='ff', src_port='ffff', dst_port='ffff'))
        self.create_classify_session(
            self.acl_tbl_idx.get(key),
            self.build_ip_match(proto=socket.IPPROTO_UDP, src_port=sport,
                                dst_port=dport))
        self.input_acl_set_interface(
            self.pg0, self.acl_tbl_idx.get(key))
        self.acl_active_table = key

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        pkts = self.pg1.get_capture(len(pkts))
        self.verify_capture(self.pg1, pkts)
        self.pg0.assert_nothing_captured(remark="packets forwarded")
        self.pg2.assert_nothing_captured(remark="packets forwarded")
        self.pg3.assert_nothing_captured(remark="packets forwarded")


class TestClassifierTCP(TestClassifier):
    """ Classifier TCP proto Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestClassifierTCP, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestClassifierTCP, cls).tearDownClass()

    def test_iacl_proto_tcp(self):
        """ TCP protocol iACL test

        Test scenario for basic protocol ACL with TCP protocol
            - Create IPv4 stream for pg0 -> pg1 interface.
            - Create iACL with TCP IP protocol.
            - Send and verify received packets on pg1 interface.
        """

        # Basic iACL testing with TCP protocol
        pkts = self.create_stream(self.pg0, self.pg1, self.pg_if_packet_sizes,
                                  TCP(sport=1234, dport=5678))
        self.pg0.add_stream(pkts)

        key = 'proto_tcp'
        self.create_classify_table(key, self.build_ip_mask(proto='ff'))
        self.create_classify_session(
            self.acl_tbl_idx.get(key),
            self.build_ip_match(proto=socket.IPPROTO_TCP))
        self.input_acl_set_interface(
            self.pg0, self.acl_tbl_idx.get(key))
        self.acl_active_table = key

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        pkts = self.pg1.get_capture(len(pkts))
        self.verify_capture(self.pg1, pkts, TCP)
        self.pg0.assert_nothing_captured(remark="packets forwarded")
        self.pg2.assert_nothing_captured(remark="packets forwarded")
        self.pg3.assert_nothing_captured(remark="packets forwarded")

    def test_iacl_proto_tcp_sport(self):
        """ TCP source port iACL test

        Test scenario for basic protocol ACL with TCP and sport
            - Create IPv4 stream for pg0 -> pg1 interface.
            - Create iACL with TCP IP protocol and defined sport.
            - Send and verify received packets on pg1 interface.
        """

        # Basic iACL testing with TCP and sport
        sport = 38
        pkts = self.create_stream(self.pg0, self.pg1, self.pg_if_packet_sizes,
                                  TCP(sport=sport, dport=5678))
        self.pg0.add_stream(pkts)

        key = 'proto_tcp_sport'
        self.create_classify_table(
            key, self.build_ip_mask(proto='ff', src_port='ffff'))
        self.create_classify_session(
            self.acl_tbl_idx.get(key),
            self.build_ip_match(proto=socket.IPPROTO_TCP, src_port=sport))
        self.input_acl_set_interface(
            self.pg0, self.acl_tbl_idx.get(key))
        self.acl_active_table = key

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        pkts = self.pg1.get_capture(len(pkts))
        self.verify_capture(self.pg1, pkts, TCP)
        self.pg0.assert_nothing_captured(remark="packets forwarded")
        self.pg2.assert_nothing_captured(remark="packets forwarded")
        self.pg3.assert_nothing_captured(remark="packets forwarded")

    def test_iacl_proto_tcp_dport(self):
        """ TCP destination port iACL test

        Test scenario for basic protocol ACL with TCP and dport
            - Create IPv4 stream for pg0 -> pg1 interface.
            - Create iACL with TCP IP protocol and defined dport.
            - Send and verify received packets on pg1 interface.
        """

        # Basic iACL testing with TCP and dport
        dport = 427
        pkts = self.create_stream(self.pg0, self.pg1, self.pg_if_packet_sizes,
                                  TCP(sport=1234, dport=dport))
        self.pg0.add_stream(pkts)

        key = 'proto_tcp_sport'
        self.create_classify_table(
            key, self.build_ip_mask(proto='ff', dst_port='ffff'))
        self.create_classify_session(
            self.acl_tbl_idx.get(key),
            self.build_ip_match(proto=socket.IPPROTO_TCP, dst_port=dport))
        self.input_acl_set_interface(
            self.pg0, self.acl_tbl_idx.get(key))
        self.acl_active_table = key

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        pkts = self.pg1.get_capture(len(pkts))
        self.verify_capture(self.pg1, pkts, TCP)
        self.pg0.assert_nothing_captured(remark="packets forwarded")
        self.pg2.assert_nothing_captured(remark="packets forwarded")
        self.pg3.assert_nothing_captured(remark="packets forwarded")

    def test_iacl_proto_tcp_sport_dport(self):
        """ TCP source and destination ports iACL test

        Test scenario for basic protocol ACL with TCP and sport and dport
            - Create IPv4 stream for pg0 -> pg1 interface.
            - Create iACL with TCP IP protocol and defined sport and dport.
            - Send and verify received packets on pg1 interface.
        """

        # Basic iACL testing with TCP and sport and dport
        sport = 13720
        dport = 9080
        pkts = self.create_stream(self.pg0, self.pg1, self.pg_if_packet_sizes,
                                  TCP(sport=sport, dport=dport))
        self.pg0.add_stream(pkts)

        key = 'proto_tcp_ports'
        self.create_classify_table(
            key,
            self.build_ip_mask(proto='ff', src_port='ffff', dst_port='ffff'))
        self.create_classify_session(
            self.acl_tbl_idx.get(key),
            self.build_ip_match(proto=socket.IPPROTO_TCP, src_port=sport,
                                dst_port=dport))
        self.input_acl_set_interface(
            self.pg0, self.acl_tbl_idx.get(key))
        self.acl_active_table = key

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        pkts = self.pg1.get_capture(len(pkts))
        self.verify_capture(self.pg1, pkts, TCP)
        self.pg0.assert_nothing_captured(remark="packets forwarded")
        self.pg2.assert_nothing_captured(remark="packets forwarded")
        self.pg3.assert_nothing_captured(remark="packets forwarded")


class TestClassifierIPOut(TestClassifier):
    """ Classifier output IP Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestClassifierIPOut, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestClassifierIPOut, cls).tearDownClass()

    def test_acl_ip_out(self):
        """ Output IP ACL test

        Test scenario for basic IP ACL with source IP
            - Create IPv4 stream for pg1 -> pg0 interface.
            - Create ACL with source IP address.
            - Send and verify received packets on pg0 interface.
        """

        # Basic oACL testing with source IP
        pkts = self.create_stream(self.pg1, self.pg0, self.pg_if_packet_sizes)
        self.pg1.add_stream(pkts)

        key = 'ip_out'
        self.create_classify_table(
            key, self.build_ip_mask(src_ip='ffffffff'), data_offset=0)
        self.create_classify_session(
            self.acl_tbl_idx.get(key),
            self.build_ip_match(src_ip=self.pg1.remote_ip4))
        self.output_acl_set_interface(self.pg0, self.acl_tbl_idx.get(key))
        self.acl_active_table = key

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        pkts = self.pg0.get_capture(len(pkts))
        self.verify_capture(self.pg0, pkts)
        self.pg1.assert_nothing_captured(remark="packets forwarded")
        self.pg2.assert_nothing_captured(remark="packets forwarded")
        self.pg3.assert_nothing_captured(remark="packets forwarded")


class TestClassifierMAC(TestClassifier):
    """ Classifier MAC Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestClassifierMAC, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestClassifierMAC, cls).tearDownClass()

    def test_acl_mac(self):
        """ MAC ACL test

        Test scenario for basic MAC ACL with source MAC
            - Create IPv4 stream for pg0 -> pg2 interface.
            - Create ACL with source MAC address.
            - Send and verify received packets on pg2 interface.
        """

        # Basic iACL testing with source MAC
        pkts = self.create_stream(self.pg0, self.pg2, self.pg_if_packet_sizes)
        self.pg0.add_stream(pkts)

        key = 'mac'
        self.create_classify_table(
            key, self.build_mac_mask(src_mac='ffffffffffff'), data_offset=-14)
        self.create_classify_session(
            self.acl_tbl_idx.get(key),
            self.build_mac_match(src_mac=self.pg0.remote_mac))
        self.input_acl_set_interface(self.pg0, self.acl_tbl_idx.get(key))
        self.acl_active_table = key

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        pkts = self.pg2.get_capture(len(pkts))
        self.verify_capture(self.pg2, pkts)
        self.pg0.assert_nothing_captured(remark="packets forwarded")
        self.pg1.assert_nothing_captured(remark="packets forwarded")
        self.pg3.assert_nothing_captured(remark="packets forwarded")


class TestClassifierComplex(TestClassifier):
    """ Large & Nested Classifiers Test Cases """

    @classmethod
    def setUpClass(cls):
        super(TestClassifierComplex, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestClassifierComplex, cls).tearDownClass()

    def test_iacl_large(self):
        """ Large input ACL test

        Test scenario for Large ACL matching on ethernet+ip+udp headers
            - Create IPv4 stream for pg0 -> pg1 interface.
            - Create large acl matching on ethernet+ip+udp header fields
            - Send and verify received packets on pg1 interface.
        """

        # 40b offset = 80bytes - (sizeof(UDP/IP/ETH) + 4b)
        # + 4b as build_ip_ma*() func, do not match against UDP Len & Chksum
        msk = VarMask(offset=40, spec='ffff')
        mth = VarMatch(offset=40, value=0x1234, length=2)

        payload_msk = self.build_payload_mask([msk])
        payload_match = self.build_payload_match([mth])

        sport = 13720
        dport = 9080

        # 36b offset = 80bytes - (sizeof(UDP/IP/ETH))
        packet_ex = bytes.fromhex(('0' * 36) + '1234')
        pkts = self.create_stream(self.pg0, self.pg1, self.pg_if_packet_sizes,
                                  UDP(sport=sport, dport=dport),
                                  packet_ex)
        self.pg0.add_stream(pkts)

        key = 'large_in'
        self.create_classify_table(
            key,
            self.build_mac_mask(src_mac='ffffffffffff',
                                dst_mac='ffffffffffff',
                                ether_type='ffff') +
            self.build_ip_mask(proto='ff',
                               src_ip='ffffffff',
                               dst_ip='ffffffff',
                               src_port='ffff',
                               dst_port='ffff') +
            payload_msk,
            data_offset=-14)

        self.create_classify_session(
            self.acl_tbl_idx.get(key),
            self.build_mac_match(src_mac=self.pg0.remote_mac,
                                 dst_mac=self.pg0.local_mac,
                                 # ipv4 next header
                                 ether_type='0800') +
            self.build_ip_match(proto=socket.IPPROTO_UDP,
                                src_ip=self.pg0.remote_ip4,
                                dst_ip=self.pg1.remote_ip4,
                                src_port=sport,
                                dst_port=dport) +
            payload_match
        )

        self.input_acl_set_interface(self.pg0, self.acl_tbl_idx.get(key))
        self.acl_active_table = key

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        pkts = self.pg1.get_capture(len(pkts))
        self.verify_capture(self.pg1, pkts)
        self.pg0.assert_nothing_captured(remark="packets forwarded")
        self.pg2.assert_nothing_captured(remark="packets forwarded")
        self.pg3.assert_nothing_captured(remark="packets forwarded")

    def test_oacl_large(self):
        """ Large output ACL test
        Test scenario for Large ACL matching on ethernet+ip+udp headers
            - Create IPv4 stream for pg1 -> pg0 interface.
            - Create large acl matching on ethernet+ip+udp header fields
            - Send and verify received packets on pg0 interface.
        """

        # 40b offset = 80bytes - (sizeof(UDP/IP/ETH) + 4b)
        # + 4b as build_ip_ma*() func, do not match against UDP Len & Chksum
        msk = VarMask(offset=40, spec='ffff')
        mth = VarMatch(offset=40, value=0x1234, length=2)

        payload_msk = self.build_payload_mask([msk])
        payload_match = self.build_payload_match([mth])

        sport = 13720
        dport = 9080

        # 36b offset = 80bytes - (sizeof(UDP/IP/ETH))
        packet_ex = bytes.fromhex(('0' * 36) + '1234')
        pkts = self.create_stream(self.pg1, self.pg0, self.pg_if_packet_sizes,
                                  UDP(sport=sport, dport=dport),
                                  packet_ex)
        self.pg1.add_stream(pkts)

        key = 'large_out'
        self.create_classify_table(
            key,
            self.build_mac_mask(src_mac='ffffffffffff',
                                dst_mac='ffffffffffff',
                                ether_type='ffff') +
            self.build_ip_mask(proto='ff',
                               src_ip='ffffffff',
                               dst_ip='ffffffff',
                               src_port='ffff',
                               dst_port='ffff') +
            payload_msk,
            data_offset=-14)

        self.create_classify_session(
            self.acl_tbl_idx.get(key),
            self.build_mac_match(src_mac=self.pg0.local_mac,
                                 dst_mac=self.pg0.remote_mac,
                                 # ipv4 next header
                                 ether_type='0800') +
            self.build_ip_match(proto=socket.IPPROTO_UDP,
                                src_ip=self.pg1.remote_ip4,
                                dst_ip=self.pg0.remote_ip4,
                                src_port=sport,
                                dst_port=dport) +
            payload_match)

        self.output_acl_set_interface(self.pg0, self.acl_tbl_idx.get(key))
        self.acl_active_table = key

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        pkts = self.pg0.get_capture(len(pkts))
        self.verify_capture(self.pg0, pkts)
        self.pg1.assert_nothing_captured(remark="packets forwarded")
        self.pg2.assert_nothing_captured(remark="packets forwarded")
        self.pg3.assert_nothing_captured(remark="packets forwarded")

    def test_iacl_nested(self):
        """ Nested input ACL test

        Test scenario for Large ACL matching on ethernet+ip+udp headers
            - Create IPv4 stream for pg0 -> pg1 interface.
            - Create 1st classifier table, without any entries
            - Create nested acl matching on ethernet+ip+udp header fields
            - Send and verify received packets on pg1 interface.
        """

        sport = 13720
        dport = 9080
        pkts = self.create_stream(self.pg0, self.pg1, self.pg_if_packet_sizes,
                                  UDP(sport=sport, dport=dport))

        self.pg0.add_stream(pkts)

        subtable_key = 'subtable_in'
        self.create_classify_table(
            subtable_key,
            self.build_mac_mask(src_mac='ffffffffffff',
                                dst_mac='ffffffffffff',
                                ether_type='ffff') +
            self.build_ip_mask(proto='ff',
                               src_ip='ffffffff',
                               dst_ip='ffffffff',
                               src_port='ffff',
                               dst_port='ffff'),
            data_offset=-14)

        key = 'nested_in'
        self.create_classify_table(
            key,
            self.build_mac_mask(src_mac='ffffffffffff',
                                dst_mac='ffffffffffff',
                                ether_type='ffff') +
            self.build_ip_mask(proto='ff',
                               src_ip='ffffffff',
                               dst_ip='ffffffff',
                               src_port='ffff',
                               dst_port='ffff'),
            next_table_index=self.acl_tbl_idx.get(subtable_key))

        self.create_classify_session(
            self.acl_tbl_idx.get(subtable_key),
            self.build_mac_match(src_mac=self.pg0.remote_mac,
                                 dst_mac=self.pg0.local_mac,
                                 # ipv4 next header
                                 ether_type='0800') +
            self.build_ip_match(proto=socket.IPPROTO_UDP,
                                src_ip=self.pg0.remote_ip4,
                                dst_ip=self.pg1.remote_ip4,
                                src_port=sport,
                                dst_port=dport))

        self.input_acl_set_interface(self.pg0, self.acl_tbl_idx.get(key))
        self.acl_active_table = key

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        pkts = self.pg1.get_capture(len(pkts))
        self.verify_capture(self.pg1, pkts)
        self.pg0.assert_nothing_captured(remark="packets forwarded")
        self.pg2.assert_nothing_captured(remark="packets forwarded")
        self.pg3.assert_nothing_captured(remark="packets forwarded")

    def test_oacl_nested(self):
        """ Nested output ACL test

        Test scenario for Large ACL matching on ethernet+ip+udp headers
            - Create IPv4 stream for pg1 -> pg0 interface.
            - Create 1st classifier table, without any entries
            - Create nested acl matching on ethernet+ip+udp header fields
            - Send and verify received packets on pg0 interface.
        """

        sport = 13720
        dport = 9080
        pkts = self.create_stream(self.pg1, self.pg0, self.pg_if_packet_sizes,
                                  UDP(sport=sport, dport=dport))
        self.pg1.add_stream(pkts)

        subtable_key = 'subtable_out'
        self.create_classify_table(
            subtable_key,
            self.build_mac_mask(src_mac='ffffffffffff',
                                dst_mac='ffffffffffff',
                                ether_type='ffff') +
            self.build_ip_mask(proto='ff',
                               src_ip='ffffffff',
                               dst_ip='ffffffff',
                               src_port='ffff',
                               dst_port='ffff'),
            data_offset=-14)

        key = 'nested_out'
        self.create_classify_table(
            key,
            self.build_mac_mask(src_mac='ffffffffffff',
                                dst_mac='ffffffffffff',
                                ether_type='ffff') +
            self.build_ip_mask(proto='ff',
                               src_ip='ffffffff',
                               dst_ip='ffffffff',
                               src_port='ffff',
                               dst_port='ffff'),
            next_table_index=self.acl_tbl_idx.get(subtable_key),
            data_offset=-14)

        self.create_classify_session(
            self.acl_tbl_idx.get(subtable_key),
            self.build_mac_match(src_mac=self.pg0.local_mac,
                                 dst_mac=self.pg0.remote_mac,
                                 # ipv4 next header
                                 ether_type='0800') +
            self.build_ip_match(proto=socket.IPPROTO_UDP,
                                src_ip=self.pg1.remote_ip4,
                                dst_ip=self.pg0.remote_ip4,
                                src_port=sport,
                                dst_port=dport))

        self.output_acl_set_interface(self.pg0, self.acl_tbl_idx.get(key))
        self.acl_active_table = key

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        pkts = self.pg0.get_capture(len(pkts))
        self.verify_capture(self.pg0, pkts)
        self.pg1.assert_nothing_captured(remark="packets forwarded")
        self.pg2.assert_nothing_captured(remark="packets forwarded")
        self.pg3.assert_nothing_captured(remark="packets forwarded")


class TestClassifierPBR(TestClassifier):
    """ Classifier PBR Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestClassifierPBR, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestClassifierPBR, cls).tearDownClass()

    def test_acl_pbr(self):
        """ IP PBR test

        Test scenario for PBR with source IP
            - Create IPv4 stream for pg0 -> pg3 interface.
            - Configure PBR fib entry for packet forwarding.
            - Send and verify received packets on pg3 interface.
        """

        # PBR testing with source IP
        pkts = self.create_stream(self.pg0, self.pg3, self.pg_if_packet_sizes)
        self.pg0.add_stream(pkts)

        key = 'pbr'
        self.create_classify_table(key, self.build_ip_mask(src_ip='ffffffff'))
        pbr_option = 1
        # this will create the VRF/table in which we will insert the route
        self.create_classify_session(
            self.acl_tbl_idx.get(key),
            self.build_ip_match(src_ip=self.pg0.remote_ip4),
            pbr_option, self.pbr_vrfid)
        self.assertTrue(self.verify_vrf(self.pbr_vrfid))
        r = VppIpRoute(self, self.pg3.local_ip4, 24,
                       [VppRoutePath(self.pg3.remote_ip4,
                                     INVALID_INDEX)],
                       table_id=self.pbr_vrfid)
        r.add_vpp_config()

        self.input_acl_set_interface(self.pg0, self.acl_tbl_idx.get(key))

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        pkts = self.pg3.get_capture(len(pkts))
        self.verify_capture(self.pg3, pkts)
        self.input_acl_set_interface(self.pg0, self.acl_tbl_idx.get(key), 0)
        self.pg0.assert_nothing_captured(remark="packets forwarded")
        self.pg1.assert_nothing_captured(remark="packets forwarded")
        self.pg2.assert_nothing_captured(remark="packets forwarded")

        # remove the classify session and the route
        r.remove_vpp_config()
        self.create_classify_session(
            self.acl_tbl_idx.get(key),
            self.build_ip_match(src_ip=self.pg0.remote_ip4),
            pbr_option, self.pbr_vrfid, is_add=0)

        # and the table should be gone.
        self.assertFalse(self.verify_vrf(self.pbr_vrfid))


class TestClassifierPunt(TestClassifier):
    """ Classifier punt Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestClassifierPunt, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestClassifierPunt, cls).tearDownClass()

    def test_punt_udp(self):
        """ IPv4/UDP protocol punt ACL test

        Test scenario for basic punt ACL with UDP protocol
            - Create IPv4 stream for pg0 -> pg1 interface.
            - Create punt ACL with UDP IP protocol.
            - Send and verify received packets on pg1 interface.
        """

        sport = 6754
        dport = 17923

        key = 'ip4_udp_punt'
        self.create_classify_table(
            key,
            self.build_ip_mask(
                src_ip='ffffffff',
                proto='ff',
                src_port='ffff'))
        table_index = self.acl_tbl_idx.get(key)
        self.vapi.punt_acl_add_del(ip4_table_index=table_index)
        self.acl_active_table = key

        # punt udp packets to dport received on pg0 through pg1
        self.vapi.set_punt(
            is_add=1,
            punt={
                'type': VppEnum.vl_api_punt_type_t.PUNT_API_TYPE_L4,
                'punt': {
                    'l4': {
                        'af': VppEnum.vl_api_address_family_t.ADDRESS_IP4,
                        'protocol': VppEnum.vl_api_ip_proto_t.IP_API_PROTO_UDP,
                        'port': dport,
                    }}})
        self.vapi.ip_punt_redirect(punt={
            'rx_sw_if_index': self.pg0.sw_if_index,
            'tx_sw_if_index': self.pg1.sw_if_index,
            'nh': self.pg1.remote_ip4,
        })

        pkts = [(Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                 IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) /
                 UDP(sport=sport, dport=dport) /
                 Raw('\x17' * 100))] * 2

        # allow a session but not matching the stream: expect to drop
        self.create_classify_session(
            table_index,
            self.build_ip_match(src_ip=self.pg0.remote_ip4,
                                proto=socket.IPPROTO_UDP, src_port=sport + 10))
        self.send_and_assert_no_replies(self.pg0, pkts)

        # allow a session matching the stream: expect to pass
        self.create_classify_session(
            table_index,
            self.build_ip_match(src_ip=self.pg0.remote_ip4,
                                proto=socket.IPPROTO_UDP, src_port=sport))
        self.send_and_expect_only(self.pg0, pkts, self.pg1)

        # cleanup
        self.acl_active_table = ''
        self.vapi.punt_acl_add_del(ip4_table_index=table_index, is_add=0)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
