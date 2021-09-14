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

import unittest
import socket
import binascii

from framework import VppTestCase, VppTestRunner

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet6 import IPv6, UDP, TCP
from util import ppp
from template_classifier import TestClassifier


class TestClassifierIP6(TestClassifier):
    """ Classifier IP6 Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestClassifierIP6, cls).setUpClass()
        cls.af = socket.AF_INET6

    @classmethod
    def tearDownClass(cls):
        super(TestClassifierIP6, cls).tearDownClass()

    def test_iacl_src_ip(self):
        """ Source IP6 iACL test

        Test scenario for basic IP ACL with source IP
            - Create IPv6 stream for pg0 -> pg1 interface.
            - Create iACL with source IP address.
            - Send and verify received packets on pg1 interface.
        """

        # Basic iACL testing with source IP
        pkts = self.create_stream(self.pg0, self.pg1, self.pg_if_packet_sizes)
        self.pg0.add_stream(pkts)

        key = 'ip6_src'
        self.create_classify_table(
            key,
            self.build_ip6_mask(src_ip='ffffffffffffffffffffffffffffffff'))
        self.create_classify_session(
            self.acl_tbl_idx.get(key),
            self.build_ip6_match(src_ip=self.pg0.remote_ip6))
        self.input_acl_set_interface(self.pg0, self.acl_tbl_idx.get(key))
        self.acl_active_table = key

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        pkts = self.pg1.get_capture(len(pkts))
        self.verify_capture(self.pg1, pkts)
        self.pg0.assert_nothing_captured(remark="packets forwarded")
        self.pg2.assert_nothing_captured(remark="packets forwarded")

    def test_iacl_dst_ip(self):
        """ Destination IP6 iACL test

        Test scenario for basic IP ACL with destination IP
            - Create IPv6 stream for pg0 -> pg1 interface.
            - Create iACL with destination IP address.
            - Send and verify received packets on pg1 interface.
        """

        # Basic iACL testing with destination IP
        pkts = self.create_stream(self.pg0, self.pg1, self.pg_if_packet_sizes)
        self.pg0.add_stream(pkts)

        key = 'ip6_dst'
        self.create_classify_table(
            key,
            self.build_ip6_mask(dst_ip='ffffffffffffffffffffffffffffffff'))
        self.create_classify_session(
            self.acl_tbl_idx.get(key),
            self.build_ip6_match(dst_ip=self.pg1.remote_ip6))
        self.input_acl_set_interface(self.pg0, self.acl_tbl_idx.get(key))
        self.acl_active_table = key

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        pkts = self.pg1.get_capture(len(pkts))
        self.verify_capture(self.pg1, pkts)
        self.pg0.assert_nothing_captured(remark="packets forwarded")
        self.pg2.assert_nothing_captured(remark="packets forwarded")

    def test_iacl_src_dst_ip(self):
        """ Source and destination IP6 iACL test

        Test scenario for basic IP ACL with source and destination IP
            - Create IPv4 stream for pg0 -> pg1 interface.
            - Create iACL with source and destination IP addresses.
            - Send and verify received packets on pg1 interface.
        """

        # Basic iACL testing with source and destination IP
        pkts = self.create_stream(self.pg0, self.pg1, self.pg_if_packet_sizes)
        self.pg0.add_stream(pkts)

        key = 'ip6'
        self.create_classify_table(
            key,
            self.build_ip6_mask(src_ip='ffffffffffffffffffffffffffffffff',
                                dst_ip='ffffffffffffffffffffffffffffffff'))
        self.create_classify_session(
            self.acl_tbl_idx.get(key),
            self.build_ip6_match(src_ip=self.pg0.remote_ip6,
                                 dst_ip=self.pg1.remote_ip6))
        self.input_acl_set_interface(self.pg0, self.acl_tbl_idx.get(key))
        self.acl_active_table = key

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        pkts = self.pg1.get_capture(len(pkts))
        self.verify_capture(self.pg1, pkts)
        self.pg0.assert_nothing_captured(remark="packets forwarded")
        self.pg2.assert_nothing_captured(remark="packets forwarded")


# Tests split to different test case classes because of issue reported in
# ticket VPP-1336
class TestClassifierIP6UDP(TestClassifier):
    """ Classifier IP6 UDP proto Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestClassifierIP6UDP, cls).setUpClass()
        cls.af = socket.AF_INET6

    def test_iacl_proto_udp(self):
        """ IP6 UDP protocol iACL test

        Test scenario for basic protocol ACL with UDP protocol
            - Create IPv6 stream for pg0 -> pg1 interface.
            - Create iACL with UDP IP protocol.
            - Send and verify received packets on pg1 interface.
        """

        # Basic iACL testing with UDP protocol
        pkts = self.create_stream(self.pg0, self.pg1, self.pg_if_packet_sizes)
        self.pg0.add_stream(pkts)

        key = 'nh_udp'
        self.create_classify_table(key, self.build_ip6_mask(nh='ff'))
        self.create_classify_session(
            self.acl_tbl_idx.get(key),
            self.build_ip6_match(nh=socket.IPPROTO_UDP))
        self.input_acl_set_interface(self.pg0, self.acl_tbl_idx.get(key))
        self.acl_active_table = key

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        pkts = self.pg1.get_capture(len(pkts))
        self.verify_capture(self.pg1, pkts)
        self.pg0.assert_nothing_captured(remark="packets forwarded")
        self.pg2.assert_nothing_captured(remark="packets forwarded")

    def test_iacl_proto_udp_sport(self):
        """ IP6 UDP source port iACL test

        Test scenario for basic protocol ACL with UDP and sport
            - Create IPv6 stream for pg0 -> pg1 interface.
            - Create iACL with UDP IP protocol and defined sport.
            - Send and verify received packets on pg1 interface.
        """

        # Basic iACL testing with UDP and sport
        sport = 38
        pkts = self.create_stream(self.pg0, self.pg1, self.pg_if_packet_sizes,
                                  UDP(sport=sport, dport=5678))
        self.pg0.add_stream(pkts)

        key = 'nh_udp_sport'
        self.create_classify_table(
            key, self.build_ip6_mask(nh='ff', src_port='ffff'))
        self.create_classify_session(
            self.acl_tbl_idx.get(key),
            self.build_ip6_match(nh=socket.IPPROTO_UDP, src_port=sport))
        self.input_acl_set_interface(
            self.pg0, self.acl_tbl_idx.get(key))
        self.acl_active_table = key

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        pkts = self.pg1.get_capture(len(pkts))
        self.verify_capture(self.pg1, pkts)
        self.pg0.assert_nothing_captured(remark="packets forwarded")
        self.pg2.assert_nothing_captured(remark="packets forwarded")

    def test_iacl_proto_udp_dport(self):
        """ IP6 UDP destination port iACL test

        Test scenario for basic protocol ACL with UDP and dport
            - Create IPv6 stream for pg0 -> pg1 interface.
            - Create iACL with UDP IP protocol and defined dport.
            - Send and verify received packets on pg1 interface.
        """

        # Basic iACL testing with UDP and dport
        dport = 427
        pkts = self.create_stream(self.pg0, self.pg1, self.pg_if_packet_sizes,
                                  UDP(sport=1234, dport=dport))
        self.pg0.add_stream(pkts)

        key = 'nh_udp_dport'
        self.create_classify_table(
            key, self.build_ip6_mask(nh='ff', dst_port='ffff'))
        self.create_classify_session(
            self.acl_tbl_idx.get(key),
            self.build_ip6_match(nh=socket.IPPROTO_UDP, dst_port=dport))
        self.input_acl_set_interface(
            self.pg0, self.acl_tbl_idx.get(key))
        self.acl_active_table = key

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        pkts = self.pg1.get_capture(len(pkts))
        self.verify_capture(self.pg1, pkts)
        self.pg0.assert_nothing_captured(remark="packets forwarded")
        self.pg2.assert_nothing_captured(remark="packets forwarded")

    def test_iacl_proto_udp_sport_dport(self):
        """ IP6 UDP source and destination ports iACL test

        Test scenario for basic protocol ACL with UDP and sport and dport
            - Create IPv6 stream for pg0 -> pg1 interface.
            - Create iACL with UDP IP protocol and defined sport and dport.
            - Send and verify received packets on pg1 interface.
        """

        # Basic iACL testing with UDP and sport and dport
        sport = 13720
        dport = 9080
        pkts = self.create_stream(self.pg0, self.pg1, self.pg_if_packet_sizes,
                                  UDP(sport=sport, dport=dport))
        self.pg0.add_stream(pkts)

        key = 'nh_udp_ports'
        self.create_classify_table(
            key,
            self.build_ip6_mask(nh='ff', src_port='ffff', dst_port='ffff'))
        self.create_classify_session(
            self.acl_tbl_idx.get(key),
            self.build_ip6_match(nh=socket.IPPROTO_UDP, src_port=sport,
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


class TestClassifierIP6TCP(TestClassifier):
    """ Classifier IP6 TCP proto Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestClassifierIP6TCP, cls).setUpClass()
        cls.af = socket.AF_INET6

    def test_iacl_proto_tcp(self):
        """ IP6 TCP protocol iACL test

        Test scenario for basic protocol ACL with TCP protocol
            - Create IPv6 stream for pg0 -> pg1 interface.
            - Create iACL with TCP IP protocol.
            - Send and verify received packets on pg1 interface.
        """

        # Basic iACL testing with TCP protocol
        pkts = self.create_stream(self.pg0, self.pg1, self.pg_if_packet_sizes,
                                  TCP(sport=1234, dport=5678))
        self.pg0.add_stream(pkts)

        key = 'nh_tcp'
        self.create_classify_table(key, self.build_ip6_mask(nh='ff'))
        self.create_classify_session(
            self.acl_tbl_idx.get(key),
            self.build_ip6_match(nh=socket.IPPROTO_TCP))
        self.input_acl_set_interface(
            self.pg0, self.acl_tbl_idx.get(key))
        self.acl_active_table = key

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        pkts = self.pg1.get_capture(len(pkts))
        self.verify_capture(self.pg1, pkts, TCP)
        self.pg0.assert_nothing_captured(remark="packets forwarded")
        self.pg2.assert_nothing_captured(remark="packets forwarded")

    def test_iacl_proto_tcp_sport(self):
        """ IP6 TCP source port iACL test

        Test scenario for basic protocol ACL with TCP and sport
            - Create IPv6 stream for pg0 -> pg1 interface.
            - Create iACL with TCP IP protocol and defined sport.
            - Send and verify received packets on pg1 interface.
        """

        # Basic iACL testing with TCP and sport
        sport = 38
        pkts = self.create_stream(self.pg0, self.pg1, self.pg_if_packet_sizes,
                                  TCP(sport=sport, dport=5678))
        self.pg0.add_stream(pkts)

        key = 'nh_tcp_sport'
        self.create_classify_table(
            key, self.build_ip6_mask(nh='ff', src_port='ffff'))
        self.create_classify_session(
            self.acl_tbl_idx.get(key),
            self.build_ip6_match(nh=socket.IPPROTO_TCP, src_port=sport))
        self.input_acl_set_interface(
            self.pg0, self.acl_tbl_idx.get(key))
        self.acl_active_table = key

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        pkts = self.pg1.get_capture(len(pkts))
        self.verify_capture(self.pg1, pkts, TCP)
        self.pg0.assert_nothing_captured(remark="packets forwarded")
        self.pg2.assert_nothing_captured(remark="packets forwarded")

    def test_iacl_proto_tcp_dport(self):
        """ IP6 TCP destination port iACL test

        Test scenario for basic protocol ACL with TCP and dport
            - Create IPv6 stream for pg0 -> pg1 interface.
            - Create iACL with TCP IP protocol and defined dport.
            - Send and verify received packets on pg1 interface.
        """

        # Basic iACL testing with TCP and dport
        dport = 427
        pkts = self.create_stream(self.pg0, self.pg1, self.pg_if_packet_sizes,
                                  TCP(sport=1234, dport=dport))
        self.pg0.add_stream(pkts)

        key = 'nh_tcp_dport'
        self.create_classify_table(
            key, self.build_ip6_mask(nh='ff', dst_port='ffff'))
        self.create_classify_session(
            self.acl_tbl_idx.get(key),
            self.build_ip6_match(nh=socket.IPPROTO_TCP, dst_port=dport))
        self.input_acl_set_interface(
            self.pg0, self.acl_tbl_idx.get(key))
        self.acl_active_table = key

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        pkts = self.pg1.get_capture(len(pkts))
        self.verify_capture(self.pg1, pkts, TCP)
        self.pg0.assert_nothing_captured(remark="packets forwarded")
        self.pg2.assert_nothing_captured(remark="packets forwarded")

    def test_iacl_proto_tcp_sport_dport(self):
        """ IP6 TCP source and destination ports iACL test

        Test scenario for basic protocol ACL with TCP and sport and dport
            - Create IPv6 stream for pg0 -> pg1 interface.
            - Create iACL with TCP IP protocol and defined sport and dport.
            - Send and verify received packets on pg1 interface.
        """

        # Basic iACL testing with TCP and sport and dport
        sport = 13720
        dport = 9080
        pkts = self.create_stream(self.pg0, self.pg1, self.pg_if_packet_sizes,
                                  TCP(sport=sport, dport=dport))
        self.pg0.add_stream(pkts)

        key = 'nh_tcp_ports'
        self.create_classify_table(
            key,
            self.build_ip6_mask(nh='ff', src_port='ffff', dst_port='ffff'))
        self.create_classify_session(
            self.acl_tbl_idx.get(key),
            self.build_ip6_match(nh=socket.IPPROTO_TCP, src_port=sport,
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


class TestClassifierIP6Out(TestClassifier):
    """ Classifier output IP6 Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestClassifierIP6Out, cls).setUpClass()
        cls.af = socket.AF_INET6

    def test_acl_ip_out(self):
        """ Output IP6 ACL test

        Test scenario for basic IP ACL with source IP
            - Create IPv6 stream for pg1 -> pg0 interface.
            - Create ACL with source IP address.
            - Send and verify received packets on pg0 interface.
        """

        # Basic oACL testing with source IP
        pkts = self.create_stream(self.pg1, self.pg0, self.pg_if_packet_sizes)
        self.pg1.add_stream(pkts)

        key = 'ip6_out'
        self.create_classify_table(
            key,
            self.build_ip6_mask(src_ip='ffffffffffffffffffffffffffffffff'),
            data_offset=0)
        self.create_classify_session(
            self.acl_tbl_idx.get(key),
            self.build_ip6_match(src_ip=self.pg1.remote_ip6))
        self.output_acl_set_interface(
            self.pg0, self.acl_tbl_idx.get(key))
        self.acl_active_table = key

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        pkts = self.pg0.get_capture(len(pkts))
        self.verify_capture(self.pg0, pkts)
        self.pg1.assert_nothing_captured(remark="packets forwarded")
        self.pg2.assert_nothing_captured(remark="packets forwarded")


class TestClassifierIP6MAC(TestClassifier):
    """ Classifier IP6 MAC Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestClassifierIP6MAC, cls).setUpClass()
        cls.af = socket.AF_INET6

    def test_acl_mac(self):
        """ IP6 MAC iACL test

        Test scenario for basic MAC ACL with source MAC
            - Create IPv6 stream for pg0 -> pg2 interface.
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


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
