#!/usr/bin/env python3

import binascii
import socket
import unittest

from framework import VppTestCase, VppTestRunner

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP
from util import ppp
from vpp_classifier import TestClassifier
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_ip import INVALID_INDEX


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

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
