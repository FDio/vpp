#!/usr/bin/env python

import unittest
import socket
import binascii
import sys

from framework import VppTestCase, VppTestRunner

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP
from util import ppp
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_ip import *


class TestClassifier(VppTestCase):
    """ Classifier Test Case """

    @classmethod
    def setUpClass(cls):
        """
        Perform standard class setup (defined by class method setUpClass in
        class VppTestCase) before running the test case, set test case related
        variables and configure VPP.
        """
        super(TestClassifier, cls).setUpClass()
        cls.acl_active_table = ''

    def setUp(self):
        """
        Perform test setup before test case.

        **Config:**
            - create 4 pg interfaces
                - untagged pg0/pg1/pg2 interface
                    pg0 -------> pg1 (IP ACL)
                           \
                            ---> pg2 (MAC ACL))
                             \
                              -> pg3 (PBR)
            - setup interfaces:
                - put it into UP state
                - set IPv4 addresses
                - resolve neighbor address using ARP

        :ivar list interfaces: pg interfaces.
        :ivar list pg_if_packet_sizes: packet sizes in test.
        :ivar dict acl_tbl_idx: ACL table index.
        :ivar int pbr_vrfid: VRF id for PBR test.
        """
        self.reset_packet_infos()
        super(TestClassifier, self).setUp()

        # create 4 pg interfaces
        self.create_pg_interfaces(range(4))

        # packet sizes to test
        self.pg_if_packet_sizes = [64, 9018]

        self.interfaces = list(self.pg_interfaces)

        # ACL & PBR vars
        self.acl_tbl_idx = {}
        self.pbr_vrfid = 200

        # setup all interfaces
        for intf in self.interfaces:
            intf.admin_up()
            intf.config_ip4()
            intf.resolve_arp()

    def tearDown(self):
        """Run standard test teardown and acl related log."""
        if not self.vpp_dead:
            self.logger.info(self.vapi.ppcli("show inacl type ip4"))
            self.logger.info(self.vapi.ppcli("show outacl type ip4"))
            self.logger.info(self.vapi.cli("show classify table verbose"))
            self.logger.info(self.vapi.cli("show ip fib"))
            if self.acl_active_table == 'ip_out':
                self.output_acl_set_interface(
                    self.pg0, self.acl_tbl_idx.get(self.acl_active_table), 0)
                self.acl_active_table = ''
            elif self.acl_active_table != '':
                self.input_acl_set_interface(
                    self.pg0, self.acl_tbl_idx.get(self.acl_active_table), 0)
                self.acl_active_table = ''
            for intf in self.interfaces:
                intf.unconfig_ip4()
                intf.admin_down()

        super(TestClassifier, self).tearDown()

    def create_stream(self, src_if, dst_if, packet_sizes,
                      proto_l=UDP(sport=1234, dport=5678)):
        """Create input packet stream for defined interfaces.

        :param VppInterface src_if: Source Interface for packet stream.
        :param VppInterface dst_if: Destination Interface for packet stream.
        :param list packet_sizes: packet size to test.
        :param Scapy proto_l: Required IP protocol. Default protocol is UDP.
        """
        pkts = []

        for size in packet_sizes:
            info = self.create_packet_info(src_if, dst_if)
            payload = self.info_to_payload(info)
            p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                 IP(src=src_if.remote_ip4, dst=dst_if.remote_ip4) /
                 proto_l /
                 Raw(payload))
            info.data = p.copy()
            self.extend_packet(p, size)
            pkts.append(p)
        return pkts

    def verify_capture(self, dst_if, capture, proto_l=UDP):
        """Verify captured input packet stream for defined interface.

        :param VppInterface dst_if: Interface to verify captured packet stream.
        :param list capture: Captured packet stream.
        :param Scapy proto_l: Required IP protocol. Default protocol is UDP.
        """
        self.logger.info("Verifying capture on interface %s" % dst_if.name)
        last_info = dict()
        for i in self.interfaces:
            last_info[i.sw_if_index] = None
        dst_sw_if_index = dst_if.sw_if_index
        for packet in capture:
            try:
                ip_received = packet[IP]
                proto_received = packet[proto_l]
                payload_info = self.payload_to_info(str(packet[Raw]))
                packet_index = payload_info.index
                self.assertEqual(payload_info.dst, dst_sw_if_index)
                self.logger.debug(
                    "Got packet on port %s: src=%u (id=%u)" %
                    (dst_if.name, payload_info.src, packet_index))
                next_info = self.get_next_packet_info_for_interface2(
                    payload_info.src, dst_sw_if_index,
                    last_info[payload_info.src])
                last_info[payload_info.src] = next_info
                self.assertTrue(next_info is not None)
                self.assertEqual(packet_index, next_info.index)
                saved_packet = next_info.data
                ip_saved = saved_packet[IP]
                proto_saved = saved_packet[proto_l]
                # Check standard fields
                self.assertEqual(ip_received.src, ip_saved.src)
                self.assertEqual(ip_received.dst, ip_saved.dst)
                self.assertEqual(proto_received.sport, proto_saved.sport)
                self.assertEqual(proto_received.dport, proto_saved.dport)
            except:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise
        for i in self.interfaces:
            remaining_packet = self.get_next_packet_info_for_interface2(
                i.sw_if_index, dst_sw_if_index, last_info[i.sw_if_index])
            self.assertTrue(remaining_packet is None,
                            "Interface %s: Packet expected from interface %s "
                            "didn't arrive" % (dst_if.name, i.name))

    def verify_vrf(self, vrf_id):
        """
        Check if the FIB table / VRF ID is configured.

        :param int vrf_id: The FIB table / VRF ID to be verified.
        :return: 1 if the FIB table / VRF ID is configured, otherwise return 0.
        """
        ip_fib_dump = self.vapi.ip_route_dump(vrf_id, False)
        vrf_count = len(ip_fib_dump)

        if vrf_count == 0:
            self.logger.info("IPv4 VRF ID %d is not configured" % vrf_id)
            return 0
        else:
            self.logger.info("IPv4 VRF ID %d is configured" % vrf_id)
            return 1

    @staticmethod
    def build_ip_mask(proto='', src_ip='', dst_ip='',
                      src_port='', dst_port=''):
        """Build IP ACL mask data with hexstring format.

        :param str proto: protocol number <0-ff>
        :param str src_ip: source ip address <0-ffffffff>
        :param str dst_ip: destination ip address <0-ffffffff>
        :param str src_port: source port number <0-ffff>
        :param str dst_port: destination port number <0-ffff>
        """

        return ('{:0>20}{:0>12}{:0>8}{:0>4}{:0>4}'.format(
            proto, src_ip, dst_ip, src_port, dst_port)).rstrip('0')

    @staticmethod
    def build_ip_match(proto=0, src_ip='', dst_ip='',
                       src_port=0, dst_port=0):
        """Build IP ACL match data with hexstring format.

        :param int proto: protocol number with valid option "x"
        :param str src_ip: source ip address with format of "x.x.x.x"
        :param str dst_ip: destination ip address with format of "x.x.x.x"
        :param int src_port: source port number "x"
        :param int dst_port: destination port number "x"
        """
        if src_ip:
            src_ip = socket.inet_aton(src_ip).encode('hex')
        if dst_ip:
            dst_ip = socket.inet_aton(dst_ip).encode('hex')

        return ('{:0>20}{:0>12}{:0>8}{:0>4}{:0>4}'.format(
            hex(proto)[2:], src_ip, dst_ip, hex(src_port)[2:],
            hex(dst_port)[2:])).rstrip('0')

    @staticmethod
    def build_mac_mask(dst_mac='', src_mac='', ether_type=''):
        """Build MAC ACL mask data with hexstring format.

        :param str dst_mac: source MAC address <0-ffffffffffff>
        :param str src_mac: destination MAC address <0-ffffffffffff>
        :param str ether_type: ethernet type <0-ffff>
        """

        return ('{:0>12}{:0>12}{:0>4}'.format(dst_mac, src_mac,
                                              ether_type)).rstrip('0')

    @staticmethod
    def build_mac_match(dst_mac='', src_mac='', ether_type=''):
        """Build MAC ACL match data with hexstring format.

        :param str dst_mac: source MAC address <x:x:x:x:x:x>
        :param str src_mac: destination MAC address <x:x:x:x:x:x>
        :param str ether_type: ethernet type <0-ffff>
        """
        if dst_mac:
            dst_mac = dst_mac.replace(':', '')
        if src_mac:
            src_mac = src_mac.replace(':', '')

        return ('{:0>12}{:0>12}{:0>4}'.format(dst_mac, src_mac,
                                              ether_type)).rstrip('0')

    def create_classify_table(self, key, mask, data_offset=0):
        """Create Classify Table

        :param str key: key for classify table (ex, ACL name).
        :param str mask: mask value for interested traffic.
        :param int data_offset:
        """
        r = self.vapi.classify_add_del_table(
            is_add=1,
            mask=binascii.unhexlify(mask),
            match_n_vectors=(len(mask) - 1) // 32 + 1,
            miss_next_index=0,
            current_data_flag=1,
            current_data_offset=data_offset)
        self.assertIsNotNone(r, msg='No response msg for add_del_table')
        self.acl_tbl_idx[key] = r.new_table_index

    def create_classify_session(self, table_index, match, pbr_option=0,
                                vrfid=0, is_add=1):
        """Create Classify Session

        :param int table_index: table index to identify classify table.
        :param str match: matched value for interested traffic.
        :param int pbr_option: enable/disable PBR feature.
        :param int vrfid: VRF id.
        :param int is_add: option to configure classify session.
            - create(1) or delete(0)
        """
        r = self.vapi.classify_add_del_session(
            is_add,
            table_index,
            binascii.unhexlify(match),
            opaque_index=0,
            action=pbr_option,
            metadata=vrfid)
        self.assertIsNotNone(r, msg='No response msg for add_del_session')

    def input_acl_set_interface(self, intf, table_index, is_add=1):
        """Configure Input ACL interface

        :param VppInterface intf: Interface to apply Input ACL feature.
        :param int table_index: table index to identify classify table.
        :param int is_add: option to configure classify session.
            - enable(1) or disable(0)
        """
        r = self.vapi.input_acl_set_interface(
            is_add,
            intf.sw_if_index,
            ip4_table_index=table_index)
        self.assertIsNotNone(r, msg='No response msg for acl_set_interface')

    def output_acl_set_interface(self, intf, table_index, is_add=1):
        """Configure Output ACL interface

        :param VppInterface intf: Interface to apply Output ACL feature.
        :param int table_index: table index to identify classify table.
        :param int is_add: option to configure classify session.
            - enable(1) or disable(0)
        """
        r = self.vapi.output_acl_set_interface(
            is_add,
            intf.sw_if_index,
            ip4_table_index=table_index)
        self.assertIsNotNone(r, msg='No response msg for acl_set_interface')


# Tests split to different test case classes because of issue reported in
# ticket VPP-1336
class TestClassifierIP(TestClassifier):
    """ Classifier IP Test Case """

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
