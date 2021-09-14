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
""" Classifier-based L2 ACL Test Case HLD:
"""

import unittest
import random
import binascii
import socket


from scapy.packet import Raw
from scapy.data import ETH_P_IP
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.layers.inet6 import IPv6ExtHdrFragment
from framework import VppTestCase, VppTestRunner
from util import Host, ppp
from template_classifier import TestClassifier


class TestClassifyAcl(TestClassifier):
    """ Classifier-based L2 input and output ACL Test Case """

    # traffic types
    IP = 0
    ICMP = 1

    # IP version
    IPRANDOM = -1
    IPV4 = 0
    IPV6 = 1

    # rule types
    DENY = 0
    PERMIT = 1

    # supported protocols
    proto = [[6, 17], [1, 58]]
    proto_map = {1: 'ICMP', 58: 'ICMPv6EchoRequest', 6: 'TCP', 17: 'UDP'}
    ICMPv4 = 0
    ICMPv6 = 1
    TCP = 0
    UDP = 1
    PROTO_ALL = 0

    # port ranges
    PORTS_ALL = -1
    PORTS_RANGE = 0
    PORTS_RANGE_2 = 1
    udp_sport_from = 10
    udp_sport_to = udp_sport_from + 5
    udp_dport_from = 20000
    udp_dport_to = udp_dport_from + 5000
    tcp_sport_from = 30
    tcp_sport_to = tcp_sport_from + 5
    tcp_dport_from = 40000
    tcp_dport_to = tcp_dport_from + 5000

    udp_sport_from_2 = 90
    udp_sport_to_2 = udp_sport_from_2 + 5
    udp_dport_from_2 = 30000
    udp_dport_to_2 = udp_dport_from_2 + 5000
    tcp_sport_from_2 = 130
    tcp_sport_to_2 = tcp_sport_from_2 + 5
    tcp_dport_from_2 = 20000
    tcp_dport_to_2 = tcp_dport_from_2 + 5000

    icmp4_type = 8  # echo request
    icmp4_code = 3
    icmp6_type = 128  # echo request
    icmp6_code = 3

    icmp4_type_2 = 8
    icmp4_code_from_2 = 5
    icmp4_code_to_2 = 20
    icmp6_type_2 = 128
    icmp6_code_from_2 = 8
    icmp6_code_to_2 = 42

    # Test variables
    bd_id = 1

    @classmethod
    def setUpClass(cls):
        """
        Perform standard class setup (defined by class method setUpClass in
        class VppTestCase) before running the test case, set test case related
        variables and configure VPP.
        """
        super(TestClassifyAcl, cls).setUpClass()
        cls.af = None

        try:
            # Create 2 pg interfaces
            cls.create_pg_interfaces(range(2))

            # Packet flows mapping pg0 -> pg1, pg2 etc.
            cls.flows = dict()
            cls.flows[cls.pg0] = [cls.pg1]

            # Packet sizes
            cls.pg_if_packet_sizes = [64, 512, 1518, 9018]

            # Create BD with MAC learning and unknown unicast flooding disabled
            # and put interfaces to this BD
            cls.vapi.bridge_domain_add_del(bd_id=cls.bd_id, uu_flood=1,
                                           learn=1)
            for pg_if in cls.pg_interfaces:
                cls.vapi.sw_interface_set_l2_bridge(
                    rx_sw_if_index=pg_if.sw_if_index, bd_id=cls.bd_id)

            # Set up all interfaces
            for i in cls.pg_interfaces:
                i.admin_up()

            # Mapping between packet-generator index and lists of test hosts
            cls.hosts_by_pg_idx = dict()
            for pg_if in cls.pg_interfaces:
                cls.hosts_by_pg_idx[pg_if.sw_if_index] = []

            # Create list of deleted hosts
            cls.deleted_hosts_by_pg_idx = dict()
            for pg_if in cls.pg_interfaces:
                cls.deleted_hosts_by_pg_idx[pg_if.sw_if_index] = []

            # warm-up the mac address tables
            # self.warmup_test()

            # Holder of the active classify table key
            cls.acl_active_table = ''

        except Exception:
            super(TestClassifyAcl, cls).tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        super(TestClassifyAcl, cls).tearDownClass()

    def setUp(self):
        super(TestClassifyAcl, self).setUp()
        self.acl_tbl_idx = {}

    def tearDown(self):
        """
        Show various debug prints after each test.
        """
        if not self.vpp_dead:
            if self.acl_active_table == 'mac_inout':
                self.output_acl_set_interface(
                    self.pg1, self.acl_tbl_idx.get(self.acl_active_table), 0)
                self.input_acl_set_interface(
                    self.pg0, self.acl_tbl_idx.get(self.acl_active_table), 0)
                self.acl_active_table = ''
            elif self.acl_active_table == 'mac_out':
                self.output_acl_set_interface(
                    self.pg1, self.acl_tbl_idx.get(self.acl_active_table), 0)
                self.acl_active_table = ''
            elif self.acl_active_table == 'mac_in':
                self.input_acl_set_interface(
                    self.pg0, self.acl_tbl_idx.get(self.acl_active_table), 0)
                self.acl_active_table = ''

        super(TestClassifyAcl, self).tearDown()

    def create_classify_session(self, intf, table_index, match,
                                hit_next_index=0xffffffff, is_add=1):
        """Create Classify Session

        :param VppInterface intf: Interface to apply classify session.
        :param int table_index: table index to identify classify table.
        :param str match: matched value for interested traffic.
        :param int is_add: option to configure classify session.
            - create(1) or delete(0)
        """
        mask_match, mask_match_len = self._resolve_mask_match(match)
        r = self.vapi.classify_add_del_session(
            is_add=is_add,
            table_index=table_index,
            match=mask_match,
            match_len=mask_match_len,
            hit_next_index=hit_next_index)
        self.assertIsNotNone(r, 'No response msg for add_del_session')

    def create_hosts(self, count, start=0):
        """
        Create required number of host MAC addresses and distribute them among
        interfaces. Create host IPv4 address for every host MAC address.

        :param int count: Number of hosts to create MAC/IPv4 addresses for.
        :param int start: Number to start numbering from.
        """
        n_int = len(self.pg_interfaces)
        macs_per_if = count // n_int
        i = -1
        for pg_if in self.pg_interfaces:
            i += 1
            start_nr = macs_per_if * i + start
            end_nr = count + start if i == (n_int - 1) \
                else macs_per_if * (i + 1) + start
            hosts = self.hosts_by_pg_idx[pg_if.sw_if_index]
            for j in range(start_nr, end_nr):
                host = Host(
                    "00:00:00:ff:%02x:%02x" % (pg_if.sw_if_index, j),
                    "172.17.1%02x.%u" % (pg_if.sw_if_index, j),
                    "2017:dead:%02x::%u" % (pg_if.sw_if_index, j))
                hosts.append(host)

    def create_upper_layer(self, packet_index, proto, ports=0):
        p = self.proto_map[proto]
        if p == 'UDP':
            if ports == 0:
                return UDP(sport=random.randint(self.udp_sport_from,
                                                self.udp_sport_to),
                           dport=random.randint(self.udp_dport_from,
                                                self.udp_dport_to))
            else:
                return UDP(sport=ports, dport=ports)
        elif p == 'TCP':
            if ports == 0:
                return TCP(sport=random.randint(self.tcp_sport_from,
                                                self.tcp_sport_to),
                           dport=random.randint(self.tcp_dport_from,
                                                self.tcp_dport_to))
            else:
                return TCP(sport=ports, dport=ports)
        return ''

    def create_stream(self, src_if, packet_sizes, traffic_type=0, ipv6=0,
                      proto=-1, ports=0, fragments=False,
                      pkt_raw=True, etype=-1):
        """
        Create input packet stream for defined interface using hosts or
        deleted_hosts list.

        :param object src_if: Interface to create packet stream for.
        :param list packet_sizes: List of required packet sizes.
        :param traffic_type: 1: ICMP packet, 2: IPv6 with EH, 0: otherwise.
        :return: Stream of packets.
        """
        pkts = []
        if self.flows.__contains__(src_if):
            src_hosts = self.hosts_by_pg_idx[src_if.sw_if_index]
            for dst_if in self.flows[src_if]:
                dst_hosts = self.hosts_by_pg_idx[dst_if.sw_if_index]
                n_int = len(dst_hosts) * len(src_hosts)
                for i in range(0, n_int):
                    dst_host = dst_hosts[i // len(src_hosts)]
                    src_host = src_hosts[i % len(src_hosts)]
                    pkt_info = self.create_packet_info(src_if, dst_if)
                    if ipv6 == 1:
                        pkt_info.ip = 1
                    elif ipv6 == 0:
                        pkt_info.ip = 0
                    else:
                        pkt_info.ip = random.choice([0, 1])
                    if proto == -1:
                        pkt_info.proto = random.choice(self.proto[self.IP])
                    else:
                        pkt_info.proto = proto
                    payload = self.info_to_payload(pkt_info)
                    p = Ether(dst=dst_host.mac, src=src_host.mac)
                    if etype > 0:
                        p = Ether(dst=dst_host.mac,
                                  src=src_host.mac,
                                  type=etype)
                    if pkt_info.ip:
                        p /= IPv6(dst=dst_host.ip6, src=src_host.ip6)
                        if fragments:
                            p /= IPv6ExtHdrFragment(offset=64, m=1)
                    else:
                        if fragments:
                            p /= IP(src=src_host.ip4, dst=dst_host.ip4,
                                    flags=1, frag=64)
                        else:
                            p /= IP(src=src_host.ip4, dst=dst_host.ip4)
                    if traffic_type == self.ICMP:
                        if pkt_info.ip:
                            p /= ICMPv6EchoRequest(type=self.icmp6_type,
                                                   code=self.icmp6_code)
                        else:
                            p /= ICMP(type=self.icmp4_type,
                                      code=self.icmp4_code)
                    else:
                        p /= self.create_upper_layer(i, pkt_info.proto, ports)
                    if pkt_raw:
                        p /= Raw(payload)
                        pkt_info.data = p.copy()
                    if pkt_raw:
                        size = random.choice(packet_sizes)
                        self.extend_packet(p, size)
                    pkts.append(p)
        return pkts

    def verify_capture(self, pg_if, capture,
                       traffic_type=0, ip_type=0, etype=-1):
        """
        Verify captured input packet stream for defined interface.

        :param object pg_if: Interface to verify captured packet stream for.
        :param list capture: Captured packet stream.
        :param traffic_type: 1: ICMP packet, 2: IPv6 with EH, 0: otherwise.
        """
        last_info = dict()
        for i in self.pg_interfaces:
            last_info[i.sw_if_index] = None
        dst_sw_if_index = pg_if.sw_if_index
        for packet in capture:
            if etype > 0:
                if packet[Ether].type != etype:
                    self.logger.error(ppp("Unexpected ethertype in packet:",
                                          packet))
                else:
                    continue
            try:
                # Raw data for ICMPv6 are stored in ICMPv6EchoRequest.data
                if traffic_type == self.ICMP and ip_type == self.IPV6:
                    payload_info = self.payload_to_info(
                        packet[ICMPv6EchoRequest].data)
                    payload = packet[ICMPv6EchoRequest]
                else:
                    payload_info = self.payload_to_info(packet[Raw])
                    payload = packet[self.proto_map[payload_info.proto]]
            except:
                self.logger.error(ppp("Unexpected or invalid packet "
                                      "(outside network):", packet))
                raise

            if ip_type != 0:
                self.assertEqual(payload_info.ip, ip_type)
            if traffic_type == self.ICMP:
                try:
                    if payload_info.ip == 0:
                        self.assertEqual(payload.type, self.icmp4_type)
                        self.assertEqual(payload.code, self.icmp4_code)
                    else:
                        self.assertEqual(payload.type, self.icmp6_type)
                        self.assertEqual(payload.code, self.icmp6_code)
                except:
                    self.logger.error(ppp("Unexpected or invalid packet "
                                          "(outside network):", packet))
                    raise
            else:
                try:
                    ip_version = IPv6 if payload_info.ip == 1 else IP

                    ip = packet[ip_version]
                    packet_index = payload_info.index

                    self.assertEqual(payload_info.dst, dst_sw_if_index)
                    self.logger.debug("Got packet on port %s: src=%u (id=%u)" %
                                      (pg_if.name, payload_info.src,
                                       packet_index))
                    next_info = self.get_next_packet_info_for_interface2(
                        payload_info.src, dst_sw_if_index,
                        last_info[payload_info.src])
                    last_info[payload_info.src] = next_info
                    self.assertTrue(next_info is not None)
                    self.assertEqual(packet_index, next_info.index)
                    saved_packet = next_info.data
                    # Check standard fields
                    self.assertEqual(ip.src, saved_packet[ip_version].src)
                    self.assertEqual(ip.dst, saved_packet[ip_version].dst)
                    p = self.proto_map[payload_info.proto]
                    if p == 'TCP':
                        tcp = packet[TCP]
                        self.assertEqual(tcp.sport, saved_packet[
                            TCP].sport)
                        self.assertEqual(tcp.dport, saved_packet[
                            TCP].dport)
                    elif p == 'UDP':
                        udp = packet[UDP]
                        self.assertEqual(udp.sport, saved_packet[
                            UDP].sport)
                        self.assertEqual(udp.dport, saved_packet[
                            UDP].dport)
                except:
                    self.logger.error(ppp("Unexpected or invalid packet:",
                                          packet))
                    raise
        for i in self.pg_interfaces:
            remaining_packet = self.get_next_packet_info_for_interface2(
                i, dst_sw_if_index, last_info[i.sw_if_index])
            self.assertTrue(
                remaining_packet is None,
                "Port %u: Packet expected from source %u didn't arrive" %
                (dst_sw_if_index, i.sw_if_index))

    def run_traffic_no_check(self):
        # Test
        # Create incoming packet streams for packet-generator interfaces
        for i in self.pg_interfaces:
            if self.flows.__contains__(i):
                pkts = self.create_stream(i, self.pg_if_packet_sizes)
                if len(pkts) > 0:
                    i.add_stream(pkts)

        # Enable packet capture and start packet sending
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

    def run_verify_test(self, traffic_type=0, ip_type=0, proto=-1, ports=0,
                        frags=False, pkt_raw=True, etype=-1):
        # Test
        # Create incoming packet streams for packet-generator interfaces
        pkts_cnt = 0
        for i in self.pg_interfaces:
            if self.flows.__contains__(i):
                pkts = self.create_stream(i, self.pg_if_packet_sizes,
                                          traffic_type, ip_type, proto, ports,
                                          frags, pkt_raw, etype)
                if len(pkts) > 0:
                    i.add_stream(pkts)
                    pkts_cnt += len(pkts)

        # Enable packet capture and start packet sendingself.IPV
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Verify
        # Verify outgoing packet streams per packet-generator interface
        for src_if in self.pg_interfaces:
            if self.flows.__contains__(src_if):
                for dst_if in self.flows[src_if]:
                    capture = dst_if.get_capture(pkts_cnt)
                    self.logger.info("Verifying capture on interface %s" %
                                     dst_if.name)
                    self.verify_capture(dst_if, capture,
                                        traffic_type, ip_type, etype)

    def run_verify_negat_test(self, traffic_type=0, ip_type=0, proto=-1,
                              ports=0, frags=False, etype=-1):
        # Test
        self.reset_packet_infos()
        for i in self.pg_interfaces:
            if self.flows.__contains__(i):
                pkts = self.create_stream(i, self.pg_if_packet_sizes,
                                          traffic_type, ip_type, proto, ports,
                                          frags, True, etype)
                if len(pkts) > 0:
                    i.add_stream(pkts)

        # Enable packet capture and start packet sending
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Verify
        # Verify outgoing packet streams per packet-generator interface
        for src_if in self.pg_interfaces:
            if self.flows.__contains__(src_if):
                for dst_if in self.flows[src_if]:
                    self.logger.info("Verifying capture on interface %s" %
                                     dst_if.name)
                    capture = dst_if.get_capture(0)
                    self.assertEqual(len(capture), 0)

    def build_classify_table(self, src_mac='', dst_mac='', ether_type='',
                             etype='', key='mac', hit_next_index=0xffffffff):
        # Basic ACL testing
        a_mask = self.build_mac_mask(src_mac=src_mac, dst_mac=dst_mac,
                                     ether_type=ether_type)
        self.create_classify_table(key, a_mask)
        for host in self.hosts_by_pg_idx[self.pg0.sw_if_index]:
            s_mac = host.mac if src_mac else ''
            if dst_mac:
                for dst_if in self.flows[self.pg0]:
                    for dst_host in self.hosts_by_pg_idx[dst_if.sw_if_index]:
                        self.create_classify_session(
                            self.pg0, self.acl_tbl_idx.get(key),
                            self.build_mac_match(src_mac=s_mac,
                                                 dst_mac=dst_host.mac,
                                                 ether_type=etype),
                            hit_next_index=hit_next_index)
            else:
                self.create_classify_session(
                    self.pg0, self.acl_tbl_idx.get(key),
                    self.build_mac_match(src_mac=s_mac, dst_mac='',
                                         ether_type=etype),
                    hit_next_index=hit_next_index)

    def test_0000_warmup_test(self):
        """ Learn the MAC addresses
        """
        self.create_hosts(2)
        self.run_traffic_no_check()

    def test_0010_inacl_permit_src_mac(self):
        """ Input  L2 ACL test - permit source MAC

        Test scenario for basic IP ACL with source IP
            - Create IPv4 stream for pg0 -> pg1 interface.
            - Create ACL with source MAC address.
            - Send and verify received packets on pg1 interface.
        """
        key = 'mac_in'
        self.build_classify_table(src_mac='ffffffffffff', key=key)
        self.input_acl_set_interface(self.pg0, self.acl_tbl_idx.get(key))
        self.acl_active_table = key
        self.run_verify_test(self.IP, self.IPV4, -1)

    def test_0011_inacl_permit_dst_mac(self):
        """ Input  L2 ACL test - permit destination MAC

        Test scenario for basic IP ACL with source IP
            - Create IPv4 stream for pg0 -> pg1 interface.
            - Create ACL with destination MAC address.
            - Send and verify received packets on pg1 interface.
        """
        key = 'mac_in'
        self.build_classify_table(dst_mac='ffffffffffff', key=key)
        self.input_acl_set_interface(self.pg0, self.acl_tbl_idx.get(key))
        self.acl_active_table = key
        self.run_verify_test(self.IP, self.IPV4, -1)

    def test_0012_inacl_permit_src_dst_mac(self):
        """ Input  L2 ACL test - permit source and destination MAC

        Test scenario for basic IP ACL with source IP
            - Create IPv4 stream for pg0 -> pg1 interface.
            - Create ACL with source and destination MAC addresses.
            - Send and verify received packets on pg1 interface.
        """
        key = 'mac_in'
        self.build_classify_table(
            src_mac='ffffffffffff', dst_mac='ffffffffffff', key=key)
        self.input_acl_set_interface(self.pg0, self.acl_tbl_idx.get(key))
        self.acl_active_table = key
        self.run_verify_test(self.IP, self.IPV4, -1)

    def test_0013_inacl_permit_ether_type(self):
        """ Input  L2 ACL test - permit ether_type

        Test scenario for basic IP ACL with source IP
            - Create IPv4 stream for pg0 -> pg1 interface.
            - Create ACL with destination MAC address.
            - Send and verify received packets on pg1 interface.
        """
        key = 'mac_in'
        self.build_classify_table(
            ether_type='ffff', etype=hex(ETH_P_IP)[2:], key=key)
        self.input_acl_set_interface(self.pg0, self.acl_tbl_idx.get(key))
        self.acl_active_table = key
        self.run_verify_test(self.IP, self.IPV4, -1)

    def test_0015_inacl_deny(self):
        """ Input  L2 ACL test - deny

        Test scenario for basic IP ACL with source IP
            - Create IPv4 stream for pg0 -> pg1 interface.

            - Create ACL with source MAC address.
            - Send and verify no received packets on pg1 interface.
        """
        key = 'mac_in'
        self.build_classify_table(
            src_mac='ffffffffffff', hit_next_index=0, key=key)
        self.input_acl_set_interface(self.pg0, self.acl_tbl_idx.get(key))
        self.acl_active_table = key
        self.run_verify_negat_test(self.IP, self.IPV4, -1)

    def test_0020_outacl_permit(self):
        """ Output L2 ACL test - permit

        Test scenario for basic IP ACL with source IP
            - Create IPv4 stream for pg0 -> pg1 interface.
            - Create ACL with source MAC address.
            - Send and verify received packets on pg1 interface.
        """
        key = 'mac_out'
        self.build_classify_table(src_mac='ffffffffffff', key=key)
        self.output_acl_set_interface(self.pg1, self.acl_tbl_idx.get(key))
        self.acl_active_table = key
        self.run_verify_test(self.IP, self.IPV4, -1)

    def test_0025_outacl_deny(self):
        """ Output L2 ACL test - deny

        Test scenario for basic IP ACL with source IP
            - Create IPv4 stream for pg0 -> pg1 interface.
            - Create ACL with source MAC address.
            - Send and verify no received packets on pg1 interface.
        """
        key = 'mac_out'
        self.build_classify_table(
            src_mac='ffffffffffff', hit_next_index=0, key=key)
        self.output_acl_set_interface(self.pg1, self.acl_tbl_idx.get(key))
        self.acl_active_table = key
        self.run_verify_negat_test(self.IP, self.IPV4, -1)

    def test_0030_inoutacl_permit(self):
        """ Input+Output L2 ACL test - permit

        Test scenario for basic IP ACL with source IP
            - Create IPv4 stream for pg0 -> pg1 interface.
            - Create ACLs with source MAC address.
            - Send and verify received packets on pg1 interface.
        """
        key = 'mac_inout'
        self.build_classify_table(src_mac='ffffffffffff', key=key)
        self.output_acl_set_interface(self.pg1, self.acl_tbl_idx.get(key))
        self.input_acl_set_interface(self.pg0, self.acl_tbl_idx.get(key))
        self.acl_active_table = key
        self.run_verify_test(self.IP, self.IPV4, -1)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
