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
import struct
import unittest
import scapy.compat
from framework import VppTestCase, running_extended_tests
from ipfix import IPFIX, Set, Template, Data, IPFIXDecoder
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet import IPerror, UDPerror
from scapy.layers.l2 import Ether
from util import ppp


class TestDET44(VppTestCase):
    """ Deterministic NAT Test Cases """

    @classmethod
    def setUpClass(cls):
        super(TestDET44, cls).setUpClass()
        cls.vapi.cli("set log class det44 level debug")

        cls.tcp_port_in = 6303
        cls.tcp_external_port = 6303
        cls.udp_port_in = 6304
        cls.udp_external_port = 6304
        cls.icmp_id_in = 6305
        cls.nat_addr = '10.0.0.3'

        cls.create_pg_interfaces(range(3))
        cls.interfaces = list(cls.pg_interfaces)

        for i in cls.interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

        cls.pg0.generate_remote_hosts(2)
        cls.pg0.configure_ipv4_neighbors()

    @classmethod
    def tearDownClass(cls):
        super(TestDET44, cls).tearDownClass()

    def setUp(self):
        super(TestDET44, self).setUp()
        self.vapi.det44_plugin_enable_disable(enable=1)

    def tearDown(self):
        super(TestDET44, self).tearDown()
        if not self.vpp_dead:
            self.vapi.det44_plugin_enable_disable(enable=0)

    def show_commands_at_teardown(self):
        self.logger.info(self.vapi.cli("show det44 interfaces"))
        self.logger.info(self.vapi.cli("show det44 timeouts"))
        self.logger.info(self.vapi.cli("show det44 mappings"))
        self.logger.info(self.vapi.cli("show det44 sessions"))

    def verify_capture_in(self, capture, in_if):
        """
        Verify captured packets on inside network

        :param capture: Captured packets
        :param in_if: Inside interface
        """
        fired = False
        for packet in capture:
            try:
                self.assert_packet_checksums_valid(packet)
                self.assertEqual(packet[IP].dst, in_if.remote_ip4)
                if packet.haslayer(TCP):
                    self.assertEqual(packet[TCP].dport, self.tcp_port_in)
                elif packet.haslayer(UDP):
                    self.assertEqual(packet[UDP].dport, self.udp_port_in)
                else:
                    self.assertEqual(packet[ICMP].id, self.icmp_id_in)
            except:
                fired = True
                self.logger.error(ppp("Unexpected or invalid packet "
                                      "(inside network):", packet))
        if fired:
            raise

    def verify_ipfix_max_entries_per_user(self, data, limit, src_addr):
        """
        Verify IPFIX maximum entries per user exceeded event

        :param data: Decoded IPFIX data records
        :param limit: Number of maximum entries per user
        :param src_addr: IPv4 source address
        """
        self.assertEqual(1, len(data))
        record = data[0]
        # natEvent
        self.assertEqual(scapy.compat.orb(record[230]), 13)
        # natQuotaExceededEvent
        self.assertEqual(struct.pack("I", 3), record[466])
        # maxEntriesPerUser
        self.assertEqual(struct.pack("I", limit), record[473])
        # sourceIPv4Address
        self.assertEqual(socket.inet_pton(socket.AF_INET, src_addr), record[8])

    def initiate_tcp_session(self, in_if, out_if):
        """
        Initiates TCP session 3 WAY HAND SHAKE

        :param in_if: Inside interface
        :param out_if: Outside interface
        """

        # SYN packet in->out
        p = (Ether(src=in_if.remote_mac, dst=in_if.local_mac) /
             IP(src=in_if.remote_ip4, dst=out_if.remote_ip4) /
             TCP(sport=self.tcp_port_in, dport=self.tcp_external_port,
             flags="S"))
        in_if.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = out_if.get_capture(1)
        p = capture[0]
        self.tcp_port_out = p[TCP].sport

        # SYN + ACK packet out->in
        p = (Ether(src=out_if.remote_mac, dst=out_if.local_mac) /
             IP(src=out_if.remote_ip4, dst=self.nat_addr) /
             TCP(sport=self.tcp_external_port, dport=self.tcp_port_out,
             flags="SA"))
        out_if.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        in_if.get_capture(1)

        # ACK packet in->out
        p = (Ether(src=in_if.remote_mac, dst=in_if.local_mac) /
             IP(src=in_if.remote_ip4, dst=out_if.remote_ip4) /
             TCP(sport=self.tcp_port_in, dport=self.tcp_external_port,
             flags="A"))
        in_if.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        out_if.get_capture(1)

    def create_stream_in(self, in_if, out_if, ttl=64):
        """
        Create packet stream for inside network

        :param in_if: Inside interface
        :param out_if: Outside interface
        :param ttl: TTL of generated packets
        """
        pkts = []
        # TCP
        p = (Ether(dst=in_if.local_mac, src=in_if.remote_mac) /
             IP(src=in_if.remote_ip4, dst=out_if.remote_ip4, ttl=ttl) /
             TCP(sport=self.tcp_port_in, dport=self.tcp_external_port))
        pkts.append(p)

        # UDP
        p = (Ether(dst=in_if.local_mac, src=in_if.remote_mac) /
             IP(src=in_if.remote_ip4, dst=out_if.remote_ip4, ttl=ttl) /
             UDP(sport=self.udp_port_in, dport=self.udp_external_port))
        pkts.append(p)

        # ICMP
        p = (Ether(dst=in_if.local_mac, src=in_if.remote_mac) /
             IP(src=in_if.remote_ip4, dst=out_if.remote_ip4, ttl=ttl) /
             ICMP(id=self.icmp_id_in, type='echo-request'))
        pkts.append(p)

        return pkts

    def create_stream_out(self, out_if, dst_ip=None, ttl=64):
        """
        Create packet stream for outside network

        :param out_if: Outside interface
        :param dst_ip: Destination IP address (Default use global NAT address)
        :param ttl: TTL of generated packets
        """
        if dst_ip is None:
            dst_ip = self.nat_addr
        pkts = []
        # TCP
        p = (Ether(dst=out_if.local_mac, src=out_if.remote_mac) /
             IP(src=out_if.remote_ip4, dst=dst_ip, ttl=ttl) /
             TCP(dport=self.tcp_port_out, sport=self.tcp_external_port))
        pkts.append(p)

        # UDP
        p = (Ether(dst=out_if.local_mac, src=out_if.remote_mac) /
             IP(src=out_if.remote_ip4, dst=dst_ip, ttl=ttl) /
             UDP(dport=self.udp_port_out, sport=self.udp_external_port))
        pkts.append(p)

        # ICMP
        p = (Ether(dst=out_if.local_mac, src=out_if.remote_mac) /
             IP(src=out_if.remote_ip4, dst=dst_ip, ttl=ttl) /
             ICMP(id=self.icmp_external_id, type='echo-reply'))
        pkts.append(p)

        return pkts

    def verify_capture_out(self, capture, nat_ip=None):
        """
        Verify captured packets on outside network

        :param capture: Captured packets
        :param nat_ip: Translated IP address (Default use global NAT address)
        :param same_port: Source port number is not translated (Default False)
        """
        if nat_ip is None:
            nat_ip = self.nat_addr
        for packet in capture:
            try:
                self.assertEqual(packet[IP].src, nat_ip)
                if packet.haslayer(TCP):
                    self.tcp_port_out = packet[TCP].sport
                elif packet.haslayer(UDP):
                    self.udp_port_out = packet[UDP].sport
                else:
                    self.icmp_external_id = packet[ICMP].id
            except:
                self.logger.error(ppp("Unexpected or invalid packet "
                                      "(outside network):", packet))
                raise

    def test_deterministic_mode(self):
        """ NAT plugin run deterministic mode """
        in_addr = '172.16.255.0'
        out_addr = '172.17.255.50'
        in_addr_t = '172.16.255.20'
        in_plen = 24
        out_plen = 32

        self.vapi.det44_add_del_map(is_add=1, in_addr=in_addr,
                                    in_plen=in_plen, out_addr=out_addr,
                                    out_plen=out_plen)

        rep1 = self.vapi.det44_forward(in_addr_t)
        self.assertEqual(str(rep1.out_addr), out_addr)
        rep2 = self.vapi.det44_reverse(rep1.out_port_hi, out_addr)

        self.assertEqual(str(rep2.in_addr), in_addr_t)

        deterministic_mappings = self.vapi.det44_map_dump()
        self.assertEqual(len(deterministic_mappings), 1)
        dsm = deterministic_mappings[0]
        self.assertEqual(in_addr, str(dsm.in_addr))
        self.assertEqual(in_plen, dsm.in_plen)
        self.assertEqual(out_addr, str(dsm.out_addr))
        self.assertEqual(out_plen, dsm.out_plen)

    def test_set_timeouts(self):
        """ Set deterministic NAT timeouts """
        timeouts_before = self.vapi.det44_get_timeouts()

        self.vapi.det44_set_timeouts(
            udp=timeouts_before.udp + 10,
            tcp_established=timeouts_before.tcp_established + 10,
            tcp_transitory=timeouts_before.tcp_transitory + 10,
            icmp=timeouts_before.icmp + 10)

        timeouts_after = self.vapi.det44_get_timeouts()

        self.assertNotEqual(timeouts_before.udp, timeouts_after.udp)
        self.assertNotEqual(timeouts_before.icmp, timeouts_after.icmp)
        self.assertNotEqual(timeouts_before.tcp_established,
                            timeouts_after.tcp_established)
        self.assertNotEqual(timeouts_before.tcp_transitory,
                            timeouts_after.tcp_transitory)

    def test_in(self):
        """ DET44 translation test (TCP, UDP, ICMP) """

        nat_ip = "10.0.0.10"

        self.vapi.det44_add_del_map(is_add=1, in_addr=self.pg0.remote_ip4,
                                    in_plen=32,
                                    out_addr=socket.inet_aton(nat_ip),
                                    out_plen=32)

        self.vapi.det44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            is_add=1, is_inside=1)
        self.vapi.det44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1, is_inside=0)

        # in2out
        pkts = self.create_stream_in(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_out(capture, nat_ip)

        # out2in
        pkts = self.create_stream_out(self.pg1, nat_ip)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(len(pkts))
        self.verify_capture_in(capture, self.pg0)

        # session dump test
        sessions = self.vapi.det44_session_dump(self.pg0.remote_ip4)
        self.assertEqual(len(sessions), 3)

        # TCP session
        s = sessions[0]
        self.assertEqual(str(s.ext_addr), self.pg1.remote_ip4)
        self.assertEqual(s.in_port, self.tcp_port_in)
        self.assertEqual(s.out_port, self.tcp_port_out)
        self.assertEqual(s.ext_port, self.tcp_external_port)

        # UDP session
        s = sessions[1]
        self.assertEqual(str(s.ext_addr), self.pg1.remote_ip4)
        self.assertEqual(s.in_port, self.udp_port_in)
        self.assertEqual(s.out_port, self.udp_port_out)
        self.assertEqual(s.ext_port, self.udp_external_port)

        # ICMP session
        s = sessions[2]
        self.assertEqual(str(s.ext_addr), self.pg1.remote_ip4)
        self.assertEqual(s.in_port, self.icmp_id_in)
        self.assertEqual(s.out_port, self.icmp_external_id)

    def test_multiple_users(self):
        """ Deterministic NAT multiple users """

        nat_ip = "10.0.0.10"
        port_in = 80
        external_port = 6303

        host0 = self.pg0.remote_hosts[0]
        host1 = self.pg0.remote_hosts[1]

        self.vapi.det44_add_del_map(is_add=1, in_addr=host0.ip4, in_plen=24,
                                    out_addr=socket.inet_aton(nat_ip),
                                    out_plen=32)
        self.vapi.det44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            is_add=1, is_inside=1)
        self.vapi.det44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1, is_inside=0)

        # host0 to out
        p = (Ether(src=host0.mac, dst=self.pg0.local_mac) /
             IP(src=host0.ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=port_in, dport=external_port))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.src, nat_ip)
            self.assertEqual(ip.dst, self.pg1.remote_ip4)
            self.assertEqual(tcp.dport, external_port)
            port_out0 = tcp.sport
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        # host1 to out
        p = (Ether(src=host1.mac, dst=self.pg0.local_mac) /
             IP(src=host1.ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=port_in, dport=external_port))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.src, nat_ip)
            self.assertEqual(ip.dst, self.pg1.remote_ip4)
            self.assertEqual(tcp.dport, external_port)
            port_out1 = tcp.sport
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        dms = self.vapi.det44_map_dump()
        self.assertEqual(1, len(dms))
        self.assertEqual(2, dms[0].ses_num)

        # out to host0
        p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
             IP(src=self.pg1.remote_ip4, dst=nat_ip) /
             TCP(sport=external_port, dport=port_out0))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.src, self.pg1.remote_ip4)
            self.assertEqual(ip.dst, host0.ip4)
            self.assertEqual(tcp.dport, port_in)
            self.assertEqual(tcp.sport, external_port)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        # out to host1
        p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
             IP(src=self.pg1.remote_ip4, dst=nat_ip) /
             TCP(sport=external_port, dport=port_out1))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.src, self.pg1.remote_ip4)
            self.assertEqual(ip.dst, host1.ip4)
            self.assertEqual(tcp.dport, port_in)
            self.assertEqual(tcp.sport, external_port)
        except:
            self.logger.error(ppp("Unexpected or invalid packet", p))
            raise

        # session close api test
        self.vapi.det44_close_session_out(socket.inet_aton(nat_ip),
                                          port_out1,
                                          self.pg1.remote_ip4,
                                          external_port)
        dms = self.vapi.det44_map_dump()
        self.assertEqual(dms[0].ses_num, 1)

        self.vapi.det44_close_session_in(host0.ip4,
                                         port_in,
                                         self.pg1.remote_ip4,
                                         external_port)
        dms = self.vapi.det44_map_dump()
        self.assertEqual(dms[0].ses_num, 0)

    def test_tcp_session_close_detection_in(self):
        """ DET44 TCP session close from inside network """
        self.vapi.det44_add_del_map(is_add=1, in_addr=self.pg0.remote_ip4,
                                    in_plen=32,
                                    out_addr=socket.inet_aton(self.nat_addr),
                                    out_plen=32)
        self.vapi.det44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            is_add=1, is_inside=1)
        self.vapi.det44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1, is_inside=0)

        self.initiate_tcp_session(self.pg0, self.pg1)

        # close the session from inside
        try:
            # FIN packet in -> out
            p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
                 IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
                 TCP(sport=self.tcp_port_in, dport=self.tcp_external_port,
                     flags="F"))
            self.pg0.add_stream(p)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            self.pg1.get_capture(1)

            pkts = []

            # ACK packet out -> in
            p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
                 IP(src=self.pg1.remote_ip4, dst=self.nat_addr) /
                 TCP(sport=self.tcp_external_port, dport=self.tcp_port_out,
                     flags="A"))
            pkts.append(p)

            # FIN packet out -> in
            p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
                 IP(src=self.pg1.remote_ip4, dst=self.nat_addr) /
                 TCP(sport=self.tcp_external_port, dport=self.tcp_port_out,
                     flags="F"))
            pkts.append(p)

            self.pg1.add_stream(pkts)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            self.pg0.get_capture(2)

            # ACK packet in -> out
            p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
                 IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
                 TCP(sport=self.tcp_port_in, dport=self.tcp_external_port,
                     flags="A"))
            self.pg0.add_stream(p)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            self.pg1.get_capture(1)

            # Check if deterministic NAT44 closed the session
            dms = self.vapi.det44_map_dump()
            self.assertEqual(0, dms[0].ses_num)
        except:
            self.logger.error("TCP session termination failed")
            raise

    def test_tcp_session_close_detection_out(self):
        """ Deterministic NAT TCP session close from outside network """
        self.vapi.det44_add_del_map(is_add=1, in_addr=self.pg0.remote_ip4,
                                    in_plen=32,
                                    out_addr=socket.inet_aton(self.nat_addr),
                                    out_plen=32)
        self.vapi.det44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            is_add=1, is_inside=1)
        self.vapi.det44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1, is_inside=0)

        self.initiate_tcp_session(self.pg0, self.pg1)

        # close the session from outside
        try:
            # FIN packet out -> in
            p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
                 IP(src=self.pg1.remote_ip4, dst=self.nat_addr) /
                 TCP(sport=self.tcp_external_port, dport=self.tcp_port_out,
                     flags="F"))
            self.pg1.add_stream(p)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            self.pg0.get_capture(1)

            pkts = []

            # ACK packet in -> out
            p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
                 IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
                 TCP(sport=self.tcp_port_in, dport=self.tcp_external_port,
                     flags="A"))
            pkts.append(p)

            # ACK packet in -> out
            p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
                 IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
                 TCP(sport=self.tcp_port_in, dport=self.tcp_external_port,
                     flags="F"))
            pkts.append(p)

            self.pg0.add_stream(pkts)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            self.pg1.get_capture(2)

            # ACK packet out -> in
            p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
                 IP(src=self.pg1.remote_ip4, dst=self.nat_addr) /
                 TCP(sport=self.tcp_external_port, dport=self.tcp_port_out,
                     flags="A"))
            self.pg1.add_stream(p)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            self.pg0.get_capture(1)

            # Check if deterministic NAT44 closed the session
            dms = self.vapi.det44_map_dump()
            self.assertEqual(0, dms[0].ses_num)
        except:
            self.logger.error("TCP session termination failed")
            raise

    def test_session_timeout(self):
        """ Deterministic NAT session timeouts """
        self.vapi.det44_add_del_map(is_add=1, in_addr=self.pg0.remote_ip4,
                                    in_plen=32,
                                    out_addr=socket.inet_aton(self.nat_addr),
                                    out_plen=32)
        self.vapi.det44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            is_add=1, is_inside=1)
        self.vapi.det44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1, is_inside=0)

        self.initiate_tcp_session(self.pg0, self.pg1)
        self.vapi.det44_set_timeouts(udp=5, tcp_established=5,
                                     tcp_transitory=5, icmp=5)
        pkts = self.create_stream_in(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.get_capture(len(pkts))
        self.virtual_sleep(15)

        dms = self.vapi.det44_map_dump()
        self.assertEqual(0, dms[0].ses_num)

    # TODO: ipfix needs to be separated from NAT base plugin
    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_session_limit_per_user(self):
        """ Deterministic NAT maximum sessions per user limit """
        self.vapi.det44_add_del_map(is_add=1, in_addr=self.pg0.remote_ip4,
                                    in_plen=32,
                                    out_addr=socket.inet_aton(self.nat_addr),
                                    out_plen=32)
        self.vapi.det44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            is_add=1, is_inside=1)
        self.vapi.det44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1, is_inside=0)
        self.vapi.set_ipfix_exporter(collector_address=self.pg2.remote_ip4,
                                     src_address=self.pg2.local_ip4,
                                     path_mtu=512,
                                     template_interval=10)
        self.vapi.nat_ipfix_enable_disable(domain_id=1, src_port=4739,
                                           enable=1)

        pkts = []
        for port in range(1025, 2025):
            p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
                 IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
                 UDP(sport=port, dport=port))
            pkts.append(p)

        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.get_capture(len(pkts))

        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             UDP(sport=3001, dport=3002))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.assert_nothing_captured()

        # verify ICMP error packet
        capture = self.pg0.get_capture(1)
        p = capture[0]
        self.assertTrue(p.haslayer(ICMP))
        icmp = p[ICMP]
        self.assertEqual(icmp.type, 3)
        self.assertEqual(icmp.code, 1)
        self.assertTrue(icmp.haslayer(IPerror))
        inner_ip = icmp[IPerror]
        self.assertEqual(inner_ip[UDPerror].sport, 3001)
        self.assertEqual(inner_ip[UDPerror].dport, 3002)

        dms = self.vapi.det44_map_dump()

        self.assertEqual(1000, dms[0].ses_num)

        # verify IPFIX logging
        self.vapi.ipfix_flush()
        capture = self.pg2.get_capture(2)
        ipfix = IPFIXDecoder()
        # first load template
        for p in capture:
            self.assertTrue(p.haslayer(IPFIX))
            if p.haslayer(Template):
                ipfix.add_template(p.getlayer(Template))
        # verify events in data set
        for p in capture:
            if p.haslayer(Data):
                data = ipfix.decode_data_set(p.getlayer(Set))
                self.verify_ipfix_max_entries_per_user(data,
                                                       1000,
                                                       self.pg0.remote_ip4)
        self.vapi.nat_ipfix_enable_disable(domain_id=1, src_port=4739,
                                           enable=0)
