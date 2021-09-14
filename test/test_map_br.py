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

import ipaddress
import unittest

from framework import VppTestCase, VppTestRunner
from vpp_ip import DpoProto
from vpp_ip_route import VppIpRoute, VppRoutePath
from util import fragment_rfc791, fragment_rfc8200

import scapy.compat
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.layers.inet import IP, UDP, ICMP, TCP, IPerror, UDPerror
from scapy.layers.inet6 import IPv6, ICMPv6TimeExceeded, ICMPv6PacketTooBig
from scapy.layers.inet6 import ICMPv6EchoRequest, ICMPv6EchoReply, IPerror6


class TestMAPBR(VppTestCase):
    """ MAP-T Test Cases """

    @classmethod
    def setUpClass(cls):
        super(TestMAPBR, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestMAPBR, cls).tearDownClass()

    def setUp(self):
        super(TestMAPBR, self).setUp()

        #
        # Create 2 pg interfaces.
        # pg0 is IPv4
        # pg1 is IPv6
        #
        self.create_pg_interfaces(range(2))

        self.pg0.admin_up()
        self.pg0.config_ip4()
        self.pg1.generate_remote_hosts(20)
        self.pg1.configure_ipv4_neighbors()
        self.pg0.resolve_arp()

        self.pg1.admin_up()
        self.pg1.config_ip6()
        self.pg1.generate_remote_hosts(20)
        self.pg1.configure_ipv6_neighbors()

        #
        # BR configuration parameters used for all test.
        #
        self.ip4_prefix = '198.18.0.0/24'
        self.ip6_prefix = '2001:db8:f0::/48'
        self.ip6_src = '2001:db8:ffff:ff00::/64'
        self.ea_bits_len = 12
        self.psid_offset = 6
        self.psid_length = 4
        self.mtu = 1500
        self.tag = 'MAP-T BR'

        self.ipv4_internet_address = self.pg0.remote_ip4
        self.ipv4_map_address = "198.18.0.12"
        self.ipv4_udp_or_tcp_internet_port = 65000
        self.ipv4_udp_or_tcp_map_port = 16606

        self.ipv6_cpe_address = "2001:db8:f0:c30:0:c612:c:3"      # 198.18.0.12
        self.ipv6_spoof_address = "2001:db8:f0:c30:0:c612:1c:3"   # 198.18.0.28
        self.ipv6_spoof_prefix = "2001:db8:f0:c30:0:a00:c:3"      # 10.0.0.12
        self.ipv6_spoof_psid = "2001:db8:f0:c30:0:c612:c:4"       # 4
        self.ipv6_spoof_subnet = "2001:db8:f1:c30:0:c612:c:3"     # f1

        self.ipv6_udp_or_tcp_internet_port = 65000
        self.ipv6_udp_or_tcp_map_port = 16606
        self.ipv6_udp_or_tcp_spoof_port = 16862

        self.ipv6_map_address = (
            "2001:db8:ffff:ff00:ac:1001:200:0")         # 176.16.1.2
        self.ipv6_map_same_rule_diff_addr = (
            "2001:db8:ffff:ff00:c6:1200:1000:0")        # 198.18.0.16
        self.ipv6_map_same_rule_same_addr = (
            "2001:db8:ffff:ff00:c6:1200:c00:0")         # 198.18.0.12

        self.map_br_prefix = "2001:db8:f0::"
        self.map_br_prefix_len = 48
        self.psid_number = 3

        #
        # Add an IPv6 route to the MAP-BR.
        #
        map_route = VppIpRoute(self,
                               self.map_br_prefix,
                               self.map_br_prefix_len,
                               [VppRoutePath(self.pg1.remote_ip6,
                                             self.pg1.sw_if_index)])
        map_route.add_vpp_config()

        #
        # Add a MAP BR domain that maps from pg0 to pg1.
        #
        self.vapi.map_add_domain(ip4_prefix=self.ip4_prefix,
                                 ip6_prefix=self.ip6_prefix,
                                 ip6_src=self.ip6_src,
                                 ea_bits_len=self.ea_bits_len,
                                 psid_offset=self.psid_offset,
                                 psid_length=self.psid_length,
                                 mtu=self.mtu,
                                 tag=self.tag)

        #
        # Set BR parameters.
        #
        self.vapi.map_param_set_fragmentation(inner=1, ignore_df=0)
        self.vapi.map_param_set_fragmentation(inner=0, ignore_df=0)
        self.vapi.map_param_set_icmp(ip4_err_relay_src=self.pg0.local_ip4)
        self.vapi.map_param_set_traffic_class(copy=1)

        #
        # Enable MAP-T on interfaces.
        #
        self.vapi.map_if_enable_disable(is_enable=1,
                                        sw_if_index=self.pg0.sw_if_index,
                                        is_translation=1)

        self.vapi.map_if_enable_disable(is_enable=1,
                                        sw_if_index=self.pg1.sw_if_index,
                                        is_translation=1)

        self.vapi.map_if_enable_disable(is_enable=1,
                                        sw_if_index=self.pg1.sw_if_index,
                                        is_translation=1)

    def tearDown(self):
        super(TestMAPBR, self).tearDown()
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.admin_down()

    def v4_address_check(self, pkt):
        self.assertEqual(pkt[IP].src, self.ipv4_map_address)
        self.assertEqual(pkt[IP].dst, self.ipv4_internet_address)

    def v4_port_check(self, pkt, proto):
        self.assertEqual(pkt[proto].sport, self.ipv4_udp_or_tcp_map_port)
        self.assertEqual(pkt[proto].dport, self.ipv4_udp_or_tcp_internet_port)

    def v6_address_check(self, pkt):
        self.assertEqual(pkt[IPv6].src, self.ipv6_map_address)
        self.assertEqual(pkt[IPv6].dst, self.ipv6_cpe_address)

    def v6_port_check(self, pkt, proto):
        self.assertEqual(pkt[proto].sport, self.ipv6_udp_or_tcp_internet_port)
        self.assertEqual(pkt[proto].dport, self.ipv6_udp_or_tcp_map_port)

    #
    # Normal translation of UDP packets v4 -> v6 direction
    # Send 128 frame size packet for IPv4/UDP.
    # Received packet should be translated into IPv6 packet with no
    # fragment header.
    #

    def test_map_t_udp_ip4_to_ip6(self):
        """ MAP-T UDP IPv4 -> IPv6 """

        eth = Ether(src=self.pg0.remote_mac,
                    dst=self.pg0.local_mac)
        ip = IP(src=self.pg0.remote_ip4,
                dst=self.ipv4_map_address,
                tos=0)
        udp = UDP(sport=self.ipv4_udp_or_tcp_internet_port,
                  dport=self.ipv4_udp_or_tcp_map_port)
        payload = "a" * 82
        tx_pkt = eth / ip / udp / payload

        self.pg_send(self.pg0, tx_pkt * 1)

        rx_pkts = self.pg1.get_capture(1)
        rx_pkt = rx_pkts[0]

        self.v6_address_check(rx_pkt)
        self.v6_port_check(rx_pkt, UDP)
        self.assertEqual(rx_pkt[IPv6].tc, 0)    # IPv4 ToS passed to v6 TC
        self.assertEqual(rx_pkt[IPv6].nh, IPv6(nh="UDP").nh)

    #
    # Normal translation of TCP packets v4 -> v6 direction.
    # Send 128 frame size packet for IPv4/TCP.
    # Received packet should be translated into IPv6 packet with no
    # fragment header.
    #

    def test_map_t_tcp_ip4_to_ip6(self):
        """ MAP-T TCP IPv4 -> IPv6 """

        eth = Ether(src=self.pg0.remote_mac,
                    dst=self.pg0.local_mac)
        ip = IP(src=self.pg0.remote_ip4,
                dst=self.ipv4_map_address,
                tos=0)
        tcp = TCP(sport=self.ipv4_udp_or_tcp_internet_port,
                  dport=self.ipv4_udp_or_tcp_map_port)
        payload = "a" * 82
        tx_pkt = eth / ip / tcp / payload

        self.pg_send(self.pg0, tx_pkt * 1)

        rx_pkts = self.pg1.get_capture(1)
        rx_pkt = rx_pkts[0]

        self.v6_address_check(rx_pkt)
        self.v6_port_check(rx_pkt, TCP)
        self.assertEqual(rx_pkt[IPv6].tc, 0)    # IPv4 ToS passed to v6 TC
        self.assertEqual(rx_pkt[IPv6].nh, IPv6(nh="TCP").nh)

    #
    # Normal translation of UDP packets v6 -> v4 direction
    # Send 128 frame size packet for IPv6/UDP.
    # Received packet should be translated into an IPv4 packet with DF=1.
    #

    def test_map_t_udp_ip6_to_ip4(self):
        """ MAP-T UDP IPv6 -> IPv4 """

        eth = Ether(src=self.pg1.remote_mac,
                    dst=self.pg1.local_mac)
        ip = IPv6(src=self.ipv6_cpe_address,
                  dst=self.ipv6_map_address)
        udp = UDP(sport=self.ipv6_udp_or_tcp_map_port,
                  dport=self.ipv6_udp_or_tcp_internet_port)
        payload = "a" * 82
        tx_pkt = eth / ip / udp / payload

        self.pg_send(self.pg1, tx_pkt * 1)

        rx_pkts = self.pg0.get_capture(1)
        rx_pkt = rx_pkts[0]

        self.v4_address_check(rx_pkt)
        self.v4_port_check(rx_pkt, UDP)
        self.assertEqual(rx_pkt[IP].proto, IP(proto="udp").proto)
        self.assertEqual(rx_pkt[IP].tos, 0)    # IPv6 TC passed to v4 ToS
        df_bit = IP(flags="DF").flags
        self.assertNotEqual(rx_pkt[IP].flags & df_bit, df_bit)

    #
    # Normal translation of TCP packets v6 -> v4 direction
    # Send 128 frame size packet for IPv6/TCP.
    # Received packet should be translated into an IPv4 packet with DF=1
    #

    def test_map_t_tcp_ip6_to_ip4(self):
        """ MAP-T TCP IPv6 -> IPv4 """

        eth = Ether(src=self.pg1.remote_mac,
                    dst=self.pg1.local_mac)
        ip = IPv6(src=self.ipv6_cpe_address,
                  dst=self.ipv6_map_address)
        tcp = TCP(sport=self.ipv6_udp_or_tcp_map_port,
                  dport=self.ipv6_udp_or_tcp_internet_port)
        payload = "a" * 82
        tx_pkt = eth / ip / tcp / payload

        self.pg_send(self.pg1, tx_pkt * 1)

        rx_pkts = self.pg0.get_capture(1)
        rx_pkt = rx_pkts[0]

        self.v4_address_check(rx_pkt)
        self.v4_port_check(rx_pkt, TCP)
        self.assertEqual(rx_pkt[IP].proto, IP(proto="tcp").proto)
        self.assertEqual(rx_pkt[IP].tos, 0)    # IPv6 TC passed to v4 ToS
        df_bit = IP(flags="DF").flags
        self.assertNotEqual(rx_pkt[IP].flags & df_bit, df_bit)

    #
    # Translation of ICMP Echo Request v4 -> v6 direction
    # Received packet should be translated into an IPv6 Echo Request.
    #

    def test_map_t_echo_request_ip4_to_ip6(self):
        """ MAP-T echo request IPv4 -> IPv6 """

        eth = Ether(src=self.pg1.remote_mac,
                    dst=self.pg1.local_mac)
        ip = IP(src=self.pg0.remote_ip4,
                dst=self.ipv4_map_address)
        icmp = ICMP(type="echo-request",
                    id=self.ipv6_udp_or_tcp_map_port)
        payload = "H" * 10
        tx_pkt = eth / ip / icmp / payload

        self.pg_send(self.pg0, tx_pkt * 1)

        rx_pkts = self.pg1.get_capture(1)
        rx_pkt = rx_pkts[0]

        self.assertEqual(rx_pkt[IPv6].nh, IPv6(nh="ICMPv6").nh)
        self.assertEqual(rx_pkt[ICMPv6EchoRequest].type,
                         ICMPv6EchoRequest(type="Echo Request").type)
        self.assertEqual(rx_pkt[ICMPv6EchoRequest].code, 0)
        self.assertEqual(rx_pkt[ICMPv6EchoRequest].id,
                         self.ipv6_udp_or_tcp_map_port)

    #
    # Translation of ICMP Echo Reply v4 -> v6 direction
    # Received packet should be translated into an IPv6 Echo Reply.
    #

    def test_map_t_echo_reply_ip4_to_ip6(self):
        """ MAP-T echo reply IPv4 -> IPv6 """

        eth = Ether(src=self.pg1.remote_mac,
                    dst=self.pg1.local_mac)
        ip = IP(src=self.pg0.remote_ip4,
                dst=self.ipv4_map_address)
        icmp = ICMP(type="echo-reply",
                    id=self.ipv6_udp_or_tcp_map_port)
        payload = "H" * 10
        tx_pkt = eth / ip / icmp / payload

        self.pg_send(self.pg0, tx_pkt * 1)

        rx_pkts = self.pg1.get_capture(1)
        rx_pkt = rx_pkts[0]

        self.assertEqual(rx_pkt[IPv6].nh, IPv6(nh="ICMPv6").nh)
        self.assertEqual(rx_pkt[ICMPv6EchoReply].type,
                         ICMPv6EchoReply(type="Echo Reply").type)
        self.assertEqual(rx_pkt[ICMPv6EchoReply].code, 0)
        self.assertEqual(rx_pkt[ICMPv6EchoReply].id,
                         self.ipv6_udp_or_tcp_map_port)

    #
    # Translation of ICMP Time Exceeded v4 -> v6 direction
    # Received packet should be translated into an IPv6 Time Exceeded.
    #

    def test_map_t_time_exceeded_ip4_to_ip6(self):
        """ MAP-T time exceeded IPv4 -> IPv6 """

        eth = Ether(src=self.pg0.remote_mac,
                    dst=self.pg0.local_mac)
        ip = IP(src=self.pg0.remote_ip4,
                dst=self.ipv4_map_address)
        icmp = ICMP(type="time-exceeded", code="ttl-zero-during-transit")
        ip_inner = IP(dst=self.pg0.remote_ip4,
                      src=self.ipv4_map_address, ttl=1)
        udp_inner = UDP(sport=self.ipv4_udp_or_tcp_map_port,
                        dport=self.ipv4_udp_or_tcp_internet_port)
        payload = "H" * 10
        tx_pkt = eth / ip / icmp / ip_inner / udp_inner / payload

        self.pg_send(self.pg0, tx_pkt * 1)

        rx_pkts = self.pg1.get_capture(1)
        rx_pkt = rx_pkts[0]

        self.v6_address_check(rx_pkt)
        self.assertEqual(rx_pkt[IPv6].nh, IPv6(nh="ICMPv6").nh)
        self.assertEqual(rx_pkt[ICMPv6TimeExceeded].type,
                         ICMPv6TimeExceeded().type)
        self.assertEqual(rx_pkt[ICMPv6TimeExceeded].code,
                         ICMPv6TimeExceeded(
                            code="hop limit exceeded in transit").code)
        self.assertEqual(rx_pkt[ICMPv6TimeExceeded].hlim, tx_pkt[IP][1].ttl)
        self.assertTrue(rx_pkt.haslayer(IPerror6))
        self.assertTrue(rx_pkt.haslayer(UDPerror))
        self.assertEqual(rx_pkt[IPv6].src, rx_pkt[IPerror6].dst)
        self.assertEqual(rx_pkt[IPv6].dst, rx_pkt[IPerror6].src)
        self.assertEqual(rx_pkt[UDPerror].sport, self.ipv6_udp_or_tcp_map_port)
        self.assertEqual(rx_pkt[UDPerror].dport,
                         self.ipv6_udp_or_tcp_internet_port)

    #
    # Translation of ICMP Echo Request v6 -> v4 direction
    # Received packet should be translated into an IPv4 Echo Request.
    #

    def test_map_t_echo_request_ip6_to_ip4(self):
        """ MAP-T echo request IPv6 -> IPv4 """

        eth = Ether(src=self.pg1.remote_mac,
                    dst=self.pg1.local_mac)
        ip = IPv6(src=self.ipv6_cpe_address,
                  dst=self.ipv6_map_address)
        icmp = ICMPv6EchoRequest()
        icmp.id = self.ipv6_udp_or_tcp_map_port
        payload = "H" * 10
        tx_pkt = eth / ip / icmp / payload

        self.pg_send(self.pg1, tx_pkt * 1)

        rx_pkts = self.pg0.get_capture(1)
        rx_pkt = rx_pkts[0]

        self.assertEqual(rx_pkt[IP].proto, IP(proto="icmp").proto)
        self.assertEqual(rx_pkt[ICMP].type, ICMP(type="echo-request").type)
        self.assertEqual(rx_pkt[ICMP].code, 0)
        self.assertEqual(rx_pkt[ICMP].id, self.ipv6_udp_or_tcp_map_port)

    #
    # Translation of ICMP Echo Reply v6 -> v4 direction
    # Received packet should be translated into an IPv4 Echo Reply.
    #

    def test_map_t_echo_reply_ip6_to_ip4(self):
        """ MAP-T echo reply IPv6 -> IPv4 """

        eth = Ether(src=self.pg1.remote_mac,
                    dst=self.pg1.local_mac)
        ip = IPv6(src=self.ipv6_cpe_address,
                  dst=self.ipv6_map_address)
        icmp = ICMPv6EchoReply(id=self.ipv6_udp_or_tcp_map_port)
        payload = "H" * 10
        tx_pkt = eth / ip / icmp / payload

        self.pg_send(self.pg1, tx_pkt * 1)

        rx_pkts = self.pg0.get_capture(1)
        rx_pkt = rx_pkts[0]

        self.assertEqual(rx_pkt[IP].proto, IP(proto="icmp").proto)
        self.assertEqual(rx_pkt[ICMP].type, ICMP(type="echo-reply").type)
        self.assertEqual(rx_pkt[ICMP].code, 0)
        self.assertEqual(rx_pkt[ICMP].id, self.ipv6_udp_or_tcp_map_port)

    #
    # Translation of ICMP Packet Too Big v6 -> v4 direction
    # Received packet should be translated into an IPv4 Dest Unreachable.
    #

    def test_map_t_packet_too_big_ip6_to_ip4(self):
        """ MAP-T packet too big IPv6 -> IPv4 """

        eth = Ether(src=self.pg1.remote_mac,
                    dst=self.pg1.local_mac)
        ip = IPv6(src=self.ipv6_cpe_address,
                  dst=self.ipv6_map_address)
        icmp = ICMPv6PacketTooBig(mtu=1280)
        ip_inner = IPv6(src=self.ipv6_map_address,
                        dst=self.ipv6_cpe_address)
        udp_inner = UDP(sport=self.ipv6_udp_or_tcp_internet_port,
                        dport=self.ipv6_udp_or_tcp_map_port)
        payload = "H" * 10
        tx_pkt = eth / ip / icmp / ip_inner / udp_inner / payload

        self.pg_send(self.pg1, tx_pkt * 1)

        rx_pkts = self.pg0.get_capture(1)
        rx_pkt = rx_pkts[0]

        self.v4_address_check(rx_pkt)
        self.assertEqual(rx_pkt[IP].proto, IP(proto="icmp").proto)
        self.assertEqual(rx_pkt[ICMP].type, ICMP(type="dest-unreach").type)
        self.assertEqual(rx_pkt[ICMP].code,
                         ICMP(code="fragmentation-needed").code)
        self.assertEqual(rx_pkt[ICMP].nexthopmtu,
                         tx_pkt[ICMPv6PacketTooBig].mtu - 20)
        self.assertTrue(rx_pkt.haslayer(IPerror))
        self.assertTrue(rx_pkt.haslayer(UDPerror))
        self.assertEqual(rx_pkt[IP].src, rx_pkt[IPerror].dst)
        self.assertEqual(rx_pkt[IP].dst, rx_pkt[IPerror].src)
        self.assertEqual(rx_pkt[UDPerror].sport,
                         self.ipv4_udp_or_tcp_internet_port)
        self.assertEqual(rx_pkt[UDPerror].dport, self.ipv4_udp_or_tcp_map_port)

    #
    # Translation of ICMP Time Exceeded v6 -> v4 direction
    # Received packet should be translated into an IPv4 Time Exceeded.
    #

    def test_map_t_time_exceeded_ip6_to_ip4(self):
        """ MAP-T time exceeded IPv6 -> IPv4 """

        eth = Ether(src=self.pg1.remote_mac,
                    dst=self.pg1.local_mac)
        ip = IPv6(src=self.ipv6_cpe_address,
                  dst=self.ipv6_map_address)
        icmp = ICMPv6TimeExceeded()
        ip_inner = IPv6(src=self.ipv6_map_address,
                        dst=self.ipv6_cpe_address, hlim=1)
        udp_inner = UDP(sport=self.ipv6_udp_or_tcp_internet_port,
                        dport=self.ipv6_udp_or_tcp_map_port)
        payload = "H" * 10
        tx_pkt = eth / ip / icmp / ip_inner / udp_inner / payload

        self.pg_send(self.pg1, tx_pkt * 1)

        rx_pkts = self.pg0.get_capture(1)
        rx_pkt = rx_pkts[0]

        self.v4_address_check(rx_pkt)
        self.assertEqual(rx_pkt[IP].proto, IP(proto="icmp").proto)
        self.assertEqual(rx_pkt[ICMP].type, ICMP(type="time-exceeded").type)
        self.assertEqual(rx_pkt[ICMP].code,
                         ICMP(code="ttl-zero-during-transit").code)
        self.assertEqual(rx_pkt[ICMP].ttl, tx_pkt[IPv6][1].hlim)
        self.assertTrue(rx_pkt.haslayer(IPerror))
        self.assertTrue(rx_pkt.haslayer(UDPerror))
        self.assertEqual(rx_pkt[IP].src, rx_pkt[IPerror].dst)
        self.assertEqual(rx_pkt[IP].dst, rx_pkt[IPerror].src)
        self.assertEqual(rx_pkt[UDPerror].sport,
                         self.ipv4_udp_or_tcp_internet_port)
        self.assertEqual(rx_pkt[UDPerror].dport, self.ipv4_udp_or_tcp_map_port)

    #
    # Spoofed IPv4 Source Address v6 -> v4 direction
    # Send a packet with a wrong IPv4 address embedded in bits 72-103.
    # The BR should either drop the packet, or rewrite the spoofed
    # source IPv4 as the actual source IPv4 address.
    # The BR really should drop the packet.
    #

    def test_map_t_spoof_ipv4_src_addr_ip6_to_ip4(self):
        """ MAP-T spoof ipv4 src addr IPv6 -> IPv4 """

        eth = Ether(src=self.pg1.remote_mac,
                    dst=self.pg1.local_mac)
        ip = IPv6(src=self.ipv6_spoof_address,
                  dst=self.ipv6_map_address)
        udp = UDP(sport=self.ipv6_udp_or_tcp_map_port,
                  dport=self.ipv6_udp_or_tcp_internet_port)
        payload = "a" * 82
        tx_pkt = eth / ip / udp / payload

        self.pg_send(self.pg1, tx_pkt * 1)

        self.pg0.get_capture(0, timeout=1)
        self.pg0.assert_nothing_captured("Should drop IPv4 spoof address")

    #
    # Spoofed IPv4 Source Prefix v6 -> v4 direction
    # Send a packet with a wrong IPv4 prefix embedded in bits 72-103.
    # The BR should either drop the packet, or rewrite the source IPv4
    # to the prefix that matches the source IPv4 address.
    #

    def test_map_t_spoof_ipv4_src_prefix_ip6_to_ip4(self):
        """ MAP-T spoof ipv4 src prefix IPv6 -> IPv4 """

        eth = Ether(src=self.pg1.remote_mac,
                    dst=self.pg1.local_mac)
        ip = IPv6(src=self.ipv6_spoof_prefix,
                  dst=self.ipv6_map_address)
        udp = UDP(sport=self.ipv6_udp_or_tcp_map_port,
                  dport=self.ipv6_udp_or_tcp_internet_port)
        payload = "a" * 82
        tx_pkt = eth / ip / udp / payload

        self.pg_send(self.pg1, tx_pkt * 1)

        self.pg0.get_capture(0, timeout=1)
        self.pg0.assert_nothing_captured("Should drop IPv4 spoof prefix")

    #
    # Spoofed IPv6 PSID v6 -> v4 direction
    # Send a packet with a wrong IPv6 port PSID
    # The BR should drop the packet.
    #

    def test_map_t_spoof_psid_ip6_to_ip4(self):
        """ MAP-T spoof psid IPv6 -> IPv4 """

        eth = Ether(src=self.pg1.remote_mac,
                    dst=self.pg1.local_mac)
        ip = IPv6(src=self.ipv6_spoof_psid,
                  dst=self.ipv6_map_address)
        udp = UDP(sport=self.ipv6_udp_or_tcp_map_port,
                  dport=self.ipv6_udp_or_tcp_internet_port)
        payload = "a" * 82
        tx_pkt = eth / ip / udp / payload

        self.pg_send(self.pg1, tx_pkt * 1)

        self.pg0.get_capture(0, timeout=1)
        self.pg0.assert_nothing_captured("Should drop IPv6 spoof PSID")

    #
    # Spoofed IPv6 subnet field v6 -> v4 direction
    # Send a packet with a wrong IPv6 subnet as "2001:db8:f1"
    # The BR should drop the packet.
    #

    def test_map_t_spoof_subnet_ip6_to_ip4(self):
        """ MAP-T spoof subnet IPv6 -> IPv4 """

        eth = Ether(src=self.pg1.remote_mac,
                    dst=self.pg1.local_mac)
        ip = IPv6(src=self.ipv6_spoof_subnet,
                  dst=self.ipv6_map_address)
        udp = UDP(sport=self.ipv6_udp_or_tcp_map_port,
                  dport=self.ipv6_udp_or_tcp_internet_port)
        payload = "a" * 82
        tx_pkt = eth / ip / udp / payload

        self.pg_send(self.pg1, tx_pkt * 1)

        self.pg0.get_capture(0, timeout=1)
        self.pg0.assert_nothing_captured("Should drop IPv6 spoof subnet")

    #
    # Spoofed IPv6 port PSID v6 -> v4 direction
    # Send a packet with a wrong IPv6 port PSID
    # The BR should drop the packet.
    #

    def test_map_t_spoof_port_psid_ip6_to_ip4(self):
        """ MAP-T spoof port psid IPv6 -> IPv4 """

        eth = Ether(src=self.pg1.remote_mac,
                    dst=self.pg1.local_mac)
        ip = IPv6(src=self.ipv6_cpe_address,
                  dst=self.ipv6_map_address)
        udp = UDP(sport=self.ipv6_udp_or_tcp_spoof_port,
                  dport=self.ipv6_udp_or_tcp_internet_port)
        payload = "a" * 82
        tx_pkt = eth / ip / udp / payload

        self.pg_send(self.pg1, tx_pkt * 1)

        self.pg0.get_capture(0, timeout=1)
        self.pg0.assert_nothing_captured("Should drop IPv6 spoof port PSID")

    #
    # Spoofed IPv6 ICMP ID PSID v6 -> v4 direction
    # Send a packet with a wrong IPv6 IMCP ID PSID
    # The BR should drop the packet.
    #

    def test_map_t_spoof_icmp_id_psid_ip6_to_ip4(self):
        """ MAP-T spoof ICMP id psid IPv6 -> IPv4 """

        eth = Ether(src=self.pg1.remote_mac,
                    dst=self.pg1.local_mac)
        ip = IPv6(src=self.ipv6_cpe_address,
                  dst=self.ipv6_map_address)
        icmp = ICMPv6EchoRequest()
        icmp.id = self.ipv6_udp_or_tcp_spoof_port
        payload = "H" * 10
        tx_pkt = eth / ip / icmp / payload

        self.pg_send(self.pg1, tx_pkt * 1)

        self.pg0.get_capture(0, timeout=1)
        self.pg0.assert_nothing_captured("Should drop IPv6 spoof port PSID")

    #
    # Map to Map - same rule, different address
    #

    @unittest.skip("Fixme: correct behavior needs clarification")
    def test_map_t_same_rule_diff_addr_ip6_to_ip4(self):
        """ MAP-T same rule, diff addr IPv6 -> IPv6 """

        eth = Ether(src=self.pg1.remote_mac,
                    dst=self.pg1.local_mac)
        ip = IPv6(src=self.ipv6_cpe_address,
                  dst=self.ipv6_map_same_rule_diff_addr)
        udp = UDP(sport=self.ipv6_udp_or_tcp_map_port,
                  dport=1025)
        payload = "a" * 82
        tx_pkt = eth / ip / udp / payload

        self.pg_send(self.pg1, tx_pkt * 1)

        rx_pkts = self.pg1.get_capture(1)
        rx_pkt = rx_pkts[0]

    #
    # Map to Map - same rule, same address
    #

    @unittest.skip("Fixme: correct behavior needs clarification")
    def test_map_t_same_rule_same_addr_ip6_to_ip4(self):
        """ MAP-T same rule, same addr IPv6 -> IPv6 """

        eth = Ether(src=self.pg1.remote_mac,
                    dst=self.pg1.local_mac)
        ip = IPv6(src=self.ipv6_cpe_address,
                  dst=self.ipv6_map_same_rule_same_addr)
        udp = UDP(sport=self.ipv6_udp_or_tcp_map_port,
                  dport=1025)
        payload = "a" * 82
        tx_pkt = eth / ip / udp / payload

        self.pg_send(self.pg1, tx_pkt * 1)

        rx_pkts = self.pg1.get_capture(1)
        rx_pkt = rx_pkts[0]

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
