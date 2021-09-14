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

import scapy.compat
from scapy.layers.l2 import Ether
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.ipsec import SecurityAssociation, ESP

from util import ppp, ppc
from template_ipsec import TemplateIpsec
from vpp_ipsec import VppIpsecSA, VppIpsecSpd, VppIpsecSpdEntry,\
        VppIpsecSpdItfBinding
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_ip import DpoProto
from vpp_papi import VppEnum


class IPSecNATTestCase(TemplateIpsec):
    """ IPSec/NAT

    TUNNEL MODE::

         public network  |   private network
         ---   encrypt  ---   plain   ---
        |pg0| <------- |VPP| <------ |pg1|
         ---            ---           ---

         ---   decrypt  ---   plain   ---
        |pg0| -------> |VPP| ------> |pg1|
         ---            ---           ---

    """

    tcp_port_in = 6303
    tcp_port_out = 6303
    udp_port_in = 6304
    udp_port_out = 6304
    icmp_id_in = 6305
    icmp_id_out = 6305

    @classmethod
    def setUpClass(cls):
        super(IPSecNATTestCase, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(IPSecNATTestCase, cls).tearDownClass()

    def setUp(self):
        super(IPSecNATTestCase, self).setUp()
        self.tun_if = self.pg0

        self.tun_spd = VppIpsecSpd(self, self.tun_spd_id)
        self.tun_spd.add_vpp_config()
        VppIpsecSpdItfBinding(self, self.tun_spd,
                              self.tun_if).add_vpp_config()

        p = self.ipv4_params
        self.config_esp_tun(p)
        self.logger.info(self.vapi.ppcli("show ipsec all"))

        d = DpoProto.DPO_PROTO_IP6 if p.is_ipv6 else DpoProto.DPO_PROTO_IP4
        VppIpRoute(self,  p.remote_tun_if_host, p.addr_len,
                   [VppRoutePath(self.tun_if.remote_addr[p.addr_type],
                                 0xffffffff,
                                 proto=d)]).add_vpp_config()

    def tearDown(self):
        super(IPSecNATTestCase, self).tearDown()

    def create_stream_plain(self, src_mac, dst_mac, src_ip, dst_ip):
        return [
            # TCP
            Ether(src=src_mac, dst=dst_mac) /
            IP(src=src_ip, dst=dst_ip) /
            TCP(sport=self.tcp_port_in, dport=20),
            # UDP
            Ether(src=src_mac, dst=dst_mac) /
            IP(src=src_ip, dst=dst_ip) /
            UDP(sport=self.udp_port_in, dport=20),
            # ICMP
            Ether(src=src_mac, dst=dst_mac) /
            IP(src=src_ip, dst=dst_ip) /
            ICMP(id=self.icmp_id_in, type='echo-request')
        ]

    def create_stream_encrypted(self, src_mac, dst_mac, src_ip, dst_ip, sa):
        return [
            # TCP
            Ether(src=src_mac, dst=dst_mac) /
            sa.encrypt(IP(src=src_ip, dst=dst_ip) /
                       TCP(dport=self.tcp_port_out, sport=20)),
            # UDP
            Ether(src=src_mac, dst=dst_mac) /
            sa.encrypt(IP(src=src_ip, dst=dst_ip) /
                       UDP(dport=self.udp_port_out, sport=20)),
            # ICMP
            Ether(src=src_mac, dst=dst_mac) /
            sa.encrypt(IP(src=src_ip, dst=dst_ip) /
                       ICMP(id=self.icmp_id_out, type='echo-request'))
        ]

    def verify_capture_plain(self, capture):
        for packet in capture:
            try:
                self.assert_packet_checksums_valid(packet)
                self.assert_equal(packet[IP].src, self.tun_if.remote_ip4,
                                  "decrypted packet source address")
                self.assert_equal(packet[IP].dst, self.pg1.remote_ip4,
                                  "decrypted packet destination address")
                if packet.haslayer(TCP):
                    self.assertFalse(
                        packet.haslayer(UDP),
                        "unexpected UDP header in decrypted packet")
                    self.assert_equal(packet[TCP].dport, self.tcp_port_in,
                                      "decrypted packet TCP destination port")
                elif packet.haslayer(UDP):
                    if packet[UDP].payload:
                        self.assertFalse(
                            packet[UDP][1].haslayer(UDP),
                            "unexpected UDP header in decrypted packet")
                    self.assert_equal(packet[UDP].dport, self.udp_port_in,
                                      "decrypted packet UDP destination port")
                else:
                    self.assertFalse(
                        packet.haslayer(UDP),
                        "unexpected UDP header in decrypted packet")
                    self.assert_equal(packet[ICMP].id, self.icmp_id_in,
                                      "decrypted packet ICMP ID")
            except Exception:
                self.logger.error(
                    ppp("Unexpected or invalid plain packet:", packet))
                raise

    def verify_capture_encrypted(self, capture, sa):
        for packet in capture:
            try:
                copy = packet.__class__(scapy.compat.raw(packet))
                del copy[UDP].len
                copy = packet.__class__(scapy.compat.raw(copy))
                self.assert_equal(packet[UDP].len, copy[UDP].len,
                                  "UDP header length")
                self.assert_packet_checksums_valid(packet)
                self.assertIn(ESP, packet[IP])
                decrypt_pkt = sa.decrypt(packet[IP])
                self.assert_packet_checksums_valid(decrypt_pkt)
                self.assert_equal(decrypt_pkt[IP].src, self.pg1.remote_ip4,
                                  "encrypted packet source address")
                self.assert_equal(decrypt_pkt[IP].dst, self.tun_if.remote_ip4,
                                  "encrypted packet destination address")
            except Exception:
                self.logger.error(
                    ppp("Unexpected or invalid encrypted packet:", packet))
                raise

    def config_esp_tun(self, params):
        addr_type = params.addr_type
        scapy_tun_sa_id = params.scapy_tun_sa_id
        scapy_tun_spi = params.scapy_tun_spi
        vpp_tun_sa_id = params.vpp_tun_sa_id
        vpp_tun_spi = params.vpp_tun_spi
        auth_algo_vpp_id = params.auth_algo_vpp_id
        auth_key = params.auth_key
        crypt_algo_vpp_id = params.crypt_algo_vpp_id
        crypt_key = params.crypt_key
        addr_any = params.addr_any
        addr_bcast = params.addr_bcast
        flags = (VppEnum.vl_api_ipsec_sad_flags_t.
                 IPSEC_API_SAD_FLAG_UDP_ENCAP)
        e = VppEnum.vl_api_ipsec_spd_action_t

        VppIpsecSA(self, scapy_tun_sa_id, scapy_tun_spi,
                   auth_algo_vpp_id, auth_key,
                   crypt_algo_vpp_id, crypt_key,
                   self.vpp_esp_protocol,
                   self.pg1.remote_addr[addr_type],
                   self.tun_if.remote_addr[addr_type],
                   flags=flags).add_vpp_config()
        VppIpsecSA(self, vpp_tun_sa_id, vpp_tun_spi,
                   auth_algo_vpp_id, auth_key,
                   crypt_algo_vpp_id, crypt_key,
                   self.vpp_esp_protocol,
                   self.tun_if.remote_addr[addr_type],
                   self.pg1.remote_addr[addr_type],
                   flags=flags).add_vpp_config()

        VppIpsecSpdEntry(self, self.tun_spd, scapy_tun_sa_id,
                         addr_any, addr_bcast,
                         addr_any, addr_bcast,
                         socket.IPPROTO_ESP).add_vpp_config()
        VppIpsecSpdEntry(self, self.tun_spd, scapy_tun_sa_id,
                         addr_any, addr_bcast,
                         addr_any, addr_bcast,
                         socket.IPPROTO_ESP,
                         is_outbound=0).add_vpp_config()
        VppIpsecSpdEntry(self, self.tun_spd, scapy_tun_sa_id,
                         addr_any, addr_bcast,
                         addr_any, addr_bcast,
                         socket.IPPROTO_UDP,
                         remote_port_start=4500,
                         remote_port_stop=4500).add_vpp_config()
        VppIpsecSpdEntry(self, self.tun_spd, scapy_tun_sa_id,
                         addr_any, addr_bcast,
                         addr_any, addr_bcast,
                         socket.IPPROTO_UDP,
                         remote_port_start=4500,
                         remote_port_stop=4500,
                         is_outbound=0).add_vpp_config()
        VppIpsecSpdEntry(self, self.tun_spd, vpp_tun_sa_id,
                         self.tun_if.remote_addr[addr_type],
                         self.tun_if.remote_addr[addr_type],
                         self.pg1.remote_addr[addr_type],
                         self.pg1.remote_addr[addr_type],
                         0, priority=10,
                         policy=e.IPSEC_API_SPD_ACTION_PROTECT,
                         is_outbound=0).add_vpp_config()
        VppIpsecSpdEntry(self, self.tun_spd, scapy_tun_sa_id,
                         self.pg1.remote_addr[addr_type],
                         self.pg1.remote_addr[addr_type],
                         self.tun_if.remote_addr[addr_type],
                         self.tun_if.remote_addr[addr_type],
                         0, policy=e.IPSEC_API_SPD_ACTION_PROTECT,
                         priority=10).add_vpp_config()

    def test_ipsec_nat_tun(self):
        """ IPSec/NAT tunnel test case """
        p = self.ipv4_params
        scapy_tun_sa = SecurityAssociation(ESP, spi=p.scapy_tun_spi,
                                           crypt_algo=p.crypt_algo,
                                           crypt_key=p.crypt_key,
                                           auth_algo=p.auth_algo,
                                           auth_key=p.auth_key,
                                           tunnel_header=IP(
                                               src=self.pg1.remote_ip4,
                                               dst=self.tun_if.remote_ip4),
                                           nat_t_header=UDP(
                                               sport=4500,
                                               dport=4500))
        # in2out - from private network to public
        pkts = self.create_stream_plain(
            self.pg1.remote_mac, self.pg1.local_mac,
            self.pg1.remote_ip4, self.tun_if.remote_ip4)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.tun_if.get_capture(len(pkts))
        self.verify_capture_encrypted(capture, scapy_tun_sa)

        vpp_tun_sa = SecurityAssociation(ESP,
                                         spi=p.vpp_tun_spi,
                                         crypt_algo=p.crypt_algo,
                                         crypt_key=p.crypt_key,
                                         auth_algo=p.auth_algo,
                                         auth_key=p.auth_key,
                                         tunnel_header=IP(
                                             src=self.tun_if.remote_ip4,
                                             dst=self.pg1.remote_ip4),
                                         nat_t_header=UDP(
                                             sport=4500,
                                             dport=4500))

        # out2in - from public network to private
        pkts = self.create_stream_encrypted(
            self.tun_if.remote_mac, self.tun_if.local_mac,
            self.tun_if.remote_ip4, self.pg1.remote_ip4, vpp_tun_sa)
        self.logger.info(ppc("Sending packets:", pkts))
        self.tun_if.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_plain(capture)
