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
import random
import socket
import struct
import unittest
from io import BytesIO

import scapy.compat
from framework import tag_fixme_vpp_workers
from framework import VppTestCase, VppTestRunner, running_extended_tests
from ipfix import IPFIX, Set, Template, Data, IPFIXDecoder
from scapy.data import IP_PROTOS
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet import IPerror, TCPerror, UDPerror, ICMPerror
from scapy.layers.inet6 import ICMPv6DestUnreach, IPerror6, IPv6ExtHdrFragment
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply, \
    ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, fragment6
from scapy.layers.l2 import Ether, GRE
from scapy.packet import Raw
from syslog_rfc5424_parser import SyslogMessage, ParseError
from syslog_rfc5424_parser.constants import SyslogSeverity
from util import ppc, ppp
from vpp_papi import VppEnum


@tag_fixme_vpp_workers
class TestNAT64(VppTestCase):
    """ NAT64 Test Cases """

    @property
    def SYSLOG_SEVERITY(self):
        return VppEnum.vl_api_syslog_severity_t

    @property
    def config_flags(self):
        return VppEnum.vl_api_nat_config_flags_t

    @classmethod
    def setUpClass(cls):
        super(TestNAT64, cls).setUpClass()

        cls.tcp_port_in = 6303
        cls.tcp_port_out = 6303
        cls.udp_port_in = 6304
        cls.udp_port_out = 6304
        cls.icmp_id_in = 6305
        cls.icmp_id_out = 6305
        cls.tcp_external_port = 80
        cls.nat_addr = '10.0.0.3'
        cls.nat_addr_n = socket.inet_pton(socket.AF_INET, cls.nat_addr)
        cls.vrf1_id = 10
        cls.vrf1_nat_addr = '10.0.10.3'
        cls.ipfix_src_port = 4739
        cls.ipfix_domain_id = 1

        cls.create_pg_interfaces(range(6))
        cls.ip6_interfaces = list(cls.pg_interfaces[0:1])
        cls.ip6_interfaces.append(cls.pg_interfaces[2])
        cls.ip4_interfaces = list(cls.pg_interfaces[1:2])

        cls.vapi.ip_table_add_del(is_add=1,
                                  table={'table_id': cls.vrf1_id,
                                         'is_ip6': 1})

        cls.pg_interfaces[2].set_table_ip6(cls.vrf1_id)

        cls.pg0.generate_remote_hosts(2)

        for i in cls.ip6_interfaces:
            i.admin_up()
            i.config_ip6()
            i.configure_ipv6_neighbors()

        for i in cls.ip4_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

        cls.pg3.admin_up()
        cls.pg3.config_ip4()
        cls.pg3.resolve_arp()
        cls.pg3.config_ip6()
        cls.pg3.configure_ipv6_neighbors()

        cls.pg5.admin_up()
        cls.pg5.config_ip6()

    @classmethod
    def tearDownClass(cls):
        super(TestNAT64, cls).tearDownClass()

    def setUp(self):
        super(TestNAT64, self).setUp()
        self.vapi.nat64_plugin_enable_disable(enable=1,
                                              bib_buckets=128, st_buckets=256)

    def tearDown(self):
        super(TestNAT64, self).tearDown()
        if not self.vpp_dead:
            self.vapi.nat64_plugin_enable_disable(enable=0)

    def show_commands_at_teardown(self):
        self.logger.info(self.vapi.cli("show nat64 pool"))
        self.logger.info(self.vapi.cli("show nat64 interfaces"))
        self.logger.info(self.vapi.cli("show nat64 prefix"))
        self.logger.info(self.vapi.cli("show nat64 bib all"))
        self.logger.info(self.vapi.cli("show nat64 session table all"))

    def create_stream_in_ip6(self, in_if, out_if, hlim=64, pref=None, plen=0):
        """
        Create IPv6 packet stream for inside network

        :param in_if: Inside interface
        :param out_if: Outside interface
        :param ttl: Hop Limit of generated packets
        :param pref: NAT64 prefix
        :param plen: NAT64 prefix length
        """
        pkts = []
        if pref is None:
            dst = ''.join(['64:ff9b::', out_if.remote_ip4])
        else:
            dst = self.compose_ip6(out_if.remote_ip4, pref, plen)

        # TCP
        p = (Ether(dst=in_if.local_mac, src=in_if.remote_mac) /
             IPv6(src=in_if.remote_ip6, dst=dst, hlim=hlim) /
             TCP(sport=self.tcp_port_in, dport=20))
        pkts.append(p)

        # UDP
        p = (Ether(dst=in_if.local_mac, src=in_if.remote_mac) /
             IPv6(src=in_if.remote_ip6, dst=dst, hlim=hlim) /
             UDP(sport=self.udp_port_in, dport=20))
        pkts.append(p)

        # ICMP
        p = (Ether(dst=in_if.local_mac, src=in_if.remote_mac) /
             IPv6(src=in_if.remote_ip6, dst=dst, hlim=hlim) /
             ICMPv6EchoRequest(id=self.icmp_id_in))
        pkts.append(p)

        return pkts

    def create_stream_out(self, out_if, dst_ip=None, ttl=64,
                          use_inside_ports=False):
        """
        Create packet stream for outside network

        :param out_if: Outside interface
        :param dst_ip: Destination IP address (Default use global NAT address)
        :param ttl: TTL of generated packets
        :param use_inside_ports: Use inside NAT ports as destination ports
               instead of outside ports
        """
        if dst_ip is None:
            dst_ip = self.nat_addr
        if not use_inside_ports:
            tcp_port = self.tcp_port_out
            udp_port = self.udp_port_out
            icmp_id = self.icmp_id_out
        else:
            tcp_port = self.tcp_port_in
            udp_port = self.udp_port_in
            icmp_id = self.icmp_id_in
        pkts = []
        # TCP
        p = (Ether(dst=out_if.local_mac, src=out_if.remote_mac) /
             IP(src=out_if.remote_ip4, dst=dst_ip, ttl=ttl) /
             TCP(dport=tcp_port, sport=20))
        pkts.extend([p, p])

        # UDP
        p = (Ether(dst=out_if.local_mac, src=out_if.remote_mac) /
             IP(src=out_if.remote_ip4, dst=dst_ip, ttl=ttl) /
             UDP(dport=udp_port, sport=20))
        pkts.append(p)

        # ICMP
        p = (Ether(dst=out_if.local_mac, src=out_if.remote_mac) /
             IP(src=out_if.remote_ip4, dst=dst_ip, ttl=ttl) /
             ICMP(id=icmp_id, type='echo-reply'))
        pkts.append(p)

        return pkts

    def verify_capture_out(self, capture, nat_ip=None, same_port=False,
                           dst_ip=None, is_ip6=False, ignore_port=False):
        """
        Verify captured packets on outside network

        :param capture: Captured packets
        :param nat_ip: Translated IP address (Default use global NAT address)
        :param same_port: Source port number is not translated (Default False)
        :param dst_ip: Destination IP address (Default do not verify)
        :param is_ip6: If L3 protocol is IPv6 (Default False)
        """
        if is_ip6:
            IP46 = IPv6
            ICMP46 = ICMPv6EchoRequest
        else:
            IP46 = IP
            ICMP46 = ICMP
        if nat_ip is None:
            nat_ip = self.nat_addr
        for packet in capture:
            try:
                if not is_ip6:
                    self.assert_packet_checksums_valid(packet)
                self.assertEqual(packet[IP46].src, nat_ip)
                if dst_ip is not None:
                    self.assertEqual(packet[IP46].dst, dst_ip)
                if packet.haslayer(TCP):
                    if not ignore_port:
                        if same_port:
                            self.assertEqual(
                                packet[TCP].sport, self.tcp_port_in)
                        else:
                            self.assertNotEqual(
                                packet[TCP].sport, self.tcp_port_in)
                    self.tcp_port_out = packet[TCP].sport
                    self.assert_packet_checksums_valid(packet)
                elif packet.haslayer(UDP):
                    if not ignore_port:
                        if same_port:
                            self.assertEqual(
                                packet[UDP].sport, self.udp_port_in)
                        else:
                            self.assertNotEqual(
                                packet[UDP].sport, self.udp_port_in)
                    self.udp_port_out = packet[UDP].sport
                else:
                    if not ignore_port:
                        if same_port:
                            self.assertEqual(
                                packet[ICMP46].id, self.icmp_id_in)
                        else:
                            self.assertNotEqual(
                                packet[ICMP46].id, self.icmp_id_in)
                    self.icmp_id_out = packet[ICMP46].id
                    self.assert_packet_checksums_valid(packet)
            except:
                self.logger.error(ppp("Unexpected or invalid packet "
                                      "(outside network):", packet))
                raise

    def verify_capture_in_ip6(self, capture, src_ip, dst_ip):
        """
        Verify captured IPv6 packets on inside network

        :param capture: Captured packets
        :param src_ip: Source IP
        :param dst_ip: Destination IP address
        """
        for packet in capture:
            try:
                self.assertEqual(packet[IPv6].src, src_ip)
                self.assertEqual(packet[IPv6].dst, dst_ip)
                self.assert_packet_checksums_valid(packet)
                if packet.haslayer(TCP):
                    self.assertEqual(packet[TCP].dport, self.tcp_port_in)
                elif packet.haslayer(UDP):
                    self.assertEqual(packet[UDP].dport, self.udp_port_in)
                else:
                    self.assertEqual(packet[ICMPv6EchoReply].id,
                                     self.icmp_id_in)
            except:
                self.logger.error(ppp("Unexpected or invalid packet "
                                      "(inside network):", packet))
                raise

    def create_stream_frag(self, src_if, dst, sport, dport, data,
                           proto=IP_PROTOS.tcp, echo_reply=False):
        """
        Create fragmented packet stream

        :param src_if: Source interface
        :param dst: Destination IPv4 address
        :param sport: Source port
        :param dport: Destination port
        :param data: Payload data
        :param proto: protocol (TCP, UDP, ICMP)
        :param echo_reply: use echo_reply if protocol is ICMP
        :returns: Fragments
        """
        if proto == IP_PROTOS.tcp:
            p = (IP(src=src_if.remote_ip4, dst=dst) /
                 TCP(sport=sport, dport=dport) /
                 Raw(data))
            p = p.__class__(scapy.compat.raw(p))
            chksum = p[TCP].chksum
            proto_header = TCP(sport=sport, dport=dport, chksum=chksum)
        elif proto == IP_PROTOS.udp:
            proto_header = UDP(sport=sport, dport=dport)
        elif proto == IP_PROTOS.icmp:
            if not echo_reply:
                proto_header = ICMP(id=sport, type='echo-request')
            else:
                proto_header = ICMP(id=sport, type='echo-reply')
        else:
            raise Exception("Unsupported protocol")
        id = random.randint(0, 65535)
        pkts = []
        if proto == IP_PROTOS.tcp:
            raw = Raw(data[0:4])
        else:
            raw = Raw(data[0:16])
        p = (Ether(src=src_if.remote_mac, dst=src_if.local_mac) /
             IP(src=src_if.remote_ip4, dst=dst, flags="MF", frag=0, id=id) /
             proto_header /
             raw)
        pkts.append(p)
        if proto == IP_PROTOS.tcp:
            raw = Raw(data[4:20])
        else:
            raw = Raw(data[16:32])
        p = (Ether(src=src_if.remote_mac, dst=src_if.local_mac) /
             IP(src=src_if.remote_ip4, dst=dst, flags="MF", frag=3, id=id,
                proto=proto) /
             raw)
        pkts.append(p)
        if proto == IP_PROTOS.tcp:
            raw = Raw(data[20:])
        else:
            raw = Raw(data[32:])
        p = (Ether(src=src_if.remote_mac, dst=src_if.local_mac) /
             IP(src=src_if.remote_ip4, dst=dst, frag=5, proto=proto,
                id=id) /
             raw)
        pkts.append(p)
        return pkts

    def create_stream_frag_ip6(self, src_if, dst, sport, dport, data,
                               pref=None, plen=0, frag_size=128):
        """
        Create fragmented packet stream

        :param src_if: Source interface
        :param dst: Destination IPv4 address
        :param sport: Source TCP port
        :param dport: Destination TCP port
        :param data: Payload data
        :param pref: NAT64 prefix
        :param plen: NAT64 prefix length
        :param fragsize: size of fragments
        :returns: Fragments
        """
        if pref is None:
            dst_ip6 = ''.join(['64:ff9b::', dst])
        else:
            dst_ip6 = self.compose_ip6(dst, pref, plen)

        p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
             IPv6(src=src_if.remote_ip6, dst=dst_ip6) /
             IPv6ExtHdrFragment(id=random.randint(0, 65535)) /
             TCP(sport=sport, dport=dport) /
             Raw(data))

        return fragment6(p, frag_size)

    def reass_frags_and_verify(self, frags, src, dst):
        """
        Reassemble and verify fragmented packet

        :param frags: Captured fragments
        :param src: Source IPv4 address to verify
        :param dst: Destination IPv4 address to verify

        :returns: Reassembled IPv4 packet
        """
        buffer = BytesIO()
        for p in frags:
            self.assertEqual(p[IP].src, src)
            self.assertEqual(p[IP].dst, dst)
            self.assert_ip_checksum_valid(p)
            buffer.seek(p[IP].frag * 8)
            buffer.write(bytes(p[IP].payload))
        ip = IP(src=frags[0][IP].src, dst=frags[0][IP].dst,
                proto=frags[0][IP].proto)
        if ip.proto == IP_PROTOS.tcp:
            p = (ip / TCP(buffer.getvalue()))
            self.logger.debug(ppp("Reassembled:", p))
            self.assert_tcp_checksum_valid(p)
        elif ip.proto == IP_PROTOS.udp:
            p = (ip / UDP(buffer.getvalue()[:8]) /
                 Raw(buffer.getvalue()[8:]))
        elif ip.proto == IP_PROTOS.icmp:
            p = (ip / ICMP(buffer.getvalue()))
        return p

    def reass_frags_and_verify_ip6(self, frags, src, dst):
        """
        Reassemble and verify fragmented packet

        :param frags: Captured fragments
        :param src: Source IPv6 address to verify
        :param dst: Destination IPv6 address to verify

        :returns: Reassembled IPv6 packet
        """
        buffer = BytesIO()
        for p in frags:
            self.assertEqual(p[IPv6].src, src)
            self.assertEqual(p[IPv6].dst, dst)
            buffer.seek(p[IPv6ExtHdrFragment].offset * 8)
            buffer.write(bytes(p[IPv6ExtHdrFragment].payload))
        ip = IPv6(src=frags[0][IPv6].src, dst=frags[0][IPv6].dst,
                  nh=frags[0][IPv6ExtHdrFragment].nh)
        if ip.nh == IP_PROTOS.tcp:
            p = (ip / TCP(buffer.getvalue()))
        elif ip.nh == IP_PROTOS.udp:
            p = (ip / UDP(buffer.getvalue()))
        self.logger.debug(ppp("Reassembled:", p))
        self.assert_packet_checksums_valid(p)
        return p

    def verify_ipfix_max_bibs(self, data, limit):
        """
        Verify IPFIX maximum BIB entries exceeded event

        :param data: Decoded IPFIX data records
        :param limit: Number of maximum BIB entries that can be created.
        """
        self.assertEqual(1, len(data))
        record = data[0]
        # natEvent
        self.assertEqual(scapy.compat.orb(record[230]), 13)
        # natQuotaExceededEvent
        self.assertEqual(struct.pack("I", 2), record[466])
        # maxBIBEntries
        self.assertEqual(struct.pack("I", limit), record[472])

    def verify_ipfix_bib(self, data, is_create, src_addr):
        """
        Verify IPFIX NAT64 BIB create and delete events

        :param data: Decoded IPFIX data records
        :param is_create: Create event if nonzero value otherwise delete event
        :param src_addr: IPv6 source address
        """
        self.assertEqual(1, len(data))
        record = data[0]
        # natEvent
        if is_create:
            self.assertEqual(scapy.compat.orb(record[230]), 10)
        else:
            self.assertEqual(scapy.compat.orb(record[230]), 11)
        # sourceIPv6Address
        self.assertEqual(src_addr, str(ipaddress.IPv6Address(record[27])))
        # postNATSourceIPv4Address
        self.assertEqual(self.nat_addr_n, record[225])
        # protocolIdentifier
        self.assertEqual(IP_PROTOS.tcp, scapy.compat.orb(record[4]))
        # ingressVRFID
        self.assertEqual(struct.pack("!I", 0), record[234])
        # sourceTransportPort
        self.assertEqual(struct.pack("!H", self.tcp_port_in), record[7])
        # postNAPTSourceTransportPort
        self.assertEqual(struct.pack("!H", self.tcp_port_out), record[227])

    def verify_ipfix_nat64_ses(self, data, is_create, src_addr, dst_addr,
                               dst_port):
        """
        Verify IPFIX NAT64 session create and delete events

        :param data: Decoded IPFIX data records
        :param is_create: Create event if nonzero value otherwise delete event
        :param src_addr: IPv6 source address
        :param dst_addr: IPv4 destination address
        :param dst_port: destination TCP port
        """
        self.assertEqual(1, len(data))
        record = data[0]
        # natEvent
        if is_create:
            self.assertEqual(scapy.compat.orb(record[230]), 6)
        else:
            self.assertEqual(scapy.compat.orb(record[230]), 7)
        # sourceIPv6Address
        self.assertEqual(src_addr, str(ipaddress.IPv6Address(record[27])))
        # destinationIPv6Address
        self.assertEqual(socket.inet_pton(socket.AF_INET6,
                                          self.compose_ip6(dst_addr,
                                                           '64:ff9b::',
                                                           96)),
                         record[28])
        # postNATSourceIPv4Address
        self.assertEqual(self.nat_addr_n, record[225])
        # postNATDestinationIPv4Address
        self.assertEqual(socket.inet_pton(socket.AF_INET, dst_addr),
                         record[226])
        # protocolIdentifier
        self.assertEqual(IP_PROTOS.tcp, scapy.compat.orb(record[4]))
        # ingressVRFID
        self.assertEqual(struct.pack("!I", 0), record[234])
        # sourceTransportPort
        self.assertEqual(struct.pack("!H", self.tcp_port_in), record[7])
        # postNAPTSourceTransportPort
        self.assertEqual(struct.pack("!H", self.tcp_port_out), record[227])
        # destinationTransportPort
        self.assertEqual(struct.pack("!H", dst_port), record[11])
        # postNAPTDestinationTransportPort
        self.assertEqual(struct.pack("!H", dst_port), record[228])

    def verify_syslog_sess(self, data, is_add=True, is_ip6=False):
        message = data.decode('utf-8')
        try:
            message = SyslogMessage.parse(message)
        except ParseError as e:
            self.logger.error(e)
            raise
        else:
            self.assertEqual(message.severity, SyslogSeverity.info)
            self.assertEqual(message.appname, 'NAT')
            self.assertEqual(message.msgid, 'SADD' if is_add else 'SDEL')
            sd_params = message.sd.get('nsess')
            self.assertTrue(sd_params is not None)
            if is_ip6:
                self.assertEqual(sd_params.get('IATYP'), 'IPv6')
                self.assertEqual(sd_params.get('ISADDR'), self.pg0.remote_ip6)
            else:
                self.assertEqual(sd_params.get('IATYP'), 'IPv4')
                self.assertEqual(sd_params.get('ISADDR'), self.pg0.remote_ip4)
                self.assertTrue(sd_params.get('SSUBIX') is not None)
            self.assertEqual(sd_params.get('ISPORT'), "%d" % self.tcp_port_in)
            self.assertEqual(sd_params.get('XATYP'), 'IPv4')
            self.assertEqual(sd_params.get('XSADDR'), self.nat_addr)
            self.assertEqual(sd_params.get('XSPORT'), "%d" % self.tcp_port_out)
            self.assertEqual(sd_params.get('PROTO'), "%d" % IP_PROTOS.tcp)
            self.assertEqual(sd_params.get('SVLAN'), '0')
            self.assertEqual(sd_params.get('XDADDR'), self.pg1.remote_ip4)
            self.assertEqual(sd_params.get('XDPORT'),
                             "%d" % self.tcp_external_port)

    def compose_ip6(self, ip4, pref, plen):
        """
        Compose IPv4-embedded IPv6 addresses

        :param ip4: IPv4 address
        :param pref: IPv6 prefix
        :param plen: IPv6 prefix length
        :returns: IPv4-embedded IPv6 addresses
        """
        pref_n = list(socket.inet_pton(socket.AF_INET6, pref))
        ip4_n = list(socket.inet_pton(socket.AF_INET, ip4))
        if plen == 32:
            pref_n[4] = ip4_n[0]
            pref_n[5] = ip4_n[1]
            pref_n[6] = ip4_n[2]
            pref_n[7] = ip4_n[3]
        elif plen == 40:
            pref_n[5] = ip4_n[0]
            pref_n[6] = ip4_n[1]
            pref_n[7] = ip4_n[2]
            pref_n[9] = ip4_n[3]
        elif plen == 48:
            pref_n[6] = ip4_n[0]
            pref_n[7] = ip4_n[1]
            pref_n[9] = ip4_n[2]
            pref_n[10] = ip4_n[3]
        elif plen == 56:
            pref_n[7] = ip4_n[0]
            pref_n[9] = ip4_n[1]
            pref_n[10] = ip4_n[2]
            pref_n[11] = ip4_n[3]
        elif plen == 64:
            pref_n[9] = ip4_n[0]
            pref_n[10] = ip4_n[1]
            pref_n[11] = ip4_n[2]
            pref_n[12] = ip4_n[3]
        elif plen == 96:
            pref_n[12] = ip4_n[0]
            pref_n[13] = ip4_n[1]
            pref_n[14] = ip4_n[2]
            pref_n[15] = ip4_n[3]
        packed_pref_n = b''.join([scapy.compat.chb(x) for x in pref_n])
        return socket.inet_ntop(socket.AF_INET6, packed_pref_n)

    def verify_ipfix_max_sessions(self, data, limit):
        """
        Verify IPFIX maximum session entries exceeded event

        :param data: Decoded IPFIX data records
        :param limit: Number of maximum session entries that can be created.
        """
        self.assertEqual(1, len(data))
        record = data[0]
        # natEvent
        self.assertEqual(scapy.compat.orb(record[230]), 13)
        # natQuotaExceededEvent
        self.assertEqual(struct.pack("I", 1), record[466])
        # maxSessionEntries
        self.assertEqual(struct.pack("I", limit), record[471])

    def test_nat64_inside_interface_handles_neighbor_advertisement(self):
        """ NAT64 inside interface handles Neighbor Advertisement """

        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat64_add_del_interface(is_add=1, flags=flags,
                                          sw_if_index=self.pg5.sw_if_index)

        # Try to send ping
        ping = (Ether(dst=self.pg5.local_mac, src=self.pg5.remote_mac) /
                IPv6(src=self.pg5.remote_ip6, dst=self.pg5.local_ip6) /
                ICMPv6EchoRequest())
        pkts = [ping]
        self.pg5.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Wait for Neighbor Solicitation
        capture = self.pg5.get_capture(len(pkts))
        packet = capture[0]
        try:
            self.assertEqual(packet[IPv6].src, self.pg5.local_ip6)
            self.assertEqual(packet.haslayer(ICMPv6ND_NS), 1)
            tgt = packet[ICMPv6ND_NS].tgt
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", packet))
            raise

        # Send Neighbor Advertisement
        p = (Ether(dst=self.pg5.local_mac, src=self.pg5.remote_mac) /
             IPv6(src=self.pg5.remote_ip6, dst=self.pg5.local_ip6) /
             ICMPv6ND_NA(tgt=tgt) /
             ICMPv6NDOptDstLLAddr(lladdr=self.pg5.remote_mac))
        pkts = [p]
        self.pg5.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Try to send ping again
        pkts = [ping]
        self.pg5.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Wait for ping reply
        capture = self.pg5.get_capture(len(pkts))
        packet = capture[0]
        try:
            self.assertEqual(packet[IPv6].src, self.pg5.local_ip6)
            self.assertEqual(packet[IPv6].dst, self.pg5.remote_ip6)
            self.assertEqual(packet.haslayer(ICMPv6EchoReply), 1)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", packet))
            raise

    def test_pool(self):
        """ Add/delete address to NAT64 pool """
        nat_addr = '1.2.3.4'

        self.vapi.nat64_add_del_pool_addr_range(start_addr=nat_addr,
                                                end_addr=nat_addr,
                                                vrf_id=0xFFFFFFFF, is_add=1)

        addresses = self.vapi.nat64_pool_addr_dump()
        self.assertEqual(len(addresses), 1)
        self.assertEqual(str(addresses[0].address), nat_addr)

        self.vapi.nat64_add_del_pool_addr_range(start_addr=nat_addr,
                                                end_addr=nat_addr,
                                                vrf_id=0xFFFFFFFF, is_add=0)

        addresses = self.vapi.nat64_pool_addr_dump()
        self.assertEqual(len(addresses), 0)

    def test_interface(self):
        """ Enable/disable NAT64 feature on the interface """
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat64_add_del_interface(is_add=1, flags=flags,
                                          sw_if_index=self.pg0.sw_if_index)
        self.vapi.nat64_add_del_interface(is_add=1, flags=0,
                                          sw_if_index=self.pg1.sw_if_index)

        interfaces = self.vapi.nat64_interface_dump()
        self.assertEqual(len(interfaces), 2)
        pg0_found = False
        pg1_found = False
        for intf in interfaces:
            if intf.sw_if_index == self.pg0.sw_if_index:
                self.assertEqual(intf.flags, self.config_flags.NAT_IS_INSIDE)
                pg0_found = True
            elif intf.sw_if_index == self.pg1.sw_if_index:
                self.assertEqual(intf.flags, self.config_flags.NAT_IS_OUTSIDE)
                pg1_found = True
        self.assertTrue(pg0_found)
        self.assertTrue(pg1_found)

        features = self.vapi.cli("show interface features pg0")
        self.assertIn('nat64-in2out', features)
        features = self.vapi.cli("show interface features pg1")
        self.assertIn('nat64-out2in', features)

        self.vapi.nat64_add_del_interface(is_add=0, flags=flags,
                                          sw_if_index=self.pg0.sw_if_index)
        self.vapi.nat64_add_del_interface(is_add=0, flags=flags,
                                          sw_if_index=self.pg1.sw_if_index)

        interfaces = self.vapi.nat64_interface_dump()
        self.assertEqual(len(interfaces), 0)

    def test_static_bib(self):
        """ Add/delete static BIB entry """
        in_addr = '2001:db8:85a3::8a2e:370:7334'
        out_addr = '10.1.1.3'
        in_port = 1234
        out_port = 5678
        proto = IP_PROTOS.tcp

        self.vapi.nat64_add_del_static_bib(i_addr=in_addr, o_addr=out_addr,
                                           i_port=in_port, o_port=out_port,
                                           proto=proto, vrf_id=0, is_add=1)
        bib = self.vapi.nat64_bib_dump(proto=IP_PROTOS.tcp)
        static_bib_num = 0
        for bibe in bib:
            if bibe.flags & self.config_flags.NAT_IS_STATIC:
                static_bib_num += 1
                self.assertEqual(str(bibe.i_addr), in_addr)
                self.assertEqual(str(bibe.o_addr), out_addr)
                self.assertEqual(bibe.i_port, in_port)
                self.assertEqual(bibe.o_port, out_port)
        self.assertEqual(static_bib_num, 1)
        bibs = self.statistics.get_counter('/nat64/total-bibs')
        self.assertEqual(bibs[0][0], 1)

        self.vapi.nat64_add_del_static_bib(i_addr=in_addr, o_addr=out_addr,
                                           i_port=in_port, o_port=out_port,
                                           proto=proto, vrf_id=0, is_add=0)
        bib = self.vapi.nat64_bib_dump(proto=IP_PROTOS.tcp)
        static_bib_num = 0
        for bibe in bib:
            if bibe.flags & self.config_flags.NAT_IS_STATIC:
                static_bib_num += 1
        self.assertEqual(static_bib_num, 0)
        bibs = self.statistics.get_counter('/nat64/total-bibs')
        self.assertEqual(bibs[0][0], 0)

    def test_set_timeouts(self):
        """ Set NAT64 timeouts """
        # verify default values
        timeouts = self.vapi.nat64_get_timeouts()
        self.assertEqual(timeouts.udp, 300)
        self.assertEqual(timeouts.icmp, 60)
        self.assertEqual(timeouts.tcp_transitory, 240)
        self.assertEqual(timeouts.tcp_established, 7440)

        # set and verify custom values
        self.vapi.nat64_set_timeouts(udp=200, tcp_established=7450,
                                     tcp_transitory=250, icmp=30)
        timeouts = self.vapi.nat64_get_timeouts()
        self.assertEqual(timeouts.udp, 200)
        self.assertEqual(timeouts.icmp, 30)
        self.assertEqual(timeouts.tcp_transitory, 250)
        self.assertEqual(timeouts.tcp_established, 7450)

    def test_dynamic(self):
        """ NAT64 dynamic translation test """
        self.tcp_port_in = 6303
        self.udp_port_in = 6304
        self.icmp_id_in = 6305

        ses_num_start = self.nat64_get_ses_num()

        self.vapi.nat64_add_del_pool_addr_range(start_addr=self.nat_addr,
                                                end_addr=self.nat_addr,
                                                vrf_id=0xFFFFFFFF,
                                                is_add=1)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat64_add_del_interface(is_add=1, flags=flags,
                                          sw_if_index=self.pg0.sw_if_index)
        self.vapi.nat64_add_del_interface(is_add=1, flags=0,
                                          sw_if_index=self.pg1.sw_if_index)

        # in2out
        tcpn = self.statistics.get_counter('/nat64/in2out/tcp')[0]
        udpn = self.statistics.get_counter('/nat64/in2out/udp')[0]
        icmpn = self.statistics.get_counter('/nat64/in2out/icmp')[0]
        drops = self.statistics.get_counter('/nat64/in2out/drops')[0]

        pkts = self.create_stream_in_ip6(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_out(capture, nat_ip=self.nat_addr,
                                dst_ip=self.pg1.remote_ip4)

        if_idx = self.pg0.sw_if_index
        cnt = self.statistics.get_counter('/nat64/in2out/tcp')[0]
        self.assertEqual(cnt[if_idx] - tcpn[if_idx], 1)
        cnt = self.statistics.get_counter('/nat64/in2out/udp')[0]
        self.assertEqual(cnt[if_idx] - udpn[if_idx], 1)
        cnt = self.statistics.get_counter('/nat64/in2out/icmp')[0]
        self.assertEqual(cnt[if_idx] - icmpn[if_idx], 1)
        cnt = self.statistics.get_counter('/nat64/in2out/drops')[0]
        self.assertEqual(cnt[if_idx] - drops[if_idx], 0)

        # out2in
        tcpn = self.statistics.get_counter('/nat64/out2in/tcp')[0]
        udpn = self.statistics.get_counter('/nat64/out2in/udp')[0]
        icmpn = self.statistics.get_counter('/nat64/out2in/icmp')[0]
        drops = self.statistics.get_counter('/nat64/out2in/drops')[0]

        pkts = self.create_stream_out(self.pg1, dst_ip=self.nat_addr)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(len(pkts))
        ip = IPv6(src=''.join(['64:ff9b::', self.pg1.remote_ip4]))
        self.verify_capture_in_ip6(capture, ip[IPv6].src, self.pg0.remote_ip6)

        if_idx = self.pg1.sw_if_index
        cnt = self.statistics.get_counter('/nat64/out2in/tcp')[0]
        self.assertEqual(cnt[if_idx] - tcpn[if_idx], 2)
        cnt = self.statistics.get_counter('/nat64/out2in/udp')[0]
        self.assertEqual(cnt[if_idx] - udpn[if_idx], 1)
        cnt = self.statistics.get_counter('/nat64/out2in/icmp')[0]
        self.assertEqual(cnt[if_idx] - icmpn[if_idx], 1)
        cnt = self.statistics.get_counter('/nat64/out2in/drops')[0]
        self.assertEqual(cnt[if_idx] - drops[if_idx], 0)

        bibs = self.statistics.get_counter('/nat64/total-bibs')
        self.assertEqual(bibs[0][0], 3)
        sessions = self.statistics.get_counter('/nat64/total-sessions')
        self.assertEqual(sessions[0][0], 3)

        # in2out
        pkts = self.create_stream_in_ip6(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_out(capture, nat_ip=self.nat_addr,
                                dst_ip=self.pg1.remote_ip4)

        # out2in
        pkts = self.create_stream_out(self.pg1, dst_ip=self.nat_addr)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(len(pkts))
        self.verify_capture_in_ip6(capture, ip[IPv6].src, self.pg0.remote_ip6)

        ses_num_end = self.nat64_get_ses_num()

        self.assertEqual(ses_num_end - ses_num_start, 3)

        # tenant with specific VRF
        self.vapi.nat64_add_del_pool_addr_range(start_addr=self.vrf1_nat_addr,
                                                end_addr=self.vrf1_nat_addr,
                                                vrf_id=self.vrf1_id, is_add=1)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat64_add_del_interface(is_add=1, flags=flags,
                                          sw_if_index=self.pg2.sw_if_index)

        pkts = self.create_stream_in_ip6(self.pg2, self.pg1)
        self.pg2.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_out(capture, nat_ip=self.vrf1_nat_addr,
                                dst_ip=self.pg1.remote_ip4)

        pkts = self.create_stream_out(self.pg1, dst_ip=self.vrf1_nat_addr)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg2.get_capture(len(pkts))
        self.verify_capture_in_ip6(capture, ip[IPv6].src, self.pg2.remote_ip6)

    def test_static(self):
        """ NAT64 static translation test """
        self.tcp_port_in = 60303
        self.udp_port_in = 60304
        self.icmp_id_in = 60305
        self.tcp_port_out = 60303
        self.udp_port_out = 60304
        self.icmp_id_out = 60305

        ses_num_start = self.nat64_get_ses_num()

        self.vapi.nat64_add_del_pool_addr_range(start_addr=self.nat_addr,
                                                end_addr=self.nat_addr,
                                                vrf_id=0xFFFFFFFF,
                                                is_add=1)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat64_add_del_interface(is_add=1, flags=flags,
                                          sw_if_index=self.pg0.sw_if_index)
        self.vapi.nat64_add_del_interface(is_add=1, flags=0,
                                          sw_if_index=self.pg1.sw_if_index)

        self.vapi.nat64_add_del_static_bib(i_addr=self.pg0.remote_ip6,
                                           o_addr=self.nat_addr,
                                           i_port=self.tcp_port_in,
                                           o_port=self.tcp_port_out,
                                           proto=IP_PROTOS.tcp, vrf_id=0,
                                           is_add=1)
        self.vapi.nat64_add_del_static_bib(i_addr=self.pg0.remote_ip6,
                                           o_addr=self.nat_addr,
                                           i_port=self.udp_port_in,
                                           o_port=self.udp_port_out,
                                           proto=IP_PROTOS.udp, vrf_id=0,
                                           is_add=1)
        self.vapi.nat64_add_del_static_bib(i_addr=self.pg0.remote_ip6,
                                           o_addr=self.nat_addr,
                                           i_port=self.icmp_id_in,
                                           o_port=self.icmp_id_out,
                                           proto=IP_PROTOS.icmp, vrf_id=0,
                                           is_add=1)

        # in2out
        pkts = self.create_stream_in_ip6(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_out(capture, nat_ip=self.nat_addr,
                                dst_ip=self.pg1.remote_ip4, same_port=True)

        # out2in
        pkts = self.create_stream_out(self.pg1, dst_ip=self.nat_addr)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(len(pkts))
        ip = IPv6(src=''.join(['64:ff9b::', self.pg1.remote_ip4]))
        self.verify_capture_in_ip6(capture, ip[IPv6].src, self.pg0.remote_ip6)

        ses_num_end = self.nat64_get_ses_num()

        self.assertEqual(ses_num_end - ses_num_start, 3)

    def test_session_timeout(self):
        """ NAT64 session timeout """
        self.icmp_id_in = 1234
        self.vapi.nat64_add_del_pool_addr_range(start_addr=self.nat_addr,
                                                end_addr=self.nat_addr,
                                                vrf_id=0xFFFFFFFF,
                                                is_add=1)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat64_add_del_interface(is_add=1, flags=flags,
                                          sw_if_index=self.pg0.sw_if_index)
        self.vapi.nat64_add_del_interface(is_add=1, flags=0,
                                          sw_if_index=self.pg1.sw_if_index)
        self.vapi.nat64_set_timeouts(udp=300, tcp_established=5,
                                     tcp_transitory=5,
                                     icmp=5)

        pkts = self.create_stream_in_ip6(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))

        ses_num_before_timeout = self.nat64_get_ses_num()

        self.virtual_sleep(15)

        # ICMP and TCP session after timeout
        ses_num_after_timeout = self.nat64_get_ses_num()
        self.assertEqual(ses_num_before_timeout - ses_num_after_timeout, 2)

    def test_icmp_error(self):
        """ NAT64 ICMP Error message translation """
        self.tcp_port_in = 6303
        self.udp_port_in = 6304
        self.icmp_id_in = 6305

        self.vapi.nat64_add_del_pool_addr_range(start_addr=self.nat_addr,
                                                end_addr=self.nat_addr,
                                                vrf_id=0xFFFFFFFF,
                                                is_add=1)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat64_add_del_interface(is_add=1, flags=flags,
                                          sw_if_index=self.pg0.sw_if_index)
        self.vapi.nat64_add_del_interface(is_add=1, flags=0,
                                          sw_if_index=self.pg1.sw_if_index)

        # send some packets to create sessions
        pkts = self.create_stream_in_ip6(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture_ip4 = self.pg1.get_capture(len(pkts))
        self.verify_capture_out(capture_ip4,
                                nat_ip=self.nat_addr,
                                dst_ip=self.pg1.remote_ip4)

        pkts = self.create_stream_out(self.pg1, dst_ip=self.nat_addr)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture_ip6 = self.pg0.get_capture(len(pkts))
        ip = IPv6(src=''.join(['64:ff9b::', self.pg1.remote_ip4]))
        self.verify_capture_in_ip6(capture_ip6, ip[IPv6].src,
                                   self.pg0.remote_ip6)

        # in2out
        pkts = [Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                IPv6(src=self.pg0.remote_ip6, dst=ip[IPv6].src) /
                ICMPv6DestUnreach(code=1) /
                packet[IPv6] for packet in capture_ip6]
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        for packet in capture:
            try:
                self.assertEqual(packet[IP].src, self.nat_addr)
                self.assertEqual(packet[IP].dst, self.pg1.remote_ip4)
                self.assertEqual(packet[ICMP].type, 3)
                self.assertEqual(packet[ICMP].code, 13)
                inner = packet[IPerror]
                self.assertEqual(inner.src, self.pg1.remote_ip4)
                self.assertEqual(inner.dst, self.nat_addr)
                self.assert_packet_checksums_valid(packet)
                if inner.haslayer(TCPerror):
                    self.assertEqual(inner[TCPerror].dport, self.tcp_port_out)
                elif inner.haslayer(UDPerror):
                    self.assertEqual(inner[UDPerror].dport, self.udp_port_out)
                else:
                    self.assertEqual(inner[ICMPerror].id, self.icmp_id_out)
            except:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise

        # out2in
        pkts = [Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
                IP(src=self.pg1.remote_ip4, dst=self.nat_addr) /
                ICMP(type=3, code=13) /
                packet[IP] for packet in capture_ip4]
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(len(pkts))
        for packet in capture:
            try:
                self.assertEqual(packet[IPv6].src, ip.src)
                self.assertEqual(packet[IPv6].dst, self.pg0.remote_ip6)
                icmp = packet[ICMPv6DestUnreach]
                self.assertEqual(icmp.code, 1)
                inner = icmp[IPerror6]
                self.assertEqual(inner.src, self.pg0.remote_ip6)
                self.assertEqual(inner.dst, ip.src)
                self.assert_icmpv6_checksum_valid(packet)
                if inner.haslayer(TCPerror):
                    self.assertEqual(inner[TCPerror].sport, self.tcp_port_in)
                elif inner.haslayer(UDPerror):
                    self.assertEqual(inner[UDPerror].sport, self.udp_port_in)
                else:
                    self.assertEqual(inner[ICMPv6EchoRequest].id,
                                     self.icmp_id_in)
            except:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise

    def test_hairpinning(self):
        """ NAT64 hairpinning """

        client = self.pg0.remote_hosts[0]
        server = self.pg0.remote_hosts[1]
        server_tcp_in_port = 22
        server_tcp_out_port = 4022
        server_udp_in_port = 23
        server_udp_out_port = 4023
        client_tcp_in_port = 1234
        client_udp_in_port = 1235
        client_tcp_out_port = 0
        client_udp_out_port = 0
        ip = IPv6(src=''.join(['64:ff9b::', self.nat_addr]))
        nat_addr_ip6 = ip.src

        self.vapi.nat64_add_del_pool_addr_range(start_addr=self.nat_addr,
                                                end_addr=self.nat_addr,
                                                vrf_id=0xFFFFFFFF,
                                                is_add=1)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat64_add_del_interface(is_add=1, flags=flags,
                                          sw_if_index=self.pg0.sw_if_index)
        self.vapi.nat64_add_del_interface(is_add=1, flags=0,
                                          sw_if_index=self.pg1.sw_if_index)

        self.vapi.nat64_add_del_static_bib(i_addr=server.ip6n,
                                           o_addr=self.nat_addr,
                                           i_port=server_tcp_in_port,
                                           o_port=server_tcp_out_port,
                                           proto=IP_PROTOS.tcp, vrf_id=0,
                                           is_add=1)
        self.vapi.nat64_add_del_static_bib(i_addr=server.ip6n,
                                           o_addr=self.nat_addr,
                                           i_port=server_udp_in_port,
                                           o_port=server_udp_out_port,
                                           proto=IP_PROTOS.udp, vrf_id=0,
                                           is_add=1)

        # client to server
        pkts = []
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IPv6(src=client.ip6, dst=nat_addr_ip6) /
             TCP(sport=client_tcp_in_port, dport=server_tcp_out_port))
        pkts.append(p)
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IPv6(src=client.ip6, dst=nat_addr_ip6) /
             UDP(sport=client_udp_in_port, dport=server_udp_out_port))
        pkts.append(p)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(len(pkts))
        for packet in capture:
            try:
                self.assertEqual(packet[IPv6].src, nat_addr_ip6)
                self.assertEqual(packet[IPv6].dst, server.ip6)
                self.assert_packet_checksums_valid(packet)
                if packet.haslayer(TCP):
                    self.assertNotEqual(packet[TCP].sport, client_tcp_in_port)
                    self.assertEqual(packet[TCP].dport, server_tcp_in_port)
                    client_tcp_out_port = packet[TCP].sport
                else:
                    self.assertNotEqual(packet[UDP].sport, client_udp_in_port)
                    self.assertEqual(packet[UDP].dport, server_udp_in_port)
                    client_udp_out_port = packet[UDP].sport
            except:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise

        # server to client
        pkts = []
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IPv6(src=server.ip6, dst=nat_addr_ip6) /
             TCP(sport=server_tcp_in_port, dport=client_tcp_out_port))
        pkts.append(p)
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IPv6(src=server.ip6, dst=nat_addr_ip6) /
             UDP(sport=server_udp_in_port, dport=client_udp_out_port))
        pkts.append(p)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(len(pkts))
        for packet in capture:
            try:
                self.assertEqual(packet[IPv6].src, nat_addr_ip6)
                self.assertEqual(packet[IPv6].dst, client.ip6)
                self.assert_packet_checksums_valid(packet)
                if packet.haslayer(TCP):
                    self.assertEqual(packet[TCP].sport, server_tcp_out_port)
                    self.assertEqual(packet[TCP].dport, client_tcp_in_port)
                else:
                    self.assertEqual(packet[UDP].sport, server_udp_out_port)
                    self.assertEqual(packet[UDP].dport, client_udp_in_port)
            except:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise

        # ICMP error
        pkts = []
        pkts = [Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                IPv6(src=client.ip6, dst=nat_addr_ip6) /
                ICMPv6DestUnreach(code=1) /
                packet[IPv6] for packet in capture]
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(len(pkts))
        for packet in capture:
            try:
                self.assertEqual(packet[IPv6].src, nat_addr_ip6)
                self.assertEqual(packet[IPv6].dst, server.ip6)
                icmp = packet[ICMPv6DestUnreach]
                self.assertEqual(icmp.code, 1)
                inner = icmp[IPerror6]
                self.assertEqual(inner.src, server.ip6)
                self.assertEqual(inner.dst, nat_addr_ip6)
                self.assert_packet_checksums_valid(packet)
                if inner.haslayer(TCPerror):
                    self.assertEqual(inner[TCPerror].sport, server_tcp_in_port)
                    self.assertEqual(inner[TCPerror].dport,
                                     client_tcp_out_port)
                else:
                    self.assertEqual(inner[UDPerror].sport, server_udp_in_port)
                    self.assertEqual(inner[UDPerror].dport,
                                     client_udp_out_port)
            except:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise

    def test_prefix(self):
        """ NAT64 Network-Specific Prefix """

        self.vapi.nat64_add_del_pool_addr_range(start_addr=self.nat_addr,
                                                end_addr=self.nat_addr,
                                                vrf_id=0xFFFFFFFF,
                                                is_add=1)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat64_add_del_interface(is_add=1, flags=flags,
                                          sw_if_index=self.pg0.sw_if_index)
        self.vapi.nat64_add_del_interface(is_add=1, flags=0,
                                          sw_if_index=self.pg1.sw_if_index)
        self.vapi.nat64_add_del_pool_addr_range(start_addr=self.vrf1_nat_addr,
                                                end_addr=self.vrf1_nat_addr,
                                                vrf_id=self.vrf1_id, is_add=1)
        self.vapi.nat64_add_del_interface(is_add=1, flags=flags,
                                          sw_if_index=self.pg2.sw_if_index)

        # Add global prefix
        global_pref64 = "2001:db8::"
        global_pref64_len = 32
        global_pref64_str = "{}/{}".format(global_pref64, global_pref64_len)
        self.vapi.nat64_add_del_prefix(prefix=global_pref64_str, vrf_id=0,
                                       is_add=1)

        prefix = self.vapi.nat64_prefix_dump()
        self.assertEqual(len(prefix), 1)
        self.assertEqual(str(prefix[0].prefix), global_pref64_str)
        self.assertEqual(prefix[0].vrf_id, 0)

        # Add tenant specific prefix
        vrf1_pref64 = "2001:db8:122:300::"
        vrf1_pref64_len = 56
        vrf1_pref64_str = "{}/{}".format(vrf1_pref64, vrf1_pref64_len)
        self.vapi.nat64_add_del_prefix(prefix=vrf1_pref64_str,
                                       vrf_id=self.vrf1_id, is_add=1)

        prefix = self.vapi.nat64_prefix_dump()
        self.assertEqual(len(prefix), 2)

        # Global prefix
        pkts = self.create_stream_in_ip6(self.pg0,
                                         self.pg1,
                                         pref=global_pref64,
                                         plen=global_pref64_len)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_out(capture, nat_ip=self.nat_addr,
                                dst_ip=self.pg1.remote_ip4)

        pkts = self.create_stream_out(self.pg1, dst_ip=self.nat_addr)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(len(pkts))
        dst_ip = self.compose_ip6(self.pg1.remote_ip4,
                                  global_pref64,
                                  global_pref64_len)
        self.verify_capture_in_ip6(capture, dst_ip, self.pg0.remote_ip6)

        # Tenant specific prefix
        pkts = self.create_stream_in_ip6(self.pg2,
                                         self.pg1,
                                         pref=vrf1_pref64,
                                         plen=vrf1_pref64_len)
        self.pg2.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_out(capture, nat_ip=self.vrf1_nat_addr,
                                dst_ip=self.pg1.remote_ip4)

        pkts = self.create_stream_out(self.pg1, dst_ip=self.vrf1_nat_addr)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg2.get_capture(len(pkts))
        dst_ip = self.compose_ip6(self.pg1.remote_ip4,
                                  vrf1_pref64,
                                  vrf1_pref64_len)
        self.verify_capture_in_ip6(capture, dst_ip, self.pg2.remote_ip6)

    def test_unknown_proto(self):
        """ NAT64 translate packet with unknown protocol """

        self.vapi.nat64_add_del_pool_addr_range(start_addr=self.nat_addr,
                                                end_addr=self.nat_addr,
                                                vrf_id=0xFFFFFFFF,
                                                is_add=1)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat64_add_del_interface(is_add=1, flags=flags,
                                          sw_if_index=self.pg0.sw_if_index)
        self.vapi.nat64_add_del_interface(is_add=1, flags=0,
                                          sw_if_index=self.pg1.sw_if_index)
        remote_ip6 = self.compose_ip6(self.pg1.remote_ip4, '64:ff9b::', 96)

        # in2out
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IPv6(src=self.pg0.remote_ip6, dst=remote_ip6) /
             TCP(sport=self.tcp_port_in, dport=20))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        p = self.pg1.get_capture(1)

        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IPv6(src=self.pg0.remote_ip6, dst=remote_ip6, nh=47) /
             GRE() /
             IP(src=self.pg2.local_ip4, dst=self.pg2.remote_ip4) /
             TCP(sport=1234, dport=1234))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        p = self.pg1.get_capture(1)
        packet = p[0]
        try:
            self.assertEqual(packet[IP].src, self.nat_addr)
            self.assertEqual(packet[IP].dst, self.pg1.remote_ip4)
            self.assertEqual(packet.haslayer(GRE), 1)
            self.assert_packet_checksums_valid(packet)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", packet))
            raise

        # out2in
        p = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
             IP(src=self.pg1.remote_ip4, dst=self.nat_addr) /
             GRE() /
             IP(src=self.pg2.remote_ip4, dst=self.pg2.local_ip4) /
             TCP(sport=1234, dport=1234))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        p = self.pg0.get_capture(1)
        packet = p[0]
        try:
            self.assertEqual(packet[IPv6].src, remote_ip6)
            self.assertEqual(packet[IPv6].dst, self.pg0.remote_ip6)
            self.assertEqual(packet[IPv6].nh, 47)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", packet))
            raise

    def test_hairpinning_unknown_proto(self):
        """ NAT64 translate packet with unknown protocol - hairpinning """

        client = self.pg0.remote_hosts[0]
        server = self.pg0.remote_hosts[1]
        server_tcp_in_port = 22
        server_tcp_out_port = 4022
        client_tcp_in_port = 1234
        client_tcp_out_port = 1235
        server_nat_ip = "10.0.0.100"
        client_nat_ip = "10.0.0.110"
        server_nat_ip6 = self.compose_ip6(server_nat_ip, '64:ff9b::', 96)
        client_nat_ip6 = self.compose_ip6(client_nat_ip, '64:ff9b::', 96)

        self.vapi.nat64_add_del_pool_addr_range(start_addr=server_nat_ip,
                                                end_addr=client_nat_ip,
                                                vrf_id=0xFFFFFFFF,
                                                is_add=1)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat64_add_del_interface(is_add=1, flags=flags,
                                          sw_if_index=self.pg0.sw_if_index)
        self.vapi.nat64_add_del_interface(is_add=1, flags=0,
                                          sw_if_index=self.pg1.sw_if_index)

        self.vapi.nat64_add_del_static_bib(i_addr=server.ip6n,
                                           o_addr=server_nat_ip,
                                           i_port=server_tcp_in_port,
                                           o_port=server_tcp_out_port,
                                           proto=IP_PROTOS.tcp, vrf_id=0,
                                           is_add=1)

        self.vapi.nat64_add_del_static_bib(i_addr=server.ip6n,
                                           o_addr=server_nat_ip, i_port=0,
                                           o_port=0,
                                           proto=IP_PROTOS.gre, vrf_id=0,
                                           is_add=1)

        self.vapi.nat64_add_del_static_bib(i_addr=client.ip6n,
                                           o_addr=client_nat_ip,
                                           i_port=client_tcp_in_port,
                                           o_port=client_tcp_out_port,
                                           proto=IP_PROTOS.tcp, vrf_id=0,
                                           is_add=1)

        # client to server
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IPv6(src=client.ip6, dst=server_nat_ip6) /
             TCP(sport=client_tcp_in_port, dport=server_tcp_out_port))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        p = self.pg0.get_capture(1)

        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IPv6(src=client.ip6, dst=server_nat_ip6, nh=IP_PROTOS.gre) /
             GRE() /
             IP(src=self.pg2.local_ip4, dst=self.pg2.remote_ip4) /
             TCP(sport=1234, dport=1234))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        p = self.pg0.get_capture(1)
        packet = p[0]
        try:
            self.assertEqual(packet[IPv6].src, client_nat_ip6)
            self.assertEqual(packet[IPv6].dst, server.ip6)
            self.assertEqual(packet[IPv6].nh, IP_PROTOS.gre)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", packet))
            raise

        # server to client
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IPv6(src=server.ip6, dst=client_nat_ip6, nh=IP_PROTOS.gre) /
             GRE() /
             IP(src=self.pg2.remote_ip4, dst=self.pg2.local_ip4) /
             TCP(sport=1234, dport=1234))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        p = self.pg0.get_capture(1)
        packet = p[0]
        try:
            self.assertEqual(packet[IPv6].src, server_nat_ip6)
            self.assertEqual(packet[IPv6].dst, client.ip6)
            self.assertEqual(packet[IPv6].nh, IP_PROTOS.gre)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", packet))
            raise

    def test_one_armed_nat64(self):
        """ One armed NAT64 """
        external_port = 0
        remote_host_ip6 = self.compose_ip6(self.pg3.remote_ip4,
                                           '64:ff9b::',
                                           96)

        self.vapi.nat64_add_del_pool_addr_range(start_addr=self.nat_addr,
                                                end_addr=self.nat_addr,
                                                vrf_id=0xFFFFFFFF,
                                                is_add=1)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat64_add_del_interface(is_add=1, flags=flags,
                                          sw_if_index=self.pg3.sw_if_index)
        self.vapi.nat64_add_del_interface(is_add=1, flags=0,
                                          sw_if_index=self.pg3.sw_if_index)

        # in2out
        p = (Ether(src=self.pg3.remote_mac, dst=self.pg3.local_mac) /
             IPv6(src=self.pg3.remote_ip6, dst=remote_host_ip6) /
             TCP(sport=12345, dport=80))
        self.pg3.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg3.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.src, self.nat_addr)
            self.assertEqual(ip.dst, self.pg3.remote_ip4)
            self.assertNotEqual(tcp.sport, 12345)
            external_port = tcp.sport
            self.assertEqual(tcp.dport, 80)
            self.assert_packet_checksums_valid(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        # out2in
        p = (Ether(src=self.pg3.remote_mac, dst=self.pg3.local_mac) /
             IP(src=self.pg3.remote_ip4, dst=self.nat_addr) /
             TCP(sport=80, dport=external_port))
        self.pg3.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg3.get_capture(1)
        p = capture[0]
        try:
            ip = p[IPv6]
            tcp = p[TCP]
            self.assertEqual(ip.src, remote_host_ip6)
            self.assertEqual(ip.dst, self.pg3.remote_ip6)
            self.assertEqual(tcp.sport, 80)
            self.assertEqual(tcp.dport, 12345)
            self.assert_packet_checksums_valid(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

    def test_frag_in_order(self):
        """ NAT64 translate fragments arriving in order """
        self.tcp_port_in = random.randint(1025, 65535)

        self.vapi.nat64_add_del_pool_addr_range(start_addr=self.nat_addr,
                                                end_addr=self.nat_addr,
                                                vrf_id=0xFFFFFFFF,
                                                is_add=1)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat64_add_del_interface(is_add=1, flags=flags,
                                          sw_if_index=self.pg0.sw_if_index)
        self.vapi.nat64_add_del_interface(is_add=1, flags=0,
                                          sw_if_index=self.pg1.sw_if_index)

        # in2out
        data = b'a' * 200
        pkts = self.create_stream_frag_ip6(self.pg0, self.pg1.remote_ip4,
                                           self.tcp_port_in, 20, data)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        frags = self.pg1.get_capture(len(pkts))
        p = self.reass_frags_and_verify(frags,
                                        self.nat_addr,
                                        self.pg1.remote_ip4)
        self.assertEqual(p[TCP].dport, 20)
        self.assertNotEqual(p[TCP].sport, self.tcp_port_in)
        self.tcp_port_out = p[TCP].sport
        self.assertEqual(data, p[Raw].load)

        # out2in
        data = b"A" * 4 + b"b" * 16 + b"C" * 3
        pkts = self.create_stream_frag(self.pg1,
                                       self.nat_addr,
                                       20,
                                       self.tcp_port_out,
                                       data)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        frags = self.pg0.get_capture(len(pkts))
        self.logger.debug(ppc("Captured:", frags))
        src = self.compose_ip6(self.pg1.remote_ip4, '64:ff9b::', 96)
        p = self.reass_frags_and_verify_ip6(frags, src, self.pg0.remote_ip6)
        self.assertEqual(p[TCP].sport, 20)
        self.assertEqual(p[TCP].dport, self.tcp_port_in)
        self.assertEqual(data, p[Raw].load)

    def test_reass_hairpinning(self):
        """ NAT64 fragments hairpinning """
        data = b'a' * 200
        server = self.pg0.remote_hosts[1]
        server_in_port = random.randint(1025, 65535)
        server_out_port = random.randint(1025, 65535)
        client_in_port = random.randint(1025, 65535)
        ip = IPv6(src=''.join(['64:ff9b::', self.nat_addr]))
        nat_addr_ip6 = ip.src

        self.vapi.nat64_add_del_pool_addr_range(start_addr=self.nat_addr,
                                                end_addr=self.nat_addr,
                                                vrf_id=0xFFFFFFFF,
                                                is_add=1)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat64_add_del_interface(is_add=1, flags=flags,
                                          sw_if_index=self.pg0.sw_if_index)
        self.vapi.nat64_add_del_interface(is_add=1, flags=0,
                                          sw_if_index=self.pg1.sw_if_index)

        # add static BIB entry for server
        self.vapi.nat64_add_del_static_bib(i_addr=server.ip6n,
                                           o_addr=self.nat_addr,
                                           i_port=server_in_port,
                                           o_port=server_out_port,
                                           proto=IP_PROTOS.tcp, vrf_id=0,
                                           is_add=1)

        # send packet from host to server
        pkts = self.create_stream_frag_ip6(self.pg0,
                                           self.nat_addr,
                                           client_in_port,
                                           server_out_port,
                                           data)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        frags = self.pg0.get_capture(len(pkts))
        self.logger.debug(ppc("Captured:", frags))
        p = self.reass_frags_and_verify_ip6(frags, nat_addr_ip6, server.ip6)
        self.assertNotEqual(p[TCP].sport, client_in_port)
        self.assertEqual(p[TCP].dport, server_in_port)
        self.assertEqual(data, p[Raw].load)

    def test_frag_out_of_order(self):
        """ NAT64 translate fragments arriving out of order """
        self.tcp_port_in = random.randint(1025, 65535)

        self.vapi.nat64_add_del_pool_addr_range(start_addr=self.nat_addr,
                                                end_addr=self.nat_addr,
                                                vrf_id=0xFFFFFFFF,
                                                is_add=1)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat64_add_del_interface(is_add=1, flags=flags,
                                          sw_if_index=self.pg0.sw_if_index)
        self.vapi.nat64_add_del_interface(is_add=1, flags=0,
                                          sw_if_index=self.pg1.sw_if_index)

        # in2out
        data = b'a' * 200
        pkts = self.create_stream_frag_ip6(self.pg0, self.pg1.remote_ip4,
                                           self.tcp_port_in, 20, data)
        pkts.reverse()
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        frags = self.pg1.get_capture(len(pkts))
        p = self.reass_frags_and_verify(frags,
                                        self.nat_addr,
                                        self.pg1.remote_ip4)
        self.assertEqual(p[TCP].dport, 20)
        self.assertNotEqual(p[TCP].sport, self.tcp_port_in)
        self.tcp_port_out = p[TCP].sport
        self.assertEqual(data, p[Raw].load)

        # out2in
        data = b"A" * 4 + b"B" * 16 + b"C" * 3
        pkts = self.create_stream_frag(self.pg1,
                                       self.nat_addr,
                                       20,
                                       self.tcp_port_out,
                                       data)
        pkts.reverse()
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        frags = self.pg0.get_capture(len(pkts))
        src = self.compose_ip6(self.pg1.remote_ip4, '64:ff9b::', 96)
        p = self.reass_frags_and_verify_ip6(frags, src, self.pg0.remote_ip6)
        self.assertEqual(p[TCP].sport, 20)
        self.assertEqual(p[TCP].dport, self.tcp_port_in)
        self.assertEqual(data, p[Raw].load)

    def test_interface_addr(self):
        """ Acquire NAT64 pool addresses from interface """
        self.vapi.nat64_add_del_interface_addr(
            is_add=1,
            sw_if_index=self.pg4.sw_if_index)

        # no address in NAT64 pool
        addresses = self.vapi.nat44_address_dump()
        self.assertEqual(0, len(addresses))

        # configure interface address and check NAT64 address pool
        self.pg4.config_ip4()
        addresses = self.vapi.nat64_pool_addr_dump()
        self.assertEqual(len(addresses), 1)

        self.assertEqual(str(addresses[0].address),
                         self.pg4.local_ip4)

        # remove interface address and check NAT64 address pool
        self.pg4.unconfig_ip4()
        addresses = self.vapi.nat64_pool_addr_dump()
        self.assertEqual(0, len(addresses))

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_ipfix_max_bibs_sessions(self):
        """ IPFIX logging maximum session and BIB entries exceeded """
        max_bibs = 1280
        max_sessions = 2560
        remote_host_ip6 = self.compose_ip6(self.pg1.remote_ip4,
                                           '64:ff9b::',
                                           96)

        self.vapi.nat64_add_del_pool_addr_range(start_addr=self.nat_addr,
                                                end_addr=self.nat_addr,
                                                vrf_id=0xFFFFFFFF,
                                                is_add=1)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat64_add_del_interface(is_add=1, flags=flags,
                                          sw_if_index=self.pg0.sw_if_index)
        self.vapi.nat64_add_del_interface(is_add=1, flags=0,
                                          sw_if_index=self.pg1.sw_if_index)

        pkts = []
        src = ""
        for i in range(0, max_bibs):
            src = "fd01:aa::%x" % (i)
            p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
                 IPv6(src=src, dst=remote_host_ip6) /
                 TCP(sport=12345, dport=80))
            pkts.append(p)
            p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
                 IPv6(src=src, dst=remote_host_ip6) /
                 TCP(sport=12345, dport=22))
            pkts.append(p)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.get_capture(max_sessions)

        self.vapi.set_ipfix_exporter(collector_address=self.pg3.remote_ip4,
                                     src_address=self.pg3.local_ip4,
                                     path_mtu=512,
                                     template_interval=10)
        self.vapi.nat_ipfix_enable_disable(domain_id=self.ipfix_domain_id,
                                           src_port=self.ipfix_src_port,
                                           enable=1)

        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IPv6(src=src, dst=remote_host_ip6) /
             TCP(sport=12345, dport=25))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.assert_nothing_captured()
        self.vapi.ipfix_flush()
        capture = self.pg3.get_capture(7)
        ipfix = IPFIXDecoder()
        # first load template
        for p in capture:
            self.assertTrue(p.haslayer(IPFIX))
            self.assertEqual(p[IP].src, self.pg3.local_ip4)
            self.assertEqual(p[IP].dst, self.pg3.remote_ip4)
            self.assertEqual(p[UDP].sport, self.ipfix_src_port)
            self.assertEqual(p[UDP].dport, 4739)
            self.assertEqual(p[IPFIX].observationDomainID,
                             self.ipfix_domain_id)
            if p.haslayer(Template):
                ipfix.add_template(p.getlayer(Template))
        # verify events in data set
        for p in capture:
            if p.haslayer(Data):
                data = ipfix.decode_data_set(p.getlayer(Set))
                self.verify_ipfix_max_sessions(data, max_sessions)

        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IPv6(src=self.pg0.remote_ip6, dst=remote_host_ip6) /
             TCP(sport=12345, dport=80))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.assert_nothing_captured()
        self.vapi.ipfix_flush()
        capture = self.pg3.get_capture(1)
        # verify events in data set
        for p in capture:
            self.assertTrue(p.haslayer(IPFIX))
            self.assertEqual(p[IP].src, self.pg3.local_ip4)
            self.assertEqual(p[IP].dst, self.pg3.remote_ip4)
            self.assertEqual(p[UDP].sport, self.ipfix_src_port)
            self.assertEqual(p[UDP].dport, 4739)
            self.assertEqual(p[IPFIX].observationDomainID,
                             self.ipfix_domain_id)
            if p.haslayer(Data):
                data = ipfix.decode_data_set(p.getlayer(Set))
                self.verify_ipfix_max_bibs(data, max_bibs)

    def test_ipfix_bib_ses(self):
        """ IPFIX logging NAT64 BIB/session create and delete events """
        self.tcp_port_in = random.randint(1025, 65535)
        remote_host_ip6 = self.compose_ip6(self.pg1.remote_ip4,
                                           '64:ff9b::',
                                           96)

        self.vapi.nat64_add_del_pool_addr_range(start_addr=self.nat_addr,
                                                end_addr=self.nat_addr,
                                                vrf_id=0xFFFFFFFF,
                                                is_add=1)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat64_add_del_interface(is_add=1, flags=flags,
                                          sw_if_index=self.pg0.sw_if_index)
        self.vapi.nat64_add_del_interface(is_add=1, flags=0,
                                          sw_if_index=self.pg1.sw_if_index)
        self.vapi.set_ipfix_exporter(collector_address=self.pg3.remote_ip4,
                                     src_address=self.pg3.local_ip4,
                                     path_mtu=512,
                                     template_interval=10)
        self.vapi.nat_ipfix_enable_disable(domain_id=self.ipfix_domain_id,
                                           src_port=self.ipfix_src_port,
                                           enable=1)

        # Create
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IPv6(src=self.pg0.remote_ip6, dst=remote_host_ip6) /
             TCP(sport=self.tcp_port_in, dport=25))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        p = self.pg1.get_capture(1)
        self.tcp_port_out = p[0][TCP].sport
        self.vapi.ipfix_flush()
        capture = self.pg3.get_capture(8)
        ipfix = IPFIXDecoder()
        # first load template
        for p in capture:
            self.assertTrue(p.haslayer(IPFIX))
            self.assertEqual(p[IP].src, self.pg3.local_ip4)
            self.assertEqual(p[IP].dst, self.pg3.remote_ip4)
            self.assertEqual(p[UDP].sport, self.ipfix_src_port)
            self.assertEqual(p[UDP].dport, 4739)
            self.assertEqual(p[IPFIX].observationDomainID,
                             self.ipfix_domain_id)
            if p.haslayer(Template):
                ipfix.add_template(p.getlayer(Template))
        # verify events in data set
        for p in capture:
            if p.haslayer(Data):
                data = ipfix.decode_data_set(p.getlayer(Set))
                if scapy.compat.orb(data[0][230]) == 10:
                    self.verify_ipfix_bib(data, 1, self.pg0.remote_ip6)
                elif scapy.compat.orb(data[0][230]) == 6:
                    self.verify_ipfix_nat64_ses(data,
                                                1,
                                                self.pg0.remote_ip6,
                                                self.pg1.remote_ip4,
                                                25)
                else:
                    self.logger.error(ppp("Unexpected or invalid packet: ", p))

        # Delete
        self.pg_enable_capture(self.pg_interfaces)
        self.vapi.nat64_add_del_pool_addr_range(start_addr=self.nat_addr,
                                                end_addr=self.nat_addr,
                                                vrf_id=0xFFFFFFFF,
                                                is_add=0)
        self.vapi.ipfix_flush()
        capture = self.pg3.get_capture(2)
        # verify events in data set
        for p in capture:
            self.assertTrue(p.haslayer(IPFIX))
            self.assertEqual(p[IP].src, self.pg3.local_ip4)
            self.assertEqual(p[IP].dst, self.pg3.remote_ip4)
            self.assertEqual(p[UDP].sport, self.ipfix_src_port)
            self.assertEqual(p[UDP].dport, 4739)
            self.assertEqual(p[IPFIX].observationDomainID,
                             self.ipfix_domain_id)
            if p.haslayer(Data):
                data = ipfix.decode_data_set(p.getlayer(Set))
                if scapy.compat.orb(data[0][230]) == 11:
                    self.verify_ipfix_bib(data, 0, self.pg0.remote_ip6)
                elif scapy.compat.orb(data[0][230]) == 7:
                    self.verify_ipfix_nat64_ses(data,
                                                0,
                                                self.pg0.remote_ip6,
                                                self.pg1.remote_ip4,
                                                25)
                else:
                    self.logger.error(ppp("Unexpected or invalid packet: ", p))

    def test_syslog_sess(self):
        """ Test syslog session creation and deletion """
        self.tcp_port_in = random.randint(1025, 65535)
        remote_host_ip6 = self.compose_ip6(self.pg1.remote_ip4,
                                           '64:ff9b::',
                                           96)

        self.vapi.nat64_add_del_pool_addr_range(start_addr=self.nat_addr,
                                                end_addr=self.nat_addr,
                                                vrf_id=0xFFFFFFFF,
                                                is_add=1)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat64_add_del_interface(is_add=1, flags=flags,
                                          sw_if_index=self.pg0.sw_if_index)
        self.vapi.nat64_add_del_interface(is_add=1, flags=0,
                                          sw_if_index=self.pg1.sw_if_index)
        self.vapi.syslog_set_filter(
            self.SYSLOG_SEVERITY.SYSLOG_API_SEVERITY_INFO)
        self.vapi.syslog_set_sender(self.pg3.local_ip4, self.pg3.remote_ip4)

        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IPv6(src=self.pg0.remote_ip6, dst=remote_host_ip6) /
             TCP(sport=self.tcp_port_in, dport=self.tcp_external_port))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        p = self.pg1.get_capture(1)
        self.tcp_port_out = p[0][TCP].sport
        capture = self.pg3.get_capture(1)
        self.verify_syslog_sess(capture[0][Raw].load, is_ip6=True)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.vapi.nat64_add_del_pool_addr_range(start_addr=self.nat_addr,
                                                end_addr=self.nat_addr,
                                                vrf_id=0xFFFFFFFF,
                                                is_add=0)
        capture = self.pg3.get_capture(1)
        self.verify_syslog_sess(capture[0][Raw].load, False, True)

    def nat64_get_ses_num(self):
        """
        Return number of active NAT64 sessions.
        """
        st = self.vapi.nat64_st_dump(proto=255)
        return len(st)

    def clear_nat64(self):
        """
        Clear NAT64 configuration.
        """
        self.vapi.nat_ipfix_enable_disable(domain_id=self.ipfix_domain_id,
                                           src_port=self.ipfix_src_port,
                                           enable=0)
        self.ipfix_src_port = 4739
        self.ipfix_domain_id = 1

        self.vapi.syslog_set_filter(
            self.SYSLOG_SEVERITY.SYSLOG_API_SEVERITY_EMERG)

        self.vapi.nat64_set_timeouts(udp=300, tcp_established=7440,
                                     tcp_transitory=240, icmp=60)

        interfaces = self.vapi.nat64_interface_dump()
        for intf in interfaces:
            self.vapi.nat64_add_del_interface(is_add=0, flags=intf.flags,
                                              sw_if_index=intf.sw_if_index)

        bib = self.vapi.nat64_bib_dump(proto=255)
        for bibe in bib:
            if bibe.flags & self.config_flags.NAT_IS_STATIC:
                self.vapi.nat64_add_del_static_bib(i_addr=bibe.i_addr,
                                                   o_addr=bibe.o_addr,
                                                   i_port=bibe.i_port,
                                                   o_port=bibe.o_port,
                                                   proto=bibe.proto,
                                                   vrf_id=bibe.vrf_id,
                                                   is_add=0)

        adresses = self.vapi.nat64_pool_addr_dump()
        for addr in adresses:
            self.vapi.nat64_add_del_pool_addr_range(start_addr=addr.address,
                                                    end_addr=addr.address,
                                                    vrf_id=addr.vrf_id,
                                                    is_add=0)

        prefixes = self.vapi.nat64_prefix_dump()
        for prefix in prefixes:
            self.vapi.nat64_add_del_prefix(prefix=str(prefix.prefix),
                                           vrf_id=prefix.vrf_id, is_add=0)

        bibs = self.statistics.get_counter('/nat64/total-bibs')
        self.assertEqual(bibs[0][0], 0)
        sessions = self.statistics.get_counter('/nat64/total-sessions')
        self.assertEqual(sessions[0][0], 0)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
