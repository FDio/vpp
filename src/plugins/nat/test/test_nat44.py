#!/usr/bin/env python3

import ipaddress
import random
import socket
import struct
import unittest
from io import BytesIO
from time import sleep

import scapy.compat
from framework import VppTestCase, VppTestRunner, running_extended_tests
from ipfix import IPFIX, Set, Template, Data, IPFIXDecoder
from scapy.all import bind_layers, Packet, ByteEnumField, ShortField, \
    IPField, IntField, LongField, XByteField, FlagsField, FieldLenField, \
    PacketListField
from scapy.data import IP_PROTOS
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet import IPerror, TCPerror, UDPerror, ICMPerror
from scapy.layers.inet6 import ICMPv6DestUnreach, IPerror6, IPv6ExtHdrFragment
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply, \
    ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, fragment6
from scapy.layers.l2 import Ether, ARP, GRE
from scapy.packet import Raw
from syslog_rfc5424_parser import SyslogMessage, ParseError
from syslog_rfc5424_parser.constants import SyslogSeverity
from util import ip4_range
from util import ppc, ppp
from vpp_acl import AclRule, VppAcl, VppAclInterface
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_neighbor import VppNeighbor
from vpp_papi import VppEnum


# NAT HA protocol event data
class Event(Packet):
    name = "Event"
    fields_desc = [ByteEnumField("event_type", None,
                                 {1: "add", 2: "del", 3: "refresh"}),
                   ByteEnumField("protocol", None,
                                 {0: "other", 1: "udp", 2: "tcp", 3: "icmp"}),
                   ShortField("flags", 0),
                   IPField("in_addr", None),
                   IPField("out_addr", None),
                   ShortField("in_port", None),
                   ShortField("out_port", None),
                   IPField("eh_addr", None),
                   IPField("ehn_addr", None),
                   ShortField("eh_port", None),
                   ShortField("ehn_port", None),
                   IntField("fib_index", None),
                   IntField("total_pkts", 0),
                   LongField("total_bytes", 0)]

    def extract_padding(self, s):
        return "", s


# NAT HA protocol header
class HANATStateSync(Packet):
    name = "HA NAT state sync"
    fields_desc = [XByteField("version", 1),
                   FlagsField("flags", 0, 8, ['ACK']),
                   FieldLenField("count", None, count_of="events"),
                   IntField("sequence_number", 1),
                   IntField("thread_index", 0),
                   PacketListField("events", [], Event,
                                   count_from=lambda pkt: pkt.count)]


class MethodHolder(VppTestCase):
    """ NAT create capture and verify method holder """

    @property
    def config_flags(self):
        return VppEnum.vl_api_nat_config_flags_t

    @property
    def nat44_config_flags(self):
        return VppEnum.vl_api_nat44_config_flags_t

    @property
    def SYSLOG_SEVERITY(self):
        return VppEnum.vl_api_syslog_severity_t

    def nat44_add_static_mapping(self, local_ip, external_ip='0.0.0.0',
                                 local_port=0, external_port=0, vrf_id=0,
                                 is_add=1, external_sw_if_index=0xFFFFFFFF,
                                 proto=0, tag="", flags=0):
        """
        Add/delete NAT44 static mapping

        :param local_ip: Local IP address
        :param external_ip: External IP address
        :param local_port: Local port number (Optional)
        :param external_port: External port number (Optional)
        :param vrf_id: VRF ID (Default 0)
        :param is_add: 1 if add, 0 if delete (Default add)
        :param external_sw_if_index: External interface instead of IP address
        :param proto: IP protocol (Mandatory if port specified)
        :param tag: Opaque string tag
        :param flags: NAT configuration flags
        """

        if not (local_port and external_port):
            flags |= self.config_flags.NAT_IS_ADDR_ONLY

        self.vapi.nat44_add_del_static_mapping(
            is_add=is_add,
            local_ip_address=local_ip,
            external_ip_address=external_ip,
            external_sw_if_index=external_sw_if_index,
            local_port=local_port,
            external_port=external_port,
            vrf_id=vrf_id, protocol=proto,
            flags=flags,
            tag=tag)

    def nat44_add_address(self, ip, is_add=1, vrf_id=0xFFFFFFFF, twice_nat=0):
        """
        Add/delete NAT44 address

        :param ip: IP address
        :param is_add: 1 if add, 0 if delete (Default add)
        :param twice_nat: twice NAT address for external hosts
        """
        flags = self.config_flags.NAT_IS_TWICE_NAT if twice_nat else 0
        self.vapi.nat44_add_del_address_range(first_ip_address=ip,
                                              last_ip_address=ip,
                                              vrf_id=vrf_id,
                                              is_add=is_add,
                                              flags=flags)

    def create_stream_in(self, in_if, out_if, dst_ip=None, ttl=64):
        """
        Create packet stream for inside network

        :param in_if: Inside interface
        :param out_if: Outside interface
        :param dst_ip: Destination address
        :param ttl: TTL of generated packets
        """
        if dst_ip is None:
            dst_ip = out_if.remote_ip4

        pkts = []
        # TCP
        p = (Ether(dst=in_if.local_mac, src=in_if.remote_mac) /
             IP(src=in_if.remote_ip4, dst=dst_ip, ttl=ttl) /
             TCP(sport=self.tcp_port_in, dport=20))
        pkts.extend([p, p])

        # UDP
        p = (Ether(dst=in_if.local_mac, src=in_if.remote_mac) /
             IP(src=in_if.remote_ip4, dst=dst_ip, ttl=ttl) /
             UDP(sport=self.udp_port_in, dport=20))
        pkts.append(p)

        # ICMP
        p = (Ether(dst=in_if.local_mac, src=in_if.remote_mac) /
             IP(src=in_if.remote_ip4, dst=dst_ip, ttl=ttl) /
             ICMP(id=self.icmp_id_in, type='echo-request'))
        pkts.append(p)

        return pkts

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

    def extract_ip4(self, ip6, plen):
        """
        Extract IPv4 address embedded in IPv6 addresses

        :param ip6: IPv6 address
        :param plen: IPv6 prefix length
        :returns: extracted IPv4 address
        """
        ip6_n = list(socket.inet_pton(socket.AF_INET6, ip6))
        ip4_n = [None] * 4
        if plen == 32:
            ip4_n[0] = ip6_n[4]
            ip4_n[1] = ip6_n[5]
            ip4_n[2] = ip6_n[6]
            ip4_n[3] = ip6_n[7]
        elif plen == 40:
            ip4_n[0] = ip6_n[5]
            ip4_n[1] = ip6_n[6]
            ip4_n[2] = ip6_n[7]
            ip4_n[3] = ip6_n[9]
        elif plen == 48:
            ip4_n[0] = ip6_n[6]
            ip4_n[1] = ip6_n[7]
            ip4_n[2] = ip6_n[9]
            ip4_n[3] = ip6_n[10]
        elif plen == 56:
            ip4_n[0] = ip6_n[7]
            ip4_n[1] = ip6_n[9]
            ip4_n[2] = ip6_n[10]
            ip4_n[3] = ip6_n[11]
        elif plen == 64:
            ip4_n[0] = ip6_n[9]
            ip4_n[1] = ip6_n[10]
            ip4_n[2] = ip6_n[11]
            ip4_n[3] = ip6_n[12]
        elif plen == 96:
            ip4_n[0] = ip6_n[12]
            ip4_n[1] = ip6_n[13]
            ip4_n[2] = ip6_n[14]
            ip4_n[3] = ip6_n[15]
        return socket.inet_ntop(socket.AF_INET, ''.join(ip4_n))

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

    def create_stream_out_ip6(self, out_if, src_ip, dst_ip, hl=64):
        """
        Create packet stream for outside network

        :param out_if: Outside interface
        :param dst_ip: Destination IP address (Default use global NAT address)
        :param hl: HL of generated packets
        """
        pkts = []
        # TCP
        p = (Ether(dst=out_if.local_mac, src=out_if.remote_mac) /
             IPv6(src=src_ip, dst=dst_ip, hlim=hl) /
             TCP(dport=self.tcp_port_out, sport=20))
        pkts.append(p)

        # UDP
        p = (Ether(dst=out_if.local_mac, src=out_if.remote_mac) /
             IPv6(src=src_ip, dst=dst_ip, hlim=hl) /
             UDP(dport=self.udp_port_out, sport=20))
        pkts.append(p)

        # ICMP
        p = (Ether(dst=out_if.local_mac, src=out_if.remote_mac) /
             IPv6(src=src_ip, dst=dst_ip, hlim=hl) /
             ICMPv6EchoReply(id=self.icmp_id_out))
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

    def verify_capture_out_ip6(self, capture, nat_ip, same_port=False,
                               dst_ip=None):
        """
        Verify captured packets on outside network

        :param capture: Captured packets
        :param nat_ip: Translated IP address
        :param same_port: Source port number is not translated (Default False)
        :param dst_ip: Destination IP address (Default do not verify)
        """
        return self.verify_capture_out(capture, nat_ip, same_port, dst_ip,
                                       True)

    def verify_capture_in(self, capture, in_if):
        """
        Verify captured packets on inside network

        :param capture: Captured packets
        :param in_if: Inside interface
        """
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
                self.logger.error(ppp("Unexpected or invalid packet "
                                      "(inside network):", packet))
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

    def verify_capture_no_translation(self, capture, ingress_if, egress_if):
        """
        Verify captured packet that don't have to be translated

        :param capture: Captured packets
        :param ingress_if: Ingress interface
        :param egress_if: Egress interface
        """
        for packet in capture:
            try:
                self.assertEqual(packet[IP].src, ingress_if.remote_ip4)
                self.assertEqual(packet[IP].dst, egress_if.remote_ip4)
                if packet.haslayer(TCP):
                    self.assertEqual(packet[TCP].sport, self.tcp_port_in)
                elif packet.haslayer(UDP):
                    self.assertEqual(packet[UDP].sport, self.udp_port_in)
                else:
                    self.assertEqual(packet[ICMP].id, self.icmp_id_in)
            except:
                self.logger.error(ppp("Unexpected or invalid packet "
                                      "(inside network):", packet))
                raise

    def verify_capture_out_with_icmp_errors(self, capture, src_ip=None,
                                            icmp_type=11):
        """
        Verify captured packets with ICMP errors on outside network

        :param capture: Captured packets
        :param src_ip: Translated IP address or IP address of VPP
                       (Default use global NAT address)
        :param icmp_type: Type of error ICMP packet
                          we are expecting (Default 11)
        """
        if src_ip is None:
            src_ip = self.nat_addr
        for packet in capture:
            try:
                self.assertEqual(packet[IP].src, src_ip)
                self.assertEqual(packet.haslayer(ICMP), 1)
                icmp = packet[ICMP]
                self.assertEqual(icmp.type, icmp_type)
                self.assertTrue(icmp.haslayer(IPerror))
                inner_ip = icmp[IPerror]
                if inner_ip.haslayer(TCPerror):
                    self.assertEqual(inner_ip[TCPerror].dport,
                                     self.tcp_port_out)
                elif inner_ip.haslayer(UDPerror):
                    self.assertEqual(inner_ip[UDPerror].dport,
                                     self.udp_port_out)
                else:
                    self.assertEqual(inner_ip[ICMPerror].id, self.icmp_id_out)
            except:
                self.logger.error(ppp("Unexpected or invalid packet "
                                      "(outside network):", packet))
                raise

    def verify_capture_in_with_icmp_errors(self, capture, in_if, icmp_type=11):
        """
        Verify captured packets with ICMP errors on inside network

        :param capture: Captured packets
        :param in_if: Inside interface
        :param icmp_type: Type of error ICMP packet
                          we are expecting (Default 11)
        """
        for packet in capture:
            try:
                self.assertEqual(packet[IP].dst, in_if.remote_ip4)
                self.assertEqual(packet.haslayer(ICMP), 1)
                icmp = packet[ICMP]
                self.assertEqual(icmp.type, icmp_type)
                self.assertTrue(icmp.haslayer(IPerror))
                inner_ip = icmp[IPerror]
                if inner_ip.haslayer(TCPerror):
                    self.assertEqual(inner_ip[TCPerror].sport,
                                     self.tcp_port_in)
                elif inner_ip.haslayer(UDPerror):
                    self.assertEqual(inner_ip[UDPerror].sport,
                                     self.udp_port_in)
                else:
                    self.assertEqual(inner_ip[ICMPerror].id, self.icmp_id_in)
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

    def initiate_tcp_session(self, in_if, out_if):
        """
        Initiates TCP session

        :param in_if: Inside interface
        :param out_if: Outside interface
        """
        try:
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

        except:
            self.logger.error("TCP 3 way handshake failed")
            raise

    def verify_ipfix_nat44_ses(self, data):
        """
        Verify IPFIX NAT44 session create/delete event

        :param data: Decoded IPFIX data records
        """
        nat44_ses_create_num = 0
        nat44_ses_delete_num = 0
        self.assertEqual(6, len(data))
        for record in data:
            # natEvent
            self.assertIn(scapy.compat.orb(record[230]), [4, 5])
            if scapy.compat.orb(record[230]) == 4:
                nat44_ses_create_num += 1
            else:
                nat44_ses_delete_num += 1
            # sourceIPv4Address
            self.assertEqual(self.pg0.remote_ip4,
                             str(ipaddress.IPv4Address(record[8])))
            # postNATSourceIPv4Address
            self.assertEqual(socket.inet_pton(socket.AF_INET, self.nat_addr),
                             record[225])
            # ingressVRFID
            self.assertEqual(struct.pack("!I", 0), record[234])
            # protocolIdentifier/sourceTransportPort
            # /postNAPTSourceTransportPort
            if IP_PROTOS.icmp == scapy.compat.orb(record[4]):
                self.assertEqual(struct.pack("!H", self.icmp_id_in), record[7])
                self.assertEqual(struct.pack("!H", self.icmp_id_out),
                                 record[227])
            elif IP_PROTOS.tcp == scapy.compat.orb(record[4]):
                self.assertEqual(struct.pack("!H", self.tcp_port_in),
                                 record[7])
                self.assertEqual(struct.pack("!H", self.tcp_port_out),
                                 record[227])
            elif IP_PROTOS.udp == scapy.compat.orb(record[4]):
                self.assertEqual(struct.pack("!H", self.udp_port_in),
                                 record[7])
                self.assertEqual(struct.pack("!H", self.udp_port_out),
                                 record[227])
            else:
                self.fail("Invalid protocol")
        self.assertEqual(3, nat44_ses_create_num)
        self.assertEqual(3, nat44_ses_delete_num)

    def verify_ipfix_addr_exhausted(self, data):
        """
        Verify IPFIX NAT addresses event

        :param data: Decoded IPFIX data records
        """
        self.assertEqual(1, len(data))
        record = data[0]
        # natEvent
        self.assertEqual(scapy.compat.orb(record[230]), 3)
        # natPoolID
        self.assertEqual(struct.pack("!I", 0), record[283])

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

    def verify_no_nat44_user(self):
        """ Verify that there is no NAT44 user """
        users = self.vapi.nat44_user_dump()
        self.assertEqual(len(users), 0)
        users = self.statistics.get_counter('/nat44/total-users')
        self.assertEqual(users[0][0], 0)
        sessions = self.statistics.get_counter('/nat44/total-sessions')
        self.assertEqual(sessions[0][0], 0)

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

    def verify_syslog_apmap(self, data, is_add=True):
        message = data.decode('utf-8')
        try:
            message = SyslogMessage.parse(message)
        except ParseError as e:
            self.logger.error(e)
            raise
        else:
            self.assertEqual(message.severity, SyslogSeverity.info)
            self.assertEqual(message.appname, 'NAT')
            self.assertEqual(message.msgid, 'APMADD' if is_add else 'APMDEL')
            sd_params = message.sd.get('napmap')
            self.assertTrue(sd_params is not None)
            self.assertEqual(sd_params.get('IATYP'), 'IPv4')
            self.assertEqual(sd_params.get('ISADDR'), self.pg0.remote_ip4)
            self.assertEqual(sd_params.get('ISPORT'), "%d" % self.tcp_port_in)
            self.assertEqual(sd_params.get('XATYP'), 'IPv4')
            self.assertEqual(sd_params.get('XSADDR'), self.nat_addr)
            self.assertEqual(sd_params.get('XSPORT'), "%d" % self.tcp_port_out)
            self.assertEqual(sd_params.get('PROTO'), "%d" % IP_PROTOS.tcp)
            self.assertTrue(sd_params.get('SSUBIX') is not None)
            self.assertEqual(sd_params.get('SVLAN'), '0')

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

    def verify_mss_value(self, pkt, mss):
        """
        Verify TCP MSS value

        :param pkt:
        :param mss:
        """
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            raise TypeError("Not a TCP/IP packet")

        for option in pkt[TCP].options:
            if option[0] == 'MSS':
                self.assertEqual(option[1], mss)
                self.assert_tcp_checksum_valid(pkt)

    @staticmethod
    def proto2layer(proto):
        if proto == IP_PROTOS.tcp:
            return TCP
        elif proto == IP_PROTOS.udp:
            return UDP
        elif proto == IP_PROTOS.icmp:
            return ICMP
        else:
            raise Exception("Unsupported protocol")

    def frag_in_order(self, proto=IP_PROTOS.tcp, dont_translate=False,
                      ignore_port=False):
        layer = self.proto2layer(proto)

        if proto == IP_PROTOS.tcp:
            data = b"A" * 4 + b"B" * 16 + b"C" * 3
        else:
            data = b"A" * 16 + b"B" * 16 + b"C" * 3
        self.port_in = random.randint(1025, 65535)

        # in2out
        pkts = self.create_stream_frag(self.pg0, self.pg1.remote_ip4,
                                       self.port_in, 20, data, proto)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        frags = self.pg1.get_capture(len(pkts))
        if not dont_translate:
            p = self.reass_frags_and_verify(frags,
                                            self.nat_addr,
                                            self.pg1.remote_ip4)
        else:
            p = self.reass_frags_and_verify(frags,
                                            self.pg0.remote_ip4,
                                            self.pg1.remote_ip4)
        if proto != IP_PROTOS.icmp:
            if not dont_translate:
                self.assertEqual(p[layer].dport, 20)
                if not ignore_port:
                    self.assertNotEqual(p[layer].sport, self.port_in)
            else:
                self.assertEqual(p[layer].sport, self.port_in)
        else:
            if not ignore_port:
                if not dont_translate:
                    self.assertNotEqual(p[layer].id, self.port_in)
                else:
                    self.assertEqual(p[layer].id, self.port_in)
        self.assertEqual(data, p[Raw].load)

        # out2in
        if not dont_translate:
            dst_addr = self.nat_addr
        else:
            dst_addr = self.pg0.remote_ip4
        if proto != IP_PROTOS.icmp:
            sport = 20
            dport = p[layer].sport
        else:
            sport = p[layer].id
            dport = 0
        pkts = self.create_stream_frag(self.pg1, dst_addr, sport, dport, data,
                                       proto, echo_reply=True)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        frags = self.pg0.get_capture(len(pkts))
        p = self.reass_frags_and_verify(frags,
                                        self.pg1.remote_ip4,
                                        self.pg0.remote_ip4)
        if proto != IP_PROTOS.icmp:
            self.assertEqual(p[layer].sport, 20)
            self.assertEqual(p[layer].dport, self.port_in)
        else:
            self.assertEqual(p[layer].id, self.port_in)
        self.assertEqual(data, p[Raw].load)

    def frag_in_order_in_plus_out(self, proto=IP_PROTOS.tcp):
        layer = self.proto2layer(proto)

        if proto == IP_PROTOS.tcp:
            data = b"A" * 4 + b"B" * 16 + b"C" * 3
        else:
            data = b"A" * 16 + b"B" * 16 + b"C" * 3
        self.port_in = random.randint(1025, 65535)

        for i in range(2):
            # out2in
            pkts = self.create_stream_frag(self.pg0, self.server_out_addr,
                                           self.port_in, self.server_out_port,
                                           data, proto)
            self.pg0.add_stream(pkts)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            frags = self.pg1.get_capture(len(pkts))
            p = self.reass_frags_and_verify(frags,
                                            self.pg0.remote_ip4,
                                            self.server_in_addr)
            if proto != IP_PROTOS.icmp:
                self.assertEqual(p[layer].sport, self.port_in)
                self.assertEqual(p[layer].dport, self.server_in_port)
            else:
                self.assertEqual(p[layer].id, self.port_in)
            self.assertEqual(data, p[Raw].load)

            # in2out
            if proto != IP_PROTOS.icmp:
                pkts = self.create_stream_frag(self.pg1, self.pg0.remote_ip4,
                                               self.server_in_port,
                                               p[layer].sport, data, proto)
            else:
                pkts = self.create_stream_frag(self.pg1, self.pg0.remote_ip4,
                                               p[layer].id, 0, data, proto,
                                               echo_reply=True)
            self.pg1.add_stream(pkts)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            frags = self.pg0.get_capture(len(pkts))
            p = self.reass_frags_and_verify(frags,
                                            self.server_out_addr,
                                            self.pg0.remote_ip4)
            if proto != IP_PROTOS.icmp:
                self.assertEqual(p[layer].sport, self.server_out_port)
                self.assertEqual(p[layer].dport, self.port_in)
            else:
                self.assertEqual(p[layer].id, self.port_in)
            self.assertEqual(data, p[Raw].load)

    def reass_hairpinning(self, proto=IP_PROTOS.tcp, ignore_port=False):
        layer = self.proto2layer(proto)

        if proto == IP_PROTOS.tcp:
            data = b"A" * 4 + b"B" * 16 + b"C" * 3
        else:
            data = b"A" * 16 + b"B" * 16 + b"C" * 3

        # send packet from host to server
        pkts = self.create_stream_frag(self.pg0,
                                       self.nat_addr,
                                       self.host_in_port,
                                       self.server_out_port,
                                       data,
                                       proto)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        frags = self.pg0.get_capture(len(pkts))
        p = self.reass_frags_and_verify(frags,
                                        self.nat_addr,
                                        self.server.ip4)
        if proto != IP_PROTOS.icmp:
            if not ignore_port:
                self.assertNotEqual(p[layer].sport, self.host_in_port)
            self.assertEqual(p[layer].dport, self.server_in_port)
        else:
            if not ignore_port:
                self.assertNotEqual(p[layer].id, self.host_in_port)
        self.assertEqual(data, p[Raw].load)

    def frag_out_of_order(self, proto=IP_PROTOS.tcp, dont_translate=False,
                          ignore_port=False):
        layer = self.proto2layer(proto)

        if proto == IP_PROTOS.tcp:
            data = b"A" * 4 + b"B" * 16 + b"C" * 3
        else:
            data = b"A" * 16 + b"B" * 16 + b"C" * 3
        self.port_in = random.randint(1025, 65535)

        for i in range(2):
            # in2out
            pkts = self.create_stream_frag(self.pg0, self.pg1.remote_ip4,
                                           self.port_in, 20, data, proto)
            pkts.reverse()
            self.pg0.add_stream(pkts)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            frags = self.pg1.get_capture(len(pkts))
            if not dont_translate:
                p = self.reass_frags_and_verify(frags,
                                                self.nat_addr,
                                                self.pg1.remote_ip4)
            else:
                p = self.reass_frags_and_verify(frags,
                                                self.pg0.remote_ip4,
                                                self.pg1.remote_ip4)
            if proto != IP_PROTOS.icmp:
                if not dont_translate:
                    self.assertEqual(p[layer].dport, 20)
                    if not ignore_port:
                        self.assertNotEqual(p[layer].sport, self.port_in)
                else:
                    self.assertEqual(p[layer].sport, self.port_in)
            else:
                if not ignore_port:
                    if not dont_translate:
                        self.assertNotEqual(p[layer].id, self.port_in)
                    else:
                        self.assertEqual(p[layer].id, self.port_in)
            self.assertEqual(data, p[Raw].load)

            # out2in
            if not dont_translate:
                dst_addr = self.nat_addr
            else:
                dst_addr = self.pg0.remote_ip4
            if proto != IP_PROTOS.icmp:
                sport = 20
                dport = p[layer].sport
            else:
                sport = p[layer].id
                dport = 0
            pkts = self.create_stream_frag(self.pg1, dst_addr, sport, dport,
                                           data, proto, echo_reply=True)
            pkts.reverse()
            self.pg1.add_stream(pkts)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            frags = self.pg0.get_capture(len(pkts))
            p = self.reass_frags_and_verify(frags,
                                            self.pg1.remote_ip4,
                                            self.pg0.remote_ip4)
            if proto != IP_PROTOS.icmp:
                self.assertEqual(p[layer].sport, 20)
                self.assertEqual(p[layer].dport, self.port_in)
            else:
                self.assertEqual(p[layer].id, self.port_in)
            self.assertEqual(data, p[Raw].load)

    def frag_out_of_order_in_plus_out(self, proto=IP_PROTOS.tcp):
        layer = self.proto2layer(proto)

        if proto == IP_PROTOS.tcp:
            data = b"A" * 4 + b"B" * 16 + b"C" * 3
        else:
            data = b"A" * 16 + b"B" * 16 + b"C" * 3
        self.port_in = random.randint(1025, 65535)

        for i in range(2):
            # out2in
            pkts = self.create_stream_frag(self.pg0, self.server_out_addr,
                                           self.port_in, self.server_out_port,
                                           data, proto)
            pkts.reverse()
            self.pg0.add_stream(pkts)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            frags = self.pg1.get_capture(len(pkts))
            p = self.reass_frags_and_verify(frags,
                                            self.pg0.remote_ip4,
                                            self.server_in_addr)
            if proto != IP_PROTOS.icmp:
                self.assertEqual(p[layer].dport, self.server_in_port)
                self.assertEqual(p[layer].sport, self.port_in)
                self.assertEqual(p[layer].dport, self.server_in_port)
            else:
                self.assertEqual(p[layer].id, self.port_in)
            self.assertEqual(data, p[Raw].load)

            # in2out
            if proto != IP_PROTOS.icmp:
                pkts = self.create_stream_frag(self.pg1, self.pg0.remote_ip4,
                                               self.server_in_port,
                                               p[layer].sport, data, proto)
            else:
                pkts = self.create_stream_frag(self.pg1, self.pg0.remote_ip4,
                                               p[layer].id, 0, data, proto,
                                               echo_reply=True)
            pkts.reverse()
            self.pg1.add_stream(pkts)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            frags = self.pg0.get_capture(len(pkts))
            p = self.reass_frags_and_verify(frags,
                                            self.server_out_addr,
                                            self.pg0.remote_ip4)
            if proto != IP_PROTOS.icmp:
                self.assertEqual(p[layer].sport, self.server_out_port)
                self.assertEqual(p[layer].dport, self.port_in)
            else:
                self.assertEqual(p[layer].id, self.port_in)
            self.assertEqual(data, p[Raw].load)


class TestNATMisc(MethodHolder):
    """ NAT misc Test Cases """

    max_translations = 10240
    max_users = 10240

    def setUp(self):
        super(TestNATMisc, self).setUp()
        self.vapi.nat44_plugin_enable_disable(
            sessions=self.max_translations,
            users=self.max_users, enable=1)

    def tearDown(self):
        super(TestNATMisc, self).tearDown()
        if not self.vpp_dead:
            self.vapi.nat44_plugin_enable_disable(enable=0)
            self.vapi.cli("clear logging")

    def test_show_max_translations(self):
        """ API test - max translations per thread """
        nat_config = self.vapi.nat_show_config_2()
        self.assertEqual(self.max_translations,
                         nat_config.max_translations_per_thread)


class TestNAT44(MethodHolder):
    """ NAT44 Test Cases """

    max_translations = 10240
    max_users = 10240

    @classmethod
    def setUpClass(cls):
        super(TestNAT44, cls).setUpClass()
        cls.vapi.cli("set log class nat level debug")

        cls.tcp_port_in = 6303
        cls.tcp_port_out = 6303
        cls.udp_port_in = 6304
        cls.udp_port_out = 6304
        cls.icmp_id_in = 6305
        cls.icmp_id_out = 6305
        cls.nat_addr = '10.0.0.3'
        cls.ipfix_src_port = 4739
        cls.ipfix_domain_id = 1
        cls.tcp_external_port = 80
        cls.udp_external_port = 69

        cls.create_pg_interfaces(range(10))
        cls.interfaces = list(cls.pg_interfaces[0:4])

        for i in cls.interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

        cls.pg0.generate_remote_hosts(3)
        cls.pg0.configure_ipv4_neighbors()

        cls.pg1.generate_remote_hosts(1)
        cls.pg1.configure_ipv4_neighbors()

        cls.overlapping_interfaces = list(list(cls.pg_interfaces[4:7]))
        cls.vapi.ip_table_add_del(is_add=1, table={'table_id': 10})
        cls.vapi.ip_table_add_del(is_add=1, table={'table_id': 20})

        cls.pg4._local_ip4 = "172.16.255.1"
        cls.pg4._remote_hosts[0]._ip4 = "172.16.255.2"
        cls.pg4.set_table_ip4(10)
        cls.pg5._local_ip4 = "172.17.255.3"
        cls.pg5._remote_hosts[0]._ip4 = "172.17.255.4"
        cls.pg5.set_table_ip4(10)
        cls.pg6._local_ip4 = "172.16.255.1"
        cls.pg6._remote_hosts[0]._ip4 = "172.16.255.2"
        cls.pg6.set_table_ip4(20)
        for i in cls.overlapping_interfaces:
            i.config_ip4()
            i.admin_up()
            i.resolve_arp()

        cls.pg7.admin_up()
        cls.pg8.admin_up()

        cls.pg9.generate_remote_hosts(2)
        cls.pg9.config_ip4()
        cls.vapi.sw_interface_add_del_address(
            sw_if_index=cls.pg9.sw_if_index,
            prefix="10.0.0.1/24")

        cls.pg9.admin_up()
        cls.pg9.resolve_arp()
        cls.pg9._remote_hosts[1]._ip4 = cls.pg9._remote_hosts[0]._ip4
        cls.pg4._remote_ip4 = cls.pg9._remote_hosts[0]._ip4 = "10.0.0.2"
        cls.pg9.resolve_arp()

    def setUp(self):
        super(TestNAT44, self).setUp()
        self.vapi.nat44_plugin_enable_disable(
            sessions=self.max_translations,
            users=self.max_users, enable=1)

    @classmethod
    def tearDownClass(cls):
        super(TestNAT44, cls).tearDownClass()

    def tearDown(self):
        super(TestNAT44, self).tearDown()
        if not self.vpp_dead:
            self.vapi.nat_ipfix_enable_disable(domain_id=self.ipfix_domain_id,
                                               src_port=self.ipfix_src_port,
                                               enable=0)
            self.ipfix_src_port = 4739
            self.ipfix_domain_id = 1

            self.vapi.nat44_plugin_enable_disable(enable=0)
            self.vapi.cli("clear logging")

    def test_clear_sessions(self):
        """ NAT44 session clearing test """

        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)

        nat_config = self.vapi.nat_show_config()
        self.assertEqual(0, nat_config.endpoint_dependent)

        pkts = self.create_stream_in(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_out(capture)

        sessions = self.statistics.get_counter('/nat44/total-sessions')
        self.assertTrue(sessions[0][0] > 0)
        self.logger.info("sessions before clearing: %s" % sessions[0][0])

        self.vapi.cli("clear nat44 sessions")

        sessions = self.statistics.get_counter('/nat44/total-sessions')
        self.assertEqual(sessions[0][0], 0)
        self.logger.info("sessions after clearing: %s" % sessions[0][0])

    def test_dynamic(self):
        """ NAT44 dynamic translation test """
        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)

        # in2out
        tcpn = self.statistics.get_counter('/nat44/in2out/slowpath/tcp')[0]
        udpn = self.statistics.get_counter('/nat44/in2out/slowpath/udp')[0]
        icmpn = self.statistics.get_counter('/nat44/in2out/slowpath/icmp')[0]
        drops = self.statistics.get_counter('/nat44/in2out/slowpath/drops')[0]

        pkts = self.create_stream_in(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_out(capture)

        if_idx = self.pg0.sw_if_index
        cnt = self.statistics.get_counter('/nat44/in2out/slowpath/tcp')[0]
        self.assertEqual(cnt[if_idx] - tcpn[if_idx], 2)
        cnt = self.statistics.get_counter('/nat44/in2out/slowpath/udp')[0]
        self.assertEqual(cnt[if_idx] - udpn[if_idx], 1)
        cnt = self.statistics.get_counter('/nat44/in2out/slowpath/icmp')[0]
        self.assertEqual(cnt[if_idx] - icmpn[if_idx], 1)
        cnt = self.statistics.get_counter('/nat44/in2out/slowpath/drops')[0]
        self.assertEqual(cnt[if_idx] - drops[if_idx], 0)

        # out2in
        tcpn = self.statistics.get_counter('/nat44/out2in/slowpath/tcp')[0]
        udpn = self.statistics.get_counter('/nat44/out2in/slowpath/udp')[0]
        icmpn = self.statistics.get_counter('/nat44/out2in/slowpath/icmp')[0]
        drops = self.statistics.get_counter('/nat44/out2in/slowpath/drops')[0]

        pkts = self.create_stream_out(self.pg1)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(len(pkts))
        self.verify_capture_in(capture, self.pg0)

        if_idx = self.pg1.sw_if_index
        cnt = self.statistics.get_counter('/nat44/out2in/slowpath/tcp')[0]
        self.assertEqual(cnt[if_idx] - tcpn[if_idx], 2)
        cnt = self.statistics.get_counter('/nat44/out2in/slowpath/udp')[0]
        self.assertEqual(cnt[if_idx] - udpn[if_idx], 1)
        cnt = self.statistics.get_counter('/nat44/out2in/slowpath/icmp')[0]
        self.assertEqual(cnt[if_idx] - icmpn[if_idx], 1)
        cnt = self.statistics.get_counter('/nat44/out2in/slowpath/drops')[0]
        self.assertEqual(cnt[if_idx] - drops[if_idx], 0)

        users = self.statistics.get_counter('/nat44/total-users')
        self.assertEqual(users[0][0], 1)
        sessions = self.statistics.get_counter('/nat44/total-sessions')
        self.assertEqual(sessions[0][0], 3)

    def test_dynamic_icmp_errors_in2out_ttl_1(self):
        """ NAT44 handling of client packets with TTL=1 """

        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)

        # Client side - generate traffic
        pkts = self.create_stream_in(self.pg0, self.pg1, ttl=1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Client side - verify ICMP type 11 packets
        capture = self.pg0.get_capture(len(pkts))
        self.verify_capture_in_with_icmp_errors(capture, self.pg0)

    def test_dynamic_icmp_errors_out2in_ttl_1(self):
        """ NAT44 handling of server packets with TTL=1 """

        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)

        # Client side - create sessions
        pkts = self.create_stream_in(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Server side - generate traffic
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_out(capture)
        pkts = self.create_stream_out(self.pg1, ttl=1)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Server side - verify ICMP type 11 packets
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_out_with_icmp_errors(capture,
                                                 src_ip=self.pg1.local_ip4)

    def test_dynamic_icmp_errors_in2out_ttl_2(self):
        """ NAT44 handling of error responses to client packets with TTL=2 """

        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)

        # Client side - generate traffic
        pkts = self.create_stream_in(self.pg0, self.pg1, ttl=2)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Server side - simulate ICMP type 11 response
        capture = self.pg1.get_capture(len(pkts))
        pkts = [Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
                IP(src=self.pg1.remote_ip4, dst=self.nat_addr) /
                ICMP(type=11) / packet[IP] for packet in capture]
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Client side - verify ICMP type 11 packets
        capture = self.pg0.get_capture(len(pkts))
        self.verify_capture_in_with_icmp_errors(capture, self.pg0)

    def test_dynamic_icmp_errors_out2in_ttl_2(self):
        """ NAT44 handling of error responses to server packets with TTL=2 """

        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)

        # Client side - create sessions
        pkts = self.create_stream_in(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Server side - generate traffic
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_out(capture)
        pkts = self.create_stream_out(self.pg1, ttl=2)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Client side - simulate ICMP type 11 response
        capture = self.pg0.get_capture(len(pkts))
        pkts = [Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
                ICMP(type=11) / packet[IP] for packet in capture]
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Server side - verify ICMP type 11 packets
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_out_with_icmp_errors(capture)

    def test_ping_out_interface_from_outside(self):
        """ Ping NAT44 out interface from outside network """

        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)

        p = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
             IP(src=self.pg1.remote_ip4, dst=self.pg1.local_ip4) /
             ICMP(id=self.icmp_id_out, type='echo-request'))
        pkts = [p]
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        packet = capture[0]
        try:
            self.assertEqual(packet[IP].src, self.pg1.local_ip4)
            self.assertEqual(packet[IP].dst, self.pg1.remote_ip4)
            self.assertEqual(packet[ICMP].id, self.icmp_id_in)
            self.assertEqual(packet[ICMP].type, 0)  # echo reply
        except:
            self.logger.error(ppp("Unexpected or invalid packet "
                                  "(outside network):", packet))
            raise

    def test_ping_internal_host_from_outside(self):
        """ Ping internal host from outside network """

        self.nat44_add_static_mapping(self.pg0.remote_ip4, self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)

        # out2in
        pkt = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
               IP(src=self.pg1.remote_ip4, dst=self.nat_addr, ttl=64) /
               ICMP(id=self.icmp_id_out, type='echo-request'))
        self.pg1.add_stream(pkt)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(1)
        self.verify_capture_in(capture, self.pg0)
        self.assert_equal(capture[0][IP].proto, IP_PROTOS.icmp)

        # in2out
        pkt = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
               IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64) /
               ICMP(id=self.icmp_id_in, type='echo-reply'))
        self.pg0.add_stream(pkt)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(1)
        self.verify_capture_out(capture, same_port=True)
        self.assert_equal(capture[0][IP].proto, IP_PROTOS.icmp)

    def test_forwarding(self):
        """ NAT44 forwarding test """

        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)
        self.vapi.nat44_forwarding_enable_disable(enable=1)

        real_ip = self.pg0.remote_ip4
        alias_ip = self.nat_addr
        flags = self.config_flags.NAT_IS_ADDR_ONLY
        self.vapi.nat44_add_del_static_mapping(is_add=1,
                                               local_ip_address=real_ip,
                                               external_ip_address=alias_ip,
                                               external_sw_if_index=0xFFFFFFFF,
                                               flags=flags)

        try:
            # static mapping match

            pkts = self.create_stream_out(self.pg1)
            self.pg1.add_stream(pkts)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            capture = self.pg0.get_capture(len(pkts))
            self.verify_capture_in(capture, self.pg0)

            pkts = self.create_stream_in(self.pg0, self.pg1)
            self.pg0.add_stream(pkts)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            capture = self.pg1.get_capture(len(pkts))
            self.verify_capture_out(capture, same_port=True)

            # no static mapping match

            host0 = self.pg0.remote_hosts[0]
            self.pg0.remote_hosts[0] = self.pg0.remote_hosts[1]
            try:
                pkts = self.create_stream_out(self.pg1,
                                              dst_ip=self.pg0.remote_ip4,
                                              use_inside_ports=True)
                self.pg1.add_stream(pkts)
                self.pg_enable_capture(self.pg_interfaces)
                self.pg_start()
                capture = self.pg0.get_capture(len(pkts))
                self.verify_capture_in(capture, self.pg0)

                pkts = self.create_stream_in(self.pg0, self.pg1)
                self.pg0.add_stream(pkts)
                self.pg_enable_capture(self.pg_interfaces)
                self.pg_start()
                capture = self.pg1.get_capture(len(pkts))
                self.verify_capture_out(capture, nat_ip=self.pg0.remote_ip4,
                                        same_port=True)
            finally:
                self.pg0.remote_hosts[0] = host0

        finally:
            self.vapi.nat44_forwarding_enable_disable(enable=0)
            flags = self.config_flags.NAT_IS_ADDR_ONLY
            self.vapi.nat44_add_del_static_mapping(
                is_add=0,
                local_ip_address=real_ip,
                external_ip_address=alias_ip,
                external_sw_if_index=0xFFFFFFFF,
                flags=flags)

    def test_static_in(self):
        """ 1:1 NAT initialized from inside network """

        nat_ip = "10.0.0.10"
        self.tcp_port_out = 6303
        self.udp_port_out = 6304
        self.icmp_id_out = 6305

        self.nat44_add_static_mapping(self.pg0.remote_ip4, nat_ip)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)
        sm = self.vapi.nat44_static_mapping_dump()
        self.assertEqual(len(sm), 1)
        self.assertEqual(sm[0].tag, '')
        self.assertEqual(sm[0].protocol, 0)
        self.assertEqual(sm[0].local_port, 0)
        self.assertEqual(sm[0].external_port, 0)

        # in2out
        pkts = self.create_stream_in(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_out(capture, nat_ip, True)

        # out2in
        pkts = self.create_stream_out(self.pg1, nat_ip)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(len(pkts))
        self.verify_capture_in(capture, self.pg0)

    def test_static_out(self):
        """ 1:1 NAT initialized from outside network """

        nat_ip = "10.0.0.20"
        self.tcp_port_out = 6303
        self.udp_port_out = 6304
        self.icmp_id_out = 6305
        tag = "testTAG"

        self.nat44_add_static_mapping(self.pg0.remote_ip4, nat_ip, tag=tag)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)
        sm = self.vapi.nat44_static_mapping_dump()
        self.assertEqual(len(sm), 1)
        self.assertEqual(sm[0].tag, tag)

        # out2in
        pkts = self.create_stream_out(self.pg1, nat_ip)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(len(pkts))
        self.verify_capture_in(capture, self.pg0)

        # in2out
        pkts = self.create_stream_in(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_out(capture, nat_ip, True)

    def test_static_with_port_in(self):
        """ 1:1 NAPT initialized from inside network """

        self.tcp_port_out = 3606
        self.udp_port_out = 3607
        self.icmp_id_out = 3608

        self.nat44_add_address(self.nat_addr)
        self.nat44_add_static_mapping(self.pg0.remote_ip4, self.nat_addr,
                                      self.tcp_port_in, self.tcp_port_out,
                                      proto=IP_PROTOS.tcp)
        self.nat44_add_static_mapping(self.pg0.remote_ip4, self.nat_addr,
                                      self.udp_port_in, self.udp_port_out,
                                      proto=IP_PROTOS.udp)
        self.nat44_add_static_mapping(self.pg0.remote_ip4, self.nat_addr,
                                      self.icmp_id_in, self.icmp_id_out,
                                      proto=IP_PROTOS.icmp)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)

        # in2out
        pkts = self.create_stream_in(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_out(capture)

        # out2in
        pkts = self.create_stream_out(self.pg1)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(len(pkts))
        self.verify_capture_in(capture, self.pg0)

    def test_static_with_port_out(self):
        """ 1:1 NAPT initialized from outside network """

        self.tcp_port_out = 30606
        self.udp_port_out = 30607
        self.icmp_id_out = 30608

        self.nat44_add_address(self.nat_addr)
        self.nat44_add_static_mapping(self.pg0.remote_ip4, self.nat_addr,
                                      self.tcp_port_in, self.tcp_port_out,
                                      proto=IP_PROTOS.tcp)
        self.nat44_add_static_mapping(self.pg0.remote_ip4, self.nat_addr,
                                      self.udp_port_in, self.udp_port_out,
                                      proto=IP_PROTOS.udp)
        self.nat44_add_static_mapping(self.pg0.remote_ip4, self.nat_addr,
                                      self.icmp_id_in, self.icmp_id_out,
                                      proto=IP_PROTOS.icmp)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)

        # out2in
        pkts = self.create_stream_out(self.pg1)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(len(pkts))
        self.verify_capture_in(capture, self.pg0)

        # in2out
        pkts = self.create_stream_in(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_out(capture)

    def test_static_vrf_aware(self):
        """ 1:1 NAT VRF awareness """

        nat_ip1 = "10.0.0.30"
        nat_ip2 = "10.0.0.40"
        self.tcp_port_out = 6303
        self.udp_port_out = 6304
        self.icmp_id_out = 6305

        self.nat44_add_static_mapping(self.pg4.remote_ip4, nat_ip1,
                                      vrf_id=10)
        self.nat44_add_static_mapping(self.pg0.remote_ip4, nat_ip2,
                                      vrf_id=10)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg3.sw_if_index,
            is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg4.sw_if_index,
            flags=flags, is_add=1)

        # inside interface VRF match NAT44 static mapping VRF
        pkts = self.create_stream_in(self.pg4, self.pg3)
        self.pg4.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg3.get_capture(len(pkts))
        self.verify_capture_out(capture, nat_ip1, True)

        # inside interface VRF don't match NAT44 static mapping VRF (packets
        # are dropped)
        pkts = self.create_stream_in(self.pg0, self.pg3)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg3.assert_nothing_captured()

    def test_dynamic_to_static(self):
        """ Switch from dynamic translation to 1:1NAT """
        nat_ip = "10.0.0.10"
        self.tcp_port_out = 6303
        self.udp_port_out = 6304
        self.icmp_id_out = 6305

        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)

        # dynamic
        pkts = self.create_stream_in(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_out(capture)

        # 1:1NAT
        self.nat44_add_static_mapping(self.pg0.remote_ip4, nat_ip)
        sessions = self.vapi.nat44_user_session_dump(self.pg0.remote_ip4, 0)
        self.assertEqual(len(sessions), 0)
        pkts = self.create_stream_in(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_out(capture, nat_ip, True)

    def test_identity_nat(self):
        """ Identity NAT """
        flags = self.config_flags.NAT_IS_ADDR_ONLY
        self.vapi.nat44_add_del_identity_mapping(
            ip_address=self.pg0.remote_ip4, sw_if_index=0xFFFFFFFF,
            flags=flags, is_add=1)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)

        p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
             IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4) /
             TCP(sport=12345, dport=56789))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.dst, self.pg0.remote_ip4)
            self.assertEqual(ip.src, self.pg1.remote_ip4)
            self.assertEqual(tcp.dport, 56789)
            self.assertEqual(tcp.sport, 12345)
            self.assert_packet_checksums_valid(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        sessions = self.vapi.nat44_user_session_dump(self.pg0.remote_ip4, 0)
        self.assertEqual(len(sessions), 0)
        flags = self.config_flags.NAT_IS_ADDR_ONLY
        self.vapi.nat44_add_del_identity_mapping(
            ip_address=self.pg0.remote_ip4, sw_if_index=0xFFFFFFFF,
            flags=flags, vrf_id=1, is_add=1)
        identity_mappings = self.vapi.nat44_identity_mapping_dump()
        self.assertEqual(len(identity_mappings), 2)

    def test_multiple_inside_interfaces(self):
        """ NAT44 multiple non-overlapping address space inside interfaces """

        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg3.sw_if_index,
            is_add=1)

        # between two NAT44 inside interfaces (no translation)
        pkts = self.create_stream_in(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_no_translation(capture, self.pg0, self.pg1)

        # from NAT44 inside to interface without NAT44 feature (no translation)
        pkts = self.create_stream_in(self.pg0, self.pg2)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg2.get_capture(len(pkts))
        self.verify_capture_no_translation(capture, self.pg0, self.pg2)

        # in2out 1st interface
        pkts = self.create_stream_in(self.pg0, self.pg3)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg3.get_capture(len(pkts))
        self.verify_capture_out(capture)

        # out2in 1st interface
        pkts = self.create_stream_out(self.pg3)
        self.pg3.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(len(pkts))
        self.verify_capture_in(capture, self.pg0)

        # in2out 2nd interface
        pkts = self.create_stream_in(self.pg1, self.pg3)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg3.get_capture(len(pkts))
        self.verify_capture_out(capture)

        # out2in 2nd interface
        pkts = self.create_stream_out(self.pg3)
        self.pg3.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_in(capture, self.pg1)

    def test_inside_overlapping_interfaces(self):
        """ NAT44 multiple inside interfaces with overlapping address space """

        static_nat_ip = "10.0.0.10"
        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg3.sw_if_index,
            is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg4.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg5.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg6.sw_if_index,
            flags=flags, is_add=1)
        self.nat44_add_static_mapping(self.pg6.remote_ip4, static_nat_ip,
                                      vrf_id=20)

        # between NAT44 inside interfaces with same VRF (no translation)
        pkts = self.create_stream_in(self.pg4, self.pg5)
        self.pg4.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg5.get_capture(len(pkts))
        self.verify_capture_no_translation(capture, self.pg4, self.pg5)

        # between NAT44 inside interfaces with different VRF (hairpinning)
        p = (Ether(src=self.pg4.remote_mac, dst=self.pg4.local_mac) /
             IP(src=self.pg4.remote_ip4, dst=static_nat_ip) /
             TCP(sport=1234, dport=5678))
        self.pg4.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg6.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.src, self.nat_addr)
            self.assertEqual(ip.dst, self.pg6.remote_ip4)
            self.assertNotEqual(tcp.sport, 1234)
            self.assertEqual(tcp.dport, 5678)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        # in2out 1st interface
        pkts = self.create_stream_in(self.pg4, self.pg3)
        self.pg4.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg3.get_capture(len(pkts))
        self.verify_capture_out(capture)

        # out2in 1st interface
        pkts = self.create_stream_out(self.pg3)
        self.pg3.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg4.get_capture(len(pkts))
        self.verify_capture_in(capture, self.pg4)

        # in2out 2nd interface
        pkts = self.create_stream_in(self.pg5, self.pg3)
        self.pg5.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg3.get_capture(len(pkts))
        self.verify_capture_out(capture)

        # out2in 2nd interface
        pkts = self.create_stream_out(self.pg3)
        self.pg3.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg5.get_capture(len(pkts))
        self.verify_capture_in(capture, self.pg5)

        # pg5 session dump
        addresses = self.vapi.nat44_address_dump()
        self.assertEqual(len(addresses), 1)
        sessions = self.vapi.nat44_user_session_dump(self.pg5.remote_ip4, 10)
        self.assertEqual(len(sessions), 3)
        for session in sessions:
            self.assertFalse(session.flags & self.config_flags.NAT_IS_STATIC)
            self.assertEqual(str(session.inside_ip_address),
                             self.pg5.remote_ip4)
            self.assertEqual(session.outside_ip_address,
                             addresses[0].ip_address)
        self.assertEqual(sessions[0].protocol, IP_PROTOS.tcp)
        self.assertEqual(sessions[1].protocol, IP_PROTOS.udp)
        self.assertEqual(sessions[2].protocol, IP_PROTOS.icmp)
        self.assertEqual(sessions[0].inside_port, self.tcp_port_in)
        self.assertEqual(sessions[1].inside_port, self.udp_port_in)
        self.assertEqual(sessions[2].inside_port, self.icmp_id_in)
        self.assertEqual(sessions[0].outside_port, self.tcp_port_out)
        self.assertEqual(sessions[1].outside_port, self.udp_port_out)
        self.assertEqual(sessions[2].outside_port, self.icmp_id_out)

        # in2out 3rd interface
        pkts = self.create_stream_in(self.pg6, self.pg3)
        self.pg6.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg3.get_capture(len(pkts))
        self.verify_capture_out(capture, static_nat_ip, True)

        # out2in 3rd interface
        pkts = self.create_stream_out(self.pg3, static_nat_ip)
        self.pg3.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg6.get_capture(len(pkts))
        self.verify_capture_in(capture, self.pg6)

        # general user and session dump verifications
        users = self.vapi.nat44_user_dump()
        self.assertGreaterEqual(len(users), 3)
        addresses = self.vapi.nat44_address_dump()
        self.assertEqual(len(addresses), 1)
        for user in users:
            sessions = self.vapi.nat44_user_session_dump(user.ip_address,
                                                         user.vrf_id)
            for session in sessions:
                self.assertEqual(user.ip_address, session.inside_ip_address)
                self.assertTrue(session.total_bytes > session.total_pkts > 0)
                self.assertTrue(session.protocol in
                                [IP_PROTOS.tcp, IP_PROTOS.udp,
                                 IP_PROTOS.icmp])
                self.assertFalse(session.flags &
                                 self.config_flags.NAT_IS_EXT_HOST_VALID)

        # pg4 session dump
        sessions = self.vapi.nat44_user_session_dump(self.pg4.remote_ip4, 10)
        self.assertGreaterEqual(len(sessions), 4)
        for session in sessions:
            self.assertFalse(session.flags & self.config_flags.NAT_IS_STATIC)
            self.assertEqual(str(session.inside_ip_address),
                             self.pg4.remote_ip4)
            self.assertEqual(session.outside_ip_address,
                             addresses[0].ip_address)

        # pg6 session dump
        sessions = self.vapi.nat44_user_session_dump(self.pg6.remote_ip4, 20)
        self.assertGreaterEqual(len(sessions), 3)
        for session in sessions:
            self.assertTrue(session.flags & self.config_flags.NAT_IS_STATIC)
            self.assertEqual(str(session.inside_ip_address),
                             self.pg6.remote_ip4)
            self.assertEqual(str(session.outside_ip_address),
                             static_nat_ip)
            self.assertTrue(session.inside_port in
                            [self.tcp_port_in, self.udp_port_in,
                             self.icmp_id_in])

    def test_hairpinning(self):
        """ NAT44 hairpinning - 1:1 NAPT """

        host = self.pg0.remote_hosts[0]
        server = self.pg0.remote_hosts[1]
        host_in_port = 1234
        host_out_port = 0
        server_in_port = 5678
        server_out_port = 8765

        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)

        # add static mapping for server
        self.nat44_add_static_mapping(server.ip4, self.nat_addr,
                                      server_in_port, server_out_port,
                                      proto=IP_PROTOS.tcp)

        cnt = self.statistics.get_counter('/nat44/hairpinning')[0]
        # send packet from host to server
        p = (Ether(src=host.mac, dst=self.pg0.local_mac) /
             IP(src=host.ip4, dst=self.nat_addr) /
             TCP(sport=host_in_port, dport=server_out_port))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.src, self.nat_addr)
            self.assertEqual(ip.dst, server.ip4)
            self.assertNotEqual(tcp.sport, host_in_port)
            self.assertEqual(tcp.dport, server_in_port)
            self.assert_packet_checksums_valid(p)
            host_out_port = tcp.sport
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        after = self.statistics.get_counter('/nat44/hairpinning')[0]
        if_idx = self.pg0.sw_if_index
        self.assertEqual(after[if_idx] - cnt[if_idx], 1)

        # send reply from server to host
        p = (Ether(src=server.mac, dst=self.pg0.local_mac) /
             IP(src=server.ip4, dst=self.nat_addr) /
             TCP(sport=server_in_port, dport=host_out_port))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.src, self.nat_addr)
            self.assertEqual(ip.dst, host.ip4)
            self.assertEqual(tcp.sport, server_out_port)
            self.assertEqual(tcp.dport, host_in_port)
            self.assert_packet_checksums_valid(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        after = self.statistics.get_counter('/nat44/hairpinning')[0]
        if_idx = self.pg0.sw_if_index
        self.assertEqual(after[if_idx] - cnt[if_idx], 2)

    def test_hairpinning2(self):
        """ NAT44 hairpinning - 1:1 NAT"""

        server1_nat_ip = "10.0.0.10"
        server2_nat_ip = "10.0.0.11"
        host = self.pg0.remote_hosts[0]
        server1 = self.pg0.remote_hosts[1]
        server2 = self.pg0.remote_hosts[2]
        server_tcp_port = 22
        server_udp_port = 20

        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)

        # add static mapping for servers
        self.nat44_add_static_mapping(server1.ip4, server1_nat_ip)
        self.nat44_add_static_mapping(server2.ip4, server2_nat_ip)

        # host to server1
        pkts = []
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=host.ip4, dst=server1_nat_ip) /
             TCP(sport=self.tcp_port_in, dport=server_tcp_port))
        pkts.append(p)
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=host.ip4, dst=server1_nat_ip) /
             UDP(sport=self.udp_port_in, dport=server_udp_port))
        pkts.append(p)
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=host.ip4, dst=server1_nat_ip) /
             ICMP(id=self.icmp_id_in, type='echo-request'))
        pkts.append(p)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(len(pkts))
        for packet in capture:
            try:
                self.assertEqual(packet[IP].src, self.nat_addr)
                self.assertEqual(packet[IP].dst, server1.ip4)
                if packet.haslayer(TCP):
                    self.assertNotEqual(packet[TCP].sport, self.tcp_port_in)
                    self.assertEqual(packet[TCP].dport, server_tcp_port)
                    self.tcp_port_out = packet[TCP].sport
                    self.assert_packet_checksums_valid(packet)
                elif packet.haslayer(UDP):
                    self.assertNotEqual(packet[UDP].sport, self.udp_port_in)
                    self.assertEqual(packet[UDP].dport, server_udp_port)
                    self.udp_port_out = packet[UDP].sport
                else:
                    self.assertNotEqual(packet[ICMP].id, self.icmp_id_in)
                    self.icmp_id_out = packet[ICMP].id
            except:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise

        # server1 to host
        pkts = []
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=server1.ip4, dst=self.nat_addr) /
             TCP(sport=server_tcp_port, dport=self.tcp_port_out))
        pkts.append(p)
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=server1.ip4, dst=self.nat_addr) /
             UDP(sport=server_udp_port, dport=self.udp_port_out))
        pkts.append(p)
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=server1.ip4, dst=self.nat_addr) /
             ICMP(id=self.icmp_id_out, type='echo-reply'))
        pkts.append(p)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(len(pkts))
        for packet in capture:
            try:
                self.assertEqual(packet[IP].src, server1_nat_ip)
                self.assertEqual(packet[IP].dst, host.ip4)
                if packet.haslayer(TCP):
                    self.assertEqual(packet[TCP].dport, self.tcp_port_in)
                    self.assertEqual(packet[TCP].sport, server_tcp_port)
                    self.assert_packet_checksums_valid(packet)
                elif packet.haslayer(UDP):
                    self.assertEqual(packet[UDP].dport, self.udp_port_in)
                    self.assertEqual(packet[UDP].sport, server_udp_port)
                else:
                    self.assertEqual(packet[ICMP].id, self.icmp_id_in)
            except:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise

        # server2 to server1
        pkts = []
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=server2.ip4, dst=server1_nat_ip) /
             TCP(sport=self.tcp_port_in, dport=server_tcp_port))
        pkts.append(p)
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=server2.ip4, dst=server1_nat_ip) /
             UDP(sport=self.udp_port_in, dport=server_udp_port))
        pkts.append(p)
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=server2.ip4, dst=server1_nat_ip) /
             ICMP(id=self.icmp_id_in, type='echo-request'))
        pkts.append(p)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(len(pkts))
        for packet in capture:
            try:
                self.assertEqual(packet[IP].src, server2_nat_ip)
                self.assertEqual(packet[IP].dst, server1.ip4)
                if packet.haslayer(TCP):
                    self.assertEqual(packet[TCP].sport, self.tcp_port_in)
                    self.assertEqual(packet[TCP].dport, server_tcp_port)
                    self.tcp_port_out = packet[TCP].sport
                    self.assert_packet_checksums_valid(packet)
                elif packet.haslayer(UDP):
                    self.assertEqual(packet[UDP].sport, self.udp_port_in)
                    self.assertEqual(packet[UDP].dport, server_udp_port)
                    self.udp_port_out = packet[UDP].sport
                else:
                    self.assertEqual(packet[ICMP].id, self.icmp_id_in)
                    self.icmp_id_out = packet[ICMP].id
            except:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise

        # server1 to server2
        pkts = []
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=server1.ip4, dst=server2_nat_ip) /
             TCP(sport=server_tcp_port, dport=self.tcp_port_out))
        pkts.append(p)
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=server1.ip4, dst=server2_nat_ip) /
             UDP(sport=server_udp_port, dport=self.udp_port_out))
        pkts.append(p)
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=server1.ip4, dst=server2_nat_ip) /
             ICMP(id=self.icmp_id_out, type='echo-reply'))
        pkts.append(p)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(len(pkts))
        for packet in capture:
            try:
                self.assertEqual(packet[IP].src, server1_nat_ip)
                self.assertEqual(packet[IP].dst, server2.ip4)
                if packet.haslayer(TCP):
                    self.assertEqual(packet[TCP].dport, self.tcp_port_in)
                    self.assertEqual(packet[TCP].sport, server_tcp_port)
                    self.assert_packet_checksums_valid(packet)
                elif packet.haslayer(UDP):
                    self.assertEqual(packet[UDP].dport, self.udp_port_in)
                    self.assertEqual(packet[UDP].sport, server_udp_port)
                else:
                    self.assertEqual(packet[ICMP].id, self.icmp_id_in)
            except:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise

    def test_interface_addr(self):
        """ Acquire NAT44 addresses from interface """
        self.vapi.nat44_add_del_interface_addr(
            is_add=1,
            sw_if_index=self.pg7.sw_if_index)

        # no address in NAT pool
        addresses = self.vapi.nat44_address_dump()
        self.assertEqual(0, len(addresses))

        # configure interface address and check NAT address pool
        self.pg7.config_ip4()
        addresses = self.vapi.nat44_address_dump()
        self.assertEqual(1, len(addresses))
        self.assertEqual(str(addresses[0].ip_address), self.pg7.local_ip4)

        # remove interface address and check NAT address pool
        self.pg7.unconfig_ip4()
        addresses = self.vapi.nat44_address_dump()
        self.assertEqual(0, len(addresses))

    def test_interface_addr_static_mapping(self):
        """ Static mapping with addresses from interface """
        tag = "testTAG"

        self.vapi.nat44_add_del_interface_addr(
            is_add=1,
            sw_if_index=self.pg7.sw_if_index)
        self.nat44_add_static_mapping(
            '1.2.3.4',
            external_sw_if_index=self.pg7.sw_if_index,
            tag=tag)

        # static mappings with external interface
        static_mappings = self.vapi.nat44_static_mapping_dump()
        self.assertEqual(1, len(static_mappings))
        self.assertEqual(self.pg7.sw_if_index,
                         static_mappings[0].external_sw_if_index)
        self.assertEqual(static_mappings[0].tag, tag)

        # configure interface address and check static mappings
        self.pg7.config_ip4()
        static_mappings = self.vapi.nat44_static_mapping_dump()
        self.assertEqual(2, len(static_mappings))
        resolved = False
        for sm in static_mappings:
            if sm.external_sw_if_index == 0xFFFFFFFF:
                self.assertEqual(str(sm.external_ip_address),
                                 self.pg7.local_ip4)
                self.assertEqual(sm.tag, tag)
                resolved = True
        self.assertTrue(resolved)

        # remove interface address and check static mappings
        self.pg7.unconfig_ip4()
        static_mappings = self.vapi.nat44_static_mapping_dump()
        self.assertEqual(1, len(static_mappings))
        self.assertEqual(self.pg7.sw_if_index,
                         static_mappings[0].external_sw_if_index)
        self.assertEqual(static_mappings[0].tag, tag)

        # configure interface address again and check static mappings
        self.pg7.config_ip4()
        static_mappings = self.vapi.nat44_static_mapping_dump()
        self.assertEqual(2, len(static_mappings))
        resolved = False
        for sm in static_mappings:
            if sm.external_sw_if_index == 0xFFFFFFFF:
                self.assertEqual(str(sm.external_ip_address),
                                 self.pg7.local_ip4)
                self.assertEqual(sm.tag, tag)
                resolved = True
        self.assertTrue(resolved)

        # remove static mapping
        self.nat44_add_static_mapping(
            '1.2.3.4',
            external_sw_if_index=self.pg7.sw_if_index,
            tag=tag,
            is_add=0)
        static_mappings = self.vapi.nat44_static_mapping_dump()
        self.assertEqual(0, len(static_mappings))

    def test_interface_addr_identity_nat(self):
        """ Identity NAT with addresses from interface """

        port = 53053
        self.vapi.nat44_add_del_interface_addr(
            is_add=1,
            sw_if_index=self.pg7.sw_if_index)
        self.vapi.nat44_add_del_identity_mapping(
            ip_address=b'0',
            sw_if_index=self.pg7.sw_if_index,
            port=port,
            protocol=IP_PROTOS.tcp,
            is_add=1)

        # identity mappings with external interface
        identity_mappings = self.vapi.nat44_identity_mapping_dump()
        self.assertEqual(1, len(identity_mappings))
        self.assertEqual(self.pg7.sw_if_index,
                         identity_mappings[0].sw_if_index)

        # configure interface address and check identity mappings
        self.pg7.config_ip4()
        identity_mappings = self.vapi.nat44_identity_mapping_dump()
        resolved = False
        self.assertEqual(2, len(identity_mappings))
        for sm in identity_mappings:
            if sm.sw_if_index == 0xFFFFFFFF:
                self.assertEqual(str(identity_mappings[0].ip_address),
                                 self.pg7.local_ip4)
                self.assertEqual(port, identity_mappings[0].port)
                self.assertEqual(IP_PROTOS.tcp, identity_mappings[0].protocol)
                resolved = True
        self.assertTrue(resolved)

        # remove interface address and check identity mappings
        self.pg7.unconfig_ip4()
        identity_mappings = self.vapi.nat44_identity_mapping_dump()
        self.assertEqual(1, len(identity_mappings))
        self.assertEqual(self.pg7.sw_if_index,
                         identity_mappings[0].sw_if_index)

    def test_ipfix_nat44_sess(self):
        """ IPFIX logging NAT44 session created/deleted """
        self.ipfix_domain_id = 10
        self.ipfix_src_port = 20202
        collector_port = 30303
        bind_layers(UDP, IPFIX, dport=30303)
        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)
        self.vapi.set_ipfix_exporter(collector_address=self.pg3.remote_ip4,
                                     src_address=self.pg3.local_ip4,
                                     path_mtu=512,
                                     template_interval=10,
                                     collector_port=collector_port)
        self.vapi.nat_ipfix_enable_disable(domain_id=self.ipfix_domain_id,
                                           src_port=self.ipfix_src_port,
                                           enable=1)

        pkts = self.create_stream_in(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_out(capture)
        self.nat44_add_address(self.nat_addr, is_add=0)
        self.vapi.ipfix_flush()
        capture = self.pg3.get_capture(7)
        ipfix = IPFIXDecoder()
        # first load template
        for p in capture:
            self.assertTrue(p.haslayer(IPFIX))
            self.assertEqual(p[IP].src, self.pg3.local_ip4)
            self.assertEqual(p[IP].dst, self.pg3.remote_ip4)
            self.assertEqual(p[UDP].sport, self.ipfix_src_port)
            self.assertEqual(p[UDP].dport, collector_port)
            self.assertEqual(p[IPFIX].observationDomainID,
                             self.ipfix_domain_id)
            if p.haslayer(Template):
                ipfix.add_template(p.getlayer(Template))
        # verify events in data set
        for p in capture:
            if p.haslayer(Data):
                data = ipfix.decode_data_set(p.getlayer(Set))
                self.verify_ipfix_nat44_ses(data)

    def test_ipfix_addr_exhausted(self):
        """ IPFIX logging NAT addresses exhausted """
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)
        self.vapi.set_ipfix_exporter(collector_address=self.pg3.remote_ip4,
                                     src_address=self.pg3.local_ip4,
                                     path_mtu=512,
                                     template_interval=10)
        self.vapi.nat_ipfix_enable_disable(domain_id=self.ipfix_domain_id,
                                           src_port=self.ipfix_src_port,
                                           enable=1)

        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=3025))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.assert_nothing_captured()
        sleep(1)
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
                self.verify_ipfix_addr_exhausted(data)

    def test_ipfix_max_sessions(self):
        """ IPFIX logging maximum session entries exceeded """
        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)

        max_sessions = self.max_translations

        pkts = []
        for i in range(0, max_sessions):
            src = "10.10.%u.%u" % ((i & 0xFF00) >> 8, i & 0xFF)
            p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                 IP(src=src, dst=self.pg1.remote_ip4) /
                 TCP(sport=1025))
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

        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=1025))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.assert_nothing_captured()
        sleep(1)
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

    def test_syslog_apmap(self):
        """ Test syslog address and port mapping creation and deletion """
        self.vapi.syslog_set_filter(
            self.SYSLOG_SEVERITY.SYSLOG_API_SEVERITY_INFO)
        self.vapi.syslog_set_sender(self.pg3.local_ip4, self.pg3.remote_ip4)
        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)

        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=self.tcp_port_in, dport=20))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(1)
        self.tcp_port_out = capture[0][TCP].sport
        capture = self.pg3.get_capture(1)
        self.verify_syslog_apmap(capture[0][Raw].load)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.nat44_add_address(self.nat_addr, is_add=0)
        capture = self.pg3.get_capture(1)
        self.verify_syslog_apmap(capture[0][Raw].load, False)

    def test_pool_addr_fib(self):
        """ NAT44 add pool addresses to FIB """
        static_addr = '10.0.0.10'
        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)
        self.nat44_add_static_mapping(self.pg0.remote_ip4, static_addr)

        # NAT44 address
        p = (Ether(src=self.pg1.remote_mac, dst='ff:ff:ff:ff:ff:ff') /
             ARP(op=ARP.who_has, pdst=self.nat_addr,
                 psrc=self.pg1.remote_ip4, hwsrc=self.pg1.remote_mac))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(1)
        self.assertTrue(capture[0].haslayer(ARP))
        self.assertTrue(capture[0][ARP].op, ARP.is_at)

        # 1:1 NAT address
        p = (Ether(src=self.pg1.remote_mac, dst='ff:ff:ff:ff:ff:ff') /
             ARP(op=ARP.who_has, pdst=static_addr,
                 psrc=self.pg1.remote_ip4, hwsrc=self.pg1.remote_mac))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(1)
        self.assertTrue(capture[0].haslayer(ARP))
        self.assertTrue(capture[0][ARP].op, ARP.is_at)

        # send ARP to non-NAT44 interface
        p = (Ether(src=self.pg2.remote_mac, dst='ff:ff:ff:ff:ff:ff') /
             ARP(op=ARP.who_has, pdst=self.nat_addr,
                 psrc=self.pg2.remote_ip4, hwsrc=self.pg2.remote_mac))
        self.pg2.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.assert_nothing_captured()

        # remove addresses and verify
        self.nat44_add_address(self.nat_addr, is_add=0)
        self.nat44_add_static_mapping(self.pg0.remote_ip4, static_addr,
                                      is_add=0)

        p = (Ether(src=self.pg1.remote_mac, dst='ff:ff:ff:ff:ff:ff') /
             ARP(op=ARP.who_has, pdst=self.nat_addr,
                 psrc=self.pg1.remote_ip4, hwsrc=self.pg1.remote_mac))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.assert_nothing_captured()

        p = (Ether(src=self.pg1.remote_mac, dst='ff:ff:ff:ff:ff:ff') /
             ARP(op=ARP.who_has, pdst=static_addr,
                 psrc=self.pg1.remote_ip4, hwsrc=self.pg1.remote_mac))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.assert_nothing_captured()

    def test_vrf_mode(self):
        """ NAT44 tenant VRF aware address pool mode """

        vrf_id1 = 1
        vrf_id2 = 2
        nat_ip1 = "10.0.0.10"
        nat_ip2 = "10.0.0.11"

        self.pg0.unconfig_ip4()
        self.pg1.unconfig_ip4()
        self.vapi.ip_table_add_del(is_add=1, table={'table_id': vrf_id1})
        self.vapi.ip_table_add_del(is_add=1, table={'table_id': vrf_id2})
        self.pg0.set_table_ip4(vrf_id1)
        self.pg1.set_table_ip4(vrf_id2)
        self.pg0.config_ip4()
        self.pg1.config_ip4()
        self.pg0.resolve_arp()
        self.pg1.resolve_arp()

        self.nat44_add_address(nat_ip1, vrf_id=vrf_id1)
        self.nat44_add_address(nat_ip2, vrf_id=vrf_id2)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg2.sw_if_index,
            is_add=1)

        try:
            # first VRF
            pkts = self.create_stream_in(self.pg0, self.pg2)
            self.pg0.add_stream(pkts)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            capture = self.pg2.get_capture(len(pkts))
            self.verify_capture_out(capture, nat_ip1)

            # second VRF
            pkts = self.create_stream_in(self.pg1, self.pg2)
            self.pg1.add_stream(pkts)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            capture = self.pg2.get_capture(len(pkts))
            self.verify_capture_out(capture, nat_ip2)

        finally:
            self.pg0.unconfig_ip4()
            self.pg1.unconfig_ip4()
            self.pg0.set_table_ip4(0)
            self.pg1.set_table_ip4(0)
            self.pg0.config_ip4()
            self.pg1.config_ip4()
            self.pg0.resolve_arp()
            self.pg1.resolve_arp()
            self.vapi.ip_table_add_del(is_add=0, table={'table_id': vrf_id1})
            self.vapi.ip_table_add_del(is_add=0, table={'table_id': vrf_id2})

    def test_vrf_feature_independent(self):
        """ NAT44 tenant VRF independent address pool mode """

        nat_ip1 = "10.0.0.10"
        nat_ip2 = "10.0.0.11"

        self.nat44_add_address(nat_ip1)
        self.nat44_add_address(nat_ip2, vrf_id=99)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg2.sw_if_index,
            is_add=1)

        # first VRF
        pkts = self.create_stream_in(self.pg0, self.pg2)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg2.get_capture(len(pkts))
        self.verify_capture_out(capture, nat_ip1)

        # second VRF
        pkts = self.create_stream_in(self.pg1, self.pg2)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg2.get_capture(len(pkts))
        self.verify_capture_out(capture, nat_ip1)

    def create_routes_and_neigbors(self):
        r1 = VppIpRoute(self, self.pg7.remote_ip4, 32,
                        [VppRoutePath(self.pg7.remote_ip4,
                                      self.pg7.sw_if_index)])
        r2 = VppIpRoute(self, self.pg8.remote_ip4, 32,
                        [VppRoutePath(self.pg8.remote_ip4,
                                      self.pg8.sw_if_index)])
        r1.add_vpp_config()
        r2.add_vpp_config()

        n1 = VppNeighbor(self,
                         self.pg7.sw_if_index,
                         self.pg7.remote_mac,
                         self.pg7.remote_ip4,
                         is_static=1)
        n2 = VppNeighbor(self,
                         self.pg8.sw_if_index,
                         self.pg8.remote_mac,
                         self.pg8.remote_ip4,
                         is_static=1)
        n1.add_vpp_config()
        n2.add_vpp_config()

    def test_dynamic_ipless_interfaces(self):
        """ NAT44 interfaces without configured IP address """
        self.create_routes_and_neigbors()
        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg7.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg8.sw_if_index,
            is_add=1)

        # in2out
        pkts = self.create_stream_in(self.pg7, self.pg8)
        self.pg7.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg8.get_capture(len(pkts))
        self.verify_capture_out(capture)

        # out2in
        pkts = self.create_stream_out(self.pg8, self.nat_addr)
        self.pg8.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg7.get_capture(len(pkts))
        self.verify_capture_in(capture, self.pg7)

    def test_static_ipless_interfaces(self):
        """ NAT44 interfaces without configured IP address - 1:1 NAT """

        self.create_routes_and_neigbors()
        self.nat44_add_static_mapping(self.pg7.remote_ip4, self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg7.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg8.sw_if_index,
            is_add=1)

        # out2in
        pkts = self.create_stream_out(self.pg8)
        self.pg8.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg7.get_capture(len(pkts))
        self.verify_capture_in(capture, self.pg7)

        # in2out
        pkts = self.create_stream_in(self.pg7, self.pg8)
        self.pg7.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg8.get_capture(len(pkts))
        self.verify_capture_out(capture, self.nat_addr, True)

    def test_static_with_port_ipless_interfaces(self):
        """ NAT44 interfaces without configured IP address - 1:1 NAPT """

        self.tcp_port_out = 30606
        self.udp_port_out = 30607
        self.icmp_id_out = 30608

        self.create_routes_and_neigbors()
        self.nat44_add_address(self.nat_addr)
        self.nat44_add_static_mapping(self.pg7.remote_ip4, self.nat_addr,
                                      self.tcp_port_in, self.tcp_port_out,
                                      proto=IP_PROTOS.tcp)
        self.nat44_add_static_mapping(self.pg7.remote_ip4, self.nat_addr,
                                      self.udp_port_in, self.udp_port_out,
                                      proto=IP_PROTOS.udp)
        self.nat44_add_static_mapping(self.pg7.remote_ip4, self.nat_addr,
                                      self.icmp_id_in, self.icmp_id_out,
                                      proto=IP_PROTOS.icmp)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg7.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg8.sw_if_index,
            is_add=1)

        # out2in
        pkts = self.create_stream_out(self.pg8)
        self.pg8.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg7.get_capture(len(pkts))
        self.verify_capture_in(capture, self.pg7)

        # in2out
        pkts = self.create_stream_in(self.pg7, self.pg8)
        self.pg7.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg8.get_capture(len(pkts))
        self.verify_capture_out(capture)

    def test_static_unknown_proto(self):
        """ 1:1 NAT translate packet with unknown protocol """
        nat_ip = "10.0.0.10"
        self.nat44_add_static_mapping(self.pg0.remote_ip4, nat_ip)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)

        # in2out
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             GRE() /
             IP(src=self.pg2.remote_ip4, dst=self.pg3.remote_ip4) /
             TCP(sport=1234, dport=1234))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        p = self.pg1.get_capture(1)
        packet = p[0]
        try:
            self.assertEqual(packet[IP].src, nat_ip)
            self.assertEqual(packet[IP].dst, self.pg1.remote_ip4)
            self.assertEqual(packet.haslayer(GRE), 1)
            self.assert_packet_checksums_valid(packet)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", packet))
            raise

        # out2in
        p = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
             IP(src=self.pg1.remote_ip4, dst=nat_ip) /
             GRE() /
             IP(src=self.pg3.remote_ip4, dst=self.pg2.remote_ip4) /
             TCP(sport=1234, dport=1234))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        p = self.pg0.get_capture(1)
        packet = p[0]
        try:
            self.assertEqual(packet[IP].src, self.pg1.remote_ip4)
            self.assertEqual(packet[IP].dst, self.pg0.remote_ip4)
            self.assertEqual(packet.haslayer(GRE), 1)
            self.assert_packet_checksums_valid(packet)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", packet))
            raise

    def test_hairpinning_static_unknown_proto(self):
        """ 1:1 NAT translate packet with unknown protocol - hairpinning """

        host = self.pg0.remote_hosts[0]
        server = self.pg0.remote_hosts[1]

        host_nat_ip = "10.0.0.10"
        server_nat_ip = "10.0.0.11"

        self.nat44_add_static_mapping(host.ip4, host_nat_ip)
        self.nat44_add_static_mapping(server.ip4, server_nat_ip)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)

        # host to server
        p = (Ether(dst=self.pg0.local_mac, src=host.mac) /
             IP(src=host.ip4, dst=server_nat_ip) /
             GRE() /
             IP(src=self.pg2.remote_ip4, dst=self.pg3.remote_ip4) /
             TCP(sport=1234, dport=1234))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        p = self.pg0.get_capture(1)
        packet = p[0]
        try:
            self.assertEqual(packet[IP].src, host_nat_ip)
            self.assertEqual(packet[IP].dst, server.ip4)
            self.assertEqual(packet.haslayer(GRE), 1)
            self.assert_packet_checksums_valid(packet)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", packet))
            raise

        # server to host
        p = (Ether(dst=self.pg0.local_mac, src=server.mac) /
             IP(src=server.ip4, dst=host_nat_ip) /
             GRE() /
             IP(src=self.pg3.remote_ip4, dst=self.pg2.remote_ip4) /
             TCP(sport=1234, dport=1234))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        p = self.pg0.get_capture(1)
        packet = p[0]
        try:
            self.assertEqual(packet[IP].src, server_nat_ip)
            self.assertEqual(packet[IP].dst, host.ip4)
            self.assertEqual(packet.haslayer(GRE), 1)
            self.assert_packet_checksums_valid(packet)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", packet))
            raise

    def test_output_feature(self):
        """ NAT44 interface output feature (in2out postrouting) """
        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_output_feature(
            is_add=1, flags=flags,
            sw_if_index=self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_output_feature(
            is_add=1, flags=flags,
            sw_if_index=self.pg1.sw_if_index)
        self.vapi.nat44_interface_add_del_output_feature(
            is_add=1,
            sw_if_index=self.pg3.sw_if_index)

        # in2out
        pkts = self.create_stream_in(self.pg0, self.pg3)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg3.get_capture(len(pkts))
        self.verify_capture_out(capture)

        # out2in
        pkts = self.create_stream_out(self.pg3)
        self.pg3.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(len(pkts))
        self.verify_capture_in(capture, self.pg0)

        # from non-NAT interface to NAT inside interface
        pkts = self.create_stream_in(self.pg2, self.pg0)
        self.pg2.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(len(pkts))
        self.verify_capture_no_translation(capture, self.pg2, self.pg0)

    def test_output_feature_vrf_aware(self):
        """ NAT44 interface output feature VRF aware (in2out postrouting) """
        nat_ip_vrf10 = "10.0.0.10"
        nat_ip_vrf20 = "10.0.0.20"

        r1 = VppIpRoute(self, self.pg3.remote_ip4, 32,
                        [VppRoutePath(self.pg3.remote_ip4,
                                      self.pg3.sw_if_index)],
                        table_id=10)
        r2 = VppIpRoute(self, self.pg3.remote_ip4, 32,
                        [VppRoutePath(self.pg3.remote_ip4,
                                      self.pg3.sw_if_index)],
                        table_id=20)
        r1.add_vpp_config()
        r2.add_vpp_config()

        self.nat44_add_address(nat_ip_vrf10, vrf_id=10)
        self.nat44_add_address(nat_ip_vrf20, vrf_id=20)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_output_feature(
            is_add=1, flags=flags,
            sw_if_index=self.pg4.sw_if_index)
        self.vapi.nat44_interface_add_del_output_feature(
            is_add=1, flags=flags,
            sw_if_index=self.pg6.sw_if_index)
        self.vapi.nat44_interface_add_del_output_feature(
            is_add=1,
            sw_if_index=self.pg3.sw_if_index)

        # in2out VRF 10
        pkts = self.create_stream_in(self.pg4, self.pg3)
        self.pg4.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg3.get_capture(len(pkts))
        self.verify_capture_out(capture, nat_ip=nat_ip_vrf10)

        # out2in VRF 10
        pkts = self.create_stream_out(self.pg3, dst_ip=nat_ip_vrf10)
        self.pg3.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg4.get_capture(len(pkts))
        self.verify_capture_in(capture, self.pg4)

        # in2out VRF 20
        pkts = self.create_stream_in(self.pg6, self.pg3)
        self.pg6.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg3.get_capture(len(pkts))
        self.verify_capture_out(capture, nat_ip=nat_ip_vrf20)

        # out2in VRF 20
        pkts = self.create_stream_out(self.pg3, dst_ip=nat_ip_vrf20)
        self.pg3.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg6.get_capture(len(pkts))
        self.verify_capture_in(capture, self.pg6)

    def test_output_feature_hairpinning(self):
        """ NAT44 interface output feature hairpinning (in2out postrouting) """
        host = self.pg0.remote_hosts[0]
        server = self.pg0.remote_hosts[1]
        host_in_port = 1234
        host_out_port = 0
        server_in_port = 5678
        server_out_port = 8765

        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_output_feature(
            is_add=1, flags=flags,
            sw_if_index=self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_output_feature(
            is_add=1,
            sw_if_index=self.pg1.sw_if_index)

        # add static mapping for server
        self.nat44_add_static_mapping(server.ip4, self.nat_addr,
                                      server_in_port, server_out_port,
                                      proto=IP_PROTOS.tcp)

        # send packet from host to server
        p = (Ether(src=host.mac, dst=self.pg0.local_mac) /
             IP(src=host.ip4, dst=self.nat_addr) /
             TCP(sport=host_in_port, dport=server_out_port))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.src, self.nat_addr)
            self.assertEqual(ip.dst, server.ip4)
            self.assertNotEqual(tcp.sport, host_in_port)
            self.assertEqual(tcp.dport, server_in_port)
            self.assert_packet_checksums_valid(p)
            host_out_port = tcp.sport
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        # send reply from server to host
        p = (Ether(src=server.mac, dst=self.pg0.local_mac) /
             IP(src=server.ip4, dst=self.nat_addr) /
             TCP(sport=server_in_port, dport=host_out_port))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.src, self.nat_addr)
            self.assertEqual(ip.dst, host.ip4)
            self.assertEqual(tcp.sport, server_out_port)
            self.assertEqual(tcp.dport, host_in_port)
            self.assert_packet_checksums_valid(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

    def test_one_armed_nat44(self):
        """ One armed NAT44 """
        remote_host = self.pg9.remote_hosts[0]
        local_host = self.pg9.remote_hosts[1]
        external_port = 0

        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg9.sw_if_index,
            is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg9.sw_if_index,
            flags=flags, is_add=1)

        # in2out
        p = (Ether(src=self.pg9.remote_mac, dst=self.pg9.local_mac) /
             IP(src=local_host.ip4, dst=remote_host.ip4) /
             TCP(sport=12345, dport=80))
        self.pg9.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg9.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.src, self.nat_addr)
            self.assertEqual(ip.dst, remote_host.ip4)
            self.assertNotEqual(tcp.sport, 12345)
            external_port = tcp.sport
            self.assertEqual(tcp.dport, 80)
            self.assert_packet_checksums_valid(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        # out2in
        p = (Ether(src=self.pg9.remote_mac, dst=self.pg9.local_mac) /
             IP(src=remote_host.ip4, dst=self.nat_addr) /
             TCP(sport=80, dport=external_port))
        self.pg9.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg9.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.src, remote_host.ip4)
            self.assertEqual(ip.dst, local_host.ip4)
            self.assertEqual(tcp.sport, 80)
            self.assertEqual(tcp.dport, 12345)
            self.assert_packet_checksums_valid(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        err = self.statistics.get_err_counter(
            '/err/nat44-classify/next in2out')
        self.assertEqual(err, 1)
        err = self.statistics.get_err_counter(
            '/err/nat44-classify/next out2in')
        self.assertEqual(err, 1)

    def test_del_session(self):
        """ Delete NAT44 session """
        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)

        pkts = self.create_stream_in(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.get_capture(len(pkts))

        sessions = self.vapi.nat44_user_session_dump(self.pg0.remote_ip4, 0)
        nsessions = len(sessions)

        self.vapi.nat44_del_session(address=sessions[0].inside_ip_address,
                                    port=sessions[0].inside_port,
                                    protocol=sessions[0].protocol,
                                    flags=self.config_flags.NAT_IS_INSIDE)
        self.vapi.nat44_del_session(address=sessions[1].outside_ip_address,
                                    port=sessions[1].outside_port,
                                    protocol=sessions[1].protocol)

        sessions = self.vapi.nat44_user_session_dump(self.pg0.remote_ip4, 0)
        self.assertEqual(nsessions - len(sessions), 2)

        self.vapi.nat44_del_session(address=sessions[0].inside_ip_address,
                                    port=sessions[0].inside_port,
                                    protocol=sessions[0].protocol,
                                    flags=self.config_flags.NAT_IS_INSIDE)

        self.verify_no_nat44_user()

    def test_frag_in_order(self):
        """ NAT44 translate fragments arriving in order """

        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)

        self.frag_in_order(proto=IP_PROTOS.tcp)
        self.frag_in_order(proto=IP_PROTOS.udp)
        self.frag_in_order(proto=IP_PROTOS.icmp)

    def test_frag_forwarding(self):
        """ NAT44 forwarding fragment test """
        self.vapi.nat44_add_del_interface_addr(
            is_add=1,
            sw_if_index=self.pg1.sw_if_index)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)
        self.vapi.nat44_forwarding_enable_disable(enable=1)

        data = b"A" * 16 + b"B" * 16 + b"C" * 3
        pkts = self.create_stream_frag(self.pg1,
                                       self.pg0.remote_ip4,
                                       4789,
                                       4789,
                                       data,
                                       proto=IP_PROTOS.udp)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        frags = self.pg0.get_capture(len(pkts))
        p = self.reass_frags_and_verify(frags,
                                        self.pg1.remote_ip4,
                                        self.pg0.remote_ip4)
        self.assertEqual(p[UDP].sport, 4789)
        self.assertEqual(p[UDP].dport, 4789)
        self.assertEqual(data, p[Raw].load)

    def test_reass_hairpinning(self):
        """ NAT44 fragments hairpinning """

        self.server = self.pg0.remote_hosts[1]
        self.host_in_port = random.randint(1025, 65535)
        self.server_in_port = random.randint(1025, 65535)
        self.server_out_port = random.randint(1025, 65535)

        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)
        # add static mapping for server
        self.nat44_add_static_mapping(self.server.ip4, self.nat_addr,
                                      self.server_in_port,
                                      self.server_out_port,
                                      proto=IP_PROTOS.tcp)
        self.nat44_add_static_mapping(self.server.ip4, self.nat_addr,
                                      self.server_in_port,
                                      self.server_out_port,
                                      proto=IP_PROTOS.udp)
        self.nat44_add_static_mapping(self.server.ip4, self.nat_addr)

        self.reass_hairpinning(proto=IP_PROTOS.tcp)
        self.reass_hairpinning(proto=IP_PROTOS.udp)
        self.reass_hairpinning(proto=IP_PROTOS.icmp)

    def test_frag_out_of_order(self):
        """ NAT44 translate fragments arriving out of order """

        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)

        self.frag_out_of_order(proto=IP_PROTOS.tcp)
        self.frag_out_of_order(proto=IP_PROTOS.udp)
        self.frag_out_of_order(proto=IP_PROTOS.icmp)

    def test_port_restricted(self):
        """ Port restricted NAT44 (MAP-E CE) """
        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)
        self.vapi.nat_set_addr_and_port_alloc_alg(alg=1,
                                                  psid_offset=6,
                                                  psid_length=6,
                                                  psid=10)

        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=4567, dport=22))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.dst, self.pg1.remote_ip4)
            self.assertEqual(ip.src, self.nat_addr)
            self.assertEqual(tcp.dport, 22)
            self.assertNotEqual(tcp.sport, 4567)
            self.assertEqual((tcp.sport >> 6) & 63, 10)
            self.assert_packet_checksums_valid(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

    def test_port_range(self):
        """ External address port range """
        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)
        self.vapi.nat_set_addr_and_port_alloc_alg(alg=2,
                                                  start_port=1025,
                                                  end_port=1027)

        pkts = []
        for port in range(0, 5):
            p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                 IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
                 TCP(sport=1125 + port))
            pkts.append(p)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(3)
        for p in capture:
            tcp = p[TCP]
            self.assertGreaterEqual(tcp.sport, 1025)
            self.assertLessEqual(tcp.sport, 1027)

    def test_multiple_outside_vrf(self):
        """ Multiple outside VRF """
        vrf_id1 = 1
        vrf_id2 = 2

        self.pg1.unconfig_ip4()
        self.pg2.unconfig_ip4()
        self.vapi.ip_table_add_del(is_add=1, table={'table_id': vrf_id1})
        self.vapi.ip_table_add_del(is_add=1, table={'table_id': vrf_id2})
        self.pg1.set_table_ip4(vrf_id1)
        self.pg2.set_table_ip4(vrf_id2)
        self.pg1.config_ip4()
        self.pg2.config_ip4()
        self.pg1.resolve_arp()
        self.pg2.resolve_arp()

        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg2.sw_if_index,
            is_add=1)

        try:
            # first VRF
            pkts = self.create_stream_in(self.pg0, self.pg1)
            self.pg0.add_stream(pkts)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            capture = self.pg1.get_capture(len(pkts))
            self.verify_capture_out(capture, self.nat_addr)

            pkts = self.create_stream_out(self.pg1, self.nat_addr)
            self.pg1.add_stream(pkts)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            capture = self.pg0.get_capture(len(pkts))
            self.verify_capture_in(capture, self.pg0)

            self.tcp_port_in = 60303
            self.udp_port_in = 60304
            self.icmp_id_in = 60305

            # second VRF
            pkts = self.create_stream_in(self.pg0, self.pg2)
            self.pg0.add_stream(pkts)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            capture = self.pg2.get_capture(len(pkts))
            self.verify_capture_out(capture, self.nat_addr)

            pkts = self.create_stream_out(self.pg2, self.nat_addr)
            self.pg2.add_stream(pkts)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            capture = self.pg0.get_capture(len(pkts))
            self.verify_capture_in(capture, self.pg0)

        finally:
            self.nat44_add_address(self.nat_addr, is_add=0)
            self.pg1.unconfig_ip4()
            self.pg2.unconfig_ip4()
            self.pg1.set_table_ip4(0)
            self.pg2.set_table_ip4(0)
            self.pg1.config_ip4()
            self.pg2.config_ip4()
            self.pg1.resolve_arp()
            self.pg2.resolve_arp()

    def test_mss_clamping(self):
        """ TCP MSS clamping """
        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)

        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=self.tcp_port_in, dport=self.tcp_external_port,
                 flags="S", options=[('MSS', 1400)]))

        self.vapi.nat_set_mss_clamping(enable=1, mss_value=1000)
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(1)
        # Negotiated MSS value greater than configured - changed
        self.verify_mss_value(capture[0], 1000)

        self.vapi.nat_set_mss_clamping(enable=0, mss_value=1500)
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(1)
        # MSS clamping disabled - negotiated MSS unchanged
        self.verify_mss_value(capture[0], 1400)

        self.vapi.nat_set_mss_clamping(enable=1, mss_value=1500)
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(1)
        # Negotiated MSS value smaller than configured - unchanged
        self.verify_mss_value(capture[0], 1400)

    def test_ha_send(self):
        """ Send HA session synchronization events (active) """
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)
        self.nat44_add_address(self.nat_addr)

        self.vapi.nat_ha_set_listener(ip_address=self.pg3.local_ip4,
                                      port=12345,
                                      path_mtu=512)
        self.vapi.nat_ha_set_failover(ip_address=self.pg3.remote_ip4,
                                      port=12346, session_refresh_interval=10)
        bind_layers(UDP, HANATStateSync, sport=12345)

        # create sessions
        pkts = self.create_stream_in(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_out(capture)
        # active send HA events
        self.vapi.nat_ha_flush()
        stats = self.statistics.get_counter('/nat44/ha/add-event-send')
        self.assertEqual(stats[0][0], 3)
        capture = self.pg3.get_capture(1)
        p = capture[0]
        self.assert_packet_checksums_valid(p)
        try:
            ip = p[IP]
            udp = p[UDP]
            hanat = p[HANATStateSync]
        except IndexError:
            self.logger.error(ppp("Invalid packet:", p))
            raise
        else:
            self.assertEqual(ip.src, self.pg3.local_ip4)
            self.assertEqual(ip.dst, self.pg3.remote_ip4)
            self.assertEqual(udp.sport, 12345)
            self.assertEqual(udp.dport, 12346)
            self.assertEqual(hanat.version, 1)
            self.assertEqual(hanat.thread_index, 0)
            self.assertEqual(hanat.count, 3)
            seq = hanat.sequence_number
            for event in hanat.events:
                self.assertEqual(event.event_type, 1)
                self.assertEqual(event.in_addr, self.pg0.remote_ip4)
                self.assertEqual(event.out_addr, self.nat_addr)
                self.assertEqual(event.fib_index, 0)

        # ACK received events
        ack = (Ether(dst=self.pg3.local_mac, src=self.pg3.remote_mac) /
               IP(src=self.pg3.remote_ip4, dst=self.pg3.local_ip4) /
               UDP(sport=12346, dport=12345) /
               HANATStateSync(sequence_number=seq, flags='ACK'))
        self.pg3.add_stream(ack)
        self.pg_start()
        stats = self.statistics.get_counter('/nat44/ha/ack-recv')
        self.assertEqual(stats[0][0], 1)

        # delete one session
        self.pg_enable_capture(self.pg_interfaces)
        self.vapi.nat44_del_session(address=self.pg0.remote_ip4,
                                    port=self.tcp_port_in,
                                    protocol=IP_PROTOS.tcp,
                                    flags=self.config_flags.NAT_IS_INSIDE)
        self.vapi.nat_ha_flush()
        stats = self.statistics.get_counter('/nat44/ha/del-event-send')
        self.assertEqual(stats[0][0], 1)
        capture = self.pg3.get_capture(1)
        p = capture[0]
        try:
            hanat = p[HANATStateSync]
        except IndexError:
            self.logger.error(ppp("Invalid packet:", p))
            raise
        else:
            self.assertGreater(hanat.sequence_number, seq)

        # do not send ACK, active retry send HA event again
        self.pg_enable_capture(self.pg_interfaces)
        sleep(12)
        stats = self.statistics.get_counter('/nat44/ha/retry-count')
        self.assertEqual(stats[0][0], 3)
        stats = self.statistics.get_counter('/nat44/ha/missed-count')
        self.assertEqual(stats[0][0], 1)
        capture = self.pg3.get_capture(3)
        for packet in capture:
            self.assertEqual(packet, p)

        # session counters refresh
        pkts = self.create_stream_out(self.pg1)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg0.get_capture(2)
        self.vapi.nat_ha_flush()
        stats = self.statistics.get_counter('/nat44/ha/refresh-event-send')
        self.assertEqual(stats[0][0], 2)
        capture = self.pg3.get_capture(1)
        p = capture[0]
        self.assert_packet_checksums_valid(p)
        try:
            ip = p[IP]
            udp = p[UDP]
            hanat = p[HANATStateSync]
        except IndexError:
            self.logger.error(ppp("Invalid packet:", p))
            raise
        else:
            self.assertEqual(ip.src, self.pg3.local_ip4)
            self.assertEqual(ip.dst, self.pg3.remote_ip4)
            self.assertEqual(udp.sport, 12345)
            self.assertEqual(udp.dport, 12346)
            self.assertEqual(hanat.version, 1)
            self.assertEqual(hanat.count, 2)
            seq = hanat.sequence_number
            for event in hanat.events:
                self.assertEqual(event.event_type, 3)
                self.assertEqual(event.out_addr, self.nat_addr)
                self.assertEqual(event.fib_index, 0)
                self.assertEqual(event.total_pkts, 2)
                self.assertGreater(event.total_bytes, 0)

        ack = (Ether(dst=self.pg3.local_mac, src=self.pg3.remote_mac) /
               IP(src=self.pg3.remote_ip4, dst=self.pg3.local_ip4) /
               UDP(sport=12346, dport=12345) /
               HANATStateSync(sequence_number=seq, flags='ACK'))
        self.pg3.add_stream(ack)
        self.pg_start()
        stats = self.statistics.get_counter('/nat44/ha/ack-recv')
        self.assertEqual(stats[0][0], 2)

    def test_ha_recv(self):
        """ Receive HA session synchronization events (passive) """
        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)
        self.vapi.nat_ha_set_listener(ip_address=self.pg3.local_ip4,
                                      port=12345,
                                      path_mtu=512)
        bind_layers(UDP, HANATStateSync, sport=12345)

        self.tcp_port_out = random.randint(1025, 65535)
        self.udp_port_out = random.randint(1025, 65535)

        # send HA session add events to failover/passive
        p = (Ether(dst=self.pg3.local_mac, src=self.pg3.remote_mac) /
             IP(src=self.pg3.remote_ip4, dst=self.pg3.local_ip4) /
             UDP(sport=12346, dport=12345) /
             HANATStateSync(sequence_number=1, events=[
                 Event(event_type='add', protocol='tcp',
                       in_addr=self.pg0.remote_ip4, out_addr=self.nat_addr,
                       in_port=self.tcp_port_in, out_port=self.tcp_port_out,
                       eh_addr=self.pg1.remote_ip4,
                       ehn_addr=self.pg1.remote_ip4,
                       eh_port=self.tcp_external_port,
                       ehn_port=self.tcp_external_port, fib_index=0),
                 Event(event_type='add', protocol='udp',
                       in_addr=self.pg0.remote_ip4, out_addr=self.nat_addr,
                       in_port=self.udp_port_in, out_port=self.udp_port_out,
                       eh_addr=self.pg1.remote_ip4,
                       ehn_addr=self.pg1.remote_ip4,
                       eh_port=self.udp_external_port,
                       ehn_port=self.udp_external_port, fib_index=0)]))

        self.pg3.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        # receive ACK
        capture = self.pg3.get_capture(1)
        p = capture[0]
        try:
            hanat = p[HANATStateSync]
        except IndexError:
            self.logger.error(ppp("Invalid packet:", p))
            raise
        else:
            self.assertEqual(hanat.sequence_number, 1)
            self.assertEqual(hanat.flags, 'ACK')
            self.assertEqual(hanat.version, 1)
            self.assertEqual(hanat.thread_index, 0)
        stats = self.statistics.get_counter('/nat44/ha/ack-send')
        self.assertEqual(stats[0][0], 1)
        stats = self.statistics.get_counter('/nat44/ha/add-event-recv')
        self.assertEqual(stats[0][0], 2)
        users = self.statistics.get_counter('/nat44/total-users')
        self.assertEqual(users[0][0], 1)
        sessions = self.statistics.get_counter('/nat44/total-sessions')
        self.assertEqual(sessions[0][0], 2)
        users = self.vapi.nat44_user_dump()
        self.assertEqual(len(users), 1)
        self.assertEqual(str(users[0].ip_address),
                         self.pg0.remote_ip4)
        # there should be 2 sessions created by HA
        sessions = self.vapi.nat44_user_session_dump(users[0].ip_address,
                                                     users[0].vrf_id)
        self.assertEqual(len(sessions), 2)
        for session in sessions:
            self.assertEqual(str(session.inside_ip_address),
                             self.pg0.remote_ip4)
            self.assertEqual(str(session.outside_ip_address),
                             self.nat_addr)
            self.assertIn(session.inside_port,
                          [self.tcp_port_in, self.udp_port_in])
            self.assertIn(session.outside_port,
                          [self.tcp_port_out, self.udp_port_out])
            self.assertIn(session.protocol, [IP_PROTOS.tcp, IP_PROTOS.udp])

        # send HA session delete event to failover/passive
        p = (Ether(dst=self.pg3.local_mac, src=self.pg3.remote_mac) /
             IP(src=self.pg3.remote_ip4, dst=self.pg3.local_ip4) /
             UDP(sport=12346, dport=12345) /
             HANATStateSync(sequence_number=2, events=[
                 Event(event_type='del', protocol='udp',
                       in_addr=self.pg0.remote_ip4, out_addr=self.nat_addr,
                       in_port=self.udp_port_in, out_port=self.udp_port_out,
                       eh_addr=self.pg1.remote_ip4,
                       ehn_addr=self.pg1.remote_ip4,
                       eh_port=self.udp_external_port,
                       ehn_port=self.udp_external_port, fib_index=0)]))

        self.pg3.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        # receive ACK
        capture = self.pg3.get_capture(1)
        p = capture[0]
        try:
            hanat = p[HANATStateSync]
        except IndexError:
            self.logger.error(ppp("Invalid packet:", p))
            raise
        else:
            self.assertEqual(hanat.sequence_number, 2)
            self.assertEqual(hanat.flags, 'ACK')
            self.assertEqual(hanat.version, 1)
        users = self.vapi.nat44_user_dump()
        self.assertEqual(len(users), 1)
        self.assertEqual(str(users[0].ip_address),
                         self.pg0.remote_ip4)
        # now we should have only 1 session, 1 deleted by HA
        sessions = self.vapi.nat44_user_session_dump(users[0].ip_address,
                                                     users[0].vrf_id)
        self.assertEqual(len(sessions), 1)
        stats = self.statistics.get_counter('/nat44/ha/del-event-recv')
        self.assertEqual(stats[0][0], 1)

        stats = self.statistics.get_err_counter('/err/nat-ha/pkts-processed')
        self.assertEqual(stats, 2)

        # send HA session refresh event to failover/passive
        p = (Ether(dst=self.pg3.local_mac, src=self.pg3.remote_mac) /
             IP(src=self.pg3.remote_ip4, dst=self.pg3.local_ip4) /
             UDP(sport=12346, dport=12345) /
             HANATStateSync(sequence_number=3, events=[
                 Event(event_type='refresh', protocol='tcp',
                       in_addr=self.pg0.remote_ip4, out_addr=self.nat_addr,
                       in_port=self.tcp_port_in, out_port=self.tcp_port_out,
                       eh_addr=self.pg1.remote_ip4,
                       ehn_addr=self.pg1.remote_ip4,
                       eh_port=self.tcp_external_port,
                       ehn_port=self.tcp_external_port, fib_index=0,
                       total_bytes=1024, total_pkts=2)]))
        self.pg3.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        # receive ACK
        capture = self.pg3.get_capture(1)
        p = capture[0]
        try:
            hanat = p[HANATStateSync]
        except IndexError:
            self.logger.error(ppp("Invalid packet:", p))
            raise
        else:
            self.assertEqual(hanat.sequence_number, 3)
            self.assertEqual(hanat.flags, 'ACK')
            self.assertEqual(hanat.version, 1)
        users = self.vapi.nat44_user_dump()
        self.assertEqual(len(users), 1)
        self.assertEqual(str(users[0].ip_address),
                         self.pg0.remote_ip4)
        sessions = self.vapi.nat44_user_session_dump(users[0].ip_address,
                                                     users[0].vrf_id)
        self.assertEqual(len(sessions), 1)
        session = sessions[0]
        self.assertEqual(session.total_bytes, 1024)
        self.assertEqual(session.total_pkts, 2)
        stats = self.statistics.get_counter('/nat44/ha/refresh-event-recv')
        self.assertEqual(stats[0][0], 1)

        stats = self.statistics.get_err_counter('/err/nat-ha/pkts-processed')
        self.assertEqual(stats, 3)

        # send packet to test session created by HA
        p = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
             IP(src=self.pg1.remote_ip4, dst=self.nat_addr) /
             TCP(sport=self.tcp_external_port, dport=self.tcp_port_out))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
        except IndexError:
            self.logger.error(ppp("Invalid packet:", p))
            raise
        else:
            self.assertEqual(ip.src, self.pg1.remote_ip4)
            self.assertEqual(ip.dst, self.pg0.remote_ip4)
            self.assertEqual(tcp.sport, self.tcp_external_port)
            self.assertEqual(tcp.dport, self.tcp_port_in)

    def show_commands_at_teardown(self):
        self.logger.info(self.vapi.cli("show nat44 addresses"))
        self.logger.info(self.vapi.cli("show nat44 interfaces"))
        self.logger.info(self.vapi.cli("show nat44 static mappings"))
        self.logger.info(self.vapi.cli("show nat44 interface address"))
        self.logger.info(self.vapi.cli("show nat44 sessions detail"))
        self.logger.info(self.vapi.cli("show nat44 hash tables detail"))
        self.logger.info(self.vapi.cli("show nat timeouts"))
        self.logger.info(
            self.vapi.cli("show nat addr-port-assignment-alg"))
        self.logger.info(self.vapi.cli("show nat ha"))


class TestNAT44EndpointDependent2(MethodHolder):
    """ Endpoint-Dependent mapping and filtering test cases """

    @classmethod
    def tearDownClass(cls):
        super(TestNAT44EndpointDependent2, cls).tearDownClass()

    def tearDown(self):
        super(TestNAT44EndpointDependent2, self).tearDown()

    @classmethod
    def create_and_add_ip4_table(cls, i, table_id):
        cls.vapi.ip_table_add_del(is_add=1, table={'table_id': table_id})
        i.set_table_ip4(table_id)

    @classmethod
    def setUpClass(cls):
        super(TestNAT44EndpointDependent2, cls).setUpClass()

        cls.create_pg_interfaces(range(3))
        cls.interfaces = list(cls.pg_interfaces)

        cls.create_and_add_ip4_table(cls.pg1, 10)

        for i in cls.interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

            i.generate_remote_hosts(1)
            i.configure_ipv4_neighbors()

    def setUp(self):
        super(TestNAT44EndpointDependent2, self).setUp()
        flags = self.nat44_config_flags.NAT44_IS_ENDPOINT_DEPENDENT
        self.vapi.nat44_plugin_enable_disable(enable=1, flags=flags)

    def tearDown(self):
        super(TestNAT44EndpointDependent2, self).tearDown()
        if not self.vpp_dead:
            self.vapi.nat44_plugin_enable_disable(enable=0)
            self.vapi.cli("clear logging")

    def nat_add_inside_interface(self, i):
        self.vapi.nat44_interface_add_del_feature(
            flags=self.config_flags.NAT_IS_INSIDE,
            sw_if_index=i.sw_if_index, is_add=1)

    def nat_add_outside_interface(self, i):
        self.vapi.nat44_interface_add_del_feature(
            flags=self.config_flags.NAT_IS_OUTSIDE,
            sw_if_index=i.sw_if_index, is_add=1)

    def nat_add_interface_address(self, i):
        self.nat_addr = i.local_ip4
        self.vapi.nat44_add_del_interface_addr(
            sw_if_index=i.sw_if_index, is_add=1)

    def nat_add_address(self, address, vrf_id=0xFFFFFFFF):
        self.nat_addr = address
        self.nat44_add_address(address, vrf_id=vrf_id)

    def cli(self, command):
        result = self.vapi.cli(command)
        self.logger.info(result)
        # print(result)

    def show_configuration(self):
        self.cli("show interface")
        self.cli("show interface address")
        self.cli("show nat44 addresses")
        self.cli("show nat44 interfaces")

    def create_tcp_stream(self, in_if, out_if, count):
        """
        Create tcp packet stream

        :param in_if: Inside interface
        :param out_if: Outside interface
        :param count: count of packets to generate
        """
        pkts = []
        port = 6303

        for i in range(count):
            p = (Ether(dst=in_if.local_mac, src=in_if.remote_mac) /
                 IP(src=in_if.remote_ip4, dst=out_if.remote_ip4, ttl=64) /
                 TCP(sport=port + i, dport=20))
            pkts.append(p)

        return pkts

    def test_session_limit_per_vrf(self):

        inside = self.pg0
        inside_vrf10 = self.pg1
        outside = self.pg2

        limit = 5

        # 2 interfaces pg0, pg1 (vrf10, limit 1 tcp session)
        # non existing vrf_id makes process core dump
        self.vapi.nat44_set_session_limit(session_limit=limit, vrf_id=10)

        self.nat_add_inside_interface(inside)
        self.nat_add_inside_interface(inside_vrf10)
        self.nat_add_outside_interface(outside)

        # vrf independent
        self.nat_add_interface_address(outside)

        # BUG: causing core dump - when bad vrf_id is specified
        # self.nat44_add_address(outside.local_ip4, vrf_id=20)

        self.show_configuration()

        stream = self.create_tcp_stream(inside_vrf10, outside, limit * 2)
        inside_vrf10.add_stream(stream)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        capture = outside.get_capture(limit)

        stream = self.create_tcp_stream(inside, outside, limit * 2)
        inside.add_stream(stream)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        capture = outside.get_capture(len(stream))


class TestNAT44EndpointDependent(MethodHolder):
    """ Endpoint-Dependent mapping and filtering test cases """

    @classmethod
    def setUpClass(cls):
        super(TestNAT44EndpointDependent, cls).setUpClass()
        cls.vapi.cli("set log class nat level debug")

        cls.tcp_port_in = 6303
        cls.tcp_port_out = 6303
        cls.udp_port_in = 6304
        cls.udp_port_out = 6304
        cls.icmp_id_in = 6305
        cls.icmp_id_out = 6305
        cls.nat_addr = '10.0.0.3'
        cls.ipfix_src_port = 4739
        cls.ipfix_domain_id = 1
        cls.tcp_external_port = 80

        cls.create_pg_interfaces(range(9))
        cls.interfaces = list(cls.pg_interfaces[0:3])

        for i in cls.interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

        cls.pg0.generate_remote_hosts(3)
        cls.pg0.configure_ipv4_neighbors()

        cls.pg3.admin_up()

        cls.pg4.generate_remote_hosts(2)
        cls.pg4.config_ip4()
        cls.vapi.sw_interface_add_del_address(
            sw_if_index=cls.pg4.sw_if_index,
            prefix="10.0.0.1/24")

        cls.pg4.admin_up()
        cls.pg4.resolve_arp()
        cls.pg4._remote_hosts[1]._ip4 = cls.pg4._remote_hosts[0]._ip4
        cls.pg4.resolve_arp()

        zero_ip4 = socket.inet_pton(socket.AF_INET, "0.0.0.0")
        cls.vapi.ip_table_add_del(is_add=1, table={'table_id': 1})

        cls.pg5._local_ip4 = "10.1.1.1"
        cls.pg5._remote_hosts[0]._ip4 = "10.1.1.2"
        cls.pg5.set_table_ip4(1)
        cls.pg5.config_ip4()
        cls.pg5.admin_up()
        r1 = VppIpRoute(cls, cls.pg5.remote_ip4, 32,
                        [VppRoutePath("0.0.0.0",
                                      cls.pg5.sw_if_index)],
                        table_id=1,
                        register=False)
        r1.add_vpp_config()

        cls.pg6._local_ip4 = "10.1.2.1"
        cls.pg6._remote_hosts[0]._ip4 = "10.1.2.2"
        cls.pg6.set_table_ip4(1)
        cls.pg6.config_ip4()
        cls.pg6.admin_up()

        r2 = VppIpRoute(cls, cls.pg6.remote_ip4, 32,
                        [VppRoutePath("0.0.0.0",
                                      cls.pg6.sw_if_index)],
                        table_id=1,
                        register=False)
        r3 = VppIpRoute(cls, cls.pg6.remote_ip4, 16,
                        [VppRoutePath("0.0.0.0",
                                      0xffffffff,
                                      nh_table_id=1)],
                        table_id=0,
                        register=False)
        r4 = VppIpRoute(cls, "0.0.0.0", 0,
                        [VppRoutePath("0.0.0.0", 0xffffffff,
                                      nh_table_id=0)],
                        table_id=1,
                        register=False)
        r5 = VppIpRoute(cls, "0.0.0.0", 0,
                        [VppRoutePath(cls.pg1.local_ip4,
                                      cls.pg1.sw_if_index)],
                        register=False)
        r2.add_vpp_config()
        r3.add_vpp_config()
        r4.add_vpp_config()
        r5.add_vpp_config()

        cls.pg5.resolve_arp()
        cls.pg6.resolve_arp()

        cls.pg7.admin_up()
        cls.pg7.config_ip4()
        cls.pg7.resolve_arp()
        cls.pg7.generate_remote_hosts(3)
        cls.pg7.configure_ipv4_neighbors()

        cls.pg8.admin_up()
        cls.pg8.config_ip4()
        cls.pg8.resolve_arp()

    @classmethod
    def tearDownClass(cls):
        super(TestNAT44EndpointDependent, cls).tearDownClass()

    def setUp(self):
        super(TestNAT44EndpointDependent, self).setUp()
        flags = self.nat44_config_flags.NAT44_IS_ENDPOINT_DEPENDENT
        self.vapi.nat44_plugin_enable_disable(enable=1, flags=flags)
        self.vapi.nat_set_timeouts(
            udp=300, tcp_established=7440,
            tcp_transitory=240, icmp=60)

    def tearDown(self):
        super(TestNAT44EndpointDependent, self).tearDown()
        if not self.vpp_dead:
            self.vapi.nat44_plugin_enable_disable(enable=0)
            self.vapi.cli("clear logging")

    def test_frag_in_order(self):
        """ NAT44 translate fragments arriving in order """
        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)
        self.frag_in_order(proto=IP_PROTOS.tcp, ignore_port=True)
        self.frag_in_order(proto=IP_PROTOS.udp, ignore_port=True)
        self.frag_in_order(proto=IP_PROTOS.icmp, ignore_port=True)

    def test_frag_in_order_dont_translate(self):
        """ NAT44 don't translate fragments arriving in order """
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)
        self.vapi.nat44_forwarding_enable_disable(enable=True)
        self.frag_in_order(proto=IP_PROTOS.tcp, dont_translate=True)

    def test_frag_out_of_order(self):
        """ NAT44 translate fragments arriving out of order """
        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)
        self.frag_out_of_order(proto=IP_PROTOS.tcp, ignore_port=True)
        self.frag_out_of_order(proto=IP_PROTOS.udp, ignore_port=True)
        self.frag_out_of_order(proto=IP_PROTOS.icmp, ignore_port=True)

    def test_frag_out_of_order_dont_translate(self):
        """ NAT44 don't translate fragments arriving out of order """
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)
        self.vapi.nat44_forwarding_enable_disable(enable=True)
        self.frag_out_of_order(proto=IP_PROTOS.tcp, dont_translate=True)

    def test_frag_in_order_in_plus_out(self):
        """ in+out interface fragments in order """
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            flags=flags, is_add=1)

        self.server = self.pg1.remote_hosts[0]

        self.server_in_addr = self.server.ip4
        self.server_out_addr = '11.11.11.11'
        self.server_in_port = random.randint(1025, 65535)
        self.server_out_port = random.randint(1025, 65535)

        self.nat44_add_address(self.server_out_addr)

        # add static mappings for server
        self.nat44_add_static_mapping(self.server_in_addr,
                                      self.server_out_addr,
                                      self.server_in_port,
                                      self.server_out_port,
                                      proto=IP_PROTOS.tcp)
        self.nat44_add_static_mapping(self.server_in_addr,
                                      self.server_out_addr,
                                      self.server_in_port,
                                      self.server_out_port,
                                      proto=IP_PROTOS.udp)
        self.nat44_add_static_mapping(self.server_in_addr,
                                      self.server_out_addr,
                                      proto=IP_PROTOS.icmp)

        self.frag_in_order_in_plus_out(proto=IP_PROTOS.tcp)
        #self.frag_in_order_in_plus_out(proto=IP_PROTOS.udp)
        #self.frag_in_order_in_plus_out(proto=IP_PROTOS.icmp)

    def test_frag_out_of_order_in_plus_out(self):
        """ in+out interface fragments out of order """
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            flags=flags, is_add=1)

        self.server = self.pg1.remote_hosts[0]

        self.server_in_addr = self.server.ip4
        self.server_out_addr = '11.11.11.11'
        self.server_in_port = random.randint(1025, 65535)
        self.server_out_port = random.randint(1025, 65535)

        self.nat44_add_address(self.server_out_addr)

        # add static mappings for server
        self.nat44_add_static_mapping(self.server_in_addr,
                                      self.server_out_addr,
                                      self.server_in_port,
                                      self.server_out_port,
                                      proto=IP_PROTOS.tcp)
        self.nat44_add_static_mapping(self.server_in_addr,
                                      self.server_out_addr,
                                      self.server_in_port,
                                      self.server_out_port,
                                      proto=IP_PROTOS.udp)
        self.nat44_add_static_mapping(self.server_in_addr,
                                      self.server_out_addr,
                                      proto=IP_PROTOS.icmp)

        self.frag_out_of_order_in_plus_out(proto=IP_PROTOS.tcp)
        self.frag_out_of_order_in_plus_out(proto=IP_PROTOS.udp)
        self.frag_out_of_order_in_plus_out(proto=IP_PROTOS.icmp)

    def test_reass_hairpinning(self):
        """ NAT44 fragments hairpinning """
        self.server = self.pg0.remote_hosts[1]
        self.host_in_port = random.randint(1025, 65535)
        self.server_in_port = random.randint(1025, 65535)
        self.server_out_port = random.randint(1025, 65535)

        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)
        # add static mapping for server
        self.nat44_add_static_mapping(self.server.ip4, self.nat_addr,
                                      self.server_in_port,
                                      self.server_out_port,
                                      proto=IP_PROTOS.tcp)
        self.nat44_add_static_mapping(self.server.ip4, self.nat_addr,
                                      self.server_in_port,
                                      self.server_out_port,
                                      proto=IP_PROTOS.udp)
        self.nat44_add_static_mapping(self.server.ip4, self.nat_addr)

        self.reass_hairpinning(proto=IP_PROTOS.tcp, ignore_port=True)
        self.reass_hairpinning(proto=IP_PROTOS.udp, ignore_port=True)
        self.reass_hairpinning(proto=IP_PROTOS.icmp, ignore_port=True)

    def test_clear_sessions(self):
        """ NAT44 ED session clearing test """

        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)

        nat_config = self.vapi.nat_show_config()
        self.assertEqual(1, nat_config.endpoint_dependent)

        pkts = self.create_stream_in(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_out(capture, ignore_port=True)

        sessions = self.statistics.get_counter('/nat44/total-sessions')
        self.assertTrue(sessions[0][0] > 0)
        self.logger.info("sessions before clearing: %s" % sessions[0][0])

        # just for testing purposes
        self.logger.info(self.vapi.cli("show nat44 summary"))

        self.vapi.cli("clear nat44 sessions")

        self.logger.info(self.vapi.cli("show nat44 summary"))

        sessions = self.statistics.get_counter('/nat44/total-sessions')
        self.assertEqual(sessions[0][0], 0)
        self.logger.info("sessions after clearing: %s" % sessions[0][0])

    def test_dynamic(self):
        """ NAT44 dynamic translation test """

        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)

        nat_config = self.vapi.nat_show_config()
        self.assertEqual(1, nat_config.endpoint_dependent)

        # in2out
        tcpn = self.statistics.get_counter('/nat44/ed/in2out/slowpath/tcp')[0]
        udpn = self.statistics.get_counter('/nat44/ed/in2out/slowpath/udp')[0]
        icmpn = self.statistics.get_counter(
            '/nat44/ed/in2out/slowpath/icmp')[0]
        drops = self.statistics.get_counter(
            '/nat44/ed/in2out/slowpath/drops')[0]

        pkts = self.create_stream_in(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_out(capture, ignore_port=True)

        if_idx = self.pg0.sw_if_index
        cnt = self.statistics.get_counter('/nat44/ed/in2out/slowpath/tcp')[0]
        self.assertEqual(cnt[if_idx] - tcpn[if_idx], 2)
        cnt = self.statistics.get_counter('/nat44/ed/in2out/slowpath/udp')[0]
        self.assertEqual(cnt[if_idx] - udpn[if_idx], 1)
        cnt = self.statistics.get_counter('/nat44/ed/in2out/slowpath/icmp')[0]
        self.assertEqual(cnt[if_idx] - icmpn[if_idx], 1)
        cnt = self.statistics.get_counter('/nat44/ed/in2out/slowpath/drops')[0]
        self.assertEqual(cnt[if_idx] - drops[if_idx], 0)

        # out2in
        tcpn = self.statistics.get_counter('/nat44/ed/out2in/fastpath/tcp')[0]
        udpn = self.statistics.get_counter('/nat44/ed/out2in/fastpath/udp')[0]
        icmpn = self.statistics.get_counter(
            '/nat44/ed/out2in/fastpath/icmp')[0]
        drops = self.statistics.get_counter(
            '/nat44/ed/out2in/fastpath/drops')[0]

        pkts = self.create_stream_out(self.pg1)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(len(pkts))
        self.verify_capture_in(capture, self.pg0)

        if_idx = self.pg1.sw_if_index
        cnt = self.statistics.get_counter('/nat44/ed/out2in/fastpath/tcp')[0]
        self.assertEqual(cnt[if_idx] - tcpn[if_idx], 2)
        cnt = self.statistics.get_counter('/nat44/ed/out2in/fastpath/udp')[0]
        self.assertEqual(cnt[if_idx] - udpn[if_idx], 1)
        cnt = self.statistics.get_counter('/nat44/ed/out2in/fastpath/icmp')[0]
        self.assertEqual(cnt[if_idx] - icmpn[if_idx], 1)
        cnt = self.statistics.get_counter('/nat44/ed/out2in/fastpath/drops')[0]
        self.assertEqual(cnt[if_idx] - drops[if_idx], 0)

        sessions = self.statistics.get_counter('/nat44/total-sessions')
        self.assertEqual(sessions[0][0], 3)

    def test_dynamic_out_of_ports(self):
        """ NAT44 dynamic translation test: out of ports """

        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)

        nat_config = self.vapi.nat_show_config()
        self.assertEqual(1, nat_config.endpoint_dependent)

        # in2out and no NAT addresses added
        err_old = self.statistics.get_err_counter(
            '/err/nat44-ed-in2out-slowpath/out of ports')

        pkts = self.create_stream_in(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.get_capture(0, timeout=1)

        err_new = self.statistics.get_err_counter(
            '/err/nat44-ed-in2out-slowpath/out of ports')

        self.assertEqual(err_new - err_old, len(pkts))

        # in2out after NAT addresses added
        self.nat44_add_address(self.nat_addr)

        err_old = self.statistics.get_err_counter(
            '/err/nat44-ed-in2out-slowpath/out of ports')

        pkts = self.create_stream_in(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_out(capture, ignore_port=True)

        err_new = self.statistics.get_err_counter(
            '/err/nat44-ed-in2out-slowpath/out of ports')

        self.assertEqual(err_new, err_old)

    def test_dynamic_output_feature_vrf(self):
        """ NAT44 dynamic translation test: output-feature, VRF"""

        # other then default (0)
        new_vrf_id = 22

        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_output_feature(
            sw_if_index=self.pg7.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_output_feature(
            sw_if_index=self.pg8.sw_if_index,
            is_add=1)

        try:
            self.vapi.ip_table_add_del(is_add=1,
                                       table={'table_id': new_vrf_id})

            self.pg7.unconfig_ip4()
            self.pg7.set_table_ip4(new_vrf_id)
            self.pg7.config_ip4()
            self.pg7.resolve_arp()

            self.pg8.unconfig_ip4()
            self.pg8.set_table_ip4(new_vrf_id)
            self.pg8.config_ip4()
            self.pg8.resolve_arp()

            nat_config = self.vapi.nat_show_config()
            self.assertEqual(1, nat_config.endpoint_dependent)

            # in2out
            tcpn = self.statistics.get_counter(
                '/nat44/ed/in2out/slowpath/tcp')[0]
            udpn = self.statistics.get_counter(
                '/nat44/ed/in2out/slowpath/udp')[0]
            icmpn = self.statistics.get_counter(
                '/nat44/ed/in2out/slowpath/icmp')[0]
            drops = self.statistics.get_counter(
                '/nat44/ed/in2out/slowpath/drops')[0]

            pkts = self.create_stream_in(self.pg7, self.pg8)
            self.pg7.add_stream(pkts)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            capture = self.pg8.get_capture(len(pkts))
            self.verify_capture_out(capture, ignore_port=True)

            if_idx = self.pg7.sw_if_index
            cnt = self.statistics.get_counter(
                '/nat44/ed/in2out/slowpath/tcp')[0]
            self.assertEqual(cnt[if_idx] - tcpn[if_idx], 2)
            cnt = self.statistics.get_counter(
                '/nat44/ed/in2out/slowpath/udp')[0]
            self.assertEqual(cnt[if_idx] - udpn[if_idx], 1)
            cnt = self.statistics.get_counter(
                '/nat44/ed/in2out/slowpath/icmp')[0]
            self.assertEqual(cnt[if_idx] - icmpn[if_idx], 1)
            cnt = self.statistics.get_counter(
                '/nat44/ed/in2out/slowpath/drops')[0]
            self.assertEqual(cnt[if_idx] - drops[if_idx], 0)

            # out2in
            tcpn = self.statistics.get_counter(
                '/nat44/ed/out2in/fastpath/tcp')[0]
            udpn = self.statistics.get_counter(
                '/nat44/ed/out2in/fastpath/udp')[0]
            icmpn = self.statistics.get_counter(
                '/nat44/ed/out2in/fastpath/icmp')[0]
            drops = self.statistics.get_counter(
                '/nat44/ed/out2in/fastpath/drops')[0]

            pkts = self.create_stream_out(self.pg8)
            self.pg8.add_stream(pkts)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            capture = self.pg7.get_capture(len(pkts))
            self.verify_capture_in(capture, self.pg7)

            if_idx = self.pg8.sw_if_index
            cnt = self.statistics.get_counter(
                '/nat44/ed/out2in/fastpath/tcp')[0]
            self.assertEqual(cnt[if_idx] - tcpn[if_idx], 2)
            cnt = self.statistics.get_counter(
                '/nat44/ed/out2in/fastpath/udp')[0]
            self.assertEqual(cnt[if_idx] - udpn[if_idx], 1)
            cnt = self.statistics.get_counter(
                '/nat44/ed/out2in/fastpath/icmp')[0]
            self.assertEqual(cnt[if_idx] - icmpn[if_idx], 1)
            cnt = self.statistics.get_counter(
                '/nat44/ed/out2in/fastpath/drops')[0]
            self.assertEqual(cnt[if_idx] - drops[if_idx], 0)

            sessions = self.statistics.get_counter('/nat44/total-sessions')
            self.assertEqual(sessions[0][0], 3)

        finally:
            self.pg7.unconfig_ip4()
            self.pg7.set_table_ip4(1)
            self.pg7.config_ip4()
            self.pg7.resolve_arp()

            self.pg8.unconfig_ip4()
            self.pg8.set_table_ip4(1)
            self.pg8.config_ip4()
            self.pg8.resolve_arp()

            self.vapi.ip_table_add_del(is_add=0,
                                       table={'table_id': new_vrf_id})

    def test_forwarding(self):
        """ NAT44 forwarding test """

        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)
        self.vapi.nat44_forwarding_enable_disable(enable=1)

        real_ip = self.pg0.remote_ip4
        alias_ip = self.nat_addr
        flags = self.config_flags.NAT_IS_ADDR_ONLY
        self.vapi.nat44_add_del_static_mapping(is_add=1,
                                               local_ip_address=real_ip,
                                               external_ip_address=alias_ip,
                                               external_sw_if_index=0xFFFFFFFF,
                                               flags=flags)

        try:
            # in2out - static mapping match

            pkts = self.create_stream_out(self.pg1)
            self.pg1.add_stream(pkts)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            capture = self.pg0.get_capture(len(pkts))
            self.verify_capture_in(capture, self.pg0)

            pkts = self.create_stream_in(self.pg0, self.pg1)
            self.pg0.add_stream(pkts)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            capture = self.pg1.get_capture(len(pkts))
            self.verify_capture_out(capture, same_port=True)

            # in2out - no static mapping match

            host0 = self.pg0.remote_hosts[0]
            self.pg0.remote_hosts[0] = self.pg0.remote_hosts[1]
            try:
                pkts = self.create_stream_out(self.pg1,
                                              dst_ip=self.pg0.remote_ip4,
                                              use_inside_ports=True)
                self.pg1.add_stream(pkts)
                self.pg_enable_capture(self.pg_interfaces)
                self.pg_start()
                capture = self.pg0.get_capture(len(pkts))
                self.verify_capture_in(capture, self.pg0)

                pkts = self.create_stream_in(self.pg0, self.pg1)
                self.pg0.add_stream(pkts)
                self.pg_enable_capture(self.pg_interfaces)
                self.pg_start()
                capture = self.pg1.get_capture(len(pkts))
                self.verify_capture_out(capture, nat_ip=self.pg0.remote_ip4,
                                        same_port=True)
            finally:
                self.pg0.remote_hosts[0] = host0

            user = self.pg0.remote_hosts[1]
            sessions = self.vapi.nat44_user_session_dump(user.ip4, 0)
            self.assertEqual(len(sessions), 3)
            self.assertTrue(sessions[0].flags &
                            self.config_flags.NAT_IS_EXT_HOST_VALID)
            self.vapi.nat44_del_session(
                address=sessions[0].inside_ip_address,
                port=sessions[0].inside_port,
                protocol=sessions[0].protocol,
                flags=(self.config_flags.NAT_IS_INSIDE |
                       self.config_flags.NAT_IS_EXT_HOST_VALID),
                ext_host_address=sessions[0].ext_host_address,
                ext_host_port=sessions[0].ext_host_port)
            sessions = self.vapi.nat44_user_session_dump(user.ip4, 0)
            self.assertEqual(len(sessions), 2)

        finally:
            self.vapi.nat44_forwarding_enable_disable(enable=0)
            flags = self.config_flags.NAT_IS_ADDR_ONLY
            self.vapi.nat44_add_del_static_mapping(
                is_add=0,
                local_ip_address=real_ip,
                external_ip_address=alias_ip,
                external_sw_if_index=0xFFFFFFFF,
                flags=flags)

    def test_static_lb(self):
        """ NAT44 local service load balancing """
        external_addr_n = self.nat_addr
        external_port = 80
        local_port = 8080
        server1 = self.pg0.remote_hosts[0]
        server2 = self.pg0.remote_hosts[1]

        locals = [{'addr': server1.ip4,
                   'port': local_port,
                   'probability': 70,
                   'vrf_id': 0},
                  {'addr': server2.ip4,
                   'port': local_port,
                   'probability': 30,
                   'vrf_id': 0}]

        self.nat44_add_address(self.nat_addr)
        self.vapi.nat44_add_del_lb_static_mapping(
            is_add=1,
            external_addr=external_addr_n,
            external_port=external_port,
            protocol=IP_PROTOS.tcp,
            local_num=len(locals),
            locals=locals)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)

        # from client to service
        p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
             IP(src=self.pg1.remote_ip4, dst=self.nat_addr) /
             TCP(sport=12345, dport=external_port))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(1)
        p = capture[0]
        server = None
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertIn(ip.dst, [server1.ip4, server2.ip4])
            if ip.dst == server1.ip4:
                server = server1
            else:
                server = server2
            self.assertEqual(tcp.dport, local_port)
            self.assert_packet_checksums_valid(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        # from service back to client
        p = (Ether(src=server.mac, dst=self.pg0.local_mac) /
             IP(src=server.ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=local_port, dport=12345))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.src, self.nat_addr)
            self.assertEqual(tcp.sport, external_port)
            self.assert_packet_checksums_valid(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        sessions = self.vapi.nat44_user_session_dump(server.ip4, 0)
        self.assertEqual(len(sessions), 1)
        self.assertTrue(sessions[0].flags &
                        self.config_flags.NAT_IS_EXT_HOST_VALID)
        self.vapi.nat44_del_session(
            address=sessions[0].inside_ip_address,
            port=sessions[0].inside_port,
            protocol=sessions[0].protocol,
            flags=(self.config_flags.NAT_IS_INSIDE |
                   self.config_flags.NAT_IS_EXT_HOST_VALID),
            ext_host_address=sessions[0].ext_host_address,
            ext_host_port=sessions[0].ext_host_port)
        sessions = self.vapi.nat44_user_session_dump(server.ip4, 0)
        self.assertEqual(len(sessions), 0)

    def test_static_lb_multi_clients(self):
        """ NAT44 local service load balancing - multiple clients"""

        external_addr = self.nat_addr
        external_port = 80
        local_port = 8080
        server1 = self.pg0.remote_hosts[0]
        server2 = self.pg0.remote_hosts[1]
        server3 = self.pg0.remote_hosts[2]

        locals = [{'addr': server1.ip4,
                   'port': local_port,
                   'probability': 90,
                   'vrf_id': 0},
                  {'addr': server2.ip4,
                   'port': local_port,
                   'probability': 10,
                   'vrf_id': 0}]

        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)

        self.nat44_add_address(self.nat_addr)
        self.vapi.nat44_add_del_lb_static_mapping(is_add=1,
                                                  external_addr=external_addr,
                                                  external_port=external_port,
                                                  protocol=IP_PROTOS.tcp,
                                                  local_num=len(locals),
                                                  locals=locals)

        server1_n = 0
        server2_n = 0
        clients = ip4_range(self.pg1.remote_ip4, 10, 50)
        pkts = []
        for client in clients:
            p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
                 IP(src=client, dst=self.nat_addr) /
                 TCP(sport=12345, dport=external_port))
            pkts.append(p)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(len(pkts))
        for p in capture:
            if p[IP].dst == server1.ip4:
                server1_n += 1
            else:
                server2_n += 1
        self.assertGreater(server1_n, server2_n)

        local = {
            'addr': server3.ip4,
            'port': local_port,
            'probability': 20,
            'vrf_id': 0
        }

        # add new back-end
        self.vapi.nat44_lb_static_mapping_add_del_local(
            is_add=1,
            external_addr=external_addr,
            external_port=external_port,
            local=local,
            protocol=IP_PROTOS.tcp)
        server1_n = 0
        server2_n = 0
        server3_n = 0
        clients = ip4_range(self.pg1.remote_ip4, 60, 110)
        pkts = []
        for client in clients:
            p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
                 IP(src=client, dst=self.nat_addr) /
                 TCP(sport=12346, dport=external_port))
            pkts.append(p)
        self.assertGreater(len(pkts), 0)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(len(pkts))
        for p in capture:
            if p[IP].dst == server1.ip4:
                server1_n += 1
            elif p[IP].dst == server2.ip4:
                server2_n += 1
            else:
                server3_n += 1
        self.assertGreater(server1_n, 0)
        self.assertGreater(server2_n, 0)
        self.assertGreater(server3_n, 0)

        local = {
            'addr': server2.ip4,
            'port': local_port,
            'probability': 10,
            'vrf_id': 0
        }

        # remove one back-end
        self.vapi.nat44_lb_static_mapping_add_del_local(
            is_add=0,
            external_addr=external_addr,
            external_port=external_port,
            local=local,
            protocol=IP_PROTOS.tcp)
        server1_n = 0
        server2_n = 0
        server3_n = 0
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(len(pkts))
        for p in capture:
            if p[IP].dst == server1.ip4:
                server1_n += 1
            elif p[IP].dst == server2.ip4:
                server2_n += 1
            else:
                server3_n += 1
        self.assertGreater(server1_n, 0)
        self.assertEqual(server2_n, 0)
        self.assertGreater(server3_n, 0)

    def test_static_lb_2(self):
        """ NAT44 local service load balancing (asymmetrical rule) """
        external_addr = self.nat_addr
        external_port = 80
        local_port = 8080
        server1 = self.pg0.remote_hosts[0]
        server2 = self.pg0.remote_hosts[1]

        locals = [{'addr': server1.ip4,
                   'port': local_port,
                   'probability': 70,
                   'vrf_id': 0},
                  {'addr': server2.ip4,
                   'port': local_port,
                   'probability': 30,
                   'vrf_id': 0}]

        self.vapi.nat44_forwarding_enable_disable(enable=1)
        flags = self.config_flags.NAT_IS_OUT2IN_ONLY
        self.vapi.nat44_add_del_lb_static_mapping(is_add=1, flags=flags,
                                                  external_addr=external_addr,
                                                  external_port=external_port,
                                                  protocol=IP_PROTOS.tcp,
                                                  local_num=len(locals),
                                                  locals=locals)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)

        # from client to service
        p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
             IP(src=self.pg1.remote_ip4, dst=self.nat_addr) /
             TCP(sport=12345, dport=external_port))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(1)
        p = capture[0]
        server = None
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertIn(ip.dst, [server1.ip4, server2.ip4])
            if ip.dst == server1.ip4:
                server = server1
            else:
                server = server2
            self.assertEqual(tcp.dport, local_port)
            self.assert_packet_checksums_valid(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        # from service back to client
        p = (Ether(src=server.mac, dst=self.pg0.local_mac) /
             IP(src=server.ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=local_port, dport=12345))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.src, self.nat_addr)
            self.assertEqual(tcp.sport, external_port)
            self.assert_packet_checksums_valid(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        # from client to server (no translation)
        p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
             IP(src=self.pg1.remote_ip4, dst=server1.ip4) /
             TCP(sport=12346, dport=local_port))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(1)
        p = capture[0]
        server = None
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.dst, server1.ip4)
            self.assertEqual(tcp.dport, local_port)
            self.assert_packet_checksums_valid(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        # from service back to client (no translation)
        p = (Ether(src=server1.mac, dst=self.pg0.local_mac) /
             IP(src=server1.ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=local_port, dport=12346))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.src, server1.ip4)
            self.assertEqual(tcp.sport, local_port)
            self.assert_packet_checksums_valid(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

    def test_lb_affinity(self):
        """ NAT44 local service load balancing affinity """
        external_addr = self.nat_addr
        external_port = 80
        local_port = 8080
        server1 = self.pg0.remote_hosts[0]
        server2 = self.pg0.remote_hosts[1]

        locals = [{'addr': server1.ip4,
                   'port': local_port,
                   'probability': 50,
                   'vrf_id': 0},
                  {'addr': server2.ip4,
                   'port': local_port,
                   'probability': 50,
                   'vrf_id': 0}]

        self.nat44_add_address(self.nat_addr)
        self.vapi.nat44_add_del_lb_static_mapping(is_add=1,
                                                  external_addr=external_addr,
                                                  external_port=external_port,
                                                  protocol=IP_PROTOS.tcp,
                                                  affinity=10800,
                                                  local_num=len(locals),
                                                  locals=locals)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)

        p = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
             IP(src=self.pg1.remote_ip4, dst=self.nat_addr) /
             TCP(sport=1025, dport=external_port))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(1)
        backend = capture[0][IP].dst

        sessions = self.vapi.nat44_user_session_dump(backend, 0)
        self.assertEqual(len(sessions), 1)
        self.assertTrue(sessions[0].flags &
                        self.config_flags.NAT_IS_EXT_HOST_VALID)
        self.vapi.nat44_del_session(
            address=sessions[0].inside_ip_address,
            port=sessions[0].inside_port,
            protocol=sessions[0].protocol,
            flags=(self.config_flags.NAT_IS_INSIDE |
                   self.config_flags.NAT_IS_EXT_HOST_VALID),
            ext_host_address=sessions[0].ext_host_address,
            ext_host_port=sessions[0].ext_host_port)

        pkts = []
        for port in range(1030, 1100):
            p = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
                 IP(src=self.pg1.remote_ip4, dst=self.nat_addr) /
                 TCP(sport=port, dport=external_port))
            pkts.append(p)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(len(pkts))
        for p in capture:
            self.assertEqual(p[IP].dst, backend)

    def test_unknown_proto(self):
        """ NAT44 translate packet with unknown protocol """
        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)

        # in2out
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=self.tcp_port_in, dport=20))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        p = self.pg1.get_capture(1)

        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             GRE() /
             IP(src=self.pg2.remote_ip4, dst=self.pg2.remote_ip4) /
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
             IP(src=self.pg2.remote_ip4, dst=self.pg2.remote_ip4) /
             TCP(sport=1234, dport=1234))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        p = self.pg0.get_capture(1)
        packet = p[0]
        try:
            self.assertEqual(packet[IP].src, self.pg1.remote_ip4)
            self.assertEqual(packet[IP].dst, self.pg0.remote_ip4)
            self.assertEqual(packet.haslayer(GRE), 1)
            self.assert_packet_checksums_valid(packet)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", packet))
            raise

    def test_hairpinning_unknown_proto(self):
        """ NAT44 translate packet with unknown protocol - hairpinning """
        host = self.pg0.remote_hosts[0]
        server = self.pg0.remote_hosts[1]
        host_in_port = 1234
        server_out_port = 8765
        server_nat_ip = "10.0.0.11"

        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)

        # add static mapping for server
        self.nat44_add_static_mapping(server.ip4, server_nat_ip)

        # host to server
        p = (Ether(src=host.mac, dst=self.pg0.local_mac) /
             IP(src=host.ip4, dst=server_nat_ip) /
             TCP(sport=host_in_port, dport=server_out_port))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg0.get_capture(1)

        p = (Ether(dst=self.pg0.local_mac, src=host.mac) /
             IP(src=host.ip4, dst=server_nat_ip) /
             GRE() /
             IP(src=self.pg2.remote_ip4, dst=self.pg2.remote_ip4) /
             TCP(sport=1234, dport=1234))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        p = self.pg0.get_capture(1)
        packet = p[0]
        try:
            self.assertEqual(packet[IP].src, self.nat_addr)
            self.assertEqual(packet[IP].dst, server.ip4)
            self.assertEqual(packet.haslayer(GRE), 1)
            self.assert_packet_checksums_valid(packet)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", packet))
            raise

        # server to host
        p = (Ether(dst=self.pg0.local_mac, src=server.mac) /
             IP(src=server.ip4, dst=self.nat_addr) /
             GRE() /
             IP(src=self.pg2.remote_ip4, dst=self.pg2.remote_ip4) /
             TCP(sport=1234, dport=1234))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        p = self.pg0.get_capture(1)
        packet = p[0]
        try:
            self.assertEqual(packet[IP].src, server_nat_ip)
            self.assertEqual(packet[IP].dst, host.ip4)
            self.assertEqual(packet.haslayer(GRE), 1)
            self.assert_packet_checksums_valid(packet)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", packet))
            raise

    def test_output_feature_and_service(self):
        """ NAT44 interface output feature and services """
        external_addr = '1.2.3.4'
        external_port = 80
        local_port = 8080

        self.vapi.nat44_forwarding_enable_disable(enable=1)
        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_ADDR_ONLY
        self.vapi.nat44_add_del_identity_mapping(
            ip_address=self.pg1.remote_ip4, sw_if_index=0xFFFFFFFF,
            flags=flags, is_add=1)
        flags = self.config_flags.NAT_IS_OUT2IN_ONLY
        self.nat44_add_static_mapping(self.pg0.remote_ip4, external_addr,
                                      local_port, external_port,
                                      proto=IP_PROTOS.tcp, flags=flags)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_output_feature(
            is_add=1,
            sw_if_index=self.pg1.sw_if_index)

        # from client to service
        p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
             IP(src=self.pg1.remote_ip4, dst=external_addr) /
             TCP(sport=12345, dport=external_port))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.dst, self.pg0.remote_ip4)
            self.assertEqual(tcp.dport, local_port)
            self.assert_packet_checksums_valid(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        # from service back to client
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=local_port, dport=12345))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.src, external_addr)
            self.assertEqual(tcp.sport, external_port)
            self.assert_packet_checksums_valid(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        # from local network host to external network
        pkts = self.create_stream_in(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_out(capture, ignore_port=True)
        pkts = self.create_stream_in(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_out(capture, ignore_port=True)

        # from external network back to local network host
        pkts = self.create_stream_out(self.pg1)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(len(pkts))
        self.verify_capture_in(capture, self.pg0)

    def test_output_feature_and_service2(self):
        """ NAT44 interface output feature and service host direct access """
        self.vapi.nat44_forwarding_enable_disable(enable=1)
        self.nat44_add_address(self.nat_addr)
        self.vapi.nat44_interface_add_del_output_feature(
            is_add=1,
            sw_if_index=self.pg1.sw_if_index)

        # session initiated from service host - translate
        pkts = self.create_stream_in(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_out(capture, ignore_port=True)

        pkts = self.create_stream_out(self.pg1)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(len(pkts))
        self.verify_capture_in(capture, self.pg0)

        # session initiated from remote host - do not translate
        self.tcp_port_in = 60303
        self.udp_port_in = 60304
        self.icmp_id_in = 60305
        pkts = self.create_stream_out(self.pg1,
                                      self.pg0.remote_ip4,
                                      use_inside_ports=True)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(len(pkts))
        self.verify_capture_in(capture, self.pg0)

        pkts = self.create_stream_in(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_out(capture, nat_ip=self.pg0.remote_ip4,
                                same_port=True)

    def test_output_feature_and_service3(self):
        """ NAT44 interface output feature and DST NAT """
        external_addr = '1.2.3.4'
        external_port = 80
        local_port = 8080

        self.vapi.nat44_forwarding_enable_disable(enable=1)
        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_OUT2IN_ONLY
        self.nat44_add_static_mapping(self.pg1.remote_ip4, external_addr,
                                      local_port, external_port,
                                      proto=IP_PROTOS.tcp, flags=flags)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_output_feature(
            is_add=1,
            sw_if_index=self.pg1.sw_if_index)

        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=external_addr) /
             TCP(sport=12345, dport=external_port))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.src, self.pg0.remote_ip4)
            self.assertEqual(tcp.sport, 12345)
            self.assertEqual(ip.dst, self.pg1.remote_ip4)
            self.assertEqual(tcp.dport, local_port)
            self.assert_packet_checksums_valid(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
             IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4) /
             TCP(sport=local_port, dport=12345))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.src, external_addr)
            self.assertEqual(tcp.sport, external_port)
            self.assertEqual(ip.dst, self.pg0.remote_ip4)
            self.assertEqual(tcp.dport, 12345)
            self.assert_packet_checksums_valid(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

    def test_next_src_nat(self):
        """ On way back forward packet to nat44-in2out node. """
        twice_nat_addr = '10.0.1.3'
        external_port = 80
        local_port = 8080
        post_twice_nat_port = 0

        self.vapi.nat44_forwarding_enable_disable(enable=1)
        self.nat44_add_address(twice_nat_addr, twice_nat=1)
        flags = (self.config_flags.NAT_IS_OUT2IN_ONLY |
                 self.config_flags.NAT_IS_SELF_TWICE_NAT)
        self.nat44_add_static_mapping(self.pg6.remote_ip4, self.pg1.remote_ip4,
                                      local_port, external_port,
                                      proto=IP_PROTOS.tcp, vrf_id=1,
                                      flags=flags)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg6.sw_if_index,
            is_add=1)

        p = (Ether(src=self.pg6.remote_mac, dst=self.pg6.local_mac) /
             IP(src=self.pg6.remote_ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=12345, dport=external_port))
        self.pg6.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg6.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.src, twice_nat_addr)
            self.assertNotEqual(tcp.sport, 12345)
            post_twice_nat_port = tcp.sport
            self.assertEqual(ip.dst, self.pg6.remote_ip4)
            self.assertEqual(tcp.dport, local_port)
            self.assert_packet_checksums_valid(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        p = (Ether(src=self.pg6.remote_mac, dst=self.pg6.local_mac) /
             IP(src=self.pg6.remote_ip4, dst=twice_nat_addr) /
             TCP(sport=local_port, dport=post_twice_nat_port))
        self.pg6.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg6.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.src, self.pg1.remote_ip4)
            self.assertEqual(tcp.sport, external_port)
            self.assertEqual(ip.dst, self.pg6.remote_ip4)
            self.assertEqual(tcp.dport, 12345)
            self.assert_packet_checksums_valid(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

    def twice_nat_common(self, self_twice_nat=False, same_pg=False, lb=False,
                         client_id=None):
        twice_nat_addr = '10.0.1.3'

        port_in = 8080
        if lb:
            if not same_pg:
                port_in1 = port_in
                port_in2 = port_in
            else:
                port_in1 = port_in + 1
                port_in2 = port_in + 2

        port_out = 80
        eh_port_out = 4567

        server1 = self.pg0.remote_hosts[0]
        server2 = self.pg0.remote_hosts[1]
        if lb and same_pg:
            server2 = server1
        if not lb:
            server = server1

        pg0 = self.pg0
        if same_pg:
            pg1 = self.pg0
        else:
            pg1 = self.pg1

        eh_translate = ((not self_twice_nat) or (not lb and same_pg) or
                        client_id == 1)

        self.nat44_add_address(self.nat_addr)
        self.nat44_add_address(twice_nat_addr, twice_nat=1)

        flags = 0
        if self_twice_nat:
            flags |= self.config_flags.NAT_IS_SELF_TWICE_NAT
        else:
            flags |= self.config_flags.NAT_IS_TWICE_NAT

        if not lb:
            self.nat44_add_static_mapping(pg0.remote_ip4, self.nat_addr,
                                          port_in, port_out,
                                          proto=IP_PROTOS.tcp,
                                          flags=flags)
        else:
            locals = [{'addr': server1.ip4,
                       'port': port_in1,
                       'probability': 50,
                       'vrf_id': 0},
                      {'addr': server2.ip4,
                       'port': port_in2,
                       'probability': 50,
                       'vrf_id': 0}]
            out_addr = self.nat_addr

            self.vapi.nat44_add_del_lb_static_mapping(is_add=1, flags=flags,
                                                      external_addr=out_addr,
                                                      external_port=port_out,
                                                      protocol=IP_PROTOS.tcp,
                                                      local_num=len(locals),
                                                      locals=locals)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=pg1.sw_if_index,
            is_add=1)

        if same_pg:
            if not lb:
                client = server
            else:
                assert client_id is not None
                if client_id == 1:
                    client = self.pg0.remote_hosts[0]
                elif client_id == 2:
                    client = self.pg0.remote_hosts[1]
        else:
            client = pg1.remote_hosts[0]
        p = (Ether(src=pg1.remote_mac, dst=pg1.local_mac) /
             IP(src=client.ip4, dst=self.nat_addr) /
             TCP(sport=eh_port_out, dport=port_out))
        pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = pg0.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            if lb:
                if ip.dst == server1.ip4:
                    server = server1
                    port_in = port_in1
                else:
                    server = server2
                    port_in = port_in2
            self.assertEqual(ip.dst, server.ip4)
            if lb and same_pg:
                self.assertIn(tcp.dport, [port_in1, port_in2])
            else:
                self.assertEqual(tcp.dport, port_in)
            if eh_translate:
                self.assertEqual(ip.src, twice_nat_addr)
                self.assertNotEqual(tcp.sport, eh_port_out)
            else:
                self.assertEqual(ip.src, client.ip4)
                self.assertEqual(tcp.sport, eh_port_out)
            eh_addr_in = ip.src
            eh_port_in = tcp.sport
            saved_port_in = tcp.dport
            self.assert_packet_checksums_valid(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        p = (Ether(src=server.mac, dst=pg0.local_mac) /
             IP(src=server.ip4, dst=eh_addr_in) /
             TCP(sport=saved_port_in, dport=eh_port_in))
        pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = pg1.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.dst, client.ip4)
            self.assertEqual(ip.src, self.nat_addr)
            self.assertEqual(tcp.dport, eh_port_out)
            self.assertEqual(tcp.sport, port_out)
            self.assert_packet_checksums_valid(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        if eh_translate:
            sessions = self.vapi.nat44_user_session_dump(server.ip4, 0)
            self.assertEqual(len(sessions), 1)
            self.assertTrue(sessions[0].flags &
                            self.config_flags.NAT_IS_EXT_HOST_VALID)
            self.assertTrue(sessions[0].flags &
                            self.config_flags.NAT_IS_TWICE_NAT)
            self.logger.info(self.vapi.cli("show nat44 sessions detail"))
            self.vapi.nat44_del_session(
                address=sessions[0].inside_ip_address,
                port=sessions[0].inside_port,
                protocol=sessions[0].protocol,
                flags=(self.config_flags.NAT_IS_INSIDE |
                       self.config_flags.NAT_IS_EXT_HOST_VALID),
                ext_host_address=sessions[0].ext_host_nat_address,
                ext_host_port=sessions[0].ext_host_nat_port)
            sessions = self.vapi.nat44_user_session_dump(server.ip4, 0)
            self.assertEqual(len(sessions), 0)

    def test_twice_nat(self):
        """ Twice NAT44 """
        self.twice_nat_common()

    def test_self_twice_nat_positive(self):
        """ Self Twice NAT44 (positive test) """
        self.twice_nat_common(self_twice_nat=True, same_pg=True)

    def test_self_twice_nat_negative(self):
        """ Self Twice NAT44 (negative test) """
        self.twice_nat_common(self_twice_nat=True)

    def test_twice_nat_lb(self):
        """ Twice NAT44 local service load balancing """
        self.twice_nat_common(lb=True)

    def test_self_twice_nat_lb_positive(self):
        """ Self Twice NAT44 local service load balancing (positive test) """
        self.twice_nat_common(lb=True, self_twice_nat=True, same_pg=True,
                              client_id=1)

    def test_self_twice_nat_lb_negative(self):
        """ Self Twice NAT44 local service load balancing (negative test) """
        self.twice_nat_common(lb=True, self_twice_nat=True, same_pg=True,
                              client_id=2)

    def test_twice_nat_interface_addr(self):
        """ Acquire twice NAT44 addresses from interface """
        flags = self.config_flags.NAT_IS_TWICE_NAT
        self.vapi.nat44_add_del_interface_addr(
            is_add=1,
            sw_if_index=self.pg3.sw_if_index,
            flags=flags)

        # no address in NAT pool
        adresses = self.vapi.nat44_address_dump()
        self.assertEqual(0, len(adresses))

        # configure interface address and check NAT address pool
        self.pg3.config_ip4()
        adresses = self.vapi.nat44_address_dump()
        self.assertEqual(1, len(adresses))
        self.assertEqual(str(adresses[0].ip_address),
                         self.pg3.local_ip4)
        self.assertEqual(adresses[0].flags, flags)

        # remove interface address and check NAT address pool
        self.pg3.unconfig_ip4()
        adresses = self.vapi.nat44_address_dump()
        self.assertEqual(0, len(adresses))

    def test_tcp_close(self):
        """ Close TCP session from inside network - output feature """
        old_timeouts = self.vapi.nat_get_timeouts()
        new_transitory = 2
        self.vapi.nat_set_timeouts(
                udp=old_timeouts.udp,
                tcp_established=old_timeouts.tcp_established,
                icmp=old_timeouts.icmp,
                tcp_transitory=new_transitory)

        self.vapi.nat44_forwarding_enable_disable(enable=1)
        self.nat44_add_address(self.pg1.local_ip4)
        twice_nat_addr = '10.0.1.3'
        service_ip = '192.168.16.150'
        self.nat44_add_address(twice_nat_addr, twice_nat=1)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_output_feature(
            is_add=1,
            sw_if_index=self.pg1.sw_if_index)
        flags = (self.config_flags.NAT_IS_OUT2IN_ONLY |
                 self.config_flags.NAT_IS_TWICE_NAT)
        self.nat44_add_static_mapping(self.pg0.remote_ip4,
                                      service_ip,
                                      80,
                                      80,
                                      proto=IP_PROTOS.tcp,
                                      flags=flags)
        sessions = self.vapi.nat44_user_session_dump(self.pg0.remote_ip4, 0)
        start_sessnum = len(sessions)

        # SYN packet out->in
        p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
             IP(src=self.pg1.remote_ip4, dst=service_ip) /
             TCP(sport=33898, dport=80, flags="S"))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(1)
        p = capture[0]
        tcp_port = p[TCP].sport

        # SYN + ACK packet in->out
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=twice_nat_addr) /
             TCP(sport=80, dport=tcp_port, flags="SA"))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.get_capture(1)

        # ACK packet out->in
        p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
             IP(src=self.pg1.remote_ip4, dst=service_ip) /
             TCP(sport=33898, dport=80, flags="A"))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg0.get_capture(1)

        # FIN packet in -> out
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=twice_nat_addr) /
             TCP(sport=80, dport=tcp_port, flags="FA", seq=100, ack=300))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.get_capture(1)

        # FIN+ACK packet out -> in
        p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
             IP(src=self.pg1.remote_ip4, dst=service_ip) /
             TCP(sport=33898, dport=80, flags="FA", seq=300, ack=101))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg0.get_capture(1)

        # ACK packet in -> out
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=twice_nat_addr) /
             TCP(sport=80, dport=tcp_port, flags="A", seq=101, ack=301))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.get_capture(1)

        # session now in transitory timeout
        # try SYN packet out->in - should be dropped
        p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
             IP(src=self.pg1.remote_ip4, dst=service_ip) /
             TCP(sport=33898, dport=80, flags="S"))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        self.sleep(new_transitory, "wait for transitory timeout")
        self.pg0.assert_nothing_captured(0)

        # session should still exist
        sessions = self.vapi.nat44_user_session_dump(self.pg0.remote_ip4, 0)
        self.assertEqual(len(sessions) - start_sessnum, 1)

        # send FIN+ACK packet out -> in - will cause session to be wiped
        # but won't create a new session
        p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
             IP(src=self.pg1.remote_ip4, dst=service_ip) /
             TCP(sport=33898, dport=80, flags="FA", seq=300, ack=101))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        sessions = self.vapi.nat44_user_session_dump(self.pg0.remote_ip4, 0)
        self.assertEqual(len(sessions) - start_sessnum, 0)
        self.pg0.assert_nothing_captured(0)

    def test_tcp_session_close_in(self):
        """ Close TCP session from inside network """
        self.tcp_port_out = 10505
        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_TWICE_NAT
        self.nat44_add_static_mapping(self.pg0.remote_ip4,
                                      self.nat_addr,
                                      self.tcp_port_in,
                                      self.tcp_port_out,
                                      proto=IP_PROTOS.tcp,
                                      flags=flags)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)

        sessions = self.vapi.nat44_user_session_dump(self.pg0.remote_ip4, 0)
        start_sessnum = len(sessions)

        self.vapi.nat_set_timeouts(udp=300, tcp_established=7440,
                                   tcp_transitory=2, icmp=5)

        self.initiate_tcp_session(self.pg0, self.pg1)

        # FIN packet in -> out
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=self.tcp_port_in, dport=self.tcp_external_port,
                 flags="FA", seq=100, ack=300))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.get_capture(1)

        pkts = []

        # ACK packet out -> in
        p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
             IP(src=self.pg1.remote_ip4, dst=self.nat_addr) /
             TCP(sport=self.tcp_external_port, dport=self.tcp_port_out,
                 flags="A", seq=300, ack=101))
        pkts.append(p)

        # FIN packet out -> in
        p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
             IP(src=self.pg1.remote_ip4, dst=self.nat_addr) /
             TCP(sport=self.tcp_external_port, dport=self.tcp_port_out,
                 flags="FA", seq=300, ack=101))
        pkts.append(p)

        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg0.get_capture(2)

        # ACK packet in -> out
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=self.tcp_port_in, dport=self.tcp_external_port,
                 flags="A", seq=101, ack=301))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.get_capture(1)

        sessions = self.vapi.nat44_user_session_dump(self.pg0.remote_ip4, 0)
        self.assertEqual(len(sessions) - start_sessnum, 1)

        stats = self.statistics.get_counter(
            '/err/nat44-ed-out2in/drops due to TCP in transitory timeout')
        out2in_drops = stats[0]
        stats = self.statistics.get_counter(
            '/err/nat44-ed-in2out/drops due to TCP in transitory timeout')
        in2out_drops = stats[0]

        # extra FIN packet out -> in - this should be dropped
        p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
             IP(src=self.pg1.remote_ip4, dst=self.nat_addr) /
             TCP(sport=self.tcp_external_port, dport=self.tcp_port_out,
                 flags="FA", seq=300, ack=101))

        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg0.assert_nothing_captured()

        # extra ACK packet in -> out - this should be dropped
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=self.tcp_port_in, dport=self.tcp_external_port,
                 flags="A", seq=101, ack=301))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.assert_nothing_captured()

        stats = self.statistics.get_counter(
            '/err/nat44-ed-out2in/drops due to TCP in transitory timeout')
        self.assertEqual(stats[0] - out2in_drops, 1)
        stats = self.statistics.get_counter(
            '/err/nat44-ed-in2out/drops due to TCP in transitory timeout')
        self.assertEqual(stats[0] - in2out_drops, 1)

        self.sleep(3)
        # extra ACK packet in -> out - this will cause session to be wiped
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=self.tcp_port_in, dport=self.tcp_external_port,
                 flags="A", seq=101, ack=301))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.assert_nothing_captured()
        sessions = self.vapi.nat44_user_session_dump(self.pg0.remote_ip4, 0)
        self.assertEqual(len(sessions) - start_sessnum, 0)

    def test_tcp_session_close_out(self):
        """ Close TCP session from outside network """
        self.tcp_port_out = 10505
        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_TWICE_NAT
        self.nat44_add_static_mapping(self.pg0.remote_ip4,
                                      self.nat_addr,
                                      self.tcp_port_in,
                                      self.tcp_port_out,
                                      proto=IP_PROTOS.tcp,
                                      flags=flags)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)

        sessions = self.vapi.nat44_user_session_dump(self.pg0.remote_ip4, 0)
        start_sessnum = len(sessions)

        self.vapi.nat_set_timeouts(udp=300, tcp_established=7440,
                                   tcp_transitory=2, icmp=5)

        self.initiate_tcp_session(self.pg0, self.pg1)

        # FIN packet out -> in
        p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
             IP(src=self.pg1.remote_ip4, dst=self.nat_addr) /
             TCP(sport=self.tcp_external_port, dport=self.tcp_port_out,
                 flags="FA", seq=100, ack=300))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg0.get_capture(1)

        # FIN+ACK packet in -> out
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=self.tcp_port_in, dport=self.tcp_external_port,
                 flags="FA", seq=300, ack=101))

        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.get_capture(1)

        # ACK packet out -> in
        p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
             IP(src=self.pg1.remote_ip4, dst=self.nat_addr) /
             TCP(sport=self.tcp_external_port, dport=self.tcp_port_out,
                 flags="A", seq=101, ack=301))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg0.get_capture(1)

        sessions = self.vapi.nat44_user_session_dump(self.pg0.remote_ip4, 0)
        self.assertEqual(len(sessions) - start_sessnum, 1)

        stats = self.statistics.get_counter(
            '/err/nat44-ed-out2in/drops due to TCP in transitory timeout')
        out2in_drops = stats[0]
        stats = self.statistics.get_counter(
            '/err/nat44-ed-in2out/drops due to TCP in transitory timeout')
        in2out_drops = stats[0]

        # extra FIN packet out -> in - this should be dropped
        p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
             IP(src=self.pg1.remote_ip4, dst=self.nat_addr) /
             TCP(sport=self.tcp_external_port, dport=self.tcp_port_out,
                 flags="FA", seq=300, ack=101))

        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg0.assert_nothing_captured()

        # extra ACK packet in -> out - this should be dropped
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=self.tcp_port_in, dport=self.tcp_external_port,
                 flags="A", seq=101, ack=301))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.assert_nothing_captured()

        stats = self.statistics.get_counter(
            '/err/nat44-ed-out2in/drops due to TCP in transitory timeout')
        self.assertEqual(stats[0] - out2in_drops, 1)
        stats = self.statistics.get_counter(
            '/err/nat44-ed-in2out/drops due to TCP in transitory timeout')
        self.assertEqual(stats[0] - in2out_drops, 1)

        self.sleep(3)
        # extra ACK packet in -> out - this will cause session to be wiped
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=self.tcp_port_in, dport=self.tcp_external_port,
                 flags="A", seq=101, ack=301))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.assert_nothing_captured()
        sessions = self.vapi.nat44_user_session_dump(self.pg0.remote_ip4, 0)
        self.assertEqual(len(sessions) - start_sessnum, 0)

    def test_tcp_session_close_simultaneous(self):
        """ Close TCP session from inside network """
        self.tcp_port_out = 10505
        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_TWICE_NAT
        self.nat44_add_static_mapping(self.pg0.remote_ip4,
                                      self.nat_addr,
                                      self.tcp_port_in,
                                      self.tcp_port_out,
                                      proto=IP_PROTOS.tcp,
                                      flags=flags)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)

        sessions = self.vapi.nat44_user_session_dump(self.pg0.remote_ip4, 0)
        start_sessnum = len(sessions)

        self.vapi.nat_set_timeouts(udp=300, tcp_established=7440,
                                   tcp_transitory=2, icmp=5)

        self.initiate_tcp_session(self.pg0, self.pg1)

        # FIN packet in -> out
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=self.tcp_port_in, dport=self.tcp_external_port,
                 flags="FA", seq=100, ack=300))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.get_capture(1)

        # FIN packet out -> in
        p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
             IP(src=self.pg1.remote_ip4, dst=self.nat_addr) /
             TCP(sport=self.tcp_external_port, dport=self.tcp_port_out,
                 flags="FA", seq=300, ack=100))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg0.get_capture(1)

        # ACK packet in -> out
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=self.tcp_port_in, dport=self.tcp_external_port,
                 flags="A", seq=101, ack=301))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.get_capture(1)

        # ACK packet out -> in
        p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
             IP(src=self.pg1.remote_ip4, dst=self.nat_addr) /
             TCP(sport=self.tcp_external_port, dport=self.tcp_port_out,
                 flags="A", seq=301, ack=101))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg0.get_capture(1)

        sessions = self.vapi.nat44_user_session_dump(self.pg0.remote_ip4, 0)
        self.assertEqual(len(sessions) - start_sessnum, 1)

        stats = self.statistics.get_counter(
            '/err/nat44-ed-out2in/drops due to TCP in transitory timeout')
        out2in_drops = stats[0]
        stats = self.statistics.get_counter(
            '/err/nat44-ed-in2out/drops due to TCP in transitory timeout')
        in2out_drops = stats[0]

        # extra FIN packet out -> in - this should be dropped
        p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
             IP(src=self.pg1.remote_ip4, dst=self.nat_addr) /
             TCP(sport=self.tcp_external_port, dport=self.tcp_port_out,
                 flags="FA", seq=300, ack=101))

        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg0.assert_nothing_captured()

        # extra ACK packet in -> out - this should be dropped
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=self.tcp_port_in, dport=self.tcp_external_port,
                 flags="A", seq=101, ack=301))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.assert_nothing_captured()

        stats = self.statistics.get_counter(
            '/err/nat44-ed-out2in/drops due to TCP in transitory timeout')
        self.assertEqual(stats[0] - out2in_drops, 1)
        stats = self.statistics.get_counter(
            '/err/nat44-ed-in2out/drops due to TCP in transitory timeout')
        self.assertEqual(stats[0] - in2out_drops, 1)

        self.sleep(3)
        # extra ACK packet in -> out - this will cause session to be wiped
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=self.tcp_port_in, dport=self.tcp_external_port,
                 flags="A", seq=101, ack=301))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.assert_nothing_captured()
        sessions = self.vapi.nat44_user_session_dump(self.pg0.remote_ip4, 0)
        self.assertEqual(len(sessions) - start_sessnum, 0)

    def test_one_armed_nat44_static(self):
        """ One armed NAT44 and 1:1 NAPT asymmetrical rule """
        remote_host = self.pg4.remote_hosts[0]
        local_host = self.pg4.remote_hosts[1]
        external_port = 80
        local_port = 8080
        eh_port_in = 0

        self.vapi.nat44_forwarding_enable_disable(enable=1)
        self.nat44_add_address(self.nat_addr, twice_nat=1)
        flags = (self.config_flags.NAT_IS_OUT2IN_ONLY |
                 self.config_flags.NAT_IS_TWICE_NAT)
        self.nat44_add_static_mapping(local_host.ip4, self.nat_addr,
                                      local_port, external_port,
                                      proto=IP_PROTOS.tcp, flags=flags)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg4.sw_if_index,
            is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg4.sw_if_index,
            flags=flags, is_add=1)

        # from client to service
        p = (Ether(src=self.pg4.remote_mac, dst=self.pg4.local_mac) /
             IP(src=remote_host.ip4, dst=self.nat_addr) /
             TCP(sport=12345, dport=external_port))
        self.pg4.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg4.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.dst, local_host.ip4)
            self.assertEqual(ip.src, self.nat_addr)
            self.assertEqual(tcp.dport, local_port)
            self.assertNotEqual(tcp.sport, 12345)
            eh_port_in = tcp.sport
            self.assert_packet_checksums_valid(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        # from service back to client
        p = (Ether(src=self.pg4.remote_mac, dst=self.pg4.local_mac) /
             IP(src=local_host.ip4, dst=self.nat_addr) /
             TCP(sport=local_port, dport=eh_port_in))
        self.pg4.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg4.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.src, self.nat_addr)
            self.assertEqual(ip.dst, remote_host.ip4)
            self.assertEqual(tcp.sport, external_port)
            self.assertEqual(tcp.dport, 12345)
            self.assert_packet_checksums_valid(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

    def test_static_with_port_out2(self):
        """ 1:1 NAPT asymmetrical rule """

        external_port = 80
        local_port = 8080

        self.vapi.nat44_forwarding_enable_disable(enable=1)
        flags = self.config_flags.NAT_IS_OUT2IN_ONLY
        self.nat44_add_static_mapping(self.pg0.remote_ip4, self.nat_addr,
                                      local_port, external_port,
                                      proto=IP_PROTOS.tcp, flags=flags)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)

        # from client to service
        p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
             IP(src=self.pg1.remote_ip4, dst=self.nat_addr) /
             TCP(sport=12345, dport=external_port))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.dst, self.pg0.remote_ip4)
            self.assertEqual(tcp.dport, local_port)
            self.assert_packet_checksums_valid(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        # ICMP error
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             ICMP(type=11) / capture[0][IP])
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(1)
        p = capture[0]
        try:
            self.assertEqual(p[IP].src, self.nat_addr)
            inner = p[IPerror]
            self.assertEqual(inner.dst, self.nat_addr)
            self.assertEqual(inner[TCPerror].dport, external_port)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        # from service back to client
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=local_port, dport=12345))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.src, self.nat_addr)
            self.assertEqual(tcp.sport, external_port)
            self.assert_packet_checksums_valid(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        # ICMP error
        p = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
             IP(src=self.pg1.remote_ip4, dst=self.nat_addr) /
             ICMP(type=11) / capture[0][IP])
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(1)
        p = capture[0]
        try:
            self.assertEqual(p[IP].dst, self.pg0.remote_ip4)
            inner = p[IPerror]
            self.assertEqual(inner.src, self.pg0.remote_ip4)
            self.assertEqual(inner[TCPerror].sport, local_port)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        # from client to server (no translation)
        p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
             IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4) /
             TCP(sport=12346, dport=local_port))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.dst, self.pg0.remote_ip4)
            self.assertEqual(tcp.dport, local_port)
            self.assert_packet_checksums_valid(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        # from service back to client (no translation)
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=local_port, dport=12346))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.src, self.pg0.remote_ip4)
            self.assertEqual(tcp.sport, local_port)
            self.assert_packet_checksums_valid(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

    def test_output_feature(self):
        """ NAT44 interface output feature (in2out postrouting) """
        self.vapi.nat44_forwarding_enable_disable(enable=1)
        self.nat44_add_address(self.nat_addr)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            is_add=1)
        self.vapi.nat44_interface_add_del_output_feature(
            is_add=1,
            sw_if_index=self.pg1.sw_if_index)

        # in2out
        pkts = self.create_stream_in(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_out(capture, ignore_port=True)

        # out2in
        pkts = self.create_stream_out(self.pg1)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(len(pkts))
        self.verify_capture_in(capture, self.pg0)

    def test_output_feature_stateful_acl(self):
        """ NAT44 endpoint-dependent output feature works with stateful ACL """
        self.nat44_add_address(self.nat_addr)
        self.vapi.nat44_interface_add_del_output_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=self.config_flags.NAT_IS_INSIDE,
            is_add=1)
        self.vapi.nat44_interface_add_del_output_feature(
            sw_if_index=self.pg1.sw_if_index,
            flags=self.config_flags.NAT_IS_OUTSIDE,
            is_add=1)

        # First ensure that the NAT is working sans ACL

        # send packets out2in, no sessions yet so packets should drop
        pkts_out2in = self.create_stream_out(self.pg1)
        self.send_and_assert_no_replies(self.pg1, pkts_out2in)

        # send packets into inside intf, ensure received via outside intf
        pkts_in2out = self.create_stream_in(self.pg0, self.pg1)
        capture = self.send_and_expect(self.pg0, pkts_in2out, self.pg1,
                                       len(pkts_in2out))
        self.verify_capture_out(capture, ignore_port=True)

        # send out2in again, with sessions created it should work now
        pkts_out2in = self.create_stream_out(self.pg1)
        capture = self.send_and_expect(self.pg1, pkts_out2in, self.pg0,
                                       len(pkts_out2in))
        self.verify_capture_in(capture, self.pg0)

        # Create an ACL blocking everything
        out2in_deny_rule = AclRule(is_permit=0)
        out2in_acl = VppAcl(self, rules=[out2in_deny_rule])
        out2in_acl.add_vpp_config()

        # create an ACL to permit/reflect everything
        in2out_reflect_rule = AclRule(is_permit=2)
        in2out_acl = VppAcl(self, rules=[in2out_reflect_rule])
        in2out_acl.add_vpp_config()

        # apply as input acl on interface and confirm it blocks everything
        acl_if = VppAclInterface(self, sw_if_index=self.pg1.sw_if_index,
                                 n_input=1, acls=[out2in_acl])
        acl_if.add_vpp_config()
        self.send_and_assert_no_replies(self.pg1, pkts_out2in)

        # apply output acl
        acl_if.acls = [out2in_acl, in2out_acl]
        acl_if.add_vpp_config()
        # send in2out to generate ACL state (NAT state was created earlier)
        capture = self.send_and_expect(self.pg0, pkts_in2out, self.pg1,
                                       len(pkts_in2out))
        self.verify_capture_out(capture, ignore_port=True)

        # send out2in again. ACL state exists so it should work now.
        # TCP packets with the syn flag set also need the ack flag
        for p in pkts_out2in:
            if p.haslayer(TCP) and p[TCP].flags & 0x02:
                p[TCP].flags |= 0x10
        capture = self.send_and_expect(self.pg1, pkts_out2in, self.pg0,
                                       len(pkts_out2in))
        self.verify_capture_in(capture, self.pg0)
        self.logger.info(self.vapi.cli("show trace"))

    def test_multiple_vrf(self):
        """ Multiple VRF setup """
        external_addr = '1.2.3.4'
        external_port = 80
        local_port = 8080
        port = 0

        self.vapi.nat44_forwarding_enable_disable(enable=1)
        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            is_add=1, flags=flags)
        self.vapi.nat44_interface_add_del_output_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg5.sw_if_index,
            is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg5.sw_if_index,
            is_add=1, flags=flags)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg6.sw_if_index,
            is_add=1)
        flags = self.config_flags.NAT_IS_OUT2IN_ONLY
        self.nat44_add_static_mapping(self.pg5.remote_ip4, external_addr,
                                      local_port, external_port, vrf_id=1,
                                      proto=IP_PROTOS.tcp, flags=flags)
        self.nat44_add_static_mapping(
            self.pg0.remote_ip4,
            external_sw_if_index=self.pg0.sw_if_index,
            local_port=local_port,
            vrf_id=0,
            external_port=external_port,
            proto=IP_PROTOS.tcp,
            flags=flags
        )

        # from client to service (both VRF1)
        p = (Ether(src=self.pg6.remote_mac, dst=self.pg6.local_mac) /
             IP(src=self.pg6.remote_ip4, dst=external_addr) /
             TCP(sport=12345, dport=external_port))
        self.pg6.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg5.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.dst, self.pg5.remote_ip4)
            self.assertEqual(tcp.dport, local_port)
            self.assert_packet_checksums_valid(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        # from service back to client (both VRF1)
        p = (Ether(src=self.pg5.remote_mac, dst=self.pg5.local_mac) /
             IP(src=self.pg5.remote_ip4, dst=self.pg6.remote_ip4) /
             TCP(sport=local_port, dport=12345))
        self.pg5.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg6.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.src, external_addr)
            self.assertEqual(tcp.sport, external_port)
            self.assert_packet_checksums_valid(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        # dynamic NAT from VRF1 to VRF0 (output-feature)
        p = (Ether(src=self.pg5.remote_mac, dst=self.pg5.local_mac) /
             IP(src=self.pg5.remote_ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=2345, dport=22))
        self.pg5.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.src, self.nat_addr)
            self.assert_packet_checksums_valid(p)
            port = tcp.sport
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
             IP(src=self.pg1.remote_ip4, dst=self.nat_addr) /
             TCP(sport=22, dport=port))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg5.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.dst, self.pg5.remote_ip4)
            self.assertEqual(tcp.dport, 2345)
            self.assert_packet_checksums_valid(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        # from client VRF1 to service VRF0
        p = (Ether(src=self.pg6.remote_mac, dst=self.pg6.local_mac) /
             IP(src=self.pg6.remote_ip4, dst=self.pg0.local_ip4) /
             TCP(sport=12346, dport=external_port))
        self.pg6.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.dst, self.pg0.remote_ip4)
            self.assertEqual(tcp.dport, local_port)
            self.assert_packet_checksums_valid(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        # from service VRF0 back to client VRF1
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg6.remote_ip4) /
             TCP(sport=local_port, dport=12346))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg6.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.src, self.pg0.local_ip4)
            self.assertEqual(tcp.sport, external_port)
            self.assert_packet_checksums_valid(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        # from client VRF0 to service VRF1
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=external_addr) /
             TCP(sport=12347, dport=external_port))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg5.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.dst, self.pg5.remote_ip4)
            self.assertEqual(tcp.dport, local_port)
            self.assert_packet_checksums_valid(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        # from service VRF1 back to client VRF0
        p = (Ether(src=self.pg5.remote_mac, dst=self.pg5.local_mac) /
             IP(src=self.pg5.remote_ip4, dst=self.pg0.remote_ip4) /
             TCP(sport=local_port, dport=12347))
        self.pg5.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.src, external_addr)
            self.assertEqual(tcp.sport, external_port)
            self.assert_packet_checksums_valid(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        # from client to server (both VRF1, no translation)
        p = (Ether(src=self.pg6.remote_mac, dst=self.pg6.local_mac) /
             IP(src=self.pg6.remote_ip4, dst=self.pg5.remote_ip4) /
             TCP(sport=12348, dport=local_port))
        self.pg6.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg5.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.dst, self.pg5.remote_ip4)
            self.assertEqual(tcp.dport, local_port)
            self.assert_packet_checksums_valid(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        # from server back to client (both VRF1, no translation)
        p = (Ether(src=self.pg5.remote_mac, dst=self.pg5.local_mac) /
             IP(src=self.pg5.remote_ip4, dst=self.pg6.remote_ip4) /
             TCP(sport=local_port, dport=12348))
        self.pg5.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg6.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.src, self.pg5.remote_ip4)
            self.assertEqual(tcp.sport, local_port)
            self.assert_packet_checksums_valid(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        # from client VRF1 to server VRF0 (no translation)
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg6.remote_ip4) /
             TCP(sport=local_port, dport=12349))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg6.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.src, self.pg0.remote_ip4)
            self.assertEqual(tcp.sport, local_port)
            self.assert_packet_checksums_valid(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        # from server VRF0 back to client VRF1 (no translation)
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg6.remote_ip4) /
             TCP(sport=local_port, dport=12349))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg6.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.src, self.pg0.remote_ip4)
            self.assertEqual(tcp.sport, local_port)
            self.assert_packet_checksums_valid(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        # from client VRF0 to server VRF1 (no translation)
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg5.remote_ip4) /
             TCP(sport=12344, dport=local_port))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg5.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.dst, self.pg5.remote_ip4)
            self.assertEqual(tcp.dport, local_port)
            self.assert_packet_checksums_valid(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        # from server VRF1 back to client VRF0 (no translation)
        p = (Ether(src=self.pg5.remote_mac, dst=self.pg5.local_mac) /
             IP(src=self.pg5.remote_ip4, dst=self.pg0.remote_ip4) /
             TCP(sport=local_port, dport=12344))
        self.pg5.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.src, self.pg5.remote_ip4)
            self.assertEqual(tcp.sport, local_port)
            self.assert_packet_checksums_valid(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

    def test_session_rst_timeout(self):
        """ NAT44 session RST timeouts """
        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)
        self.vapi.nat_set_timeouts(udp=300, tcp_established=7440,
                                   tcp_transitory=5, icmp=60)

        self.initiate_tcp_session(self.pg0, self.pg1)
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=self.tcp_port_in, dport=self.tcp_external_port,
                 flags="R"))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.get_capture(1)

        sleep(6)

        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=self.tcp_port_in + 1, dport=self.tcp_external_port + 1,
                 flags="S"))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.get_capture(1)

    def test_syslog_sess(self):
        """ Test syslog session creation and deletion """
        self.vapi.syslog_set_filter(
            self.SYSLOG_SEVERITY.SYSLOG_API_SEVERITY_INFO)
        self.vapi.syslog_set_sender(self.pg2.local_ip4, self.pg2.remote_ip4)
        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)

        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=self.tcp_port_in, dport=self.tcp_external_port))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(1)
        self.tcp_port_out = capture[0][TCP].sport
        capture = self.pg2.get_capture(1)
        self.verify_syslog_sess(capture[0][Raw].load)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.nat44_add_address(self.nat_addr, is_add=0)
        capture = self.pg2.get_capture(1)
        self.verify_syslog_sess(capture[0][Raw].load, False)

    def test_ed_users_dump(self):
        """ API test - nat44_user_dump """
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index,
            is_add=1)
        self.vapi.nat44_forwarding_enable_disable(enable=1)

        real_ip = self.pg0.remote_ip4
        alias_ip = self.nat_addr
        flags = self.config_flags.NAT_IS_ADDR_ONLY
        self.vapi.nat44_add_del_static_mapping(is_add=1,
                                               local_ip_address=real_ip,
                                               external_ip_address=alias_ip,
                                               external_sw_if_index=0xFFFFFFFF,
                                               flags=flags)

        users = self.vapi.nat44_user_dump()
        self.assertEqual(len(users), 0)
        try:
            # in2out - static mapping match

            pkts = self.create_stream_out(self.pg1)
            self.pg1.add_stream(pkts)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            capture = self.pg0.get_capture(len(pkts))
            self.verify_capture_in(capture, self.pg0)

            pkts = self.create_stream_in(self.pg0, self.pg1)
            self.pg0.add_stream(pkts)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            capture = self.pg1.get_capture(len(pkts))
            self.verify_capture_out(capture, same_port=True)

            users = self.vapi.nat44_user_dump()
            self.assertEqual(len(users), 1)
            static_user = users[0]
            self.assertEqual(static_user.nstaticsessions, 3)
            self.assertEqual(static_user.nsessions, 0)

            # in2out - no static mapping match

            host0 = self.pg0.remote_hosts[0]
            self.pg0.remote_hosts[0] = self.pg0.remote_hosts[1]
            try:
                pkts = self.create_stream_out(self.pg1,
                                              dst_ip=self.pg0.remote_ip4,
                                              use_inside_ports=True)
                self.pg1.add_stream(pkts)
                self.pg_enable_capture(self.pg_interfaces)
                self.pg_start()
                capture = self.pg0.get_capture(len(pkts))
                self.verify_capture_in(capture, self.pg0)

                pkts = self.create_stream_in(self.pg0, self.pg1)
                self.pg0.add_stream(pkts)
                self.pg_enable_capture(self.pg_interfaces)
                self.pg_start()
                capture = self.pg1.get_capture(len(pkts))
                self.verify_capture_out(capture, nat_ip=self.pg0.remote_ip4,
                                        same_port=True)
            finally:
                self.pg0.remote_hosts[0] = host0

            users = self.vapi.nat44_user_dump()
            self.assertEqual(len(users), 2)
            if str(users[0].ip_address) == self.pg0.remote_hosts[0].ip4:
                non_static_user = users[1]
                static_user = users[0]
            else:
                non_static_user = users[0]
                static_user = users[1]
            self.assertEqual(static_user.nstaticsessions, 3)
            self.assertEqual(static_user.nsessions, 0)
            self.assertEqual(non_static_user.nstaticsessions, 0)
            self.assertEqual(non_static_user.nsessions, 3)

            users = self.vapi.nat44_user_dump()
            self.assertEqual(len(users), 2)
            if str(users[0].ip_address) == self.pg0.remote_hosts[0].ip4:
                non_static_user = users[1]
                static_user = users[0]
            else:
                non_static_user = users[0]
                static_user = users[1]
            self.assertEqual(static_user.nstaticsessions, 3)
            self.assertEqual(static_user.nsessions, 0)
            self.assertEqual(non_static_user.nstaticsessions, 0)
            self.assertEqual(non_static_user.nsessions, 3)

        finally:
            self.vapi.nat44_forwarding_enable_disable(enable=0)
            flags = self.config_flags.NAT_IS_ADDR_ONLY
            self.vapi.nat44_add_del_static_mapping(
                is_add=0,
                local_ip_address=real_ip,
                external_ip_address=alias_ip,
                external_sw_if_index=0xFFFFFFFF,
                flags=flags)

    def show_commands_at_teardown(self):
        self.logger.info(self.vapi.cli("show errors"))
        self.logger.info(self.vapi.cli("show nat44 addresses"))
        self.logger.info(self.vapi.cli("show nat44 interfaces"))
        self.logger.info(self.vapi.cli("show nat44 static mappings"))
        self.logger.info(self.vapi.cli("show nat44 interface address"))
        self.logger.info(self.vapi.cli("show nat44 sessions detail"))
        self.logger.info(self.vapi.cli("show nat44 hash tables detail"))
        self.logger.info(self.vapi.cli("show nat timeouts"))
        self.logger.info(self.vapi.cli("debug nat44 fib registration"))


class TestNAT44EndpointDependent3(MethodHolder):
    """ Endpoint-Dependent mapping and filtering extra test cases """

    max_translations = 50

    @classmethod
    def setUpClass(cls):
        super(TestNAT44EndpointDependent3, cls).setUpClass()
        cls.vapi.cli("set log class nat level debug")

        cls.nat_addr = '10.0.0.3'

        cls.create_pg_interfaces(range(2))

        for i in cls.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    def setUp(self):
        super(TestNAT44EndpointDependent3, self).setUp()
        flags = self.nat44_config_flags.NAT44_IS_ENDPOINT_DEPENDENT
        self.vapi.nat44_plugin_enable_disable(
            sessions=self.max_translations,
            flags=flags, enable=1)
        self.vapi.nat_set_timeouts(
            udp=1, tcp_established=7440, tcp_transitory=30, icmp=1)

        self.nat44_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index, flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg1.sw_if_index, is_add=1)

    @classmethod
    def tearDownClass(cls):
        super(TestNAT44EndpointDependent3, cls).tearDownClass()

    def tearDown(self):
        super(TestNAT44EndpointDependent3, self).tearDown()
        if not self.vpp_dead:
            self.vapi.nat44_plugin_enable_disable(enable=0)
            self.vapi.cli("clear logging")

    def init_tcp_session(self, in_if, out_if, sport, ext_dport):
        # SYN packet in->out
        p = (Ether(src=in_if.remote_mac, dst=in_if.local_mac) /
             IP(src=in_if.remote_ip4, dst=out_if.remote_ip4) /
             TCP(sport=sport, dport=ext_dport, flags="S"))
        in_if.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = out_if.get_capture(1)
        p = capture[0]
        tcp_port_out = p[TCP].sport

        # SYN + ACK packet out->in
        p = (Ether(src=out_if.remote_mac, dst=out_if.local_mac) /
             IP(src=out_if.remote_ip4, dst=self.nat_addr) /
             TCP(sport=ext_dport, dport=tcp_port_out, flags="SA"))
        out_if.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        in_if.get_capture(1)

        # ACK packet in->out
        p = (Ether(src=in_if.remote_mac, dst=in_if.local_mac) /
             IP(src=in_if.remote_ip4, dst=out_if.remote_ip4) /
             TCP(sport=sport, dport=ext_dport, flags="A"))
        in_if.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        out_if.get_capture(1)

        return tcp_port_out

    def test_lru_cleanup(self):
        """ LRU cleanup algorithm """
        tcp_port_out = self.init_tcp_session(self.pg0, self.pg1, 2000, 80)
        pkts = []
        for i in range(0, self.max_translations - 1):
            p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                 IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64) /
                 UDP(sport=7000+i, dport=80))
            pkts.append(p)

        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.get_capture(len(pkts))
        self.sleep(1.5, "wait for timeouts")

        pkts = []
        for i in range(0, self.max_translations - 1):
            p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                 IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64) /
                 ICMP(id=8000+i, type='echo-request'))
            pkts.append(p)

        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.get_capture(len(pkts))


class TestNAT44Out2InDPO(MethodHolder):
    """ NAT44 Test Cases using out2in DPO """

    @classmethod
    def setUpClass(cls):
        super(TestNAT44Out2InDPO, cls).setUpClass()
        cls.vapi.cli("set log class nat level debug")

        cls.tcp_port_in = 6303
        cls.tcp_port_out = 6303
        cls.udp_port_in = 6304
        cls.udp_port_out = 6304
        cls.icmp_id_in = 6305
        cls.icmp_id_out = 6305
        cls.nat_addr = '10.0.0.3'
        cls.dst_ip4 = '192.168.70.1'

        cls.create_pg_interfaces(range(2))

        cls.pg0.admin_up()
        cls.pg0.config_ip4()
        cls.pg0.resolve_arp()

        cls.pg1.admin_up()
        cls.pg1.config_ip6()
        cls.pg1.resolve_ndp()

        r1 = VppIpRoute(cls, "::", 0,
                        [VppRoutePath(cls.pg1.remote_ip6,
                                      cls.pg1.sw_if_index)],
                        register=False)
        r1.add_vpp_config()

    @classmethod
    def tearDownClass(cls):
        super(TestNAT44Out2InDPO, cls).tearDownClass()

    def setUp(self):
        super(TestNAT44Out2InDPO, self).setUp()
        flags = self.nat44_config_flags.NAT44_API_IS_OUT2IN_DPO
        self.vapi.nat44_plugin_enable_disable(enable=1, flags=flags)

    def tearDown(self):
        super(TestNAT44Out2InDPO, self).tearDown()
        if not self.vpp_dead:
            self.vapi.nat44_plugin_enable_disable(enable=0)
            self.vapi.cli("clear logging")

    def configure_xlat(self):
        self.dst_ip6_pfx = '1:2:3::'
        self.dst_ip6_pfx_n = socket.inet_pton(socket.AF_INET6,
                                              self.dst_ip6_pfx)
        self.dst_ip6_pfx_len = 96
        self.src_ip6_pfx = '4:5:6::'
        self.src_ip6_pfx_n = socket.inet_pton(socket.AF_INET6,
                                              self.src_ip6_pfx)
        self.src_ip6_pfx_len = 96
        self.vapi.map_add_domain(self.dst_ip6_pfx_n, self.dst_ip6_pfx_len,
                                 self.src_ip6_pfx_n, self.src_ip6_pfx_len,
                                 '\x00\x00\x00\x00', 0)

    @unittest.skip('Temporary disabled')
    def test_464xlat_ce(self):
        """ Test 464XLAT CE with NAT44 """

        nat_config = self.vapi.nat_show_config()
        self.assertEqual(1, nat_config.out2in_dpo)

        self.configure_xlat()

        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_add_del_address_range(first_ip_address=self.nat_addr_n,
                                              last_ip_address=self.nat_addr_n,
                                              vrf_id=0xFFFFFFFF, is_add=1)

        out_src_ip6 = self.compose_ip6(self.dst_ip4, self.dst_ip6_pfx,
                                       self.dst_ip6_pfx_len)
        out_dst_ip6 = self.compose_ip6(self.nat_addr, self.src_ip6_pfx,
                                       self.src_ip6_pfx_len)

        try:
            pkts = self.create_stream_in(self.pg0, self.pg1, self.dst_ip4)
            self.pg0.add_stream(pkts)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            capture = self.pg1.get_capture(len(pkts))
            self.verify_capture_out_ip6(capture, nat_ip=out_dst_ip6,
                                        dst_ip=out_src_ip6)

            pkts = self.create_stream_out_ip6(self.pg1, out_src_ip6,
                                              out_dst_ip6)
            self.pg1.add_stream(pkts)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            capture = self.pg0.get_capture(len(pkts))
            self.verify_capture_in(capture, self.pg0)
        finally:
            self.vapi.nat44_interface_add_del_feature(
                sw_if_index=self.pg0.sw_if_index,
                flags=flags)
            self.vapi.nat44_add_del_address_range(
                first_ip_address=self.nat_addr_n,
                last_ip_address=self.nat_addr_n,
                vrf_id=0xFFFFFFFF)

    @unittest.skip('Temporary disabled')
    def test_464xlat_ce_no_nat(self):
        """ Test 464XLAT CE without NAT44 """

        self.configure_xlat()

        out_src_ip6 = self.compose_ip6(self.dst_ip4, self.dst_ip6_pfx,
                                       self.dst_ip6_pfx_len)
        out_dst_ip6 = self.compose_ip6(self.pg0.remote_ip4, self.src_ip6_pfx,
                                       self.src_ip6_pfx_len)

        pkts = self.create_stream_in(self.pg0, self.pg1, self.dst_ip4)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_out_ip6(capture, dst_ip=out_src_ip6,
                                    nat_ip=out_dst_ip6, same_port=True)

        pkts = self.create_stream_out_ip6(self.pg1, out_src_ip6, out_dst_ip6)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(len(pkts))
        self.verify_capture_in(capture, self.pg0)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
