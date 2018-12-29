#!/usr/bin/env python

import socket
import unittest
import struct
import random

from framework import VppTestCase, VppTestRunner, running_extended_tests
from vpp_capture import CaptureInvalidPacketError
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet import IPerror, TCPerror, UDPerror, ICMPerror
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply, \
    ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, fragment6
from scapy.layers.inet6 import ICMPv6DestUnreach, IPerror6, IPv6ExtHdrFragment
from scapy.layers.l2 import Ether, ARP, GRE
from scapy.data import IP_PROTOS
from scapy.packet import bind_layers, Raw
from util import ppp
from ipfix import IPFIX, Set, Template, Data, IPFIXDecoder
from time import sleep
from util import ip4_range
from vpp_papi import mac_pton
from syslog_rfc5424_parser import SyslogMessage, ParseError
from syslog_rfc5424_parser.constants import SyslogFacility, SyslogSeverity
from vpp_papi_provider import SYSLOG_SEVERITY
from io import BytesIO


class MethodHolder(VppTestCase):
    """ NAT create capture and verify method holder """

    def clear_nat44(self):
        """
        Clear NAT44 configuration.
        """
        if hasattr(self, 'pg7') and hasattr(self, 'pg8'):
            # I found no elegant way to do this
            self.vapi.ip_add_del_route(
                dst_address=self.pg7.remote_ip4n,
                dst_address_length=32,
                next_hop_address=self.pg7.remote_ip4n,
                next_hop_sw_if_index=self.pg7.sw_if_index,
                is_add=0)
            self.vapi.ip_add_del_route(
                dst_address=self.pg8.remote_ip4n,
                dst_address_length=32,
                next_hop_address=self.pg8.remote_ip4n,
                next_hop_sw_if_index=self.pg8.sw_if_index,
                is_add=0)

            for intf in [self.pg7, self.pg8]:
                neighbors = self.vapi.ip_neighbor_dump(intf.sw_if_index)
                for n in neighbors:
                    self.vapi.ip_neighbor_add_del(intf.sw_if_index,
                                                  n.mac_address,
                                                  n.ip_address,
                                                  is_add=0)

            if self.pg7.has_ip4_config:
                self.pg7.unconfig_ip4()

        self.vapi.nat44_forwarding_enable_disable(0)

        interfaces = self.vapi.nat44_interface_addr_dump()
        for intf in interfaces:
            self.vapi.nat44_add_interface_addr(intf.sw_if_index,
                                               twice_nat=intf.twice_nat,
                                               is_add=0)

        self.vapi.nat_ipfix(enable=0, src_port=self.ipfix_src_port,
                            domain_id=self.ipfix_domain_id)
        self.ipfix_src_port = 4739
        self.ipfix_domain_id = 1

        self.vapi.syslog_set_filter(SYSLOG_SEVERITY.EMERG)

        interfaces = self.vapi.nat44_interface_dump()
        for intf in interfaces:
            if intf.is_inside > 1:
                self.vapi.nat44_interface_add_del_feature(intf.sw_if_index,
                                                          0,
                                                          is_add=0)
            self.vapi.nat44_interface_add_del_feature(intf.sw_if_index,
                                                      intf.is_inside,
                                                      is_add=0)

        interfaces = self.vapi.nat44_interface_output_feature_dump()
        for intf in interfaces:
            self.vapi.nat44_interface_add_del_output_feature(intf.sw_if_index,
                                                             intf.is_inside,
                                                             is_add=0)

        static_mappings = self.vapi.nat44_static_mapping_dump()
        for sm in static_mappings:
            self.vapi.nat44_add_del_static_mapping(
                sm.local_ip_address,
                sm.external_ip_address,
                local_port=sm.local_port,
                external_port=sm.external_port,
                addr_only=sm.addr_only,
                vrf_id=sm.vrf_id,
                protocol=sm.protocol,
                twice_nat=sm.twice_nat,
                self_twice_nat=sm.self_twice_nat,
                out2in_only=sm.out2in_only,
                tag=sm.tag,
                external_sw_if_index=sm.external_sw_if_index,
                is_add=0)

        lb_static_mappings = self.vapi.nat44_lb_static_mapping_dump()
        for lb_sm in lb_static_mappings:
            self.vapi.nat44_add_del_lb_static_mapping(
                lb_sm.external_addr,
                lb_sm.external_port,
                lb_sm.protocol,
                twice_nat=lb_sm.twice_nat,
                self_twice_nat=lb_sm.self_twice_nat,
                out2in_only=lb_sm.out2in_only,
                tag=lb_sm.tag,
                is_add=0,
                local_num=0,
                locals=[])

        identity_mappings = self.vapi.nat44_identity_mapping_dump()
        for id_m in identity_mappings:
            self.vapi.nat44_add_del_identity_mapping(
                addr_only=id_m.addr_only,
                ip=id_m.ip_address,
                port=id_m.port,
                sw_if_index=id_m.sw_if_index,
                vrf_id=id_m.vrf_id,
                protocol=id_m.protocol,
                is_add=0)

        adresses = self.vapi.nat44_address_dump()
        for addr in adresses:
            self.vapi.nat44_add_del_address_range(addr.ip_address,
                                                  addr.ip_address,
                                                  twice_nat=addr.twice_nat,
                                                  is_add=0)

        self.vapi.nat_set_reass()
        self.vapi.nat_set_reass(is_ip6=1)
        self.verify_no_nat44_user()
        self.vapi.nat_set_timeouts()
        self.vapi.nat_set_addr_and_port_alloc_alg()
        self.vapi.nat_set_mss_clamping()

    def nat44_add_static_mapping(self, local_ip, external_ip='0.0.0.0',
                                 local_port=0, external_port=0, vrf_id=0,
                                 is_add=1, external_sw_if_index=0xFFFFFFFF,
                                 proto=0, twice_nat=0, self_twice_nat=0,
                                 out2in_only=0, tag=""):
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
        :param twice_nat: 1 if translate external host address and port
        :param self_twice_nat: 1 if translate external host address and port
                               whenever external host address equals
                               local address of internal host
        :param out2in_only: if 1 rule is matching only out2in direction
        :param tag: Opaque string tag
        """
        addr_only = 1
        if local_port and external_port:
            addr_only = 0
        l_ip = socket.inet_pton(socket.AF_INET, local_ip)
        e_ip = socket.inet_pton(socket.AF_INET, external_ip)
        self.vapi.nat44_add_del_static_mapping(
            l_ip,
            e_ip,
            external_sw_if_index,
            local_port,
            external_port,
            addr_only,
            vrf_id,
            proto,
            twice_nat,
            self_twice_nat,
            out2in_only,
            tag,
            is_add)

    def nat44_add_address(self, ip, is_add=1, vrf_id=0xFFFFFFFF, twice_nat=0):
        """
        Add/delete NAT44 address

        :param ip: IP address
        :param is_add: 1 if add, 0 if delete (Default add)
        :param twice_nat: twice NAT address for extenal hosts
        """
        nat_addr = socket.inet_pton(socket.AF_INET, ip)
        self.vapi.nat44_add_del_address_range(nat_addr, nat_addr, is_add,
                                              vrf_id=vrf_id,
                                              twice_nat=twice_nat)

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
        pkts.append(p)

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
        return socket.inet_ntop(socket.AF_INET6, ''.join(pref_n))

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
        pkts.append(p)

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
                           dst_ip=None, is_ip6=False):
        """
        Verify captured packets on outside network

        :param capture: Captured packets
        :param nat_ip: Translated IP address (Default use global NAT address)
        :param same_port: Sorce port number is not translated (Default False)
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
                    if same_port:
                        self.assertEqual(packet[TCP].sport, self.tcp_port_in)
                    else:
                        self.assertNotEqual(
                            packet[TCP].sport, self.tcp_port_in)
                    self.tcp_port_out = packet[TCP].sport
                    self.assert_packet_checksums_valid(packet)
                elif packet.haslayer(UDP):
                    if same_port:
                        self.assertEqual(packet[UDP].sport, self.udp_port_in)
                    else:
                        self.assertNotEqual(
                            packet[UDP].sport, self.udp_port_in)
                    self.udp_port_out = packet[UDP].sport
                else:
                    if same_port:
                        self.assertEqual(packet[ICMP46].id, self.icmp_id_in)
                    else:
                        self.assertNotEqual(packet[ICMP46].id, self.icmp_id_in)
                    self.icmp_id_out = packet[ICMP46].id
                    self.assert_packet_checksums_valid(packet)
            except (IndexError, AssertionError):
                self.logger.error(ppp("Unexpected or invalid packet "
                                      "(outside network):", packet))
                raise CaptureInvalidPacketError

    def verify_capture_out_ip6(self, capture, nat_ip, same_port=False,
                               dst_ip=None):
        """
        Verify captured packets on outside network

        :param capture: Captured packets
        :param nat_ip: Translated IP address
        :param same_port: Sorce port number is not translated (Default False)
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
            except (IndexError, AssertionError):
                self.logger.error(ppp("Unexpected or invalid packet "
                                      "(inside network):", packet))
                raise CaptureInvalidPacketError

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
            except (IndexError, AssertionError):
                self.logger.error(ppp("Unexpected or invalid packet "
                                      "(inside network):", packet))
                raise CaptureInvalidPacketError

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
            except (IndexError, AssertionError) :
                self.logger.error(ppp("Unexpected or invalid packet "
                                      "(inside network):", packet))
                raise CaptureInvalidPacketError

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
            except (IndexError, AssertionError):
                self.logger.error(ppp("Unexpected or invalid packet "
                                      "(outside network):", packet))
                raise CaptureInvalidPacketError

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
            except (IndexError, AssertionError):
                self.logger.error(ppp("Unexpected or invalid packet "
                                      "(inside network):", packet))
                raise CaptureInvalidPacketError

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
            p = p.__class__(str(p))
            chksum = p['TCP'].chksum
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
        :returns: Fragmets
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
            raise CaptureInvalidPacketError

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
            self.assertIn(ord(record[230]), [4, 5])
            if ord(record[230]) == 4:
                nat44_ses_create_num += 1
            else:
                nat44_ses_delete_num += 1
            # sourceIPv4Address
            self.assertEqual(self.pg0.remote_ip4n, record[8])
            # postNATSourceIPv4Address
            self.assertEqual(socket.inet_pton(socket.AF_INET, self.nat_addr),
                             record[225])
            # ingressVRFID
            self.assertEqual(struct.pack("!I", 0), record[234])
            # protocolIdentifier/sourceTransportPort/postNAPTSourceTransportPort
            if IP_PROTOS.icmp == ord(record[4]):
                self.assertEqual(struct.pack("!H", self.icmp_id_in), record[7])
                self.assertEqual(struct.pack("!H", self.icmp_id_out),
                                 record[227])
            elif IP_PROTOS.tcp == ord(record[4]):
                self.assertEqual(struct.pack("!H", self.tcp_port_in),
                                 record[7])
                self.assertEqual(struct.pack("!H", self.tcp_port_out),
                                 record[227])
            elif IP_PROTOS.udp == ord(record[4]):
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
        self.assertEqual(ord(record[230]), 3)
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
        self.assertEqual(ord(record[230]), 13)
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
        self.assertEqual(ord(record[230]), 13)
        # natQuotaExceededEvent
        self.assertEqual(struct.pack("I", 2), record[466])
        # maxBIBEntries
        self.assertEqual(struct.pack("I", limit), record[472])

    def verify_ipfix_max_fragments_ip6(self, data, limit, src_addr):
        """
        Verify IPFIX maximum IPv6 fragments pending reassembly exceeded event

        :param data: Decoded IPFIX data records
        :param limit: Number of maximum fragments pending reassembly
        :param src_addr: IPv6 source address
        """
        self.assertEqual(1, len(data))
        record = data[0]
        # natEvent
        self.assertEqual(ord(record[230]), 13)
        # natQuotaExceededEvent
        self.assertEqual(struct.pack("I", 5), record[466])
        # maxFragmentsPendingReassembly
        self.assertEqual(struct.pack("I", limit), record[475])
        # sourceIPv6Address
        self.assertEqual(src_addr, record[27])

    def verify_ipfix_max_fragments_ip4(self, data, limit, src_addr):
        """
        Verify IPFIX maximum IPv4 fragments pending reassembly exceeded event

        :param data: Decoded IPFIX data records
        :param limit: Number of maximum fragments pending reassembly
        :param src_addr: IPv4 source address
        """
        self.assertEqual(1, len(data))
        record = data[0]
        # natEvent
        self.assertEqual(ord(record[230]), 13)
        # natQuotaExceededEvent
        self.assertEqual(struct.pack("I", 5), record[466])
        # maxFragmentsPendingReassembly
        self.assertEqual(struct.pack("I", limit), record[475])
        # sourceIPv4Address
        self.assertEqual(src_addr, record[8])

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
            self.assertEqual(ord(record[230]), 10)
        else:
            self.assertEqual(ord(record[230]), 11)
        # sourceIPv6Address
        self.assertEqual(src_addr, record[27])
        # postNATSourceIPv4Address
        self.assertEqual(self.nat_addr_n, record[225])
        # protocolIdentifier
        self.assertEqual(IP_PROTOS.tcp, ord(record[4]))
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
            self.assertEqual(ord(record[230]), 6)
        else:
            self.assertEqual(ord(record[230]), 7)
        # sourceIPv6Address
        self.assertEqual(src_addr, record[27])
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
        self.assertEqual(IP_PROTOS.tcp, ord(record[4]))
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
        self.assertEqual(ord(record[230]), 13)
        # natQuotaExceededEvent
        self.assertEqual(struct.pack("I", 3), record[466])
        # maxEntriesPerUser
        self.assertEqual(struct.pack("I", limit), record[473])
        # sourceIPv4Address
        self.assertEqual(src_addr, record[8])

    def verify_syslog_apmap(self, data, is_add=True):
        message = data.decode('utf-8')
        try:
            message = SyslogMessage.parse(message)
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
        except ParseError as e:
            self.logger.error(e)

    def verify_syslog_sess(self, data, is_add=True, is_ip6=False):
        message = data.decode('utf-8')
        try:
            message = SyslogMessage.parse(message)
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
        except ParseError as e:
            self.logger.error(e)

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
            raise ValueError("Unsupported protocol")

    def frag_in_order(self, proto=IP_PROTOS.tcp, dont_translate=False):
        layer = self.proto2layer(proto)

        if proto == IP_PROTOS.tcp:
            data = "A" * 4 + "B" * 16 + "C" * 3
        else:
            data = "A" * 16 + "B" * 16 + "C" * 3
        self.port_in = random.randint(1025, 65535)

        reass = self.vapi.nat_reass_dump()
        reass_n_start = len(reass)

        # in2out
        pkts = self.create_stream_frag(self.pg0,
                                       self.pg1.remote_ip4,
                                       self.port_in,
                                       20,
                                       data,
                                       proto)
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
                self.assertNotEqual(p[layer].sport, self.port_in)
            else:
                self.assertEqual(p[layer].sport, self.port_in)
        else:
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
        pkts = self.create_stream_frag(self.pg1,
                                       dst_addr,
                                       sport,
                                       dport,
                                       data,
                                       proto,
                                       echo_reply=True)
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

        reass = self.vapi.nat_reass_dump()
        reass_n_end = len(reass)

        self.assertEqual(reass_n_end - reass_n_start, 2)

    def frag_in_order_in_plus_out(self, proto=IP_PROTOS.tcp):
        layer = self.proto2layer(proto)

        if proto == IP_PROTOS.tcp:
            data = "A" * 4 + "B" * 16 + "C" * 3
        else:
            data = "A" * 16 + "B" * 16 + "C" * 3
        self.port_in = random.randint(1025, 65535)

        for i in range(2):
            reass = self.vapi.nat_reass_dump()
            reass_n_start = len(reass)

            # out2in
            pkts = self.create_stream_frag(self.pg0,
                                           self.server_out_addr,
                                           self.port_in,
                                           self.server_out_port,
                                           data,
                                           proto)
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
                pkts = self.create_stream_frag(self.pg1,
                                               self.pg0.remote_ip4,
                                               self.server_in_port,
                                               p[layer].sport,
                                               data,
                                               proto)
            else:
                pkts = self.create_stream_frag(self.pg1,
                                               self.pg0.remote_ip4,
                                               p[layer].id,
                                               0,
                                               data,
                                               proto,
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

            reass = self.vapi.nat_reass_dump()
            reass_n_end = len(reass)

            self.assertEqual(reass_n_end - reass_n_start, 2)

    def reass_hairpinning(self, proto=IP_PROTOS.tcp):
        layer = self.proto2layer(proto)

        if proto == IP_PROTOS.tcp:
            data = "A" * 4 + "B" * 16 + "C" * 3
        else:
            data = "A" * 16 + "B" * 16 + "C" * 3

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
            self.assertNotEqual(p[layer].sport, self.host_in_port)
            self.assertEqual(p[layer].dport, self.server_in_port)
        else:
            self.assertNotEqual(p[layer].id, self.host_in_port)
        self.assertEqual(data, p[Raw].load)

    def frag_out_of_order(self, proto=IP_PROTOS.tcp, dont_translate=False):
        layer = self.proto2layer(proto)

        if proto == IP_PROTOS.tcp:
            data = "A" * 4 + "B" * 16 + "C" * 3
        else:
            data = "A" * 16 + "B" * 16 + "C" * 3
        self.port_in = random.randint(1025, 65535)

        for i in range(2):
            # in2out
            pkts = self.create_stream_frag(self.pg0,
                                           self.pg1.remote_ip4,
                                           self.port_in,
                                           20,
                                           data,
                                           proto)
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
                    self.assertNotEqual(p[layer].sport, self.port_in)
                else:
                    self.assertEqual(p[layer].sport, self.port_in)
            else:
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
            pkts = self.create_stream_frag(self.pg1,
                                           dst_addr,
                                           sport,
                                           dport,
                                           data,
                                           proto,
                                           echo_reply=True)
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
            data = "A" * 4 + "B" * 16 + "C" * 3
        else:
            data = "A" * 16 + "B" * 16 + "C" * 3
        self.port_in = random.randint(1025, 65535)

        for i in range(2):
            # out2in
            pkts = self.create_stream_frag(self.pg0,
                                           self.server_out_addr,
                                           self.port_in,
                                           self.server_out_port,
                                           data,
                                           proto)
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
                pkts = self.create_stream_frag(self.pg1,
                                               self.pg0.remote_ip4,
                                               self.server_in_port,
                                               p[layer].sport,
                                               data,
                                               proto)
            else:
                pkts = self.create_stream_frag(self.pg1,
                                               self.pg0.remote_ip4,
                                               p[layer].id,
                                               0,
                                               data,
                                               proto,
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


class TestNAT44(MethodHolder):
    """ NAT44 Test Cases """

    @classmethod
    def setUpClass(cls):
        super(TestNAT44, cls).setUpClass()
        cls.vapi.cli("set log class nat level debug")

        try:
            cls.tcp_port_in = 6303
            cls.tcp_port_out = 6303
            cls.udp_port_in = 6304
            cls.udp_port_out = 6304
            cls.icmp_id_in = 6305
            cls.icmp_id_out = 6305
            cls.nat_addr = '10.0.0.3'
            cls.nat_addr_n = socket.inet_pton(socket.AF_INET, cls.nat_addr)
            cls.ipfix_src_port = 4739
            cls.ipfix_domain_id = 1
            cls.tcp_external_port = 80

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
            cls.vapi.ip_table_add_del(10, is_add=1)
            cls.vapi.ip_table_add_del(20, is_add=1)

            cls.pg4._local_ip4 = "172.16.255.1"
            cls.pg4._local_ip4n = socket.inet_pton(socket.AF_INET, i.local_ip4)
            cls.pg4._remote_hosts[0]._ip4 = "172.16.255.2"
            cls.pg4.set_table_ip4(10)
            cls.pg5._local_ip4 = "172.17.255.3"
            cls.pg5._local_ip4n = socket.inet_pton(socket.AF_INET, i.local_ip4)
            cls.pg5._remote_hosts[0]._ip4 = "172.17.255.4"
            cls.pg5.set_table_ip4(10)
            cls.pg6._local_ip4 = "172.16.255.1"
            cls.pg6._local_ip4n = socket.inet_pton(socket.AF_INET, i.local_ip4)
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
            ip_addr_n = socket.inet_pton(socket.AF_INET, "10.0.0.1")
            cls.vapi.sw_interface_add_del_address(cls.pg9.sw_if_index,
                                                  ip_addr_n,
                                                  24)
            cls.pg9.admin_up()
            cls.pg9.resolve_arp()
            cls.pg9._remote_hosts[1]._ip4 = cls.pg9._remote_hosts[0]._ip4
            cls.pg4._remote_ip4 = cls.pg9._remote_hosts[0]._ip4 = "10.0.0.2"
            cls.pg9.resolve_arp()

        except Exception:
            super(TestNAT44, cls).tearDownClass()
            raise

    def test_dynamic(self):
        """ NAT44 dynamic translation test """
        self.nat44_add_address(self.nat_addr)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)

        # in2out
        tcpn = self.statistics.get_counter(
            '/err/nat44-in2out-slowpath/TCP packets')
        udpn = self.statistics.get_counter(
            '/err/nat44-in2out-slowpath/UDP packets')
        icmpn = self.statistics.get_counter(
            '/err/nat44-in2out-slowpath/ICMP packets')
        totaln = self.statistics.get_counter(
            '/err/nat44-in2out-slowpath/good in2out packets processed')

        pkts = self.create_stream_in(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_out(capture)

        err = self.statistics.get_counter(
            '/err/nat44-in2out-slowpath/TCP packets')
        self.assertEqual(err - tcpn, 1)
        err = self.statistics.get_counter(
            '/err/nat44-in2out-slowpath/UDP packets')
        self.assertEqual(err - udpn, 1)
        err = self.statistics.get_counter(
            '/err/nat44-in2out-slowpath/ICMP packets')
        self.assertEqual(err - icmpn, 1)
        err = self.statistics.get_counter(
            '/err/nat44-in2out-slowpath/good in2out packets processed')
        self.assertEqual(err - totaln, 3)

        # out2in
        tcpn = self.statistics.get_counter('/err/nat44-out2in/TCP packets')
        udpn = self.statistics.get_counter('/err/nat44-out2in/UDP packets')
        icmpn = self.statistics.get_counter('/err/nat44-out2in/ICMP packets')
        totaln = self.statistics.get_counter(
            '/err/nat44-out2in/good out2in packets processed')

        pkts = self.create_stream_out(self.pg1)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(len(pkts))
        self.verify_capture_in(capture, self.pg0)

        err = self.statistics.get_counter('/err/nat44-out2in/TCP packets')
        self.assertEqual(err - tcpn, 1)
        err = self.statistics.get_counter('/err/nat44-out2in/UDP packets')
        self.assertEqual(err - udpn, 1)
        err = self.statistics.get_counter('/err/nat44-out2in/ICMP packets')
        self.assertEqual(err - icmpn, 1)
        err = self.statistics.get_counter(
            '/err/nat44-out2in/good out2in packets processed')
        self.assertEqual(err - totaln, 3)

        users = self.statistics.get_counter('/nat44/total-users')
        self.assertEqual(users[0][0], 1)
        sessions = self.statistics.get_counter('/nat44/total-sessions')
        self.assertEqual(sessions[0][0], 3)

    def test_dynamic_icmp_errors_in2out_ttl_1(self):
        """ NAT44 handling of client packets with TTL=1 """

        self.nat44_add_address(self.nat_addr)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)

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
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)

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
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)

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
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)

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
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet "
                                  "(outside network):", packet))
            raise CaptureInvalidPacketError

    def test_ping_internal_host_from_outside(self):
        """ Ping internal host from outside network """

        self.nat44_add_static_mapping(self.pg0.remote_ip4, self.nat_addr)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)

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

        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)
        self.vapi.nat44_forwarding_enable_disable(1)

        real_ip = self.pg0.remote_ip4n
        alias_ip = self.nat_addr_n
        self.vapi.nat44_add_del_static_mapping(local_ip=real_ip,
                                               external_ip=alias_ip)

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
            self.vapi.nat44_forwarding_enable_disable(0)
            self.vapi.nat44_add_del_static_mapping(local_ip=real_ip,
                                                   external_ip=alias_ip,
                                                   is_add=0)

    def test_static_in(self):
        """ 1:1 NAT initialized from inside network """

        nat_ip = "10.0.0.10"
        self.tcp_port_out = 6303
        self.udp_port_out = 6304
        self.icmp_id_out = 6305

        self.nat44_add_static_mapping(self.pg0.remote_ip4, nat_ip)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)
        sm = self.vapi.nat44_static_mapping_dump()
        self.assertEqual(len(sm), 1)
        self.assertEqual((sm[0].tag).split('\0', 1)[0], '')
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
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)
        sm = self.vapi.nat44_static_mapping_dump()
        self.assertEqual(len(sm), 1)
        self.assertEqual((sm[0].tag).split('\0', 1)[0], tag)

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
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)

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
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)

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
        self.vapi.nat44_interface_add_del_feature(self.pg3.sw_if_index,
                                                  is_inside=0)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg4.sw_if_index)

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
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)

        # dynamic
        pkts = self.create_stream_in(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_out(capture)

        # 1:1NAT
        self.nat44_add_static_mapping(self.pg0.remote_ip4, nat_ip)
        sessions = self.vapi.nat44_user_session_dump(self.pg0.remote_ip4n, 0)
        self.assertEqual(len(sessions), 0)
        pkts = self.create_stream_in(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_out(capture, nat_ip, True)

    def test_identity_nat(self):
        """ Identity NAT """

        self.vapi.nat44_add_del_identity_mapping(ip=self.pg0.remote_ip4n)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

        sessions = self.vapi.nat44_user_session_dump(self.pg0.remote_ip4n, 0)
        self.assertEqual(len(sessions), 0)
        self.vapi.nat44_add_del_identity_mapping(ip=self.pg0.remote_ip4n,
                                                 vrf_id=1)
        identity_mappings = self.vapi.nat44_identity_mapping_dump()
        self.assertEqual(len(identity_mappings), 2)

    def test_multiple_inside_interfaces(self):
        """ NAT44 multiple non-overlapping address space inside interfaces """

        self.nat44_add_address(self.nat_addr)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg3.sw_if_index,
                                                  is_inside=0)

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
        self.vapi.nat44_interface_add_del_feature(self.pg3.sw_if_index,
                                                  is_inside=0)
        self.vapi.nat44_interface_add_del_feature(self.pg4.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg5.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg6.sw_if_index)
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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

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
        sessions = self.vapi.nat44_user_session_dump(self.pg5.remote_ip4n, 10)
        self.assertEqual(len(sessions), 3)
        for session in sessions:
            self.assertFalse(session.is_static)
            self.assertEqual(session.inside_ip_address[0:4],
                             self.pg5.remote_ip4n)
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
                self.assertFalse(session.ext_host_valid)

        # pg4 session dump
        sessions = self.vapi.nat44_user_session_dump(self.pg4.remote_ip4n, 10)
        self.assertGreaterEqual(len(sessions), 4)
        for session in sessions:
            self.assertFalse(session.is_static)
            self.assertEqual(session.inside_ip_address[0:4],
                             self.pg4.remote_ip4n)
            self.assertEqual(session.outside_ip_address,
                             addresses[0].ip_address)

        # pg6 session dump
        sessions = self.vapi.nat44_user_session_dump(self.pg6.remote_ip4n, 20)
        self.assertGreaterEqual(len(sessions), 3)
        for session in sessions:
            self.assertTrue(session.is_static)
            self.assertEqual(session.inside_ip_address[0:4],
                             self.pg6.remote_ip4n)
            self.assertEqual(map(ord, session.outside_ip_address[0:4]),
                             map(int, static_nat_ip.split('.')))
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
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)
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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

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
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)

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
            except (IndexError, AssertionError):
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise CaptureInvalidPacketError

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
            except (IndexError, AssertionError):
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise CaptureInvalidPacketError

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
            except (IndexError, AssertionError):
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise CaptureInvalidPacketError

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
            except (IndexError, AssertionError):
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise CaptureInvalidPacketError

    def test_max_translations_per_user(self):
        """ MAX translations per user - recycle the least recently used """

        self.nat44_add_address(self.nat_addr)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)

        # get maximum number of translations per user
        nat44_config = self.vapi.nat_show_config()

        # send more than maximum number of translations per user packets
        pkts_num = nat44_config.max_translations_per_user + 5
        pkts = []
        for port in range(0, pkts_num):
            p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                 IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
                 TCP(sport=1025 + port))
            pkts.append(p)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # verify number of translated packet
        self.pg1.get_capture(pkts_num)

        users = self.vapi.nat44_user_dump()
        for user in users:
            if user.ip_address == self.pg0.remote_ip4n:
                self.assertEqual(user.nsessions,
                                 nat44_config.max_translations_per_user)
                self.assertEqual(user.nstaticsessions, 0)

        tcp_port = 22
        self.nat44_add_static_mapping(self.pg0.remote_ip4, self.nat_addr,
                                      tcp_port, tcp_port,
                                      proto=IP_PROTOS.tcp)
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=tcp_port))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.get_capture(1)
        users = self.vapi.nat44_user_dump()
        for user in users:
            if user.ip_address == self.pg0.remote_ip4n:
                self.assertEqual(user.nsessions,
                                 nat44_config.max_translations_per_user - 1)
                self.assertEqual(user.nstaticsessions, 1)

    def test_interface_addr(self):
        """ Acquire NAT44 addresses from interface """
        self.vapi.nat44_add_interface_addr(self.pg7.sw_if_index)

        # no address in NAT pool
        adresses = self.vapi.nat44_address_dump()
        self.assertEqual(0, len(adresses))

        # configure interface address and check NAT address pool
        self.pg7.config_ip4()
        adresses = self.vapi.nat44_address_dump()
        self.assertEqual(1, len(adresses))
        self.assertEqual(adresses[0].ip_address[0:4], self.pg7.local_ip4n)

        # remove interface address and check NAT address pool
        self.pg7.unconfig_ip4()
        adresses = self.vapi.nat44_address_dump()
        self.assertEqual(0, len(adresses))

    def test_interface_addr_static_mapping(self):
        """ Static mapping with addresses from interface """
        tag = "testTAG"

        self.vapi.nat44_add_interface_addr(self.pg7.sw_if_index)
        self.nat44_add_static_mapping(
            '1.2.3.4',
            external_sw_if_index=self.pg7.sw_if_index,
            tag=tag)

        # static mappings with external interface
        static_mappings = self.vapi.nat44_static_mapping_dump()
        self.assertEqual(1, len(static_mappings))
        self.assertEqual(self.pg7.sw_if_index,
                         static_mappings[0].external_sw_if_index)
        self.assertEqual((static_mappings[0].tag).split('\0', 1)[0], tag)

        # configure interface address and check static mappings
        self.pg7.config_ip4()
        static_mappings = self.vapi.nat44_static_mapping_dump()
        self.assertEqual(2, len(static_mappings))
        resolved = False
        for sm in static_mappings:
            if sm.external_sw_if_index == 0xFFFFFFFF:
                self.assertEqual(sm.external_ip_address[0:4],
                                 self.pg7.local_ip4n)
                self.assertEqual((sm.tag).split('\0', 1)[0], tag)
                resolved = True
        self.assertTrue(resolved)

        # remove interface address and check static mappings
        self.pg7.unconfig_ip4()
        static_mappings = self.vapi.nat44_static_mapping_dump()
        self.assertEqual(1, len(static_mappings))
        self.assertEqual(self.pg7.sw_if_index,
                         static_mappings[0].external_sw_if_index)
        self.assertEqual((static_mappings[0].tag).split('\0', 1)[0], tag)

        # configure interface address again and check static mappings
        self.pg7.config_ip4()
        static_mappings = self.vapi.nat44_static_mapping_dump()
        self.assertEqual(2, len(static_mappings))
        resolved = False
        for sm in static_mappings:
            if sm.external_sw_if_index == 0xFFFFFFFF:
                self.assertEqual(sm.external_ip_address[0:4],
                                 self.pg7.local_ip4n)
                self.assertEqual((sm.tag).split('\0', 1)[0], tag)
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
        self.vapi.nat44_add_interface_addr(self.pg7.sw_if_index)
        self.vapi.nat44_add_del_identity_mapping(
            sw_if_index=self.pg7.sw_if_index,
            port=port,
            protocol=IP_PROTOS.tcp,
            addr_only=0)

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
                self.assertEqual(identity_mappings[0].ip_address,
                                 self.pg7.local_ip4n)
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
        """ IPFIX logging NAT44 session created/delted """
        self.ipfix_domain_id = 10
        self.ipfix_src_port = 20202
        colector_port = 30303
        bind_layers(UDP, IPFIX, dport=30303)
        self.nat44_add_address(self.nat_addr)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)
        self.vapi.set_ipfix_exporter(collector_address=self.pg3.remote_ip4n,
                                     src_address=self.pg3.local_ip4n,
                                     path_mtu=512,
                                     template_interval=10,
                                     collector_port=colector_port)
        self.vapi.nat_ipfix(domain_id=self.ipfix_domain_id,
                            src_port=self.ipfix_src_port)

        pkts = self.create_stream_in(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_out(capture)
        self.nat44_add_address(self.nat_addr, is_add=0)
        self.vapi.cli("ipfix flush")  # FIXME this should be an API call
        capture = self.pg3.get_capture(9)
        ipfix = IPFIXDecoder()
        # first load template
        for p in capture:
            self.assertTrue(p.haslayer(IPFIX))
            self.assertEqual(p[IP].src, self.pg3.local_ip4)
            self.assertEqual(p[IP].dst, self.pg3.remote_ip4)
            self.assertEqual(p[UDP].sport, self.ipfix_src_port)
            self.assertEqual(p[UDP].dport, colector_port)
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
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)
        self.vapi.set_ipfix_exporter(collector_address=self.pg3.remote_ip4n,
                                     src_address=self.pg3.local_ip4n,
                                     path_mtu=512,
                                     template_interval=10)
        self.vapi.nat_ipfix(domain_id=self.ipfix_domain_id,
                            src_port=self.ipfix_src_port)

        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=3025))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.assert_nothing_captured()
        sleep(1)
        self.vapi.cli("ipfix flush")  # FIXME this should be an API call
        capture = self.pg3.get_capture(9)
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

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_ipfix_max_sessions(self):
        """ IPFIX logging maximum session entries exceeded """
        self.nat44_add_address(self.nat_addr)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)

        nat44_config = self.vapi.nat_show_config()
        max_sessions = 10 * nat44_config.translation_buckets

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
        self.vapi.set_ipfix_exporter(collector_address=self.pg3.remote_ip4n,
                                     src_address=self.pg3.local_ip4n,
                                     path_mtu=512,
                                     template_interval=10)
        self.vapi.nat_ipfix(domain_id=self.ipfix_domain_id,
                            src_port=self.ipfix_src_port)

        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=1025))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.assert_nothing_captured()
        sleep(1)
        self.vapi.cli("ipfix flush")  # FIXME this should be an API call
        capture = self.pg3.get_capture(9)
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
        self.vapi.syslog_set_filter(SYSLOG_SEVERITY.INFO)
        self.vapi.syslog_set_sender(self.pg3.remote_ip4n, self.pg3.local_ip4n)
        self.nat44_add_address(self.nat_addr)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)

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
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)
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
        self.vapi.ip_table_add_del(vrf_id1, is_add=1)
        self.vapi.ip_table_add_del(vrf_id2, is_add=1)
        self.pg0.set_table_ip4(vrf_id1)
        self.pg1.set_table_ip4(vrf_id2)
        self.pg0.config_ip4()
        self.pg1.config_ip4()
        self.pg0.resolve_arp()
        self.pg1.resolve_arp()

        self.nat44_add_address(nat_ip1, vrf_id=vrf_id1)
        self.nat44_add_address(nat_ip2, vrf_id=vrf_id2)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg2.sw_if_index,
                                                  is_inside=0)

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
            self.vapi.ip_table_add_del(vrf_id1, is_add=0)
            self.vapi.ip_table_add_del(vrf_id2, is_add=0)

    def test_vrf_feature_independent(self):
        """ NAT44 tenant VRF independent address pool mode """

        nat_ip1 = "10.0.0.10"
        nat_ip2 = "10.0.0.11"

        self.nat44_add_address(nat_ip1)
        self.nat44_add_address(nat_ip2, vrf_id=99)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg2.sw_if_index,
                                                  is_inside=0)

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

    def test_dynamic_ipless_interfaces(self):
        """ NAT44 interfaces without configured IP address """

        self.vapi.ip_neighbor_add_del(self.pg7.sw_if_index,
                                      mac_pton(self.pg7.remote_mac),
                                      self.pg7.remote_ip4n,
                                      is_static=1)
        self.vapi.ip_neighbor_add_del(self.pg8.sw_if_index,
                                      mac_pton(self.pg8.remote_mac),
                                      self.pg8.remote_ip4n,
                                      is_static=1)

        self.vapi.ip_add_del_route(dst_address=self.pg7.remote_ip4n,
                                   dst_address_length=32,
                                   next_hop_address=self.pg7.remote_ip4n,
                                   next_hop_sw_if_index=self.pg7.sw_if_index)
        self.vapi.ip_add_del_route(dst_address=self.pg8.remote_ip4n,
                                   dst_address_length=32,
                                   next_hop_address=self.pg8.remote_ip4n,
                                   next_hop_sw_if_index=self.pg8.sw_if_index)

        self.nat44_add_address(self.nat_addr)
        self.vapi.nat44_interface_add_del_feature(self.pg7.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg8.sw_if_index,
                                                  is_inside=0)

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

        self.vapi.ip_neighbor_add_del(self.pg7.sw_if_index,
                                      mac_pton(self.pg7.remote_mac),
                                      self.pg7.remote_ip4n,
                                      is_static=1)
        self.vapi.ip_neighbor_add_del(self.pg8.sw_if_index,
                                      mac_pton(self.pg8.remote_mac),
                                      self.pg8.remote_ip4n,
                                      is_static=1)

        self.vapi.ip_add_del_route(dst_address=self.pg7.remote_ip4n,
                                   dst_address_length=32,
                                   next_hop_address=self.pg7.remote_ip4n,
                                   next_hop_sw_if_index=self.pg7.sw_if_index)
        self.vapi.ip_add_del_route(dst_address=self.pg8.remote_ip4n,
                                   dst_address_length=32,
                                   next_hop_address=self.pg8.remote_ip4n,
                                   next_hop_sw_if_index=self.pg8.sw_if_index)

        self.nat44_add_static_mapping(self.pg7.remote_ip4, self.nat_addr)
        self.vapi.nat44_interface_add_del_feature(self.pg7.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg8.sw_if_index,
                                                  is_inside=0)

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

        self.vapi.ip_neighbor_add_del(self.pg7.sw_if_index,
                                      mac_pton(self.pg7.remote_mac),
                                      self.pg7.remote_ip4n,
                                      is_static=1)
        self.vapi.ip_neighbor_add_del(self.pg8.sw_if_index,
                                      mac_pton(self.pg8.remote_mac),
                                      self.pg8.remote_ip4n,
                                      is_static=1)

        self.vapi.ip_add_del_route(dst_address=self.pg7.remote_ip4n,
                                   dst_address_length=32,
                                   next_hop_address=self.pg7.remote_ip4n,
                                   next_hop_sw_if_index=self.pg7.sw_if_index)
        self.vapi.ip_add_del_route(dst_address=self.pg8.remote_ip4n,
                                   dst_address_length=32,
                                   next_hop_address=self.pg8.remote_ip4n,
                                   next_hop_sw_if_index=self.pg8.sw_if_index)

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
        self.vapi.nat44_interface_add_del_feature(self.pg7.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg8.sw_if_index,
                                                  is_inside=0)

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
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", packet))
            raise CaptureInvalidPacketError

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", packet))
            raise CaptureInvalidPacketError

    def test_hairpinning_static_unknown_proto(self):
        """ 1:1 NAT translate packet with unknown protocol - hairpinning """

        host = self.pg0.remote_hosts[0]
        server = self.pg0.remote_hosts[1]

        host_nat_ip = "10.0.0.10"
        server_nat_ip = "10.0.0.11"

        self.nat44_add_static_mapping(host.ip4, host_nat_ip)
        self.nat44_add_static_mapping(server.ip4, server_nat_ip)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", packet))
            raise CaptureInvalidPacketError

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", packet))
            raise CaptureInvalidPacketError

    def test_output_feature(self):
        """ NAT44 interface output feature (in2out postrouting) """
        self.nat44_add_address(self.nat_addr)
        self.vapi.nat44_interface_add_del_output_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_output_feature(self.pg1.sw_if_index)
        self.vapi.nat44_interface_add_del_output_feature(self.pg3.sw_if_index,
                                                         is_inside=0)

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

        self.vapi.ip_add_del_route(dst_address=self.pg3.remote_ip4n,
                                   dst_address_length=32,
                                   next_hop_address=self.pg3.remote_ip4n,
                                   next_hop_sw_if_index=self.pg3.sw_if_index,
                                   table_id=10)
        self.vapi.ip_add_del_route(dst_address=self.pg3.remote_ip4n,
                                   dst_address_length=32,
                                   next_hop_address=self.pg3.remote_ip4n,
                                   next_hop_sw_if_index=self.pg3.sw_if_index,
                                   table_id=20)

        self.nat44_add_address(nat_ip_vrf10, vrf_id=10)
        self.nat44_add_address(nat_ip_vrf20, vrf_id=20)
        self.vapi.nat44_interface_add_del_output_feature(self.pg4.sw_if_index)
        self.vapi.nat44_interface_add_del_output_feature(self.pg6.sw_if_index)
        self.vapi.nat44_interface_add_del_output_feature(self.pg3.sw_if_index,
                                                         is_inside=0)

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
        self.vapi.nat44_interface_add_del_output_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_output_feature(self.pg1.sw_if_index,
                                                         is_inside=0)

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

    def test_one_armed_nat44(self):
        """ One armed NAT44 """
        remote_host = self.pg9.remote_hosts[0]
        local_host = self.pg9.remote_hosts[1]
        external_port = 0

        self.nat44_add_address(self.nat_addr)
        self.vapi.nat44_interface_add_del_feature(self.pg9.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg9.sw_if_index,
                                                  is_inside=0)

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

        err = self.statistics.get_counter('/err/nat44-classify/next in2out')
        self.assertEqual(err, 1)
        err = self.statistics.get_counter('/err/nat44-classify/next out2in')
        self.assertEqual(err, 1)

    def test_del_session(self):
        """ Delete NAT44 session """
        self.nat44_add_address(self.nat_addr)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)

        pkts = self.create_stream_in(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.get_capture(len(pkts))

        sessions = self.vapi.nat44_user_session_dump(self.pg0.remote_ip4n, 0)
        nsessions = len(sessions)

        self.vapi.nat44_del_session(sessions[0].inside_ip_address,
                                    sessions[0].inside_port,
                                    sessions[0].protocol)
        self.vapi.nat44_del_session(sessions[1].outside_ip_address,
                                    sessions[1].outside_port,
                                    sessions[1].protocol,
                                    is_in=0)

        sessions = self.vapi.nat44_user_session_dump(self.pg0.remote_ip4n, 0)
        self.assertEqual(nsessions - len(sessions), 2)

        self.vapi.nat44_del_session(sessions[0].inside_ip_address,
                                    sessions[0].inside_port,
                                    sessions[0].protocol)

        self.verify_no_nat44_user()

    def test_set_get_reass(self):
        """ NAT44 set/get virtual fragmentation reassembly """
        reas_cfg1 = self.vapi.nat_get_reass()

        self.vapi.nat_set_reass(timeout=reas_cfg1.ip4_timeout + 5,
                                max_reass=reas_cfg1.ip4_max_reass * 2,
                                max_frag=reas_cfg1.ip4_max_frag * 2)

        reas_cfg2 = self.vapi.nat_get_reass()

        self.assertEqual(reas_cfg1.ip4_timeout + 5, reas_cfg2.ip4_timeout)
        self.assertEqual(reas_cfg1.ip4_max_reass * 2, reas_cfg2.ip4_max_reass)
        self.assertEqual(reas_cfg1.ip4_max_frag * 2, reas_cfg2.ip4_max_frag)

        self.vapi.nat_set_reass(drop_frag=1)
        self.assertTrue(self.vapi.nat_get_reass().ip4_drop_frag)

    def test_frag_in_order(self):
        """ NAT44 translate fragments arriving in order """

        self.nat44_add_address(self.nat_addr)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)

        self.frag_in_order(proto=IP_PROTOS.tcp)
        self.frag_in_order(proto=IP_PROTOS.udp)
        self.frag_in_order(proto=IP_PROTOS.icmp)

    def test_frag_forwarding(self):
        """ NAT44 forwarding fragment test """
        self.vapi.nat44_add_interface_addr(self.pg1.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)
        self.vapi.nat44_forwarding_enable_disable(1)

        data = "A" * 16 + "B" * 16 + "C" * 3
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
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)
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
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)

        self.frag_out_of_order(proto=IP_PROTOS.tcp)
        self.frag_out_of_order(proto=IP_PROTOS.udp)
        self.frag_out_of_order(proto=IP_PROTOS.icmp)

    def test_port_restricted(self):
        """ Port restricted NAT44 (MAP-E CE) """
        self.nat44_add_address(self.nat_addr)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)
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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

    def test_port_range(self):
        """ External address port range """
        self.nat44_add_address(self.nat_addr)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)
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

    def test_ipfix_max_frags(self):
        """ IPFIX logging maximum fragments pending reassembly exceeded """
        self.nat44_add_address(self.nat_addr)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)
        self.vapi.nat_set_reass(max_frag=1)
        self.vapi.set_ipfix_exporter(collector_address=self.pg3.remote_ip4n,
                                     src_address=self.pg3.local_ip4n,
                                     path_mtu=512,
                                     template_interval=10)
        self.vapi.nat_ipfix(domain_id=self.ipfix_domain_id,
                            src_port=self.ipfix_src_port)

        data = "A" * 4 + "B" * 16 + "C" * 3
        self.tcp_port_in = random.randint(1025, 65535)
        pkts = self.create_stream_frag(self.pg0,
                                       self.pg1.remote_ip4,
                                       self.tcp_port_in,
                                       20,
                                       data)
        pkts.reverse()
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.assert_nothing_captured()
        sleep(1)
        self.vapi.cli("ipfix flush")  # FIXME this should be an API call
        capture = self.pg3.get_capture(9)
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
                self.verify_ipfix_max_fragments_ip4(data, 1,
                                                    self.pg0.remote_ip4n)

    def test_multiple_outside_vrf(self):
        """ Multiple outside VRF """
        vrf_id1 = 1
        vrf_id2 = 2

        self.pg1.unconfig_ip4()
        self.pg2.unconfig_ip4()
        self.vapi.ip_table_add_del(vrf_id1, is_add=1)
        self.vapi.ip_table_add_del(vrf_id2, is_add=1)
        self.pg1.set_table_ip4(vrf_id1)
        self.pg2.set_table_ip4(vrf_id2)
        self.pg1.config_ip4()
        self.pg2.config_ip4()
        self.pg1.resolve_arp()
        self.pg2.resolve_arp()

        self.nat44_add_address(self.nat_addr)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)
        self.vapi.nat44_interface_add_del_feature(self.pg2.sw_if_index,
                                                  is_inside=0)

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
            self.pg1.unconfig_ip4()
            self.pg2.unconfig_ip4()
            self.pg1.set_table_ip4(0)
            self.pg2.set_table_ip4(0)
            self.pg1.config_ip4()
            self.pg2.config_ip4()
            self.pg1.resolve_arp()
            self.pg2.resolve_arp()

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_session_timeout(self):
        """ NAT44 session timeouts """
        self.nat44_add_address(self.nat_addr)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)
        self.vapi.nat_set_timeouts(udp=5)

        max_sessions = 1000
        pkts = []
        for i in range(0, max_sessions):
            src = "10.10.%u.%u" % ((i & 0xFF00) >> 8, i & 0xFF)
            p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                 IP(src=src, dst=self.pg1.remote_ip4) /
                 UDP(sport=1025, dport=53))
            pkts.append(p)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.get_capture(max_sessions)

        sleep(6)

        pkts = []
        for i in range(0, max_sessions):
            src = "10.10.%u.%u" % ((i & 0xFF00) >> 8, i & 0xFF)
            p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                 IP(src=src, dst=self.pg1.remote_ip4) /
                 UDP(sport=1026, dport=53))
            pkts.append(p)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.get_capture(max_sessions)

        nsessions = 0
        users = self.vapi.nat44_user_dump()
        for user in users:
            nsessions = nsessions + user.nsessions
        self.assertLess(nsessions, 2 * max_sessions)

    def test_mss_clamping(self):
        """ TCP MSS clamping """
        self.nat44_add_address(self.nat_addr)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)

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

        self.vapi.nat_set_mss_clamping(enable=0)
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

    def tearDown(self):
        super(TestNAT44, self).tearDown()
        if not self.vpp_dead:
            self.logger.info(self.vapi.cli("show nat44 addresses"))
            self.logger.info(self.vapi.cli("show nat44 interfaces"))
            self.logger.info(self.vapi.cli("show nat44 static mappings"))
            self.logger.info(self.vapi.cli("show nat44 interface address"))
            self.logger.info(self.vapi.cli("show nat44 sessions detail"))
            self.logger.info(self.vapi.cli("show nat virtual-reassembly"))
            self.logger.info(self.vapi.cli("show nat44 hash tables detail"))
            self.logger.info(self.vapi.cli("show nat timeouts"))
            self.logger.info(
                self.vapi.cli("show nat addr-port-assignment-alg"))
            self.clear_nat44()
            self.vapi.cli("clear logging")


class TestNAT44EndpointDependent(MethodHolder):
    """ Endpoint-Dependent mapping and filtering test cases """

    @classmethod
    def setUpConstants(cls):
        super(TestNAT44EndpointDependent, cls).setUpConstants()
        cls.vpp_cmdline.extend(["nat", "{", "endpoint-dependent", "}"])

    @classmethod
    def setUpClass(cls):
        super(TestNAT44EndpointDependent, cls).setUpClass()
        cls.vapi.cli("set log class nat level debug")
        try:
            cls.tcp_port_in = 6303
            cls.tcp_port_out = 6303
            cls.udp_port_in = 6304
            cls.udp_port_out = 6304
            cls.icmp_id_in = 6305
            cls.icmp_id_out = 6305
            cls.nat_addr = '10.0.0.3'
            cls.nat_addr_n = socket.inet_pton(socket.AF_INET, cls.nat_addr)
            cls.ipfix_src_port = 4739
            cls.ipfix_domain_id = 1
            cls.tcp_external_port = 80

            cls.create_pg_interfaces(range(7))
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
            ip_addr_n = socket.inet_pton(socket.AF_INET, "10.0.0.1")
            cls.vapi.sw_interface_add_del_address(cls.pg4.sw_if_index,
                                                  ip_addr_n,
                                                  24)
            cls.pg4.admin_up()
            cls.pg4.resolve_arp()
            cls.pg4._remote_hosts[1]._ip4 = cls.pg4._remote_hosts[0]._ip4
            cls.pg4.resolve_arp()

            zero_ip4n = socket.inet_pton(socket.AF_INET, "0.0.0.0")
            cls.vapi.ip_table_add_del(1, is_add=1)

            cls.pg5._local_ip4 = "10.1.1.1"
            cls.pg5._local_ip4n = socket.inet_pton(socket.AF_INET,
                                                   cls.pg5.local_ip4)
            cls.pg5._remote_hosts[0]._ip4 = "10.1.1.2"
            cls.pg5._remote_hosts[0]._ip4n = socket.inet_pton(
                socket.AF_INET, cls.pg5.remote_ip4)
            cls.pg5.set_table_ip4(1)
            cls.pg5.config_ip4()
            cls.pg5.admin_up()
            cls.vapi.ip_add_del_route(dst_address=cls.pg5.remote_ip4n,
                                      dst_address_length=32,
                                      table_id=1,
                                      next_hop_sw_if_index=cls.pg5.sw_if_index,
                                      next_hop_address=zero_ip4n)

            cls.pg6._local_ip4 = "10.1.2.1"
            cls.pg6._local_ip4n = socket.inet_pton(socket.AF_INET,
                                                   cls.pg6.local_ip4)
            cls.pg6._remote_hosts[0]._ip4 = "10.1.2.2"
            cls.pg6._remote_hosts[0]._ip4n = socket.inet_pton(
                socket.AF_INET, cls.pg6.remote_ip4)
            cls.pg6.set_table_ip4(1)
            cls.pg6.config_ip4()
            cls.pg6.admin_up()
            cls.vapi.ip_add_del_route(dst_address=cls.pg6.remote_ip4n,
                                      dst_address_length=32,
                                      table_id=1,
                                      next_hop_sw_if_index=cls.pg6.sw_if_index,
                                      next_hop_address=zero_ip4n)

            cls.vapi.ip_add_del_route(dst_address=cls.pg6.remote_ip4n,
                                      dst_address_length=16,
                                      next_hop_address=zero_ip4n,
                                      table_id=0,
                                      next_hop_table_id=1)
            cls.vapi.ip_add_del_route(dst_address=zero_ip4n,
                                      dst_address_length=0,
                                      next_hop_address=zero_ip4n,
                                      table_id=1,
                                      next_hop_table_id=0)
            cls.vapi.ip_add_del_route(dst_address=zero_ip4n,
                                      dst_address_length=0,
                                      table_id=0,
                                      next_hop_sw_if_index=cls.pg1.sw_if_index,
                                      next_hop_address=cls.pg1.local_ip4n)

            cls.pg5.resolve_arp()
            cls.pg6.resolve_arp()

        except Exception:
            super(TestNAT44EndpointDependent, cls).tearDownClass()
            raise

    def test_frag_in_order(self):
        """ NAT44 translate fragments arriving in order """
        self.nat44_add_address(self.nat_addr)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)
        self.frag_in_order(proto=IP_PROTOS.tcp)
        self.frag_in_order(proto=IP_PROTOS.udp)
        self.frag_in_order(proto=IP_PROTOS.icmp)

    def test_frag_in_order_dont_translate(self):
        """ NAT44 don't translate fragments arriving in order """
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)
        self.vapi.nat44_forwarding_enable_disable(enable=True)
        self.frag_in_order(proto=IP_PROTOS.tcp, dont_translate=True)

    def test_frag_out_of_order(self):
        """ NAT44 translate fragments arriving out of order """
        self.nat44_add_address(self.nat_addr)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)
        self.frag_out_of_order(proto=IP_PROTOS.tcp)
        self.frag_out_of_order(proto=IP_PROTOS.udp)
        self.frag_out_of_order(proto=IP_PROTOS.icmp)

    def test_frag_out_of_order_dont_translate(self):
        """ NAT44 don't translate fragments arriving out of order """
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)
        self.vapi.nat44_forwarding_enable_disable(enable=True)
        self.frag_out_of_order(proto=IP_PROTOS.tcp, dont_translate=True)

    def test_frag_in_order_in_plus_out(self):
        """ in+out interface fragments in order """
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index,
                                                  is_inside=0)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)

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

        self.vapi.nat_set_reass(timeout=10)

        self.frag_in_order_in_plus_out(proto=IP_PROTOS.tcp)
        self.frag_in_order_in_plus_out(proto=IP_PROTOS.udp)
        self.frag_in_order_in_plus_out(proto=IP_PROTOS.icmp)

    def test_frag_out_of_order_in_plus_out(self):
        """ in+out interface fragments out of order """
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index,
                                                  is_inside=0)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)

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

        self.vapi.nat_set_reass(timeout=10)

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
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)
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

    def test_dynamic(self):
        """ NAT44 dynamic translation test """

        self.nat44_add_address(self.nat_addr)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)

        nat_config = self.vapi.nat_show_config()
        self.assertEqual(1, nat_config.endpoint_dependent)

        # in2out
        tcpn = self.statistics.get_counter(
            '/err/nat44-ed-in2out-slowpath/TCP packets')
        udpn = self.statistics.get_counter(
            '/err/nat44-ed-in2out-slowpath/UDP packets')
        icmpn = self.statistics.get_counter(
            '/err/nat44-ed-in2out-slowpath/ICMP packets')
        totaln = self.statistics.get_counter(
            '/err/nat44-ed-in2out-slowpath/good in2out packets processed')

        pkts = self.create_stream_in(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_out(capture)

        err = self.statistics.get_counter(
            '/err/nat44-ed-in2out-slowpath/TCP packets')
        self.assertEqual(err - tcpn, 1)
        err = self.statistics.get_counter(
            '/err/nat44-ed-in2out-slowpath/UDP packets')
        self.assertEqual(err - udpn, 1)
        err = self.statistics.get_counter(
            '/err/nat44-ed-in2out-slowpath/ICMP packets')
        self.assertEqual(err - icmpn, 1)
        err = self.statistics.get_counter(
            '/err/nat44-ed-in2out-slowpath/good in2out packets processed')
        self.assertEqual(err - totaln, 3)

        # out2in
        tcpn = self.statistics.get_counter('/err/nat44-ed-out2in/TCP packets')
        udpn = self.statistics.get_counter('/err/nat44-ed-out2in/UDP packets')
        icmpn = self.statistics.get_counter(
            '/err/nat44-ed-out2in-slowpath/ICMP packets')
        totaln = self.statistics.get_counter(
            '/err/nat44-ed-out2in/good out2in packets processed')

        pkts = self.create_stream_out(self.pg1)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(len(pkts))
        self.verify_capture_in(capture, self.pg0)

        err = self.statistics.get_counter('/err/nat44-ed-out2in/TCP packets')
        self.assertEqual(err - tcpn, 1)
        err = self.statistics.get_counter('/err/nat44-ed-out2in/UDP packets')
        self.assertEqual(err - udpn, 1)
        err = self.statistics.get_counter(
            '/err/nat44-ed-out2in-slowpath/ICMP packets')
        self.assertEqual(err - icmpn, 1)
        err = self.statistics.get_counter(
            '/err/nat44-ed-out2in/good out2in packets processed')
        self.assertEqual(err - totaln, 2)

        users = self.statistics.get_counter('/nat44/total-users')
        self.assertEqual(users[0][0], 1)
        sessions = self.statistics.get_counter('/nat44/total-sessions')
        self.assertEqual(sessions[0][0], 3)

    def test_forwarding(self):
        """ NAT44 forwarding test """

        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)
        self.vapi.nat44_forwarding_enable_disable(1)

        real_ip = self.pg0.remote_ip4n
        alias_ip = self.nat_addr_n
        self.vapi.nat44_add_del_static_mapping(local_ip=real_ip,
                                               external_ip=alias_ip)

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
            sessions = self.vapi.nat44_user_session_dump(user.ip4n, 0)
            self.assertEqual(len(sessions), 3)
            self.assertTrue(sessions[0].ext_host_valid)
            self.vapi.nat44_del_session(
                sessions[0].inside_ip_address,
                sessions[0].inside_port,
                sessions[0].protocol,
                ext_host_address=sessions[0].ext_host_address,
                ext_host_port=sessions[0].ext_host_port)
            sessions = self.vapi.nat44_user_session_dump(user.ip4n, 0)
            self.assertEqual(len(sessions), 2)

        finally:
            self.vapi.nat44_forwarding_enable_disable(0)
            self.vapi.nat44_add_del_static_mapping(local_ip=real_ip,
                                                   external_ip=alias_ip,
                                                   is_add=0)

    def test_static_lb(self):
        """ NAT44 local service load balancing """
        external_addr_n = socket.inet_pton(socket.AF_INET, self.nat_addr)
        external_port = 80
        local_port = 8080
        server1 = self.pg0.remote_hosts[0]
        server2 = self.pg0.remote_hosts[1]

        locals = [{'addr': server1.ip4n,
                   'port': local_port,
                   'probability': 70,
                   'vrf_id': 0},
                  {'addr': server2.ip4n,
                   'port': local_port,
                   'probability': 30,
                   'vrf_id': 0}]

        self.nat44_add_address(self.nat_addr)
        self.vapi.nat44_add_del_lb_static_mapping(external_addr_n,
                                                  external_port,
                                                  IP_PROTOS.tcp,
                                                  local_num=len(locals),
                                                  locals=locals)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

        sessions = self.vapi.nat44_user_session_dump(server.ip4n, 0)
        self.assertEqual(len(sessions), 1)
        self.assertTrue(sessions[0].ext_host_valid)
        self.vapi.nat44_del_session(
            sessions[0].inside_ip_address,
            sessions[0].inside_port,
            sessions[0].protocol,
            ext_host_address=sessions[0].ext_host_address,
            ext_host_port=sessions[0].ext_host_port)
        sessions = self.vapi.nat44_user_session_dump(server.ip4n, 0)
        self.assertEqual(len(sessions), 0)

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_static_lb_multi_clients(self):
        """ NAT44 local service load balancing - multiple clients"""

        external_addr_n = socket.inet_pton(socket.AF_INET, self.nat_addr)
        external_port = 80
        local_port = 8080
        server1 = self.pg0.remote_hosts[0]
        server2 = self.pg0.remote_hosts[1]
        server3 = self.pg0.remote_hosts[2]

        locals = [{'addr': server1.ip4n,
                   'port': local_port,
                   'probability': 90,
                   'vrf_id': 0},
                  {'addr': server2.ip4n,
                   'port': local_port,
                   'probability': 10,
                   'vrf_id': 0}]

        self.nat44_add_address(self.nat_addr)
        self.vapi.nat44_add_del_lb_static_mapping(external_addr_n,
                                                  external_port,
                                                  IP_PROTOS.tcp,
                                                  local_num=len(locals),
                                                  locals=locals)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)

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

        # add new back-end
        self.vapi.nat44_lb_static_mapping_add_del_local(external_addr_n,
                                                        external_port,
                                                        server3.ip4n,
                                                        local_port,
                                                        IP_PROTOS.tcp,
                                                        20)
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

        # remove one back-end
        self.vapi.nat44_lb_static_mapping_add_del_local(external_addr_n,
                                                        external_port,
                                                        server2.ip4n,
                                                        local_port,
                                                        IP_PROTOS.tcp,
                                                        10,
                                                        is_add=0)
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
        external_addr_n = socket.inet_pton(socket.AF_INET, self.nat_addr)
        external_port = 80
        local_port = 8080
        server1 = self.pg0.remote_hosts[0]
        server2 = self.pg0.remote_hosts[1]

        locals = [{'addr': server1.ip4n,
                   'port': local_port,
                   'probability': 70,
                   'vrf_id': 0},
                  {'addr': server2.ip4n,
                   'port': local_port,
                   'probability': 30,
                   'vrf_id': 0}]

        self.vapi.nat44_forwarding_enable_disable(1)
        self.vapi.nat44_add_del_lb_static_mapping(external_addr_n,
                                                  external_port,
                                                  IP_PROTOS.tcp,
                                                  out2in_only=1,
                                                  local_num=len(locals),
                                                  locals=locals)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

    def test_lb_affinity(self):
        """ NAT44 local service load balancing affinity """
        external_addr_n = socket.inet_pton(socket.AF_INET, self.nat_addr)
        external_port = 80
        local_port = 8080
        server1 = self.pg0.remote_hosts[0]
        server2 = self.pg0.remote_hosts[1]

        locals = [{'addr': server1.ip4n,
                   'port': local_port,
                   'probability': 50,
                   'vrf_id': 0},
                  {'addr': server2.ip4n,
                   'port': local_port,
                   'probability': 50,
                   'vrf_id': 0}]

        self.nat44_add_address(self.nat_addr)
        self.vapi.nat44_add_del_lb_static_mapping(external_addr_n,
                                                  external_port,
                                                  IP_PROTOS.tcp,
                                                  affinity=10800,
                                                  local_num=len(locals),
                                                  locals=locals)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)

        p = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
             IP(src=self.pg1.remote_ip4, dst=self.nat_addr) /
             TCP(sport=1025, dport=external_port))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(1)
        backend = capture[0][IP].dst

        sessions = self.vapi.nat44_user_session_dump(
            socket.inet_pton(socket.AF_INET, backend), 0)
        self.assertEqual(len(sessions), 1)
        self.assertTrue(sessions[0].ext_host_valid)
        self.vapi.nat44_del_session(
            sessions[0].inside_ip_address,
            sessions[0].inside_port,
            sessions[0].protocol,
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
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", packet))
            raise CaptureInvalidPacketError

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", packet))
            raise CaptureInvalidPacketError

    def test_hairpinning_unknown_proto(self):
        """ NAT44 translate packet with unknown protocol - hairpinning """
        host = self.pg0.remote_hosts[0]
        server = self.pg0.remote_hosts[1]
        host_in_port = 1234
        server_out_port = 8765
        server_nat_ip = "10.0.0.11"

        self.nat44_add_address(self.nat_addr)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", packet))
            raise CaptureInvalidPacketError

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", packet))
            raise CaptureInvalidPacketError

    def test_output_feature_and_service(self):
        """ NAT44 interface output feature and services """
        external_addr = '1.2.3.4'
        external_port = 80
        local_port = 8080

        self.vapi.nat44_forwarding_enable_disable(1)
        self.nat44_add_address(self.nat_addr)
        self.vapi.nat44_add_del_identity_mapping(ip=self.pg1.remote_ip4n)
        self.nat44_add_static_mapping(self.pg0.remote_ip4, external_addr,
                                      local_port, external_port,
                                      proto=IP_PROTOS.tcp, out2in_only=1)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index,
                                                  is_inside=0)
        self.vapi.nat44_interface_add_del_output_feature(self.pg1.sw_if_index,
                                                         is_inside=0)

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

        # from local network host to external network
        pkts = self.create_stream_in(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_out(capture)
        pkts = self.create_stream_in(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_out(capture)

        # from external network back to local network host
        pkts = self.create_stream_out(self.pg1)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(len(pkts))
        self.verify_capture_in(capture, self.pg0)

    def test_output_feature_and_service2(self):
        """ NAT44 interface output feature and service host direct access """
        self.vapi.nat44_forwarding_enable_disable(1)
        self.nat44_add_address(self.nat_addr)
        self.vapi.nat44_interface_add_del_output_feature(self.pg1.sw_if_index,
                                                         is_inside=0)

        # session initiaded from service host - translate
        pkts = self.create_stream_in(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_out(capture)

        pkts = self.create_stream_out(self.pg1)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(len(pkts))
        self.verify_capture_in(capture, self.pg0)

        # session initiaded from remote host - do not translate
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

        self.vapi.nat44_forwarding_enable_disable(1)
        self.nat44_add_address(self.nat_addr)
        self.nat44_add_static_mapping(self.pg1.remote_ip4, external_addr,
                                      local_port, external_port,
                                      proto=IP_PROTOS.tcp, out2in_only=1)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index,
                                                  is_inside=0)
        self.vapi.nat44_interface_add_del_output_feature(self.pg1.sw_if_index,
                                                         is_inside=0)

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

    def test_next_src_nat(self):
        """ On way back forward packet to nat44-in2out node. """
        twice_nat_addr = '10.0.1.3'
        external_port = 80
        local_port = 8080
        post_twice_nat_port = 0

        self.vapi.nat44_forwarding_enable_disable(1)
        self.nat44_add_address(twice_nat_addr, twice_nat=1)
        self.nat44_add_static_mapping(self.pg6.remote_ip4, self.pg1.remote_ip4,
                                      local_port, external_port,
                                      proto=IP_PROTOS.tcp, out2in_only=1,
                                      self_twice_nat=1, vrf_id=1)
        self.vapi.nat44_interface_add_del_feature(self.pg6.sw_if_index,
                                                  is_inside=0)

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

    def twice_nat_common(self, self_twice_nat=False, same_pg=False, lb=False,
                         client_id=None):
        twice_nat_addr = '10.0.1.3'

        port_in = 8080
        if lb:
            if not same_pg:
                port_in1 = port_in
                port_in2 = port_in
            else:
                port_in1 = port_in+1
                port_in2 = port_in+2

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
        if not lb:
            self.nat44_add_static_mapping(pg0.remote_ip4, self.nat_addr,
                                          port_in, port_out,
                                          proto=IP_PROTOS.tcp,
                                          twice_nat=int(not self_twice_nat),
                                          self_twice_nat=int(self_twice_nat))
        else:
            locals = [{'addr': server1.ip4n,
                       'port': port_in1,
                       'probability': 50,
                       'vrf_id': 0},
                      {'addr': server2.ip4n,
                       'port': port_in2,
                       'probability': 50,
                       'vrf_id': 0}]
            out_addr_n = socket.inet_pton(socket.AF_INET, self.nat_addr)
            self.vapi.nat44_add_del_lb_static_mapping(out_addr_n,
                                                      port_out,
                                                      IP_PROTOS.tcp,
                                                      twice_nat=int(
                                                          not self_twice_nat),
                                                      self_twice_nat=int(
                                                          self_twice_nat),
                                                      local_num=len(locals),
                                                      locals=locals)
        self.vapi.nat44_interface_add_del_feature(pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(pg1.sw_if_index,
                                                  is_inside=0)

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

        if eh_translate:
            sessions = self.vapi.nat44_user_session_dump(server.ip4n, 0)
            self.assertEqual(len(sessions), 1)
            self.assertTrue(sessions[0].ext_host_valid)
            self.assertTrue(sessions[0].is_twicenat)
            self.vapi.nat44_del_session(
                sessions[0].inside_ip_address,
                sessions[0].inside_port,
                sessions[0].protocol,
                ext_host_address=sessions[0].ext_host_nat_address,
                ext_host_port=sessions[0].ext_host_nat_port)
            sessions = self.vapi.nat44_user_session_dump(server.ip4n, 0)
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
        self.vapi.nat44_add_interface_addr(self.pg3.sw_if_index, twice_nat=1)

        # no address in NAT pool
        adresses = self.vapi.nat44_address_dump()
        self.assertEqual(0, len(adresses))

        # configure interface address and check NAT address pool
        self.pg3.config_ip4()
        adresses = self.vapi.nat44_address_dump()
        self.assertEqual(1, len(adresses))
        self.assertEqual(adresses[0].ip_address[0:4], self.pg3.local_ip4n)
        self.assertEqual(adresses[0].twice_nat, 1)

        # remove interface address and check NAT address pool
        self.pg3.unconfig_ip4()
        adresses = self.vapi.nat44_address_dump()
        self.assertEqual(0, len(adresses))

    def test_tcp_close(self):
        """ Close TCP session from inside network - output feature """
        self.vapi.nat44_forwarding_enable_disable(1)
        self.nat44_add_address(self.pg1.local_ip4)
        twice_nat_addr = '10.0.1.3'
        service_ip = '192.168.16.150'
        self.nat44_add_address(twice_nat_addr, twice_nat=1)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index,
                                                  is_inside=0)
        self.vapi.nat44_interface_add_del_output_feature(self.pg1.sw_if_index,
                                                         is_inside=0)
        self.nat44_add_static_mapping(self.pg0.remote_ip4,
                                      service_ip,
                                      80,
                                      80,
                                      proto=IP_PROTOS.tcp,
                                      out2in_only=1,
                                      twice_nat=1)
        sessions = self.vapi.nat44_user_session_dump(self.pg0.remote_ip4n, 0)
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

        sessions = self.vapi.nat44_user_session_dump(self.pg0.remote_ip4n,
                                                     0)
        self.assertEqual(len(sessions) - start_sessnum, 0)

    def test_tcp_session_close_in(self):
        """ Close TCP session from inside network """
        self.tcp_port_out = 10505
        self.nat44_add_address(self.nat_addr)
        self.nat44_add_static_mapping(self.pg0.remote_ip4,
                                      self.nat_addr,
                                      self.tcp_port_in,
                                      self.tcp_port_out,
                                      proto=IP_PROTOS.tcp,
                                      twice_nat=1)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)

        sessions = self.vapi.nat44_user_session_dump(self.pg0.remote_ip4n, 0)
        start_sessnum = len(sessions)

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

        sessions = self.vapi.nat44_user_session_dump(self.pg0.remote_ip4n,
                                                     0)
        self.assertEqual(len(sessions) - start_sessnum, 0)

    def test_tcp_session_close_out(self):
        """ Close TCP session from outside network """
        self.tcp_port_out = 10505
        self.nat44_add_address(self.nat_addr)
        self.nat44_add_static_mapping(self.pg0.remote_ip4,
                                      self.nat_addr,
                                      self.tcp_port_in,
                                      self.tcp_port_out,
                                      proto=IP_PROTOS.tcp,
                                      twice_nat=1)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)

        sessions = self.vapi.nat44_user_session_dump(self.pg0.remote_ip4n, 0)
        start_sessnum = len(sessions)

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

        sessions = self.vapi.nat44_user_session_dump(self.pg0.remote_ip4n,
                                                     0)
        self.assertEqual(len(sessions) - start_sessnum, 0)

    def test_tcp_session_close_simultaneous(self):
        """ Close TCP session from inside network """
        self.tcp_port_out = 10505
        self.nat44_add_address(self.nat_addr)
        self.nat44_add_static_mapping(self.pg0.remote_ip4,
                                      self.nat_addr,
                                      self.tcp_port_in,
                                      self.tcp_port_out,
                                      proto=IP_PROTOS.tcp,
                                      twice_nat=1)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)

        sessions = self.vapi.nat44_user_session_dump(self.pg0.remote_ip4n, 0)
        start_sessnum = len(sessions)

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

        sessions = self.vapi.nat44_user_session_dump(self.pg0.remote_ip4n,
                                                     0)
        self.assertEqual(len(sessions) - start_sessnum, 0)

    def test_one_armed_nat44_static(self):
        """ One armed NAT44 and 1:1 NAPT asymmetrical rule """
        remote_host = self.pg4.remote_hosts[0]
        local_host = self.pg4.remote_hosts[1]
        external_port = 80
        local_port = 8080
        eh_port_in = 0

        self.vapi.nat44_forwarding_enable_disable(1)
        self.nat44_add_address(self.nat_addr, twice_nat=1)
        self.nat44_add_static_mapping(local_host.ip4, self.nat_addr,
                                      local_port, external_port,
                                      proto=IP_PROTOS.tcp, out2in_only=1,
                                      twice_nat=1)
        self.vapi.nat44_interface_add_del_feature(self.pg4.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg4.sw_if_index,
                                                  is_inside=0)

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

    def test_static_with_port_out2(self):
        """ 1:1 NAPT asymmetrical rule """

        external_port = 80
        local_port = 8080

        self.vapi.nat44_forwarding_enable_disable(1)
        self.nat44_add_static_mapping(self.pg0.remote_ip4, self.nat_addr,
                                      local_port, external_port,
                                      proto=IP_PROTOS.tcp, out2in_only=1)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

    def test_output_feature(self):
        """ NAT44 interface output feature (in2out postrouting) """
        self.vapi.nat44_forwarding_enable_disable(1)
        self.nat44_add_address(self.nat_addr)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index,
                                                  is_inside=0)
        self.vapi.nat44_interface_add_del_output_feature(self.pg1.sw_if_index,
                                                         is_inside=0)

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

    def test_multiple_vrf(self):
        """ Multiple VRF setup """
        external_addr = '1.2.3.4'
        external_port = 80
        local_port = 8080
        port = 0

        self.vapi.nat44_forwarding_enable_disable(1)
        self.nat44_add_address(self.nat_addr)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index,
                                                  is_inside=0)
        self.vapi.nat44_interface_add_del_output_feature(self.pg1.sw_if_index,
                                                         is_inside=0)
        self.vapi.nat44_interface_add_del_feature(self.pg5.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg5.sw_if_index,
                                                  is_inside=0)
        self.vapi.nat44_interface_add_del_feature(self.pg6.sw_if_index,
                                                  is_inside=0)
        self.nat44_add_static_mapping(self.pg5.remote_ip4, external_addr,
                                      local_port, external_port, vrf_id=1,
                                      proto=IP_PROTOS.tcp, out2in_only=1)
        self.nat44_add_static_mapping(
             self.pg0.remote_ip4, external_sw_if_index=self.pg0.sw_if_index,
             local_port=local_port, vrf_id=0, external_port=external_port,
             proto=IP_PROTOS.tcp, out2in_only=1)

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

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
            self.assertNotEqual(tcp.sport, 2345)
            self.assert_packet_checksums_valid(p)
            port = tcp.sport
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_session_timeout(self):
        """ NAT44 session timeouts """
        self.nat44_add_address(self.nat_addr)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)
        self.vapi.nat_set_timeouts(icmp=5)

        max_sessions = 1000
        pkts = []
        for i in range(0, max_sessions):
            src = "10.10.%u.%u" % ((i & 0xFF00) >> 8, i & 0xFF)
            p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                 IP(src=src, dst=self.pg1.remote_ip4) /
                 ICMP(id=1025, type='echo-request'))
            pkts.append(p)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.get_capture(max_sessions)

        sleep(10)

        pkts = []
        for i in range(0, max_sessions):
            src = "10.11.%u.%u" % ((i & 0xFF00) >> 8, i & 0xFF)
            p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                 IP(src=src, dst=self.pg1.remote_ip4) /
                 ICMP(id=1026, type='echo-request'))
            pkts.append(p)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.get_capture(max_sessions)

        nsessions = 0
        users = self.vapi.nat44_user_dump()
        for user in users:
            nsessions = nsessions + user.nsessions
        self.assertLess(nsessions, 2 * max_sessions)

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_session_rst_timeout(self):
        """ NAT44 session RST timeouts """
        self.nat44_add_address(self.nat_addr)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)
        self.vapi.nat_set_timeouts(tcp_transitory=5)

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

        nsessions = 0
        users = self.vapi.nat44_user_dump()
        self.assertEqual(len(users), 1)
        self.assertEqual(users[0].ip_address, self.pg0.remote_ip4n)
        self.assertEqual(users[0].nsessions, 1)

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_session_limit_per_user(self):
        """ Maximum sessions per user limit """
        self.nat44_add_address(self.nat_addr)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)
        self.vapi.set_ipfix_exporter(collector_address=self.pg2.remote_ip4n,
                                     src_address=self.pg2.local_ip4n,
                                     path_mtu=512,
                                     template_interval=10)
        self.vapi.nat_set_timeouts(udp=5)

        # get maximum number of translations per user
        nat44_config = self.vapi.nat_show_config()

        pkts = []
        for port in range(0, nat44_config.max_translations_per_user):
            p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
                 IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
                 UDP(sport=1025 + port, dport=1025 + port))
            pkts.append(p)

        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))

        self.vapi.nat_ipfix(domain_id=self.ipfix_domain_id,
                            src_port=self.ipfix_src_port)

        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             UDP(sport=3001, dport=3002))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.assert_nothing_captured()

        # verify IPFIX logging
        self.vapi.cli("ipfix flush")  # FIXME this should be an API call
        sleep(1)
        capture = self.pg2.get_capture(10)
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
                self.verify_ipfix_max_entries_per_user(
                    data,
                    nat44_config.max_translations_per_user,
                    self.pg0.remote_ip4n)

        sleep(6)
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             UDP(sport=3001, dport=3002))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.get_capture(1)

    def test_syslog_sess(self):
        """ Test syslog session creation and deletion """
        self.vapi.syslog_set_filter(SYSLOG_SEVERITY.INFO)
        self.vapi.syslog_set_sender(self.pg2.remote_ip4n, self.pg2.local_ip4n)
        self.nat44_add_address(self.nat_addr)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)

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

    def tearDown(self):
        super(TestNAT44EndpointDependent, self).tearDown()
        if not self.vpp_dead:
            self.logger.info(self.vapi.cli("show nat44 addresses"))
            self.logger.info(self.vapi.cli("show nat44 interfaces"))
            self.logger.info(self.vapi.cli("show nat44 static mappings"))
            self.logger.info(self.vapi.cli("show nat44 interface address"))
            self.logger.info(self.vapi.cli("show nat44 sessions detail"))
            self.logger.info(self.vapi.cli("show nat44 hash tables detail"))
            self.logger.info(self.vapi.cli("show nat timeouts"))
            self.clear_nat44()
            self.vapi.cli("clear logging")


class TestNAT44Out2InDPO(MethodHolder):
    """ NAT44 Test Cases using out2in DPO """

    @classmethod
    def setUpConstants(cls):
        super(TestNAT44Out2InDPO, cls).setUpConstants()
        cls.vpp_cmdline.extend(["nat", "{", "out2in dpo", "}"])

    @classmethod
    def setUpClass(cls):
        super(TestNAT44Out2InDPO, cls).setUpClass()
        cls.vapi.cli("set log class nat level debug")

        try:
            cls.tcp_port_in = 6303
            cls.tcp_port_out = 6303
            cls.udp_port_in = 6304
            cls.udp_port_out = 6304
            cls.icmp_id_in = 6305
            cls.icmp_id_out = 6305
            cls.nat_addr = '10.0.0.3'
            cls.nat_addr_n = socket.inet_pton(socket.AF_INET, cls.nat_addr)
            cls.dst_ip4 = '192.168.70.1'

            cls.create_pg_interfaces(range(2))

            cls.pg0.admin_up()
            cls.pg0.config_ip4()
            cls.pg0.resolve_arp()

            cls.pg1.admin_up()
            cls.pg1.config_ip6()
            cls.pg1.resolve_ndp()

            cls.vapi.ip_add_del_route(is_ipv6=True, dst_address='\x00'*16,
                                      dst_address_length=0,
                                      next_hop_address=cls.pg1.remote_ip6n,
                                      next_hop_sw_if_index=cls.pg1.sw_if_index)

        except Exception:
            super(TestNAT44Out2InDPO, cls).tearDownClass()
            raise

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

        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_add_del_address_range(self.nat_addr_n, self.nat_addr_n)

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
            self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index,
                                                      is_add=0)
            self.vapi.nat44_add_del_address_range(self.nat_addr_n,
                                                  self.nat_addr_n, is_add=0)

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


class TestDeterministicNAT(MethodHolder):
    """ Deterministic NAT Test Cases """

    @classmethod
    def setUpConstants(cls):
        super(TestDeterministicNAT, cls).setUpConstants()
        cls.vpp_cmdline.extend(["nat", "{", "deterministic", "}"])

    @classmethod
    def setUpClass(cls):
        super(TestDeterministicNAT, cls).setUpClass()
        cls.vapi.cli("set log class nat level debug")

        try:
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

        except Exception:
            super(TestDeterministicNAT, cls).tearDownClass()
            raise

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
        :param same_port: Sorce port number is not translated (Default False)
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
            except (IndexError, AssertionError):
                self.logger.error(ppp("Unexpected or invalid packet "
                                      "(outside network):", packet))
                raise CaptureInvalidPacketError

    def test_deterministic_mode(self):
        """ NAT plugin run deterministic mode """
        in_addr = '172.16.255.0'
        out_addr = '172.17.255.50'
        in_addr_t = '172.16.255.20'
        in_addr_n = socket.inet_aton(in_addr)
        out_addr_n = socket.inet_aton(out_addr)
        in_addr_t_n = socket.inet_aton(in_addr_t)
        in_plen = 24
        out_plen = 32

        nat_config = self.vapi.nat_show_config()
        self.assertEqual(1, nat_config.deterministic)

        self.vapi.nat_det_add_del_map(in_addr_n, in_plen, out_addr_n, out_plen)

        rep1 = self.vapi.nat_det_forward(in_addr_t_n)
        self.assertEqual(rep1.out_addr[:4], out_addr_n)
        rep2 = self.vapi.nat_det_reverse(out_addr_n, rep1.out_port_hi)
        self.assertEqual(rep2.in_addr[:4], in_addr_t_n)

        deterministic_mappings = self.vapi.nat_det_map_dump()
        self.assertEqual(len(deterministic_mappings), 1)
        dsm = deterministic_mappings[0]
        self.assertEqual(in_addr_n, dsm.in_addr[:4])
        self.assertEqual(in_plen, dsm.in_plen)
        self.assertEqual(out_addr_n, dsm.out_addr[:4])
        self.assertEqual(out_plen, dsm.out_plen)

        self.clear_nat_det()
        deterministic_mappings = self.vapi.nat_det_map_dump()
        self.assertEqual(len(deterministic_mappings), 0)

    def test_set_timeouts(self):
        """ Set deterministic NAT timeouts """
        timeouts_before = self.vapi.nat_get_timeouts()

        self.vapi.nat_set_timeouts(timeouts_before.udp + 10,
                                   timeouts_before.tcp_established + 10,
                                   timeouts_before.tcp_transitory + 10,
                                   timeouts_before.icmp + 10)

        timeouts_after = self.vapi.nat_get_timeouts()

        self.assertNotEqual(timeouts_before.udp, timeouts_after.udp)
        self.assertNotEqual(timeouts_before.icmp, timeouts_after.icmp)
        self.assertNotEqual(timeouts_before.tcp_established,
                            timeouts_after.tcp_established)
        self.assertNotEqual(timeouts_before.tcp_transitory,
                            timeouts_after.tcp_transitory)

    def test_det_in(self):
        """ Deterministic NAT translation test (TCP, UDP, ICMP) """

        nat_ip = "10.0.0.10"

        self.vapi.nat_det_add_del_map(self.pg0.remote_ip4n,
                                      32,
                                      socket.inet_aton(nat_ip),
                                      32)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)

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
        sessions = self.vapi.nat_det_session_dump(self.pg0.remote_ip4n)
        self.assertEqual(len(sessions), 3)

        # TCP session
        s = sessions[0]
        self.assertEqual(s.ext_addr[:4], self.pg1.remote_ip4n)
        self.assertEqual(s.in_port, self.tcp_port_in)
        self.assertEqual(s.out_port, self.tcp_port_out)
        self.assertEqual(s.ext_port, self.tcp_external_port)

        # UDP session
        s = sessions[1]
        self.assertEqual(s.ext_addr[:4], self.pg1.remote_ip4n)
        self.assertEqual(s.in_port, self.udp_port_in)
        self.assertEqual(s.out_port, self.udp_port_out)
        self.assertEqual(s.ext_port, self.udp_external_port)

        # ICMP session
        s = sessions[2]
        self.assertEqual(s.ext_addr[:4], self.pg1.remote_ip4n)
        self.assertEqual(s.in_port, self.icmp_id_in)
        self.assertEqual(s.out_port, self.icmp_external_id)

    def test_multiple_users(self):
        """ Deterministic NAT multiple users """

        nat_ip = "10.0.0.10"
        port_in = 80
        external_port = 6303

        host0 = self.pg0.remote_hosts[0]
        host1 = self.pg0.remote_hosts[1]

        self.vapi.nat_det_add_del_map(host0.ip4n,
                                      24,
                                      socket.inet_aton(nat_ip),
                                      32)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

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
        except (IndexError, AssertionError):
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise CaptureInvalidPacketError

        dms = self.vapi.nat_det_map_dump()
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
        self.vapi.nat_det_close_session_out(socket.inet_aton(nat_ip),
                                            port_out1,
                                            self.pg1.remote_ip4n,
                                            external_port)
        dms = self.vapi.nat_det_map_dump()
        self.assertEqual(dms[0].ses_num, 1)

        self.vapi.nat_det_close_session_in(host0.ip4n,
                                           port_in,
                                           self.pg1.remote_ip4n,
                                           external_port)
        dms = self.vapi.nat_det_map_dump()
        self.assertEqual(dms[0].ses_num, 0)

    def test_tcp_session_close_detection_in(self):
        """ Deterministic NAT TCP session close from inside network """
        self.vapi.nat_det_add_del_map(self.pg0.remote_ip4n,
                                      32,
                                      socket.inet_aton(self.nat_addr),
                                      32)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)

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
            dms = self.vapi.nat_det_map_dump()
            self.assertEqual(0, dms[0].ses_num)
        except:
            self.logger.error("TCP session termination failed")
            raise

    def test_tcp_session_close_detection_out(self):
        """ Deterministic NAT TCP session close from outside network """
        self.vapi.nat_det_add_del_map(self.pg0.remote_ip4n,
                                      32,
                                      socket.inet_aton(self.nat_addr),
                                      32)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)

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
            dms = self.vapi.nat_det_map_dump()
            self.assertEqual(0, dms[0].ses_num)
        except:
            self.logger.error("TCP session termination failed")
            raise

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_session_timeout(self):
        """ Deterministic NAT session timeouts """
        self.vapi.nat_det_add_del_map(self.pg0.remote_ip4n,
                                      32,
                                      socket.inet_aton(self.nat_addr),
                                      32)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)

        self.initiate_tcp_session(self.pg0, self.pg1)
        self.vapi.nat_set_timeouts(5, 5, 5, 5)
        pkts = self.create_stream_in(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        sleep(15)

        dms = self.vapi.nat_det_map_dump()
        self.assertEqual(0, dms[0].ses_num)

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_session_limit_per_user(self):
        """ Deterministic NAT maximum sessions per user limit """
        self.vapi.nat_det_add_del_map(self.pg0.remote_ip4n,
                                      32,
                                      socket.inet_aton(self.nat_addr),
                                      32)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)
        self.vapi.set_ipfix_exporter(collector_address=self.pg2.remote_ip4n,
                                     src_address=self.pg2.local_ip4n,
                                     path_mtu=512,
                                     template_interval=10)
        self.vapi.nat_ipfix()

        pkts = []
        for port in range(1025, 2025):
            p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
                 IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
                 UDP(sport=port, dport=port))
            pkts.append(p)

        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))

        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             UDP(sport=3001, dport=3002))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.assert_nothing_captured()

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

        dms = self.vapi.nat_det_map_dump()

        self.assertEqual(1000, dms[0].ses_num)

        # verify IPFIX logging
        self.vapi.cli("ipfix flush")  # FIXME this should be an API call
        sleep(1)
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
                                                       self.pg0.remote_ip4n)

    def clear_nat_det(self):
        """
        Clear deterministic NAT configuration.
        """
        self.vapi.nat_ipfix(enable=0)
        self.vapi.nat_set_timeouts()
        deterministic_mappings = self.vapi.nat_det_map_dump()
        for dsm in deterministic_mappings:
            self.vapi.nat_det_add_del_map(dsm.in_addr,
                                          dsm.in_plen,
                                          dsm.out_addr,
                                          dsm.out_plen,
                                          is_add=0)

        interfaces = self.vapi.nat44_interface_dump()
        for intf in interfaces:
            self.vapi.nat44_interface_add_del_feature(intf.sw_if_index,
                                                      intf.is_inside,
                                                      is_add=0)

    def tearDown(self):
        super(TestDeterministicNAT, self).tearDown()
        if not self.vpp_dead:
            self.logger.info(self.vapi.cli("show nat44 interfaces"))
            self.logger.info(self.vapi.cli("show nat timeouts"))
            self.logger.info(
                self.vapi.cli("show nat44 deterministic mappings"))
            self.logger.info(
                self.vapi.cli("show nat44 deterministic sessions"))
            self.clear_nat_det()


class TestNAT64(MethodHolder):
    """ NAT64 Test Cases """

    @classmethod
    def setUpConstants(cls):
        super(TestNAT64, cls).setUpConstants()
        cls.vpp_cmdline.extend(["nat", "{", "nat64 bib hash buckets 128",
                                "nat64 st hash buckets 256", "}"])

    @classmethod
    def setUpClass(cls):
        super(TestNAT64, cls).setUpClass()

        try:
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
            cls.vrf1_nat_addr_n = socket.inet_pton(socket.AF_INET,
                                                   cls.vrf1_nat_addr)
            cls.ipfix_src_port = 4739
            cls.ipfix_domain_id = 1

            cls.create_pg_interfaces(range(6))
            cls.ip6_interfaces = list(cls.pg_interfaces[0:1])
            cls.ip6_interfaces.append(cls.pg_interfaces[2])
            cls.ip4_interfaces = list(cls.pg_interfaces[1:2])

            cls.vapi.ip_table_add_del(cls.vrf1_id, is_add=1, is_ipv6=1)

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

        except Exception:
            super(TestNAT64, cls).tearDownClass()
            raise

    def test_nat64_inside_interface_handles_neighbor_advertisement(self):
        """ NAT64 inside interface handles Neighbor Advertisement """

        self.vapi.nat64_add_del_interface(self.pg5.sw_if_index)

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
        nat_addr = socket.inet_pton(socket.AF_INET, '1.2.3.4')

        self.vapi.nat64_add_del_pool_addr_range(nat_addr, nat_addr)

        addresses = self.vapi.nat64_pool_addr_dump()
        self.assertEqual(len(addresses), 1)
        self.assertEqual(addresses[0].address, nat_addr)

        self.vapi.nat64_add_del_pool_addr_range(nat_addr, nat_addr, is_add=0)

        addresses = self.vapi.nat64_pool_addr_dump()
        self.assertEqual(len(addresses), 0)

    def test_interface(self):
        """ Enable/disable NAT64 feature on the interface """
        self.vapi.nat64_add_del_interface(self.pg0.sw_if_index)
        self.vapi.nat64_add_del_interface(self.pg1.sw_if_index, is_inside=0)

        interfaces = self.vapi.nat64_interface_dump()
        self.assertEqual(len(interfaces), 2)
        pg0_found = False
        pg1_found = False
        for intf in interfaces:
            if intf.sw_if_index == self.pg0.sw_if_index:
                self.assertEqual(intf.is_inside, 1)
                pg0_found = True
            elif intf.sw_if_index == self.pg1.sw_if_index:
                self.assertEqual(intf.is_inside, 0)
                pg1_found = True
        self.assertTrue(pg0_found)
        self.assertTrue(pg1_found)

        features = self.vapi.cli("show interface features pg0")
        self.assertNotEqual(features.find('nat64-in2out'), -1)
        features = self.vapi.cli("show interface features pg1")
        self.assertNotEqual(features.find('nat64-out2in'), -1)

        self.vapi.nat64_add_del_interface(self.pg0.sw_if_index, is_add=0)
        self.vapi.nat64_add_del_interface(self.pg1.sw_if_index, is_add=0)

        interfaces = self.vapi.nat64_interface_dump()
        self.assertEqual(len(interfaces), 0)

    def test_static_bib(self):
        """ Add/delete static BIB entry """
        in_addr = socket.inet_pton(socket.AF_INET6,
                                   '2001:db8:85a3::8a2e:370:7334')
        out_addr = socket.inet_pton(socket.AF_INET, '10.1.1.3')
        in_port = 1234
        out_port = 5678
        proto = IP_PROTOS.tcp

        self.vapi.nat64_add_del_static_bib(in_addr,
                                           out_addr,
                                           in_port,
                                           out_port,
                                           proto)
        bib = self.vapi.nat64_bib_dump(IP_PROTOS.tcp)
        static_bib_num = 0
        for bibe in bib:
            if bibe.is_static:
                static_bib_num += 1
                self.assertEqual(bibe.i_addr, in_addr)
                self.assertEqual(bibe.o_addr, out_addr)
                self.assertEqual(bibe.i_port, in_port)
                self.assertEqual(bibe.o_port, out_port)
        self.assertEqual(static_bib_num, 1)
        bibs = self.statistics.get_counter('/nat64/total-bibs')
        self.assertEqual(bibs[0][0], 1)

        self.vapi.nat64_add_del_static_bib(in_addr,
                                           out_addr,
                                           in_port,
                                           out_port,
                                           proto,
                                           is_add=0)
        bib = self.vapi.nat64_bib_dump(IP_PROTOS.tcp)
        static_bib_num = 0
        for bibe in bib:
            if bibe.is_static:
                static_bib_num += 1
        self.assertEqual(static_bib_num, 0)
        bibs = self.statistics.get_counter('/nat64/total-bibs')
        self.assertEqual(bibs[0][0], 0)

    def test_set_timeouts(self):
        """ Set NAT64 timeouts """
        # verify default values
        timeouts = self.vapi.nat_get_timeouts()
        self.assertEqual(timeouts.udp, 300)
        self.assertEqual(timeouts.icmp, 60)
        self.assertEqual(timeouts.tcp_transitory, 240)
        self.assertEqual(timeouts.tcp_established, 7440)

        # set and verify custom values
        self.vapi.nat_set_timeouts(udp=200, icmp=30, tcp_transitory=250,
                                   tcp_established=7450)
        timeouts = self.vapi.nat_get_timeouts()
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

        self.vapi.nat64_add_del_pool_addr_range(self.nat_addr_n,
                                                self.nat_addr_n)
        self.vapi.nat64_add_del_interface(self.pg0.sw_if_index)
        self.vapi.nat64_add_del_interface(self.pg1.sw_if_index, is_inside=0)

        # in2out
        tcpn = self.statistics.get_counter('/err/nat64-in2out/TCP packets')
        udpn = self.statistics.get_counter('/err/nat64-in2out/UDP packets')
        icmpn = self.statistics.get_counter('/err/nat64-in2out/ICMP packets')
        totaln = self.statistics.get_counter(
            '/err/nat64-in2out/good in2out packets processed')

        pkts = self.create_stream_in_ip6(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_out(capture, nat_ip=self.nat_addr,
                                dst_ip=self.pg1.remote_ip4)

        err = self.statistics.get_counter('/err/nat64-in2out/TCP packets')
        self.assertEqual(err - tcpn, 1)
        err = self.statistics.get_counter('/err/nat64-in2out/UDP packets')
        self.assertEqual(err - udpn, 1)
        err = self.statistics.get_counter('/err/nat64-in2out/ICMP packets')
        self.assertEqual(err - icmpn, 1)
        err = self.statistics.get_counter(
            '/err/nat64-in2out/good in2out packets processed')
        self.assertEqual(err - totaln, 3)

        # out2in
        tcpn = self.statistics.get_counter('/err/nat64-out2in/TCP packets')
        udpn = self.statistics.get_counter('/err/nat64-out2in/UDP packets')
        icmpn = self.statistics.get_counter('/err/nat64-out2in/ICMP packets')
        totaln = self.statistics.get_counter(
            '/err/nat64-out2in/good out2in packets processed')

        pkts = self.create_stream_out(self.pg1, dst_ip=self.nat_addr)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(len(pkts))
        ip = IPv6(src=''.join(['64:ff9b::', self.pg1.remote_ip4]))
        self.verify_capture_in_ip6(capture, ip[IPv6].src, self.pg0.remote_ip6)

        err = self.statistics.get_counter('/err/nat64-out2in/TCP packets')
        self.assertEqual(err - tcpn, 1)
        err = self.statistics.get_counter('/err/nat64-out2in/UDP packets')
        self.assertEqual(err - udpn, 1)
        err = self.statistics.get_counter('/err/nat64-out2in/ICMP packets')
        self.assertEqual(err - icmpn, 1)
        err = self.statistics.get_counter(
            '/err/nat64-out2in/good out2in packets processed')
        self.assertEqual(err - totaln, 3)

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
        self.vapi.nat64_add_del_pool_addr_range(self.vrf1_nat_addr_n,
                                                self.vrf1_nat_addr_n,
                                                vrf_id=self.vrf1_id)
        self.vapi.nat64_add_del_interface(self.pg2.sw_if_index)

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

        self.vapi.nat64_add_del_pool_addr_range(self.nat_addr_n,
                                                self.nat_addr_n)
        self.vapi.nat64_add_del_interface(self.pg0.sw_if_index)
        self.vapi.nat64_add_del_interface(self.pg1.sw_if_index, is_inside=0)

        self.vapi.nat64_add_del_static_bib(self.pg0.remote_ip6n,
                                           self.nat_addr_n,
                                           self.tcp_port_in,
                                           self.tcp_port_out,
                                           IP_PROTOS.tcp)
        self.vapi.nat64_add_del_static_bib(self.pg0.remote_ip6n,
                                           self.nat_addr_n,
                                           self.udp_port_in,
                                           self.udp_port_out,
                                           IP_PROTOS.udp)
        self.vapi.nat64_add_del_static_bib(self.pg0.remote_ip6n,
                                           self.nat_addr_n,
                                           self.icmp_id_in,
                                           self.icmp_id_out,
                                           IP_PROTOS.icmp)

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

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_session_timeout(self):
        """ NAT64 session timeout """
        self.icmp_id_in = 1234
        self.vapi.nat64_add_del_pool_addr_range(self.nat_addr_n,
                                                self.nat_addr_n)
        self.vapi.nat64_add_del_interface(self.pg0.sw_if_index)
        self.vapi.nat64_add_del_interface(self.pg1.sw_if_index, is_inside=0)
        self.vapi.nat_set_timeouts(icmp=5, tcp_transitory=5, tcp_established=5)

        pkts = self.create_stream_in_ip6(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))

        ses_num_before_timeout = self.nat64_get_ses_num()

        sleep(15)

        # ICMP and TCP session after timeout
        ses_num_after_timeout = self.nat64_get_ses_num()
        self.assertEqual(ses_num_before_timeout - ses_num_after_timeout, 2)

    def test_icmp_error(self):
        """ NAT64 ICMP Error message translation """
        self.tcp_port_in = 6303
        self.udp_port_in = 6304
        self.icmp_id_in = 6305

        self.vapi.nat64_add_del_pool_addr_range(self.nat_addr_n,
                                                self.nat_addr_n)
        self.vapi.nat64_add_del_interface(self.pg0.sw_if_index)
        self.vapi.nat64_add_del_interface(self.pg1.sw_if_index, is_inside=0)

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

        self.vapi.nat64_add_del_pool_addr_range(self.nat_addr_n,
                                                self.nat_addr_n)
        self.vapi.nat64_add_del_interface(self.pg0.sw_if_index)
        self.vapi.nat64_add_del_interface(self.pg1.sw_if_index, is_inside=0)

        self.vapi.nat64_add_del_static_bib(server.ip6n,
                                           self.nat_addr_n,
                                           server_tcp_in_port,
                                           server_tcp_out_port,
                                           IP_PROTOS.tcp)
        self.vapi.nat64_add_del_static_bib(server.ip6n,
                                           self.nat_addr_n,
                                           server_udp_in_port,
                                           server_udp_out_port,
                                           IP_PROTOS.udp)

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

        self.vapi.nat64_add_del_pool_addr_range(self.nat_addr_n,
                                                self.nat_addr_n)
        self.vapi.nat64_add_del_interface(self.pg0.sw_if_index)
        self.vapi.nat64_add_del_interface(self.pg1.sw_if_index, is_inside=0)
        self.vapi.nat64_add_del_pool_addr_range(self.vrf1_nat_addr_n,
                                                self.vrf1_nat_addr_n,
                                                vrf_id=self.vrf1_id)
        self.vapi.nat64_add_del_interface(self.pg2.sw_if_index)

        # Add global prefix
        global_pref64 = "2001:db8::"
        global_pref64_n = socket.inet_pton(socket.AF_INET6, global_pref64)
        global_pref64_len = 32
        self.vapi.nat64_add_del_prefix(global_pref64_n, global_pref64_len)

        prefix = self.vapi.nat64_prefix_dump()
        self.assertEqual(len(prefix), 1)
        self.assertEqual(prefix[0].prefix, global_pref64_n)
        self.assertEqual(prefix[0].prefix_len, global_pref64_len)
        self.assertEqual(prefix[0].vrf_id, 0)

        # Add tenant specific prefix
        vrf1_pref64 = "2001:db8:122:300::"
        vrf1_pref64_n = socket.inet_pton(socket.AF_INET6, vrf1_pref64)
        vrf1_pref64_len = 56
        self.vapi.nat64_add_del_prefix(vrf1_pref64_n,
                                       vrf1_pref64_len,
                                       vrf_id=self.vrf1_id)
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

        self.vapi.nat64_add_del_pool_addr_range(self.nat_addr_n,
                                                self.nat_addr_n)
        self.vapi.nat64_add_del_interface(self.pg0.sw_if_index)
        self.vapi.nat64_add_del_interface(self.pg1.sw_if_index, is_inside=0)
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
        server_nat_ip_n = socket.inet_pton(socket.AF_INET, server_nat_ip)
        client_nat_ip_n = socket.inet_pton(socket.AF_INET, client_nat_ip)
        server_nat_ip6 = self.compose_ip6(server_nat_ip, '64:ff9b::', 96)
        client_nat_ip6 = self.compose_ip6(client_nat_ip, '64:ff9b::', 96)

        self.vapi.nat64_add_del_pool_addr_range(server_nat_ip_n,
                                                client_nat_ip_n)
        self.vapi.nat64_add_del_interface(self.pg0.sw_if_index)
        self.vapi.nat64_add_del_interface(self.pg1.sw_if_index, is_inside=0)

        self.vapi.nat64_add_del_static_bib(server.ip6n,
                                           server_nat_ip_n,
                                           server_tcp_in_port,
                                           server_tcp_out_port,
                                           IP_PROTOS.tcp)

        self.vapi.nat64_add_del_static_bib(server.ip6n,
                                           server_nat_ip_n,
                                           0,
                                           0,
                                           IP_PROTOS.gre)

        self.vapi.nat64_add_del_static_bib(client.ip6n,
                                           client_nat_ip_n,
                                           client_tcp_in_port,
                                           client_tcp_out_port,
                                           IP_PROTOS.tcp)

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

        self.vapi.nat64_add_del_pool_addr_range(self.nat_addr_n,
                                                self.nat_addr_n)
        self.vapi.nat64_add_del_interface(self.pg3.sw_if_index)
        self.vapi.nat64_add_del_interface(self.pg3.sw_if_index, is_inside=0)

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

        self.vapi.nat64_add_del_pool_addr_range(self.nat_addr_n,
                                                self.nat_addr_n)
        self.vapi.nat64_add_del_interface(self.pg0.sw_if_index)
        self.vapi.nat64_add_del_interface(self.pg1.sw_if_index, is_inside=0)

        reass = self.vapi.nat_reass_dump()
        reass_n_start = len(reass)

        # in2out
        data = 'a' * 200
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
        data = "A" * 4 + "b" * 16 + "C" * 3
        pkts = self.create_stream_frag(self.pg1,
                                       self.nat_addr,
                                       20,
                                       self.tcp_port_out,
                                       data)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        frags = self.pg0.get_capture(len(pkts))
        src = self.compose_ip6(self.pg1.remote_ip4, '64:ff9b::', 96)
        p = self.reass_frags_and_verify_ip6(frags, src, self.pg0.remote_ip6)
        self.assertEqual(p[TCP].sport, 20)
        self.assertEqual(p[TCP].dport, self.tcp_port_in)
        self.assertEqual(data, p[Raw].load)

        reass = self.vapi.nat_reass_dump()
        reass_n_end = len(reass)

        self.assertEqual(reass_n_end - reass_n_start, 2)

    def test_reass_hairpinning(self):
        """ NAT64 fragments hairpinning """
        data = 'a' * 200
        server = self.pg0.remote_hosts[1]
        server_in_port = random.randint(1025, 65535)
        server_out_port = random.randint(1025, 65535)
        client_in_port = random.randint(1025, 65535)
        ip = IPv6(src=''.join(['64:ff9b::', self.nat_addr]))
        nat_addr_ip6 = ip.src

        self.vapi.nat64_add_del_pool_addr_range(self.nat_addr_n,
                                                self.nat_addr_n)
        self.vapi.nat64_add_del_interface(self.pg0.sw_if_index)
        self.vapi.nat64_add_del_interface(self.pg1.sw_if_index, is_inside=0)

        # add static BIB entry for server
        self.vapi.nat64_add_del_static_bib(server.ip6n,
                                           self.nat_addr_n,
                                           server_in_port,
                                           server_out_port,
                                           IP_PROTOS.tcp)

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
        p = self.reass_frags_and_verify_ip6(frags, nat_addr_ip6, server.ip6)
        self.assertNotEqual(p[TCP].sport, client_in_port)
        self.assertEqual(p[TCP].dport, server_in_port)
        self.assertEqual(data, p[Raw].load)

    def test_frag_out_of_order(self):
        """ NAT64 translate fragments arriving out of order """
        self.tcp_port_in = random.randint(1025, 65535)

        self.vapi.nat64_add_del_pool_addr_range(self.nat_addr_n,
                                                self.nat_addr_n)
        self.vapi.nat64_add_del_interface(self.pg0.sw_if_index)
        self.vapi.nat64_add_del_interface(self.pg1.sw_if_index, is_inside=0)

        # in2out
        data = 'a' * 200
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
        data = "A" * 4 + "B" * 16 + "C" * 3
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
        self.vapi.nat64_add_interface_addr(self.pg4.sw_if_index)

        # no address in NAT64 pool
        adresses = self.vapi.nat44_address_dump()
        self.assertEqual(0, len(adresses))

        # configure interface address and check NAT64 address pool
        self.pg4.config_ip4()
        addresses = self.vapi.nat64_pool_addr_dump()
        self.assertEqual(len(addresses), 1)
        self.assertEqual(addresses[0].address, self.pg4.local_ip4n)

        # remove interface address and check NAT64 address pool
        self.pg4.unconfig_ip4()
        addresses = self.vapi.nat64_pool_addr_dump()
        self.assertEqual(0, len(adresses))

    @unittest.skipUnless(running_extended_tests, "part of extended tests")
    def test_ipfix_max_bibs_sessions(self):
        """ IPFIX logging maximum session and BIB entries exceeded """
        max_bibs = 1280
        max_sessions = 2560
        remote_host_ip6 = self.compose_ip6(self.pg1.remote_ip4,
                                           '64:ff9b::',
                                           96)

        self.vapi.nat64_add_del_pool_addr_range(self.nat_addr_n,
                                                self.nat_addr_n)
        self.vapi.nat64_add_del_interface(self.pg0.sw_if_index)
        self.vapi.nat64_add_del_interface(self.pg1.sw_if_index, is_inside=0)

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

        self.vapi.set_ipfix_exporter(collector_address=self.pg3.remote_ip4n,
                                     src_address=self.pg3.local_ip4n,
                                     path_mtu=512,
                                     template_interval=10)
        self.vapi.nat_ipfix(domain_id=self.ipfix_domain_id,
                            src_port=self.ipfix_src_port)

        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IPv6(src=src, dst=remote_host_ip6) /
             TCP(sport=12345, dport=25))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.assert_nothing_captured()
        sleep(1)
        self.vapi.cli("ipfix flush")  # FIXME this should be an API call
        capture = self.pg3.get_capture(9)
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
        sleep(1)
        self.vapi.cli("ipfix flush")  # FIXME this should be an API call
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

    def test_ipfix_max_frags(self):
        """ IPFIX logging maximum fragments pending reassembly exceeded """
        self.vapi.nat64_add_del_pool_addr_range(self.nat_addr_n,
                                                self.nat_addr_n)
        self.vapi.nat64_add_del_interface(self.pg0.sw_if_index)
        self.vapi.nat64_add_del_interface(self.pg1.sw_if_index, is_inside=0)
        self.vapi.nat_set_reass(max_frag=1, is_ip6=1)
        self.vapi.set_ipfix_exporter(collector_address=self.pg3.remote_ip4n,
                                     src_address=self.pg3.local_ip4n,
                                     path_mtu=512,
                                     template_interval=10)
        self.vapi.nat_ipfix(domain_id=self.ipfix_domain_id,
                            src_port=self.ipfix_src_port)

        data = 'a' * 200
        pkts = self.create_stream_frag_ip6(self.pg0, self.pg1.remote_ip4,
                                           self.tcp_port_in, 20, data)
        pkts.reverse()
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.assert_nothing_captured()
        sleep(1)
        self.vapi.cli("ipfix flush")  # FIXME this should be an API call
        capture = self.pg3.get_capture(9)
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
                self.verify_ipfix_max_fragments_ip6(data, 1,
                                                    self.pg0.remote_ip6n)

    def test_ipfix_bib_ses(self):
        """ IPFIX logging NAT64 BIB/session create and delete events """
        self.tcp_port_in = random.randint(1025, 65535)
        remote_host_ip6 = self.compose_ip6(self.pg1.remote_ip4,
                                           '64:ff9b::',
                                           96)

        self.vapi.nat64_add_del_pool_addr_range(self.nat_addr_n,
                                                self.nat_addr_n)
        self.vapi.nat64_add_del_interface(self.pg0.sw_if_index)
        self.vapi.nat64_add_del_interface(self.pg1.sw_if_index, is_inside=0)
        self.vapi.set_ipfix_exporter(collector_address=self.pg3.remote_ip4n,
                                     src_address=self.pg3.local_ip4n,
                                     path_mtu=512,
                                     template_interval=10)
        self.vapi.nat_ipfix(domain_id=self.ipfix_domain_id,
                            src_port=self.ipfix_src_port)

        # Create
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IPv6(src=self.pg0.remote_ip6, dst=remote_host_ip6) /
             TCP(sport=self.tcp_port_in, dport=25))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        p = self.pg1.get_capture(1)
        self.tcp_port_out = p[0][TCP].sport
        self.vapi.cli("ipfix flush")  # FIXME this should be an API call
        capture = self.pg3.get_capture(10)
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
                if ord(data[0][230]) == 10:
                    self.verify_ipfix_bib(data, 1, self.pg0.remote_ip6n)
                elif ord(data[0][230]) == 6:
                    self.verify_ipfix_nat64_ses(data,
                                                1,
                                                self.pg0.remote_ip6n,
                                                self.pg1.remote_ip4,
                                                25)
                else:
                    self.logger.error(ppp("Unexpected or invalid packet: ", p))

        # Delete
        self.pg_enable_capture(self.pg_interfaces)
        self.vapi.nat64_add_del_pool_addr_range(self.nat_addr_n,
                                                self.nat_addr_n,
                                                is_add=0)
        self.vapi.cli("ipfix flush")  # FIXME this should be an API call
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
                if ord(data[0][230]) == 11:
                    self.verify_ipfix_bib(data, 0, self.pg0.remote_ip6n)
                elif ord(data[0][230]) == 7:
                    self.verify_ipfix_nat64_ses(data,
                                                0,
                                                self.pg0.remote_ip6n,
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

        self.vapi.nat64_add_del_pool_addr_range(self.nat_addr_n,
                                                self.nat_addr_n)
        self.vapi.nat64_add_del_interface(self.pg0.sw_if_index)
        self.vapi.nat64_add_del_interface(self.pg1.sw_if_index, is_inside=0)
        self.vapi.syslog_set_filter(SYSLOG_SEVERITY.INFO)
        self.vapi.syslog_set_sender(self.pg3.remote_ip4n, self.pg3.local_ip4n)

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
        self.vapi.nat64_add_del_pool_addr_range(self.nat_addr_n,
                                                self.nat_addr_n,
                                                is_add=0)
        capture = self.pg3.get_capture(1)
        self.verify_syslog_sess(capture[0][Raw].load, False, True)

    def nat64_get_ses_num(self):
        """
        Return number of active NAT64 sessions.
        """
        st = self.vapi.nat64_st_dump()
        return len(st)

    def clear_nat64(self):
        """
        Clear NAT64 configuration.
        """
        self.vapi.nat_ipfix(enable=0, src_port=self.ipfix_src_port,
                            domain_id=self.ipfix_domain_id)
        self.ipfix_src_port = 4739
        self.ipfix_domain_id = 1

        self.vapi.syslog_set_filter(SYSLOG_SEVERITY.EMERG)

        self.vapi.nat_set_timeouts()

        interfaces = self.vapi.nat64_interface_dump()
        for intf in interfaces:
            if intf.is_inside > 1:
                self.vapi.nat64_add_del_interface(intf.sw_if_index,
                                                  0,
                                                  is_add=0)
            self.vapi.nat64_add_del_interface(intf.sw_if_index,
                                              intf.is_inside,
                                              is_add=0)

        bib = self.vapi.nat64_bib_dump(255)
        for bibe in bib:
            if bibe.is_static:
                self.vapi.nat64_add_del_static_bib(bibe.i_addr,
                                                   bibe.o_addr,
                                                   bibe.i_port,
                                                   bibe.o_port,
                                                   bibe.proto,
                                                   bibe.vrf_id,
                                                   is_add=0)

        adresses = self.vapi.nat64_pool_addr_dump()
        for addr in adresses:
            self.vapi.nat64_add_del_pool_addr_range(addr.address,
                                                    addr.address,
                                                    vrf_id=addr.vrf_id,
                                                    is_add=0)

        prefixes = self.vapi.nat64_prefix_dump()
        for prefix in prefixes:
            self.vapi.nat64_add_del_prefix(prefix.prefix,
                                           prefix.prefix_len,
                                           vrf_id=prefix.vrf_id,
                                           is_add=0)

        bibs = self.statistics.get_counter('/nat64/total-bibs')
        self.assertEqual(bibs[0][0], 0)
        sessions = self.statistics.get_counter('/nat64/total-sessions')
        self.assertEqual(sessions[0][0], 0)

    def tearDown(self):
        super(TestNAT64, self).tearDown()
        if not self.vpp_dead:
            self.logger.info(self.vapi.cli("show nat64 pool"))
            self.logger.info(self.vapi.cli("show nat64 interfaces"))
            self.logger.info(self.vapi.cli("show nat64 prefix"))
            self.logger.info(self.vapi.cli("show nat64 bib all"))
            self.logger.info(self.vapi.cli("show nat64 session table all"))
            self.logger.info(self.vapi.cli("show nat virtual-reassembly"))
            self.clear_nat64()


class TestDSlite(MethodHolder):
    """ DS-Lite Test Cases """

    @classmethod
    def setUpClass(cls):
        super(TestDSlite, cls).setUpClass()

        try:
            cls.nat_addr = '10.0.0.3'
            cls.nat_addr_n = socket.inet_pton(socket.AF_INET, cls.nat_addr)

            cls.create_pg_interfaces(range(3))
            cls.pg0.admin_up()
            cls.pg0.config_ip4()
            cls.pg0.resolve_arp()
            cls.pg1.admin_up()
            cls.pg1.config_ip6()
            cls.pg1.generate_remote_hosts(2)
            cls.pg1.configure_ipv6_neighbors()
            cls.pg2.admin_up()
            cls.pg2.config_ip4()
            cls.pg2.resolve_arp()

        except Exception:
            super(TestDSlite, cls).tearDownClass()
            raise

    def verify_syslog_apmadd(self, data, isaddr, isport, xsaddr, xsport,
                             sv6enc, proto):
        message = data.decode('utf-8')
        try:
            message = SyslogMessage.parse(message)
            self.assertEqual(message.severity, SyslogSeverity.info)
            self.assertEqual(message.appname, 'NAT')
            self.assertEqual(message.msgid, 'APMADD')
            sd_params = message.sd.get('napmap')
            self.assertTrue(sd_params is not None)
            self.assertEqual(sd_params.get('IATYP'), 'IPv4')
            self.assertEqual(sd_params.get('ISADDR'), isaddr)
            self.assertEqual(sd_params.get('ISPORT'), "%d" % isport)
            self.assertEqual(sd_params.get('XATYP'), 'IPv4')
            self.assertEqual(sd_params.get('XSADDR'), xsaddr)
            self.assertEqual(sd_params.get('XSPORT'), "%d" % xsport)
            self.assertEqual(sd_params.get('PROTO'), "%d" % proto)
            self.assertTrue(sd_params.get('SSUBIX') is not None)
            self.assertEqual(sd_params.get('SV6ENC'), sv6enc)
        except ParseError as e:
            self.logger.error(e)

    def test_dslite(self):
        """ Test DS-Lite """
        nat_config = self.vapi.nat_show_config()
        self.assertEqual(0, nat_config.dslite_ce)

        self.vapi.dslite_add_del_pool_addr_range(self.nat_addr_n,
                                                 self.nat_addr_n)
        aftr_ip4 = '192.0.0.1'
        aftr_ip4_n = socket.inet_pton(socket.AF_INET, aftr_ip4)
        aftr_ip6 = '2001:db8:85a3::8a2e:370:1'
        aftr_ip6_n = socket.inet_pton(socket.AF_INET6, aftr_ip6)
        self.vapi.dslite_set_aftr_addr(aftr_ip6_n, aftr_ip4_n)
        self.vapi.syslog_set_sender(self.pg2.remote_ip4n, self.pg2.local_ip4n)

        # UDP
        p = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
             IPv6(dst=aftr_ip6, src=self.pg1.remote_hosts[0].ip6) /
             IP(dst=self.pg0.remote_ip4, src='192.168.1.1') /
             UDP(sport=20000, dport=10000))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(1)
        capture = capture[0]
        self.assertFalse(capture.haslayer(IPv6))
        self.assertEqual(capture[IP].src, self.nat_addr)
        self.assertEqual(capture[IP].dst, self.pg0.remote_ip4)
        self.assertNotEqual(capture[UDP].sport, 20000)
        self.assertEqual(capture[UDP].dport, 10000)
        self.assert_packet_checksums_valid(capture)
        out_port = capture[UDP].sport
        capture = self.pg2.get_capture(1)
        self.verify_syslog_apmadd(capture[0][Raw].load, '192.168.1.1',
                                  20000, self.nat_addr, out_port,
                                  self.pg1.remote_hosts[0].ip6, IP_PROTOS.udp)

        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(dst=self.nat_addr, src=self.pg0.remote_ip4) /
             UDP(sport=10000, dport=out_port))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(1)
        capture = capture[0]
        self.assertEqual(capture[IPv6].src, aftr_ip6)
        self.assertEqual(capture[IPv6].dst, self.pg1.remote_hosts[0].ip6)
        self.assertEqual(capture[IP].src, self.pg0.remote_ip4)
        self.assertEqual(capture[IP].dst, '192.168.1.1')
        self.assertEqual(capture[UDP].sport, 10000)
        self.assertEqual(capture[UDP].dport, 20000)
        self.assert_packet_checksums_valid(capture)

        # TCP
        p = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
             IPv6(dst=aftr_ip6, src=self.pg1.remote_hosts[1].ip6) /
             IP(dst=self.pg0.remote_ip4, src='192.168.1.1') /
             TCP(sport=20001, dport=10001))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(1)
        capture = capture[0]
        self.assertFalse(capture.haslayer(IPv6))
        self.assertEqual(capture[IP].src, self.nat_addr)
        self.assertEqual(capture[IP].dst, self.pg0.remote_ip4)
        self.assertNotEqual(capture[TCP].sport, 20001)
        self.assertEqual(capture[TCP].dport, 10001)
        self.assert_packet_checksums_valid(capture)
        out_port = capture[TCP].sport

        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(dst=self.nat_addr, src=self.pg0.remote_ip4) /
             TCP(sport=10001, dport=out_port))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(1)
        capture = capture[0]
        self.assertEqual(capture[IPv6].src, aftr_ip6)
        self.assertEqual(capture[IPv6].dst, self.pg1.remote_hosts[1].ip6)
        self.assertEqual(capture[IP].src, self.pg0.remote_ip4)
        self.assertEqual(capture[IP].dst, '192.168.1.1')
        self.assertEqual(capture[TCP].sport, 10001)
        self.assertEqual(capture[TCP].dport, 20001)
        self.assert_packet_checksums_valid(capture)

        # ICMP
        p = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
             IPv6(dst=aftr_ip6, src=self.pg1.remote_hosts[1].ip6) /
             IP(dst=self.pg0.remote_ip4, src='192.168.1.1') /
             ICMP(id=4000, type='echo-request'))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(1)
        capture = capture[0]
        self.assertFalse(capture.haslayer(IPv6))
        self.assertEqual(capture[IP].src, self.nat_addr)
        self.assertEqual(capture[IP].dst, self.pg0.remote_ip4)
        self.assertNotEqual(capture[ICMP].id, 4000)
        self.assert_packet_checksums_valid(capture)
        out_id = capture[ICMP].id

        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(dst=self.nat_addr, src=self.pg0.remote_ip4) /
             ICMP(id=out_id, type='echo-reply'))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(1)
        capture = capture[0]
        self.assertEqual(capture[IPv6].src, aftr_ip6)
        self.assertEqual(capture[IPv6].dst, self.pg1.remote_hosts[1].ip6)
        self.assertEqual(capture[IP].src, self.pg0.remote_ip4)
        self.assertEqual(capture[IP].dst, '192.168.1.1')
        self.assertEqual(capture[ICMP].id, 4000)
        self.assert_packet_checksums_valid(capture)

        # ping DS-Lite AFTR tunnel endpoint address
        p = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
             IPv6(src=self.pg1.remote_hosts[1].ip6, dst=aftr_ip6) /
             ICMPv6EchoRequest())
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(1)
        capture = capture[0]
        self.assertEqual(capture[IPv6].src, aftr_ip6)
        self.assertEqual(capture[IPv6].dst, self.pg1.remote_hosts[1].ip6)
        self.assertTrue(capture.haslayer(ICMPv6EchoReply))

        b4s = self.statistics.get_counter('/dslite/total-b4s')
        self.assertEqual(b4s[0][0], 2)
        sessions = self.statistics.get_counter('/dslite/total-sessions')
        self.assertEqual(sessions[0][0], 3)

    def tearDown(self):
        super(TestDSlite, self).tearDown()
        if not self.vpp_dead:
            self.logger.info(self.vapi.cli("show dslite pool"))
            self.logger.info(
                self.vapi.cli("show dslite aftr-tunnel-endpoint-address"))
            self.logger.info(self.vapi.cli("show dslite sessions"))


class TestDSliteCE(MethodHolder):
    """ DS-Lite CE Test Cases """

    @classmethod
    def setUpConstants(cls):
        super(TestDSliteCE, cls).setUpConstants()
        cls.vpp_cmdline.extend(["nat", "{", "dslite ce", "}"])

    @classmethod
    def setUpClass(cls):
        super(TestDSliteCE, cls).setUpClass()

        try:
            cls.create_pg_interfaces(range(2))
            cls.pg0.admin_up()
            cls.pg0.config_ip4()
            cls.pg0.resolve_arp()
            cls.pg1.admin_up()
            cls.pg1.config_ip6()
            cls.pg1.generate_remote_hosts(1)
            cls.pg1.configure_ipv6_neighbors()

        except Exception:
            super(TestDSliteCE, cls).tearDownClass()
            raise

    def test_dslite_ce(self):
        """ Test DS-Lite CE """

        nat_config = self.vapi.nat_show_config()
        self.assertEqual(1, nat_config.dslite_ce)

        b4_ip4 = '192.0.0.2'
        b4_ip4_n = socket.inet_pton(socket.AF_INET, b4_ip4)
        b4_ip6 = '2001:db8:62aa::375e:f4c1:1'
        b4_ip6_n = socket.inet_pton(socket.AF_INET6, b4_ip6)
        self.vapi.dslite_set_b4_addr(b4_ip6_n, b4_ip4_n)

        aftr_ip4 = '192.0.0.1'
        aftr_ip4_n = socket.inet_pton(socket.AF_INET, aftr_ip4)
        aftr_ip6 = '2001:db8:85a3::8a2e:370:1'
        aftr_ip6_n = socket.inet_pton(socket.AF_INET6, aftr_ip6)
        self.vapi.dslite_set_aftr_addr(aftr_ip6_n, aftr_ip4_n)

        self.vapi.ip_add_del_route(dst_address=aftr_ip6_n,
                                   dst_address_length=128,
                                   next_hop_address=self.pg1.remote_ip6n,
                                   next_hop_sw_if_index=self.pg1.sw_if_index,
                                   is_ipv6=1)

        # UDP encapsulation
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(dst=self.pg1.remote_ip4, src=self.pg0.remote_ip4) /
             UDP(sport=10000, dport=20000))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(1)
        capture = capture[0]
        self.assertEqual(capture[IPv6].src, b4_ip6)
        self.assertEqual(capture[IPv6].dst, aftr_ip6)
        self.assertEqual(capture[IP].src, self.pg0.remote_ip4)
        self.assertEqual(capture[IP].dst, self.pg1.remote_ip4)
        self.assertEqual(capture[UDP].sport, 10000)
        self.assertEqual(capture[UDP].dport, 20000)
        self.assert_packet_checksums_valid(capture)

        # UDP decapsulation
        p = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
             IPv6(dst=b4_ip6, src=aftr_ip6) /
             IP(dst=self.pg0.remote_ip4, src=self.pg1.remote_ip4) /
             UDP(sport=20000, dport=10000))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(1)
        capture = capture[0]
        self.assertFalse(capture.haslayer(IPv6))
        self.assertEqual(capture[IP].src, self.pg1.remote_ip4)
        self.assertEqual(capture[IP].dst, self.pg0.remote_ip4)
        self.assertEqual(capture[UDP].sport, 20000)
        self.assertEqual(capture[UDP].dport, 10000)
        self.assert_packet_checksums_valid(capture)

        # ping DS-Lite B4 tunnel endpoint address
        p = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
             IPv6(src=self.pg1.remote_hosts[0].ip6, dst=b4_ip6) /
             ICMPv6EchoRequest())
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(1)
        capture = capture[0]
        self.assertEqual(capture[IPv6].src, b4_ip6)
        self.assertEqual(capture[IPv6].dst, self.pg1.remote_hosts[0].ip6)
        self.assertTrue(capture.haslayer(ICMPv6EchoReply))

    def tearDown(self):
        super(TestDSliteCE, self).tearDown()
        if not self.vpp_dead:
            self.logger.info(
                self.vapi.cli("show dslite aftr-tunnel-endpoint-address"))
            self.logger.info(
                self.vapi.cli("show dslite b4-tunnel-endpoint-address"))


class TestNAT66(MethodHolder):
    """ NAT66 Test Cases """

    @classmethod
    def setUpClass(cls):
        super(TestNAT66, cls).setUpClass()

        try:
            cls.nat_addr = 'fd01:ff::2'
            cls.nat_addr_n = socket.inet_pton(socket.AF_INET6, cls.nat_addr)

            cls.create_pg_interfaces(range(2))
            cls.interfaces = list(cls.pg_interfaces)

            for i in cls.interfaces:
                i.admin_up()
                i.config_ip6()
                i.configure_ipv6_neighbors()

        except Exception:
            super(TestNAT66, cls).tearDownClass()
            raise

    def test_static(self):
        """ 1:1 NAT66 test """
        self.vapi.nat66_add_del_interface(self.pg0.sw_if_index)
        self.vapi.nat66_add_del_interface(self.pg1.sw_if_index, is_inside=0)
        self.vapi.nat66_add_del_static_mapping(self.pg0.remote_ip6n,
                                               self.nat_addr_n)

        # in2out
        pkts = []
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IPv6(src=self.pg0.remote_ip6, dst=self.pg1.remote_ip6) /
             TCP())
        pkts.append(p)
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IPv6(src=self.pg0.remote_ip6, dst=self.pg1.remote_ip6) /
             UDP())
        pkts.append(p)
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IPv6(src=self.pg0.remote_ip6, dst=self.pg1.remote_ip6) /
             ICMPv6EchoRequest())
        pkts.append(p)
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IPv6(src=self.pg0.remote_ip6, dst=self.pg1.remote_ip6) /
             GRE() / IP() / TCP())
        pkts.append(p)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        for packet in capture:
            try:
                self.assertEqual(packet[IPv6].src, self.nat_addr)
                self.assertEqual(packet[IPv6].dst, self.pg1.remote_ip6)
                self.assert_packet_checksums_valid(packet)
            except:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise

        # out2in
        pkts = []
        p = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
             IPv6(src=self.pg1.remote_ip6, dst=self.nat_addr) /
             TCP())
        pkts.append(p)
        p = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
             IPv6(src=self.pg1.remote_ip6, dst=self.nat_addr) /
             UDP())
        pkts.append(p)
        p = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
             IPv6(src=self.pg1.remote_ip6, dst=self.nat_addr) /
             ICMPv6EchoReply())
        pkts.append(p)
        p = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
             IPv6(src=self.pg1.remote_ip6, dst=self.nat_addr) /
             GRE() / IP() / TCP())
        pkts.append(p)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(len(pkts))
        for packet in capture:
            try:
                self.assertEqual(packet[IPv6].src, self.pg1.remote_ip6)
                self.assertEqual(packet[IPv6].dst, self.pg0.remote_ip6)
                self.assert_packet_checksums_valid(packet)
            except:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise

        sm = self.vapi.nat66_static_mapping_dump()
        self.assertEqual(len(sm), 1)
        self.assertEqual(sm[0].total_pkts, 8)

    def test_check_no_translate(self):
        """ NAT66 translate only when egress interface is outside interface """
        self.vapi.nat66_add_del_interface(self.pg0.sw_if_index)
        self.vapi.nat66_add_del_interface(self.pg1.sw_if_index)
        self.vapi.nat66_add_del_static_mapping(self.pg0.remote_ip6n,
                                               self.nat_addr_n)

        # in2out
        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IPv6(src=self.pg0.remote_ip6, dst=self.pg1.remote_ip6) /
             UDP())
        self.pg0.add_stream([p])
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(1)
        packet = capture[0]
        try:
            self.assertEqual(packet[IPv6].src, self.pg0.remote_ip6)
            self.assertEqual(packet[IPv6].dst, self.pg1.remote_ip6)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", packet))
            raise

    def clear_nat66(self):
        """
        Clear NAT66 configuration.
        """
        interfaces = self.vapi.nat66_interface_dump()
        for intf in interfaces:
            self.vapi.nat66_add_del_interface(intf.sw_if_index,
                                              intf.is_inside,
                                              is_add=0)

        static_mappings = self.vapi.nat66_static_mapping_dump()
        for sm in static_mappings:
            self.vapi.nat66_add_del_static_mapping(sm.local_ip_address,
                                                   sm.external_ip_address,
                                                   sm.vrf_id,
                                                   is_add=0)

    def tearDown(self):
        super(TestNAT66, self).tearDown()
        if not self.vpp_dead:
            self.logger.info(self.vapi.cli("show nat66 interfaces"))
            self.logger.info(self.vapi.cli("show nat66 static mappings"))
            self.clear_nat66()


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
