#!/usr/bin/env python

import socket
import unittest
import struct
import StringIO
import random

from framework import VppTestCase, VppTestRunner, running_extended_tests
from vpp_ip_route import VppIpRoute, VppRoutePath, DpoProto
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet import IPerror, TCPerror, UDPerror, ICMPerror
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply
from scapy.layers.inet6 import ICMPv6DestUnreach, IPerror6, IPv6ExtHdrFragment
from scapy.layers.l2 import Ether, ARP, GRE
from scapy.data import IP_PROTOS
from scapy.packet import bind_layers, Raw
from scapy.all import fragment6
from util import ppp
from ipfix import IPFIX, Set, Template, Data, IPFIXDecoder
from time import sleep
from util import ip4_range
from util import mactobinary


class MethodHolder(VppTestCase):
    """ NAT create capture and verify method holder """

    @classmethod
    def setUpClass(cls):
        super(MethodHolder, cls).setUpClass()

    def tearDown(self):
        super(MethodHolder, self).tearDown()

    def check_ip_checksum(self, pkt):
        """
        Check IP checksum of the packet

        :param pkt: Packet to check IP checksum
        """
        new = pkt.__class__(str(pkt))
        del new['IP'].chksum
        new = new.__class__(str(new))
        self.assertEqual(new['IP'].chksum, pkt['IP'].chksum)

    def check_tcp_checksum(self, pkt):
        """
        Check TCP checksum in IP packet

        :param pkt: Packet to check TCP checksum
        """
        new = pkt.__class__(str(pkt))
        del new['TCP'].chksum
        new = new.__class__(str(new))
        self.assertEqual(new['TCP'].chksum, pkt['TCP'].chksum)

    def check_udp_checksum(self, pkt):
        """
        Check UDP checksum in IP packet

        :param pkt: Packet to check UDP checksum
        """
        new = pkt.__class__(str(pkt))
        del new['UDP'].chksum
        new = new.__class__(str(new))
        self.assertEqual(new['UDP'].chksum, pkt['UDP'].chksum)

    def check_icmp_errror_embedded(self, pkt):
        """
        Check ICMP error embeded packet checksum

        :param pkt: Packet to check ICMP error embeded packet checksum
        """
        if pkt.haslayer(IPerror):
            new = pkt.__class__(str(pkt))
            del new['IPerror'].chksum
            new = new.__class__(str(new))
            self.assertEqual(new['IPerror'].chksum, pkt['IPerror'].chksum)

        if pkt.haslayer(TCPerror):
            new = pkt.__class__(str(pkt))
            del new['TCPerror'].chksum
            new = new.__class__(str(new))
            self.assertEqual(new['TCPerror'].chksum, pkt['TCPerror'].chksum)

        if pkt.haslayer(UDPerror):
            if pkt['UDPerror'].chksum != 0:
                new = pkt.__class__(str(pkt))
                del new['UDPerror'].chksum
                new = new.__class__(str(new))
                self.assertEqual(new['UDPerror'].chksum,
                                 pkt['UDPerror'].chksum)

        if pkt.haslayer(ICMPerror):
            del new['ICMPerror'].chksum
            new = new.__class__(str(new))
            self.assertEqual(new['ICMPerror'].chksum, pkt['ICMPerror'].chksum)

    def check_icmp_checksum(self, pkt):
        """
        Check ICMP checksum in IPv4 packet

        :param pkt: Packet to check ICMP checksum
        """
        new = pkt.__class__(str(pkt))
        del new['ICMP'].chksum
        new = new.__class__(str(new))
        self.assertEqual(new['ICMP'].chksum, pkt['ICMP'].chksum)
        if pkt.haslayer(IPerror):
            self.check_icmp_errror_embedded(pkt)

    def check_icmpv6_checksum(self, pkt):
        """
        Check ICMPv6 checksum in IPv4 packet

        :param pkt: Packet to check ICMPv6 checksum
        """
        new = pkt.__class__(str(pkt))
        if pkt.haslayer(ICMPv6DestUnreach):
            del new['ICMPv6DestUnreach'].cksum
            new = new.__class__(str(new))
            self.assertEqual(new['ICMPv6DestUnreach'].cksum,
                             pkt['ICMPv6DestUnreach'].cksum)
            self.check_icmp_errror_embedded(pkt)
        if pkt.haslayer(ICMPv6EchoRequest):
            del new['ICMPv6EchoRequest'].cksum
            new = new.__class__(str(new))
            self.assertEqual(new['ICMPv6EchoRequest'].cksum,
                             pkt['ICMPv6EchoRequest'].cksum)
        if pkt.haslayer(ICMPv6EchoReply):
            del new['ICMPv6EchoReply'].cksum
            new = new.__class__(str(new))
            self.assertEqual(new['ICMPv6EchoReply'].cksum,
                             pkt['ICMPv6EchoReply'].cksum)

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
             TCP(sport=self.tcp_port_in, dport=20))
        pkts.append(p)

        # UDP
        p = (Ether(dst=in_if.local_mac, src=in_if.remote_mac) /
             IP(src=in_if.remote_ip4, dst=out_if.remote_ip4, ttl=ttl) /
             UDP(sport=self.udp_port_in, dport=20))
        pkts.append(p)

        # ICMP
        p = (Ether(dst=in_if.local_mac, src=in_if.remote_mac) /
             IP(src=in_if.remote_ip4, dst=out_if.remote_ip4, ttl=ttl) /
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
             TCP(dport=self.tcp_port_out, sport=20))
        pkts.append(p)

        # UDP
        p = (Ether(dst=out_if.local_mac, src=out_if.remote_mac) /
             IP(src=out_if.remote_ip4, dst=dst_ip, ttl=ttl) /
             UDP(dport=self.udp_port_out, sport=20))
        pkts.append(p)

        # ICMP
        p = (Ether(dst=out_if.local_mac, src=out_if.remote_mac) /
             IP(src=out_if.remote_ip4, dst=dst_ip, ttl=ttl) /
             ICMP(id=self.icmp_id_out, type='echo-reply'))
        pkts.append(p)

        return pkts

    def verify_capture_out(self, capture, nat_ip=None, same_port=False,
                           packet_num=3, dst_ip=None):
        """
        Verify captured packets on outside network

        :param capture: Captured packets
        :param nat_ip: Translated IP address (Default use global NAT address)
        :param same_port: Sorce port number is not translated (Default False)
        :param packet_num: Expected number of packets (Default 3)
        :param dst_ip: Destination IP address (Default do not verify)
        """
        if nat_ip is None:
            nat_ip = self.nat_addr
        self.assertEqual(packet_num, len(capture))
        for packet in capture:
            try:
                self.check_ip_checksum(packet)
                self.assertEqual(packet[IP].src, nat_ip)
                if dst_ip is not None:
                    self.assertEqual(packet[IP].dst, dst_ip)
                if packet.haslayer(TCP):
                    if same_port:
                        self.assertEqual(packet[TCP].sport, self.tcp_port_in)
                    else:
                        self.assertNotEqual(
                            packet[TCP].sport, self.tcp_port_in)
                    self.tcp_port_out = packet[TCP].sport
                    self.check_tcp_checksum(packet)
                elif packet.haslayer(UDP):
                    if same_port:
                        self.assertEqual(packet[UDP].sport, self.udp_port_in)
                    else:
                        self.assertNotEqual(
                            packet[UDP].sport, self.udp_port_in)
                    self.udp_port_out = packet[UDP].sport
                else:
                    if same_port:
                        self.assertEqual(packet[ICMP].id, self.icmp_id_in)
                    else:
                        self.assertNotEqual(packet[ICMP].id, self.icmp_id_in)
                    self.icmp_id_out = packet[ICMP].id
                    self.check_icmp_checksum(packet)
            except:
                self.logger.error(ppp("Unexpected or invalid packet "
                                      "(outside network):", packet))
                raise

    def verify_capture_in(self, capture, in_if, packet_num=3):
        """
        Verify captured packets on inside network

        :param capture: Captured packets
        :param in_if: Inside interface
        :param packet_num: Expected number of packets (Default 3)
        """
        self.assertEqual(packet_num, len(capture))
        for packet in capture:
            try:
                self.check_ip_checksum(packet)
                self.assertEqual(packet[IP].dst, in_if.remote_ip4)
                if packet.haslayer(TCP):
                    self.assertEqual(packet[TCP].dport, self.tcp_port_in)
                    self.check_tcp_checksum(packet)
                elif packet.haslayer(UDP):
                    self.assertEqual(packet[UDP].dport, self.udp_port_in)
                else:
                    self.assertEqual(packet[ICMP].id, self.icmp_id_in)
                    self.check_icmp_checksum(packet)
            except:
                self.logger.error(ppp("Unexpected or invalid packet "
                                      "(inside network):", packet))
                raise

    def verify_capture_in_ip6(self, capture, src_ip, dst_ip, packet_num=3):
        """
        Verify captured IPv6 packets on inside network

        :param capture: Captured packets
        :param src_ip: Source IP
        :param dst_ip: Destination IP address
        :param packet_num: Expected number of packets (Default 3)
        """
        self.assertEqual(packet_num, len(capture))
        for packet in capture:
            try:
                self.assertEqual(packet[IPv6].src, src_ip)
                self.assertEqual(packet[IPv6].dst, dst_ip)
                if packet.haslayer(TCP):
                    self.assertEqual(packet[TCP].dport, self.tcp_port_in)
                    self.check_tcp_checksum(packet)
                elif packet.haslayer(UDP):
                    self.assertEqual(packet[UDP].dport, self.udp_port_in)
                    self.check_udp_checksum(packet)
                else:
                    self.assertEqual(packet[ICMPv6EchoReply].id,
                                     self.icmp_id_in)
                    self.check_icmpv6_checksum(packet)
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
                                            packet_num=3, icmp_type=11):
        """
        Verify captured packets with ICMP errors on outside network

        :param capture: Captured packets
        :param src_ip: Translated IP address or IP address of VPP
                       (Default use global NAT address)
        :param packet_num: Expected number of packets (Default 3)
        :param icmp_type: Type of error ICMP packet
                          we are expecting (Default 11)
        """
        if src_ip is None:
            src_ip = self.nat_addr
        self.assertEqual(packet_num, len(capture))
        for packet in capture:
            try:
                self.assertEqual(packet[IP].src, src_ip)
                self.assertTrue(packet.haslayer(ICMP))
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

    def verify_capture_in_with_icmp_errors(self, capture, in_if, packet_num=3,
                                           icmp_type=11):
        """
        Verify captured packets with ICMP errors on inside network

        :param capture: Captured packets
        :param in_if: Inside interface
        :param packet_num: Expected number of packets (Default 3)
        :param icmp_type: Type of error ICMP packet
                          we are expecting (Default 11)
        """
        self.assertEqual(packet_num, len(capture))
        for packet in capture:
            try:
                self.assertEqual(packet[IP].dst, in_if.remote_ip4)
                self.assertTrue(packet.haslayer(ICMP))
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

    def create_stream_frag(self, src_if, dst, sport, dport, data):
        """
        Create fragmented packet stream

        :param src_if: Source interface
        :param dst: Destination IPv4 address
        :param sport: Source TCP port
        :param dport: Destination TCP port
        :param data: Payload data
        :returns: Fragmets
        """
        id = random.randint(0, 65535)
        p = (IP(src=src_if.remote_ip4, dst=dst) /
             TCP(sport=sport, dport=dport) /
             Raw(data))
        p = p.__class__(str(p))
        chksum = p['TCP'].chksum
        pkts = []
        p = (Ether(src=src_if.remote_mac, dst=src_if.local_mac) /
             IP(src=src_if.remote_ip4, dst=dst, flags="MF", frag=0, id=id) /
             TCP(sport=sport, dport=dport, chksum=chksum) /
             Raw(data[0:4]))
        pkts.append(p)
        p = (Ether(src=src_if.remote_mac, dst=src_if.local_mac) /
             IP(src=src_if.remote_ip4, dst=dst, flags="MF", frag=3, id=id,
                proto=IP_PROTOS.tcp) /
             Raw(data[4:20]))
        pkts.append(p)
        p = (Ether(src=src_if.remote_mac, dst=src_if.local_mac) /
             IP(src=src_if.remote_ip4, dst=dst, frag=5, proto=IP_PROTOS.tcp,
                id=id) /
             Raw(data[20:]))
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
        buffer = StringIO.StringIO()
        for p in frags:
            self.assertEqual(p[IP].src, src)
            self.assertEqual(p[IP].dst, dst)
            self.check_ip_checksum(p)
            buffer.seek(p[IP].frag * 8)
            buffer.write(p[IP].payload)
        ip = frags[0].getlayer(IP)
        ip = IP(src=frags[0][IP].src, dst=frags[0][IP].dst,
                proto=frags[0][IP].proto)
        if ip.proto == IP_PROTOS.tcp:
            p = (ip / TCP(buffer.getvalue()))
            self.check_tcp_checksum(p)
        elif ip.proto == IP_PROTOS.udp:
            p = (ip / UDP(buffer.getvalue()))
        return p

    def reass_frags_and_verify_ip6(self, frags, src, dst):
        """
        Reassemble and verify fragmented packet

        :param frags: Captured fragments
        :param src: Source IPv6 address to verify
        :param dst: Destination IPv6 address to verify

        :returns: Reassembled IPv6 packet
        """
        buffer = StringIO.StringIO()
        for p in frags:
            self.assertEqual(p[IPv6].src, src)
            self.assertEqual(p[IPv6].dst, dst)
            buffer.seek(p[IPv6ExtHdrFragment].offset * 8)
            buffer.write(p[IPv6ExtHdrFragment].payload)
        ip = IPv6(src=frags[0][IPv6].src, dst=frags[0][IPv6].dst,
                  nh=frags[0][IPv6ExtHdrFragment].nh)
        if ip.nh == IP_PROTOS.tcp:
            p = (ip / TCP(buffer.getvalue()))
            self.check_tcp_checksum(p)
        elif ip.nh == IP_PROTOS.udp:
            p = (ip / UDP(buffer.getvalue()))
        return p

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


class TestNAT44(MethodHolder):
    """ NAT44 Test Cases """

    @classmethod
    def setUpClass(cls):
        super(TestNAT44, cls).setUpClass()

        try:
            cls.tcp_port_in = 6303
            cls.tcp_port_out = 6303
            cls.udp_port_in = 6304
            cls.udp_port_out = 6304
            cls.icmp_id_in = 6305
            cls.icmp_id_out = 6305
            cls.nat_addr = '10.0.0.3'
            cls.ipfix_src_port = 4739
            cls.ipfix_domain_id = 1

            cls.create_pg_interfaces(range(10))
            cls.interfaces = list(cls.pg_interfaces[0:4])

            for i in cls.interfaces:
                i.admin_up()
                i.config_ip4()
                i.resolve_arp()

            cls.pg0.generate_remote_hosts(3)
            cls.pg0.configure_ipv4_neighbors()

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

    def clear_nat44(self):
        """
        Clear NAT44 configuration.
        """
        # I found no elegant way to do this
        self.vapi.ip_add_del_route(dst_address=self.pg7.remote_ip4n,
                                   dst_address_length=32,
                                   next_hop_address=self.pg7.remote_ip4n,
                                   next_hop_sw_if_index=self.pg7.sw_if_index,
                                   is_add=0)
        self.vapi.ip_add_del_route(dst_address=self.pg8.remote_ip4n,
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

        interfaces = self.vapi.nat44_interface_addr_dump()
        for intf in interfaces:
            self.vapi.nat44_add_interface_addr(intf.sw_if_index, is_add=0)

        self.vapi.nat_ipfix(enable=0, src_port=self.ipfix_src_port,
                            domain_id=self.ipfix_domain_id)
        self.ipfix_src_port = 4739
        self.ipfix_domain_id = 1

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
                is_add=0)

        lb_static_mappings = self.vapi.nat44_lb_static_mapping_dump()
        for lb_sm in lb_static_mappings:
            self.vapi.nat44_add_del_lb_static_mapping(
                lb_sm.external_addr,
                lb_sm.external_port,
                lb_sm.protocol,
                lb_sm.vrf_id,
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
                                                  is_add=0)

        self.vapi.nat_set_reass()
        self.vapi.nat_set_reass(is_ip6=1)

    def nat44_add_static_mapping(self, local_ip, external_ip='0.0.0.0',
                                 local_port=0, external_port=0, vrf_id=0,
                                 is_add=1, external_sw_if_index=0xFFFFFFFF,
                                 proto=0):
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
            is_add)

    def nat44_add_address(self, ip, is_add=1, vrf_id=0xFFFFFFFF):
        """
        Add/delete NAT44 address

        :param ip: IP address
        :param is_add: 1 if add, 0 if delete (Default add)
        """
        nat_addr = socket.inet_pton(socket.AF_INET, ip)
        self.vapi.nat44_add_del_address_range(nat_addr, nat_addr, is_add,
                                              vrf_id=vrf_id)

    def test_dynamic(self):
        """ NAT44 dynamic translation test """

        self.nat44_add_address(self.nat_addr)
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
        self.assertEqual(1, len(capture))
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
        self.verify_capture_in(capture, self.pg0, packet_num=1)
        self.assert_equal(capture[0][IP].proto, IP_PROTOS.icmp)

        # in2out
        pkt = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
               IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64) /
               ICMP(id=self.icmp_id_in, type='echo-reply'))
        self.pg0.add_stream(pkt)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(1)
        self.verify_capture_out(capture, same_port=True, packet_num=1)
        self.assert_equal(capture[0][IP].proto, IP_PROTOS.icmp)

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

        self.nat44_add_static_mapping(self.pg0.remote_ip4, nat_ip)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)

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
            self.check_tcp_checksum(p)
            self.check_ip_checksum(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

    def test_static_lb(self):
        """ NAT44 local service load balancing """
        external_addr_n = socket.inet_pton(socket.AF_INET, self.nat_addr)
        external_port = 80
        local_port = 8080
        server1 = self.pg0.remote_hosts[0]
        server2 = self.pg0.remote_hosts[1]

        locals = [{'addr': server1.ip4n,
                   'port': local_port,
                   'probability': 70},
                  {'addr': server2.ip4n,
                   'port': local_port,
                   'probability': 30}]

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
            self.check_tcp_checksum(p)
            self.check_ip_checksum(p)
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
            self.check_tcp_checksum(p)
            self.check_ip_checksum(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        # multiple clients
        server1_n = 0
        server2_n = 0
        clients = ip4_range(self.pg1.remote_ip4, 10, 20)
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
        self.assertTrue(server1_n > server2_n)

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
        self.assertTrue(len(users) >= 3)
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

        # pg4 session dump
        sessions = self.vapi.nat44_user_session_dump(self.pg4.remote_ip4n, 10)
        self.assertTrue(len(sessions) >= 4)
        for session in sessions:
            self.assertFalse(session.is_static)
            self.assertEqual(session.inside_ip_address[0:4],
                             self.pg4.remote_ip4n)
            self.assertEqual(session.outside_ip_address,
                             addresses[0].ip_address)

        # pg6 session dump
        sessions = self.vapi.nat44_user_session_dump(self.pg6.remote_ip4n, 20)
        self.assertTrue(len(sessions) >= 3)
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
            self.check_tcp_checksum(p)
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
            self.check_tcp_checksum(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:"), p)
            raise

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
                    self.check_tcp_checksum(packet)
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
                    self.check_tcp_checksum(packet)
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
                    self.check_tcp_checksum(packet)
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
                    self.check_tcp_checksum(packet)
                elif packet.haslayer(UDP):
                    self.assertEqual(packet[UDP].dport, self.udp_port_in)
                    self.assertEqual(packet[UDP].sport, server_udp_port)
                else:
                    self.assertEqual(packet[ICMP].id, self.icmp_id_in)
            except:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise

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
        self.vapi.nat44_add_interface_addr(self.pg7.sw_if_index)
        self.nat44_add_static_mapping(
            '1.2.3.4',
            external_sw_if_index=self.pg7.sw_if_index)

        # static mappings with external interface
        static_mappings = self.vapi.nat44_static_mapping_dump()
        self.assertEqual(1, len(static_mappings))
        self.assertEqual(self.pg7.sw_if_index,
                         static_mappings[0].external_sw_if_index)

        # configure interface address and check static mappings
        self.pg7.config_ip4()
        static_mappings = self.vapi.nat44_static_mapping_dump()
        self.assertEqual(1, len(static_mappings))
        self.assertEqual(static_mappings[0].external_ip_address[0:4],
                         self.pg7.local_ip4n)
        self.assertEqual(0xFFFFFFFF, static_mappings[0].external_sw_if_index)

        # remove interface address and check static mappings
        self.pg7.unconfig_ip4()
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
        self.assertEqual(1, len(identity_mappings))
        self.assertEqual(identity_mappings[0].ip_address,
                         self.pg7.local_ip4n)
        self.assertEqual(0xFFFFFFFF, identity_mappings[0].sw_if_index)
        self.assertEqual(port, identity_mappings[0].port)
        self.assertEqual(IP_PROTOS.tcp, identity_mappings[0].protocol)

        # remove interface address and check identity mappings
        self.pg7.unconfig_ip4()
        identity_mappings = self.vapi.nat44_identity_mapping_dump()
        self.assertEqual(0, len(identity_mappings))

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
        capture = self.pg3.get_capture(3)
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
        capture = self.pg1.get_capture(0)
        self.vapi.cli("ipfix flush")  # FIXME this should be an API call
        capture = self.pg3.get_capture(3)
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
        capture = self.pg1.get_capture(0)

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
        capture = self.pg1.get_capture(0)

        p = (Ether(src=self.pg1.remote_mac, dst='ff:ff:ff:ff:ff:ff') /
             ARP(op=ARP.who_has, pdst=static_addr,
                 psrc=self.pg1.remote_ip4, hwsrc=self.pg1.remote_mac))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(0)

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

        self.nat44_add_address(nat_ip1, vrf_id=vrf_id1)
        self.nat44_add_address(nat_ip2, vrf_id=vrf_id2)
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
        self.verify_capture_out(capture, nat_ip2)

        self.pg0.unconfig_ip4()
        self.pg1.unconfig_ip4()
        self.pg0.set_table_ip4(0)
        self.pg1.set_table_ip4(0)
        self.vapi.ip_table_add_del(vrf_id1, is_add=0)
        self.vapi.ip_table_add_del(vrf_id2, is_add=0)

    def test_vrf_feature_independent(self):
        """ NAT44 tenant VRF independent address pool mode """

        nat_ip1 = "10.0.0.10"
        nat_ip2 = "10.0.0.11"

        self.nat44_add_address(nat_ip1)
        self.nat44_add_address(nat_ip2)
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
                                      mactobinary(self.pg7.remote_mac),
                                      self.pg7.remote_ip4n,
                                      is_static=1)
        self.vapi.ip_neighbor_add_del(self.pg8.sw_if_index,
                                      mactobinary(self.pg8.remote_mac),
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
                                      mactobinary(self.pg7.remote_mac),
                                      self.pg7.remote_ip4n,
                                      is_static=1)
        self.vapi.ip_neighbor_add_del(self.pg8.sw_if_index,
                                      mactobinary(self.pg8.remote_mac),
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
                                      mactobinary(self.pg7.remote_mac),
                                      self.pg7.remote_ip4n,
                                      is_static=1)
        self.vapi.ip_neighbor_add_del(self.pg8.sw_if_index,
                                      mactobinary(self.pg8.remote_mac),
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
            self.assertTrue(packet.haslayer(GRE))
            self.check_ip_checksum(packet)
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
            self.assertTrue(packet.haslayer(GRE))
            self.check_ip_checksum(packet)
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
            self.assertTrue(packet.haslayer(GRE))
            self.check_ip_checksum(packet)
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
            self.assertTrue(packet.haslayer(GRE))
            self.check_ip_checksum(packet)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", packet))
            raise

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
             IP(src=self.pg2.remote_ip4, dst=self.pg3.remote_ip4) /
             TCP(sport=1234, dport=1234))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        p = self.pg1.get_capture(1)
        packet = p[0]
        try:
            self.assertEqual(packet[IP].src, self.nat_addr)
            self.assertEqual(packet[IP].dst, self.pg1.remote_ip4)
            self.assertTrue(packet.haslayer(GRE))
            self.check_ip_checksum(packet)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", packet))
            raise

        # out2in
        p = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
             IP(src=self.pg1.remote_ip4, dst=self.nat_addr) /
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
            self.assertTrue(packet.haslayer(GRE))
            self.check_ip_checksum(packet)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", packet))
            raise

    def test_hairpinning_unknown_proto(self):
        """ NAT44 translate packet with unknown protocol - hairpinning """
        host = self.pg0.remote_hosts[0]
        server = self.pg0.remote_hosts[1]
        host_in_port = 1234
        host_out_port = 0
        server_in_port = 5678
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
        capture = self.pg0.get_capture(1)

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
            self.assertEqual(packet[IP].src, self.nat_addr)
            self.assertEqual(packet[IP].dst, server.ip4)
            self.assertTrue(packet.haslayer(GRE))
            self.check_ip_checksum(packet)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", packet))
            raise

        # server to host
        p = (Ether(dst=self.pg0.local_mac, src=server.mac) /
             IP(src=server.ip4, dst=self.nat_addr) /
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
            self.assertTrue(packet.haslayer(GRE))
            self.check_ip_checksum(packet)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", packet))
            raise

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
            self.check_tcp_checksum(p)
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
            self.check_tcp_checksum(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:"), p)
            raise

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
            self.check_tcp_checksum(p)
            self.check_ip_checksum(p)
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
            self.check_tcp_checksum(p)
            self.check_ip_checksum(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

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
        capture = self.pg1.get_capture(len(pkts))

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

        data = "A" * 4 + "B" * 16 + "C" * 3
        self.tcp_port_in = random.randint(1025, 65535)

        reass = self.vapi.nat_reass_dump()
        reass_n_start = len(reass)

        # in2out
        pkts = self.create_stream_frag(self.pg0,
                                       self.pg1.remote_ip4,
                                       self.tcp_port_in,
                                       20,
                                       data)
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
        pkts = self.create_stream_frag(self.pg1,
                                       self.nat_addr,
                                       20,
                                       self.tcp_port_out,
                                       data)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        frags = self.pg0.get_capture(len(pkts))
        p = self.reass_frags_and_verify(frags,
                                        self.pg1.remote_ip4,
                                        self.pg0.remote_ip4)
        self.assertEqual(p[TCP].sport, 20)
        self.assertEqual(p[TCP].dport, self.tcp_port_in)
        self.assertEqual(data, p[Raw].load)

        reass = self.vapi.nat_reass_dump()
        reass_n_end = len(reass)

        self.assertEqual(reass_n_end - reass_n_start, 2)

    def test_reass_hairpinning(self):
        """ NAT44 fragments hairpinning """
        host = self.pg0.remote_hosts[0]
        server = self.pg0.remote_hosts[1]
        host_in_port = random.randint(1025, 65535)
        host_out_port = 0
        server_in_port = random.randint(1025, 65535)
        server_out_port = random.randint(1025, 65535)
        data = "A" * 4 + "B" * 16 + "C" * 3

        self.nat44_add_address(self.nat_addr)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)
        # add static mapping for server
        self.nat44_add_static_mapping(server.ip4, self.nat_addr,
                                      server_in_port, server_out_port,
                                      proto=IP_PROTOS.tcp)

        # send packet from host to server
        pkts = self.create_stream_frag(self.pg0,
                                       self.nat_addr,
                                       host_in_port,
                                       server_out_port,
                                       data)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        frags = self.pg0.get_capture(len(pkts))
        p = self.reass_frags_and_verify(frags,
                                        self.nat_addr,
                                        server.ip4)
        self.assertNotEqual(p[TCP].sport, host_in_port)
        self.assertEqual(p[TCP].dport, server_in_port)
        self.assertEqual(data, p[Raw].load)

    def test_frag_out_of_order(self):
        """ NAT44 translate fragments arriving out of order """
        self.nat44_add_address(self.nat_addr)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)

        data = "A" * 4 + "B" * 16 + "C" * 3
        random.randint(1025, 65535)

        # in2out
        pkts = self.create_stream_frag(self.pg0,
                                       self.pg1.remote_ip4,
                                       self.tcp_port_in,
                                       20,
                                       data)
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
        p = self.reass_frags_and_verify(frags,
                                        self.pg1.remote_ip4,
                                        self.pg0.remote_ip4)
        self.assertEqual(p[TCP].sport, 20)
        self.assertEqual(p[TCP].dport, self.tcp_port_in)
        self.assertEqual(data, p[Raw].load)

    def test_port_restricted(self):
        """ Port restricted NAT44 (MAP-E CE) """
        self.nat44_add_address(self.nat_addr)
        self.vapi.nat44_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.nat44_interface_add_del_feature(self.pg1.sw_if_index,
                                                  is_inside=0)
        self.vapi.cli("nat44 addr-port-assignment-alg map-e psid 10 "
                      "psid-offset 6 psid-len 6")

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
            self.check_tcp_checksum(p)
            self.check_ip_checksum(p)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

    def tearDown(self):
        super(TestNAT44, self).tearDown()
        if not self.vpp_dead:
            self.logger.info(self.vapi.cli("show nat44 verbose"))
            self.logger.info(self.vapi.cli("show nat virtual-reassembly"))
            self.vapi.cli("nat44 addr-port-assignment-alg default")
            self.clear_nat44()


class TestDeterministicNAT(MethodHolder):
    """ Deterministic NAT Test Cases """

    @classmethod
    def setUpConstants(cls):
        super(TestDeterministicNAT, cls).setUpConstants()
        cls.vpp_cmdline.extend(["nat", "{", "deterministic", "}"])

    @classmethod
    def setUpClass(cls):
        super(TestDeterministicNAT, cls).setUpClass()

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

    def verify_capture_out(self, capture, nat_ip=None, packet_num=3):
        """
        Verify captured packets on outside network

        :param capture: Captured packets
        :param nat_ip: Translated IP address (Default use global NAT address)
        :param same_port: Sorce port number is not translated (Default False)
        :param packet_num: Expected number of packets (Default 3)
        """
        if nat_ip is None:
            nat_ip = self.nat_addr
        self.assertEqual(packet_num, len(capture))
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

    def verify_ipfix_max_entries_per_user(self, data):
        """
        Verify IPFIX maximum entries per user exceeded event

        :param data: Decoded IPFIX data records
        """
        self.assertEqual(1, len(data))
        record = data[0]
        # natEvent
        self.assertEqual(ord(record[230]), 13)
        # natQuotaExceededEvent
        self.assertEqual('\x03\x00\x00\x00', record[466])
        # sourceIPv4Address
        self.assertEqual(self.pg0.remote_ip4n, record[8])

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
        timeouts_before = self.vapi.nat_det_get_timeouts()

        self.vapi.nat_det_set_timeouts(timeouts_before.udp + 10,
                                       timeouts_before.tcp_established + 10,
                                       timeouts_before.tcp_transitory + 10,
                                       timeouts_before.icmp + 10)

        timeouts_after = self.vapi.nat_det_get_timeouts()

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

    @unittest.skipUnless(running_extended_tests(), "part of extended tests")
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
        self.vapi.nat_det_set_timeouts(5, 5, 5, 5)
        pkts = self.create_stream_in(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        sleep(15)

        dms = self.vapi.nat_det_map_dump()
        self.assertEqual(0, dms[0].ses_num)

    @unittest.skipUnless(running_extended_tests(), "part of extended tests")
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
                self.verify_ipfix_max_entries_per_user(data)

    def clear_nat_det(self):
        """
        Clear deterministic NAT configuration.
        """
        self.vapi.nat_ipfix(enable=0)
        self.vapi.nat_det_set_timeouts()
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
            self.logger.info(self.vapi.cli("show nat44 detail"))
            self.clear_nat_det()


class TestNAT64(MethodHolder):
    """ NAT64 Test Cases """

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
            cls.nat_addr = '10.0.0.3'
            cls.nat_addr_n = socket.inet_pton(socket.AF_INET, cls.nat_addr)
            cls.vrf1_id = 10
            cls.vrf1_nat_addr = '10.0.10.3'
            cls.vrf1_nat_addr_n = socket.inet_pton(socket.AF_INET,
                                                   cls.vrf1_nat_addr)

            cls.create_pg_interfaces(range(5))
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

        except Exception:
            super(TestNAT64, cls).tearDownClass()
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

    def test_set_timeouts(self):
        """ Set NAT64 timeouts """
        # verify default values
        timeouts = self.vapi.nat64_get_timeouts()
        self.assertEqual(timeouts.udp, 300)
        self.assertEqual(timeouts.icmp, 60)
        self.assertEqual(timeouts.tcp_trans, 240)
        self.assertEqual(timeouts.tcp_est, 7440)
        self.assertEqual(timeouts.tcp_incoming_syn, 6)

        # set and verify custom values
        self.vapi.nat64_set_timeouts(udp=200, icmp=30, tcp_trans=250,
                                     tcp_est=7450, tcp_incoming_syn=10)
        timeouts = self.vapi.nat64_get_timeouts()
        self.assertEqual(timeouts.udp, 200)
        self.assertEqual(timeouts.icmp, 30)
        self.assertEqual(timeouts.tcp_trans, 250)
        self.assertEqual(timeouts.tcp_est, 7450)
        self.assertEqual(timeouts.tcp_incoming_syn, 10)

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
        ip = IPv6(src=''.join(['64:ff9b::', self.pg1.remote_ip4]))
        self.verify_capture_in_ip6(capture, ip[IPv6].src, self.pg0.remote_ip6)

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

    @unittest.skipUnless(running_extended_tests(), "part of extended tests")
    def test_session_timeout(self):
        """ NAT64 session timeout """
        self.icmp_id_in = 1234
        self.vapi.nat64_add_del_pool_addr_range(self.nat_addr_n,
                                                self.nat_addr_n)
        self.vapi.nat64_add_del_interface(self.pg0.sw_if_index)
        self.vapi.nat64_add_del_interface(self.pg1.sw_if_index, is_inside=0)
        self.vapi.nat64_set_timeouts(icmp=5)

        pkts = self.create_stream_in_ip6(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))

        ses_num_before_timeout = self.nat64_get_ses_num()

        sleep(15)

        # ICMP session after timeout
        ses_num_after_timeout = self.nat64_get_ses_num()
        self.assertNotEqual(ses_num_before_timeout, ses_num_after_timeout)

    def test_icmp_error(self):
        """ NAT64 ICMP Error message translation """
        self.tcp_port_in = 6303
        self.udp_port_in = 6304
        self.icmp_id_in = 6305

        ses_num_start = self.nat64_get_ses_num()

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
                self.check_icmp_checksum(packet)
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
                self.check_icmpv6_checksum(packet)
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
                if packet.haslayer(TCP):
                    self.assertNotEqual(packet[TCP].sport, client_tcp_in_port)
                    self.assertEqual(packet[TCP].dport, server_tcp_in_port)
                    self.check_tcp_checksum(packet)
                    client_tcp_out_port = packet[TCP].sport
                else:
                    self.assertNotEqual(packet[UDP].sport, client_udp_in_port)
                    self.assertEqual(packet[UDP].dport, server_udp_in_port)
                    self.check_udp_checksum(packet)
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
                if packet.haslayer(TCP):
                    self.assertEqual(packet[TCP].sport, server_tcp_out_port)
                    self.assertEqual(packet[TCP].dport, client_tcp_in_port)
                    self.check_tcp_checksum(packet)
                else:
                    self.assertEqual(packet[UDP].sport, server_udp_out_port)
                    self.assertEqual(packet[UDP].dport, client_udp_in_port)
                    self.check_udp_checksum(packet)
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
                self.check_icmpv6_checksum(packet)
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
            self.assertTrue(packet.haslayer(GRE))
            self.check_ip_checksum(packet)
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
            self.check_tcp_checksum(p)
            self.check_ip_checksum(p)
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
            self.check_tcp_checksum(p)
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
        client = self.pg0.remote_hosts[0]
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
        self.vapi.nat64_set_timeouts()

        interfaces = self.vapi.nat64_interface_dump()
        for intf in interfaces:
            if intf.is_inside > 1:
                self.vapi.nat64_add_del_interface(intf.sw_if_index,
                                                  0,
                                                  is_add=0)
            self.vapi.nat64_add_del_interface(intf.sw_if_index,
                                              intf.is_inside,
                                              is_add=0)

        bib = self.vapi.nat64_bib_dump(IP_PROTOS.tcp)
        for bibe in bib:
            if bibe.is_static:
                self.vapi.nat64_add_del_static_bib(bibe.i_addr,
                                                   bibe.o_addr,
                                                   bibe.i_port,
                                                   bibe.o_port,
                                                   bibe.proto,
                                                   bibe.vrf_id,
                                                   is_add=0)

        bib = self.vapi.nat64_bib_dump(IP_PROTOS.udp)
        for bibe in bib:
            if bibe.is_static:
                self.vapi.nat64_add_del_static_bib(bibe.i_addr,
                                                   bibe.o_addr,
                                                   bibe.i_port,
                                                   bibe.o_port,
                                                   bibe.proto,
                                                   bibe.vrf_id,
                                                   is_add=0)

        bib = self.vapi.nat64_bib_dump(IP_PROTOS.icmp)
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

            cls.create_pg_interfaces(range(2))
            cls.pg0.admin_up()
            cls.pg0.config_ip4()
            cls.pg0.resolve_arp()
            cls.pg1.admin_up()
            cls.pg1.config_ip6()
            cls.pg1.generate_remote_hosts(2)
            cls.pg1.configure_ipv6_neighbors()

        except Exception:
            super(TestDSlite, cls).tearDownClass()
            raise

    def test_dslite(self):
        """ Test DS-Lite """
        self.vapi.dslite_add_del_pool_addr_range(self.nat_addr_n,
                                                 self.nat_addr_n)
        aftr_ip4 = '192.0.0.1'
        aftr_ip4_n = socket.inet_pton(socket.AF_INET, aftr_ip4)
        aftr_ip6 = '2001:db8:85a3::8a2e:370:1'
        aftr_ip6_n = socket.inet_pton(socket.AF_INET6, aftr_ip6)
        self.vapi.dslite_set_aftr_addr(aftr_ip6_n, aftr_ip4_n)

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
        self.check_ip_checksum(capture)
        out_port = capture[UDP].sport

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
        self.check_ip_checksum(capture)

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
        self.check_ip_checksum(capture)
        self.check_tcp_checksum(capture)
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
        self.check_ip_checksum(capture)
        self.check_tcp_checksum(capture)

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
        self.check_ip_checksum(capture)
        self.check_icmp_checksum(capture)
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
        self.check_ip_checksum(capture)
        self.check_icmp_checksum(capture)

    def tearDown(self):
        super(TestDSlite, self).tearDown()
        if not self.vpp_dead:
            self.logger.info(self.vapi.cli("show dslite pool"))
            self.logger.info(
                self.vapi.cli("show dslite aftr-tunnel-endpoint-address"))
            self.logger.info(self.vapi.cli("show dslite sessions"))

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
