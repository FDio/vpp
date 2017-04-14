#!/usr/bin/env python

import socket
import unittest
import struct

from framework import VppTestCase, VppTestRunner
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet import IPerror, TCPerror, UDPerror, ICMPerror
from scapy.layers.l2 import Ether, ARP
from scapy.data import IP_PROTOS
from util import ppp
from ipfix import IPFIX, Set, Template, Data, IPFIXDecoder


class TestSNAT(VppTestCase):
    """ SNAT Test Cases """

    @classmethod
    def setUpClass(cls):
        super(TestSNAT, cls).setUpClass()

        try:
            cls.tcp_port_in = 6303
            cls.tcp_port_out = 6303
            cls.udp_port_in = 6304
            cls.udp_port_out = 6304
            cls.icmp_id_in = 6305
            cls.icmp_id_out = 6305
            cls.snat_addr = '10.0.0.3'

            cls.create_pg_interfaces(range(8))
            cls.interfaces = list(cls.pg_interfaces[0:4])

            for i in cls.interfaces:
                i.admin_up()
                i.config_ip4()
                i.resolve_arp()

            cls.pg0.generate_remote_hosts(2)
            cls.pg0.configure_ipv4_neighbors()

            cls.overlapping_interfaces = list(list(cls.pg_interfaces[4:7]))

            cls.pg4._local_ip4 = "172.16.255.1"
            cls.pg4._local_ip4n = socket.inet_pton(socket.AF_INET, i.local_ip4)
            cls.pg4._remote_hosts[0]._ip4 = "172.16.255.2"
            cls.pg4.set_table_ip4(10)
            cls.pg5._local_ip4 = "172.16.255.3"
            cls.pg5._local_ip4n = socket.inet_pton(socket.AF_INET, i.local_ip4)
            cls.pg5._remote_hosts[0]._ip4 = "172.16.255.4"
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

        except Exception:
            super(TestSNAT, cls).tearDownClass()
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
             TCP(sport=self.tcp_port_in))
        pkts.append(p)

        # UDP
        p = (Ether(dst=in_if.local_mac, src=in_if.remote_mac) /
             IP(src=in_if.remote_ip4, dst=out_if.remote_ip4, ttl=ttl) /
             UDP(sport=self.udp_port_in))
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
        :param dst_ip: Destination IP address (Default use global SNAT address)
        :param ttl: TTL of generated packets
        """
        if dst_ip is None:
            dst_ip = self.snat_addr
        pkts = []
        # TCP
        p = (Ether(dst=out_if.local_mac, src=out_if.remote_mac) /
             IP(src=out_if.remote_ip4, dst=dst_ip, ttl=ttl) /
             TCP(dport=self.tcp_port_out))
        pkts.append(p)

        # UDP
        p = (Ether(dst=out_if.local_mac, src=out_if.remote_mac) /
             IP(src=out_if.remote_ip4, dst=dst_ip, ttl=ttl) /
             UDP(dport=self.udp_port_out))
        pkts.append(p)

        # ICMP
        p = (Ether(dst=out_if.local_mac, src=out_if.remote_mac) /
             IP(src=out_if.remote_ip4, dst=dst_ip, ttl=ttl) /
             ICMP(id=self.icmp_id_out, type='echo-reply'))
        pkts.append(p)

        return pkts

    def verify_capture_out(self, capture, nat_ip=None, same_port=False,
                           packet_num=3):
        """
        Verify captured packets on outside network

        :param capture: Captured packets
        :param nat_ip: Translated IP address (Default use global SNAT address)
        :param same_port: Sorce port number is not translated (Default False)
        :param packet_num: Expected number of packets (Default 3)
        """
        if nat_ip is None:
            nat_ip = self.snat_addr
        self.assertEqual(packet_num, len(capture))
        for packet in capture:
            try:
                self.assertEqual(packet[IP].src, nat_ip)
                if packet.haslayer(TCP):
                    if same_port:
                        self.assertEqual(packet[TCP].sport, self.tcp_port_in)
                    else:
                        self.assertNotEqual(
                            packet[TCP].sport, self.tcp_port_in)
                    self.tcp_port_out = packet[TCP].sport
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
                       (Default use global SNAT address)
        :param packet_num: Expected number of packets (Default 3)
        :param icmp_type: Type of error ICMP packet
                          we are expecting (Default 11)
        """
        if src_ip is None:
            src_ip = self.snat_addr
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
            self.assertEqual(socket.inet_pton(socket.AF_INET, self.snat_addr),
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

    def clear_snat(self):
        """
        Clear SNAT configuration.
        """
        if self.pg7.has_ip4_config:
            self.pg7.unconfig_ip4()

        interfaces = self.vapi.snat_interface_addr_dump()
        for intf in interfaces:
            self.vapi.snat_add_interface_addr(intf.sw_if_index, is_add=0)

        self.vapi.snat_ipfix(enable=0)

        interfaces = self.vapi.snat_interface_dump()
        for intf in interfaces:
            self.vapi.snat_interface_add_del_feature(intf.sw_if_index,
                                                     intf.is_inside,
                                                     is_add=0)

        static_mappings = self.vapi.snat_static_mapping_dump()
        for sm in static_mappings:
            self.vapi.snat_add_static_mapping(sm.local_ip_address,
                                              sm.external_ip_address,
                                              local_port=sm.local_port,
                                              external_port=sm.external_port,
                                              addr_only=sm.addr_only,
                                              vrf_id=sm.vrf_id,
                                              protocol=sm.protocol,
                                              is_add=0)

        adresses = self.vapi.snat_address_dump()
        for addr in adresses:
            self.vapi.snat_add_address_range(addr.ip_address,
                                             addr.ip_address,
                                             is_add=0)

    def snat_add_static_mapping(self, local_ip, external_ip='0.0.0.0',
                                local_port=0, external_port=0, vrf_id=0,
                                is_add=1, external_sw_if_index=0xFFFFFFFF,
                                proto=0):
        """
        Add/delete S-NAT static mapping

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
        self.vapi.snat_add_static_mapping(
            l_ip,
            e_ip,
            external_sw_if_index,
            local_port,
            external_port,
            addr_only,
            vrf_id,
            proto,
            is_add)

    def snat_add_address(self, ip, is_add=1, vrf_id=0xFFFFFFFF):
        """
        Add/delete S-NAT address

        :param ip: IP address
        :param is_add: 1 if add, 0 if delete (Default add)
        """
        snat_addr = socket.inet_pton(socket.AF_INET, ip)
        self.vapi.snat_add_address_range(snat_addr, snat_addr, is_add,
                                         vrf_id=vrf_id)

    def test_dynamic(self):
        """ SNAT dynamic translation test """

        self.snat_add_address(self.snat_addr)
        self.vapi.snat_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.snat_interface_add_del_feature(self.pg1.sw_if_index,
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
        """ SNAT handling of client packets with TTL=1 """

        self.snat_add_address(self.snat_addr)
        self.vapi.snat_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.snat_interface_add_del_feature(self.pg1.sw_if_index,
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
        """ SNAT handling of server packets with TTL=1 """

        self.snat_add_address(self.snat_addr)
        self.vapi.snat_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.snat_interface_add_del_feature(self.pg1.sw_if_index,
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
        """ SNAT handling of error responses to client packets with TTL=2 """

        self.snat_add_address(self.snat_addr)
        self.vapi.snat_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.snat_interface_add_del_feature(self.pg1.sw_if_index,
                                                 is_inside=0)

        # Client side - generate traffic
        pkts = self.create_stream_in(self.pg0, self.pg1, ttl=2)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Server side - simulate ICMP type 11 response
        capture = self.pg1.get_capture(len(pkts))
        pkts = [Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
                IP(src=self.pg1.remote_ip4, dst=self.snat_addr) /
                ICMP(type=11) / packet[IP] for packet in capture]
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Client side - verify ICMP type 11 packets
        capture = self.pg0.get_capture(len(pkts))
        self.verify_capture_in_with_icmp_errors(capture, self.pg0)

    def test_dynamic_icmp_errors_out2in_ttl_2(self):
        """ SNAT handling of error responses to server packets with TTL=2 """

        self.snat_add_address(self.snat_addr)
        self.vapi.snat_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.snat_interface_add_del_feature(self.pg1.sw_if_index,
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
        """ Ping SNAT out interface from outside network """

        self.snat_add_address(self.snat_addr)
        self.vapi.snat_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.snat_interface_add_del_feature(self.pg1.sw_if_index,
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

        self.snat_add_static_mapping(self.pg0.remote_ip4, self.snat_addr)
        self.vapi.snat_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.snat_interface_add_del_feature(self.pg1.sw_if_index,
                                                 is_inside=0)

        # out2in
        pkt = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
               IP(src=self.pg1.remote_ip4, dst=self.snat_addr, ttl=64) /
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
        """ SNAT 1:1 NAT initialized from inside network """

        nat_ip = "10.0.0.10"
        self.tcp_port_out = 6303
        self.udp_port_out = 6304
        self.icmp_id_out = 6305

        self.snat_add_static_mapping(self.pg0.remote_ip4, nat_ip)
        self.vapi.snat_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.snat_interface_add_del_feature(self.pg1.sw_if_index,
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
        """ SNAT 1:1 NAT initialized from outside network """

        nat_ip = "10.0.0.20"
        self.tcp_port_out = 6303
        self.udp_port_out = 6304
        self.icmp_id_out = 6305

        self.snat_add_static_mapping(self.pg0.remote_ip4, nat_ip)
        self.vapi.snat_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.snat_interface_add_del_feature(self.pg1.sw_if_index,
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
        """ SNAT 1:1 NAT with port initialized from inside network """

        self.tcp_port_out = 3606
        self.udp_port_out = 3607
        self.icmp_id_out = 3608

        self.snat_add_address(self.snat_addr)
        self.snat_add_static_mapping(self.pg0.remote_ip4, self.snat_addr,
                                     self.tcp_port_in, self.tcp_port_out,
                                     proto=IP_PROTOS.tcp)
        self.snat_add_static_mapping(self.pg0.remote_ip4, self.snat_addr,
                                     self.udp_port_in, self.udp_port_out,
                                     proto=IP_PROTOS.udp)
        self.snat_add_static_mapping(self.pg0.remote_ip4, self.snat_addr,
                                     self.icmp_id_in, self.icmp_id_out,
                                     proto=IP_PROTOS.icmp)
        self.vapi.snat_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.snat_interface_add_del_feature(self.pg1.sw_if_index,
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
        """ SNAT 1:1 NAT with port initialized from outside network """

        self.tcp_port_out = 30606
        self.udp_port_out = 30607
        self.icmp_id_out = 30608

        self.snat_add_address(self.snat_addr)
        self.snat_add_static_mapping(self.pg0.remote_ip4, self.snat_addr,
                                     self.tcp_port_in, self.tcp_port_out,
                                     proto=IP_PROTOS.tcp)
        self.snat_add_static_mapping(self.pg0.remote_ip4, self.snat_addr,
                                     self.udp_port_in, self.udp_port_out,
                                     proto=IP_PROTOS.udp)
        self.snat_add_static_mapping(self.pg0.remote_ip4, self.snat_addr,
                                     self.icmp_id_in, self.icmp_id_out,
                                     proto=IP_PROTOS.icmp)
        self.vapi.snat_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.snat_interface_add_del_feature(self.pg1.sw_if_index,
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
        """ SNAT 1:1 NAT VRF awareness """

        nat_ip1 = "10.0.0.30"
        nat_ip2 = "10.0.0.40"
        self.tcp_port_out = 6303
        self.udp_port_out = 6304
        self.icmp_id_out = 6305

        self.snat_add_static_mapping(self.pg4.remote_ip4, nat_ip1,
                                     vrf_id=10)
        self.snat_add_static_mapping(self.pg0.remote_ip4, nat_ip2,
                                     vrf_id=10)
        self.vapi.snat_interface_add_del_feature(self.pg3.sw_if_index,
                                                 is_inside=0)
        self.vapi.snat_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.snat_interface_add_del_feature(self.pg4.sw_if_index)

        # inside interface VRF match SNAT static mapping VRF
        pkts = self.create_stream_in(self.pg4, self.pg3)
        self.pg4.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg3.get_capture(len(pkts))
        self.verify_capture_out(capture, nat_ip1, True)

        # inside interface VRF don't match SNAT static mapping VRF (packets
        # are dropped)
        pkts = self.create_stream_in(self.pg0, self.pg3)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg3.assert_nothing_captured()

    def test_multiple_inside_interfaces(self):
        """ SNAT multiple inside interfaces (non-overlapping address space) """

        self.snat_add_address(self.snat_addr)
        self.vapi.snat_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.snat_interface_add_del_feature(self.pg1.sw_if_index)
        self.vapi.snat_interface_add_del_feature(self.pg3.sw_if_index,
                                                 is_inside=0)

        # between two S-NAT inside interfaces (no translation)
        pkts = self.create_stream_in(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_no_translation(capture, self.pg0, self.pg1)

        # from S-NAT inside to interface without S-NAT feature (no translation)
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
        """ SNAT multiple inside interfaces with overlapping address space """

        static_nat_ip = "10.0.0.10"
        self.snat_add_address(self.snat_addr)
        self.vapi.snat_interface_add_del_feature(self.pg3.sw_if_index,
                                                 is_inside=0)
        self.vapi.snat_interface_add_del_feature(self.pg4.sw_if_index)
        self.vapi.snat_interface_add_del_feature(self.pg5.sw_if_index)
        self.vapi.snat_interface_add_del_feature(self.pg6.sw_if_index)
        self.snat_add_static_mapping(self.pg6.remote_ip4, static_nat_ip,
                                     vrf_id=20)

        # between S-NAT inside interfaces with same VRF (no translation)
        pkts = self.create_stream_in(self.pg4, self.pg5)
        self.pg4.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg5.get_capture(len(pkts))
        self.verify_capture_no_translation(capture, self.pg4, self.pg5)

        # between S-NAT inside interfaces with different VRF (hairpinning)
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
            self.assertEqual(ip.src, self.snat_addr)
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
        addresses = self.vapi.snat_address_dump()
        self.assertEqual(len(addresses), 1)
        sessions = self.vapi.snat_user_session_dump(self.pg5.remote_ip4n, 10)
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
        users = self.vapi.snat_user_dump()
        self.assertTrue(len(users) >= 3)
        addresses = self.vapi.snat_address_dump()
        self.assertEqual(len(addresses), 1)
        for user in users:
            sessions = self.vapi.snat_user_session_dump(user.ip_address,
                                                        user.vrf_id)
            for session in sessions:
                self.assertEqual(user.ip_address, session.inside_ip_address)
                self.assertTrue(session.total_bytes > session.total_pkts > 0)
                self.assertTrue(session.protocol in
                                [IP_PROTOS.tcp, IP_PROTOS.udp,
                                 IP_PROTOS.icmp])

        # pg4 session dump
        sessions = self.vapi.snat_user_session_dump(self.pg4.remote_ip4n, 10)
        self.assertTrue(len(sessions) >= 4)
        for session in sessions:
            self.assertFalse(session.is_static)
            self.assertEqual(session.inside_ip_address[0:4],
                             self.pg4.remote_ip4n)
            self.assertEqual(session.outside_ip_address,
                             addresses[0].ip_address)

        # pg6 session dump
        sessions = self.vapi.snat_user_session_dump(self.pg6.remote_ip4n, 20)
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
        """ SNAT hairpinning """

        host = self.pg0.remote_hosts[0]
        server = self.pg0.remote_hosts[1]
        host_in_port = 1234
        host_out_port = 0
        server_in_port = 5678
        server_out_port = 8765

        self.snat_add_address(self.snat_addr)
        self.vapi.snat_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.snat_interface_add_del_feature(self.pg1.sw_if_index,
                                                 is_inside=0)
        # add static mapping for server
        self.snat_add_static_mapping(server.ip4, self.snat_addr,
                                     server_in_port, server_out_port,
                                     proto=IP_PROTOS.tcp)

        # send packet from host to server
        p = (Ether(src=host.mac, dst=self.pg0.local_mac) /
             IP(src=host.ip4, dst=self.snat_addr) /
             TCP(sport=host_in_port, dport=server_out_port))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.src, self.snat_addr)
            self.assertEqual(ip.dst, server.ip4)
            self.assertNotEqual(tcp.sport, host_in_port)
            self.assertEqual(tcp.dport, server_in_port)
            host_out_port = tcp.sport
        except:
            self.logger.error(ppp("Unexpected or invalid packet:", p))
            raise

        # send reply from server to host
        p = (Ether(src=server.mac, dst=self.pg0.local_mac) /
             IP(src=server.ip4, dst=self.snat_addr) /
             TCP(sport=server_in_port, dport=host_out_port))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(1)
        p = capture[0]
        try:
            ip = p[IP]
            tcp = p[TCP]
            self.assertEqual(ip.src, self.snat_addr)
            self.assertEqual(ip.dst, host.ip4)
            self.assertEqual(tcp.sport, server_out_port)
            self.assertEqual(tcp.dport, host_in_port)
        except:
            self.logger.error(ppp("Unexpected or invalid packet:"), p)
            raise

    def test_max_translations_per_user(self):
        """ MAX translations per user - recycle the least recently used """

        self.snat_add_address(self.snat_addr)
        self.vapi.snat_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.snat_interface_add_del_feature(self.pg1.sw_if_index,
                                                 is_inside=0)

        # get maximum number of translations per user
        snat_config = self.vapi.snat_show_config()

        # send more than maximum number of translations per user packets
        pkts_num = snat_config.max_translations_per_user + 5
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
        """ Acquire SNAT addresses from interface """
        self.vapi.snat_add_interface_addr(self.pg7.sw_if_index)

        # no address in NAT pool
        adresses = self.vapi.snat_address_dump()
        self.assertEqual(0, len(adresses))

        # configure interface address and check NAT address pool
        self.pg7.config_ip4()
        adresses = self.vapi.snat_address_dump()
        self.assertEqual(1, len(adresses))
        self.assertEqual(adresses[0].ip_address[0:4], self.pg7.local_ip4n)

        # remove interface address and check NAT address pool
        self.pg7.unconfig_ip4()
        adresses = self.vapi.snat_address_dump()
        self.assertEqual(0, len(adresses))

    def test_interface_addr_static_mapping(self):
        """ Static mapping with addresses from interface """
        self.vapi.snat_add_interface_addr(self.pg7.sw_if_index)
        self.snat_add_static_mapping('1.2.3.4',
                                     external_sw_if_index=self.pg7.sw_if_index)

        # static mappings with external interface
        static_mappings = self.vapi.snat_static_mapping_dump()
        self.assertEqual(1, len(static_mappings))
        self.assertEqual(self.pg7.sw_if_index,
                         static_mappings[0].external_sw_if_index)

        # configure interface address and check static mappings
        self.pg7.config_ip4()
        static_mappings = self.vapi.snat_static_mapping_dump()
        self.assertEqual(1, len(static_mappings))
        self.assertEqual(static_mappings[0].external_ip_address[0:4],
                         self.pg7.local_ip4n)
        self.assertEqual(0xFFFFFFFF, static_mappings[0].external_sw_if_index)

        # remove interface address and check static mappings
        self.pg7.unconfig_ip4()
        static_mappings = self.vapi.snat_static_mapping_dump()
        self.assertEqual(0, len(static_mappings))

    def test_ipfix_nat44_sess(self):
        """ S-NAT IPFIX logging NAT44 session created/delted """
        self.snat_add_address(self.snat_addr)
        self.vapi.snat_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.snat_interface_add_del_feature(self.pg1.sw_if_index,
                                                 is_inside=0)
        self.vapi.set_ipfix_exporter(collector_address=self.pg3.remote_ip4n,
                                     src_address=self.pg3.local_ip4n,
                                     path_mtu=512,
                                     template_interval=10)
        self.vapi.snat_ipfix()

        pkts = self.create_stream_in(self.pg0, self.pg1)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_out(capture)
        self.snat_add_address(self.snat_addr, is_add=0)
        self.vapi.cli("ipfix flush")  # FIXME this should be an API call
        capture = self.pg3.get_capture(3)
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
                self.verify_ipfix_nat44_ses(data)

    def test_ipfix_addr_exhausted(self):
        """ S-NAT IPFIX logging NAT addresses exhausted """
        self.vapi.snat_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.snat_interface_add_del_feature(self.pg1.sw_if_index,
                                                 is_inside=0)
        self.vapi.set_ipfix_exporter(collector_address=self.pg3.remote_ip4n,
                                     src_address=self.pg3.local_ip4n,
                                     path_mtu=512,
                                     template_interval=10)
        self.vapi.snat_ipfix()

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
            if p.haslayer(Template):
                ipfix.add_template(p.getlayer(Template))
        # verify events in data set
        for p in capture:
            if p.haslayer(Data):
                data = ipfix.decode_data_set(p.getlayer(Set))
                self.verify_ipfix_addr_exhausted(data)

    def test_pool_addr_fib(self):
        """ S-NAT add pool addresses to FIB """
        static_addr = '10.0.0.10'
        self.snat_add_address(self.snat_addr)
        self.vapi.snat_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.snat_interface_add_del_feature(self.pg1.sw_if_index,
                                                 is_inside=0)
        self.snat_add_static_mapping(self.pg0.remote_ip4, static_addr)

        # SNAT address
        p = (Ether(src=self.pg1.remote_mac, dst='ff:ff:ff:ff:ff:ff') /
             ARP(op=ARP.who_has, pdst=self.snat_addr,
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

        # send ARP to non-SNAT interface
        p = (Ether(src=self.pg2.remote_mac, dst='ff:ff:ff:ff:ff:ff') /
             ARP(op=ARP.who_has, pdst=self.snat_addr,
                 psrc=self.pg2.remote_ip4, hwsrc=self.pg2.remote_mac))
        self.pg2.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(0)

        # remove addresses and verify
        self.snat_add_address(self.snat_addr, is_add=0)
        self.snat_add_static_mapping(self.pg0.remote_ip4, static_addr,
                                     is_add=0)

        p = (Ether(src=self.pg1.remote_mac, dst='ff:ff:ff:ff:ff:ff') /
             ARP(op=ARP.who_has, pdst=self.snat_addr,
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
        """ S-NAT tenant VRF aware address pool mode """

        vrf_id1 = 1
        vrf_id2 = 2
        nat_ip1 = "10.0.0.10"
        nat_ip2 = "10.0.0.11"

        self.pg0.unconfig_ip4()
        self.pg1.unconfig_ip4()
        self.pg0.set_table_ip4(vrf_id1)
        self.pg1.set_table_ip4(vrf_id2)
        self.pg0.config_ip4()
        self.pg1.config_ip4()

        self.snat_add_address(nat_ip1, vrf_id=vrf_id1)
        self.snat_add_address(nat_ip2, vrf_id=vrf_id2)
        self.vapi.snat_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.snat_interface_add_del_feature(self.pg1.sw_if_index)
        self.vapi.snat_interface_add_del_feature(self.pg2.sw_if_index,
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

    def test_vrf_feature_independent(self):
        """ S-NAT tenant VRF independent address pool mode """

        nat_ip1 = "10.0.0.10"
        nat_ip2 = "10.0.0.11"

        self.snat_add_address(nat_ip1)
        self.snat_add_address(nat_ip2)
        self.vapi.snat_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.snat_interface_add_del_feature(self.pg1.sw_if_index)
        self.vapi.snat_interface_add_del_feature(self.pg2.sw_if_index,
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

    def tearDown(self):
        super(TestSNAT, self).tearDown()
        if not self.vpp_dead:
            self.logger.info(self.vapi.cli("show snat verbose"))
            self.clear_snat()


class TestDeterministicNAT(VppTestCase):
    """ Deterministic NAT Test Cases """

    @classmethod
    def setUpConstants(cls):
        super(TestDeterministicNAT, cls).setUpConstants()
        cls.vpp_cmdline.extend(["snat", "{", "deterministic", "}"])

    @classmethod
    def setUpClass(cls):
        super(TestDeterministicNAT, cls).setUpClass()

        try:
            cls.create_pg_interfaces(range(2))
            cls.interfaces = list(cls.pg_interfaces)

            for i in cls.interfaces:
                i.admin_up()
                i.config_ip4()
                i.resolve_arp()

        except Exception:
            super(TestDeterministicNAT, cls).tearDownClass()
            raise

    def test_deterministic_mode(self):
        """ S-NAT run deterministic mode """
        in_addr = '172.16.255.0'
        out_addr = '172.17.255.50'
        in_addr_t = '172.16.255.20'
        in_addr_n = socket.inet_aton(in_addr)
        out_addr_n = socket.inet_aton(out_addr)
        in_addr_t_n = socket.inet_aton(in_addr_t)
        in_plen = 24
        out_plen = 32

        snat_config = self.vapi.snat_show_config()
        self.assertEqual(1, snat_config.deterministic)

        self.vapi.snat_add_det_map(in_addr_n, in_plen, out_addr_n, out_plen)

        rep1 = self.vapi.snat_det_forward(in_addr_t_n)
        self.assertEqual(rep1.out_addr[:4], out_addr_n)
        rep2 = self.vapi.snat_det_reverse(out_addr_n, rep1.out_port_hi)
        self.assertEqual(rep2.in_addr[:4], in_addr_t_n)

        deterministic_mappings = self.vapi.snat_det_map_dump()
        self.assertEqual(len(deterministic_mappings), 1)
        dsm = deterministic_mappings[0]
        self.assertEqual(in_addr_n, dsm.in_addr[:4])
        self.assertEqual(in_plen, dsm.in_plen)
        self.assertEqual(out_addr_n, dsm.out_addr[:4])
        self.assertEqual(out_plen, dsm.out_plen)

        self.clear_snat()
        deterministic_mappings = self.vapi.snat_det_map_dump()
        self.assertEqual(len(deterministic_mappings), 0)

    def clear_snat(self):
        """
        Clear SNAT configuration.
        """
        deterministic_mappings = self.vapi.snat_det_map_dump()
        for dsm in deterministic_mappings:
            self.vapi.snat_add_det_map(dsm.in_addr,
                                       dsm.in_plen,
                                       dsm.out_addr,
                                       dsm.out_plen,
                                       is_add=0)

    def tearDown(self):
        super(TestDeterministicNAT, self).tearDown()
        if not self.vpp_dead:
            self.logger.info(self.vapi.cli("show snat detail"))
            self.clear_snat()

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
