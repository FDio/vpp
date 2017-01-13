#!/usr/bin/env python

import socket
import unittest
import struct

from framework import VppTestCase, VppTestRunner
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
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

            for i in cls.overlapping_interfaces:
                i._local_ip4 = "172.16.255.1"
                i._local_ip4n = socket.inet_pton(socket.AF_INET, i.local_ip4)
                i._remote_hosts[0]._ip4 = "172.16.255.2"
                i.set_table_ip4(i.sw_if_index)
                i.config_ip4()
                i.admin_up()
                i.resolve_arp()

            cls.pg7.admin_up()

        except Exception:
            super(TestSNAT, cls).tearDownClass()
            raise

    def create_stream_in(self, in_if, out_if):
        """
        Create packet stream for inside network

        :param in_if: Inside interface
        :param out_if: Outside interface
        """
        pkts = []
        # TCP
        p = (Ether(dst=in_if.local_mac, src=in_if.remote_mac) /
             IP(src=in_if.remote_ip4, dst=out_if.remote_ip4) /
             TCP(sport=self.tcp_port_in))
        pkts.append(p)

        # UDP
        p = (Ether(dst=in_if.local_mac, src=in_if.remote_mac) /
             IP(src=in_if.remote_ip4, dst=out_if.remote_ip4) /
             UDP(sport=self.udp_port_in))
        pkts.append(p)

        # ICMP
        p = (Ether(dst=in_if.local_mac, src=in_if.remote_mac) /
             IP(src=in_if.remote_ip4, dst=out_if.remote_ip4) /
             ICMP(id=self.icmp_id_in, type='echo-request'))
        pkts.append(p)

        return pkts

    def create_stream_out(self, out_if, dst_ip=None):
        """
        Create packet stream for outside network

        :param out_if: Outside interface
        :param dst_ip: Destination IP address (Default use global SNAT address)
        """
        if dst_ip is None:
            dst_ip = self.snat_addr
        pkts = []
        # TCP
        p = (Ether(dst=out_if.local_mac, src=out_if.remote_mac) /
             IP(src=out_if.remote_ip4, dst=dst_ip) /
             TCP(dport=self.tcp_port_out))
        pkts.append(p)

        # UDP
        p = (Ether(dst=out_if.local_mac, src=out_if.remote_mac) /
             IP(src=out_if.remote_ip4, dst=dst_ip) /
             UDP(dport=self.udp_port_out))
        pkts.append(p)

        # ICMP
        p = (Ether(dst=out_if.local_mac, src=out_if.remote_mac) /
             IP(src=out_if.remote_ip4, dst=dst_ip) /
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
                                              is_add=0)

        adresses = self.vapi.snat_address_dump()
        for addr in adresses:
            self.vapi.snat_add_address_range(addr.ip_address,
                                             addr.ip_address,
                                             is_add=0)

    def snat_add_static_mapping(self, local_ip, external_ip, local_port=0,
                                external_port=0, vrf_id=0, is_add=1):
        """
        Add/delete S-NAT static mapping

        :param local_ip: Local IP address
        :param external_ip: External IP address
        :param local_port: Local port number (Optional)
        :param external_port: External port number (Optional)
        :param vrf_id: VRF ID (Default 0)
        :param is_add: 1 if add, 0 if delete (Default add)
        """
        addr_only = 1
        if local_port and external_port:
            addr_only = 0
        l_ip = socket.inet_pton(socket.AF_INET, local_ip)
        e_ip = socket.inet_pton(socket.AF_INET, external_ip)
        self.vapi.snat_add_static_mapping(
            l_ip,
            e_ip,
            local_port,
            external_port,
            addr_only,
            vrf_id,
            is_add)

    def snat_add_address(self, ip, is_add=1):
        """
        Add/delete S-NAT address

        :param ip: IP address
        :param is_add: 1 if add, 0 if delete (Default add)
        """
        snat_addr = socket.inet_pton(socket.AF_INET, ip)
        self.vapi.snat_add_address_range(snat_addr, snat_addr, is_add)

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
                                     self.tcp_port_in, self.tcp_port_out)
        self.snat_add_static_mapping(self.pg0.remote_ip4, self.snat_addr,
                                     self.udp_port_in, self.udp_port_out)
        self.snat_add_static_mapping(self.pg0.remote_ip4, self.snat_addr,
                                     self.icmp_id_in, self.icmp_id_out)
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
                                     self.tcp_port_in, self.tcp_port_out)
        self.snat_add_static_mapping(self.pg0.remote_ip4, self.snat_addr,
                                     self.udp_port_in, self.udp_port_out)
        self.snat_add_static_mapping(self.pg0.remote_ip4, self.snat_addr,
                                     self.icmp_id_in, self.icmp_id_out)
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
                                     vrf_id=self.pg4.sw_if_index)
        self.snat_add_static_mapping(self.pg0.remote_ip4, nat_ip2,
                                     vrf_id=self.pg4.sw_if_index)
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
        """
        SNAT multiple inside interfaces with non-overlapping address space
        """

        self.snat_add_address(self.snat_addr)
        self.vapi.snat_interface_add_del_feature(self.pg0.sw_if_index)
        self.vapi.snat_interface_add_del_feature(self.pg1.sw_if_index)
        self.vapi.snat_interface_add_del_feature(self.pg2.sw_if_index)
        self.vapi.snat_interface_add_del_feature(self.pg3.sw_if_index,
                                                 is_inside=0)

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

        # in2out 3rd interface
        pkts = self.create_stream_in(self.pg2, self.pg3)
        self.pg2.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg3.get_capture(len(pkts))
        self.verify_capture_out(capture)

        # out2in 3rd interface
        pkts = self.create_stream_out(self.pg3)
        self.pg3.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg2.get_capture(len(pkts))
        self.verify_capture_in(capture, self.pg2)

    def test_inside_overlapping_interfaces(self):
        """ SNAT multiple inside interfaces with overlapping address space """

        self.snat_add_address(self.snat_addr)
        self.vapi.snat_interface_add_del_feature(self.pg3.sw_if_index,
                                                 is_inside=0)
        self.vapi.snat_interface_add_del_feature(self.pg4.sw_if_index)
        self.vapi.snat_interface_add_del_feature(self.pg5.sw_if_index)
        self.vapi.snat_interface_add_del_feature(self.pg6.sw_if_index)

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

        # in2out 3rd interface
        pkts = self.create_stream_in(self.pg6, self.pg3)
        self.pg6.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg3.get_capture(len(pkts))
        self.verify_capture_out(capture)

        # out2in 3rd interface
        pkts = self.create_stream_out(self.pg3)
        self.pg3.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg6.get_capture(len(pkts))
        self.verify_capture_in(capture, self.pg6)

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
                                     server_in_port, server_out_port)

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

        # remove interface address and check NAT address pool
        self.pg7.unconfig_ip4()
        adresses = self.vapi.snat_address_dump()
        self.assertEqual(0, len(adresses))

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

    def tearDown(self):
        super(TestSNAT, self).tearDown()
        if not self.vpp_dead:
            self.logger.info(self.vapi.cli("show snat verbose"))
            self.clear_snat()


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
