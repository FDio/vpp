#!/usr/bin/env python3

import unittest
from io import BytesIO
from random import randint

import scapy.compat
from framework import VppTestCase, VppTestRunner
from scapy.data import IP_PROTOS
from scapy.layers.inet import IP, TCP, UDP, ICMP, GRE
from scapy.layers.inet import IPerror, TCPerror
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from syslog_rfc5424_parser import SyslogMessage, ParseError
from syslog_rfc5424_parser.constants import SyslogSeverity
from util import ppp, ip4_range
from vpp_acl import AclRule, VppAcl, VppAclInterface
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_papi import VppEnum


class NAT44EDTestCase(VppTestCase):

    nat_addr = '10.0.0.3'

    tcp_port_in = 6303
    tcp_port_out = 6303

    udp_port_in = 6304
    udp_port_out = 6304

    icmp_id_in = 6305
    icmp_id_out = 6305

    tcp_external_port = 80

    max_sessions = 100

    def setUp(self):
        super(NAT44EDTestCase, self).setUp()
        self.plugin_enable()

    def tearDown(self):
        super(NAT44EDTestCase, self).tearDown()
        if not self.vpp_dead:
            self.plugin_disable()

    def plugin_enable(self):
        self.vapi.nat44_ed_plugin_enable_disable(
            sessions=self.max_sessions, enable=1)

    def plugin_disable(self):
        self.vapi.nat44_ed_plugin_enable_disable(enable=0)

    @property
    def config_flags(self):
        return VppEnum.vl_api_nat_config_flags_t

    @property
    def nat44_config_flags(self):
        return VppEnum.vl_api_nat44_config_flags_t

    @property
    def syslog_severity(self):
        return VppEnum.vl_api_syslog_severity_t

    @property
    def server_addr(self):
        return self.pg1.remote_hosts[0].ip4

    @staticmethod
    def random_port():
        return randint(1025, 65535)

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

    @classmethod
    def create_and_add_ip4_table(cls, i, table_id=0):
        cls.vapi.ip_table_add_del(is_add=1, table={'table_id': table_id})
        i.set_table_ip4(table_id)

    @classmethod
    def configure_ip4_interface(cls, i, hosts=0, table_id=None):
        if table_id:
            cls.create_and_add_ip4_table(i, table_id)

        i.admin_up()
        i.unconfig_ip4()
        i.config_ip4()
        i.resolve_arp()

        if hosts:
            i.generate_remote_hosts(hosts)
            i.configure_ipv4_neighbors()

    @classmethod
    def nat_add_interface_address(cls, i):
        cls.vapi.nat44_add_del_interface_addr(
            sw_if_index=i.sw_if_index, is_add=1)

    def nat_add_inside_interface(self, i):
        self.vapi.nat44_interface_add_del_feature(
            flags=self.config_flags.NAT_IS_INSIDE,
            sw_if_index=i.sw_if_index, is_add=1)

    def nat_add_outside_interface(self, i):
        self.vapi.nat44_interface_add_del_feature(
            flags=self.config_flags.NAT_IS_OUTSIDE,
            sw_if_index=i.sw_if_index, is_add=1)

    def nat_add_address(self, address, twice_nat=0,
                        vrf_id=0xFFFFFFFF, is_add=1):
        flags = self.config_flags.NAT_IS_TWICE_NAT if twice_nat else 0
        self.vapi.nat44_add_del_address_range(first_ip_address=address,
                                              last_ip_address=address,
                                              vrf_id=vrf_id,
                                              is_add=is_add,
                                              flags=flags)

    def nat_add_static_mapping(self, local_ip, external_ip='0.0.0.0',
                               local_port=0, external_port=0, vrf_id=0,
                               is_add=1, external_sw_if_index=0xFFFFFFFF,
                               proto=0, tag="", flags=0):

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

    @classmethod
    def setUpClass(cls):
        super(NAT44EDTestCase, cls).setUpClass()

        cls.create_pg_interfaces(range(12))
        cls.interfaces = list(cls.pg_interfaces[:4])

        cls.create_and_add_ip4_table(cls.pg2, 10)

        for i in cls.interfaces:
            cls.configure_ip4_interface(i, hosts=3)

        # test specific (test-multiple-vrf)
        cls.vapi.ip_table_add_del(is_add=1, table={'table_id': 1})

        # test specific (test-one-armed-nat44-static)
        cls.pg4.generate_remote_hosts(2)
        cls.pg4.config_ip4()
        cls.vapi.sw_interface_add_del_address(
            sw_if_index=cls.pg4.sw_if_index,
            prefix="10.0.0.1/24")
        cls.pg4.admin_up()
        cls.pg4.resolve_arp()
        cls.pg4._remote_hosts[1]._ip4 = cls.pg4._remote_hosts[0]._ip4
        cls.pg4.resolve_arp()

        # test specific interface (pg5)
        cls.pg5._local_ip4 = "10.1.1.1"
        cls.pg5._remote_hosts[0]._ip4 = "10.1.1.2"
        cls.pg5.set_table_ip4(1)
        cls.pg5.config_ip4()
        cls.pg5.admin_up()
        cls.pg5.resolve_arp()

        # test specific interface (pg6)
        cls.pg6._local_ip4 = "10.1.2.1"
        cls.pg6._remote_hosts[0]._ip4 = "10.1.2.2"
        cls.pg6.set_table_ip4(1)
        cls.pg6.config_ip4()
        cls.pg6.admin_up()
        cls.pg6.resolve_arp()

        rl = list()

        rl.append(VppIpRoute(cls, "0.0.0.0", 0,
                             [VppRoutePath("0.0.0.0", 0xffffffff,
                                           nh_table_id=0)],
                             register=False, table_id=1))
        rl.append(VppIpRoute(cls, "0.0.0.0", 0,
                             [VppRoutePath(cls.pg1.local_ip4,
                                           cls.pg1.sw_if_index)],
                             register=False))
        rl.append(VppIpRoute(cls, cls.pg5.remote_ip4, 32,
                             [VppRoutePath("0.0.0.0",
                                           cls.pg5.sw_if_index)],
                             register=False, table_id=1))
        rl.append(VppIpRoute(cls, cls.pg6.remote_ip4, 32,
                             [VppRoutePath("0.0.0.0",
                                           cls.pg6.sw_if_index)],
                             register=False, table_id=1))
        rl.append(VppIpRoute(cls, cls.pg6.remote_ip4, 16,
                             [VppRoutePath("0.0.0.0", 0xffffffff,
                                           nh_table_id=1)],
                             register=False, table_id=0))

        for r in rl:
            r.add_vpp_config()

    def get_err_counter(self, path):
        return self.statistics.get_err_counter(path)

    def get_stats_counter(self, path, worker=0):
        return self.statistics.get_counter(path)[worker]

    def reass_hairpinning(self, server_addr, server_in_port, server_out_port,
                          host_in_port, proto=IP_PROTOS.tcp,
                          ignore_port=False):
        layer = self.proto2layer(proto)

        if proto == IP_PROTOS.tcp:
            data = b"A" * 4 + b"B" * 16 + b"C" * 3
        else:
            data = b"A" * 16 + b"B" * 16 + b"C" * 3

        # send packet from host to server
        pkts = self.create_stream_frag(self.pg0,
                                       self.nat_addr,
                                       host_in_port,
                                       server_out_port,
                                       data,
                                       proto)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        frags = self.pg0.get_capture(len(pkts))
        p = self.reass_frags_and_verify(frags,
                                        self.nat_addr,
                                        server_addr)
        if proto != IP_PROTOS.icmp:
            if not ignore_port:
                self.assertNotEqual(p[layer].sport, host_in_port)
            self.assertEqual(p[layer].dport, server_in_port)
        else:
            if not ignore_port:
                self.assertNotEqual(p[layer].id, host_in_port)
        self.assertEqual(data, p[Raw].load)

    def frag_out_of_order(self, proto=IP_PROTOS.tcp, dont_translate=False,
                          ignore_port=False):
        layer = self.proto2layer(proto)

        if proto == IP_PROTOS.tcp:
            data = b"A" * 4 + b"B" * 16 + b"C" * 3
        else:
            data = b"A" * 16 + b"B" * 16 + b"C" * 3
        self.port_in = self.random_port()

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
            self.logger.info(self.vapi.cli("show trace"))
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

    def reass_frags_and_verify(self, frags, src, dst):
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

    def frag_in_order(self, proto=IP_PROTOS.tcp, dont_translate=False,
                      ignore_port=False):
        layer = self.proto2layer(proto)

        if proto == IP_PROTOS.tcp:
            data = b"A" * 4 + b"B" * 16 + b"C" * 3
        else:
            data = b"A" * 16 + b"B" * 16 + b"C" * 3
        self.port_in = self.random_port()

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

    def verify_capture_out(self, capture, nat_ip=None, same_port=False,
                           dst_ip=None, ignore_port=False):
        if nat_ip is None:
            nat_ip = self.nat_addr
        for packet in capture:
            try:
                self.assert_packet_checksums_valid(packet)
                self.assertEqual(packet[IP].src, nat_ip)
                if dst_ip is not None:
                    self.assertEqual(packet[IP].dst, dst_ip)
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
                                packet[ICMP].id, self.icmp_id_in)
                        else:
                            self.assertNotEqual(
                                packet[ICMP].id, self.icmp_id_in)
                    self.icmp_id_out = packet[ICMP].id
                    self.assert_packet_checksums_valid(packet)
            except:
                self.logger.error(ppp("Unexpected or invalid packet "
                                      "(outside network):", packet))
                raise

    def verify_capture_in(self, capture, in_if):
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

    def create_stream_in(self, in_if, out_if, dst_ip=None, ttl=64):
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

    def create_stream_out(self, out_if, dst_ip=None, ttl=64,
                          use_inside_ports=False):
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

    def create_tcp_stream(self, in_if, out_if, count):
        pkts = []
        port = 6303

        for i in range(count):
            p = (Ether(dst=in_if.local_mac, src=in_if.remote_mac) /
                 IP(src=in_if.remote_ip4, dst=out_if.remote_ip4, ttl=64) /
                 TCP(sport=port + i, dport=20))
            pkts.append(p)

        return pkts

    def create_stream_frag(self, src_if, dst, sport, dport, data,
                           proto=IP_PROTOS.tcp, echo_reply=False):
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
        id = self.random_port()
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

    def frag_in_order_in_plus_out(self, in_addr, out_addr, in_port, out_port,
                                  proto=IP_PROTOS.tcp):

        layer = self.proto2layer(proto)

        if proto == IP_PROTOS.tcp:
            data = b"A" * 4 + b"B" * 16 + b"C" * 3
        else:
            data = b"A" * 16 + b"B" * 16 + b"C" * 3
        port_in = self.random_port()

        for i in range(2):
            # out2in
            pkts = self.create_stream_frag(self.pg0, out_addr,
                                           port_in, out_port,
                                           data, proto)
            self.pg0.add_stream(pkts)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            frags = self.pg1.get_capture(len(pkts))
            p = self.reass_frags_and_verify(frags,
                                            self.pg0.remote_ip4,
                                            in_addr)
            if proto != IP_PROTOS.icmp:
                self.assertEqual(p[layer].sport, port_in)
                self.assertEqual(p[layer].dport, in_port)
            else:
                self.assertEqual(p[layer].id, port_in)
            self.assertEqual(data, p[Raw].load)

            # in2out
            if proto != IP_PROTOS.icmp:
                pkts = self.create_stream_frag(self.pg1, self.pg0.remote_ip4,
                                               in_port,
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
                                            out_addr,
                                            self.pg0.remote_ip4)
            if proto != IP_PROTOS.icmp:
                self.assertEqual(p[layer].sport, out_port)
                self.assertEqual(p[layer].dport, port_in)
            else:
                self.assertEqual(p[layer].id, port_in)
            self.assertEqual(data, p[Raw].load)

    def frag_out_of_order_in_plus_out(self, in_addr, out_addr, in_port,
                                      out_port, proto=IP_PROTOS.tcp):

        layer = self.proto2layer(proto)

        if proto == IP_PROTOS.tcp:
            data = b"A" * 4 + b"B" * 16 + b"C" * 3
        else:
            data = b"A" * 16 + b"B" * 16 + b"C" * 3
        port_in = self.random_port()

        for i in range(2):
            # out2in
            pkts = self.create_stream_frag(self.pg0, out_addr,
                                           port_in, out_port,
                                           data, proto)
            pkts.reverse()
            self.pg0.add_stream(pkts)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            frags = self.pg1.get_capture(len(pkts))
            p = self.reass_frags_and_verify(frags,
                                            self.pg0.remote_ip4,
                                            in_addr)
            if proto != IP_PROTOS.icmp:
                self.assertEqual(p[layer].dport, in_port)
                self.assertEqual(p[layer].sport, port_in)
                self.assertEqual(p[layer].dport, in_port)
            else:
                self.assertEqual(p[layer].id, port_in)
            self.assertEqual(data, p[Raw].load)

            # in2out
            if proto != IP_PROTOS.icmp:
                pkts = self.create_stream_frag(self.pg1, self.pg0.remote_ip4,
                                               in_port,
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
                                            out_addr,
                                            self.pg0.remote_ip4)
            if proto != IP_PROTOS.icmp:
                self.assertEqual(p[layer].sport, out_port)
                self.assertEqual(p[layer].dport, port_in)
            else:
                self.assertEqual(p[layer].id, port_in)
            self.assertEqual(data, p[Raw].load)

    def init_tcp_session(self, in_if, out_if, in_port, ext_port):
        # SYN packet in->out
        p = (Ether(src=in_if.remote_mac, dst=in_if.local_mac) /
             IP(src=in_if.remote_ip4, dst=out_if.remote_ip4) /
             TCP(sport=in_port, dport=ext_port, flags="S"))
        in_if.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = out_if.get_capture(1)
        p = capture[0]
        out_port = p[TCP].sport

        # SYN + ACK packet out->in
        p = (Ether(src=out_if.remote_mac, dst=out_if.local_mac) /
             IP(src=out_if.remote_ip4, dst=self.nat_addr) /
             TCP(sport=ext_port, dport=out_port, flags="SA"))
        out_if.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        in_if.get_capture(1)

        # ACK packet in->out
        p = (Ether(src=in_if.remote_mac, dst=in_if.local_mac) /
             IP(src=in_if.remote_ip4, dst=out_if.remote_ip4) /
             TCP(sport=in_port, dport=ext_port, flags="A"))
        in_if.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        out_if.get_capture(1)

        return out_port

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

        self.nat_add_address(self.nat_addr)
        self.nat_add_address(twice_nat_addr, twice_nat=1)

        flags = 0
        if self_twice_nat:
            flags |= self.config_flags.NAT_IS_SELF_TWICE_NAT
        else:
            flags |= self.config_flags.NAT_IS_TWICE_NAT

        if not lb:
            self.nat_add_static_mapping(pg0.remote_ip4, self.nat_addr,
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
        self.nat_add_inside_interface(pg0)
        self.nat_add_outside_interface(pg1)

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
            self.logger.info(self.vapi.cli("show nat44 sessions"))
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


class TestNAT44ED(NAT44EDTestCase):
    """ NAT44ED Test Case """

    def test_users_dump(self):
        """ NAT44ED API test - nat44_user_dump """

        self.nat_add_address(self.nat_addr)
        self.nat_add_inside_interface(self.pg0)
        self.nat_add_outside_interface(self.pg1)

        self.vapi.nat44_forwarding_enable_disable(enable=1)

        local_ip = self.pg0.remote_ip4
        external_ip = self.nat_addr
        self.nat_add_static_mapping(local_ip, external_ip)

        users = self.vapi.nat44_user_dump()
        self.assertEqual(len(users), 0)

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

        # in2out - no static mapping match (forwarding test)

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

    def test_frag_out_of_order_do_not_translate(self):
        """ NAT44ED don't translate fragments arriving out of order """
        self.nat_add_inside_interface(self.pg0)
        self.nat_add_outside_interface(self.pg1)
        self.vapi.nat44_forwarding_enable_disable(enable=True)
        self.frag_out_of_order(proto=IP_PROTOS.tcp, dont_translate=True)

    def test_forwarding(self):
        """ NAT44ED forwarding test """

        self.nat_add_inside_interface(self.pg0)
        self.nat_add_outside_interface(self.pg1)
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

    def test_output_feature_and_service2(self):
        """ NAT44ED interface output feature and service host direct access """
        self.vapi.nat44_forwarding_enable_disable(enable=1)
        self.nat_add_address(self.nat_addr)

        self.vapi.nat44_interface_add_del_output_feature(
            sw_if_index=self.pg1.sw_if_index, is_add=1,)

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
        tcp_port_in = self.tcp_port_in
        udp_port_in = self.udp_port_in
        icmp_id_in = self.icmp_id_in

        self.tcp_port_in = 60303
        self.udp_port_in = 60304
        self.icmp_id_in = 60305

        try:
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
        finally:
            self.tcp_port_in = tcp_port_in
            self.udp_port_in = udp_port_in
            self.icmp_id_in = icmp_id_in

    def test_twice_nat(self):
        """ NAT44ED Twice NAT """
        self.twice_nat_common()

    def test_self_twice_nat_positive(self):
        """ NAT44ED Self Twice NAT (positive test) """
        self.twice_nat_common(self_twice_nat=True, same_pg=True)

    def test_self_twice_nat_lb_positive(self):
        """ NAT44ED Self Twice NAT local service load balancing (positive test)
        """
        self.twice_nat_common(lb=True, self_twice_nat=True, same_pg=True,
                              client_id=1)

    def test_twice_nat_lb(self):
        """ NAT44ED Twice NAT local service load balancing """
        self.twice_nat_common(lb=True)

    def test_output_feature(self):
        """ NAT44ED interface output feature (in2out postrouting) """
        self.vapi.nat44_forwarding_enable_disable(enable=1)
        self.nat_add_address(self.nat_addr)

        self.nat_add_outside_interface(self.pg0)
        self.vapi.nat44_interface_add_del_output_feature(
            sw_if_index=self.pg1.sw_if_index, is_add=1)

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

    def test_static_with_port_out2(self):
        """ NAT44ED 1:1 NAPT asymmetrical rule """

        external_port = 80
        local_port = 8080

        self.vapi.nat44_forwarding_enable_disable(enable=1)
        flags = self.config_flags.NAT_IS_OUT2IN_ONLY
        self.nat_add_static_mapping(self.pg0.remote_ip4, self.nat_addr,
                                    local_port, external_port,
                                    proto=IP_PROTOS.tcp, flags=flags)

        self.nat_add_inside_interface(self.pg0)
        self.nat_add_outside_interface(self.pg1)

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

    def test_static_lb(self):
        """ NAT44ED local service load balancing """
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

        self.nat_add_address(self.nat_addr)
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

    def test_static_lb_2(self):
        """ NAT44ED local service load balancing (asymmetrical rule) """
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
        """ NAT44ED local service load balancing affinity """
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

        self.nat_add_address(self.nat_addr)
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

    def test_multiple_vrf(self):
        """ NAT44ED Multiple VRF setup """

        external_addr = '1.2.3.4'
        external_port = 80
        local_port = 8080
        port = 0

        self.vapi.nat44_forwarding_enable_disable(enable=1)
        self.nat_add_address(self.nat_addr)
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
        self.nat_add_static_mapping(self.pg5.remote_ip4, external_addr,
                                    local_port, external_port, vrf_id=1,
                                    proto=IP_PROTOS.tcp, flags=flags)
        self.nat_add_static_mapping(
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

    def test_outside_address_distribution(self):
        """ Outside address distribution based on source address """

        x = 100
        nat_addresses = []

        for i in range(1, x):
            a = "10.0.0.%d" % i
            nat_addresses.append(a)

        self.nat_add_inside_interface(self.pg0)
        self.nat_add_outside_interface(self.pg1)

        self.vapi.nat44_add_del_address_range(
            first_ip_address=nat_addresses[0],
            last_ip_address=nat_addresses[-1],
            vrf_id=0xFFFFFFFF, is_add=1, flags=0)

        self.pg0.generate_remote_hosts(x)

        pkts = []
        for i in range(x):
            info = self.create_packet_info(self.pg0, self.pg1)
            payload = self.info_to_payload(info)
            p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                 IP(src=self.pg0.remote_hosts[i].ip4,
                     dst=self.pg1.remote_ip4) /
                 UDP(sport=7000+i, dport=8000+i) /
                 Raw(payload))
            info.data = p
            pkts.append(p)

        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        recvd = self.pg1.get_capture(len(pkts))
        for p_recvd in recvd:
            payload_info = self.payload_to_info(p_recvd[Raw])
            packet_index = payload_info.index
            info = self._packet_infos[packet_index]
            self.assertTrue(info is not None)
            self.assertEqual(packet_index, info.index)
            p_sent = info.data
            packed = socket.inet_aton(p_sent[IP].src)
            numeric = struct.unpack("!L", packed)[0]
            numeric = socket.htonl(numeric)
            a = nat_addresses[(numeric-1) % len(nat_addresses)]
            self.assertEqual(
                a, p_recvd[IP].src,
                "Invalid packet (src IP %s translated to %s, but expected %s)"
                % (p_sent[IP].src, p_recvd[IP].src, a))


class TestNAT44EDMW(TestNAT44ED):
    """ NAT44ED MW Test Case """
    worker_config = "workers 1"

    def get_stats_counter(self, path, worker=1):
        return super(TestNAT44EDMW, self).get_stats_counter(path, worker)

    @unittest.skip('MW fix required')
    def test_users_dump(self):
        """ NAT44ED API test - nat44_user_dump """

    @unittest.skip('MW fix required')
    def test_frag_out_of_order_do_not_translate(self):
        """ NAT44ED don't translate fragments arriving out of order """

    @unittest.skip('MW fix required')
    def test_forwarding(self):
        """ NAT44ED forwarding test """

    @unittest.skip('MW fix required')
    def test_twice_nat(self):
        """ NAT44ED Twice NAT """

    @unittest.skip('MW fix required')
    def test_twice_nat_lb(self):
        """ NAT44ED Twice NAT local service load balancing """

    @unittest.skip('MW fix required')
    def test_output_feature(self):
        """ NAT44ED interface output feature (in2out postrouting) """

    @unittest.skip('MW fix required')
    def test_static_with_port_out2(self):
        """ NAT44ED 1:1 NAPT asymmetrical rule """

    @unittest.skip('MW fix required')
    def test_output_feature_and_service2(self):
        """ NAT44ED interface output feature and service host direct access """

    @unittest.skip('MW fix required')
    def test_static_lb(self):
        """ NAT44ED local service load balancing """

    @unittest.skip('MW fix required')
    def test_static_lb_2(self):
        """ NAT44ED local service load balancing (asymmetrical rule) """

    @unittest.skip('MW fix required')
    def test_lb_affinity(self):
        """ NAT44ED local service load balancing affinity """

    @unittest.skip('MW fix required')
    def test_multiple_vrf(self):
        """ NAT44ED Multiple VRF setup """

    @unittest.skip('MW fix required')
    def test_self_twice_nat_positive(self):
        """ NAT44ED Self Twice NAT (positive test) """

    @unittest.skip('MW fix required')
    def test_self_twice_nat_lb_positive(self):
        """ NAT44ED Self Twice NAT local service load balancing (positive test)
        """

    def test_dynamic(self):
        """ NAT44ED dynamic translation test """

        self.nat_add_address(self.nat_addr)
        self.nat_add_inside_interface(self.pg0)
        self.nat_add_outside_interface(self.pg1)

        # in2out
        tc1 = self.get_stats_counter('/nat44-ed/in2out/slowpath/tcp')
        uc1 = self.get_stats_counter('/nat44-ed/in2out/slowpath/udp')
        ic1 = self.get_stats_counter('/nat44-ed/in2out/slowpath/icmp')
        dc1 = self.get_stats_counter('/nat44-ed/in2out/slowpath/drops')

        pkts = self.create_stream_in(self.pg0, self.pg1)
        # TODO: specify worker=idx, also stats have to
        #       know from which worker to take capture
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_out(capture, ignore_port=True)

        if_idx = self.pg0.sw_if_index
        tc2 = self.get_stats_counter('/nat44-ed/in2out/slowpath/tcp')
        uc2 = self.get_stats_counter('/nat44-ed/in2out/slowpath/udp')
        ic2 = self.get_stats_counter('/nat44-ed/in2out/slowpath/icmp')
        dc2 = self.get_stats_counter('/nat44-ed/in2out/slowpath/drops')

        self.assertEqual(tc2[if_idx] - tc1[if_idx], 2)
        self.assertEqual(uc2[if_idx] - uc1[if_idx], 1)
        self.assertEqual(ic2[if_idx] - ic1[if_idx], 1)
        self.assertEqual(dc2[if_idx] - dc1[if_idx], 0)

        # out2in
        tc1 = self.get_stats_counter('/nat44-ed/out2in/fastpath/tcp')
        uc1 = self.get_stats_counter('/nat44-ed/out2in/fastpath/udp')
        ic1 = self.get_stats_counter('/nat44-ed/out2in/fastpath/icmp')
        dc1 = self.get_stats_counter('/nat44-ed/out2in/fastpath/drops')

        pkts = self.create_stream_out(self.pg1)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(len(pkts))
        self.verify_capture_in(capture, self.pg0)

        if_idx = self.pg1.sw_if_index
        tc2 = self.get_stats_counter('/nat44-ed/out2in/fastpath/tcp')
        uc2 = self.get_stats_counter('/nat44-ed/out2in/fastpath/udp')
        ic2 = self.get_stats_counter('/nat44-ed/out2in/fastpath/icmp')
        dc2 = self.get_stats_counter('/nat44-ed/out2in/fastpath/drops')

        self.assertEqual(tc2[if_idx] - tc1[if_idx], 2)
        self.assertEqual(uc2[if_idx] - uc1[if_idx], 1)
        self.assertEqual(ic2[if_idx] - ic1[if_idx], 1)
        self.assertEqual(dc2[if_idx] - dc1[if_idx], 0)

        sc = self.get_stats_counter('/nat44-ed/total-sessions')
        self.assertEqual(sc[0], 3)

    def test_frag_in_order(self):
        """ NAT44ED translate fragments arriving in order """

        self.nat_add_address(self.nat_addr)
        self.nat_add_inside_interface(self.pg0)
        self.nat_add_outside_interface(self.pg1)

        self.frag_in_order(proto=IP_PROTOS.tcp, ignore_port=True)
        self.frag_in_order(proto=IP_PROTOS.udp, ignore_port=True)
        self.frag_in_order(proto=IP_PROTOS.icmp, ignore_port=True)

    def test_frag_in_order_do_not_translate(self):
        """ NAT44ED don't translate fragments arriving in order """

        self.nat_add_address(self.nat_addr)
        self.nat_add_inside_interface(self.pg0)
        self.nat_add_outside_interface(self.pg1)
        self.vapi.nat44_forwarding_enable_disable(enable=True)

        self.frag_in_order(proto=IP_PROTOS.tcp, dont_translate=True)

    def test_frag_out_of_order(self):
        """ NAT44ED translate fragments arriving out of order """

        self.nat_add_address(self.nat_addr)
        self.nat_add_inside_interface(self.pg0)
        self.nat_add_outside_interface(self.pg1)

        self.frag_out_of_order(proto=IP_PROTOS.tcp, ignore_port=True)
        self.frag_out_of_order(proto=IP_PROTOS.udp, ignore_port=True)
        self.frag_out_of_order(proto=IP_PROTOS.icmp, ignore_port=True)

    def test_frag_in_order_in_plus_out(self):
        """ NAT44ED in+out interface fragments in order """

        in_port = self.random_port()
        out_port = self.random_port()

        self.nat_add_address(self.nat_addr)
        self.nat_add_inside_interface(self.pg0)
        self.nat_add_outside_interface(self.pg0)
        self.nat_add_inside_interface(self.pg1)
        self.nat_add_outside_interface(self.pg1)

        # add static mappings for server
        self.nat_add_static_mapping(self.server_addr,
                                    self.nat_addr,
                                    in_port,
                                    out_port,
                                    proto=IP_PROTOS.tcp)
        self.nat_add_static_mapping(self.server_addr,
                                    self.nat_addr,
                                    in_port,
                                    out_port,
                                    proto=IP_PROTOS.udp)
        self.nat_add_static_mapping(self.server_addr,
                                    self.nat_addr,
                                    proto=IP_PROTOS.icmp)

        # run tests for each protocol
        self.frag_in_order_in_plus_out(self.server_addr,
                                       self.nat_addr,
                                       in_port,
                                       out_port,
                                       IP_PROTOS.tcp)
        self.frag_in_order_in_plus_out(self.server_addr,
                                       self.nat_addr,
                                       in_port,
                                       out_port,
                                       IP_PROTOS.udp)
        self.frag_in_order_in_plus_out(self.server_addr,
                                       self.nat_addr,
                                       in_port,
                                       out_port,
                                       IP_PROTOS.icmp)

    def test_frag_out_of_order_in_plus_out(self):
        """ NAT44ED in+out interface fragments out of order """

        in_port = self.random_port()
        out_port = self.random_port()

        self.nat_add_address(self.nat_addr)
        self.nat_add_inside_interface(self.pg0)
        self.nat_add_outside_interface(self.pg0)
        self.nat_add_inside_interface(self.pg1)
        self.nat_add_outside_interface(self.pg1)

        # add static mappings for server
        self.nat_add_static_mapping(self.server_addr,
                                    self.nat_addr,
                                    in_port,
                                    out_port,
                                    proto=IP_PROTOS.tcp)
        self.nat_add_static_mapping(self.server_addr,
                                    self.nat_addr,
                                    in_port,
                                    out_port,
                                    proto=IP_PROTOS.udp)
        self.nat_add_static_mapping(self.server_addr,
                                    self.nat_addr,
                                    proto=IP_PROTOS.icmp)

        # run tests for each protocol
        self.frag_out_of_order_in_plus_out(self.server_addr,
                                           self.nat_addr,
                                           in_port,
                                           out_port,
                                           IP_PROTOS.tcp)
        self.frag_out_of_order_in_plus_out(self.server_addr,
                                           self.nat_addr,
                                           in_port,
                                           out_port,
                                           IP_PROTOS.udp)
        self.frag_out_of_order_in_plus_out(self.server_addr,
                                           self.nat_addr,
                                           in_port,
                                           out_port,
                                           IP_PROTOS.icmp)

    def test_reass_hairpinning(self):
        """ NAT44ED fragments hairpinning """

        server_addr = self.pg0.remote_hosts[1].ip4

        host_in_port = self.random_port()
        server_in_port = self.random_port()
        server_out_port = self.random_port()

        self.nat_add_address(self.nat_addr)
        self.nat_add_inside_interface(self.pg0)
        self.nat_add_outside_interface(self.pg1)

        # add static mapping for server
        self.nat_add_static_mapping(server_addr, self.nat_addr,
                                    server_in_port, server_out_port,
                                    proto=IP_PROTOS.tcp)
        self.nat_add_static_mapping(server_addr, self.nat_addr,
                                    server_in_port, server_out_port,
                                    proto=IP_PROTOS.udp)
        self.nat_add_static_mapping(server_addr, self.nat_addr)

        self.reass_hairpinning(server_addr, server_in_port, server_out_port,
                               host_in_port, proto=IP_PROTOS.tcp,
                               ignore_port=True)
        self.reass_hairpinning(server_addr, server_in_port, server_out_port,
                               host_in_port, proto=IP_PROTOS.udp,
                               ignore_port=True)
        self.reass_hairpinning(server_addr, server_in_port, server_out_port,
                               host_in_port, proto=IP_PROTOS.icmp,
                               ignore_port=True)

    def test_session_limit_per_vrf(self):
        """ NAT44ED per vrf session limit """

        inside = self.pg0
        inside_vrf10 = self.pg2
        outside = self.pg1

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
        # self.nat_add_address(outside.local_ip4, vrf_id=20)

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

    def test_show_max_translations(self):
        """ NAT44ED API test - max translations per thread """
        nat_config = self.vapi.nat_show_config_2()
        self.assertEqual(self.max_sessions,
                         nat_config.max_translations_per_thread)

    def test_lru_cleanup(self):
        """ NAT44ED LRU cleanup algorithm """

        self.nat_add_address(self.nat_addr)
        self.nat_add_inside_interface(self.pg0)
        self.nat_add_outside_interface(self.pg1)

        self.vapi.nat_set_timeouts(
            udp=1, tcp_established=7440, tcp_transitory=30, icmp=1)

        tcp_port_out = self.init_tcp_session(self.pg0, self.pg1, 2000, 80)
        pkts = []
        for i in range(0, self.max_sessions - 1):
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
        for i in range(0, self.max_sessions - 1):
            p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
                 IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64) /
                 ICMP(id=8000+i, type='echo-request'))
            pkts.append(p)

        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.get_capture(len(pkts))

    def test_session_rst_timeout(self):
        """ NAT44ED session RST timeouts """

        self.nat_add_address(self.nat_addr)
        self.nat_add_inside_interface(self.pg0)
        self.nat_add_outside_interface(self.pg1)

        self.vapi.nat_set_timeouts(udp=300, tcp_established=7440,
                                   tcp_transitory=5, icmp=60)

        self.init_tcp_session(self.pg0, self.pg1, self.tcp_port_in,
                              self.tcp_external_port)
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=self.tcp_port_in, dport=self.tcp_external_port,
                 flags="R"))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.get_capture(1)

        self.sleep(6)

        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=self.tcp_port_in + 1, dport=self.tcp_external_port + 1,
                 flags="S"))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.get_capture(1)

    def test_dynamic_out_of_ports(self):
        """ NAT44ED dynamic translation test: out of ports """

        self.nat_add_inside_interface(self.pg0)
        self.nat_add_outside_interface(self.pg1)

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
        self.nat_add_address(self.nat_addr)

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

    def test_unknown_proto(self):
        """ NAT44ED translate packet with unknown protocol """

        self.nat_add_address(self.nat_addr)
        self.nat_add_inside_interface(self.pg0)
        self.nat_add_outside_interface(self.pg1)

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
        """ NAT44ED translate packet with unknown protocol - hairpinning """
        host = self.pg0.remote_hosts[0]
        server = self.pg0.remote_hosts[1]
        host_in_port = 1234
        server_out_port = 8765
        server_nat_ip = "10.0.0.11"

        self.nat_add_address(self.nat_addr)
        self.nat_add_inside_interface(self.pg0)
        self.nat_add_outside_interface(self.pg1)

        # add static mapping for server
        self.nat_add_static_mapping(server.ip4, server_nat_ip)

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
        """ NAT44ED interface output feature and services """
        external_addr = '1.2.3.4'
        external_port = 80
        local_port = 8080

        self.vapi.nat44_forwarding_enable_disable(enable=1)
        self.nat_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_ADDR_ONLY
        self.vapi.nat44_add_del_identity_mapping(
            ip_address=self.pg1.remote_ip4, sw_if_index=0xFFFFFFFF,
            flags=flags, is_add=1)
        flags = self.config_flags.NAT_IS_OUT2IN_ONLY
        self.nat_add_static_mapping(self.pg0.remote_ip4, external_addr,
                                    local_port, external_port,
                                    proto=IP_PROTOS.tcp, flags=flags)

        self.nat_add_inside_interface(self.pg0)
        self.nat_add_outside_interface(self.pg0)
        self.vapi.nat44_interface_add_del_output_feature(
            sw_if_index=self.pg1.sw_if_index, is_add=1)

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

    def test_output_feature_and_service3(self):
        """ NAT44ED interface output feature and DST NAT """
        external_addr = '1.2.3.4'
        external_port = 80
        local_port = 8080

        self.vapi.nat44_forwarding_enable_disable(enable=1)
        self.nat_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_OUT2IN_ONLY
        self.nat_add_static_mapping(self.pg1.remote_ip4, external_addr,
                                    local_port, external_port,
                                    proto=IP_PROTOS.tcp, flags=flags)

        self.nat_add_inside_interface(self.pg0)
        self.nat_add_outside_interface(self.pg0)
        self.vapi.nat44_interface_add_del_output_feature(
            sw_if_index=self.pg1.sw_if_index, is_add=1)

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

    def test_self_twice_nat_lb_negative(self):
        """ NAT44ED Self Twice NAT local service load balancing (negative test)
        """
        self.twice_nat_common(lb=True, self_twice_nat=True, same_pg=True,
                              client_id=2)

    def test_self_twice_nat_negative(self):
        """ NAT44ED Self Twice NAT (negative test) """
        self.twice_nat_common(self_twice_nat=True)

    def test_static_lb_multi_clients(self):
        """ NAT44ED local service load balancing - multiple clients"""

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

        self.nat_add_address(self.nat_addr)
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

    def test_syslog_sess(self):
        """ NAT44ED Test syslog session creation and deletion """
        self.vapi.syslog_set_filter(
            self.syslog_severity.SYSLOG_API_SEVERITY_INFO)
        self.vapi.syslog_set_sender(self.pg3.local_ip4, self.pg3.remote_ip4)

        self.nat_add_address(self.nat_addr)
        self.nat_add_inside_interface(self.pg0)
        self.nat_add_outside_interface(self.pg1)

        p = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=self.tcp_port_in, dport=self.tcp_external_port))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(1)
        self.tcp_port_out = capture[0][TCP].sport
        capture = self.pg3.get_capture(1)
        self.verify_syslog_sess(capture[0][Raw].load)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.nat_add_address(self.nat_addr, is_add=0)
        capture = self.pg3.get_capture(1)
        self.verify_syslog_sess(capture[0][Raw].load, False)

    def test_twice_nat_interface_addr(self):
        """ NAT44ED Acquire twice NAT addresses from interface """
        flags = self.config_flags.NAT_IS_TWICE_NAT
        self.vapi.nat44_add_del_interface_addr(
            sw_if_index=self.pg11.sw_if_index,
            flags=flags, is_add=1)

        # no address in NAT pool
        adresses = self.vapi.nat44_address_dump()
        self.assertEqual(0, len(adresses))

        # configure interface address and check NAT address pool
        self.pg11.config_ip4()
        adresses = self.vapi.nat44_address_dump()
        self.assertEqual(1, len(adresses))
        self.assertEqual(str(adresses[0].ip_address),
                         self.pg11.local_ip4)
        self.assertEqual(adresses[0].flags, flags)

        # remove interface address and check NAT address pool
        self.pg11.unconfig_ip4()
        adresses = self.vapi.nat44_address_dump()
        self.assertEqual(0, len(adresses))

    def test_output_feature_stateful_acl(self):
        """ NAT44ED output feature works with stateful ACL """

        self.nat_add_address(self.nat_addr)
        self.vapi.nat44_interface_add_del_output_feature(
            sw_if_index=self.pg0.sw_if_index,
            flags=self.config_flags.NAT_IS_INSIDE, is_add=1)
        self.vapi.nat44_interface_add_del_output_feature(
            sw_if_index=self.pg1.sw_if_index,
            flags=self.config_flags.NAT_IS_OUTSIDE, is_add=1)

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

    def test_tcp_close(self):
        """ NAT44ED Close TCP session from inside network - output feature """
        old_timeouts = self.vapi.nat_get_timeouts()
        new_transitory = 2
        self.vapi.nat_set_timeouts(
            udp=old_timeouts.udp,
            tcp_established=old_timeouts.tcp_established,
            icmp=old_timeouts.icmp,
            tcp_transitory=new_transitory)

        self.vapi.nat44_forwarding_enable_disable(enable=1)
        self.nat_add_address(self.pg1.local_ip4)
        twice_nat_addr = '10.0.1.3'
        service_ip = '192.168.16.150'
        self.nat_add_address(twice_nat_addr, twice_nat=1)

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
        self.nat_add_static_mapping(self.pg0.remote_ip4,
                                    service_ip, 80, 80,
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
        """ NAT44ED Close TCP session from inside network """

        in_port = self.tcp_port_in
        out_port = 10505
        ext_port = self.tcp_external_port

        self.nat_add_address(self.nat_addr)
        self.nat_add_inside_interface(self.pg0)
        self.nat_add_outside_interface(self.pg1)
        self.nat_add_static_mapping(self.pg0.remote_ip4, self.nat_addr,
                                    in_port, out_port, proto=IP_PROTOS.tcp,
                                    flags=self.config_flags.NAT_IS_TWICE_NAT)

        sessions = self.vapi.nat44_user_session_dump(self.pg0.remote_ip4, 0)
        session_n = len(sessions)

        self.vapi.nat_set_timeouts(udp=300, tcp_established=7440,
                                   tcp_transitory=2, icmp=5)

        self.init_tcp_session(self.pg0, self.pg1, in_port, ext_port)

        # FIN packet in -> out
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=in_port, dport=ext_port,
                 flags="FA", seq=100, ack=300))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.get_capture(1)

        pkts = []

        # ACK packet out -> in
        p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
             IP(src=self.pg1.remote_ip4, dst=self.nat_addr) /
             TCP(sport=ext_port, dport=out_port,
                 flags="A", seq=300, ack=101))
        pkts.append(p)

        # FIN packet out -> in
        p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
             IP(src=self.pg1.remote_ip4, dst=self.nat_addr) /
             TCP(sport=ext_port, dport=out_port,
                 flags="FA", seq=300, ack=101))
        pkts.append(p)

        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg0.get_capture(2)

        # ACK packet in -> out
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=in_port, dport=ext_port,
                 flags="A", seq=101, ack=301))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.get_capture(1)

        sessions = self.vapi.nat44_user_session_dump(self.pg0.remote_ip4, 0)
        self.assertEqual(len(sessions) - session_n, 1)

        out2in_drops = self.get_err_counter(
            '/err/nat44-ed-out2in/drops due to TCP in transitory timeout')
        in2out_drops = self.get_err_counter(
            '/err/nat44-ed-in2out/drops due to TCP in transitory timeout')

        # extra FIN packet out -> in - this should be dropped
        p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
             IP(src=self.pg1.remote_ip4, dst=self.nat_addr) /
             TCP(sport=ext_port, dport=out_port,
                 flags="FA", seq=300, ack=101))

        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg0.assert_nothing_captured()

        # extra ACK packet in -> out - this should be dropped
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=in_port, dport=ext_port,
                 flags="A", seq=101, ack=301))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.assert_nothing_captured()

        stats = self.get_err_counter(
            '/err/nat44-ed-out2in/drops due to TCP in transitory timeout')
        self.assertEqual(stats - out2in_drops, 1)
        stats = self.get_err_counter(
            '/err/nat44-ed-in2out/drops due to TCP in transitory timeout')
        self.assertEqual(stats - in2out_drops, 1)

        self.sleep(3)
        # extra ACK packet in -> out - this will cause session to be wiped
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=in_port, dport=ext_port,
                 flags="A", seq=101, ack=301))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.assert_nothing_captured()
        sessions = self.vapi.nat44_user_session_dump(self.pg0.remote_ip4, 0)
        self.assertEqual(len(sessions) - session_n, 0)

    def test_tcp_session_close_out(self):
        """ NAT44ED Close TCP session from outside network """

        in_port = self.tcp_port_in
        out_port = 10505
        ext_port = self.tcp_external_port

        self.nat_add_address(self.nat_addr)
        self.nat_add_inside_interface(self.pg0)
        self.nat_add_outside_interface(self.pg1)
        self.nat_add_static_mapping(self.pg0.remote_ip4, self.nat_addr,
                                    in_port, out_port, proto=IP_PROTOS.tcp,
                                    flags=self.config_flags.NAT_IS_TWICE_NAT)

        sessions = self.vapi.nat44_user_session_dump(self.pg0.remote_ip4, 0)
        session_n = len(sessions)

        self.vapi.nat_set_timeouts(udp=300, tcp_established=7440,
                                   tcp_transitory=2, icmp=5)

        _ = self.init_tcp_session(self.pg0, self.pg1, in_port, ext_port)

        # FIN packet out -> in
        p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
             IP(src=self.pg1.remote_ip4, dst=self.nat_addr) /
             TCP(sport=ext_port, dport=out_port,
                 flags="FA", seq=100, ack=300))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg0.get_capture(1)

        # FIN+ACK packet in -> out
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=in_port, dport=ext_port,
                 flags="FA", seq=300, ack=101))

        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.get_capture(1)

        # ACK packet out -> in
        p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
             IP(src=self.pg1.remote_ip4, dst=self.nat_addr) /
             TCP(sport=ext_port, dport=out_port,
                 flags="A", seq=101, ack=301))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg0.get_capture(1)

        sessions = self.vapi.nat44_user_session_dump(self.pg0.remote_ip4, 0)
        self.assertEqual(len(sessions) - session_n, 1)

        out2in_drops = self.get_err_counter(
            '/err/nat44-ed-out2in/drops due to TCP in transitory timeout')
        in2out_drops = self.get_err_counter(
            '/err/nat44-ed-in2out/drops due to TCP in transitory timeout')

        # extra FIN packet out -> in - this should be dropped
        p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
             IP(src=self.pg1.remote_ip4, dst=self.nat_addr) /
             TCP(sport=ext_port, dport=out_port,
                 flags="FA", seq=300, ack=101))

        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg0.assert_nothing_captured()

        # extra ACK packet in -> out - this should be dropped
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=in_port, dport=ext_port,
                 flags="A", seq=101, ack=301))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.assert_nothing_captured()

        stats = self.get_err_counter(
            '/err/nat44-ed-out2in/drops due to TCP in transitory timeout')
        self.assertEqual(stats - out2in_drops, 1)
        stats = self.get_err_counter(
            '/err/nat44-ed-in2out/drops due to TCP in transitory timeout')
        self.assertEqual(stats - in2out_drops, 1)

        self.sleep(3)
        # extra ACK packet in -> out - this will cause session to be wiped
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=in_port, dport=ext_port,
                 flags="A", seq=101, ack=301))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.assert_nothing_captured()
        sessions = self.vapi.nat44_user_session_dump(self.pg0.remote_ip4, 0)
        self.assertEqual(len(sessions) - session_n, 0)

    def test_tcp_session_close_simultaneous(self):
        """ NAT44ED Close TCP session from inside network """

        in_port = self.tcp_port_in
        ext_port = 10505

        self.nat_add_address(self.nat_addr)
        self.nat_add_inside_interface(self.pg0)
        self.nat_add_outside_interface(self.pg1)
        self.nat_add_static_mapping(self.pg0.remote_ip4, self.nat_addr,
                                    in_port, ext_port, proto=IP_PROTOS.tcp,
                                    flags=self.config_flags.NAT_IS_TWICE_NAT)

        sessions = self.vapi.nat44_user_session_dump(self.pg0.remote_ip4, 0)
        session_n = len(sessions)

        self.vapi.nat_set_timeouts(udp=300, tcp_established=7440,
                                   tcp_transitory=2, icmp=5)

        out_port = self.init_tcp_session(self.pg0, self.pg1, in_port, ext_port)

        # FIN packet in -> out
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=in_port, dport=ext_port,
                 flags="FA", seq=100, ack=300))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.get_capture(1)

        # FIN packet out -> in
        p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
             IP(src=self.pg1.remote_ip4, dst=self.nat_addr) /
             TCP(sport=ext_port, dport=out_port,
                 flags="FA", seq=300, ack=100))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg0.get_capture(1)

        # ACK packet in -> out
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=in_port, dport=ext_port,
                 flags="A", seq=101, ack=301))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.get_capture(1)

        # ACK packet out -> in
        p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
             IP(src=self.pg1.remote_ip4, dst=self.nat_addr) /
             TCP(sport=ext_port, dport=out_port,
                 flags="A", seq=301, ack=101))
        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg0.get_capture(1)

        sessions = self.vapi.nat44_user_session_dump(self.pg0.remote_ip4, 0)
        self.assertEqual(len(sessions) - session_n, 1)

        out2in_drops = self.get_err_counter(
            '/err/nat44-ed-out2in/drops due to TCP in transitory timeout')
        in2out_drops = self.get_err_counter(
            '/err/nat44-ed-in2out/drops due to TCP in transitory timeout')

        # extra FIN packet out -> in - this should be dropped
        p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
             IP(src=self.pg1.remote_ip4, dst=self.nat_addr) /
             TCP(sport=ext_port, dport=out_port,
                 flags="FA", seq=300, ack=101))

        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg0.assert_nothing_captured()

        # extra ACK packet in -> out - this should be dropped
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=in_port, dport=ext_port,
                 flags="A", seq=101, ack=301))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.assert_nothing_captured()

        stats = self.get_err_counter(
            '/err/nat44-ed-out2in/drops due to TCP in transitory timeout')
        self.assertEqual(stats - out2in_drops, 1)
        stats = self.get_err_counter(
            '/err/nat44-ed-in2out/drops due to TCP in transitory timeout')
        self.assertEqual(stats - in2out_drops, 1)

        self.sleep(3)
        # extra ACK packet in -> out - this will cause session to be wiped
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
             TCP(sport=in_port, dport=ext_port,
                 flags="A", seq=101, ack=301))
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.assert_nothing_captured()
        sessions = self.vapi.nat44_user_session_dump(self.pg0.remote_ip4, 0)
        self.assertEqual(len(sessions) - session_n, 0)

    def test_dynamic_output_feature_vrf(self):
        """ NAT44ED dynamic translation test: output-feature, VRF"""

        # other then default (0)
        new_vrf_id = 22

        self.nat_add_address(self.nat_addr)
        flags = self.config_flags.NAT_IS_INSIDE
        self.vapi.nat44_interface_add_del_output_feature(
            sw_if_index=self.pg7.sw_if_index,
            flags=flags, is_add=1)
        self.vapi.nat44_interface_add_del_output_feature(
            sw_if_index=self.pg8.sw_if_index,
            is_add=1)

        try:
            self.configure_ip4_interface(self.pg7, table_id=new_vrf_id)
            self.configure_ip4_interface(self.pg8, table_id=new_vrf_id)

            # in2out
            tcpn = self.get_stats_counter(
                '/nat44-ed/in2out/slowpath/tcp')
            udpn = self.get_stats_counter(
                '/nat44-ed/in2out/slowpath/udp')
            icmpn = self.get_stats_counter(
                '/nat44-ed/in2out/slowpath/icmp')
            drops = self.get_stats_counter(
                '/nat44-ed/in2out/slowpath/drops')

            pkts = self.create_stream_in(self.pg7, self.pg8)
            self.pg7.add_stream(pkts)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            capture = self.pg8.get_capture(len(pkts))
            self.verify_capture_out(capture, ignore_port=True)

            if_idx = self.pg7.sw_if_index
            cnt = self.get_stats_counter(
                '/nat44-ed/in2out/slowpath/tcp')
            self.assertEqual(cnt[if_idx] - tcpn[if_idx], 2)
            cnt = self.get_stats_counter(
                '/nat44-ed/in2out/slowpath/udp')
            self.assertEqual(cnt[if_idx] - udpn[if_idx], 1)
            cnt = self.get_stats_counter(
                '/nat44-ed/in2out/slowpath/icmp')
            self.assertEqual(cnt[if_idx] - icmpn[if_idx], 1)
            cnt = self.get_stats_counter(
                '/nat44-ed/in2out/slowpath/drops')
            self.assertEqual(cnt[if_idx] - drops[if_idx], 0)

            # out2in
            tcpn = self.get_stats_counter(
                '/nat44-ed/out2in/fastpath/tcp')
            udpn = self.get_stats_counter(
                '/nat44-ed/out2in/fastpath/udp')
            icmpn = self.get_stats_counter(
                '/nat44-ed/out2in/fastpath/icmp')
            drops = self.get_stats_counter(
                '/nat44-ed/out2in/fastpath/drops')

            pkts = self.create_stream_out(self.pg8)
            self.pg8.add_stream(pkts)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            capture = self.pg7.get_capture(len(pkts))
            self.verify_capture_in(capture, self.pg7)

            if_idx = self.pg8.sw_if_index
            cnt = self.get_stats_counter(
                '/nat44-ed/out2in/fastpath/tcp')
            self.assertEqual(cnt[if_idx] - tcpn[if_idx], 2)
            cnt = self.get_stats_counter(
                '/nat44-ed/out2in/fastpath/udp')
            self.assertEqual(cnt[if_idx] - udpn[if_idx], 1)
            cnt = self.get_stats_counter(
                '/nat44-ed/out2in/fastpath/icmp')
            self.assertEqual(cnt[if_idx] - icmpn[if_idx], 1)
            cnt = self.get_stats_counter(
                '/nat44-ed/out2in/fastpath/drops')
            self.assertEqual(cnt[if_idx] - drops[if_idx], 0)

            sessions = self.get_stats_counter('/nat44-ed/total-sessions')
            self.assertEqual(sessions[0], 3)

        finally:
            self.configure_ip4_interface(self.pg7, table_id=0)
            self.configure_ip4_interface(self.pg8, table_id=0)

            self.vapi.ip_table_add_del(is_add=0,
                                       table={'table_id': new_vrf_id})

    def test_next_src_nat(self):
        """ NAT44ED On way back forward packet to nat44-in2out node. """

        twice_nat_addr = '10.0.1.3'
        external_port = 80
        local_port = 8080
        post_twice_nat_port = 0

        self.vapi.nat44_forwarding_enable_disable(enable=1)
        self.nat_add_address(twice_nat_addr, twice_nat=1)
        flags = (self.config_flags.NAT_IS_OUT2IN_ONLY |
                 self.config_flags.NAT_IS_SELF_TWICE_NAT)
        self.nat_add_static_mapping(self.pg6.remote_ip4, self.pg1.remote_ip4,
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

    def test_one_armed_nat44_static(self):
        """ NAT44ED One armed NAT and 1:1 NAPT asymmetrical rule """

        remote_host = self.pg4.remote_hosts[0]
        local_host = self.pg4.remote_hosts[1]
        external_port = 80
        local_port = 8080
        eh_port_in = 0

        self.vapi.nat44_forwarding_enable_disable(enable=1)
        self.nat_add_address(self.nat_addr, twice_nat=1)
        flags = (self.config_flags.NAT_IS_OUT2IN_ONLY |
                 self.config_flags.NAT_IS_TWICE_NAT)
        self.nat_add_static_mapping(local_host.ip4, self.nat_addr,
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


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
