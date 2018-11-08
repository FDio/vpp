#!/usr/bin/env python

import socket

from scapy.layers.l2 import Ether
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.ipsec import SecurityAssociation, ESP
from util import ppp, ppc
from template_ipsec import TemplateIpsec


class TemplateIPSecNAT(TemplateIpsec):
    """ IPSec/NAT
    TUNNEL MODE:


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
        super(TemplateIPSecNAT, cls).setUpClass()
        cls.tun_if = cls.pg0
        cls.vapi.ipsec_spd_add_del(cls.tun_spd_id)
        cls.vapi.ipsec_interface_add_del_spd(cls.tun_spd_id,
                                             cls.tun_if.sw_if_index)
        p = cls.ipv4_params
        cls.config_esp_tun(p)
        cls.logger.info(cls.vapi.ppcli("show ipsec"))
        src = socket.inet_pton(p.addr_type, p.remote_tun_if_host)
        cls.vapi.ip_add_del_route(src, p.addr_len,
                                  cls.tun_if.remote_addr_n[p.addr_type],
                                  is_ipv6=p.is_ipv6)

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
                copy = packet.__class__(str(packet))
                del copy[UDP].len
                copy = packet.__class__(str(copy))
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

    @classmethod
    def config_esp_tun(cls, params):
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
        cls.vapi.ipsec_sad_add_del_entry(scapy_tun_sa_id, scapy_tun_spi,
                                         auth_algo_vpp_id, auth_key,
                                         crypt_algo_vpp_id, crypt_key,
                                         cls.vpp_esp_protocol,
                                         cls.pg1.remote_addr_n[addr_type],
                                         cls.tun_if.remote_addr_n[addr_type],
                                         udp_encap=1)
        cls.vapi.ipsec_sad_add_del_entry(vpp_tun_sa_id, vpp_tun_spi,
                                         auth_algo_vpp_id, auth_key,
                                         crypt_algo_vpp_id, crypt_key,
                                         cls.vpp_esp_protocol,
                                         cls.tun_if.remote_addr_n[addr_type],
                                         cls.pg1.remote_addr_n[addr_type],
                                         udp_encap=1)
        l_startaddr = r_startaddr = socket.inet_pton(addr_type, addr_any)
        l_stopaddr = r_stopaddr = socket.inet_pton(addr_type, addr_bcast)
        cls.vapi.ipsec_spd_add_del_entry(cls.tun_spd_id, scapy_tun_sa_id,
                                         l_startaddr, l_stopaddr, r_startaddr,
                                         r_stopaddr,
                                         protocol=socket.IPPROTO_ESP)
        cls.vapi.ipsec_spd_add_del_entry(cls.tun_spd_id, scapy_tun_sa_id,
                                         l_startaddr, l_stopaddr, r_startaddr,
                                         r_stopaddr, is_outbound=0,
                                         protocol=socket.IPPROTO_ESP)
        cls.vapi.ipsec_spd_add_del_entry(cls.tun_spd_id, scapy_tun_sa_id,
                                         l_startaddr, l_stopaddr, r_startaddr,
                                         r_stopaddr, remote_port_start=4500,
                                         remote_port_stop=4500,
                                         protocol=socket.IPPROTO_UDP)
        cls.vapi.ipsec_spd_add_del_entry(cls.tun_spd_id, scapy_tun_sa_id,
                                         l_startaddr, l_stopaddr, r_startaddr,
                                         r_stopaddr, remote_port_start=4500,
                                         remote_port_stop=4500,
                                         protocol=socket.IPPROTO_UDP,
                                         is_outbound=0)
        l_startaddr = l_stopaddr = cls.tun_if.remote_addr_n[addr_type]
        r_startaddr = r_stopaddr = cls.pg1.remote_addr_n[addr_type]
        cls.vapi.ipsec_spd_add_del_entry(cls.tun_spd_id, vpp_tun_sa_id,
                                         l_startaddr, l_stopaddr, r_startaddr,
                                         r_stopaddr, priority=10, policy=3,
                                         is_outbound=0)
        cls.vapi.ipsec_spd_add_del_entry(cls.tun_spd_id, scapy_tun_sa_id,
                                         r_startaddr, r_stopaddr, l_startaddr,
                                         l_stopaddr, priority=10, policy=3)

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


class IPSecNAT(TemplateIPSecNAT):
    """ IPSec/NAT """
    pass
