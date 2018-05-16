#!/usr/bin/env python

import socket

from scapy.layers.l2 import Ether
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.ipsec import SecurityAssociation, ESP
from util import ppp, ppc
from framework import VppTestCase


class IPSecNATTestCase(VppTestCase):
    """ IPSec/NAT

    TRANSPORT MODE:

     ---   encrypt   ---
    |pg2| <-------> |VPP|
     ---   decrypt   ---

    TUNNEL MODE:


     public network  |   private network
     ---   encrypt  ---   plain   ---
    |pg0| <------- |VPP| <------ |pg1|
     ---            ---           ---

     ---   decrypt  ---   plain   ---
    |pg0| -------> |VPP| ------> |pg1|
     ---            ---           ---
    """

    remote_pg0_client_addr = '1.1.1.1'

    @classmethod
    def setUpClass(cls):
        super(IPSecNATTestCase, cls).setUpClass()
        cls.create_pg_interfaces(range(2))
        for i in cls.pg_interfaces:
            i.configure_ipv4_neighbors()
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

        cls.tcp_port_in = 6303
        cls.tcp_port_out = 6303
        cls.udp_port_in = 6304
        cls.udp_port_out = 6304
        cls.icmp_id_in = 6305
        cls.icmp_id_out = 6305
        cls.config_esp_tun()
        cls.logger.info(cls.vapi.ppcli("show ipsec"))

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
                self.assert_equal(packet[IP].src, self.pg0.remote_ip4,
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
                self.assertIn(ESP, packet[IP])
                decrypt_pkt = sa.decrypt(packet[IP])
                self.assert_equal(decrypt_pkt[IP].src, self.pg1.remote_ip4,
                                  "encrypted packet source address")
                self.assert_equal(decrypt_pkt[IP].dst, self.pg0.remote_ip4,
                                  "encrypted packet destination address")
                # if decrypt_pkt.haslayer(TCP):
                #     self.tcp_port_out = decrypt_pkt[TCP].sport
                # elif decrypt_pkt.haslayer(UDP):
                #     self.udp_port_out = decrypt_pkt[UDP].sport
                # else:
                #     self.icmp_id_out = decrypt_pkt[ICMP].id
            except Exception:
                self.logger.error(
                    ppp("Unexpected or invalid encrypted packet:", packet))
                raise

    @classmethod
    def config_esp_tun(cls):
        spd_id = 1
        remote_sa_id = 10
        local_sa_id = 20
        scapy_tun_spi = 1001
        vpp_tun_spi = 1000
        client = socket.inet_pton(socket.AF_INET, cls.remote_pg0_client_addr)
        cls.vapi.ip_add_del_route(client, 32, cls.pg0.remote_ip4n)
        cls.vapi.ipsec_sad_add_del_entry(remote_sa_id, scapy_tun_spi,
                                         cls.pg1.remote_ip4n,
                                         cls.pg0.remote_ip4n,
                                         integrity_key_length=20,
                                         crypto_key_length=16,
                                         protocol=1, udp_encap=1)
        cls.vapi.ipsec_sad_add_del_entry(local_sa_id, vpp_tun_spi,
                                         cls.pg0.remote_ip4n,
                                         cls.pg1.remote_ip4n,
                                         integrity_key_length=20,
                                         crypto_key_length=16,
                                         protocol=1, udp_encap=1)
        cls.vapi.ipsec_spd_add_del(spd_id)
        cls.vapi.ipsec_interface_add_del_spd(spd_id, cls.pg0.sw_if_index)
        l_startaddr = r_startaddr = socket.inet_pton(socket.AF_INET,
                                                     "0.0.0.0")
        l_stopaddr = r_stopaddr = socket.inet_pton(socket.AF_INET,
                                                   "255.255.255.255")
        cls.vapi.ipsec_spd_add_del_entry(spd_id, l_startaddr, l_stopaddr,
                                         r_startaddr, r_stopaddr,
                                         protocol=socket.IPPROTO_ESP)
        cls.vapi.ipsec_spd_add_del_entry(spd_id, l_startaddr, l_stopaddr,
                                         r_startaddr, r_stopaddr,
                                         protocol=socket.IPPROTO_ESP,
                                         is_outbound=0)
        cls.vapi.ipsec_spd_add_del_entry(spd_id, l_startaddr, l_stopaddr,
                                         r_startaddr, r_stopaddr,
                                         remote_port_start=4500,
                                         remote_port_stop=4500,
                                         protocol=socket.IPPROTO_UDP)
        cls.vapi.ipsec_spd_add_del_entry(spd_id, l_startaddr, l_stopaddr,
                                         r_startaddr, r_stopaddr,
                                         remote_port_start=4500,
                                         remote_port_stop=4500,
                                         protocol=socket.IPPROTO_UDP,
                                         is_outbound=0)
        l_startaddr = l_stopaddr = cls.pg0.remote_ip4n
        r_startaddr = r_stopaddr = cls.pg1.remote_ip4n
        cls.vapi.ipsec_spd_add_del_entry(spd_id, l_startaddr, l_stopaddr,
                                         r_startaddr, r_stopaddr,
                                         priority=10, policy=3,
                                         is_outbound=0, sa_id=local_sa_id)
        cls.vapi.ipsec_spd_add_del_entry(spd_id, r_startaddr, r_stopaddr,
                                         l_startaddr, l_stopaddr,
                                         priority=10, policy=3,
                                         sa_id=remote_sa_id)

    def test_ipsec_nat_tun(self):
        """ IPSec/NAT tunnel test case """
        local_tun_sa = SecurityAssociation(ESP, spi=0x000003e9,
                                           crypt_algo='AES-CBC',
                                           crypt_key='JPjyOWBeVEQiMe7h',
                                           auth_algo='HMAC-SHA1-96',
                                           auth_key='C91KUR9GYMm5GfkEvNjX',
                                           tunnel_header=IP(
                                               src=self.pg1.remote_ip4,
                                               dst=self.pg0.remote_ip4),
                                           nat_t_header=UDP(
                                               sport=4500,
                                               dport=4500))
        # in2out - from private network to public
        pkts = self.create_stream_plain(
            self.pg1.remote_mac, self.pg1.local_mac,
            self.pg1.remote_ip4, self.pg0.remote_ip4)
        self.pg1.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(len(pkts))
        self.verify_capture_encrypted(capture, local_tun_sa)

        remote_tun_sa = SecurityAssociation(ESP, spi=0x000003e8,
                                            crypt_algo='AES-CBC',
                                            crypt_key='JPjyOWBeVEQiMe7h',
                                            auth_algo='HMAC-SHA1-96',
                                            auth_key='C91KUR9GYMm5GfkEvNjX',
                                            tunnel_header=IP(
                                                src=self.pg0.remote_ip4,
                                                dst=self.pg1.remote_ip4),
                                            nat_t_header=UDP(
                                                sport=4500,
                                                dport=4500))

        # out2in - from public network to private
        pkts = self.create_stream_encrypted(
            self.pg0.remote_mac, self.pg0.local_mac,
            self.pg0.remote_ip4, self.pg1.remote_ip4, remote_tun_sa)
        self.logger.info(ppc("Sending packets:", pkts))
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg1.get_capture(len(pkts))
        self.verify_capture_plain(capture)
