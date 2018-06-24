import unittest

from scapy.layers.inet import IP, ICMP, TCP
from scapy.layers.ipsec import SecurityAssociation
from scapy.layers.l2 import Ether, Raw

from framework import VppTestCase, VppTestRunner
from util import ppp


class TemplateIpsec(VppTestCase):
    """
    TRANSPORT MODE:

     ------   encrypt   ---
    |tra_if| <-------> |VPP|
     ------   decrypt   ---

    TUNNEL MODE:

     ------   encrypt   ---   plain   ---
    |tun_if| <-------  |VPP| <------ |pg1|
     ------             ---           ---

     ------   decrypt   ---   plain   ---
    |tun_if| ------->  |VPP| ------> |pg1|
     ------             ---           ---
    """

    remote_tun_if_host = '1.1.1.1'
    payload = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

    tun_spd_id = 1
    scapy_tun_sa_id = 10
    scapy_tun_spi = 1001
    vpp_tun_sa_id = 20
    vpp_tun_spi = 1000

    tra_spd_id = 2
    scapy_tra_sa_id = 30
    scapy_tra_spi = 2001
    vpp_tra_sa_id = 40
    vpp_tra_spi = 2000

    vpp_esp_protocol = 1
    vpp_ah_protocol = 0

    auth_algo_vpp_id = 2  # internal VPP enum value for SHA1_96
    auth_algo = 'HMAC-SHA1-96'  # scapy name
    auth_key = 'C91KUR9GYMm5GfkEvNjX'

    crypt_algo_vpp_id = 1  # internal VPP enum value for AES_CBC_128
    crypt_algo = 'AES-CBC'  # scapy name
    crypt_key = 'JPjyOWBeVEQiMe7h'

    @classmethod
    def setUpClass(cls):
        super(TemplateIpsec, cls).setUpClass()
        cls.create_pg_interfaces(range(3))
        cls.interfaces = list(cls.pg_interfaces)
        for i in cls.interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    def tearDown(self):
        super(TemplateIpsec, self).tearDown()
        if not self.vpp_dead:
            self.vapi.cli("show hardware")

    def send_and_expect(self, input, pkts, output, count=1):
        input.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = output.get_capture(count)
        return rx

    def gen_encrypt_pkts(self, sa, sw_intf, src, dst, count=1):
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                sa.encrypt(IP(src=src, dst=dst) / ICMP() / self.payload)
                for i in range(count)]

    def gen_pkts(self, sw_intf, src, dst, count=1):
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                IP(src=src, dst=dst) / ICMP() / self.payload
                for i in range(count)]

    def configure_sa_tun(self):
        scapy_tun_sa = SecurityAssociation(self.encryption_type,
                                           spi=self.vpp_tun_spi,
                                           crypt_algo=self.crypt_algo,
                                           crypt_key=self.crypt_key,
                                           auth_algo=self.auth_algo,
                                           auth_key=self.auth_key,
                                           tunnel_header=IP(
                                               src=self.tun_if.remote_ip4,
                                               dst=self.tun_if.local_ip4))
        vpp_tun_sa = SecurityAssociation(self.encryption_type,
                                         spi=self.scapy_tun_spi,
                                         crypt_algo=self.crypt_algo,
                                         crypt_key=self.crypt_key,
                                         auth_algo=self.auth_algo,
                                         auth_key=self.auth_key,
                                         tunnel_header=IP(
                                             dst=self.tun_if.remote_ip4,
                                             src=self.tun_if.local_ip4))
        return vpp_tun_sa, scapy_tun_sa

    def configure_sa_tra(self):
        scapy_tra_sa = SecurityAssociation(self.encryption_type,
                                           spi=self.vpp_tra_spi,
                                           crypt_algo=self.crypt_algo,
                                           crypt_key=self.crypt_key,
                                           auth_algo=self.auth_algo,
                                           auth_key=self.auth_key)
        vpp_tra_sa = SecurityAssociation(self.encryption_type,
                                         spi=self.scapy_tra_spi,
                                         crypt_algo=self.crypt_algo,
                                         crypt_key=self.crypt_key,
                                         auth_algo=self.auth_algo,
                                         auth_key=self.auth_key)
        return vpp_tra_sa, scapy_tra_sa


class IpsecTcpTests(object):
    def test_tcp_checksum(self):
        """ verify checksum correctness for vpp generated packets """
        self.vapi.cli("test http server")
        vpp_tun_sa, scapy_tun_sa = self.configure_sa_tun()
        send = (Ether(src=self.tun_if.remote_mac, dst=self.tun_if.local_mac) /
                scapy_tun_sa.encrypt(IP(src=self.remote_tun_if_host,
                                        dst=self.tun_if.local_ip4) /
                                     TCP(flags='S', dport=80)))
        self.logger.debug(ppp("Sending packet:", send))
        recv = self.send_and_expect(self.tun_if, [send], self.tun_if, 1)
        recv = recv[0]
        decrypted = vpp_tun_sa.decrypt(recv[IP])
        self.assert_packet_checksums_valid(decrypted)


class IpsecTraTests(object):
    def test_tra_basic(self, count=1):
        """ ipsec v4 transport basic test """
        try:
            vpp_tra_sa, scapy_tra_sa = self.configure_sa_tra()
            send_pkts = self.gen_encrypt_pkts(scapy_tra_sa, self.tra_if,
                                              src=self.tra_if.remote_ip4,
                                              dst=self.tra_if.local_ip4,
                                              count=count)
            recv_pkts = self.send_and_expect(self.tra_if, send_pkts,
                                             self.tra_if, count=count)
            for p in recv_pkts:
                decrypted = vpp_tra_sa.decrypt(p[IP])
                self.assert_packet_checksums_valid(decrypted)
        finally:
            self.logger.info(self.vapi.ppcli("show error"))
            self.logger.info(self.vapi.ppcli("show ipsec"))

    def test_tra_burst(self):
        """ ipsec v4 transport burst test """
        try:
            self.test_tra_basic(count=257)
        finally:
            self.logger.info(self.vapi.ppcli("show error"))
            self.logger.info(self.vapi.ppcli("show ipsec"))


class IpsecTunTests(object):
    def test_tun_basic(self, count=1):
        """ ipsec 4o4 tunnel basic test """
        try:
            vpp_tun_sa, scapy_tun_sa = self.configure_sa_tun()
            send_pkts = self.gen_encrypt_pkts(scapy_tun_sa, self.tun_if,
                                              src=self.remote_tun_if_host,
                                              dst=self.pg1.remote_ip4,
                                              count=count)
            recv_pkts = self.send_and_expect(self.tun_if, send_pkts, self.pg1,
                                             count=count)
            for recv_pkt in recv_pkts:
                self.assert_equal(recv_pkt[IP].src, self.remote_tun_if_host)
                self.assert_equal(recv_pkt[IP].dst, self.pg1.remote_ip4)
                self.assert_packet_checksums_valid(recv_pkt)
            send_pkts = self.gen_pkts(self.pg1, src=self.pg1.remote_ip4,
                                      dst=self.remote_tun_if_host, count=count)
            recv_pkts = self.send_and_expect(self.pg1, send_pkts, self.tun_if,
                                             count=count)
            for recv_pkt in recv_pkts:
                decrypt_pkt = vpp_tun_sa.decrypt(recv_pkt[IP])
                if not decrypt_pkt.haslayer(IP):
                    decrypt_pkt = IP(decrypt_pkt[Raw].load)
                self.assert_equal(decrypt_pkt.src, self.pg1.remote_ip4)
                self.assert_equal(decrypt_pkt.dst, self.remote_tun_if_host)
                self.assert_packet_checksums_valid(decrypt_pkt)
        finally:
            self.logger.info(self.vapi.ppcli("show error"))
            self.logger.info(self.vapi.ppcli("show ipsec"))

    def test_tun_burst(self):
        """ ipsec 4o4 tunnel burst test """
        try:
            self.test_tun_basic(count=257)
        finally:
            self.logger.info(self.vapi.ppcli("show error"))
            self.logger.info(self.vapi.ppcli("show ipsec"))


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
