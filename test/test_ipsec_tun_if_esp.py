import unittest
import socket
from scapy.layers.ipsec import ESP
from scapy.layers.l2 import Ether, Raw, GRE
from scapy.layers.inet import IP, UDP
from framework import VppTestRunner
from template_ipsec import TemplateIpsec, IpsecTun4Tests, IpsecTcpTests
from vpp_ipsec_tun_interface import VppIpsecTunInterface, \
    VppIpsecGRETunInterface
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_ipsec import VppIpsecSA
from vpp_l2 import VppBridgeDomain, VppBridgeDomainPort
from util import ppp


class TemplateIpsecTunIfEsp(TemplateIpsec):
    """ IPsec tunnel interface tests """

    encryption_type = ESP

    def setUp(self):
        super(TemplateIpsecTunIfEsp, self).setUp()

        self.tun_if = self.pg0

        p = self.ipv4_params
        tun_if = VppIpsecTunInterface(self, self.pg0, p.vpp_tun_spi,
                                      p.scapy_tun_spi, p.crypt_algo_vpp_id,
                                      p.crypt_key, p.crypt_key,
                                      p.auth_algo_vpp_id, p.auth_key,
                                      p.auth_key)
        tun_if.add_vpp_config()
        tun_if.admin_up()
        tun_if.config_ip4()

        VppIpRoute(self,  p.remote_tun_if_host, 32,
                   [VppRoutePath(tun_if.remote_ip4,
                                 0xffffffff)]).add_vpp_config()

    def tearDown(self):
        if not self.vpp_dead:
            self.vapi.cli("show hardware")
        super(TemplateIpsecTunIfEsp, self).tearDown()


class TemplateIpsecGRETunIfEsp(TemplateIpsec):
    """ IPsec GRE tunnel interface tests """

    encryption_type = ESP
    omac = "00:11:22:33:44:55"

    def gen_encrypt_pkts(self, sa, sw_intf, src, dst, count=1):
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                sa.encrypt(IP(src=self.pg0.remote_ip4,
                              dst=self.pg0.local_ip4) /
                           GRE() /
                           Ether(dst=self.omac) /
                           IP(src="1.1.1.1", dst="1.1.1.2") /
                           UDP(sport=1144, dport=2233) /
                           self.payload)
                for i in range(count)]

    def gen_pkts(self, sw_intf, src, dst, count=1):
        return [Ether(dst=self.omac) /
                IP(src="1.1.1.1", dst="1.1.1.2") /
                UDP(sport=1144, dport=2233) /
                self.payload
                for i in range(count)]

    def verify_decrypted(self, p, rxs):
        for rx in rxs:
            self.assert_equal(rx[Ether].dst, self.omac)
            self.assert_equal(rx[IP].dst, "1.1.1.2")

    def verify_encrypted(self, p, sa, rxs):
        for rx in rxs:
            try:
                pkt = sa.decrypt(rx[IP])
                if not pkt.haslayer(IP):
                    pkt = IP(pkt[Raw].load)
                self.assert_packet_checksums_valid(pkt)
                self.assert_equal(pkt[IP].dst, self.pg0.remote_ip4)
                self.assert_equal(pkt[IP].src, self.pg0.local_ip4)
                self.assertTrue(pkt.haslayer(GRE))
                e = pkt[Ether]
                self.assertEqual(e[Ether].dst, self.omac)
                self.assertEqual(e[IP].dst, "1.1.1.2")
            except (IndexError, AssertionError):
                self.logger.debug(ppp("Unexpected packet:", rx))
                try:
                    self.logger.debug(ppp("Decrypted packet:", pkt))
                except:
                    pass
                raise

    def setUp(self):
        super(TemplateIpsecGRETunIfEsp, self).setUp()

        self.tun_if = self.pg0

        p = self.ipv4_params

        bd1 = VppBridgeDomain(self, 1)
        bd1.add_vpp_config()

        p.tun_sa_in = VppIpsecSA(self, p.vpp_tun_sa_id, p.vpp_tun_spi,
                                 p.auth_algo_vpp_id, p.auth_key,
                                 p.crypt_algo_vpp_id, p.crypt_key,
                                 self.vpp_esp_protocol,
                                 self.pg0.local_ip4,
                                 self.pg0.remote_ip4)
        p.tun_sa_in.add_vpp_config()

        p.tun_sa_out = VppIpsecSA(self, p.scapy_tun_sa_id, p.scapy_tun_spi,
                                  p.auth_algo_vpp_id, p.auth_key,
                                  p.crypt_algo_vpp_id, p.crypt_key,
                                  self.vpp_ah_protocol,
                                  self.pg0.local_ip4,
                                  self.pg0.remote_ip4)
        p.tun_sa_out.add_vpp_config()

        self.tun = VppIpsecGRETunInterface(self, self.pg0,
                                           p.tun_sa_in.id,
                                           p.tun_sa_out.id)

        self.tun.add_vpp_config()
        self.tun.admin_up()
        self.tun.config_ip4()

        VppIpRoute(self, p.remote_tun_if_host, 32,
                   [VppRoutePath(self.tun.remote_ip4,
                                 0xffffffff)]).add_vpp_config()
        VppBridgeDomainPort(self, bd1, self.tun).add_vpp_config()
        VppBridgeDomainPort(self, bd1, self.pg1).add_vpp_config()

    def tearDown(self):
        if not self.vpp_dead:
            self.vapi.cli("show hardware")
        self.tun.unconfig_ip4()
        super(TemplateIpsecGRETunIfEsp, self).tearDown()


class TestIpsecTunIfEsp1(TemplateIpsecTunIfEsp, IpsecTun4Tests):
    """ Ipsec ESP - TUN tests """
    tun4_encrypt_node_name = "esp4-encrypt"
    tun4_decrypt_node_name = "esp4-decrypt"


class TestIpsecTunIfEsp2(TemplateIpsecTunIfEsp, IpsecTcpTests):
    """ Ipsec ESP - TCP tests """
    pass


class TestIpsecGRETunIfEsp1(TemplateIpsecGRETunIfEsp, IpsecTun4Tests):
    """ Ipsec GRE ESP - TUN tests """
    tun4_encrypt_node_name = "esp4-encrypt"
    tun4_decrypt_node_name = "esp4-decrypt"


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
