import unittest
import socket
from scapy.layers.ipsec import ESP
from framework import VppTestRunner
from template_ipsec import TemplateIpsec, IpsecTun4Tests, IpsecTcpTests
from vpp_ipsec_tun_interface import VppIpsecTunInterface


class TemplateIpsecTunIfEsp(TemplateIpsec):
    """ IPsec tunnel interface tests """

    encryption_type = ESP

    @classmethod
    def setUpClass(cls):
        super(TemplateIpsecTunIfEsp, cls).setUpClass()
        cls.tun_if = cls.pg0

    def setUp(self):
        p = self.ipv4_params
        tun_if = VppIpsecTunInterface(self, self.pg0, p.vpp_tun_spi,
                                      p.scapy_tun_spi, p.crypt_algo_vpp_id,
                                      p.crypt_key, p.crypt_key,
                                      p.auth_algo_vpp_id, p.auth_key,
                                      p.auth_key)
        tun_if.add_vpp_config()
        tun_if.admin_up()
        tun_if.config_ip4()
        src4 = socket.inet_pton(socket.AF_INET, p.remote_tun_if_host)
        self.vapi.ip_add_del_route(src4, 32, tun_if.remote_ip4n)

    def tearDown(self):
        if not self.vpp_dead:
            self.vapi.cli("show hardware")
        super(TemplateIpsecTunIfEsp, self).tearDown()


class TestIpsecTunIfEsp1(TemplateIpsecTunIfEsp, IpsecTun4Tests):
    """ Ipsec ESP - TUN tests """
    tun4_encrypt_node_name = "esp4-encrypt"
    tun4_decrypt_node_name = "esp4-decrypt"


class TestIpsecTunIfEsp2(TemplateIpsecTunIfEsp, IpsecTcpTests):
    """ Ipsec ESP - TCP tests """
    pass


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
