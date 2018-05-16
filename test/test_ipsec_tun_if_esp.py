import unittest
import socket
from scapy.layers.ipsec import ESP
from framework import VppTestRunner
from template_ipsec import TemplateIpsec, IpsecTunTests, IpsecTcpTests
from vpp_ipsec_tun_interface import VppIpsecTunInterface


class TemplateIpsecTunIfEsp(TemplateIpsec):
    """ IPsec tunnel interface tests """

    encryption_type = ESP

    @classmethod
    def setUpClass(cls):
        super(TemplateIpsecTunIfEsp, cls).setUpClass()
        cls.tun_if = cls.pg0

    def setUp(self):
        self.ipsec_tun_if = VppIpsecTunInterface(self, self.pg0,
                                                 self.vpp_tun_spi,
                                                 self.scapy_tun_spi,
                                                 self.crypt_algo_vpp_id,
                                                 self.crypt_key,
                                                 self.crypt_key,
                                                 self.auth_algo_vpp_id,
                                                 self.auth_key,
                                                 self.auth_key)
        self.ipsec_tun_if.add_vpp_config()
        self.ipsec_tun_if.admin_up()
        self.ipsec_tun_if.config_ip4()
        src4 = socket.inet_pton(socket.AF_INET, self.remote_tun_if_host)
        self.vapi.ip_add_del_route(src4, 32, self.ipsec_tun_if.remote_ip4n)

    def tearDown(self):
        if not self.vpp_dead:
            self.vapi.cli("show hardware")
        super(TemplateIpsecTunIfEsp, self).tearDown()


class TestIpsecTunIfEsp1(TemplateIpsecTunIfEsp, IpsecTunTests):
    """ Ipsec ESP - TUN tests """
    pass


class TestIpsecTunIfEsp2(TemplateIpsecTunIfEsp, IpsecTcpTests):
    """ Ipsec ESP - TCP tests """
    pass


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
