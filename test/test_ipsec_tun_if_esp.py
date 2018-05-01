import unittest
import socket
from scapy.layers.ipsec import ESP
from framework import VppTestRunner
from template_ipsec import TemplateIpsec, IpsecTun4Tests, IpsecTcpTests
from vpp_ipsec_tun_interface import VppIpsecTunInterface
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_ip import *


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
        r = VppIpRoute(self, p.remote_tun_if_host, 32,
                       [VppRoutePath(tun_if.remote_ip4,
                                     INVALID_INDEX)])
        r.add_vpp_config()

    def tearDown(self):
        if not self.vpp_dead:
            self.vapi.cli("show hardware")
        super(TemplateIpsecTunIfEsp, self).tearDown()


class TestIpsecTunIfEsp1(TemplateIpsecTunIfEsp, IpsecTun4Tests):
    """ Ipsec ESP - TUN tests """
    pass


class TestIpsecTunIfEsp2(TemplateIpsecTunIfEsp, IpsecTcpTests):
    """ Ipsec ESP - TCP tests """
    pass


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
