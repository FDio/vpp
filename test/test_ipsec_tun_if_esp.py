import unittest
import socket
import copy
from scapy.layers.ipsec import ESP
from framework import VppTestRunner
from template_ipsec import TemplateIpsec, IpsecTun4Tests, IpsecTun6Tests, \
    IpsecTun4, IpsecTun6,  IpsecTcpTests,  config_tun_params
from vpp_ipsec_tun_interface import VppIpsecTunInterface
from vpp_ip_route import VppIpRoute, VppRoutePath, DpoProto


class TemplateIpsec4TunIfEsp(TemplateIpsec):
    """ IPsec tunnel interface tests """

    encryption_type = ESP

    def setUp(self):
        super(TemplateIpsec4TunIfEsp, self).setUp()

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
        super(TemplateIpsec4TunIfEsp, self).tearDown()


class TestIpsec4TunIfEsp1(TemplateIpsec4TunIfEsp, IpsecTun4Tests):
    """ Ipsec ESP - TUN tests """
    tun4_encrypt_node_name = "esp4-encrypt"
    tun4_decrypt_node_name = "esp4-decrypt"


class TestIpsec4TunIfEsp2(TemplateIpsec4TunIfEsp, IpsecTcpTests):
    """ Ipsec ESP - TCP tests """
    pass


class TemplateIpsec6TunIfEsp(TemplateIpsec):
    """ IPsec tunnel interface tests """

    encryption_type = ESP

    def setUp(self):
        super(TemplateIpsec6TunIfEsp, self).setUp()

        self.tun_if = self.pg0

        p = self.ipv6_params
        tun_if = VppIpsecTunInterface(self, self.pg0, p.vpp_tun_spi,
                                      p.scapy_tun_spi, p.crypt_algo_vpp_id,
                                      p.crypt_key, p.crypt_key,
                                      p.auth_algo_vpp_id, p.auth_key,
                                      p.auth_key, is_ip6=True)
        tun_if.add_vpp_config()
        tun_if.admin_up()
        tun_if.config_ip6()

        VppIpRoute(self,  p.remote_tun_if_host, 128,
                   [VppRoutePath(tun_if.remote_ip6,
                                 0xffffffff,
                                 proto=DpoProto.DPO_PROTO_IP6)],
                   is_ip6=1).add_vpp_config()

    def tearDown(self):
        if not self.vpp_dead:
            self.vapi.cli("show hardware")
        super(TemplateIpsec6TunIfEsp, self).tearDown()


class TestIpsec6TunIfEsp1(TemplateIpsec6TunIfEsp, IpsecTun6Tests):
    """ Ipsec ESP - TUN tests """
    tun6_encrypt_node_name = "esp6-encrypt"
    tun6_decrypt_node_name = "esp6-decrypt"


class TestIpsec4MultiTunIfEsp(TemplateIpsec, IpsecTun4):
    """ IPsec IPv4 Multi Tunnel interface """

    encryption_type = ESP
    tun4_encrypt_node_name = "esp4-encrypt"
    tun4_decrypt_node_name = "esp4-decrypt"

    def setUp(self):
        super(TestIpsec4MultiTunIfEsp, self).setUp()

        self.tun_if = self.pg0

        self.multi_params = []

        for ii in range(10):
            p = copy.copy(self.ipv4_params)

            p.remote_tun_if_host = "1.1.1.%d" % (ii + 1)
            p.scapy_tun_sa_id = p.scapy_tun_sa_id + ii
            p.scapy_tun_spi = p.scapy_tun_spi + ii
            p.vpp_tun_sa_id = p.vpp_tun_sa_id + ii
            p.vpp_tun_spi = p.vpp_tun_spi + ii

            p.scapy_tra_sa_id = p.scapy_tra_sa_id + ii
            p.scapy_tra_spi = p.scapy_tra_spi + ii
            p.vpp_tra_sa_id = p.vpp_tra_sa_id + ii
            p.vpp_tra_spi = p.vpp_tra_spi + ii

            config_tun_params(p, self.encryption_type, self.tun_if)
            self.multi_params.append(p)

            p.tun_if = VppIpsecTunInterface(self, self.pg0, p.vpp_tun_spi,
                                            p.scapy_tun_spi,
                                            p.crypt_algo_vpp_id,
                                            p.crypt_key, p.crypt_key,
                                            p.auth_algo_vpp_id, p.auth_key,
                                            p.auth_key)
            p.tun_if.add_vpp_config()
            p.tun_if.admin_up()
            p.tun_if.config_ip4()

            VppIpRoute(self, p.remote_tun_if_host, 32,
                       [VppRoutePath(p.tun_if.remote_ip4,
                                     0xffffffff)]).add_vpp_config()

    def tearDown(self):
        if not self.vpp_dead:
            self.vapi.cli("show hardware")
        super(TestIpsec4MultiTunIfEsp, self).tearDown()

    def test_tun_44(self):
        """Multiple IPSEC tunnel interfaces """
        for p in self.multi_params:
            self.verify_tun_44(p, count=127)
            c = p.tun_if.get_rx_stats()
            self.assertEqual(c['packets'], 127)
            c = p.tun_if.get_tx_stats()
            self.assertEqual(c['packets'], 127)


class TestIpsec6MultiTunIfEsp(TemplateIpsec, IpsecTun6):
    """ IPsec IPv6 Multi Tunnel interface """

    encryption_type = ESP
    tun6_encrypt_node_name = "esp6-encrypt"
    tun6_decrypt_node_name = "esp6-decrypt"

    def setUp(self):
        super(TestIpsec6MultiTunIfEsp, self).setUp()

        self.tun_if = self.pg0

        self.multi_params = []

        for ii in range(10):
            p = copy.copy(self.ipv6_params)

            p.remote_tun_if_host = "1111::%d" % (ii + 1)
            p.scapy_tun_sa_id = p.scapy_tun_sa_id + ii
            p.scapy_tun_spi = p.scapy_tun_spi + ii
            p.vpp_tun_sa_id = p.vpp_tun_sa_id + ii
            p.vpp_tun_spi = p.vpp_tun_spi + ii

            p.scapy_tra_sa_id = p.scapy_tra_sa_id + ii
            p.scapy_tra_spi = p.scapy_tra_spi + ii
            p.vpp_tra_sa_id = p.vpp_tra_sa_id + ii
            p.vpp_tra_spi = p.vpp_tra_spi + ii

            config_tun_params(p, self.encryption_type, self.tun_if)
            self.multi_params.append(p)

            p.tun_if = VppIpsecTunInterface(self, self.pg0, p.vpp_tun_spi,
                                            p.scapy_tun_spi,
                                            p.crypt_algo_vpp_id,
                                            p.crypt_key, p.crypt_key,
                                            p.auth_algo_vpp_id, p.auth_key,
                                            p.auth_key, is_ip6=True)
            p.tun_if.add_vpp_config()
            p.tun_if.admin_up()
            p.tun_if.config_ip6()

            VppIpRoute(self, p.remote_tun_if_host, 128,
                       [VppRoutePath(p.tun_if.remote_ip6,
                                     0xffffffff,
                                     proto=DpoProto.DPO_PROTO_IP6)],
                       is_ip6=1).add_vpp_config()

    def tearDown(self):
        if not self.vpp_dead:
            self.vapi.cli("show hardware")
        super(TestIpsec6MultiTunIfEsp, self).tearDown()

    def test_tun_66(self):
        """Multiple IPSEC tunnel interfaces """
        for p in self.multi_params:
            self.verify_tun_66(p, count=127)
            c = p.tun_if.get_rx_stats()
            self.assertEqual(c['packets'], 127)
            c = p.tun_if.get_tx_stats()
            self.assertEqual(c['packets'], 127)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
