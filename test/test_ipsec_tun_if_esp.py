import unittest
import socket
import copy
from scapy.layers.ipsec import ESP
from scapy.layers.l2 import Ether, Raw, GRE
from scapy.layers.inet import IP, UDP
from framework import VppTestRunner
from template_ipsec import TemplateIpsec, IpsecTun4Tests, IpsecTun6Tests, \
    IpsecTun4, IpsecTun6,  IpsecTcpTests,  config_tun_params
from vpp_ipsec_tun_interface import VppIpsecTunInterface, \
    VppIpsecGRETunInterface
from vpp_ip_route import VppIpRoute, VppRoutePath, DpoProto
from vpp_ipsec import VppIpsecSA
from vpp_l2 import VppBridgeDomain, VppBridgeDomainPort
from util import ppp


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
        tun_if.config_ip6()

        VppIpRoute(self, p.remote_tun_if_host, 32,
                   [VppRoutePath(tun_if.remote_ip4,
                                 0xffffffff)]).add_vpp_config()
        VppIpRoute(self, p.remote_tun_if_host6, 128,
                   [VppRoutePath(tun_if.remote_ip6,
                                 0xffffffff,
                                 proto=DpoProto.DPO_PROTO_IP6)],
                   is_ip6=1).add_vpp_config()

    def tearDown(self):
        if not self.vpp_dead:
            self.vapi.cli("show hardware")
        super(TemplateIpsec4TunIfEsp, self).tearDown()


class TestIpsec4TunIfEsp1(TemplateIpsec4TunIfEsp, IpsecTun4Tests):
    """ Ipsec ESP - TUN tests """
    tun4_encrypt_node_name = "esp4-encrypt"
    tun4_decrypt_node_name = "esp4-decrypt"

    def test_tun_basic64(self):
        """ ipsec 6o4 tunnel basic test """
        self.verify_tun_64(self.params[socket.AF_INET], count=1)

    def test_tun_burst64(self):
        """ ipsec 6o4 tunnel basic test """
        self.verify_tun_64(self.params[socket.AF_INET], count=257)


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
        tun_if.config_ip4()

        VppIpRoute(self, p.remote_tun_if_host, 128,
                   [VppRoutePath(tun_if.remote_ip6,
                                 0xffffffff,
                                 proto=DpoProto.DPO_PROTO_IP6)],
                   is_ip6=1).add_vpp_config()
        VppIpRoute(self, p.remote_tun_if_host4, 32,
                   [VppRoutePath(tun_if.remote_ip4,
                                 0xffffffff)]).add_vpp_config()

    def tearDown(self):
        if not self.vpp_dead:
            self.vapi.cli("show hardware")
        super(TemplateIpsec6TunIfEsp, self).tearDown()


class TestIpsec6TunIfEsp1(TemplateIpsec6TunIfEsp, IpsecTun6Tests):
    """ Ipsec ESP - TUN tests """
    tun6_encrypt_node_name = "esp6-encrypt"
    tun6_decrypt_node_name = "esp6-decrypt"

    def test_tun_basic46(self):
        """ ipsec 4o6 tunnel basic test """
        self.verify_tun_46(self.params[socket.AF_INET6], count=1)

    def test_tun_burst46(self):
        """ ipsec 4o6 tunnel burst test """
        self.verify_tun_46(self.params[socket.AF_INET6], count=257)


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

        p.tun_sa_out = VppIpsecSA(self, p.scapy_tun_sa_id, p.scapy_tun_spi,
                                  p.auth_algo_vpp_id, p.auth_key,
                                  p.crypt_algo_vpp_id, p.crypt_key,
                                  self.vpp_esp_protocol,
                                  self.pg0.local_ip4,
                                  self.pg0.remote_ip4)
        p.tun_sa_out.add_vpp_config()

        p.tun_sa_in = VppIpsecSA(self, p.vpp_tun_sa_id, p.vpp_tun_spi,
                                 p.auth_algo_vpp_id, p.auth_key,
                                 p.crypt_algo_vpp_id, p.crypt_key,
                                 self.vpp_esp_protocol,
                                 self.pg0.remote_ip4,
                                 self.pg0.local_ip4)
        p.tun_sa_in.add_vpp_config()

        self.tun = VppIpsecGRETunInterface(self, self.pg0,
                                           p.tun_sa_out.id,
                                           p.tun_sa_in.id)

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


class TestIpsecGRETunIfEsp1(TemplateIpsecGRETunIfEsp, IpsecTun4Tests):
    """ Ipsec GRE ESP - TUN tests """
    tun4_encrypt_node_name = "esp4-encrypt"
    tun4_decrypt_node_name = "esp4-decrypt"

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
