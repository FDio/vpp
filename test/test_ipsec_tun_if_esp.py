import unittest
import socket
import copy

from scapy.layers.ipsec import ESP
from scapy.layers.l2 import Ether, Raw, GRE
from scapy.layers.inet import IP, UDP
from framework import VppTestRunner, is_skip_aarch64_set, is_platform_aarch64
from template_ipsec import TemplateIpsec, IpsecTun4Tests, IpsecTun6Tests, \
    IpsecTun4, IpsecTun6,  IpsecTcpTests,  config_tun_params
from vpp_ipsec_tun_interface import VppIpsecTunInterface, \
    VppIpsecGRETunInterface
from vpp_ip_route import VppIpRoute, VppRoutePath, DpoProto
from vpp_ipsec import VppIpsecSA
from vpp_l2 import VppBridgeDomain, VppBridgeDomainPort
from util import ppp
from vpp_papi import VppEnum


class TemplateIpsec4TunIfEsp(TemplateIpsec):
    """ IPsec tunnel interface tests """

    encryption_type = ESP

    @classmethod
    def setUpClass(cls):
        super(TemplateIpsec4TunIfEsp, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TemplateIpsec4TunIfEsp, cls).tearDownClass()

    def setUp(self):
        super(TemplateIpsec4TunIfEsp, self).setUp()

        self.tun_if = self.pg0

        p = self.ipv4_params

        p.tun_if = VppIpsecTunInterface(self, self.pg0, p.vpp_tun_spi,
                                        p.scapy_tun_spi, p.crypt_algo_vpp_id,
                                        p.crypt_key, p.crypt_key,
                                        p.auth_algo_vpp_id, p.auth_key,
                                        p.auth_key)
        p.tun_if.add_vpp_config()
        p.tun_if.admin_up()
        p.tun_if.config_ip4()
        p.tun_if.config_ip6()

        VppIpRoute(self, p.remote_tun_if_host, 32,
                   [VppRoutePath(p.tun_if.remote_ip4,
                                 0xffffffff)]).add_vpp_config()
        VppIpRoute(self, p.remote_tun_if_host6, 128,
                   [VppRoutePath(p.tun_if.remote_ip6,
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

    def test_tun_basic_frag44(self):
        """ ipsec 4o4 tunnel frag basic test """
        p = self.ipv4_params

        self.vapi.sw_interface_set_mtu(p.tun_if.sw_if_index,
                                       [1500, 0, 0, 0])
        self.verify_tun_44(self.params[socket.AF_INET],
                           count=1, payload_size=1800, n_rx=2)
        self.vapi.sw_interface_set_mtu(p.tun_if.sw_if_index,
                                       [9000, 0, 0, 0])


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


class TestIpsec4TunIfEspAll(TemplateIpsec, IpsecTun4):
    """ IPsec IPv4 Tunnel interface all Algos """

    encryption_type = ESP
    tun4_encrypt_node_name = "esp4-encrypt"
    tun4_decrypt_node_name = "esp4-decrypt"

    def config_network(self, p):
        config_tun_params(p, self.encryption_type, self.tun_if)

        p.tun_if = VppIpsecTunInterface(self, self.pg0, p.vpp_tun_spi,
                                        p.scapy_tun_spi,
                                        p.crypt_algo_vpp_id,
                                        p.crypt_key, p.crypt_key,
                                        p.auth_algo_vpp_id, p.auth_key,
                                        p.auth_key,
                                        salt=p.salt)
        p.tun_if.add_vpp_config()
        p.tun_if.admin_up()
        p.tun_if.config_ip4()
        self.logger.info(self.vapi.cli("sh ipsec sa 0"))
        self.logger.info(self.vapi.cli("sh ipsec sa 1"))

        p.route = VppIpRoute(self, p.remote_tun_if_host, 32,
                             [VppRoutePath(p.tun_if.remote_ip4,
                                           0xffffffff)])
        p.route.add_vpp_config()

    def unconfig_network(self, p):
        p.tun_if.unconfig_ip4()
        p.tun_if.remove_vpp_config()
        p.route.remove_vpp_config()

    def setUp(self):
        super(TestIpsec4TunIfEspAll, self).setUp()

        self.tun_if = self.pg0

    def tearDown(self):
        super(TestIpsec4TunIfEspAll, self).tearDown()

    def rekey(self, p):
        #
        # change the key and the SPI
        #
        p.crypt_key = 'X' + p.crypt_key[1:]
        p.scapy_tun_spi += 1
        p.scapy_tun_sa_id += 1
        p.vpp_tun_spi += 1
        p.vpp_tun_sa_id += 1
        p.tun_if.local_spi = p.vpp_tun_spi
        p.tun_if.remote_spi = p.scapy_tun_spi

        config_tun_params(p, self.encryption_type, self.tun_if)

        p.tun_sa_in = VppIpsecSA(self,
                                 p.scapy_tun_sa_id,
                                 p.scapy_tun_spi,
                                 p.auth_algo_vpp_id,
                                 p.auth_key,
                                 p.crypt_algo_vpp_id,
                                 p.crypt_key,
                                 self.vpp_esp_protocol,
                                 self.tun_if.local_addr[p.addr_type],
                                 self.tun_if.remote_addr[p.addr_type],
                                 flags=p.flags,
                                 salt=p.salt)
        p.tun_sa_out = VppIpsecSA(self,
                                  p.vpp_tun_sa_id,
                                  p.vpp_tun_spi,
                                  p.auth_algo_vpp_id,
                                  p.auth_key,
                                  p.crypt_algo_vpp_id,
                                  p.crypt_key,
                                  self.vpp_esp_protocol,
                                  self.tun_if.remote_addr[p.addr_type],
                                  self.tun_if.local_addr[p.addr_type],
                                  flags=p.flags,
                                  salt=p.salt)
        p.tun_sa_in.add_vpp_config()
        p.tun_sa_out.add_vpp_config()

        self.vapi.ipsec_tunnel_if_set_sa(sw_if_index=p.tun_if.sw_if_index,
                                         sa_id=p.tun_sa_in.id,
                                         is_outbound=1)
        self.vapi.ipsec_tunnel_if_set_sa(sw_if_index=p.tun_if.sw_if_index,
                                         sa_id=p.tun_sa_out.id,
                                         is_outbound=0)
        self.logger.info(self.vapi.cli("sh ipsec sa"))

    def test_tun_44(self):
        """IPSEC tunnel all algos """

        # foreach VPP crypto engine
        engines = ["ia32", "ipsecmb", "openssl"]

        # foreach crypto algorithm
        algos = [{'vpp-crypto': (VppEnum.vl_api_ipsec_crypto_alg_t.
                                 IPSEC_API_CRYPTO_ALG_AES_GCM_128),
                  'vpp-integ': (VppEnum.vl_api_ipsec_integ_alg_t.
                                IPSEC_API_INTEG_ALG_NONE),
                  'scapy-crypto': "AES-GCM",
                  'scapy-integ': "NULL",
                  'key': "JPjyOWBeVEQiMe7h",
                  'salt': 3333},
                 {'vpp-crypto': (VppEnum.vl_api_ipsec_crypto_alg_t.
                                 IPSEC_API_CRYPTO_ALG_AES_GCM_192),
                  'vpp-integ': (VppEnum.vl_api_ipsec_integ_alg_t.
                                IPSEC_API_INTEG_ALG_NONE),
                  'scapy-crypto': "AES-GCM",
                  'scapy-integ': "NULL",
                  'key': "JPjyOWBeVEQiMe7hJPjyOWBe",
                  'salt': 0},
                 {'vpp-crypto': (VppEnum.vl_api_ipsec_crypto_alg_t.
                                 IPSEC_API_CRYPTO_ALG_AES_GCM_256),
                  'vpp-integ': (VppEnum.vl_api_ipsec_integ_alg_t.
                                IPSEC_API_INTEG_ALG_NONE),
                  'scapy-crypto': "AES-GCM",
                  'scapy-integ': "NULL",
                  'key': "JPjyOWBeVEQiMe7hJPjyOWBeVEQiMe7h",
                  'salt': 9999},
                 {'vpp-crypto': (VppEnum.vl_api_ipsec_crypto_alg_t.
                                 IPSEC_API_CRYPTO_ALG_AES_CBC_128),
                  'vpp-integ': (VppEnum.vl_api_ipsec_integ_alg_t.
                                IPSEC_API_INTEG_ALG_SHA1_96),
                  'scapy-crypto': "AES-CBC",
                  'scapy-integ': "HMAC-SHA1-96",
                  'salt': 0,
                  'key': "JPjyOWBeVEQiMe7h"},
                 {'vpp-crypto': (VppEnum.vl_api_ipsec_crypto_alg_t.
                                 IPSEC_API_CRYPTO_ALG_AES_CBC_192),
                  'vpp-integ': (VppEnum.vl_api_ipsec_integ_alg_t.
                                IPSEC_API_INTEG_ALG_SHA1_96),
                  'scapy-crypto': "AES-CBC",
                  'scapy-integ': "HMAC-SHA1-96",
                  'salt': 0,
                  'key': "JPjyOWBeVEQiMe7hJPjyOWBe"},
                 {'vpp-crypto': (VppEnum.vl_api_ipsec_crypto_alg_t.
                                 IPSEC_API_CRYPTO_ALG_AES_CBC_256),
                  'vpp-integ': (VppEnum.vl_api_ipsec_integ_alg_t.
                                IPSEC_API_INTEG_ALG_SHA1_96),
                  'scapy-crypto': "AES-CBC",
                  'scapy-integ': "HMAC-SHA1-96",
                  'salt': 0,
                  'key': "JPjyOWBeVEQiMe7hJPjyOWBeVEQiMe7h"}]

        for engine in engines:
            self.vapi.cli("set crypto handler all %s" % engine)

            #
            # loop through each of the algorithms
            #
            for algo in algos:
                # with self.subTest(algo=algo['scapy']):

                p = copy.copy(self.ipv4_params)
                p.auth_algo_vpp_id = algo['vpp-integ']
                p.crypt_algo_vpp_id = algo['vpp-crypto']
                p.crypt_algo = algo['scapy-crypto']
                p.auth_algo = algo['scapy-integ']
                p.crypt_key = algo['key']
                p.salt = algo['salt']

                self.config_network(p)

                self.verify_tun_44(p, count=127)
                c = p.tun_if.get_rx_stats()
                self.assertEqual(c['packets'], 127)
                c = p.tun_if.get_tx_stats()
                self.assertEqual(c['packets'], 127)

                #
                # rekey the tunnel
                #
                self.rekey(p)
                self.verify_tun_44(p, count=127)

                self.unconfig_network(p)
                p.tun_sa_out.remove_vpp_config()
                p.tun_sa_in.remove_vpp_config()


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

    def gen_encrypt_pkts(self, sa, sw_intf, src, dst, count=1,
                         payload_size=100):
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                sa.encrypt(IP(src=self.pg0.remote_ip4,
                              dst=self.pg0.local_ip4) /
                           GRE() /
                           Ether(dst=self.omac) /
                           IP(src="1.1.1.1", dst="1.1.1.2") /
                           UDP(sport=1144, dport=2233) /
                           Raw('X' * payload_size))
                for i in range(count)]

    def gen_pkts(self, sw_intf, src, dst, count=1,
                 payload_size=100):
        return [Ether(dst=self.omac) /
                IP(src="1.1.1.1", dst="1.1.1.2") /
                UDP(sport=1144, dport=2233) /
                Raw('X' * payload_size)
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


@unittest.skipIf(is_skip_aarch64_set and is_platform_aarch64,
                 "test doesn't work on aarch64")
class TestIpsecGRETunIfEsp1(TemplateIpsecGRETunIfEsp, IpsecTun4Tests):
    """ Ipsec GRE ESP - TUN tests """
    tun4_encrypt_node_name = "esp4-encrypt"
    tun4_decrypt_node_name = "esp4-decrypt"

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
