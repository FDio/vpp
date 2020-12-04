import unittest
import socket
import copy

from scapy.layers.ipsec import SecurityAssociation, ESP
from scapy.layers.l2 import Ether, GRE, Dot1Q
from scapy.packet import Raw
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from framework import VppTestRunner
from template_ipsec import TemplateIpsec, IpsecTun4Tests, IpsecTun6Tests, \
    IpsecTun4, IpsecTun6,  IpsecTcpTests, mk_scapy_crypt_key, \
    IpsecTun6HandoffTests, IpsecTun4HandoffTests, config_tun_params
from vpp_ipsec_tun_interface import VppIpsecTunInterface
from vpp_gre_interface import VppGreInterface
from vpp_ipip_tun_interface import VppIpIpTunInterface
from vpp_ip_route import VppIpRoute, VppRoutePath, DpoProto
from vpp_ipsec import VppIpsecSA, VppIpsecTunProtect, VppIpsecInterface
from vpp_l2 import VppBridgeDomain, VppBridgeDomainPort
from vpp_sub_interface import L2_VTR_OP, VppDot1QSubint
from vpp_teib import VppTeib
from util import ppp
from vpp_papi import VppEnum
from vpp_papi_provider import CliFailedCommandError
from vpp_acl import AclRule, VppAcl, VppAclInterface


def config_tun_params(p, encryption_type, tun_if, src=None, dst=None):
    ip_class_by_addr_type = {socket.AF_INET: IP, socket.AF_INET6: IPv6}
    esn_en = bool(p.flags & (VppEnum.vl_api_ipsec_sad_flags_t.
                             IPSEC_API_SAD_FLAG_USE_ESN))
    crypt_key = mk_scapy_crypt_key(p)
    if tun_if:
        p.tun_dst = tun_if.remote_ip
        p.tun_src = tun_if.local_ip
    else:
        p.tun_dst = dst
        p.tun_src = src

    p.scapy_tun_sa = SecurityAssociation(
        encryption_type, spi=p.vpp_tun_spi,
        crypt_algo=p.crypt_algo,
        crypt_key=crypt_key,
        auth_algo=p.auth_algo, auth_key=p.auth_key,
        tunnel_header=ip_class_by_addr_type[p.addr_type](
            src=p.tun_dst,
            dst=p.tun_src),
        nat_t_header=p.nat_header,
        esn_en=esn_en)
    p.vpp_tun_sa = SecurityAssociation(
        encryption_type, spi=p.scapy_tun_spi,
        crypt_algo=p.crypt_algo,
        crypt_key=crypt_key,
        auth_algo=p.auth_algo, auth_key=p.auth_key,
        tunnel_header=ip_class_by_addr_type[p.addr_type](
            dst=p.tun_dst,
            src=p.tun_src),
        nat_t_header=p.nat_header,
        esn_en=esn_en)


def config_tra_params(p, encryption_type, tun_if):
    ip_class_by_addr_type = {socket.AF_INET: IP, socket.AF_INET6: IPv6}
    esn_en = bool(p.flags & (VppEnum.vl_api_ipsec_sad_flags_t.
                             IPSEC_API_SAD_FLAG_USE_ESN))
    crypt_key = mk_scapy_crypt_key(p)
    p.tun_dst = tun_if.remote_ip
    p.tun_src = tun_if.local_ip
    p.scapy_tun_sa = SecurityAssociation(
        encryption_type, spi=p.vpp_tun_spi,
        crypt_algo=p.crypt_algo,
        crypt_key=crypt_key,
        auth_algo=p.auth_algo, auth_key=p.auth_key,
        esn_en=esn_en,
        nat_t_header=p.nat_header)
    p.vpp_tun_sa = SecurityAssociation(
        encryption_type, spi=p.scapy_tun_spi,
        crypt_algo=p.crypt_algo,
        crypt_key=crypt_key,
        auth_algo=p.auth_algo, auth_key=p.auth_key,
        esn_en=esn_en,
        nat_t_header=p.nat_header)


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
        config_tun_params(p, self.encryption_type, p.tun_if)

        r = VppIpRoute(self, p.remote_tun_if_host, 32,
                       [VppRoutePath(p.tun_if.remote_ip4,
                                     0xffffffff)])
        r.add_vpp_config()
        r = VppIpRoute(self, p.remote_tun_if_host6, 128,
                       [VppRoutePath(p.tun_if.remote_ip6,
                                     0xffffffff,
                                     proto=DpoProto.DPO_PROTO_IP6)])
        r.add_vpp_config()

    def tearDown(self):
        super(TemplateIpsec4TunIfEsp, self).tearDown()


class TemplateIpsec4TunIfEspUdp(TemplateIpsec):
    """ IPsec UDP tunnel interface tests """

    tun4_encrypt_node_name = "esp4-encrypt-tun"
    tun4_decrypt_node_name = "esp4-decrypt-tun"
    encryption_type = ESP

    @classmethod
    def setUpClass(cls):
        super(TemplateIpsec4TunIfEspUdp, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TemplateIpsec4TunIfEspUdp, cls).tearDownClass()

    def verify_encrypted(self, p, sa, rxs):
        for rx in rxs:
            try:
                # ensure the UDP ports are correct before we decrypt
                # which strips them
                self.assertTrue(rx.haslayer(UDP))
                self.assert_equal(rx[UDP].sport, 4500)
                self.assert_equal(rx[UDP].dport, 4500)

                pkt = sa.decrypt(rx[IP])
                if not pkt.haslayer(IP):
                    pkt = IP(pkt[Raw].load)

                self.assert_packet_checksums_valid(pkt)
                self.assert_equal(pkt[IP].dst, "1.1.1.1")
                self.assert_equal(pkt[IP].src, self.pg1.remote_ip4)
            except (IndexError, AssertionError):
                self.logger.debug(ppp("Unexpected packet:", rx))
                try:
                    self.logger.debug(ppp("Decrypted packet:", pkt))
                except:
                    pass
                raise

    def setUp(self):
        super(TemplateIpsec4TunIfEspUdp, self).setUp()

        p = self.ipv4_params
        p.flags = (VppEnum.vl_api_ipsec_sad_flags_t.
                   IPSEC_API_SAD_FLAG_UDP_ENCAP)
        p.nat_header = UDP(sport=5454, dport=4500)

    def config_network(self):

        self.tun_if = self.pg0
        p = self.ipv4_params
        p.tun_if = VppIpsecTunInterface(self, self.pg0, p.vpp_tun_spi,
                                        p.scapy_tun_spi, p.crypt_algo_vpp_id,
                                        p.crypt_key, p.crypt_key,
                                        p.auth_algo_vpp_id, p.auth_key,
                                        p.auth_key, udp_encap=True)
        p.tun_if.add_vpp_config()
        p.tun_if.admin_up()
        p.tun_if.config_ip4()
        p.tun_if.config_ip6()
        config_tun_params(p, self.encryption_type, p.tun_if)

        r = VppIpRoute(self, p.remote_tun_if_host, 32,
                       [VppRoutePath(p.tun_if.remote_ip4,
                                     0xffffffff)])
        r.add_vpp_config()
        r = VppIpRoute(self, p.remote_tun_if_host6, 128,
                       [VppRoutePath(p.tun_if.remote_ip6,
                                     0xffffffff,
                                     proto=DpoProto.DPO_PROTO_IP6)])
        r.add_vpp_config()

    def tearDown(self):
        super(TemplateIpsec4TunIfEspUdp, self).tearDown()


class TestIpsec4TunIfEsp1(TemplateIpsec4TunIfEsp, IpsecTun4Tests):
    """ Ipsec ESP - TUN tests """
    tun4_encrypt_node_name = "esp4-encrypt-tun"
    tun4_decrypt_node_name = "esp4-decrypt-tun"

    def test_tun_basic64(self):
        """ ipsec 6o4 tunnel basic test """
        self.tun4_encrypt_node_name = "esp4-encrypt-tun"

        self.verify_tun_64(self.params[socket.AF_INET], count=1)

    def test_tun_burst64(self):
        """ ipsec 6o4 tunnel basic test """
        self.tun4_encrypt_node_name = "esp4-encrypt-tun"

        self.verify_tun_64(self.params[socket.AF_INET], count=257)

    def test_tun_basic_frag44(self):
        """ ipsec 4o4 tunnel frag basic test """
        self.tun4_encrypt_node_name = "esp4-encrypt-tun"

        p = self.ipv4_params

        self.vapi.sw_interface_set_mtu(p.tun_if.sw_if_index,
                                       [1500, 0, 0, 0])
        self.verify_tun_44(self.params[socket.AF_INET],
                           count=1, payload_size=1800, n_rx=2)
        self.vapi.sw_interface_set_mtu(p.tun_if.sw_if_index,
                                       [9000, 0, 0, 0])


class TestIpsec4TunIfEspUdp(TemplateIpsec4TunIfEspUdp, IpsecTun4Tests):
    """ Ipsec ESP UDP tests """

    tun4_input_node = "ipsec4-tun-input"

    def setUp(self):
        super(TemplateIpsec4TunIfEspUdp, self).setUp()
        self.config_network()

    def test_keepalive(self):
        """ IPSEC NAT Keepalive """
        self.verify_keepalive(self.ipv4_params)


class TestIpsec4TunIfEspUdpGCM(TemplateIpsec4TunIfEspUdp, IpsecTun4Tests):
    """ Ipsec ESP UDP GCM tests """

    tun4_input_node = "ipsec4-tun-input"

    def setUp(self):
        super(TemplateIpsec4TunIfEspUdp, self).setUp()
        p = self.ipv4_params
        p.auth_algo_vpp_id = (VppEnum.vl_api_ipsec_integ_alg_t.
                              IPSEC_API_INTEG_ALG_NONE)
        p.crypt_algo_vpp_id = (VppEnum.vl_api_ipsec_crypto_alg_t.
                               IPSEC_API_CRYPTO_ALG_AES_GCM_256)
        p.crypt_algo = "AES-GCM"
        p.auth_algo = "NULL"
        p.crypt_key = b"JPjyOWBeVEQiMe7hJPjyOWBeVEQiMe7h"
        p.salt = 0
        self.config_network()


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
        p.tun_if = VppIpsecTunInterface(self, self.pg0, p.vpp_tun_spi,
                                        p.scapy_tun_spi, p.crypt_algo_vpp_id,
                                        p.crypt_key, p.crypt_key,
                                        p.auth_algo_vpp_id, p.auth_key,
                                        p.auth_key, is_ip6=True)
        p.tun_if.add_vpp_config()
        p.tun_if.admin_up()
        p.tun_if.config_ip6()
        p.tun_if.config_ip4()
        config_tun_params(p, self.encryption_type, p.tun_if)

        r = VppIpRoute(self, p.remote_tun_if_host, 128,
                       [VppRoutePath(p.tun_if.remote_ip6,
                                     0xffffffff,
                                     proto=DpoProto.DPO_PROTO_IP6)])
        r.add_vpp_config()
        r = VppIpRoute(self, p.remote_tun_if_host4, 32,
                       [VppRoutePath(p.tun_if.remote_ip4,
                                     0xffffffff)])
        r.add_vpp_config()

    def tearDown(self):
        super(TemplateIpsec6TunIfEsp, self).tearDown()


class TestIpsec6TunIfEsp1(TemplateIpsec6TunIfEsp,
                          IpsecTun6Tests):
    """ Ipsec ESP - TUN tests """
    tun6_encrypt_node_name = "esp6-encrypt-tun"
    tun6_decrypt_node_name = "esp6-decrypt-tun"

    def test_tun_basic46(self):
        """ ipsec 4o6 tunnel basic test """
        self.tun6_encrypt_node_name = "esp6-encrypt-tun"
        self.verify_tun_46(self.params[socket.AF_INET6], count=1)

    def test_tun_burst46(self):
        """ ipsec 4o6 tunnel burst test """
        self.tun6_encrypt_node_name = "esp6-encrypt-tun"
        self.verify_tun_46(self.params[socket.AF_INET6], count=257)


class TestIpsec6TunIfEspHandoff(TemplateIpsec6TunIfEsp,
                                IpsecTun6HandoffTests):
    """ Ipsec ESP 6 Handoff tests """
    tun6_encrypt_node_name = "esp6-encrypt-tun"
    tun6_decrypt_node_name = "esp6-decrypt-tun"


class TestIpsec4TunIfEspHandoff(TemplateIpsec4TunIfEsp,
                                IpsecTun4HandoffTests):
    """ Ipsec ESP 4 Handoff tests """
    tun4_encrypt_node_name = "esp4-encrypt-tun"
    tun4_decrypt_node_name = "esp4-decrypt-tun"


class TestIpsec4MultiTunIfEsp(TemplateIpsec, IpsecTun4):
    """ IPsec IPv4 Multi Tunnel interface """

    encryption_type = ESP
    tun4_encrypt_node_name = "esp4-encrypt-tun"
    tun4_decrypt_node_name = "esp4-decrypt-tun"

    def setUp(self):
        super(TestIpsec4MultiTunIfEsp, self).setUp()

        self.tun_if = self.pg0

        self.multi_params = []
        self.pg0.generate_remote_hosts(10)
        self.pg0.configure_ipv4_neighbors()

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
            p.tun_dst = self.pg0.remote_hosts[ii].ip4

            p.tun_if = VppIpsecTunInterface(self, self.pg0, p.vpp_tun_spi,
                                            p.scapy_tun_spi,
                                            p.crypt_algo_vpp_id,
                                            p.crypt_key, p.crypt_key,
                                            p.auth_algo_vpp_id, p.auth_key,
                                            p.auth_key,
                                            dst=p.tun_dst)
            p.tun_if.add_vpp_config()
            p.tun_if.admin_up()
            p.tun_if.config_ip4()
            config_tun_params(p, self.encryption_type, p.tun_if)
            self.multi_params.append(p)

            VppIpRoute(self, p.remote_tun_if_host, 32,
                       [VppRoutePath(p.tun_if.remote_ip4,
                                     0xffffffff)]).add_vpp_config()

    def tearDown(self):
        super(TestIpsec4MultiTunIfEsp, self).tearDown()

    def test_tun_44(self):
        """Multiple IPSEC tunnel interfaces """
        for p in self.multi_params:
            self.verify_tun_44(p, count=127)
            c = p.tun_if.get_rx_stats()
            self.assertEqual(c['packets'], 127)
            c = p.tun_if.get_tx_stats()
            self.assertEqual(c['packets'], 127)

    def test_tun_rr_44(self):
        """ Round-robin packets acrros multiple interface """
        tx = []
        for p in self.multi_params:
            tx = tx + self.gen_encrypt_pkts(p, p.scapy_tun_sa, self.tun_if,
                                            src=p.remote_tun_if_host,
                                            dst=self.pg1.remote_ip4)
        rxs = self.send_and_expect(self.tun_if, tx, self.pg1)

        for rx, p in zip(rxs, self.multi_params):
            self.verify_decrypted(p, [rx])

        tx = []
        for p in self.multi_params:
            tx = tx + self.gen_pkts(self.pg1, src=self.pg1.remote_ip4,
                                    dst=p.remote_tun_if_host)
        rxs = self.send_and_expect(self.pg1, tx, self.tun_if)

        for rx, p in zip(rxs, self.multi_params):
            self.verify_encrypted(p, p.vpp_tun_sa, [rx])


class TestIpsec4TunIfEspAll(TemplateIpsec, IpsecTun4):
    """ IPsec IPv4 Tunnel interface all Algos """

    encryption_type = ESP
    tun4_encrypt_node_name = "esp4-encrypt-tun"
    tun4_decrypt_node_name = "esp4-decrypt-tun"

    def config_network(self, p):

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
        config_tun_params(p, self.encryption_type, p.tun_if)
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
        p.crypt_key = b'X' + p.crypt_key[1:]
        p.scapy_tun_spi += 1
        p.scapy_tun_sa_id += 1
        p.vpp_tun_spi += 1
        p.vpp_tun_sa_id += 1
        p.tun_if.local_spi = p.vpp_tun_spi
        p.tun_if.remote_spi = p.scapy_tun_spi

        config_tun_params(p, self.encryption_type, p.tun_if)

        p.tun_sa_in = VppIpsecSA(self,
                                 p.scapy_tun_sa_id,
                                 p.scapy_tun_spi,
                                 p.auth_algo_vpp_id,
                                 p.auth_key,
                                 p.crypt_algo_vpp_id,
                                 p.crypt_key,
                                 self.vpp_esp_protocol,
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
                  'key': b"JPjyOWBeVEQiMe7h",
                  'salt': 3333},
                 {'vpp-crypto': (VppEnum.vl_api_ipsec_crypto_alg_t.
                                 IPSEC_API_CRYPTO_ALG_AES_GCM_192),
                  'vpp-integ': (VppEnum.vl_api_ipsec_integ_alg_t.
                                IPSEC_API_INTEG_ALG_NONE),
                  'scapy-crypto': "AES-GCM",
                  'scapy-integ': "NULL",
                  'key': b"JPjyOWBeVEQiMe7hJPjyOWBe",
                  'salt': 0},
                 {'vpp-crypto': (VppEnum.vl_api_ipsec_crypto_alg_t.
                                 IPSEC_API_CRYPTO_ALG_AES_GCM_256),
                  'vpp-integ': (VppEnum.vl_api_ipsec_integ_alg_t.
                                IPSEC_API_INTEG_ALG_NONE),
                  'scapy-crypto': "AES-GCM",
                  'scapy-integ': "NULL",
                  'key': b"JPjyOWBeVEQiMe7hJPjyOWBeVEQiMe7h",
                  'salt': 9999},
                 {'vpp-crypto': (VppEnum.vl_api_ipsec_crypto_alg_t.
                                 IPSEC_API_CRYPTO_ALG_AES_CBC_128),
                  'vpp-integ': (VppEnum.vl_api_ipsec_integ_alg_t.
                                IPSEC_API_INTEG_ALG_SHA1_96),
                  'scapy-crypto': "AES-CBC",
                  'scapy-integ': "HMAC-SHA1-96",
                  'salt': 0,
                  'key': b"JPjyOWBeVEQiMe7h"},
                 {'vpp-crypto': (VppEnum.vl_api_ipsec_crypto_alg_t.
                                 IPSEC_API_CRYPTO_ALG_AES_CBC_192),
                  'vpp-integ': (VppEnum.vl_api_ipsec_integ_alg_t.
                                IPSEC_API_INTEG_ALG_SHA_512_256),
                  'scapy-crypto': "AES-CBC",
                  'scapy-integ': "SHA2-512-256",
                  'salt': 0,
                  'key': b"JPjyOWBeVEQiMe7hJPjyOWBe"},
                 {'vpp-crypto': (VppEnum.vl_api_ipsec_crypto_alg_t.
                                 IPSEC_API_CRYPTO_ALG_AES_CBC_256),
                  'vpp-integ': (VppEnum.vl_api_ipsec_integ_alg_t.
                                IPSEC_API_INTEG_ALG_SHA_256_128),
                  'scapy-crypto': "AES-CBC",
                  'scapy-integ': "SHA2-256-128",
                  'salt': 0,
                  'key': b"JPjyOWBeVEQiMe7hJPjyOWBeVEQiMe7h"},
                 {'vpp-crypto': (VppEnum.vl_api_ipsec_crypto_alg_t.
                                 IPSEC_API_CRYPTO_ALG_NONE),
                  'vpp-integ': (VppEnum.vl_api_ipsec_integ_alg_t.
                                IPSEC_API_INTEG_ALG_SHA1_96),
                  'scapy-crypto': "NULL",
                  'scapy-integ': "HMAC-SHA1-96",
                  'salt': 0,
                  'key': b"JPjyOWBeVEQiMe7hJPjyOWBeVEQiMe7h"}]

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


class TestIpsec4TunIfEspNoAlgo(TemplateIpsec, IpsecTun4):
    """ IPsec IPv4 Tunnel interface no Algos """

    encryption_type = ESP
    tun4_encrypt_node_name = "esp4-encrypt-tun"
    tun4_decrypt_node_name = "esp4-decrypt-tun"

    def config_network(self, p):

        p.auth_algo_vpp_id = (VppEnum.vl_api_ipsec_integ_alg_t.
                              IPSEC_API_INTEG_ALG_NONE)
        p.auth_algo = 'NULL'
        p.auth_key = []

        p.crypt_algo_vpp_id = (VppEnum.vl_api_ipsec_crypto_alg_t.
                               IPSEC_API_CRYPTO_ALG_NONE)
        p.crypt_algo = 'NULL'
        p.crypt_key = []

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
        config_tun_params(p, self.encryption_type, p.tun_if)
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
        super(TestIpsec4TunIfEspNoAlgo, self).setUp()

        self.tun_if = self.pg0

    def tearDown(self):
        super(TestIpsec4TunIfEspNoAlgo, self).tearDown()

    def test_tun_44(self):
        """ IPSec SA with NULL algos """
        p = self.ipv4_params

        self.config_network(p)

        tx = self.gen_pkts(self.pg1, src=self.pg1.remote_ip4,
                           dst=p.remote_tun_if_host)
        self.send_and_assert_no_replies(self.pg1, tx)

        self.unconfig_network(p)


class TestIpsec6MultiTunIfEsp(TemplateIpsec, IpsecTun6):
    """ IPsec IPv6 Multi Tunnel interface """

    encryption_type = ESP
    tun6_encrypt_node_name = "esp6-encrypt-tun"
    tun6_decrypt_node_name = "esp6-decrypt-tun"

    def setUp(self):
        super(TestIpsec6MultiTunIfEsp, self).setUp()

        self.tun_if = self.pg0

        self.multi_params = []
        self.pg0.generate_remote_hosts(10)
        self.pg0.configure_ipv6_neighbors()

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

            p.tun_if = VppIpsecTunInterface(self, self.pg0, p.vpp_tun_spi,
                                            p.scapy_tun_spi,
                                            p.crypt_algo_vpp_id,
                                            p.crypt_key, p.crypt_key,
                                            p.auth_algo_vpp_id, p.auth_key,
                                            p.auth_key, is_ip6=True,
                                            dst=self.pg0.remote_hosts[ii].ip6)
            p.tun_if.add_vpp_config()
            p.tun_if.admin_up()
            p.tun_if.config_ip6()
            config_tun_params(p, self.encryption_type, p.tun_if)
            self.multi_params.append(p)

            r = VppIpRoute(self, p.remote_tun_if_host, 128,
                           [VppRoutePath(p.tun_if.remote_ip6,
                                         0xffffffff,
                                         proto=DpoProto.DPO_PROTO_IP6)])
            r.add_vpp_config()

    def tearDown(self):
        super(TestIpsec6MultiTunIfEsp, self).tearDown()

    def test_tun_66(self):
        """Multiple IPSEC tunnel interfaces """
        for p in self.multi_params:
            self.verify_tun_66(p, count=127)
            c = p.tun_if.get_rx_stats()
            self.assertEqual(c['packets'], 127)
            c = p.tun_if.get_tx_stats()
            self.assertEqual(c['packets'], 127)


class TestIpsecGreTebIfEsp(TemplateIpsec,
                           IpsecTun4Tests):
    """ Ipsec GRE TEB ESP - TUN tests """
    tun4_encrypt_node_name = "esp4-encrypt-tun"
    tun4_decrypt_node_name = "esp4-decrypt-tun"
    encryption_type = ESP
    omac = "00:11:22:33:44:55"

    def gen_encrypt_pkts(self, p, sa, sw_intf, src, dst, count=1,
                         payload_size=100):
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                sa.encrypt(IP(src=self.pg0.remote_ip4,
                              dst=self.pg0.local_ip4) /
                           GRE() /
                           Ether(dst=self.omac) /
                           IP(src="1.1.1.1", dst="1.1.1.2") /
                           UDP(sport=1144, dport=2233) /
                           Raw(b'X' * payload_size))
                for i in range(count)]

    def gen_pkts(self, sw_intf, src, dst, count=1,
                 payload_size=100):
        return [Ether(dst=self.omac) /
                IP(src="1.1.1.1", dst="1.1.1.2") /
                UDP(sport=1144, dport=2233) /
                Raw(b'X' * payload_size)
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
        super(TestIpsecGreTebIfEsp, self).setUp()

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

        p.tun_if = VppGreInterface(self,
                                   self.pg0.local_ip4,
                                   self.pg0.remote_ip4,
                                   type=(VppEnum.vl_api_gre_tunnel_type_t.
                                         GRE_API_TUNNEL_TYPE_TEB))
        p.tun_if.add_vpp_config()

        p.tun_protect = VppIpsecTunProtect(self,
                                           p.tun_if,
                                           p.tun_sa_out,
                                           [p.tun_sa_in])

        p.tun_protect.add_vpp_config()

        p.tun_if.admin_up()
        p.tun_if.config_ip4()
        config_tun_params(p, self.encryption_type, p.tun_if)

        VppBridgeDomainPort(self, bd1, p.tun_if).add_vpp_config()
        VppBridgeDomainPort(self, bd1, self.pg1).add_vpp_config()

        self.vapi.cli("clear ipsec sa")
        self.vapi.cli("sh adj")
        self.vapi.cli("sh ipsec tun")

    def tearDown(self):
        p = self.ipv4_params
        p.tun_if.unconfig_ip4()
        super(TestIpsecGreTebIfEsp, self).tearDown()


class TestIpsecGreTebVlanIfEsp(TemplateIpsec,
                               IpsecTun4Tests):
    """ Ipsec GRE TEB ESP - TUN tests """
    tun4_encrypt_node_name = "esp4-encrypt-tun"
    tun4_decrypt_node_name = "esp4-decrypt-tun"
    encryption_type = ESP
    omac = "00:11:22:33:44:55"

    def gen_encrypt_pkts(self, p, sa, sw_intf, src, dst, count=1,
                         payload_size=100):
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                sa.encrypt(IP(src=self.pg0.remote_ip4,
                              dst=self.pg0.local_ip4) /
                           GRE() /
                           Ether(dst=self.omac) /
                           IP(src="1.1.1.1", dst="1.1.1.2") /
                           UDP(sport=1144, dport=2233) /
                           Raw(b'X' * payload_size))
                for i in range(count)]

    def gen_pkts(self, sw_intf, src, dst, count=1,
                 payload_size=100):
        return [Ether(dst=self.omac) /
                Dot1Q(vlan=11) /
                IP(src="1.1.1.1", dst="1.1.1.2") /
                UDP(sport=1144, dport=2233) /
                Raw(b'X' * payload_size)
                for i in range(count)]

    def verify_decrypted(self, p, rxs):
        for rx in rxs:
            self.assert_equal(rx[Ether].dst, self.omac)
            self.assert_equal(rx[Dot1Q].vlan, 11)
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
                self.assertFalse(e.haslayer(Dot1Q))
                self.assertEqual(e[IP].dst, "1.1.1.2")
            except (IndexError, AssertionError):
                self.logger.debug(ppp("Unexpected packet:", rx))
                try:
                    self.logger.debug(ppp("Decrypted packet:", pkt))
                except:
                    pass
                raise

    def setUp(self):
        super(TestIpsecGreTebVlanIfEsp, self).setUp()

        self.tun_if = self.pg0

        p = self.ipv4_params

        bd1 = VppBridgeDomain(self, 1)
        bd1.add_vpp_config()

        self.pg1_11 = VppDot1QSubint(self, self.pg1, 11)
        self.vapi.l2_interface_vlan_tag_rewrite(
            sw_if_index=self.pg1_11.sw_if_index, vtr_op=L2_VTR_OP.L2_POP_1,
            push_dot1q=11)
        self.pg1_11.admin_up()

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

        p.tun_if = VppGreInterface(self,
                                   self.pg0.local_ip4,
                                   self.pg0.remote_ip4,
                                   type=(VppEnum.vl_api_gre_tunnel_type_t.
                                         GRE_API_TUNNEL_TYPE_TEB))
        p.tun_if.add_vpp_config()

        p.tun_protect = VppIpsecTunProtect(self,
                                           p.tun_if,
                                           p.tun_sa_out,
                                           [p.tun_sa_in])

        p.tun_protect.add_vpp_config()

        p.tun_if.admin_up()
        p.tun_if.config_ip4()
        config_tun_params(p, self.encryption_type, p.tun_if)

        VppBridgeDomainPort(self, bd1, p.tun_if).add_vpp_config()
        VppBridgeDomainPort(self, bd1, self.pg1_11).add_vpp_config()

        self.vapi.cli("clear ipsec sa")

    def tearDown(self):
        p = self.ipv4_params
        p.tun_if.unconfig_ip4()
        super(TestIpsecGreTebVlanIfEsp, self).tearDown()
        self.pg1_11.admin_down()
        self.pg1_11.remove_vpp_config()


class TestIpsecGreTebIfEspTra(TemplateIpsec,
                              IpsecTun4Tests):
    """ Ipsec GRE TEB ESP - Tra tests """
    tun4_encrypt_node_name = "esp4-encrypt-tun"
    tun4_decrypt_node_name = "esp4-decrypt-tun"
    encryption_type = ESP
    omac = "00:11:22:33:44:55"

    def gen_encrypt_pkts(self, p, sa, sw_intf, src, dst, count=1,
                         payload_size=100):
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                sa.encrypt(IP(src=self.pg0.remote_ip4,
                              dst=self.pg0.local_ip4) /
                           GRE() /
                           Ether(dst=self.omac) /
                           IP(src="1.1.1.1", dst="1.1.1.2") /
                           UDP(sport=1144, dport=2233) /
                           Raw(b'X' * payload_size))
                for i in range(count)]

    def gen_pkts(self, sw_intf, src, dst, count=1,
                 payload_size=100):
        return [Ether(dst=self.omac) /
                IP(src="1.1.1.1", dst="1.1.1.2") /
                UDP(sport=1144, dport=2233) /
                Raw(b'X' * payload_size)
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
        super(TestIpsecGreTebIfEspTra, self).setUp()

        self.tun_if = self.pg0

        p = self.ipv4_params

        bd1 = VppBridgeDomain(self, 1)
        bd1.add_vpp_config()

        p.tun_sa_out = VppIpsecSA(self, p.scapy_tun_sa_id, p.scapy_tun_spi,
                                  p.auth_algo_vpp_id, p.auth_key,
                                  p.crypt_algo_vpp_id, p.crypt_key,
                                  self.vpp_esp_protocol)
        p.tun_sa_out.add_vpp_config()

        p.tun_sa_in = VppIpsecSA(self, p.vpp_tun_sa_id, p.vpp_tun_spi,
                                 p.auth_algo_vpp_id, p.auth_key,
                                 p.crypt_algo_vpp_id, p.crypt_key,
                                 self.vpp_esp_protocol)
        p.tun_sa_in.add_vpp_config()

        p.tun_if = VppGreInterface(self,
                                   self.pg0.local_ip4,
                                   self.pg0.remote_ip4,
                                   type=(VppEnum.vl_api_gre_tunnel_type_t.
                                         GRE_API_TUNNEL_TYPE_TEB))
        p.tun_if.add_vpp_config()

        p.tun_protect = VppIpsecTunProtect(self,
                                           p.tun_if,
                                           p.tun_sa_out,
                                           [p.tun_sa_in])

        p.tun_protect.add_vpp_config()

        p.tun_if.admin_up()
        p.tun_if.config_ip4()
        config_tra_params(p, self.encryption_type, p.tun_if)

        VppBridgeDomainPort(self, bd1, p.tun_if).add_vpp_config()
        VppBridgeDomainPort(self, bd1, self.pg1).add_vpp_config()

        self.vapi.cli("clear ipsec sa")

    def tearDown(self):
        p = self.ipv4_params
        p.tun_if.unconfig_ip4()
        super(TestIpsecGreTebIfEspTra, self).tearDown()


class TestIpsecGreTebUdpIfEspTra(TemplateIpsec,
                                 IpsecTun4Tests):
    """ Ipsec GRE TEB UDP ESP - Tra tests """
    tun4_encrypt_node_name = "esp4-encrypt-tun"
    tun4_decrypt_node_name = "esp4-decrypt-tun"
    encryption_type = ESP
    omac = "00:11:22:33:44:55"

    def gen_encrypt_pkts(self, p, sa, sw_intf, src, dst, count=1,
                         payload_size=100):
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                sa.encrypt(IP(src=self.pg0.remote_ip4,
                              dst=self.pg0.local_ip4) /
                           GRE() /
                           Ether(dst=self.omac) /
                           IP(src="1.1.1.1", dst="1.1.1.2") /
                           UDP(sport=1144, dport=2233) /
                           Raw(b'X' * payload_size))
                for i in range(count)]

    def gen_pkts(self, sw_intf, src, dst, count=1,
                 payload_size=100):
        return [Ether(dst=self.omac) /
                IP(src="1.1.1.1", dst="1.1.1.2") /
                UDP(sport=1144, dport=2233) /
                Raw(b'X' * payload_size)
                for i in range(count)]

    def verify_decrypted(self, p, rxs):
        for rx in rxs:
            self.assert_equal(rx[Ether].dst, self.omac)
            self.assert_equal(rx[IP].dst, "1.1.1.2")

    def verify_encrypted(self, p, sa, rxs):
        for rx in rxs:
            self.assertTrue(rx.haslayer(UDP))
            self.assertEqual(rx[UDP].dport, 4545)
            self.assertEqual(rx[UDP].sport, 5454)
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
        super(TestIpsecGreTebUdpIfEspTra, self).setUp()

        self.tun_if = self.pg0

        p = self.ipv4_params
        p = self.ipv4_params
        p.flags = (VppEnum.vl_api_ipsec_sad_flags_t.
                   IPSEC_API_SAD_FLAG_UDP_ENCAP)
        p.nat_header = UDP(sport=5454, dport=4545)

        bd1 = VppBridgeDomain(self, 1)
        bd1.add_vpp_config()

        p.tun_sa_out = VppIpsecSA(self, p.scapy_tun_sa_id, p.scapy_tun_spi,
                                  p.auth_algo_vpp_id, p.auth_key,
                                  p.crypt_algo_vpp_id, p.crypt_key,
                                  self.vpp_esp_protocol,
                                  flags=p.flags,
                                  udp_src=5454,
                                  udp_dst=4545)
        p.tun_sa_out.add_vpp_config()

        p.tun_sa_in = VppIpsecSA(self, p.vpp_tun_sa_id, p.vpp_tun_spi,
                                 p.auth_algo_vpp_id, p.auth_key,
                                 p.crypt_algo_vpp_id, p.crypt_key,
                                 self.vpp_esp_protocol,
                                 flags=(p.flags |
                                        VppEnum.vl_api_ipsec_sad_flags_t.
                                        IPSEC_API_SAD_FLAG_IS_INBOUND),
                                 udp_src=5454,
                                 udp_dst=4545)
        p.tun_sa_in.add_vpp_config()

        p.tun_if = VppGreInterface(self,
                                   self.pg0.local_ip4,
                                   self.pg0.remote_ip4,
                                   type=(VppEnum.vl_api_gre_tunnel_type_t.
                                         GRE_API_TUNNEL_TYPE_TEB))
        p.tun_if.add_vpp_config()

        p.tun_protect = VppIpsecTunProtect(self,
                                           p.tun_if,
                                           p.tun_sa_out,
                                           [p.tun_sa_in])

        p.tun_protect.add_vpp_config()

        p.tun_if.admin_up()
        p.tun_if.config_ip4()
        config_tra_params(p, self.encryption_type, p.tun_if)

        VppBridgeDomainPort(self, bd1, p.tun_if).add_vpp_config()
        VppBridgeDomainPort(self, bd1, self.pg1).add_vpp_config()

        self.vapi.cli("clear ipsec sa")
        self.logger.info(self.vapi.cli("sh ipsec sa 0"))

    def tearDown(self):
        p = self.ipv4_params
        p.tun_if.unconfig_ip4()
        super(TestIpsecGreTebUdpIfEspTra, self).tearDown()


class TestIpsecGreIfEsp(TemplateIpsec,
                        IpsecTun4Tests):
    """ Ipsec GRE ESP - TUN tests """
    tun4_encrypt_node_name = "esp4-encrypt-tun"
    tun4_decrypt_node_name = "esp4-decrypt-tun"
    encryption_type = ESP

    def gen_encrypt_pkts(self, p, sa, sw_intf, src, dst, count=1,
                         payload_size=100):
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                sa.encrypt(IP(src=self.pg0.remote_ip4,
                              dst=self.pg0.local_ip4) /
                           GRE() /
                           IP(src=self.pg1.local_ip4,
                              dst=self.pg1.remote_ip4) /
                           UDP(sport=1144, dport=2233) /
                           Raw(b'X' * payload_size))
                for i in range(count)]

    def gen_pkts(self, sw_intf, src, dst, count=1,
                 payload_size=100):
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                IP(src="1.1.1.1", dst="1.1.1.2") /
                UDP(sport=1144, dport=2233) /
                Raw(b'X' * payload_size)
                for i in range(count)]

    def verify_decrypted(self, p, rxs):
        for rx in rxs:
            self.assert_equal(rx[Ether].dst, self.pg1.remote_mac)
            self.assert_equal(rx[IP].dst, self.pg1.remote_ip4)

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
                e = pkt[GRE]
                self.assertEqual(e[IP].dst, "1.1.1.2")
            except (IndexError, AssertionError):
                self.logger.debug(ppp("Unexpected packet:", rx))
                try:
                    self.logger.debug(ppp("Decrypted packet:", pkt))
                except:
                    pass
                raise

    def setUp(self):
        super(TestIpsecGreIfEsp, self).setUp()

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

        p.tun_if = VppGreInterface(self,
                                   self.pg0.local_ip4,
                                   self.pg0.remote_ip4)
        p.tun_if.add_vpp_config()

        p.tun_protect = VppIpsecTunProtect(self,
                                           p.tun_if,
                                           p.tun_sa_out,
                                           [p.tun_sa_in])
        p.tun_protect.add_vpp_config()

        p.tun_if.admin_up()
        p.tun_if.config_ip4()
        config_tun_params(p, self.encryption_type, p.tun_if)

        VppIpRoute(self, "1.1.1.2", 32,
                   [VppRoutePath(p.tun_if.remote_ip4,
                                 0xffffffff)]).add_vpp_config()

    def tearDown(self):
        p = self.ipv4_params
        p.tun_if.unconfig_ip4()
        super(TestIpsecGreIfEsp, self).tearDown()


class TestIpsecGreIfEspTra(TemplateIpsec,
                           IpsecTun4Tests):
    """ Ipsec GRE ESP - TRA tests """
    tun4_encrypt_node_name = "esp4-encrypt-tun"
    tun4_decrypt_node_name = "esp4-decrypt-tun"
    encryption_type = ESP

    def gen_encrypt_pkts(self, p, sa, sw_intf, src, dst, count=1,
                         payload_size=100):
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                sa.encrypt(IP(src=self.pg0.remote_ip4,
                              dst=self.pg0.local_ip4) /
                           GRE() /
                           IP(src=self.pg1.local_ip4,
                              dst=self.pg1.remote_ip4) /
                           UDP(sport=1144, dport=2233) /
                           Raw(b'X' * payload_size))
                for i in range(count)]

    def gen_encrypt_non_ip_pkts(self, sa, sw_intf, src, dst, count=1,
                                payload_size=100):
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                sa.encrypt(IP(src=self.pg0.remote_ip4,
                              dst=self.pg0.local_ip4) /
                           GRE() /
                           UDP(sport=1144, dport=2233) /
                           Raw(b'X' * payload_size))
                for i in range(count)]

    def gen_pkts(self, sw_intf, src, dst, count=1,
                 payload_size=100):
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                IP(src="1.1.1.1", dst="1.1.1.2") /
                UDP(sport=1144, dport=2233) /
                Raw(b'X' * payload_size)
                for i in range(count)]

    def verify_decrypted(self, p, rxs):
        for rx in rxs:
            self.assert_equal(rx[Ether].dst, self.pg1.remote_mac)
            self.assert_equal(rx[IP].dst, self.pg1.remote_ip4)

    def verify_encrypted(self, p, sa, rxs):
        for rx in rxs:
            try:
                pkt = sa.decrypt(rx[IP])
                if not pkt.haslayer(IP):
                    pkt = IP(pkt[Raw].load)
                self.assert_packet_checksums_valid(pkt)
                self.assertTrue(pkt.haslayer(GRE))
                e = pkt[GRE]
                self.assertEqual(e[IP].dst, "1.1.1.2")
            except (IndexError, AssertionError):
                self.logger.debug(ppp("Unexpected packet:", rx))
                try:
                    self.logger.debug(ppp("Decrypted packet:", pkt))
                except:
                    pass
                raise

    def setUp(self):
        super(TestIpsecGreIfEspTra, self).setUp()

        self.tun_if = self.pg0

        p = self.ipv4_params

        p.tun_sa_out = VppIpsecSA(self, p.scapy_tun_sa_id, p.scapy_tun_spi,
                                  p.auth_algo_vpp_id, p.auth_key,
                                  p.crypt_algo_vpp_id, p.crypt_key,
                                  self.vpp_esp_protocol)
        p.tun_sa_out.add_vpp_config()

        p.tun_sa_in = VppIpsecSA(self, p.vpp_tun_sa_id, p.vpp_tun_spi,
                                 p.auth_algo_vpp_id, p.auth_key,
                                 p.crypt_algo_vpp_id, p.crypt_key,
                                 self.vpp_esp_protocol)
        p.tun_sa_in.add_vpp_config()

        p.tun_if = VppGreInterface(self,
                                   self.pg0.local_ip4,
                                   self.pg0.remote_ip4)
        p.tun_if.add_vpp_config()

        p.tun_protect = VppIpsecTunProtect(self,
                                           p.tun_if,
                                           p.tun_sa_out,
                                           [p.tun_sa_in])
        p.tun_protect.add_vpp_config()

        p.tun_if.admin_up()
        p.tun_if.config_ip4()
        config_tra_params(p, self.encryption_type, p.tun_if)

        VppIpRoute(self, "1.1.1.2", 32,
                   [VppRoutePath(p.tun_if.remote_ip4,
                                 0xffffffff)]).add_vpp_config()

    def tearDown(self):
        p = self.ipv4_params
        p.tun_if.unconfig_ip4()
        super(TestIpsecGreIfEspTra, self).tearDown()

    def test_gre_non_ip(self):
        p = self.ipv4_params
        tx = self.gen_encrypt_non_ip_pkts(p.scapy_tun_sa, self.tun_if,
                                          src=p.remote_tun_if_host,
                                          dst=self.pg1.remote_ip6)
        self.send_and_assert_no_replies(self.tun_if, tx)
        node_name = ('/err/%s/unsupported payload' %
                     self.tun4_decrypt_node_name)
        self.assertEqual(1, self.statistics.get_err_counter(node_name))


class TestIpsecGre6IfEspTra(TemplateIpsec,
                            IpsecTun6Tests):
    """ Ipsec GRE ESP - TRA tests """
    tun6_encrypt_node_name = "esp6-encrypt-tun"
    tun6_decrypt_node_name = "esp6-decrypt-tun"
    encryption_type = ESP

    def gen_encrypt_pkts6(self, p, sa, sw_intf, src, dst, count=1,
                          payload_size=100):
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                sa.encrypt(IPv6(src=self.pg0.remote_ip6,
                                dst=self.pg0.local_ip6) /
                           GRE() /
                           IPv6(src=self.pg1.local_ip6,
                                dst=self.pg1.remote_ip6) /
                           UDP(sport=1144, dport=2233) /
                           Raw(b'X' * payload_size))
                for i in range(count)]

    def gen_pkts6(self, sw_intf, src, dst, count=1,
                  payload_size=100):
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                IPv6(src="1::1", dst="1::2") /
                UDP(sport=1144, dport=2233) /
                Raw(b'X' * payload_size)
                for i in range(count)]

    def verify_decrypted6(self, p, rxs):
        for rx in rxs:
            self.assert_equal(rx[Ether].dst, self.pg1.remote_mac)
            self.assert_equal(rx[IPv6].dst, self.pg1.remote_ip6)

    def verify_encrypted6(self, p, sa, rxs):
        for rx in rxs:
            try:
                pkt = sa.decrypt(rx[IPv6])
                if not pkt.haslayer(IPv6):
                    pkt = IPv6(pkt[Raw].load)
                self.assert_packet_checksums_valid(pkt)
                self.assertTrue(pkt.haslayer(GRE))
                e = pkt[GRE]
                self.assertEqual(e[IPv6].dst, "1::2")
            except (IndexError, AssertionError):
                self.logger.debug(ppp("Unexpected packet:", rx))
                try:
                    self.logger.debug(ppp("Decrypted packet:", pkt))
                except:
                    pass
                raise

    def setUp(self):
        super(TestIpsecGre6IfEspTra, self).setUp()

        self.tun_if = self.pg0

        p = self.ipv6_params

        bd1 = VppBridgeDomain(self, 1)
        bd1.add_vpp_config()

        p.tun_sa_out = VppIpsecSA(self, p.scapy_tun_sa_id, p.scapy_tun_spi,
                                  p.auth_algo_vpp_id, p.auth_key,
                                  p.crypt_algo_vpp_id, p.crypt_key,
                                  self.vpp_esp_protocol)
        p.tun_sa_out.add_vpp_config()

        p.tun_sa_in = VppIpsecSA(self, p.vpp_tun_sa_id, p.vpp_tun_spi,
                                 p.auth_algo_vpp_id, p.auth_key,
                                 p.crypt_algo_vpp_id, p.crypt_key,
                                 self.vpp_esp_protocol)
        p.tun_sa_in.add_vpp_config()

        p.tun_if = VppGreInterface(self,
                                   self.pg0.local_ip6,
                                   self.pg0.remote_ip6)
        p.tun_if.add_vpp_config()

        p.tun_protect = VppIpsecTunProtect(self,
                                           p.tun_if,
                                           p.tun_sa_out,
                                           [p.tun_sa_in])
        p.tun_protect.add_vpp_config()

        p.tun_if.admin_up()
        p.tun_if.config_ip6()
        config_tra_params(p, self.encryption_type, p.tun_if)

        r = VppIpRoute(self, "1::2", 128,
                       [VppRoutePath(p.tun_if.remote_ip6,
                                     0xffffffff,
                                     proto=DpoProto.DPO_PROTO_IP6)])
        r.add_vpp_config()

    def tearDown(self):
        p = self.ipv6_params
        p.tun_if.unconfig_ip6()
        super(TestIpsecGre6IfEspTra, self).tearDown()


class TestIpsecMGreIfEspTra4(TemplateIpsec, IpsecTun4):
    """ Ipsec mGRE ESP v4 TRA tests """
    tun4_encrypt_node_name = "esp4-encrypt-tun"
    tun4_decrypt_node_name = "esp4-decrypt-tun"
    encryption_type = ESP

    def gen_encrypt_pkts(self, p, sa, sw_intf, src, dst, count=1,
                         payload_size=100):
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                sa.encrypt(IP(src=p.tun_dst,
                              dst=self.pg0.local_ip4) /
                           GRE() /
                           IP(src=self.pg1.local_ip4,
                              dst=self.pg1.remote_ip4) /
                           UDP(sport=1144, dport=2233) /
                           Raw(b'X' * payload_size))
                for i in range(count)]

    def gen_pkts(self, sw_intf, src, dst, count=1,
                 payload_size=100):
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                IP(src="1.1.1.1", dst=dst) /
                UDP(sport=1144, dport=2233) /
                Raw(b'X' * payload_size)
                for i in range(count)]

    def verify_decrypted(self, p, rxs):
        for rx in rxs:
            self.assert_equal(rx[Ether].dst, self.pg1.remote_mac)
            self.assert_equal(rx[IP].dst, self.pg1.remote_ip4)

    def verify_encrypted(self, p, sa, rxs):
        for rx in rxs:
            try:
                pkt = sa.decrypt(rx[IP])
                if not pkt.haslayer(IP):
                    pkt = IP(pkt[Raw].load)
                self.assert_packet_checksums_valid(pkt)
                self.assertTrue(pkt.haslayer(GRE))
                e = pkt[GRE]
                self.assertEqual(e[IP].dst, p.remote_tun_if_host)
            except (IndexError, AssertionError):
                self.logger.debug(ppp("Unexpected packet:", rx))
                try:
                    self.logger.debug(ppp("Decrypted packet:", pkt))
                except:
                    pass
                raise

    def setUp(self):
        super(TestIpsecMGreIfEspTra4, self).setUp()

        N_NHS = 16
        self.tun_if = self.pg0
        p = self.ipv4_params
        p.tun_if = VppGreInterface(self,
                                   self.pg0.local_ip4,
                                   "0.0.0.0",
                                   mode=(VppEnum.vl_api_tunnel_mode_t.
                                         TUNNEL_API_MODE_MP))
        p.tun_if.add_vpp_config()
        p.tun_if.admin_up()
        p.tun_if.config_ip4()
        p.tun_if.generate_remote_hosts(N_NHS)
        self.pg0.generate_remote_hosts(N_NHS)
        self.pg0.configure_ipv4_neighbors()

        # setup some SAs for several next-hops on the interface
        self.multi_params = []

        for ii in range(N_NHS):
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
            p.tun_sa_out = VppIpsecSA(self, p.scapy_tun_sa_id, p.scapy_tun_spi,
                                      p.auth_algo_vpp_id, p.auth_key,
                                      p.crypt_algo_vpp_id, p.crypt_key,
                                      self.vpp_esp_protocol)
            p.tun_sa_out.add_vpp_config()

            p.tun_sa_in = VppIpsecSA(self, p.vpp_tun_sa_id, p.vpp_tun_spi,
                                     p.auth_algo_vpp_id, p.auth_key,
                                     p.crypt_algo_vpp_id, p.crypt_key,
                                     self.vpp_esp_protocol)
            p.tun_sa_in.add_vpp_config()

            p.tun_protect = VppIpsecTunProtect(
                self,
                p.tun_if,
                p.tun_sa_out,
                [p.tun_sa_in],
                nh=p.tun_if.remote_hosts[ii].ip4)
            p.tun_protect.add_vpp_config()
            config_tra_params(p, self.encryption_type, p.tun_if)
            self.multi_params.append(p)

            VppIpRoute(self, p.remote_tun_if_host, 32,
                       [VppRoutePath(p.tun_if.remote_hosts[ii].ip4,
                                     p.tun_if.sw_if_index)]).add_vpp_config()

            # in this v4 variant add the teibs after the protect
            p.teib = VppTeib(self, p.tun_if,
                             p.tun_if.remote_hosts[ii].ip4,
                             self.pg0.remote_hosts[ii].ip4).add_vpp_config()
            p.tun_dst = self.pg0.remote_hosts[ii].ip4
        self.logger.info(self.vapi.cli("sh ipsec protect-hash"))

    def tearDown(self):
        p = self.ipv4_params
        p.tun_if.unconfig_ip4()
        super(TestIpsecMGreIfEspTra4, self).tearDown()

    def test_tun_44(self):
        """mGRE IPSEC 44"""
        N_PKTS = 63
        for p in self.multi_params:
            self.verify_tun_44(p, count=N_PKTS)
            p.teib.remove_vpp_config()
            self.verify_tun_dropped_44(p, count=N_PKTS)
            p.teib.add_vpp_config()
            self.verify_tun_44(p, count=N_PKTS)


class TestIpsecMGreIfEspTra6(TemplateIpsec, IpsecTun6):
    """ Ipsec mGRE ESP v6 TRA tests """
    tun6_encrypt_node_name = "esp6-encrypt-tun"
    tun6_decrypt_node_name = "esp6-decrypt-tun"
    encryption_type = ESP

    def gen_encrypt_pkts6(self, p, sa, sw_intf, src, dst, count=1,
                          payload_size=100):
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                sa.encrypt(IPv6(src=p.tun_dst,
                                dst=self.pg0.local_ip6) /
                           GRE() /
                           IPv6(src=self.pg1.local_ip6,
                                dst=self.pg1.remote_ip6) /
                           UDP(sport=1144, dport=2233) /
                           Raw(b'X' * payload_size))
                for i in range(count)]

    def gen_pkts6(self, sw_intf, src, dst, count=1,
                  payload_size=100):
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                IPv6(src="1::1", dst=dst) /
                UDP(sport=1144, dport=2233) /
                Raw(b'X' * payload_size)
                for i in range(count)]

    def verify_decrypted6(self, p, rxs):
        for rx in rxs:
            self.assert_equal(rx[Ether].dst, self.pg1.remote_mac)
            self.assert_equal(rx[IPv6].dst, self.pg1.remote_ip6)

    def verify_encrypted6(self, p, sa, rxs):
        for rx in rxs:
            try:
                pkt = sa.decrypt(rx[IPv6])
                if not pkt.haslayer(IPv6):
                    pkt = IPv6(pkt[Raw].load)
                self.assert_packet_checksums_valid(pkt)
                self.assertTrue(pkt.haslayer(GRE))
                e = pkt[GRE]
                self.assertEqual(e[IPv6].dst, p.remote_tun_if_host)
            except (IndexError, AssertionError):
                self.logger.debug(ppp("Unexpected packet:", rx))
                try:
                    self.logger.debug(ppp("Decrypted packet:", pkt))
                except:
                    pass
                raise

    def setUp(self):
        super(TestIpsecMGreIfEspTra6, self).setUp()

        self.vapi.cli("set logging class ipsec level debug")

        N_NHS = 16
        self.tun_if = self.pg0
        p = self.ipv6_params
        p.tun_if = VppGreInterface(self,
                                   self.pg0.local_ip6,
                                   "::",
                                   mode=(VppEnum.vl_api_tunnel_mode_t.
                                         TUNNEL_API_MODE_MP))
        p.tun_if.add_vpp_config()
        p.tun_if.admin_up()
        p.tun_if.config_ip6()
        p.tun_if.generate_remote_hosts(N_NHS)
        self.pg0.generate_remote_hosts(N_NHS)
        self.pg0.configure_ipv6_neighbors()

        # setup some SAs for several next-hops on the interface
        self.multi_params = []

        for ii in range(N_NHS):
            p = copy.copy(self.ipv6_params)

            p.remote_tun_if_host = "1::%d" % (ii + 1)
            p.scapy_tun_sa_id = p.scapy_tun_sa_id + ii
            p.scapy_tun_spi = p.scapy_tun_spi + ii
            p.vpp_tun_sa_id = p.vpp_tun_sa_id + ii
            p.vpp_tun_spi = p.vpp_tun_spi + ii

            p.scapy_tra_sa_id = p.scapy_tra_sa_id + ii
            p.scapy_tra_spi = p.scapy_tra_spi + ii
            p.vpp_tra_sa_id = p.vpp_tra_sa_id + ii
            p.vpp_tra_spi = p.vpp_tra_spi + ii
            p.tun_sa_out = VppIpsecSA(self, p.scapy_tun_sa_id, p.scapy_tun_spi,
                                      p.auth_algo_vpp_id, p.auth_key,
                                      p.crypt_algo_vpp_id, p.crypt_key,
                                      self.vpp_esp_protocol)
            p.tun_sa_out.add_vpp_config()

            p.tun_sa_in = VppIpsecSA(self, p.vpp_tun_sa_id, p.vpp_tun_spi,
                                     p.auth_algo_vpp_id, p.auth_key,
                                     p.crypt_algo_vpp_id, p.crypt_key,
                                     self.vpp_esp_protocol)
            p.tun_sa_in.add_vpp_config()

            # in this v6 variant add the teibs first then the protection
            p.tun_dst = self.pg0.remote_hosts[ii].ip6
            VppTeib(self, p.tun_if,
                    p.tun_if.remote_hosts[ii].ip6,
                    p.tun_dst).add_vpp_config()

            p.tun_protect = VppIpsecTunProtect(
                self,
                p.tun_if,
                p.tun_sa_out,
                [p.tun_sa_in],
                nh=p.tun_if.remote_hosts[ii].ip6)
            p.tun_protect.add_vpp_config()
            config_tra_params(p, self.encryption_type, p.tun_if)
            self.multi_params.append(p)

            VppIpRoute(self, p.remote_tun_if_host, 128,
                       [VppRoutePath(p.tun_if.remote_hosts[ii].ip6,
                                     p.tun_if.sw_if_index)]).add_vpp_config()
            p.tun_dst = self.pg0.remote_hosts[ii].ip6

        self.logger.info(self.vapi.cli("sh log"))
        self.logger.info(self.vapi.cli("sh ipsec protect-hash"))
        self.logger.info(self.vapi.cli("sh adj 41"))

    def tearDown(self):
        p = self.ipv6_params
        p.tun_if.unconfig_ip6()
        super(TestIpsecMGreIfEspTra6, self).tearDown()

    def test_tun_66(self):
        """mGRE IPSec 66"""
        for p in self.multi_params:
            self.verify_tun_66(p, count=63)


class TemplateIpsec4TunProtect(object):
    """ IPsec IPv4 Tunnel protect """

    encryption_type = ESP
    tun4_encrypt_node_name = "esp4-encrypt-tun"
    tun4_decrypt_node_name = "esp4-decrypt-tun"
    tun4_input_node = "ipsec4-tun-input"

    def config_sa_tra(self, p):
        config_tun_params(p, self.encryption_type, p.tun_if)

        p.tun_sa_out = VppIpsecSA(self, p.scapy_tun_sa_id, p.scapy_tun_spi,
                                  p.auth_algo_vpp_id, p.auth_key,
                                  p.crypt_algo_vpp_id, p.crypt_key,
                                  self.vpp_esp_protocol,
                                  flags=p.flags)
        p.tun_sa_out.add_vpp_config()

        p.tun_sa_in = VppIpsecSA(self, p.vpp_tun_sa_id, p.vpp_tun_spi,
                                 p.auth_algo_vpp_id, p.auth_key,
                                 p.crypt_algo_vpp_id, p.crypt_key,
                                 self.vpp_esp_protocol,
                                 flags=p.flags)
        p.tun_sa_in.add_vpp_config()

    def config_sa_tun(self, p):
        config_tun_params(p, self.encryption_type, p.tun_if)

        p.tun_sa_out = VppIpsecSA(self, p.scapy_tun_sa_id, p.scapy_tun_spi,
                                  p.auth_algo_vpp_id, p.auth_key,
                                  p.crypt_algo_vpp_id, p.crypt_key,
                                  self.vpp_esp_protocol,
                                  self.tun_if.local_addr[p.addr_type],
                                  self.tun_if.remote_addr[p.addr_type],
                                  flags=p.flags)
        p.tun_sa_out.add_vpp_config()

        p.tun_sa_in = VppIpsecSA(self, p.vpp_tun_sa_id, p.vpp_tun_spi,
                                 p.auth_algo_vpp_id, p.auth_key,
                                 p.crypt_algo_vpp_id, p.crypt_key,
                                 self.vpp_esp_protocol,
                                 self.tun_if.remote_addr[p.addr_type],
                                 self.tun_if.local_addr[p.addr_type],
                                 flags=p.flags)
        p.tun_sa_in.add_vpp_config()

    def config_protect(self, p):
        p.tun_protect = VppIpsecTunProtect(self,
                                           p.tun_if,
                                           p.tun_sa_out,
                                           [p.tun_sa_in])
        p.tun_protect.add_vpp_config()

    def config_network(self, p):
        p.tun_if = VppIpIpTunInterface(self, self.pg0,
                                       self.pg0.local_ip4,
                                       self.pg0.remote_ip4)
        p.tun_if.add_vpp_config()
        p.tun_if.admin_up()
        p.tun_if.config_ip4()
        p.tun_if.config_ip6()

        p.route = VppIpRoute(self, p.remote_tun_if_host, 32,
                             [VppRoutePath(p.tun_if.remote_ip4,
                                           0xffffffff)])
        p.route.add_vpp_config()
        r = VppIpRoute(self, p.remote_tun_if_host6, 128,
                       [VppRoutePath(p.tun_if.remote_ip6,
                                     0xffffffff,
                                     proto=DpoProto.DPO_PROTO_IP6)])
        r.add_vpp_config()

    def unconfig_network(self, p):
        p.route.remove_vpp_config()
        p.tun_if.remove_vpp_config()

    def unconfig_protect(self, p):
        p.tun_protect.remove_vpp_config()

    def unconfig_sa(self, p):
        p.tun_sa_out.remove_vpp_config()
        p.tun_sa_in.remove_vpp_config()


class TestIpsec4TunProtect(TemplateIpsec,
                           TemplateIpsec4TunProtect,
                           IpsecTun4):
    """ IPsec IPv4 Tunnel protect - transport mode"""

    def setUp(self):
        super(TestIpsec4TunProtect, self).setUp()

        self.tun_if = self.pg0

    def tearDown(self):
        super(TestIpsec4TunProtect, self).tearDown()

    def test_tun_44(self):
        """IPSEC tunnel protect"""

        p = self.ipv4_params

        self.config_network(p)
        self.config_sa_tra(p)
        self.config_protect(p)

        self.verify_tun_44(p, count=127)
        c = p.tun_if.get_rx_stats()
        self.assertEqual(c['packets'], 127)
        c = p.tun_if.get_tx_stats()
        self.assertEqual(c['packets'], 127)

        self.vapi.cli("clear ipsec sa")
        self.verify_tun_64(p, count=127)
        c = p.tun_if.get_rx_stats()
        self.assertEqual(c['packets'], 254)
        c = p.tun_if.get_tx_stats()
        self.assertEqual(c['packets'], 254)

        # rekey - create new SAs and update the tunnel protection
        np = copy.copy(p)
        np.crypt_key = b'X' + p.crypt_key[1:]
        np.scapy_tun_spi += 100
        np.scapy_tun_sa_id += 1
        np.vpp_tun_spi += 100
        np.vpp_tun_sa_id += 1
        np.tun_if.local_spi = p.vpp_tun_spi
        np.tun_if.remote_spi = p.scapy_tun_spi

        self.config_sa_tra(np)
        self.config_protect(np)
        self.unconfig_sa(p)

        self.verify_tun_44(np, count=127)
        c = p.tun_if.get_rx_stats()
        self.assertEqual(c['packets'], 381)
        c = p.tun_if.get_tx_stats()
        self.assertEqual(c['packets'], 381)

        # teardown
        self.unconfig_protect(np)
        self.unconfig_sa(np)
        self.unconfig_network(p)


class TestIpsec4TunProtectUdp(TemplateIpsec,
                              TemplateIpsec4TunProtect,
                              IpsecTun4):
    """ IPsec IPv4 Tunnel protect - transport mode"""

    def setUp(self):
        super(TestIpsec4TunProtectUdp, self).setUp()

        self.tun_if = self.pg0

        p = self.ipv4_params
        p.flags = (VppEnum.vl_api_ipsec_sad_flags_t.
                   IPSEC_API_SAD_FLAG_UDP_ENCAP)
        p.nat_header = UDP(sport=4500, dport=4500)
        self.config_network(p)
        self.config_sa_tra(p)
        self.config_protect(p)

    def tearDown(self):
        p = self.ipv4_params
        self.unconfig_protect(p)
        self.unconfig_sa(p)
        self.unconfig_network(p)
        super(TestIpsec4TunProtectUdp, self).tearDown()

    def verify_encrypted(self, p, sa, rxs):
        # ensure encrypted packets are recieved with the default UDP ports
        for rx in rxs:
            self.assertEqual(rx[UDP].sport, 4500)
            self.assertEqual(rx[UDP].dport, 4500)
        super(TestIpsec4TunProtectUdp, self).verify_encrypted(p, sa, rxs)

    def test_tun_44(self):
        """IPSEC UDP tunnel protect"""

        p = self.ipv4_params

        self.verify_tun_44(p, count=127)
        c = p.tun_if.get_rx_stats()
        self.assertEqual(c['packets'], 127)
        c = p.tun_if.get_tx_stats()
        self.assertEqual(c['packets'], 127)

    def test_keepalive(self):
        """ IPSEC NAT Keepalive """
        self.verify_keepalive(self.ipv4_params)


class TestIpsec4TunProtectTun(TemplateIpsec,
                              TemplateIpsec4TunProtect,
                              IpsecTun4):
    """ IPsec IPv4 Tunnel protect - tunnel mode"""

    encryption_type = ESP
    tun4_encrypt_node_name = "esp4-encrypt-tun"
    tun4_decrypt_node_name = "esp4-decrypt-tun"

    def setUp(self):
        super(TestIpsec4TunProtectTun, self).setUp()

        self.tun_if = self.pg0

    def tearDown(self):
        super(TestIpsec4TunProtectTun, self).tearDown()

    def gen_encrypt_pkts(self, p, sa, sw_intf, src, dst, count=1,
                         payload_size=100):
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                sa.encrypt(IP(src=sw_intf.remote_ip4,
                              dst=sw_intf.local_ip4) /
                           IP(src=src, dst=dst) /
                           UDP(sport=1144, dport=2233) /
                           Raw(b'X' * payload_size))
                for i in range(count)]

    def gen_pkts(self, sw_intf, src, dst, count=1,
                 payload_size=100):
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                IP(src=src, dst=dst) /
                UDP(sport=1144, dport=2233) /
                Raw(b'X' * payload_size)
                for i in range(count)]

    def verify_decrypted(self, p, rxs):
        for rx in rxs:
            self.assert_equal(rx[IP].dst, self.pg1.remote_ip4)
            self.assert_equal(rx[IP].src, p.remote_tun_if_host)
            self.assert_packet_checksums_valid(rx)

    def verify_encrypted(self, p, sa, rxs):
        for rx in rxs:
            try:
                pkt = sa.decrypt(rx[IP])
                if not pkt.haslayer(IP):
                    pkt = IP(pkt[Raw].load)
                self.assert_packet_checksums_valid(pkt)
                self.assert_equal(pkt[IP].dst, self.pg0.remote_ip4)
                self.assert_equal(pkt[IP].src, self.pg0.local_ip4)
                inner = pkt[IP].payload
                self.assertEqual(inner[IP][IP].dst, p.remote_tun_if_host)

            except (IndexError, AssertionError):
                self.logger.debug(ppp("Unexpected packet:", rx))
                try:
                    self.logger.debug(ppp("Decrypted packet:", pkt))
                except:
                    pass
                raise

    def test_tun_44(self):
        """IPSEC tunnel protect """

        p = self.ipv4_params

        self.config_network(p)
        self.config_sa_tun(p)
        self.config_protect(p)

        # also add an output features on the tunnel and physical interface
        # so we test they still work
        r_all = AclRule(True,
                        src_prefix="0.0.0.0/0",
                        dst_prefix="0.0.0.0/0",
                        proto=0)
        a = VppAcl(self, [r_all]).add_vpp_config()

        VppAclInterface(self, self.pg0.sw_if_index, [a]).add_vpp_config()
        VppAclInterface(self, p.tun_if.sw_if_index, [a]).add_vpp_config()

        self.verify_tun_44(p, count=127)

        c = p.tun_if.get_rx_stats()
        self.assertEqual(c['packets'], 127)
        c = p.tun_if.get_tx_stats()
        self.assertEqual(c['packets'], 127)

        # rekey - create new SAs and update the tunnel protection
        np = copy.copy(p)
        np.crypt_key = b'X' + p.crypt_key[1:]
        np.scapy_tun_spi += 100
        np.scapy_tun_sa_id += 1
        np.vpp_tun_spi += 100
        np.vpp_tun_sa_id += 1
        np.tun_if.local_spi = p.vpp_tun_spi
        np.tun_if.remote_spi = p.scapy_tun_spi

        self.config_sa_tun(np)
        self.config_protect(np)
        self.unconfig_sa(p)

        self.verify_tun_44(np, count=127)
        c = p.tun_if.get_rx_stats()
        self.assertEqual(c['packets'], 254)
        c = p.tun_if.get_tx_stats()
        self.assertEqual(c['packets'], 254)

        # teardown
        self.unconfig_protect(np)
        self.unconfig_sa(np)
        self.unconfig_network(p)


class TestIpsec4TunProtectTunDrop(TemplateIpsec,
                                  TemplateIpsec4TunProtect,
                                  IpsecTun4):
    """ IPsec IPv4 Tunnel protect - tunnel mode - drop"""

    encryption_type = ESP
    tun4_encrypt_node_name = "esp4-encrypt-tun"
    tun4_decrypt_node_name = "esp4-decrypt-tun"

    def setUp(self):
        super(TestIpsec4TunProtectTunDrop, self).setUp()

        self.tun_if = self.pg0

    def tearDown(self):
        super(TestIpsec4TunProtectTunDrop, self).tearDown()

    def gen_encrypt_pkts(self, p, sa, sw_intf, src, dst, count=1,
                         payload_size=100):
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                sa.encrypt(IP(src=sw_intf.remote_ip4,
                              dst="5.5.5.5") /
                           IP(src=src, dst=dst) /
                           UDP(sport=1144, dport=2233) /
                           Raw(b'X' * payload_size))
                for i in range(count)]

    def test_tun_drop_44(self):
        """IPSEC tunnel protect bogus tunnel header """

        p = self.ipv4_params

        self.config_network(p)
        self.config_sa_tun(p)
        self.config_protect(p)

        tx = self.gen_encrypt_pkts(p, p.scapy_tun_sa, self.tun_if,
                                   src=p.remote_tun_if_host,
                                   dst=self.pg1.remote_ip4,
                                   count=63)
        self.send_and_assert_no_replies(self.tun_if, tx)

        # teardown
        self.unconfig_protect(p)
        self.unconfig_sa(p)
        self.unconfig_network(p)


class TemplateIpsec6TunProtect(object):
    """ IPsec IPv6 Tunnel protect """

    def config_sa_tra(self, p):
        config_tun_params(p, self.encryption_type, p.tun_if)

        p.tun_sa_out = VppIpsecSA(self, p.scapy_tun_sa_id, p.scapy_tun_spi,
                                  p.auth_algo_vpp_id, p.auth_key,
                                  p.crypt_algo_vpp_id, p.crypt_key,
                                  self.vpp_esp_protocol)
        p.tun_sa_out.add_vpp_config()

        p.tun_sa_in = VppIpsecSA(self, p.vpp_tun_sa_id, p.vpp_tun_spi,
                                 p.auth_algo_vpp_id, p.auth_key,
                                 p.crypt_algo_vpp_id, p.crypt_key,
                                 self.vpp_esp_protocol)
        p.tun_sa_in.add_vpp_config()

    def config_sa_tun(self, p):
        config_tun_params(p, self.encryption_type, p.tun_if)

        p.tun_sa_out = VppIpsecSA(self, p.scapy_tun_sa_id, p.scapy_tun_spi,
                                  p.auth_algo_vpp_id, p.auth_key,
                                  p.crypt_algo_vpp_id, p.crypt_key,
                                  self.vpp_esp_protocol,
                                  self.tun_if.local_addr[p.addr_type],
                                  self.tun_if.remote_addr[p.addr_type])
        p.tun_sa_out.add_vpp_config()

        p.tun_sa_in = VppIpsecSA(self, p.vpp_tun_sa_id, p.vpp_tun_spi,
                                 p.auth_algo_vpp_id, p.auth_key,
                                 p.crypt_algo_vpp_id, p.crypt_key,
                                 self.vpp_esp_protocol,
                                 self.tun_if.remote_addr[p.addr_type],
                                 self.tun_if.local_addr[p.addr_type])
        p.tun_sa_in.add_vpp_config()

    def config_protect(self, p):
        p.tun_protect = VppIpsecTunProtect(self,
                                           p.tun_if,
                                           p.tun_sa_out,
                                           [p.tun_sa_in])
        p.tun_protect.add_vpp_config()

    def config_network(self, p):
        p.tun_if = VppIpIpTunInterface(self, self.pg0,
                                       self.pg0.local_ip6,
                                       self.pg0.remote_ip6)
        p.tun_if.add_vpp_config()
        p.tun_if.admin_up()
        p.tun_if.config_ip6()
        p.tun_if.config_ip4()

        p.route = VppIpRoute(self, p.remote_tun_if_host, 128,
                             [VppRoutePath(p.tun_if.remote_ip6,
                                           0xffffffff,
                                           proto=DpoProto.DPO_PROTO_IP6)])
        p.route.add_vpp_config()
        r = VppIpRoute(self, p.remote_tun_if_host4, 32,
                       [VppRoutePath(p.tun_if.remote_ip4,
                                     0xffffffff)])
        r.add_vpp_config()

    def unconfig_network(self, p):
        p.route.remove_vpp_config()
        p.tun_if.remove_vpp_config()

    def unconfig_protect(self, p):
        p.tun_protect.remove_vpp_config()

    def unconfig_sa(self, p):
        p.tun_sa_out.remove_vpp_config()
        p.tun_sa_in.remove_vpp_config()


class TestIpsec6TunProtect(TemplateIpsec,
                           TemplateIpsec6TunProtect,
                           IpsecTun6):
    """ IPsec IPv6 Tunnel protect - transport mode"""

    encryption_type = ESP
    tun6_encrypt_node_name = "esp6-encrypt-tun"
    tun6_decrypt_node_name = "esp6-decrypt-tun"

    def setUp(self):
        super(TestIpsec6TunProtect, self).setUp()

        self.tun_if = self.pg0

    def tearDown(self):
        super(TestIpsec6TunProtect, self).tearDown()

    def test_tun_66(self):
        """IPSEC tunnel protect 6o6"""

        p = self.ipv6_params

        self.config_network(p)
        self.config_sa_tra(p)
        self.config_protect(p)

        self.verify_tun_66(p, count=127)
        c = p.tun_if.get_rx_stats()
        self.assertEqual(c['packets'], 127)
        c = p.tun_if.get_tx_stats()
        self.assertEqual(c['packets'], 127)

        # rekey - create new SAs and update the tunnel protection
        np = copy.copy(p)
        np.crypt_key = b'X' + p.crypt_key[1:]
        np.scapy_tun_spi += 100
        np.scapy_tun_sa_id += 1
        np.vpp_tun_spi += 100
        np.vpp_tun_sa_id += 1
        np.tun_if.local_spi = p.vpp_tun_spi
        np.tun_if.remote_spi = p.scapy_tun_spi

        self.config_sa_tra(np)
        self.config_protect(np)
        self.unconfig_sa(p)

        self.verify_tun_66(np, count=127)
        c = p.tun_if.get_rx_stats()
        self.assertEqual(c['packets'], 254)
        c = p.tun_if.get_tx_stats()
        self.assertEqual(c['packets'], 254)

        # bounce the interface state
        p.tun_if.admin_down()
        self.verify_drop_tun_66(np, count=127)
        node = ('/err/ipsec6-tun-input/%s' %
                'ipsec packets received on disabled interface')
        self.assertEqual(127, self.statistics.get_err_counter(node))
        p.tun_if.admin_up()
        self.verify_tun_66(np, count=127)

        # 3 phase rekey
        #  1) add two input SAs [old, new]
        #  2) swap output SA to [new]
        #  3) use only [new] input SA
        np3 = copy.copy(np)
        np3.crypt_key = b'Z' + p.crypt_key[1:]
        np3.scapy_tun_spi += 100
        np3.scapy_tun_sa_id += 1
        np3.vpp_tun_spi += 100
        np3.vpp_tun_sa_id += 1
        np3.tun_if.local_spi = p.vpp_tun_spi
        np3.tun_if.remote_spi = p.scapy_tun_spi

        self.config_sa_tra(np3)

        # step 1;
        p.tun_protect.update_vpp_config(np.tun_sa_out,
                                        [np.tun_sa_in, np3.tun_sa_in])
        self.verify_tun_66(np, np, count=127)
        self.verify_tun_66(np3, np, count=127)

        # step 2;
        p.tun_protect.update_vpp_config(np3.tun_sa_out,
                                        [np.tun_sa_in, np3.tun_sa_in])
        self.verify_tun_66(np, np3, count=127)
        self.verify_tun_66(np3, np3, count=127)

        # step 1;
        p.tun_protect.update_vpp_config(np3.tun_sa_out,
                                        [np3.tun_sa_in])
        self.verify_tun_66(np3, np3, count=127)
        self.verify_drop_tun_66(np, count=127)

        c = p.tun_if.get_rx_stats()
        self.assertEqual(c['packets'], 127*9)
        c = p.tun_if.get_tx_stats()
        self.assertEqual(c['packets'], 127*8)
        self.unconfig_sa(np)

        # teardown
        self.unconfig_protect(np3)
        self.unconfig_sa(np3)
        self.unconfig_network(p)

    def test_tun_46(self):
        """IPSEC tunnel protect 4o6"""

        p = self.ipv6_params

        self.config_network(p)
        self.config_sa_tra(p)
        self.config_protect(p)

        self.verify_tun_46(p, count=127)
        c = p.tun_if.get_rx_stats()
        self.assertEqual(c['packets'], 127)
        c = p.tun_if.get_tx_stats()
        self.assertEqual(c['packets'], 127)

        # teardown
        self.unconfig_protect(p)
        self.unconfig_sa(p)
        self.unconfig_network(p)


class TestIpsec6TunProtectTun(TemplateIpsec,
                              TemplateIpsec6TunProtect,
                              IpsecTun6):
    """ IPsec IPv6 Tunnel protect - tunnel mode"""

    encryption_type = ESP
    tun6_encrypt_node_name = "esp6-encrypt-tun"
    tun6_decrypt_node_name = "esp6-decrypt-tun"

    def setUp(self):
        super(TestIpsec6TunProtectTun, self).setUp()

        self.tun_if = self.pg0

    def tearDown(self):
        super(TestIpsec6TunProtectTun, self).tearDown()

    def gen_encrypt_pkts6(self, p, sa, sw_intf, src, dst, count=1,
                          payload_size=100):
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                sa.encrypt(IPv6(src=sw_intf.remote_ip6,
                                dst=sw_intf.local_ip6) /
                           IPv6(src=src, dst=dst) /
                           UDP(sport=1166, dport=2233) /
                           Raw(b'X' * payload_size))
                for i in range(count)]

    def gen_pkts6(self, sw_intf, src, dst, count=1,
                  payload_size=100):
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                IPv6(src=src, dst=dst) /
                UDP(sport=1166, dport=2233) /
                Raw(b'X' * payload_size)
                for i in range(count)]

    def verify_decrypted6(self, p, rxs):
        for rx in rxs:
            self.assert_equal(rx[IPv6].dst, self.pg1.remote_ip6)
            self.assert_equal(rx[IPv6].src, p.remote_tun_if_host)
            self.assert_packet_checksums_valid(rx)

    def verify_encrypted6(self, p, sa, rxs):
        for rx in rxs:
            try:
                pkt = sa.decrypt(rx[IPv6])
                if not pkt.haslayer(IPv6):
                    pkt = IPv6(pkt[Raw].load)
                self.assert_packet_checksums_valid(pkt)
                self.assert_equal(pkt[IPv6].dst, self.pg0.remote_ip6)
                self.assert_equal(pkt[IPv6].src, self.pg0.local_ip6)
                inner = pkt[IPv6].payload
                self.assertEqual(inner[IPv6][IPv6].dst, p.remote_tun_if_host)

            except (IndexError, AssertionError):
                self.logger.debug(ppp("Unexpected packet:", rx))
                try:
                    self.logger.debug(ppp("Decrypted packet:", pkt))
                except:
                    pass
                raise

    def test_tun_66(self):
        """IPSEC tunnel protect """

        p = self.ipv6_params

        self.config_network(p)
        self.config_sa_tun(p)
        self.config_protect(p)

        self.verify_tun_66(p, count=127)

        c = p.tun_if.get_rx_stats()
        self.assertEqual(c['packets'], 127)
        c = p.tun_if.get_tx_stats()
        self.assertEqual(c['packets'], 127)

        # rekey - create new SAs and update the tunnel protection
        np = copy.copy(p)
        np.crypt_key = b'X' + p.crypt_key[1:]
        np.scapy_tun_spi += 100
        np.scapy_tun_sa_id += 1
        np.vpp_tun_spi += 100
        np.vpp_tun_sa_id += 1
        np.tun_if.local_spi = p.vpp_tun_spi
        np.tun_if.remote_spi = p.scapy_tun_spi

        self.config_sa_tun(np)
        self.config_protect(np)
        self.unconfig_sa(p)

        self.verify_tun_66(np, count=127)
        c = p.tun_if.get_rx_stats()
        self.assertEqual(c['packets'], 254)
        c = p.tun_if.get_tx_stats()
        self.assertEqual(c['packets'], 254)

        # teardown
        self.unconfig_protect(np)
        self.unconfig_sa(np)
        self.unconfig_network(p)


class TestIpsec6TunProtectTunDrop(TemplateIpsec,
                                  TemplateIpsec6TunProtect,
                                  IpsecTun6):
    """ IPsec IPv6 Tunnel protect - tunnel mode - drop"""

    encryption_type = ESP
    tun6_encrypt_node_name = "esp6-encrypt-tun"
    tun6_decrypt_node_name = "esp6-decrypt-tun"

    def setUp(self):
        super(TestIpsec6TunProtectTunDrop, self).setUp()

        self.tun_if = self.pg0

    def tearDown(self):
        super(TestIpsec6TunProtectTunDrop, self).tearDown()

    def gen_encrypt_pkts6(self, p, sa, sw_intf, src, dst, count=1,
                          payload_size=100):
        # the IP destination of the revelaed packet does not match
        # that assigned to the tunnel
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                sa.encrypt(IPv6(src=sw_intf.remote_ip6,
                                dst="5::5") /
                           IPv6(src=src, dst=dst) /
                           UDP(sport=1144, dport=2233) /
                           Raw(b'X' * payload_size))
                for i in range(count)]

    def test_tun_drop_66(self):
        """IPSEC 6 tunnel protect bogus tunnel header """

        p = self.ipv6_params

        self.config_network(p)
        self.config_sa_tun(p)
        self.config_protect(p)

        tx = self.gen_encrypt_pkts6(p, p.scapy_tun_sa, self.tun_if,
                                    src=p.remote_tun_if_host,
                                    dst=self.pg1.remote_ip6,
                                    count=63)
        self.send_and_assert_no_replies(self.tun_if, tx)

        self.unconfig_protect(p)
        self.unconfig_sa(p)
        self.unconfig_network(p)


class TemplateIpsecItf4(object):
    """ IPsec Interface IPv4 """

    encryption_type = ESP
    tun4_encrypt_node_name = "esp4-encrypt-tun"
    tun4_decrypt_node_name = "esp4-decrypt-tun"
    tun4_input_node = "ipsec4-tun-input"

    def config_sa_tun(self, p, src, dst):
        config_tun_params(p, self.encryption_type, None, src, dst)

        p.tun_sa_out = VppIpsecSA(self, p.scapy_tun_sa_id, p.scapy_tun_spi,
                                  p.auth_algo_vpp_id, p.auth_key,
                                  p.crypt_algo_vpp_id, p.crypt_key,
                                  self.vpp_esp_protocol,
                                  src, dst,
                                  flags=p.flags)
        p.tun_sa_out.add_vpp_config()

        p.tun_sa_in = VppIpsecSA(self, p.vpp_tun_sa_id, p.vpp_tun_spi,
                                 p.auth_algo_vpp_id, p.auth_key,
                                 p.crypt_algo_vpp_id, p.crypt_key,
                                 self.vpp_esp_protocol,
                                 dst, src,
                                 flags=p.flags)
        p.tun_sa_in.add_vpp_config()

    def config_protect(self, p):
        p.tun_protect = VppIpsecTunProtect(self,
                                           p.tun_if,
                                           p.tun_sa_out,
                                           [p.tun_sa_in])
        p.tun_protect.add_vpp_config()

    def config_network(self, p, instance=0xffffffff):
        p.tun_if = VppIpsecInterface(self, instance=instance)

        p.tun_if.add_vpp_config()
        p.tun_if.admin_up()
        p.tun_if.config_ip4()
        p.tun_if.config_ip6()

        p.route = VppIpRoute(self, p.remote_tun_if_host, 32,
                             [VppRoutePath(p.tun_if.remote_ip4,
                                           0xffffffff)])
        p.route.add_vpp_config()
        r = VppIpRoute(self, p.remote_tun_if_host6, 128,
                       [VppRoutePath(p.tun_if.remote_ip6,
                                     0xffffffff,
                                     proto=DpoProto.DPO_PROTO_IP6)])
        r.add_vpp_config()

    def unconfig_network(self, p):
        p.route.remove_vpp_config()
        p.tun_if.remove_vpp_config()

    def unconfig_protect(self, p):
        p.tun_protect.remove_vpp_config()

    def unconfig_sa(self, p):
        p.tun_sa_out.remove_vpp_config()
        p.tun_sa_in.remove_vpp_config()


class TestIpsecItf4(TemplateIpsec,
                    TemplateIpsecItf4,
                    IpsecTun4):
    """ IPsec Interface IPv4 """

    def setUp(self):
        super(TestIpsecItf4, self).setUp()

        self.tun_if = self.pg0

    def tearDown(self):
        super(TestIpsecItf4, self).tearDown()

    def test_tun_instance_44(self):
        p = self.ipv4_params
        self.config_network(p, instance=3)

        with self.assertRaises(CliFailedCommandError):
            self.vapi.cli("show interface ipsec0")

        output = self.vapi.cli("show interface ipsec3")
        self.assertTrue("unknown" not in output)

        self.unconfig_network(p)

    def test_tun_44(self):
        """IPSEC interface IPv4"""

        n_pkts = 127
        p = self.ipv4_params

        self.config_network(p)
        self.config_sa_tun(p,
                           self.pg0.local_ip4,
                           self.pg0.remote_ip4)
        self.config_protect(p)

        self.verify_tun_44(p, count=n_pkts)
        c = p.tun_if.get_rx_stats()
        self.assertEqual(c['packets'], n_pkts)
        c = p.tun_if.get_tx_stats()
        self.assertEqual(c['packets'], n_pkts)

        p.tun_if.admin_down()
        self.verify_tun_dropped_44(p, count=n_pkts)
        p.tun_if.admin_up()
        self.verify_tun_44(p, count=n_pkts)

        c = p.tun_if.get_rx_stats()
        self.assertEqual(c['packets'], 3*n_pkts)
        c = p.tun_if.get_tx_stats()
        self.assertEqual(c['packets'], 2*n_pkts)

        # it's a v6 packet when its encrypted
        self.tun4_encrypt_node_name = "esp6-encrypt-tun"

        self.verify_tun_64(p, count=n_pkts)
        c = p.tun_if.get_rx_stats()
        self.assertEqual(c['packets'], 4*n_pkts)
        c = p.tun_if.get_tx_stats()
        self.assertEqual(c['packets'], 3*n_pkts)

        self.tun4_encrypt_node_name = "esp4-encrypt-tun"

        self.vapi.cli("clear interfaces")

        # rekey - create new SAs and update the tunnel protection
        np = copy.copy(p)
        np.crypt_key = b'X' + p.crypt_key[1:]
        np.scapy_tun_spi += 100
        np.scapy_tun_sa_id += 1
        np.vpp_tun_spi += 100
        np.vpp_tun_sa_id += 1
        np.tun_if.local_spi = p.vpp_tun_spi
        np.tun_if.remote_spi = p.scapy_tun_spi

        self.config_sa_tun(np,
                           self.pg0.local_ip4,
                           self.pg0.remote_ip4)
        self.config_protect(np)
        self.unconfig_sa(p)

        self.verify_tun_44(np, count=n_pkts)
        c = p.tun_if.get_rx_stats()
        self.assertEqual(c['packets'], n_pkts)
        c = p.tun_if.get_tx_stats()
        self.assertEqual(c['packets'], n_pkts)

        # teardown
        self.unconfig_protect(np)
        self.unconfig_sa(np)
        self.unconfig_network(p)

    def test_tun_44_null(self):
        """IPSEC interface IPv4 NULL auth/crypto"""

        n_pkts = 127
        p = copy.copy(self.ipv4_params)

        p.auth_algo_vpp_id = (VppEnum.vl_api_ipsec_integ_alg_t.
                              IPSEC_API_INTEG_ALG_NONE)
        p.crypt_algo_vpp_id = (VppEnum.vl_api_ipsec_crypto_alg_t.
                               IPSEC_API_CRYPTO_ALG_NONE)
        p.crypt_algo = "NULL"
        p.auth_algo = "NULL"

        self.config_network(p)
        self.config_sa_tun(p,
                           self.pg0.local_ip4,
                           self.pg0.remote_ip4)
        self.config_protect(p)

        self.verify_tun_44(p, count=n_pkts)

        # teardown
        self.unconfig_protect(p)
        self.unconfig_sa(p)
        self.unconfig_network(p)


class TemplateIpsecItf6(object):
    """ IPsec Interface IPv6 """

    encryption_type = ESP
    tun6_encrypt_node_name = "esp6-encrypt-tun"
    tun6_decrypt_node_name = "esp6-decrypt-tun"
    tun6_input_node = "ipsec6-tun-input"

    def config_sa_tun(self, p, src, dst):
        config_tun_params(p, self.encryption_type, None, src, dst)

        p.tun_sa_out = VppIpsecSA(self, p.scapy_tun_sa_id, p.scapy_tun_spi,
                                  p.auth_algo_vpp_id, p.auth_key,
                                  p.crypt_algo_vpp_id, p.crypt_key,
                                  self.vpp_esp_protocol,
                                  src, dst,
                                  flags=p.flags)
        p.tun_sa_out.add_vpp_config()

        p.tun_sa_in = VppIpsecSA(self, p.vpp_tun_sa_id, p.vpp_tun_spi,
                                 p.auth_algo_vpp_id, p.auth_key,
                                 p.crypt_algo_vpp_id, p.crypt_key,
                                 self.vpp_esp_protocol,
                                 dst, src,
                                 flags=p.flags)
        p.tun_sa_in.add_vpp_config()

    def config_protect(self, p):
        p.tun_protect = VppIpsecTunProtect(self,
                                           p.tun_if,
                                           p.tun_sa_out,
                                           [p.tun_sa_in])
        p.tun_protect.add_vpp_config()

    def config_network(self, p):
        p.tun_if = VppIpsecInterface(self)

        p.tun_if.add_vpp_config()
        p.tun_if.admin_up()
        p.tun_if.config_ip4()
        p.tun_if.config_ip6()

        r = VppIpRoute(self, p.remote_tun_if_host4, 32,
                       [VppRoutePath(p.tun_if.remote_ip4,
                                     0xffffffff)])
        r.add_vpp_config()

        p.route = VppIpRoute(self, p.remote_tun_if_host, 128,
                             [VppRoutePath(p.tun_if.remote_ip6,
                                           0xffffffff,
                                           proto=DpoProto.DPO_PROTO_IP6)])
        p.route.add_vpp_config()

    def unconfig_network(self, p):
        p.route.remove_vpp_config()
        p.tun_if.remove_vpp_config()

    def unconfig_protect(self, p):
        p.tun_protect.remove_vpp_config()

    def unconfig_sa(self, p):
        p.tun_sa_out.remove_vpp_config()
        p.tun_sa_in.remove_vpp_config()


class TestIpsecItf6(TemplateIpsec,
                    TemplateIpsecItf6,
                    IpsecTun6):
    """ IPsec Interface IPv6 """

    def setUp(self):
        super(TestIpsecItf6, self).setUp()

        self.tun_if = self.pg0

    def tearDown(self):
        super(TestIpsecItf6, self).tearDown()

    def test_tun_44(self):
        """IPSEC interface IPv6"""

        n_pkts = 127
        p = self.ipv6_params

        self.config_network(p)
        self.config_sa_tun(p,
                           self.pg0.local_ip6,
                           self.pg0.remote_ip6)
        self.config_protect(p)

        self.verify_tun_66(p, count=n_pkts)
        c = p.tun_if.get_rx_stats()
        self.assertEqual(c['packets'], n_pkts)
        c = p.tun_if.get_tx_stats()
        self.assertEqual(c['packets'], n_pkts)

        p.tun_if.admin_down()
        self.verify_drop_tun_66(p, count=n_pkts)
        p.tun_if.admin_up()
        self.verify_tun_66(p, count=n_pkts)

        c = p.tun_if.get_rx_stats()
        self.assertEqual(c['packets'], 3*n_pkts)
        c = p.tun_if.get_tx_stats()
        self.assertEqual(c['packets'], 2*n_pkts)

        # it's a v4 packet when its encrypted
        self.tun6_encrypt_node_name = "esp4-encrypt-tun"

        self.verify_tun_46(p, count=n_pkts)
        c = p.tun_if.get_rx_stats()
        self.assertEqual(c['packets'], 4*n_pkts)
        c = p.tun_if.get_tx_stats()
        self.assertEqual(c['packets'], 3*n_pkts)

        self.tun6_encrypt_node_name = "esp6-encrypt-tun"

        self.vapi.cli("clear interfaces")

        # rekey - create new SAs and update the tunnel protection
        np = copy.copy(p)
        np.crypt_key = b'X' + p.crypt_key[1:]
        np.scapy_tun_spi += 100
        np.scapy_tun_sa_id += 1
        np.vpp_tun_spi += 100
        np.vpp_tun_sa_id += 1
        np.tun_if.local_spi = p.vpp_tun_spi
        np.tun_if.remote_spi = p.scapy_tun_spi

        self.config_sa_tun(np,
                           self.pg0.local_ip6,
                           self.pg0.remote_ip6)
        self.config_protect(np)
        self.unconfig_sa(p)

        self.verify_tun_66(np, count=n_pkts)
        c = p.tun_if.get_rx_stats()
        self.assertEqual(c['packets'], n_pkts)
        c = p.tun_if.get_tx_stats()
        self.assertEqual(c['packets'], n_pkts)

        # teardown
        self.unconfig_protect(np)
        self.unconfig_sa(np)
        self.unconfig_network(p)


class TestIpsecMIfEsp4(TemplateIpsec, IpsecTun4):
    """ Ipsec P2MP ESP v4 tests """
    tun4_encrypt_node_name = "esp4-encrypt-tun"
    tun4_decrypt_node_name = "esp4-decrypt-tun"
    encryption_type = ESP

    def gen_encrypt_pkts(self, p, sa, sw_intf, src, dst, count=1,
                         payload_size=100):
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                sa.encrypt(IP(src=self.pg1.local_ip4,
                              dst=self.pg1.remote_ip4) /
                           UDP(sport=1144, dport=2233) /
                           Raw(b'X' * payload_size))
                for i in range(count)]

    def gen_pkts(self, sw_intf, src, dst, count=1,
                 payload_size=100):
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                IP(src="1.1.1.1", dst=dst) /
                UDP(sport=1144, dport=2233) /
                Raw(b'X' * payload_size)
                for i in range(count)]

    def verify_decrypted(self, p, rxs):
        for rx in rxs:
            self.assert_equal(rx[Ether].dst, self.pg1.remote_mac)
            self.assert_equal(rx[IP].dst, self.pg1.remote_ip4)

    def verify_encrypted(self, p, sa, rxs):
        for rx in rxs:
            try:
                self.assertEqual(rx[IP].tos,
                                 VppEnum.vl_api_ip_dscp_t.IP_API_DSCP_EF << 2)
                pkt = sa.decrypt(rx[IP])
                if not pkt.haslayer(IP):
                    pkt = IP(pkt[Raw].load)
                self.assert_packet_checksums_valid(pkt)
                e = pkt[IP]
                self.assertEqual(e[IP].dst, p.remote_tun_if_host)
            except (IndexError, AssertionError):
                self.logger.debug(ppp("Unexpected packet:", rx))
                try:
                    self.logger.debug(ppp("Decrypted packet:", pkt))
                except:
                    pass
                raise

    def setUp(self):
        super(TestIpsecMIfEsp4, self).setUp()

        N_NHS = 16
        self.tun_if = self.pg0
        p = self.ipv4_params
        p.tun_if = VppIpsecInterface(self,
                                     mode=(VppEnum.vl_api_tunnel_mode_t.
                                           TUNNEL_API_MODE_MP))
        p.tun_if.add_vpp_config()
        p.tun_if.admin_up()
        p.tun_if.config_ip4()
        p.tun_if.unconfig_ip4()
        p.tun_if.config_ip4()
        p.tun_if.generate_remote_hosts(N_NHS)
        self.pg0.generate_remote_hosts(N_NHS)
        self.pg0.configure_ipv4_neighbors()

        # setup some SAs for several next-hops on the interface
        self.multi_params = []

        for ii in range(N_NHS):
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
            p.tun_sa_out = VppIpsecSA(
                self, p.scapy_tun_sa_id, p.scapy_tun_spi,
                p.auth_algo_vpp_id, p.auth_key,
                p.crypt_algo_vpp_id, p.crypt_key,
                self.vpp_esp_protocol,
                self.pg0.local_ip4,
                self.pg0.remote_hosts[ii].ip4,
                dscp=VppEnum.vl_api_ip_dscp_t.IP_API_DSCP_EF)
            p.tun_sa_out.add_vpp_config()

            p.tun_sa_in = VppIpsecSA(
                self, p.vpp_tun_sa_id, p.vpp_tun_spi,
                p.auth_algo_vpp_id, p.auth_key,
                p.crypt_algo_vpp_id, p.crypt_key,
                self.vpp_esp_protocol,
                self.pg0.remote_hosts[ii].ip4,
                self.pg0.local_ip4,
                dscp=VppEnum.vl_api_ip_dscp_t.IP_API_DSCP_EF)
            p.tun_sa_in.add_vpp_config()

            p.tun_protect = VppIpsecTunProtect(
                self,
                p.tun_if,
                p.tun_sa_out,
                [p.tun_sa_in],
                nh=p.tun_if.remote_hosts[ii].ip4)
            p.tun_protect.add_vpp_config()
            config_tun_params(p, self.encryption_type, None,
                              self.pg0.local_ip4,
                              self.pg0.remote_hosts[ii].ip4)
            self.multi_params.append(p)

            VppIpRoute(self, p.remote_tun_if_host, 32,
                       [VppRoutePath(p.tun_if.remote_hosts[ii].ip4,
                                     p.tun_if.sw_if_index)]).add_vpp_config()

            p.tun_dst = self.pg0.remote_hosts[ii].ip4

    def tearDown(self):
        p = self.ipv4_params
        p.tun_if.unconfig_ip4()
        super(TestIpsecMIfEsp4, self).tearDown()

    def test_tun_44(self):
        """P2MP IPSEC 44"""
        N_PKTS = 63
        for p in self.multi_params:
            self.verify_tun_44(p, count=N_PKTS)


if __name__ == '__main__':
    unittest