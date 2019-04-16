import socket
import unittest
from scapy.layers.ipsec import ESP
from scapy.layers.inet import UDP

from framework import VppTestRunner
from template_ipsec import IpsecTra46Tests, IpsecTun46Tests, TemplateIpsec, \
    IpsecTcpTests, IpsecTun4Tests, IpsecTra4Tests, config_tra_params, \
    IPsecIPv4Params, IPsecIPv6Params, \
    IpsecTra4, IpsecTun4, IpsecTra6, IpsecTun6
from vpp_ipsec import VppIpsecSpd, VppIpsecSpdEntry, VppIpsecSA,\
    VppIpsecSpdItfBinding
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_ip import DpoProto
from vpp_papi import VppEnum


class ConfigIpsecESP(TemplateIpsec):
    encryption_type = ESP
    tra4_encrypt_node_name = "esp4-encrypt"
    tra4_decrypt_node_name = "esp4-decrypt"
    tra6_encrypt_node_name = "esp6-encrypt"
    tra6_decrypt_node_name = "esp6-decrypt"
    tun4_encrypt_node_name = "esp4-encrypt"
    tun4_decrypt_node_name = "esp4-decrypt"
    tun6_encrypt_node_name = "esp6-encrypt"
    tun6_decrypt_node_name = "esp6-decrypt"

    @classmethod
    def setUpClass(cls):
        super(ConfigIpsecESP, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(ConfigIpsecESP, cls).tearDownClass()

    def setUp(self):
        super(ConfigIpsecESP, self).setUp()

    def tearDown(self):
        super(ConfigIpsecESP, self).tearDown()

    def config_network(self, params):
        self.net_objs = []
        self.tun_if = self.pg0
        self.tra_if = self.pg2
        self.logger.info(self.vapi.ppcli("show int addr"))

        self.tra_spd = VppIpsecSpd(self, self.tra_spd_id)
        self.tra_spd.add_vpp_config()
        self.net_objs.append(self.tra_spd)
        self.tun_spd = VppIpsecSpd(self, self.tun_spd_id)
        self.tun_spd.add_vpp_config()
        self.net_objs.append(self.tun_spd)

        b = VppIpsecSpdItfBinding(self, self.tun_spd,
                                  self.tun_if)
        b.add_vpp_config()
        self.net_objs.append(b)

        b = VppIpsecSpdItfBinding(self, self.tra_spd,
                                  self.tra_if)
        b.add_vpp_config()
        self.net_objs.append(b)

        for p in params:
            self.config_esp_tra(p)
            config_tra_params(p, self.encryption_type)
        for p in params:
            self.config_esp_tun(p)

        for p in params:
            d = DpoProto.DPO_PROTO_IP6 if p.is_ipv6 else DpoProto.DPO_PROTO_IP4
            r = VppIpRoute(self,  p.remote_tun_if_host, p.addr_len,
                           [VppRoutePath(self.tun_if.remote_addr[p.addr_type],
                                         0xffffffff,
                                         proto=d)],
                           is_ip6=p.is_ipv6)
            r.add_vpp_config()
            self.net_objs.append(r)

        self.logger.info(self.vapi.ppcli("show ipsec all"))

    def unconfig_network(self):
        for o in reversed(self.net_objs):
            o.remove_vpp_config()
        self.net_objs = []

    def config_esp_tun(self, params):
        addr_type = params.addr_type
        scapy_tun_sa_id = params.scapy_tun_sa_id
        scapy_tun_spi = params.scapy_tun_spi
        vpp_tun_sa_id = params.vpp_tun_sa_id
        vpp_tun_spi = params.vpp_tun_spi
        auth_algo_vpp_id = params.auth_algo_vpp_id
        auth_key = params.auth_key
        crypt_algo_vpp_id = params.crypt_algo_vpp_id
        crypt_key = params.crypt_key
        remote_tun_if_host = params.remote_tun_if_host
        addr_any = params.addr_any
        addr_bcast = params.addr_bcast
        e = VppEnum.vl_api_ipsec_spd_action_t
        flags = params.flags
        salt = params.salt
        objs = []

        params.tun_sa_in = VppIpsecSA(self, scapy_tun_sa_id, scapy_tun_spi,
                                      auth_algo_vpp_id, auth_key,
                                      crypt_algo_vpp_id, crypt_key,
                                      self.vpp_esp_protocol,
                                      self.tun_if.local_addr[addr_type],
                                      self.tun_if.remote_addr[addr_type],
                                      flags=flags,
                                      salt=salt)
        params.tun_sa_out = VppIpsecSA(self, vpp_tun_sa_id, vpp_tun_spi,
                                       auth_algo_vpp_id, auth_key,
                                       crypt_algo_vpp_id, crypt_key,
                                       self.vpp_esp_protocol,
                                       self.tun_if.remote_addr[addr_type],
                                       self.tun_if.local_addr[addr_type],
                                       flags=flags,
                                       salt=salt)
        objs.append(params.tun_sa_in)
        objs.append(params.tun_sa_out)

        params.spd_policy_in_any = VppIpsecSpdEntry(self, self.tun_spd,
                                                    scapy_tun_sa_id,
                                                    addr_any, addr_bcast,
                                                    addr_any, addr_bcast,
                                                    socket.IPPROTO_ESP)
        params.spd_policy_out_any = VppIpsecSpdEntry(self, self.tun_spd,
                                                     scapy_tun_sa_id,
                                                     addr_any, addr_bcast,
                                                     addr_any, addr_bcast,
                                                     socket.IPPROTO_ESP,
                                                     is_outbound=0)
        objs.append(params.spd_policy_out_any)
        objs.append(params.spd_policy_in_any)

        objs.append(VppIpsecSpdEntry(self, self.tun_spd, vpp_tun_sa_id,
                                     remote_tun_if_host, remote_tun_if_host,
                                     self.pg1.remote_addr[addr_type],
                                     self.pg1.remote_addr[addr_type],
                                     0,
                                     priority=10,
                                     policy=e.IPSEC_API_SPD_ACTION_PROTECT,
                                     is_outbound=0))
        objs.append(VppIpsecSpdEntry(self, self.tun_spd, scapy_tun_sa_id,
                                     self.pg1.remote_addr[addr_type],
                                     self.pg1.remote_addr[addr_type],
                                     remote_tun_if_host, remote_tun_if_host,
                                     0,
                                     policy=e.IPSEC_API_SPD_ACTION_PROTECT,
                                     priority=10))
        objs.append(VppIpsecSpdEntry(self, self.tun_spd, vpp_tun_sa_id,
                                     remote_tun_if_host, remote_tun_if_host,
                                     self.pg0.local_addr[addr_type],
                                     self.pg0.local_addr[addr_type],
                                     0,
                                     priority=20,
                                     policy=e.IPSEC_API_SPD_ACTION_PROTECT,
                                     is_outbound=0))
        objs.append(VppIpsecSpdEntry(self, self.tun_spd, scapy_tun_sa_id,
                                     self.pg0.local_addr[addr_type],
                                     self.pg0.local_addr[addr_type],
                                     remote_tun_if_host, remote_tun_if_host,
                                     0,
                                     policy=e.IPSEC_API_SPD_ACTION_PROTECT,
                                     priority=20))
        for o in objs:
            o.add_vpp_config()
        self.net_objs = self.net_objs + objs

    def config_esp_tra(self, params):
        addr_type = params.addr_type
        scapy_tra_sa_id = params.scapy_tra_sa_id
        scapy_tra_spi = params.scapy_tra_spi
        vpp_tra_sa_id = params.vpp_tra_sa_id
        vpp_tra_spi = params.vpp_tra_spi
        auth_algo_vpp_id = params.auth_algo_vpp_id
        auth_key = params.auth_key
        crypt_algo_vpp_id = params.crypt_algo_vpp_id
        crypt_key = params.crypt_key
        addr_any = params.addr_any
        addr_bcast = params.addr_bcast
        flags = (VppEnum.vl_api_ipsec_sad_flags_t.
                 IPSEC_API_SAD_FLAG_USE_ANTI_REPLAY)
        e = VppEnum.vl_api_ipsec_spd_action_t
        flags = params.flags | flags
        salt = params.salt
        objs = []

        params.tra_sa_in = VppIpsecSA(self, scapy_tra_sa_id, scapy_tra_spi,
                                      auth_algo_vpp_id, auth_key,
                                      crypt_algo_vpp_id, crypt_key,
                                      self.vpp_esp_protocol,
                                      flags=flags,
                                      salt=salt)
        params.tra_sa_out = VppIpsecSA(self, vpp_tra_sa_id, vpp_tra_spi,
                                       auth_algo_vpp_id, auth_key,
                                       crypt_algo_vpp_id, crypt_key,
                                       self.vpp_esp_protocol,
                                       flags=flags,
                                       salt=salt)
        objs.append(params.tra_sa_in)
        objs.append(params.tra_sa_out)

        objs.append(VppIpsecSpdEntry(self, self.tra_spd, vpp_tra_sa_id,
                                     addr_any, addr_bcast,
                                     addr_any, addr_bcast,
                                     socket.IPPROTO_ESP))
        objs.append(VppIpsecSpdEntry(self, self.tra_spd, vpp_tra_sa_id,
                                     addr_any, addr_bcast,
                                     addr_any, addr_bcast,
                                     socket.IPPROTO_ESP,
                                     is_outbound=0))
        objs.append(VppIpsecSpdEntry(self, self.tra_spd, vpp_tra_sa_id,
                                     self.tra_if.local_addr[addr_type],
                                     self.tra_if.local_addr[addr_type],
                                     self.tra_if.remote_addr[addr_type],
                                     self.tra_if.remote_addr[addr_type],
                                     0, priority=10,
                                     policy=e.IPSEC_API_SPD_ACTION_PROTECT,
                                     is_outbound=0))
        objs.append(VppIpsecSpdEntry(self, self.tra_spd, scapy_tra_sa_id,
                                     self.tra_if.local_addr[addr_type],
                                     self.tra_if.local_addr[addr_type],
                                     self.tra_if.remote_addr[addr_type],
                                     self.tra_if.remote_addr[addr_type],
                                     0, policy=e.IPSEC_API_SPD_ACTION_PROTECT,
                                     priority=10))
        for o in objs:
            o.add_vpp_config()
        self.net_objs = self.net_objs + objs


class TemplateIpsecEsp(ConfigIpsecESP):
    """
    Basic test for ipsec esp sanity - tunnel and transport modes.

    Below 4 cases are covered as part of this test
    1) ipsec esp v4 transport basic test  - IPv4 Transport mode
        scenario using HMAC-SHA1-96 integrity algo
    2) ipsec esp v4 transport burst test
        Above test for 257 pkts
    3) ipsec esp 4o4 tunnel basic test    - IPv4 Tunnel mode
        scenario using HMAC-SHA1-96 integrity algo
    4) ipsec esp 4o4 tunnel burst test
        Above test for 257 pkts

    TRANSPORT MODE:

     ---   encrypt   ---
    |pg2| <-------> |VPP|
     ---   decrypt   ---

    TUNNEL MODE:

     ---   encrypt   ---   plain   ---
    |pg0| <-------  |VPP| <------ |pg1|
     ---             ---           ---

     ---   decrypt   ---   plain   ---
    |pg0| ------->  |VPP| ------> |pg1|
     ---             ---           ---
    """

    @classmethod
    def setUpClass(cls):
        super(TemplateIpsecEsp, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TemplateIpsecEsp, cls).tearDownClass()

    def setUp(self):
        super(TemplateIpsecEsp, self).setUp()
        self.config_network(self.params.values())

    def tearDown(self):
        self.unconfig_network()
        super(TemplateIpsecEsp, self).tearDown()


class TestIpsecEsp1(TemplateIpsecEsp, IpsecTra46Tests, IpsecTun46Tests):
    """ Ipsec ESP - TUN & TRA tests """
    pass


class TestIpsecEsp2(TemplateIpsecEsp, IpsecTcpTests):
    """ Ipsec ESP - TCP tests """
    pass


class TemplateIpsecEspUdp(ConfigIpsecESP):
    """
    UDP encapped ESP
    """

    @classmethod
    def setUpClass(cls):
        super(TemplateIpsecEspUdp, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TemplateIpsecEspUdp, cls).tearDownClass()

    def setUp(self):
        super(TemplateIpsecEspUdp, self).setUp()
        self.net_objs = []
        self.tun_if = self.pg0
        self.tra_if = self.pg2
        self.logger.info(self.vapi.ppcli("show int addr"))

        p = self.ipv4_params
        p.flags = (VppEnum.vl_api_ipsec_sad_flags_t.
                   IPSEC_API_SAD_FLAG_UDP_ENCAP)
        p.nat_header = UDP(sport=5454, dport=4500)

        self.tra_spd = VppIpsecSpd(self, self.tra_spd_id)
        self.tra_spd.add_vpp_config()
        VppIpsecSpdItfBinding(self, self.tra_spd,
                              self.tra_if).add_vpp_config()

        self.config_esp_tra(p)
        config_tra_params(p, self.encryption_type)

        self.tun_spd = VppIpsecSpd(self, self.tun_spd_id)
        self.tun_spd.add_vpp_config()
        VppIpsecSpdItfBinding(self, self.tun_spd,
                              self.tun_if).add_vpp_config()

        self.config_esp_tun(p)
        self.logger.info(self.vapi.ppcli("show ipsec all"))

        d = DpoProto.DPO_PROTO_IP4
        VppIpRoute(self,  p.remote_tun_if_host, p.addr_len,
                   [VppRoutePath(self.tun_if.remote_addr[p.addr_type],
                                 0xffffffff,
                                 proto=d)]).add_vpp_config()

    def tearDown(self):
        super(TemplateIpsecEspUdp, self).tearDown()

    def show_commands_at_teardown(self):
        self.logger.info(self.vapi.cli("show hardware"))


class TestIpsecEspUdp(TemplateIpsecEspUdp, IpsecTra4Tests):
    """ Ipsec NAT-T ESP UDP tests """
    pass


class TestIpsecEspAll(ConfigIpsecESP,
                      IpsecTra4, IpsecTra6,
                      IpsecTun4, IpsecTun6):
    """ Ipsec ESP all Algos """

    def setUp(self):
        super(TestIpsecEspAll, self).setUp()

    def tearDown(self):
        super(TestIpsecEspAll, self).tearDown()

    def test_crypto_algs(self):
        """All engines AES-[CBC, GCM]-[128, 192, 256] w/ & w/o ESN"""

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
                  'salt': 0},
                 {'vpp-crypto': (VppEnum.vl_api_ipsec_crypto_alg_t.
                                 IPSEC_API_CRYPTO_ALG_AES_GCM_192),
                  'vpp-integ': (VppEnum.vl_api_ipsec_integ_alg_t.
                                IPSEC_API_INTEG_ALG_NONE),
                  'scapy-crypto': "AES-GCM",
                  'scapy-integ': "NULL",
                  'key': "JPjyOWBeVEQiMe7h01234567",
                  'salt': 1010},
                 {'vpp-crypto': (VppEnum.vl_api_ipsec_crypto_alg_t.
                                 IPSEC_API_CRYPTO_ALG_AES_GCM_256),
                  'vpp-integ': (VppEnum.vl_api_ipsec_integ_alg_t.
                                IPSEC_API_INTEG_ALG_NONE),
                  'scapy-crypto': "AES-GCM",
                  'scapy-integ': "NULL",
                  'key': "JPjyOWBeVEQiMe7h0123456787654321",
                  'salt': 2020},
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

        # with and without ESN
        flags = [0,
                 VppEnum.vl_api_ipsec_sad_flags_t.IPSEC_API_SAD_FLAG_USE_ESN]

        #
        # loop through the VPP engines
        #
        for engine in engines:
            self.vapi.cli("set crypto handler all %s" % engine)
            #
            # loop through each of the algorithms
            #
            for algo in algos:
                # with self.subTest(algo=algo['scapy']):
                for flag in flags:
                    #
                    # setup up the config paramters
                    #
                    self.ipv4_params = IPsecIPv4Params()
                    self.ipv6_params = IPsecIPv6Params()

                    self.params = {self.ipv4_params.addr_type:
                                   self.ipv4_params,
                                   self.ipv6_params.addr_type:
                                   self.ipv6_params}

                    for _, p in self.params.items():
                        p.auth_algo_vpp_id = algo['vpp-integ']
                        p.crypt_algo_vpp_id = algo['vpp-crypto']
                        p.crypt_algo = algo['scapy-crypto']
                        p.auth_algo = algo['scapy-integ']
                        p.crypt_key = algo['key']
                        p.salt = algo['salt']
                        p.flags = p.flags | flag

                    #
                    # configure the SPDs. SAs, etc
                    #
                    self.config_network(self.params.values())

                    #
                    # run some traffic.
                    #  An exhautsive 4o6, 6o4 is not necessary
                    #  for each algo
                    #
                    self.verify_tra_basic6(count=17)
                    self.verify_tra_basic4(count=17)
                    self.verify_tun_66(self.params[socket.AF_INET6], 17)
                    self.verify_tun_44(self.params[socket.AF_INET], 17)

                    #
                    # remove the SPDs, SAs, etc
                    #
                    self.unconfig_network()


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
