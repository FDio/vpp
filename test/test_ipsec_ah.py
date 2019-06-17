import socket
import unittest

from scapy.layers.ipsec import AH

from framework import VppTestRunner
from template_ipsec import TemplateIpsec, IpsecTra46Tests, IpsecTun46Tests, \
    config_tun_params, config_tra_params, IPsecIPv4Params, IPsecIPv6Params, \
    IpsecTra4, IpsecTun4, IpsecTra6, IpsecTun6
from template_ipsec import IpsecTcpTests
from vpp_ipsec import VppIpsecSA, VppIpsecSpd, VppIpsecSpdEntry,\
        VppIpsecSpdItfBinding
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_ip import DpoProto
from vpp_papi import VppEnum


class ConfigIpsecAH(TemplateIpsec):
    """
    Basic test for IPSEC using AH transport and Tunnel mode

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
    encryption_type = AH
    net_objs = []
    tra4_encrypt_node_name = "ah4-encrypt"
    tra4_decrypt_node_name = "ah4-decrypt"
    tra6_encrypt_node_name = "ah6-encrypt"
    tra6_decrypt_node_name = "ah6-decrypt"
    tun4_encrypt_node_name = "ah4-encrypt"
    tun4_decrypt_node_name = "ah4-decrypt"
    tun6_encrypt_node_name = "ah6-encrypt"
    tun6_decrypt_node_name = "ah6-decrypt"

    @classmethod
    def setUpClass(cls):
        super(ConfigIpsecAH, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(ConfigIpsecAH, cls).tearDownClass()

    def setUp(self):
        super(ConfigIpsecAH, self).setUp()

    def tearDown(self):
        super(ConfigIpsecAH, self).tearDown()

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

        b = VppIpsecSpdItfBinding(self, self.tra_spd,
                                  self.tra_if)
        b.add_vpp_config()
        self.net_objs.append(b)

        b = VppIpsecSpdItfBinding(self, self.tun_spd,
                                  self.tun_if)
        b.add_vpp_config()
        self.net_objs.append(b)

        for p in params:
            self.config_ah_tra(p)
            config_tra_params(p, self.encryption_type)
        for p in params:
            self.config_ah_tun(p)
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

    def config_ah_tun(self, params):
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
        flags = params.flags
        e = VppEnum.vl_api_ipsec_spd_action_t
        objs = []

        params.tun_sa_in = VppIpsecSA(self, scapy_tun_sa_id, scapy_tun_spi,
                                      auth_algo_vpp_id, auth_key,
                                      crypt_algo_vpp_id, crypt_key,
                                      self.vpp_ah_protocol,
                                      self.tun_if.local_addr[addr_type],
                                      self.tun_if.remote_addr[addr_type],
                                      flags=flags)

        params.tun_sa_out = VppIpsecSA(self, vpp_tun_sa_id, vpp_tun_spi,
                                       auth_algo_vpp_id, auth_key,
                                       crypt_algo_vpp_id, crypt_key,
                                       self.vpp_ah_protocol,
                                       self.tun_if.remote_addr[addr_type],
                                       self.tun_if.local_addr[addr_type],
                                       flags=flags)

        objs.append(params.tun_sa_in)
        objs.append(params.tun_sa_out)

        params.spd_policy_in_any = VppIpsecSpdEntry(self, self.tun_spd,
                                                    vpp_tun_sa_id,
                                                    addr_any, addr_bcast,
                                                    addr_any, addr_bcast,
                                                    socket.IPPROTO_AH)
        params.spd_policy_out_any = VppIpsecSpdEntry(self, self.tun_spd,
                                                     vpp_tun_sa_id,
                                                     addr_any, addr_bcast,
                                                     addr_any, addr_bcast,
                                                     socket.IPPROTO_AH,
                                                     is_outbound=0)

        objs.append(params.spd_policy_out_any)
        objs.append(params.spd_policy_in_any)

        e1 = VppIpsecSpdEntry(self, self.tun_spd, vpp_tun_sa_id,
                              remote_tun_if_host,
                              remote_tun_if_host,
                              self.pg1.remote_addr[addr_type],
                              self.pg1.remote_addr[addr_type],
                              0, priority=10,
                              policy=e.IPSEC_API_SPD_ACTION_PROTECT,
                              is_outbound=0)
        e2 = VppIpsecSpdEntry(self, self.tun_spd, scapy_tun_sa_id,
                              self.pg1.remote_addr[addr_type],
                              self.pg1.remote_addr[addr_type],
                              remote_tun_if_host,
                              remote_tun_if_host,
                              0, policy=e.IPSEC_API_SPD_ACTION_PROTECT,
                              priority=10)
        e3 = VppIpsecSpdEntry(self, self.tun_spd, vpp_tun_sa_id,
                              remote_tun_if_host,
                              remote_tun_if_host,
                              self.pg0.local_addr[addr_type],
                              self.pg0.local_addr[addr_type],
                              0, priority=20,
                              policy=e.IPSEC_API_SPD_ACTION_PROTECT,
                              is_outbound=0)
        e4 = VppIpsecSpdEntry(self, self.tun_spd, scapy_tun_sa_id,
                              self.pg0.local_addr[addr_type],
                              self.pg0.local_addr[addr_type],
                              remote_tun_if_host,
                              remote_tun_if_host,
                              0, policy=e.IPSEC_API_SPD_ACTION_PROTECT,
                              priority=20)

        objs = objs + [e1, e2, e3, e4]

        for o in objs:
            o.add_vpp_config()

        self.net_objs = self.net_objs + objs

    def config_ah_tra(self, params):
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
        flags = params.flags | (VppEnum.vl_api_ipsec_sad_flags_t.
                                IPSEC_API_SAD_FLAG_USE_ANTI_REPLAY)
        e = VppEnum.vl_api_ipsec_spd_action_t
        objs = []

        params.tra_sa_in = VppIpsecSA(self, scapy_tra_sa_id, scapy_tra_spi,
                                      auth_algo_vpp_id, auth_key,
                                      crypt_algo_vpp_id, crypt_key,
                                      self.vpp_ah_protocol,
                                      flags=flags)
        params.tra_sa_out = VppIpsecSA(self, vpp_tra_sa_id, vpp_tra_spi,
                                       auth_algo_vpp_id, auth_key,
                                       crypt_algo_vpp_id, crypt_key,
                                       self.vpp_ah_protocol,
                                       flags=flags)

        objs.append(params.tra_sa_in)
        objs.append(params.tra_sa_out)

        objs.append(VppIpsecSpdEntry(self, self.tra_spd, vpp_tra_sa_id,
                                     addr_any, addr_bcast,
                                     addr_any, addr_bcast,
                                     socket.IPPROTO_AH))
        objs.append(VppIpsecSpdEntry(self, self.tra_spd, scapy_tra_sa_id,
                                     addr_any, addr_bcast,
                                     addr_any, addr_bcast,
                                     socket.IPPROTO_AH,
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


class TemplateIpsecAh(ConfigIpsecAH):
    """
    Basic test for IPSEC using AH transport and Tunnel mode

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
        super(TemplateIpsecAh, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TemplateIpsecAh, cls).tearDownClass()

    def setUp(self):
        super(TemplateIpsecAh, self).setUp()
        self.config_network(self.params.values())

    def tearDown(self):
        self.unconfig_network()
        super(TemplateIpsecAh, self).tearDown()


class TestIpsecAh1(TemplateIpsecAh, IpsecTcpTests):
    """ Ipsec AH - TCP tests """
    pass


class TestIpsecAh2(TemplateIpsecAh, IpsecTra46Tests, IpsecTun46Tests):
    """ Ipsec AH w/ SHA1 """
    pass


class TestIpsecAhAll(ConfigIpsecAH,
                     IpsecTra4, IpsecTra6,
                     IpsecTun4, IpsecTun6):
    """ Ipsec AH all Algos """

    def setUp(self):
        super(TestIpsecAhAll, self).setUp()

    def tearDown(self):
        super(TestIpsecAhAll, self).tearDown()

    def test_integ_algs(self):
        """All Engines SHA[1_96, 256, 384, 512] w/ & w/o ESN"""
        # foreach VPP crypto engine
        engines = ["ia32", "ipsecmb", "openssl"]

        algos = [{'vpp': VppEnum.vl_api_ipsec_integ_alg_t.
                  IPSEC_API_INTEG_ALG_SHA1_96,
                  'scapy': "HMAC-SHA1-96"},
                 {'vpp': VppEnum.vl_api_ipsec_integ_alg_t.
                  IPSEC_API_INTEG_ALG_SHA_256_128,
                  'scapy': "SHA2-256-128"},
                 {'vpp': VppEnum.vl_api_ipsec_integ_alg_t.
                  IPSEC_API_INTEG_ALG_SHA_384_192,
                  'scapy': "SHA2-384-192"},
                 {'vpp': VppEnum.vl_api_ipsec_integ_alg_t.
                  IPSEC_API_INTEG_ALG_SHA_512_256,
                  'scapy': "SHA2-512-256"}]

        flags = [0, (VppEnum.vl_api_ipsec_sad_flags_t.
                     IPSEC_API_SAD_FLAG_USE_ESN)]

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
                        p.auth_algo_vpp_id = algo['vpp']
                        p.auth_algo = algo['scapy']
                        p.flags = p.flags | flag

                    #
                    # configure the SPDs. SAs, etc
                    #
                    self.config_network(self.params.values())

                    #
                    # run some traffic.
                    #  An exhautsive 4o6, 6o4 is not necessary for each algo
                    #
                    self.verify_tra_basic6(count=17)
                    self.verify_tra_basic4(count=17)
                    self.verify_tun_66(self.params[socket.AF_INET6], count=17)
                    self.verify_tun_44(self.params[socket.AF_INET], count=17)

                    #
                    # remove the SPDs, SAs, etc
                    #
                    self.unconfig_network()


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
