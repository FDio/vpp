import socket
import unittest

from scapy.layers.ipsec import AH

from framework import VppTestRunner
from template_ipsec import TemplateIpsec, IpsecTra46Tests, IpsecTun46Tests, \
    config_tun_params, config_tra_params, IPsecIPv4Params, IPsecIPv6Params
from template_ipsec import IpsecTcpTests
from vpp_ipsec import VppIpsecSA, VppIpsecSpd, VppIpsecSpdEntry,\
        VppIpsecSpdItfBinding
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_ip import DpoProto
from vpp_papi import VppEnum


class TemplateIpsecAh(TemplateIpsec):
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

    def setUp(self):
        super(TemplateIpsecAh, self).setUp()

        self.encryption_type = AH
        self.tun_if = self.pg0
        self.tra_if = self.pg2
        self.logger.info(self.vapi.ppcli("show int addr"))

        self.tra_spd = VppIpsecSpd(self, self.tra_spd_id)
        self.tra_spd.add_vpp_config()
        VppIpsecSpdItfBinding(self, self.tra_spd,
                              self.tra_if).add_vpp_config()
        self.tun_spd = VppIpsecSpd(self, self.tun_spd_id)
        self.tun_spd.add_vpp_config()
        VppIpsecSpdItfBinding(self, self.tun_spd,
                              self.tun_if).add_vpp_config()

        for _, p in self.params.items():
            self.config_ah_tra(p)
            config_tra_params(p, self.encryption_type)
            self.logger.info(self.vapi.ppcli("show ipsec"))
        for _, p in self.params.items():
            self.config_ah_tun(p)
            self.logger.info(self.vapi.ppcli("show ipsec"))
        for _, p in self.params.items():
            d = DpoProto.DPO_PROTO_IP6 if p.is_ipv6 else DpoProto.DPO_PROTO_IP4
            VppIpRoute(self,  p.remote_tun_if_host, p.addr_len,
                       [VppRoutePath(self.tun_if.remote_addr[p.addr_type],
                                     0xffffffff,
                                     proto=d)],
                       is_ip6=p.is_ipv6).add_vpp_config()

    def tearDown(self):
        super(TemplateIpsecAh, self).tearDown()
        if not self.vpp_dead:
            self.vapi.cli("show hardware")

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

        params.tun_sa_in = VppIpsecSA(self, scapy_tun_sa_id, scapy_tun_spi,
                                      auth_algo_vpp_id, auth_key,
                                      crypt_algo_vpp_id, crypt_key,
                                      self.vpp_ah_protocol,
                                      self.tun_if.local_addr[addr_type],
                                      self.tun_if.remote_addr[addr_type],
                                      flags=flags)
        params.tun_sa_in.add_vpp_config()
        params.tun_sa_out = VppIpsecSA(self, vpp_tun_sa_id, vpp_tun_spi,
                                       auth_algo_vpp_id, auth_key,
                                       crypt_algo_vpp_id, crypt_key,
                                       self.vpp_ah_protocol,
                                       self.tun_if.remote_addr[addr_type],
                                       self.tun_if.local_addr[addr_type],
                                       flags=flags)
        params.tun_sa_out.add_vpp_config()

        params.spd_policy_in_any = VppIpsecSpdEntry(self, self.tun_spd,
                                                    vpp_tun_sa_id,
                                                    addr_any, addr_bcast,
                                                    addr_any, addr_bcast,
                                                    socket.IPPROTO_AH)
        params.spd_policy_in_any.add_vpp_config()
        params.spd_policy_out_any = VppIpsecSpdEntry(self, self.tun_spd,
                                                     vpp_tun_sa_id,
                                                     addr_any, addr_bcast,
                                                     addr_any, addr_bcast,
                                                     socket.IPPROTO_AH,
                                                     is_outbound=0)
        params.spd_policy_out_any.add_vpp_config()

        VppIpsecSpdEntry(self, self.tun_spd, vpp_tun_sa_id,
                         remote_tun_if_host,
                         remote_tun_if_host,
                         self.pg1.remote_addr[addr_type],
                         self.pg1.remote_addr[addr_type],
                         0, priority=10,
                         policy=e.IPSEC_API_SPD_ACTION_PROTECT,
                         is_outbound=0).add_vpp_config()
        VppIpsecSpdEntry(self, self.tun_spd, scapy_tun_sa_id,
                         self.pg1.remote_addr[addr_type],
                         self.pg1.remote_addr[addr_type],
                         remote_tun_if_host,
                         remote_tun_if_host,
                         0, policy=e.IPSEC_API_SPD_ACTION_PROTECT,
                         priority=10).add_vpp_config()

        VppIpsecSpdEntry(self, self.tun_spd, vpp_tun_sa_id,
                         remote_tun_if_host,
                         remote_tun_if_host,
                         self.pg0.local_addr[addr_type],
                         self.pg0.local_addr[addr_type],
                         0, priority=20,
                         policy=e.IPSEC_API_SPD_ACTION_PROTECT,
                         is_outbound=0).add_vpp_config()
        VppIpsecSpdEntry(self, self.tun_spd, scapy_tun_sa_id,
                         self.pg0.local_addr[addr_type],
                         self.pg0.local_addr[addr_type],
                         remote_tun_if_host,
                         remote_tun_if_host,
                         0, policy=e.IPSEC_API_SPD_ACTION_PROTECT,
                         priority=20).add_vpp_config()

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

        params.tra_sa_in = VppIpsecSA(self, scapy_tra_sa_id, scapy_tra_spi,
                                      auth_algo_vpp_id, auth_key,
                                      crypt_algo_vpp_id, crypt_key,
                                      self.vpp_ah_protocol,
                                      flags=flags)
        params.tra_sa_in.add_vpp_config()
        params.tra_sa_out = VppIpsecSA(self, vpp_tra_sa_id, vpp_tra_spi,
                                       auth_algo_vpp_id, auth_key,
                                       crypt_algo_vpp_id, crypt_key,
                                       self.vpp_ah_protocol,
                                       flags=flags)
        params.tra_sa_out.add_vpp_config()

        VppIpsecSpdEntry(self, self.tra_spd, vpp_tra_sa_id,
                         addr_any, addr_bcast,
                         addr_any, addr_bcast,
                         socket.IPPROTO_AH).add_vpp_config()
        VppIpsecSpdEntry(self, self.tra_spd, scapy_tra_sa_id,
                         addr_any, addr_bcast,
                         addr_any, addr_bcast,
                         socket.IPPROTO_AH,
                         is_outbound=0).add_vpp_config()

        VppIpsecSpdEntry(self, self.tra_spd, vpp_tra_sa_id,
                         self.tra_if.local_addr[addr_type],
                         self.tra_if.local_addr[addr_type],
                         self.tra_if.remote_addr[addr_type],
                         self.tra_if.remote_addr[addr_type],
                         0, priority=10,
                         policy=e.IPSEC_API_SPD_ACTION_PROTECT,
                         is_outbound=0).add_vpp_config()
        VppIpsecSpdEntry(self, self.tra_spd, scapy_tra_sa_id,
                         self.tra_if.local_addr[addr_type],
                         self.tra_if.local_addr[addr_type],
                         self.tra_if.remote_addr[addr_type],
                         self.tra_if.remote_addr[addr_type],
                         0, policy=e.IPSEC_API_SPD_ACTION_PROTECT,
                         priority=10).add_vpp_config()


class TestIpsecAh1(TemplateIpsecAh, IpsecTcpTests):
    """ Ipsec AH - TCP tests """
    pass


class TestIpsecAh2(TemplateIpsecAh, IpsecTra46Tests, IpsecTun46Tests):
    """ Ipsec AH w/ SHA1 """
    tra4_encrypt_node_name = "ah4-encrypt"
    tra4_decrypt_node_name = "ah4-decrypt"
    tra6_encrypt_node_name = "ah6-encrypt"
    tra6_decrypt_node_name = "ah6-decrypt"
    tun4_encrypt_node_name = "ah4-encrypt"
    tun4_decrypt_node_name = "ah4-decrypt"
    tun6_encrypt_node_name = "ah6-encrypt"
    tun6_decrypt_node_name = "ah6-decrypt"


class TestIpsecAh3(TemplateIpsecAh, IpsecTra46Tests, IpsecTun46Tests):
    """ Ipsec AH w/ SHA1 & ESN """

    tra4_encrypt_node_name = "ah4-encrypt"
    tra4_decrypt_node_name = "ah4-decrypt"
    tra6_encrypt_node_name = "ah6-encrypt"
    tra6_decrypt_node_name = "ah6-decrypt"
    tun4_encrypt_node_name = "ah4-encrypt"
    tun4_decrypt_node_name = "ah4-decrypt"
    tun6_encrypt_node_name = "ah6-encrypt"
    tun6_decrypt_node_name = "ah6-decrypt"

    def setup_params(self):
        self.ipv4_params = IPsecIPv4Params()
        self.ipv6_params = IPsecIPv6Params()
        self.params = {self.ipv4_params.addr_type: self.ipv4_params,
                       self.ipv6_params.addr_type: self.ipv6_params}
        for _, p in self.params.items():
            p.flags = (VppEnum.vl_api_ipsec_sad_flags_t.
                       IPSEC_API_SAD_FLAG_USE_ESN)


class TestIpsecAh4(TemplateIpsecAh, IpsecTra46Tests, IpsecTun46Tests):
    """ Ipsec AH w/ SHA256 """

    tra4_encrypt_node_name = "ah4-encrypt"
    tra4_decrypt_node_name = "ah4-decrypt"
    tra6_encrypt_node_name = "ah6-encrypt"
    tra6_decrypt_node_name = "ah6-decrypt"
    tun4_encrypt_node_name = "ah4-encrypt"
    tun4_decrypt_node_name = "ah4-decrypt"
    tun6_encrypt_node_name = "ah6-encrypt"
    tun6_decrypt_node_name = "ah6-decrypt"

    def setup_params(self):
        self.ipv4_params = IPsecIPv4Params()
        self.ipv6_params = IPsecIPv6Params()
        self.ipv4_params.auth_algo_vpp_id = (VppEnum.vl_api_ipsec_integ_alg_t.
                                             IPSEC_API_INTEG_ALG_SHA_256_128)
        self.ipv4_params.auth_algo = 'SHA2-256-128'  # scapy name
        self.ipv6_params.auth_algo_vpp_id = (VppEnum.vl_api_ipsec_integ_alg_t.
                                             IPSEC_API_INTEG_ALG_SHA_256_128)
        self.ipv6_params.auth_algo = 'SHA2-256-128'  # scapy name

        self.params = {self.ipv4_params.addr_type: self.ipv4_params,
                       self.ipv6_params.addr_type: self.ipv6_params}


class TestIpsecAh5(TemplateIpsecAh, IpsecTra46Tests, IpsecTun46Tests):
    """ Ipsec AH w/ SHA384 """

    tra4_encrypt_node_name = "ah4-encrypt"
    tra4_decrypt_node_name = "ah4-decrypt"
    tra6_encrypt_node_name = "ah6-encrypt"
    tra6_decrypt_node_name = "ah6-decrypt"
    tun4_encrypt_node_name = "ah4-encrypt"
    tun4_decrypt_node_name = "ah4-decrypt"
    tun6_encrypt_node_name = "ah6-encrypt"
    tun6_decrypt_node_name = "ah6-decrypt"

    def setup_params(self):
        self.ipv4_params = IPsecIPv4Params()
        self.ipv6_params = IPsecIPv6Params()
        self.ipv4_params.auth_algo_vpp_id = (VppEnum.vl_api_ipsec_integ_alg_t.
                                             IPSEC_API_INTEG_ALG_SHA_384_192)
        self.ipv4_params.auth_algo = 'SHA2-384-192'  # scapy name
        self.ipv6_params.auth_algo_vpp_id = (VppEnum.vl_api_ipsec_integ_alg_t.
                                             IPSEC_API_INTEG_ALG_SHA_384_192)
        self.ipv6_params.auth_algo = 'SHA2-384-192'  # scapy name

        self.params = {self.ipv4_params.addr_type: self.ipv4_params,
                       self.ipv6_params.addr_type: self.ipv6_params}


class TestIpsecAh6(TemplateIpsecAh, IpsecTra46Tests, IpsecTun46Tests):
    """ Ipsec AH w/ SHA512 """

    tra4_encrypt_node_name = "ah4-encrypt"
    tra4_decrypt_node_name = "ah4-decrypt"
    tra6_encrypt_node_name = "ah6-encrypt"
    tra6_decrypt_node_name = "ah6-decrypt"
    tun4_encrypt_node_name = "ah4-encrypt"
    tun4_decrypt_node_name = "ah4-decrypt"
    tun6_encrypt_node_name = "ah6-encrypt"
    tun6_decrypt_node_name = "ah6-decrypt"

    def setup_params(self):
        self.ipv4_params = IPsecIPv4Params()
        self.ipv6_params = IPsecIPv6Params()
        self.ipv4_params.auth_algo_vpp_id = (VppEnum.vl_api_ipsec_integ_alg_t.
                                             IPSEC_API_INTEG_ALG_SHA_512_256)
        self.ipv4_params.auth_algo = 'SHA2-512-256'  # scapy name
        self.ipv6_params.auth_algo_vpp_id = (VppEnum.vl_api_ipsec_integ_alg_t.
                                             IPSEC_API_INTEG_ALG_SHA_512_256)
        self.ipv6_params.auth_algo = 'SHA2-512-256'  # scapy name

        self.params = {self.ipv4_params.addr_type: self.ipv4_params,
                       self.ipv6_params.addr_type: self.ipv6_params}


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
