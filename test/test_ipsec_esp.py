import socket
import unittest
from scapy.layers.ipsec import ESP

from framework import VppTestRunner
from template_ipsec import IpsecTraTests, IpsecTunTests
from template_ipsec import TemplateIpsec, IpsecTcpTests
from vpp_ipsec import *
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_ip import DpoProto


class TemplateIpsecEsp(TemplateIpsec):
    """
    Basic test for ipsec esp sanity - tunnel and transport modes.

    Below 4 cases are covered as part of this test
    1) ipsec esp v4 transport basic test  - IPv4 Transport mode
        scenario using HMAC-SHA1-96 intergrity algo
    2) ipsec esp v4 transport burst test
        Above test for 257 pkts
    3) ipsec esp 4o4 tunnel basic test    - IPv4 Tunnel mode
        scenario using HMAC-SHA1-96 intergrity algo
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

    def setUp(self):
        super(TemplateIpsecEsp, self).setUp()
        self.encryption_type = ESP
        self.tun_if = self.pg0
        self.tra_if = self.pg2
        self.logger.info(self.vapi.ppcli("show int addr"))

        self.tra_spd = VppIpsecSpd(self, self.tra_spd_id)
        self.tra_spd.add_vpp_config()
        VppIpsecSpdItfBinding(self, self.tra_spd,
                              self.tra_if).add_vpp_config()

        for _, p in self.params.items():
            self.config_esp_tra(p)
            self.configure_sa_tra(p)
        self.logger.info(self.vapi.ppcli("show ipsec"))

        self.tun_spd = VppIpsecSpd(self, self.tun_spd_id)
        self.tun_spd.add_vpp_config()
        VppIpsecSpdItfBinding(self, self.tun_spd,
                              self.tun_if).add_vpp_config()

        for _, p in self.params.items():
            self.config_esp_tun(p)
        self.logger.info(self.vapi.ppcli("show ipsec"))

        for _, p in self.params.items():
            d = DpoProto.DPO_PROTO_IP6 if p.is_ipv6 else DpoProto.DPO_PROTO_IP4
            VppIpRoute(self,  p.remote_tun_if_host, p.addr_len,
                       [VppRoutePath(self.tun_if.remote_addr[p.addr_type],
                                     0xffffffff,
                                     proto=d)],
                       is_ip6=p.is_ipv6).add_vpp_config()

    def tearDown(self):
        super(TemplateIpsecEsp, self).tearDown()
        if not self.vpp_dead:
            self.vapi.cli("show hardware")

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

        VppIpsecSA(self, scapy_tun_sa_id, scapy_tun_spi,
                   auth_algo_vpp_id, auth_key,
                   crypt_algo_vpp_id, crypt_key,
                   self.vpp_esp_protocol,
                   self.tun_if.local_addr[addr_type],
                   self.tun_if.remote_addr[addr_type]).add_vpp_config()
        VppIpsecSA(self, vpp_tun_sa_id, vpp_tun_spi,
                   auth_algo_vpp_id, auth_key,
                   crypt_algo_vpp_id, crypt_key,
                   self.vpp_esp_protocol,
                   self.tun_if.remote_addr[addr_type],
                   self.tun_if.local_addr[addr_type]).add_vpp_config()

        VppIpsecSpdEntry(self, self.tun_spd, scapy_tun_sa_id,
                         addr_any, addr_bcast,
                         addr_any, addr_bcast,
                         socket.IPPROTO_ESP).add_vpp_config()
        VppIpsecSpdEntry(self, self.tun_spd, scapy_tun_sa_id,
                         addr_any, addr_bcast,
                         addr_any, addr_bcast,
                         socket.IPPROTO_ESP,
                         is_outbound=0).add_vpp_config()

        VppIpsecSpdEntry(self, self.tun_spd, vpp_tun_sa_id,
                         remote_tun_if_host, remote_tun_if_host,
                         self.pg1.remote_addr[addr_type],
                         self.pg1.remote_addr[addr_type],
                         0,
                         priority=10,
                         policy=e.IPSEC_API_SPD_ACTION_PROTECT,
                         is_outbound=0).add_vpp_config()
        VppIpsecSpdEntry(self, self.tun_spd, scapy_tun_sa_id,
                         self.pg1.remote_addr[addr_type],
                         self.pg1.remote_addr[addr_type],
                         remote_tun_if_host, remote_tun_if_host,
                         0,
                         policy=e.IPSEC_API_SPD_ACTION_PROTECT,
                         priority=10).add_vpp_config()

        VppIpsecSpdEntry(self, self.tun_spd, vpp_tun_sa_id,
                         remote_tun_if_host, remote_tun_if_host,
                         self.pg0.local_addr[addr_type],
                         self.pg0.local_addr[addr_type],
                         0,
                         priority=20,
                         policy=e.IPSEC_API_SPD_ACTION_PROTECT,
                         is_outbound=0).add_vpp_config()
        VppIpsecSpdEntry(self, self.tun_spd, scapy_tun_sa_id,
                         self.pg0.local_addr[addr_type],
                         self.pg0.local_addr[addr_type],
                         remote_tun_if_host, remote_tun_if_host,
                         0,
                         policy=e.IPSEC_API_SPD_ACTION_PROTECT,
                         priority=20).add_vpp_config()

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

        VppIpsecSA(self, scapy_tra_sa_id, scapy_tra_spi,
                   auth_algo_vpp_id, auth_key,
                   crypt_algo_vpp_id, crypt_key,
                   self.vpp_esp_protocol,
                   flags=flags).add_vpp_config()
        VppIpsecSA(self, vpp_tra_sa_id, vpp_tra_spi,
                   auth_algo_vpp_id, auth_key,
                   crypt_algo_vpp_id, crypt_key,
                   self.vpp_esp_protocol,
                   flags=flags).add_vpp_config()

        VppIpsecSpdEntry(self, self.tra_spd, vpp_tra_sa_id,
                         addr_any, addr_bcast,
                         addr_any, addr_bcast,
                         socket.IPPROTO_ESP).add_vpp_config()
        VppIpsecSpdEntry(self, self.tra_spd, vpp_tra_sa_id,
                         addr_any, addr_bcast,
                         addr_any, addr_bcast,
                         socket.IPPROTO_ESP,
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


class TestIpsecEsp1(TemplateIpsecEsp, IpsecTraTests, IpsecTunTests):
    """ Ipsec ESP - TUN & TRA tests """
    tra4_encrypt_node_name = "esp4-encrypt"
    tra4_decrypt_node_name = "esp4-decrypt"
    tra6_encrypt_node_name = "esp6-encrypt"
    tra6_decrypt_node_name = "esp6-decrypt"
    tun4_encrypt_node_name = "esp4-encrypt"
    tun4_decrypt_node_name = "esp4-decrypt"
    tun6_encrypt_node_name = "esp6-encrypt"
    tun6_decrypt_node_name = "esp6-decrypt"


class TestIpsecEsp2(TemplateIpsecEsp, IpsecTcpTests):
    """ Ipsec ESP - TCP tests """
    pass


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
