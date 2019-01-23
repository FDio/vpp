import socket
import unittest
from scapy.layers.ipsec import ESP

from framework import VppTestRunner
from template_ipsec import IpsecTraTests, IpsecTunTests
from template_ipsec import TemplateIpsec, IpsecTcpTests


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
        self.vapi.ipsec_spd_add_del(self.tra_spd_id)
        self.vapi.ipsec_interface_add_del_spd(self.tra_spd_id,
                                              self.tra_if.sw_if_index)
        for _, p in self.params.items():
            self.config_esp_tra(p)
            self.configure_sa_tra(p)
        self.logger.info(self.vapi.ppcli("show ipsec"))
        self.vapi.ipsec_spd_add_del(self.tun_spd_id)
        self.vapi.ipsec_interface_add_del_spd(self.tun_spd_id,
                                              self.tun_if.sw_if_index)
        for _, p in self.params.items():
            self.config_esp_tun(p)
        self.logger.info(self.vapi.ppcli("show ipsec"))
        for _, p in self.params.items():
            src = socket.inet_pton(p.addr_type, p.remote_tun_if_host)
            self.vapi.ip_add_del_route(
                src, p.addr_len, self.tun_if.remote_addr_n[p.addr_type],
                is_ipv6=p.is_ipv6)

    def tearDown(self):
        for _, p in self.params.items():
            self.unconfig_esp_tun(p)
        for _, p in self.params.items():
            self.unconfig_esp_tra(p)

        self.vapi.ipsec_interface_add_del_spd(self.tun_spd_id,
                                              self.tun_if.sw_if_index,
                                              is_add=0)
        self.vapi.ipsec_spd_add_del(self.tun_spd_id, is_add=0)
        self.vapi.ipsec_interface_add_del_spd(self.tra_spd_id,
                                              self.tra_if.sw_if_index,
                                              is_add=0)
        self.vapi.ipsec_spd_add_del(self.tra_spd_id,
                                    is_add=0)
        for _, p in self.params.items():
            src = socket.inet_pton(p.addr_type, p.remote_tun_if_host)
            self.vapi.ip_add_del_route(
                src, p.addr_len, self.tun_if.remote_addr_n[p.addr_type],
                is_ipv6=p.is_ipv6, is_add=0)

        super(TemplateIpsecEsp, self).tearDown()
        if not self.vpp_dead:
            self.vapi.cli("show hardware")

    def config_esp_tun(self, params):
        addr_type = params.addr_type
        is_ipv6 = params.is_ipv6
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
        self.vapi.ipsec_sad_add_del_entry(scapy_tun_sa_id, scapy_tun_spi,
                                          auth_algo_vpp_id, auth_key,
                                          crypt_algo_vpp_id, crypt_key,
                                          self.vpp_esp_protocol,
                                          self.tun_if.local_addr_n[addr_type],
                                          self.tun_if.remote_addr_n[addr_type],
                                          is_tunnel=1, is_tunnel_ipv6=is_ipv6)
        self.vapi.ipsec_sad_add_del_entry(vpp_tun_sa_id, vpp_tun_spi,
                                          auth_algo_vpp_id, auth_key,
                                          crypt_algo_vpp_id, crypt_key,
                                          self.vpp_esp_protocol,
                                          self.tun_if.remote_addr_n[addr_type],
                                          self.tun_if.local_addr_n[addr_type],
                                          is_tunnel=1, is_tunnel_ipv6=is_ipv6)
        l_startaddr = r_startaddr = socket.inet_pton(addr_type, addr_any)
        l_stopaddr = r_stopaddr = socket.inet_pton(addr_type, addr_bcast)
        self.vapi.ipsec_spd_add_del_entry(self.tun_spd_id, scapy_tun_sa_id,
                                          l_startaddr, l_stopaddr, r_startaddr,
                                          r_stopaddr, is_ipv6=is_ipv6,
                                          protocol=socket.IPPROTO_ESP)
        self.vapi.ipsec_spd_add_del_entry(self.tun_spd_id, scapy_tun_sa_id,
                                          l_startaddr, l_stopaddr, r_startaddr,
                                          r_stopaddr, is_outbound=0,
                                          protocol=socket.IPPROTO_ESP,
                                          is_ipv6=is_ipv6)
        l_startaddr = l_stopaddr = socket.inet_pton(addr_type,
                                                    remote_tun_if_host)
        r_startaddr = r_stopaddr = self.pg1.remote_addr_n[addr_type]
        self.vapi.ipsec_spd_add_del_entry(self.tun_spd_id, vpp_tun_sa_id,
                                          l_startaddr, l_stopaddr, r_startaddr,
                                          r_stopaddr, priority=10, policy=3,
                                          is_ipv6=is_ipv6, is_outbound=0)
        self.vapi.ipsec_spd_add_del_entry(self.tun_spd_id, scapy_tun_sa_id,
                                          r_startaddr, r_stopaddr, l_startaddr,
                                          l_stopaddr, priority=10, policy=3,
                                          is_ipv6=is_ipv6)
        l_startaddr = l_stopaddr = socket.inet_pton(addr_type,
                                                    remote_tun_if_host)
        r_startaddr = r_stopaddr = self.pg0.local_addr_n[addr_type]
        self.vapi.ipsec_spd_add_del_entry(self.tun_spd_id, vpp_tun_sa_id,
                                          l_startaddr, l_stopaddr, r_startaddr,
                                          r_stopaddr, priority=20, policy=3,
                                          is_outbound=0, is_ipv6=is_ipv6)
        self.vapi.ipsec_spd_add_del_entry(self.tun_spd_id, scapy_tun_sa_id,
                                          r_startaddr, r_stopaddr, l_startaddr,
                                          l_stopaddr, priority=20, policy=3,
                                          is_ipv6=is_ipv6)

    def unconfig_esp_tun(self, params):
        addr_type = params.addr_type
        is_ipv6 = params.is_ipv6
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
        l_startaddr = r_startaddr = socket.inet_pton(addr_type, addr_any)
        l_stopaddr = r_stopaddr = socket.inet_pton(addr_type, addr_bcast)
        self.vapi.ipsec_spd_add_del_entry(self.tun_spd_id, scapy_tun_sa_id,
                                          l_startaddr, l_stopaddr, r_startaddr,
                                          r_stopaddr, is_ipv6=is_ipv6,
                                          protocol=socket.IPPROTO_ESP,
                                          is_add=0)
        self.vapi.ipsec_spd_add_del_entry(self.tun_spd_id, scapy_tun_sa_id,
                                          l_startaddr, l_stopaddr, r_startaddr,
                                          r_stopaddr, is_outbound=0,
                                          protocol=socket.IPPROTO_ESP,
                                          is_ipv6=is_ipv6,
                                          is_add=0)
        l_startaddr = l_stopaddr = socket.inet_pton(addr_type,
                                                    remote_tun_if_host)
        r_startaddr = r_stopaddr = self.pg1.remote_addr_n[addr_type]
        self.vapi.ipsec_spd_add_del_entry(self.tun_spd_id, vpp_tun_sa_id,
                                          l_startaddr, l_stopaddr, r_startaddr,
                                          r_stopaddr, priority=10, policy=3,
                                          is_ipv6=is_ipv6, is_outbound=0,
                                          is_add=0)
        self.vapi.ipsec_spd_add_del_entry(self.tun_spd_id, scapy_tun_sa_id,
                                          r_startaddr, r_stopaddr, l_startaddr,
                                          l_stopaddr, priority=10, policy=3,
                                          is_ipv6=is_ipv6, is_add=0)
        l_startaddr = l_stopaddr = socket.inet_pton(addr_type,
                                                    remote_tun_if_host)
        r_startaddr = r_stopaddr = self.pg0.local_addr_n[addr_type]
        self.vapi.ipsec_spd_add_del_entry(self.tun_spd_id, vpp_tun_sa_id,
                                          l_startaddr, l_stopaddr, r_startaddr,
                                          r_stopaddr, priority=20, policy=3,
                                          is_outbound=0, is_ipv6=is_ipv6,
                                          is_add=0)
        self.vapi.ipsec_spd_add_del_entry(self.tun_spd_id, scapy_tun_sa_id,
                                          r_startaddr, r_stopaddr, l_startaddr,
                                          l_stopaddr, priority=20, policy=3,
                                          is_ipv6=is_ipv6,
                                          is_add=0)
        self.vapi.ipsec_sad_add_del_entry(scapy_tun_sa_id, scapy_tun_spi,
                                          auth_algo_vpp_id, auth_key,
                                          crypt_algo_vpp_id, crypt_key,
                                          self.vpp_esp_protocol,
                                          self.tun_if.local_addr_n[addr_type],
                                          self.tun_if.remote_addr_n[addr_type],
                                          is_tunnel=1, is_tunnel_ipv6=is_ipv6,
                                          is_add=0)
        self.vapi.ipsec_sad_add_del_entry(vpp_tun_sa_id, vpp_tun_spi,
                                          auth_algo_vpp_id, auth_key,
                                          crypt_algo_vpp_id, crypt_key,
                                          self.vpp_esp_protocol,
                                          self.tun_if.remote_addr_n[addr_type],
                                          self.tun_if.local_addr_n[addr_type],
                                          is_tunnel=1, is_tunnel_ipv6=is_ipv6,
                                          is_add=0)

    def config_esp_tra(self, params):
        addr_type = params.addr_type
        is_ipv6 = params.is_ipv6
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
        self.vapi.ipsec_sad_add_del_entry(scapy_tra_sa_id, scapy_tra_spi,
                                          auth_algo_vpp_id, auth_key,
                                          crypt_algo_vpp_id, crypt_key,
                                          self.vpp_esp_protocol, is_tunnel=0,
                                          use_anti_replay=1)
        self.vapi.ipsec_sad_add_del_entry(vpp_tra_sa_id, vpp_tra_spi,
                                          auth_algo_vpp_id, auth_key,
                                          crypt_algo_vpp_id, crypt_key,
                                          self.vpp_esp_protocol, is_tunnel=0,
                                          use_anti_replay=1)
        l_startaddr = r_startaddr = socket.inet_pton(addr_type, addr_any)
        l_stopaddr = r_stopaddr = socket.inet_pton(addr_type, addr_bcast)
        self.vapi.ipsec_spd_add_del_entry(self.tra_spd_id, vpp_tra_sa_id,
                                          l_startaddr, l_stopaddr, r_startaddr,
                                          r_stopaddr, is_ipv6=is_ipv6,
                                          protocol=socket.IPPROTO_ESP)
        self.vapi.ipsec_spd_add_del_entry(self.tra_spd_id, vpp_tra_sa_id,
                                          l_startaddr, l_stopaddr, r_startaddr,
                                          r_stopaddr, is_outbound=0,
                                          is_ipv6=is_ipv6,
                                          protocol=socket.IPPROTO_ESP)
        l_startaddr = l_stopaddr = self.tra_if.local_addr_n[addr_type]
        r_startaddr = r_stopaddr = self.tra_if.remote_addr_n[addr_type]
        self.vapi.ipsec_spd_add_del_entry(self.tra_spd_id, vpp_tra_sa_id,
                                          l_startaddr, l_stopaddr, r_startaddr,
                                          r_stopaddr, priority=10, policy=3,
                                          is_outbound=0, is_ipv6=is_ipv6)
        self.vapi.ipsec_spd_add_del_entry(self.tra_spd_id, scapy_tra_sa_id,
                                          l_startaddr, l_stopaddr, r_startaddr,
                                          r_stopaddr, priority=10, policy=3,
                                          is_ipv6=is_ipv6)

    def unconfig_esp_tra(self, params):
        addr_type = params.addr_type
        is_ipv6 = params.is_ipv6
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
        l_startaddr = r_startaddr = socket.inet_pton(addr_type, addr_any)
        l_stopaddr = r_stopaddr = socket.inet_pton(addr_type, addr_bcast)
        self.vapi.ipsec_spd_add_del_entry(self.tra_spd_id, vpp_tra_sa_id,
                                          l_startaddr, l_stopaddr, r_startaddr,
                                          r_stopaddr, is_ipv6=is_ipv6,
                                          protocol=socket.IPPROTO_ESP,
                                          is_add=0)
        self.vapi.ipsec_spd_add_del_entry(self.tra_spd_id, vpp_tra_sa_id,
                                          l_startaddr, l_stopaddr, r_startaddr,
                                          r_stopaddr, is_outbound=0,
                                          is_ipv6=is_ipv6,
                                          protocol=socket.IPPROTO_ESP,
                                          is_add=0)
        l_startaddr = l_stopaddr = self.tra_if.local_addr_n[addr_type]
        r_startaddr = r_stopaddr = self.tra_if.remote_addr_n[addr_type]
        self.vapi.ipsec_spd_add_del_entry(self.tra_spd_id, vpp_tra_sa_id,
                                          l_startaddr, l_stopaddr, r_startaddr,
                                          r_stopaddr, priority=10, policy=3,
                                          is_outbound=0, is_ipv6=is_ipv6,
                                          is_add=0)
        self.vapi.ipsec_spd_add_del_entry(self.tra_spd_id, scapy_tra_sa_id,
                                          l_startaddr, l_stopaddr, r_startaddr,
                                          r_stopaddr, priority=10, policy=3,
                                          is_ipv6=is_ipv6,
                                          is_add=0)
        self.vapi.ipsec_sad_add_del_entry(scapy_tra_sa_id, scapy_tra_spi,
                                          auth_algo_vpp_id, auth_key,
                                          crypt_algo_vpp_id, crypt_key,
                                          self.vpp_esp_protocol, is_tunnel=0,
                                          use_anti_replay=1,
                                          is_add=0)
        self.vapi.ipsec_sad_add_del_entry(vpp_tra_sa_id, vpp_tra_spi,
                                          auth_algo_vpp_id, auth_key,
                                          crypt_algo_vpp_id, crypt_key,
                                          self.vpp_esp_protocol, is_tunnel=0,
                                          use_anti_replay=1,
                                          is_add=0)


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
