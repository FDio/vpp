import socket
import unittest
from scapy.layers.ipsec import ESP
from scapy.layers.inet import IP, ICMP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from parameterized import parameterized
from framework import VppTestRunner
from template_ipsec import IpsecTra46Tests, IpsecTun46Tests, TemplateIpsec, \
    IpsecTcpTests, IpsecTun4Tests, IpsecTra4Tests, config_tra_params, \
    config_tun_params, IPsecIPv4Params, IPsecIPv6Params, \
    IpsecTra4, IpsecTun4, IpsecTra6, IpsecTun6, \
    IpsecTun6HandoffTests, IpsecTun4HandoffTests, \
    IpsecTra6ExtTests
from vpp_ipsec import VppIpsecSpd, VppIpsecSpdEntry, VppIpsecSA,\
    VppIpsecSpdItfBinding
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_ip import DpoProto
from vpp_papi import VppEnum

NUM_PKTS = 67
engines_supporting_chain_bufs = ["openssl", "async"]
engines = ["ia32", "ipsecmb", "openssl"]


class ConfigIpsecESP(TemplateIpsec):
    encryption_type = ESP
    tra4_encrypt_node_name = "esp4-encrypt"
    tra4_decrypt_node_name = ["esp4-decrypt", "esp4-decrypt-post"]
    tra6_encrypt_node_name = "esp6-encrypt"
    tra6_decrypt_node_name = ["esp6-decrypt", "esp6-decrypt-post"]
    tun4_encrypt_node_name = "esp4-encrypt"
    tun4_decrypt_node_name = ["esp4-decrypt", "esp4-decrypt-post"]
    tun6_encrypt_node_name = "esp6-encrypt"
    tun6_decrypt_node_name = ["esp6-decrypt", "esp6-decrypt-post"]

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
            config_tun_params(p, self.encryption_type, self.tun_if)

        for p in params:
            d = DpoProto.DPO_PROTO_IP6 if p.is_ipv6 else DpoProto.DPO_PROTO_IP4
            r = VppIpRoute(self,  p.remote_tun_if_host, p.addr_len,
                           [VppRoutePath(self.tun_if.remote_addr[p.addr_type],
                                         0xffffffff,
                                         proto=d)])
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
        tun_flags = params.tun_flags
        salt = params.salt
        objs = []

        params.tun_sa_in = VppIpsecSA(self, scapy_tun_sa_id, scapy_tun_spi,
                                      auth_algo_vpp_id, auth_key,
                                      crypt_algo_vpp_id, crypt_key,
                                      self.vpp_esp_protocol,
                                      self.tun_if.local_addr[addr_type],
                                      self.tun_if.remote_addr[addr_type],
                                      tun_flags=tun_flags,
                                      dscp=params.dscp,
                                      flags=flags,
                                      salt=salt,
                                      hop_limit=params.outer_hop_limit)
        params.tun_sa_out = VppIpsecSA(self, vpp_tun_sa_id, vpp_tun_spi,
                                       auth_algo_vpp_id, auth_key,
                                       crypt_algo_vpp_id, crypt_key,
                                       self.vpp_esp_protocol,
                                       self.tun_if.remote_addr[addr_type],
                                       self.tun_if.local_addr[addr_type],
                                       tun_flags=tun_flags,
                                       dscp=params.dscp,
                                       flags=flags,
                                       salt=salt,
                                       hop_limit=params.outer_hop_limit)
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


class TestIpsecEsp1(TemplateIpsecEsp, IpsecTra46Tests,
                    IpsecTun46Tests, IpsecTra6ExtTests):
    """ Ipsec ESP - TUN & TRA tests """

    @classmethod
    def setUpClass(cls):
        super(TestIpsecEsp1, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestIpsecEsp1, cls).tearDownClass()

    def setUp(self):
        super(TestIpsecEsp1, self).setUp()

    def tearDown(self):
        super(TestIpsecEsp1, self).tearDown()

    def test_tun_46(self):
        """ ipsec 4o6 tunnel """
        # add an SPD entry to direct 2.2.2.2 to the v6 tunnel SA
        p6 = self.ipv6_params
        p4 = self.ipv4_params

        p6.remote_tun_if_host4 = "2.2.2.2"
        e = VppEnum.vl_api_ipsec_spd_action_t

        VppIpsecSpdEntry(self,
                         self.tun_spd,
                         p6.scapy_tun_sa_id,
                         self.pg1.remote_addr[p4.addr_type],
                         self.pg1.remote_addr[p4.addr_type],
                         p6.remote_tun_if_host4,
                         p6.remote_tun_if_host4,
                         0,
                         priority=10,
                         policy=e.IPSEC_API_SPD_ACTION_PROTECT,
                         is_outbound=1).add_vpp_config()
        VppIpRoute(self,  p6.remote_tun_if_host4, p4.addr_len,
                   [VppRoutePath(self.tun_if.remote_addr[p4.addr_type],
                                 0xffffffff)]).add_vpp_config()

        old_name = self.tun6_encrypt_node_name
        self.tun6_encrypt_node_name = "esp4-encrypt"

        self.verify_tun_46(p6, count=63)
        self.tun6_encrypt_node_name = old_name

    def test_tun_64(self):
        """ ipsec 6o4 tunnel """
        # add an SPD entry to direct 4444::4 to the v4 tunnel SA
        p6 = self.ipv6_params
        p4 = self.ipv4_params

        p4.remote_tun_if_host6 = "4444::4"
        e = VppEnum.vl_api_ipsec_spd_action_t

        VppIpsecSpdEntry(self,
                         self.tun_spd,
                         p4.scapy_tun_sa_id,
                         self.pg1.remote_addr[p6.addr_type],
                         self.pg1.remote_addr[p6.addr_type],
                         p4.remote_tun_if_host6,
                         p4.remote_tun_if_host6,
                         0,
                         priority=10,
                         policy=e.IPSEC_API_SPD_ACTION_PROTECT,
                         is_outbound=1).add_vpp_config()
        d = DpoProto.DPO_PROTO_IP6
        VppIpRoute(self,  p4.remote_tun_if_host6, p6.addr_len,
                   [VppRoutePath(self.tun_if.remote_addr[p6.addr_type],
                                 0xffffffff,
                                 proto=d)]).add_vpp_config()

        old_name = self.tun4_encrypt_node_name
        self.tun4_encrypt_node_name = "esp6-encrypt"
        self.verify_tun_64(p4, count=63)
        self.tun4_encrypt_node_name = old_name


class TestIpsecEspTun(TemplateIpsecEsp, IpsecTun46Tests):
    """ Ipsec ESP - TUN encap tests """

    def setUp(self):
        self.ipv4_params = IPsecIPv4Params()
        self.ipv6_params = IPsecIPv6Params()

        c = (VppEnum.vl_api_tunnel_encap_decap_flags_t.
             TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_DSCP)
        c1 = c | (VppEnum.vl_api_tunnel_encap_decap_flags_t.
                  TUNNEL_API_ENCAP_DECAP_FLAG_ENCAP_COPY_ECN)

        self.ipv4_params.tun_flags = c
        self.ipv6_params.tun_flags = c1

        super(TestIpsecEspTun, self).setUp()

    def gen_pkts(self, sw_intf, src, dst, count=1, payload_size=54):
        # set the DSCP + ECN - flags are set to copy only DSCP
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                IP(src=src, dst=dst, tos=5) /
                UDP(sport=4444, dport=4444) /
                Raw(b'X' * payload_size)
                for i in range(count)]

    def gen_pkts6(self, p, sw_intf, src, dst, count=1, payload_size=54):
        # set the DSCP + ECN - flags are set to copy both
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                IPv6(src=src, dst=dst, tc=5) /
                UDP(sport=4444, dport=4444) /
                Raw(b'X' * payload_size)
                for i in range(count)]

    def verify_encrypted(self, p, sa, rxs):
        # just check that only the DSCP is copied
        for rx in rxs:
            self.assertEqual(rx[IP].tos, 4)

    def verify_encrypted6(self, p, sa, rxs):
        # just check that the DSCP & ECN are copied
        for rx in rxs:
            self.assertEqual(rx[IPv6].tc, 5)


class TestIpsecEspTun2(TemplateIpsecEsp, IpsecTun46Tests):
    """ Ipsec ESP - TUN DSCP tests """

    def setUp(self):
        self.ipv4_params = IPsecIPv4Params()
        self.ipv6_params = IPsecIPv6Params()

        self.ipv4_params.dscp = VppEnum.vl_api_ip_dscp_t.IP_API_DSCP_EF
        self.ipv6_params.dscp = VppEnum.vl_api_ip_dscp_t.IP_API_DSCP_AF11

        super(TestIpsecEspTun2, self).setUp()

    def gen_pkts(self, sw_intf, src, dst, count=1, payload_size=54):
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                IP(src=src, dst=dst) /
                UDP(sport=4444, dport=4444) /
                Raw(b'X' * payload_size)
                for i in range(count)]

    def gen_pkts6(self, p, sw_intf, src, dst, count=1, payload_size=54):
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                IPv6(src=src, dst=dst) /
                UDP(sport=4444, dport=4444) /
                Raw(b'X' * payload_size)
                for i in range(count)]

    def verify_encrypted(self, p, sa, rxs):
        # just check that only the DSCP is set
        for rx in rxs:
            self.assertEqual(rx[IP].tos,
                             VppEnum.vl_api_ip_dscp_t.IP_API_DSCP_EF << 2)

    def verify_encrypted6(self, p, sa, rxs):
        # just check that the DSCP is set
        for rx in rxs:
            self.assertEqual(rx[IPv6].tc,
                             VppEnum.vl_api_ip_dscp_t.IP_API_DSCP_AF11 << 2)


class TestIpsecEsp2(TemplateIpsecEsp, IpsecTcpTests):
    """ Ipsec ESP - TCP tests """
    pass


class TestIpsecEspAsync(TemplateIpsecEsp):
    """ Ipsec ESP - Aysnc tests """

    worker_config = "workers 2"

    def setUp(self):
        super(TestIpsecEspAsync, self).setUp()

        self.p_sync = IPsecIPv4Params()

        self.p_sync.crypt_algo_vpp_id = (VppEnum.vl_api_ipsec_crypto_alg_t.
                                         IPSEC_API_CRYPTO_ALG_AES_CBC_256)
        self.p_sync.crypt_algo = 'AES-CBC'  # scapy name
        self.p_sync.crypt_key = b'JPjyOWBeVEQiMe7hJPjyOWBeVEQiMe7h'

        self.p_sync.scapy_tun_sa_id += 0xf0000
        self.p_sync.scapy_tun_spi += 0xf0000
        self.p_sync.vpp_tun_sa_id += 0xf0000
        self.p_sync.vpp_tun_spi += 0xf0000
        self.p_sync.remote_tun_if_host = "2.2.2.2"
        e = VppEnum.vl_api_ipsec_spd_action_t

        self.p_sync.sa = VppIpsecSA(
            self,
            self.p_sync.vpp_tun_sa_id,
            self.p_sync.vpp_tun_spi,
            self.p_sync.auth_algo_vpp_id,
            self.p_sync.auth_key,
            self.p_sync.crypt_algo_vpp_id,
            self.p_sync.crypt_key,
            self.vpp_esp_protocol,
            self.tun_if.local_addr[self.p_sync.addr_type],
            self.tun_if.remote_addr[self.p_sync.addr_type]).add_vpp_config()
        self.p_sync.spd = VppIpsecSpdEntry(
            self,
            self.tun_spd,
            self.p_sync.vpp_tun_sa_id,
            self.pg1.remote_addr[self.p_sync.addr_type],
            self.pg1.remote_addr[self.p_sync.addr_type],
            self.p_sync.remote_tun_if_host,
            self.p_sync.remote_tun_if_host,
            0,
            priority=1,
            policy=e.IPSEC_API_SPD_ACTION_PROTECT,
            is_outbound=1).add_vpp_config()
        VppIpRoute(self,
                   self.p_sync.remote_tun_if_host,
                   self.p_sync.addr_len,
                   [VppRoutePath(
                       self.tun_if.remote_addr[self.p_sync.addr_type],
                       0xffffffff)]).add_vpp_config()
        config_tun_params(self.p_sync, self.encryption_type, self.tun_if)

        self.p_async = IPsecIPv4Params()

        self.p_async.crypt_algo_vpp_id = (VppEnum.vl_api_ipsec_crypto_alg_t.
                                          IPSEC_API_CRYPTO_ALG_AES_GCM_256)
        self.p_async.auth_algo_vpp_id = (VppEnum.vl_api_ipsec_integ_alg_t.
                                         IPSEC_API_INTEG_ALG_NONE)
        self.p_async.crypt_algo = 'AES-GCM'  # scapy name
        self.p_async.crypt_key = b'JPjyOWBeVEQiMe7hJPjyOWBeVEQiMe7h'
        self.p_async.auth_algo = 'NULL'

        self.p_async.scapy_tun_sa_id += 0xe0000
        self.p_async.scapy_tun_spi += 0xe0000
        self.p_async.vpp_tun_sa_id += 0xe0000
        self.p_async.vpp_tun_spi += 0xe0000
        self.p_async.remote_tun_if_host = "2.2.2.3"

        iflags = VppEnum.vl_api_ipsec_sad_flags_t
        self.p_async.flags = (iflags.IPSEC_API_SAD_FLAG_USE_ESN |
                              iflags.IPSEC_API_SAD_FLAG_USE_ANTI_REPLAY |
                              iflags.IPSEC_API_SAD_FLAG_ASYNC)

        self.p_async.sa = VppIpsecSA(
            self,
            self.p_async.vpp_tun_sa_id,
            self.p_async.vpp_tun_spi,
            self.p_async.auth_algo_vpp_id,
            self.p_async.auth_key,
            self.p_async.crypt_algo_vpp_id,
            self.p_async.crypt_key,
            self.vpp_esp_protocol,
            self.tun_if.local_addr[self.p_async.addr_type],
            self.tun_if.remote_addr[self.p_async.addr_type],
            flags=self.p_async.flags).add_vpp_config()
        self.p_async.spd = VppIpsecSpdEntry(
            self,
            self.tun_spd,
            self.p_async.vpp_tun_sa_id,
            self.pg1.remote_addr[self.p_async.addr_type],
            self.pg1.remote_addr[self.p_async.addr_type],
            self.p_async.remote_tun_if_host,
            self.p_async.remote_tun_if_host,
            0,
            priority=2,
            policy=e.IPSEC_API_SPD_ACTION_PROTECT,
            is_outbound=1).add_vpp_config()
        VppIpRoute(self,
                   self.p_async.remote_tun_if_host,
                   self.p_async.addr_len,
                   [VppRoutePath(
                       self.tun_if.remote_addr[self.p_async.addr_type],
                       0xffffffff)]).add_vpp_config()
        config_tun_params(self.p_async, self.encryption_type, self.tun_if)

    def test_dual_stream(self):
        """ Alternating SAs """
        p = self.params[self.p_sync.addr_type]
        self.vapi.ipsec_set_async_mode(async_enable=True)

        pkts = [(Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
                 IP(src=self.pg1.remote_ip4,
                    dst=self.p_sync.remote_tun_if_host) /
                 UDP(sport=4444, dport=4444) /
                 Raw(b'0x0' * 200)),
                (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
                 IP(src=self.pg1.remote_ip4,
                    dst=p.remote_tun_if_host) /
                 UDP(sport=4444, dport=4444) /
                 Raw(b'0x0' * 200))]
        pkts *= 1023

        rxs = self.send_and_expect(self.pg1, pkts, self.pg0)

        self.assertEqual(len(rxs), len(pkts))

        for rx in rxs:
            if rx[ESP].spi == p.scapy_tun_spi:
                decrypted = p.vpp_tun_sa.decrypt(rx[IP])
            elif rx[ESP].spi == self.p_sync.vpp_tun_spi:
                decrypted = self.p_sync.scapy_tun_sa.decrypt(rx[IP])
            else:
                rx.show()
                self.assertTrue(False)

        self.p_sync.spd.remove_vpp_config()
        self.p_sync.sa.remove_vpp_config()
        self.p_async.spd.remove_vpp_config()
        self.p_async.sa.remove_vpp_config()
        self.vapi.ipsec_set_async_mode(async_enable=False)

    def test_sync_async_noop_stream(self):
        """ Alternating SAs sync/async/noop """
        p = self.params[self.p_sync.addr_type]

        # first pin the default/noop SA to worker 0
        pkts = [(Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
                 IP(src=self.pg1.remote_ip4,
                    dst=p.remote_tun_if_host) /
                 UDP(sport=4444, dport=4444) /
                 Raw(b'0x0' * 200))]
        rxs = self.send_and_expect(self.pg1, pkts, self.pg0, worker=0)

        self.logger.info(self.vapi.cli("sh ipsec sa"))
        self.logger.info(self.vapi.cli("sh crypto async status"))

        # then use all the other SAs on worker 1.
        # some will handoff, other take the sync and async paths
        pkts = [(Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
                 IP(src=self.pg1.remote_ip4,
                    dst=self.p_sync.remote_tun_if_host) /
                 UDP(sport=4444, dport=4444) /
                 Raw(b'0x0' * 200)),
                (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
                 IP(src=self.pg1.remote_ip4,
                    dst=p.remote_tun_if_host) /
                 UDP(sport=4444, dport=4444) /
                 Raw(b'0x0' * 200)),
                (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
                 IP(src=self.pg1.remote_ip4,
                    dst=self.p_async.remote_tun_if_host) /
                 UDP(sport=4444, dport=4444) /
                 Raw(b'0x0' * 200))]
        pkts *= 1023

        rxs = self.send_and_expect(self.pg1, pkts, self.pg0, worker=1)

        self.assertEqual(len(rxs), len(pkts))

        for rx in rxs:
            if rx[ESP].spi == p.scapy_tun_spi:
                decrypted = p.vpp_tun_sa.decrypt(rx[IP])
            elif rx[ESP].spi == self.p_sync.vpp_tun_spi:
                decrypted = self.p_sync.scapy_tun_sa.decrypt(rx[IP])
            elif rx[ESP].spi == self.p_async.vpp_tun_spi:
                decrypted = self.p_async.scapy_tun_sa.decrypt(rx[IP])
            else:
                rx.show()
                self.assertTrue(False)

        self.p_sync.spd.remove_vpp_config()
        self.p_sync.sa.remove_vpp_config()
        self.p_async.spd.remove_vpp_config()
        self.p_async.sa.remove_vpp_config()

        # async mode should have been disabled now that there are
        # no async SAs. there's no API for this, so a reluctant
        # screen scrape.
        self.assertTrue("DISABLED" in self.vapi.cli("sh crypto async status"))


class TestIpsecEspHandoff(TemplateIpsecEsp,
                          IpsecTun6HandoffTests,
                          IpsecTun4HandoffTests):
    """ Ipsec ESP - handoff tests """
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


class MyParameters():
    def __init__(self):
        flag_esn = VppEnum.vl_api_ipsec_sad_flags_t.IPSEC_API_SAD_FLAG_USE_ESN
        self.flags = [0, flag_esn]
        # foreach crypto algorithm
        self.algos = {
            'AES-GCM-128/NONE': {
                  'vpp-crypto': (VppEnum.vl_api_ipsec_crypto_alg_t.
                                 IPSEC_API_CRYPTO_ALG_AES_GCM_128),
                  'vpp-integ': (VppEnum.vl_api_ipsec_integ_alg_t.
                                IPSEC_API_INTEG_ALG_NONE),
                  'scapy-crypto': "AES-GCM",
                  'scapy-integ': "NULL",
                  'key': b"JPjyOWBeVEQiMe7h",
                  'salt': 0},
            'AES-GCM-192/NONE': {
                  'vpp-crypto': (VppEnum.vl_api_ipsec_crypto_alg_t.
                                 IPSEC_API_CRYPTO_ALG_AES_GCM_192),
                  'vpp-integ': (VppEnum.vl_api_ipsec_integ_alg_t.
                                IPSEC_API_INTEG_ALG_NONE),
                  'scapy-crypto': "AES-GCM",
                  'scapy-integ': "NULL",
                  'key': b"JPjyOWBeVEQiMe7h01234567",
                  'salt': 1010},
            'AES-GCM-256/NONE': {
                  'vpp-crypto': (VppEnum.vl_api_ipsec_crypto_alg_t.
                                 IPSEC_API_CRYPTO_ALG_AES_GCM_256),
                  'vpp-integ': (VppEnum.vl_api_ipsec_integ_alg_t.
                                IPSEC_API_INTEG_ALG_NONE),
                  'scapy-crypto': "AES-GCM",
                  'scapy-integ': "NULL",
                  'key': b"JPjyOWBeVEQiMe7h0123456787654321",
                  'salt': 2020},
            'AES-CBC-128/MD5-96': {
                  'vpp-crypto': (VppEnum.vl_api_ipsec_crypto_alg_t.
                                 IPSEC_API_CRYPTO_ALG_AES_CBC_128),
                  'vpp-integ': (VppEnum.vl_api_ipsec_integ_alg_t.
                                IPSEC_API_INTEG_ALG_MD5_96),
                  'scapy-crypto': "AES-CBC",
                  'scapy-integ': "HMAC-MD5-96",
                  'salt': 0,
                  'key': b"JPjyOWBeVEQiMe7h"},
            'AES-CBC-192/SHA1-96': {
                  'vpp-crypto': (VppEnum.vl_api_ipsec_crypto_alg_t.
                                 IPSEC_API_CRYPTO_ALG_AES_CBC_192),
                  'vpp-integ': (VppEnum.vl_api_ipsec_integ_alg_t.
                                IPSEC_API_INTEG_ALG_SHA1_96),
                  'scapy-crypto': "AES-CBC",
                  'scapy-integ': "HMAC-SHA1-96",
                  'salt': 0,
                  'key': b"JPjyOWBeVEQiMe7hJPjyOWBe"},
            'AES-CBC-256/SHA1-96': {
                  'vpp-crypto': (VppEnum.vl_api_ipsec_crypto_alg_t.
                                 IPSEC_API_CRYPTO_ALG_AES_CBC_256),
                  'vpp-integ': (VppEnum.vl_api_ipsec_integ_alg_t.
                                IPSEC_API_INTEG_ALG_SHA1_96),
                  'scapy-crypto': "AES-CBC",
                  'scapy-integ': "HMAC-SHA1-96",
                  'salt': 0,
                  'key': b"JPjyOWBeVEQiMe7hJPjyOWBeVEQiMe7h"},
            '3DES-CBC/SHA1-96': {
                  'vpp-crypto': (VppEnum.vl_api_ipsec_crypto_alg_t.
                                 IPSEC_API_CRYPTO_ALG_3DES_CBC),
                  'vpp-integ': (VppEnum.vl_api_ipsec_integ_alg_t.
                                IPSEC_API_INTEG_ALG_SHA1_96),
                  'scapy-crypto': "3DES",
                  'scapy-integ': "HMAC-SHA1-96",
                  'salt': 0,
                  'key': b"JPjyOWBeVEQiMe7h00112233"},
            'NONE/SHA1-96': {
                  'vpp-crypto': (VppEnum.vl_api_ipsec_crypto_alg_t.
                                 IPSEC_API_CRYPTO_ALG_NONE),
                  'vpp-integ': (VppEnum.vl_api_ipsec_integ_alg_t.
                                IPSEC_API_INTEG_ALG_SHA1_96),
                  'scapy-crypto': "NULL",
                  'scapy-integ': "HMAC-SHA1-96",
                  'salt': 0,
                  'key': b"JPjyOWBeVEQiMe7h00112233"},
            'AES-CTR-128/SHA1-96': {
                  'vpp-crypto': (VppEnum.vl_api_ipsec_crypto_alg_t.
                                 IPSEC_API_CRYPTO_ALG_AES_CTR_128),
                  'vpp-integ': (VppEnum.vl_api_ipsec_integ_alg_t.
                                IPSEC_API_INTEG_ALG_SHA1_96),
                  'scapy-crypto': "AES-CTR",
                  'scapy-integ': "HMAC-SHA1-96",
                  'salt': 0,
                  'key': b"JPjyOWBeVEQiMe7h"},
            'AES-CTR-192/SHA1-96': {
                  'vpp-crypto': (VppEnum.vl_api_ipsec_crypto_alg_t.
                                 IPSEC_API_CRYPTO_ALG_AES_CTR_192),
                  'vpp-integ': (VppEnum.vl_api_ipsec_integ_alg_t.
                                IPSEC_API_INTEG_ALG_SHA1_96),
                  'scapy-crypto': "AES-CTR",
                  'scapy-integ': "HMAC-SHA1-96",
                  'salt': 1010,
                  'key': b"JPjyOWBeVEQiMe7hJPjyOWBe"},
            'AES-CTR-256/SHA1-96': {
                  'vpp-crypto': (VppEnum.vl_api_ipsec_crypto_alg_t.
                                 IPSEC_API_CRYPTO_ALG_AES_CTR_256),
                  'vpp-integ': (VppEnum.vl_api_ipsec_integ_alg_t.
                                IPSEC_API_INTEG_ALG_SHA1_96),
                  'scapy-crypto': "AES-CTR",
                  'scapy-integ': "HMAC-SHA1-96",
                  'salt': 2020,
                  'key': b"JPjyOWBeVEQiMe7hJPjyOWBeVEQiMe7h"}}


class RunTestIpsecEspAll(ConfigIpsecESP,
                         IpsecTra4, IpsecTra6,
                         IpsecTun4, IpsecTun6):
    """ Ipsec ESP all Algos """

    @classmethod
    def setUpConstants(cls):
        test_args = str.split(cls.__doc__, " ")
        engine = test_args[0]
        if engine == "async":
            cls.worker_config = "workers 2"
        super(RunTestIpsecEspAll, cls).setUpConstants()

    def setUp(self):
        super(RunTestIpsecEspAll, self).setUp()
        test_args = str.split(self.__doc__, " ")

        params = MyParameters()
        self.engine = test_args[0]
        self.flag = params.flags[0]
        if test_args[1] == 'ESN':
            self.flag = params.flags[1]

        self.algo = params.algos[test_args[2]]
        self.async_mode = False
        if self.engine == "async":
            self.async_mode = True

    def tearDown(self):
        super(RunTestIpsecEspAll, self).tearDown()

    def run_test(self):
        self.run_a_test(self.engine, self.flag, self.algo)

    def run_a_test(self, engine, flag, algo, payload_size=None):
        if self.async_mode:
            self.vapi.cli("set ipsec async mode on")
        else:
            self.vapi.cli("set crypto handler all %s" % engine)

        self.logger.info(self.vapi.cli("show crypto async status"))
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
            p.outer_flow_label = 243224
            p.async_mode = self.async_mode

        self.reporter.send_keep_alive(self)

        #
        # configure the SPDs. SAs, etc
        #
        self.config_network(self.params.values())

        #
        # run some traffic.
        #  An exhautsive 4o6, 6o4 is not necessary
        #  for each algo
        #
        self.verify_tra_basic6(count=NUM_PKTS)
        self.verify_tra_basic4(count=NUM_PKTS)
        self.verify_tun_66(self.params[socket.AF_INET6],
                           count=NUM_PKTS)
        #
        # Use an odd-byte payload size to check for correct padding.
        #
        # 49 + 2 == 51 which should pad +1 to 52 for 4 byte alignment, +5
        # to 56 for 8 byte alignment, and +13 to 64 for 64 byte alignment.
        # This should catch bugs where the code is incorrectly over-padding
        # for algorithms that don't require it
        psz = 49 - len(IP()/ICMP()) if payload_size is None else payload_size
        self.verify_tun_44(self.params[socket.AF_INET],
                           count=NUM_PKTS, payload_size=psz)

        LARGE_PKT_SZ = [
            1970,  # results in 2 chained buffers entering decrypt node
                   # but leaving as simple buffer due to ICV removal (tra4)
            2004,  # footer+ICV will be added to 2nd buffer (tun4)
            4010,  # ICV ends up splitted accross 2 buffers in esp_decrypt
                   # for transport4; transport6 takes normal path
            4020,  # same as above but tra4 and tra6 are switched
        ]
        if self.engine in engines_supporting_chain_bufs:
            for sz in LARGE_PKT_SZ:
                self.verify_tra_basic4(count=NUM_PKTS, payload_size=sz)
                self.verify_tra_basic6(count=NUM_PKTS, payload_size=sz)
                self.verify_tun_66(self.params[socket.AF_INET6],
                                   count=NUM_PKTS, payload_size=sz)
                self.verify_tun_44(self.params[socket.AF_INET],
                                   count=NUM_PKTS, payload_size=sz)

        #
        # swap the handlers while SAs are up
        #
        for e in engines:
            if e != engine:
                self.vapi.cli("set crypto handler all %s" % e)
                self.verify_tra_basic4(count=NUM_PKTS)

        #
        # remove the SPDs, SAs, etc
        #
        self.unconfig_network()

        #
        # reconfigure the network and SA to run the
        # anti replay tests
        #
        self.config_network(self.params.values())
        self.verify_tra_anti_replay()
        self.unconfig_network()

#
# To generate test classes, do:
#   grep '# GEN' test_ipsec_esp.py | sed -e 's/# GEN //g' | bash
#
# GEN for ENG in native ipsecmb openssl; do \
# GEN   for FLG in noESN ESN; do for ALG in AES-GCM-128/NONE \
# GEN     AES-GCM-192/NONE AES-GCM-256/NONE AES-CBC-128/MD5-96 \
# GEN     AES-CBC-192/SHA1-96 AES-CBC-256/SHA1-96 \
# GEN     3DES-CBC/SHA1-96 NONE/SHA1-96 \
# GEN     AES-CTR-128/SHA1-96 AES-CTR-192/SHA1-96 AES-CTR-256/SHA1-96; do \
# GEN      [[ ${FLG} == "ESN" &&  ${ALG} == *"NONE" ]] && continue
# GEN      echo -e "\n\nclass Test_${ENG}_${FLG}_${ALG}(RunTestIpsecEspAll):" |
# GEN             sed -e 's/-/_/g' -e 's#/#_#g' ; \
# GEN      echo '    """'$ENG $FLG $ALG IPSec test'"""' ;
# GEN      echo "    def test_ipsec(self):";
# GEN      echo "        self.run_test()";
# GEN done; done; done
#
# GEN   for FLG in noESN ESN; do for ALG in \
# GEN     AES-GCM-128/NONE AES-GCM-192/NONE AES-GCM-256/NONE \
# GEN     AES-CBC-192/SHA1-96 AES-CBC-256/SHA1-96; do \
# GEN      [[ ${FLG} == "ESN" &&  ${ALG} == *"NONE" ]] && continue
# GEN      echo -e "\n\nclass Test_async_${FLG}_${ALG}(RunTestIpsecEspAll):" |
# GEN             sed -e 's/-/_/g' -e 's#/#_#g' ; \
# GEN      echo '    """'async $FLG $ALG IPSec test'"""' ;
# GEN      echo "    def test_ipsec(self):";
# GEN      echo "        self.run_test()";
# GEN done; done;


class Test_native_noESN_AES_GCM_128_NONE(RunTestIpsecEspAll):
    """native noESN AES-GCM-128/NONE IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_native_noESN_AES_GCM_192_NONE(RunTestIpsecEspAll):
    """native noESN AES-GCM-192/NONE IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_native_noESN_AES_GCM_256_NONE(RunTestIpsecEspAll):
    """native noESN AES-GCM-256/NONE IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_native_noESN_AES_CBC_128_MD5_96(RunTestIpsecEspAll):
    """native noESN AES-CBC-128/MD5-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_native_noESN_AES_CBC_192_SHA1_96(RunTestIpsecEspAll):
    """native noESN AES-CBC-192/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_native_noESN_AES_CBC_256_SHA1_96(RunTestIpsecEspAll):
    """native noESN AES-CBC-256/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_native_noESN_3DES_CBC_SHA1_96(RunTestIpsecEspAll):
    """native noESN 3DES-CBC/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_native_noESN_NONE_SHA1_96(RunTestIpsecEspAll):
    """native noESN NONE/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_native_noESN_AES_CTR_128_SHA1_96(RunTestIpsecEspAll):
    """native noESN AES-CTR-128/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_native_noESN_AES_CTR_192_SHA1_96(RunTestIpsecEspAll):
    """native noESN AES-CTR-192/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_native_noESN_AES_CTR_256_SHA1_96(RunTestIpsecEspAll):
    """native noESN AES-CTR-256/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_native_ESN_AES_CBC_128_MD5_96(RunTestIpsecEspAll):
    """native ESN AES-CBC-128/MD5-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_native_ESN_AES_CBC_192_SHA1_96(RunTestIpsecEspAll):
    """native ESN AES-CBC-192/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_native_ESN_AES_CBC_256_SHA1_96(RunTestIpsecEspAll):
    """native ESN AES-CBC-256/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_native_ESN_3DES_CBC_SHA1_96(RunTestIpsecEspAll):
    """native ESN 3DES-CBC/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_native_ESN_NONE_SHA1_96(RunTestIpsecEspAll):
    """native ESN NONE/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_native_ESN_AES_CTR_128_SHA1_96(RunTestIpsecEspAll):
    """native ESN AES-CTR-128/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_native_ESN_AES_CTR_192_SHA1_96(RunTestIpsecEspAll):
    """native ESN AES-CTR-192/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_native_ESN_AES_CTR_256_SHA1_96(RunTestIpsecEspAll):
    """native ESN AES-CTR-256/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_ipsecmb_noESN_AES_GCM_128_NONE(RunTestIpsecEspAll):
    """ipsecmb noESN AES-GCM-128/NONE IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_ipsecmb_noESN_AES_GCM_192_NONE(RunTestIpsecEspAll):
    """ipsecmb noESN AES-GCM-192/NONE IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_ipsecmb_noESN_AES_GCM_256_NONE(RunTestIpsecEspAll):
    """ipsecmb noESN AES-GCM-256/NONE IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_ipsecmb_noESN_AES_CBC_128_MD5_96(RunTestIpsecEspAll):
    """ipsecmb noESN AES-CBC-128/MD5-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_ipsecmb_noESN_AES_CBC_192_SHA1_96(RunTestIpsecEspAll):
    """ipsecmb noESN AES-CBC-192/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_ipsecmb_noESN_AES_CBC_256_SHA1_96(RunTestIpsecEspAll):
    """ipsecmb noESN AES-CBC-256/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_ipsecmb_noESN_3DES_CBC_SHA1_96(RunTestIpsecEspAll):
    """ipsecmb noESN 3DES-CBC/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_ipsecmb_noESN_NONE_SHA1_96(RunTestIpsecEspAll):
    """ipsecmb noESN NONE/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_ipsecmb_noESN_AES_CTR_128_SHA1_96(RunTestIpsecEspAll):
    """ipsecmb noESN AES-CTR-128/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_ipsecmb_noESN_AES_CTR_192_SHA1_96(RunTestIpsecEspAll):
    """ipsecmb noESN AES-CTR-192/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_ipsecmb_noESN_AES_CTR_256_SHA1_96(RunTestIpsecEspAll):
    """ipsecmb noESN AES-CTR-256/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_ipsecmb_ESN_AES_CBC_128_MD5_96(RunTestIpsecEspAll):
    """ipsecmb ESN AES-CBC-128/MD5-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_ipsecmb_ESN_AES_CBC_192_SHA1_96(RunTestIpsecEspAll):
    """ipsecmb ESN AES-CBC-192/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_ipsecmb_ESN_AES_CBC_256_SHA1_96(RunTestIpsecEspAll):
    """ipsecmb ESN AES-CBC-256/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_ipsecmb_ESN_3DES_CBC_SHA1_96(RunTestIpsecEspAll):
    """ipsecmb ESN 3DES-CBC/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_ipsecmb_ESN_NONE_SHA1_96(RunTestIpsecEspAll):
    """ipsecmb ESN NONE/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_ipsecmb_ESN_AES_CTR_128_SHA1_96(RunTestIpsecEspAll):
    """ipsecmb ESN AES-CTR-128/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_ipsecmb_ESN_AES_CTR_192_SHA1_96(RunTestIpsecEspAll):
    """ipsecmb ESN AES-CTR-192/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_ipsecmb_ESN_AES_CTR_256_SHA1_96(RunTestIpsecEspAll):
    """ipsecmb ESN AES-CTR-256/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_openssl_noESN_AES_GCM_128_NONE(RunTestIpsecEspAll):
    """openssl noESN AES-GCM-128/NONE IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_openssl_noESN_AES_GCM_192_NONE(RunTestIpsecEspAll):
    """openssl noESN AES-GCM-192/NONE IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_openssl_noESN_AES_GCM_256_NONE(RunTestIpsecEspAll):
    """openssl noESN AES-GCM-256/NONE IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_openssl_noESN_AES_CBC_128_MD5_96(RunTestIpsecEspAll):
    """openssl noESN AES-CBC-128/MD5-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_openssl_noESN_AES_CBC_192_SHA1_96(RunTestIpsecEspAll):
    """openssl noESN AES-CBC-192/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_openssl_noESN_AES_CBC_256_SHA1_96(RunTestIpsecEspAll):
    """openssl noESN AES-CBC-256/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_openssl_noESN_3DES_CBC_SHA1_96(RunTestIpsecEspAll):
    """openssl noESN 3DES-CBC/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_openssl_noESN_NONE_SHA1_96(RunTestIpsecEspAll):
    """openssl noESN NONE/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_openssl_noESN_AES_CTR_128_SHA1_96(RunTestIpsecEspAll):
    """openssl noESN AES-CTR-128/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_openssl_noESN_AES_CTR_192_SHA1_96(RunTestIpsecEspAll):
    """openssl noESN AES-CTR-192/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_openssl_noESN_AES_CTR_256_SHA1_96(RunTestIpsecEspAll):
    """openssl noESN AES-CTR-256/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_openssl_ESN_AES_CBC_128_MD5_96(RunTestIpsecEspAll):
    """openssl ESN AES-CBC-128/MD5-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_openssl_ESN_AES_CBC_192_SHA1_96(RunTestIpsecEspAll):
    """openssl ESN AES-CBC-192/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_openssl_ESN_AES_CBC_256_SHA1_96(RunTestIpsecEspAll):
    """openssl ESN AES-CBC-256/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_openssl_ESN_3DES_CBC_SHA1_96(RunTestIpsecEspAll):
    """openssl ESN 3DES-CBC/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_openssl_ESN_NONE_SHA1_96(RunTestIpsecEspAll):
    """openssl ESN NONE/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_openssl_ESN_AES_CTR_128_SHA1_96(RunTestIpsecEspAll):
    """openssl ESN AES-CTR-128/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_openssl_ESN_AES_CTR_192_SHA1_96(RunTestIpsecEspAll):
    """openssl ESN AES-CTR-192/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_openssl_ESN_AES_CTR_256_SHA1_96(RunTestIpsecEspAll):
    """openssl ESN AES-CTR-256/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_async_noESN_AES_GCM_128_NONE(RunTestIpsecEspAll):
    """async noESN AES-GCM-128/NONE IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_async_noESN_AES_GCM_192_NONE(RunTestIpsecEspAll):
    """async noESN AES-GCM-192/NONE IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_async_noESN_AES_GCM_256_NONE(RunTestIpsecEspAll):
    """async noESN AES-GCM-256/NONE IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_async_noESN_AES_CBC_192_SHA1_96(RunTestIpsecEspAll):
    """async noESN AES-CBC-192/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_async_noESN_AES_CBC_256_SHA1_96(RunTestIpsecEspAll):
    """async noESN AES-CBC-256/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_async_ESN_AES_CBC_192_SHA1_96(RunTestIpsecEspAll):
    """async ESN AES-CBC-192/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()


class Test_async_ESN_AES_CBC_256_SHA1_96(RunTestIpsecEspAll):
    """async ESN AES-CBC-256/SHA1-96 IPSec test"""
    def test_ipsec(self):
        self.run_test()
