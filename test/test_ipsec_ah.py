import socket
import unittest

from scapy.layers.ipsec import AH

from framework import VppTestRunner
from template_ipsec import TemplateIpsec, IpsecTraTests, IpsecTunTests
from template_ipsec import IpsecTcpTests


class TemplateIpsecAh(TemplateIpsec):
    """
    Basic test for IPSEC using AH transport and Tunnel mode

    Below 4 cases are covered as part of this test
    1) ipsec ah v4 transport basic test  - IPv4 Transport mode
     scenario using HMAC-SHA1-96 intergrity algo
    2) ipsec ah v4 transport burst test
     Above test for 257 pkts
    3) ipsec ah 4o4 tunnel basic test    - IPv4 Tunnel mode
     scenario using HMAC-SHA1-96 intergrity algo
    4) ipsec ah 4o4 tunnel burst test
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

    Note : IPv6 is not covered
    """

    encryption_type = AH

    @classmethod
    def setUpClass(cls):
        super(TemplateIpsecAh, cls).setUpClass()
        cls.tun_if = cls.pg0
        cls.tra_if = cls.pg2
        cls.logger.info(cls.vapi.ppcli("show int addr"))
        cls.config_ah_tra()
        cls.logger.info(cls.vapi.ppcli("show ipsec"))
        cls.config_ah_tun()
        cls.logger.info(cls.vapi.ppcli("show ipsec"))
        src4 = socket.inet_pton(socket.AF_INET, cls.remote_tun_if_host)
        cls.vapi.ip_add_del_route(src4, 32, cls.tun_if.remote_ip4n)

    @classmethod
    def config_ah_tun(cls):
        cls.vapi.ipsec_sad_add_del_entry(cls.scapy_tun_sa_id,
                                         cls.scapy_tun_spi,
                                         cls.auth_algo_vpp_id, cls.auth_key,
                                         cls.crypt_algo_vpp_id,
                                         cls.crypt_key, cls.vpp_ah_protocol,
                                         cls.tun_if.local_ip4n,
                                         cls.tun_if.remote_ip4n)
        cls.vapi.ipsec_sad_add_del_entry(cls.vpp_tun_sa_id,
                                         cls.vpp_tun_spi,
                                         cls.auth_algo_vpp_id, cls.auth_key,
                                         cls.crypt_algo_vpp_id,
                                         cls.crypt_key, cls.vpp_ah_protocol,
                                         cls.tun_if.remote_ip4n,
                                         cls.tun_if.local_ip4n)
        cls.vapi.ipsec_spd_add_del(cls.tun_spd_id)
        cls.vapi.ipsec_interface_add_del_spd(cls.tun_spd_id,
                                             cls.tun_if.sw_if_index)
        l_startaddr = r_startaddr = socket.inet_pton(socket.AF_INET, "0.0.0.0")
        l_stopaddr = r_stopaddr = socket.inet_pton(socket.AF_INET,
                                                   "255.255.255.255")
        cls.vapi.ipsec_spd_add_del_entry(cls.tun_spd_id, cls.vpp_tun_sa_id,
                                         l_startaddr, l_stopaddr, r_startaddr,
                                         r_stopaddr,
                                         protocol=socket.IPPROTO_AH)
        cls.vapi.ipsec_spd_add_del_entry(cls.tun_spd_id, cls.vpp_tun_sa_id,
                                         l_startaddr, l_stopaddr, r_startaddr,
                                         r_stopaddr, is_outbound=0,
                                         protocol=socket.IPPROTO_AH)
        l_startaddr = l_stopaddr = socket.inet_pton(socket.AF_INET,
                                                    cls.remote_tun_if_host)
        r_startaddr = r_stopaddr = cls.pg1.remote_ip4n
        cls.vapi.ipsec_spd_add_del_entry(cls.tun_spd_id, cls.vpp_tun_sa_id,
                                         l_startaddr, l_stopaddr, r_startaddr,
                                         r_stopaddr, priority=10, policy=3,
                                         is_outbound=0)
        cls.vapi.ipsec_spd_add_del_entry(cls.tun_spd_id, cls.scapy_tun_sa_id,
                                         r_startaddr, r_stopaddr, l_startaddr,
                                         l_stopaddr, priority=10, policy=3)
        r_startaddr = r_stopaddr = cls.pg0.local_ip4n
        cls.vapi.ipsec_spd_add_del_entry(cls.tun_spd_id, cls.vpp_tun_sa_id,
                                         l_startaddr, l_stopaddr, r_startaddr,
                                         r_stopaddr, priority=20, policy=3,
                                         is_outbound=0)
        cls.vapi.ipsec_spd_add_del_entry(cls.tun_spd_id, cls.scapy_tun_sa_id,
                                         r_startaddr, r_stopaddr, l_startaddr,
                                         l_stopaddr, priority=20, policy=3)

    @classmethod
    def config_ah_tra(cls):
        cls.vapi.ipsec_sad_add_del_entry(cls.scapy_tra_sa_id,
                                         cls.scapy_tra_spi,
                                         cls.auth_algo_vpp_id, cls.auth_key,
                                         cls.crypt_algo_vpp_id,
                                         cls.crypt_key, cls.vpp_ah_protocol,
                                         is_tunnel=0)
        cls.vapi.ipsec_sad_add_del_entry(cls.vpp_tra_sa_id,
                                         cls.vpp_tra_spi,
                                         cls.auth_algo_vpp_id, cls.auth_key,
                                         cls.crypt_algo_vpp_id,
                                         cls.crypt_key, cls.vpp_ah_protocol,
                                         is_tunnel=0)
        cls.vapi.ipsec_spd_add_del(cls.tra_spd_id)
        cls.vapi.ipsec_interface_add_del_spd(cls.tra_spd_id,
                                             cls.tra_if.sw_if_index)
        l_startaddr = r_startaddr = socket.inet_pton(socket.AF_INET, "0.0.0.0")
        l_stopaddr = r_stopaddr = socket.inet_pton(socket.AF_INET,
                                                   "255.255.255.255")
        cls.vapi.ipsec_spd_add_del_entry(cls.tra_spd_id, cls.vpp_tra_sa_id,
                                         l_startaddr, l_stopaddr, r_startaddr,
                                         r_stopaddr,
                                         protocol=socket.IPPROTO_AH)
        cls.vapi.ipsec_spd_add_del_entry(cls.tra_spd_id, cls.scapy_tra_sa_id,
                                         l_startaddr, l_stopaddr, r_startaddr,
                                         r_stopaddr, is_outbound=0,
                                         protocol=socket.IPPROTO_AH)
        l_startaddr = l_stopaddr = cls.tra_if.local_ip4n
        r_startaddr = r_stopaddr = cls.tra_if.remote_ip4n
        cls.vapi.ipsec_spd_add_del_entry(cls.tra_spd_id, cls.vpp_tra_sa_id,
                                         l_startaddr, l_stopaddr, r_startaddr,
                                         r_stopaddr, priority=10, policy=3,
                                         is_outbound=0)
        cls.vapi.ipsec_spd_add_del_entry(cls.tra_spd_id, cls.scapy_tra_sa_id,
                                         l_startaddr, l_stopaddr, r_startaddr,
                                         r_stopaddr, priority=10,
                                         policy=3)

    def tearDown(self):
        super(TemplateIpsecAh, self).tearDown()
        if not self.vpp_dead:
            self.vapi.cli("show hardware")


class TestIpsecAh1(TemplateIpsecAh, IpsecTraTests, IpsecTunTests):
    """ Ipsec AH - TUN & TRA tests """
    pass


class TestIpsecAh2(TemplateIpsecAh, IpsecTcpTests):
    """ Ipsec AH - TCP tests """
    pass


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
