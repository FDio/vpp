import socket

from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether
from scapy.layers.ipsec import *

from framework import VppTestCase
from vpp_ip_route import VppIpRoute

from util import ppp


class TestIpsecAh(VppTestCase):
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
    |pg0| ------->  |VPP| ------> |pg1|
     ---             ---           ---

     ---   decrypt   ---   plain   ---
    |pg0| <-------  |VPP| <------ |pg1|
     ---             ---           ---

    Note : IPv6 is not covered
    """

    remote_pg0_lb_addr = '1.1.1.1'
    remote_pg1_lb_addr = '2.2.2.2'

    @classmethod
    def setUpClass(cls):
        super(TestIpsecAh, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(3))
            cls.interfaces = list(cls.pg_interfaces)
            for i in cls.interfaces:
                i.admin_up()
                i.config_ip4()
                i.resolve_arp()
            cls.logger.info(cls.vapi.ppcli("show int addr"))
            cls.configAhTra()
            cls.logger.info(cls.vapi.ppcli("show ipsec"))
            cls.configAhTun()
            cls.logger.info(cls.vapi.ppcli("show ipsec"))
        except Exception:
            super(TestIpsecAh, cls).tearDownClass()
            raise

    @classmethod
    def configAhTun(cls):
        try:
            spd_id = 1
            remote_sa_id = 10
            local_sa_id = 20
            remote_tun_spi = 1001
            local_tun_spi = 1000
            src4 = socket.inet_pton(socket.AF_INET, cls.remote_pg0_lb_addr)
            cls.vapi.ip_add_del_route(src4, 32, cls.pg0.remote_ip4n)
            dst4 = socket.inet_pton(socket.AF_INET, cls.remote_pg1_lb_addr)
            cls.vapi.ip_add_del_route(dst4, 32, cls.pg1.remote_ip4n)
            cls.vapi.ipsec_sad_add_del_entry(
                remote_sa_id,
                remote_tun_spi,
                cls.pg0.local_ip4n,
                cls.pg0.remote_ip4n,
                integrity_key_length=20)
            cls.vapi.ipsec_sad_add_del_entry(
                local_sa_id,
                local_tun_spi,
                cls.pg0.remote_ip4n,
                cls.pg0.local_ip4n,
                integrity_key_length=20)
            cls.vapi.ipsec_spd_add_del(spd_id)
            cls.vapi.ipsec_interface_add_del_spd(spd_id, cls.pg0.sw_if_index)
            l_startaddr = r_startaddr = socket.inet_pton(
                socket.AF_INET, "0.0.0.0")
            l_stopaddr = r_stopaddr = socket.inet_pton(
                socket.AF_INET, "255.255.255.255")
            cls.vapi.ipsec_spd_add_del_entry(
                spd_id,
                l_startaddr,
                l_stopaddr,
                r_startaddr,
                r_stopaddr,
                protocol=51)
            cls.vapi.ipsec_spd_add_del_entry(
                spd_id,
                l_startaddr,
                l_stopaddr,
                r_startaddr,
                r_stopaddr,
                protocol=51,
                is_outbound=0)
            l_startaddr = l_stopaddr = socket.inet_pton(
                socket.AF_INET, cls.remote_pg0_lb_addr)
            r_startaddr = r_stopaddr = socket.inet_pton(
                socket.AF_INET, cls.remote_pg1_lb_addr)
            cls.vapi.ipsec_spd_add_del_entry(
                spd_id,
                l_startaddr,
                l_stopaddr,
                r_startaddr,
                r_stopaddr,
                priority=10,
                policy=3,
                is_outbound=0,
                sa_id=local_sa_id)
            cls.vapi.ipsec_spd_add_del_entry(
                spd_id,
                r_startaddr,
                r_stopaddr,
                l_startaddr,
                l_stopaddr,
                priority=10,
                policy=3,
                sa_id=remote_sa_id)
        except Exception:
            raise

    @classmethod
    def configAhTra(cls):
        try:
            spd_id = 2
            remote_sa_id = 30
            local_sa_id = 40
            remote_tra_spi = 2001
            local_tra_spi = 2000
            cls.vapi.ipsec_sad_add_del_entry(
                remote_sa_id,
                remote_tra_spi,
                integrity_key_length=20,
                is_tunnel=0)
            cls.vapi.ipsec_sad_add_del_entry(
                local_sa_id,
                local_tra_spi,
                integrity_key_length=20,
                is_tunnel=0)
            cls.vapi.ipsec_spd_add_del(spd_id)
            cls.vapi.ipsec_interface_add_del_spd(spd_id, cls.pg2.sw_if_index)
            l_startaddr = r_startaddr = socket.inet_pton(
                socket.AF_INET, "0.0.0.0")
            l_stopaddr = r_stopaddr = socket.inet_pton(
                socket.AF_INET, "255.255.255.255")
            cls.vapi.ipsec_spd_add_del_entry(
                spd_id,
                l_startaddr,
                l_stopaddr,
                r_startaddr,
                r_stopaddr,
                protocol=51)
            cls.vapi.ipsec_spd_add_del_entry(
                spd_id,
                l_startaddr,
                l_stopaddr,
                r_startaddr,
                r_stopaddr,
                protocol=51,
                is_outbound=0)
            l_startaddr = l_stopaddr = cls.pg2.local_ip4n
            r_startaddr = r_stopaddr = cls.pg2.remote_ip4n
            cls.vapi.ipsec_spd_add_del_entry(
                spd_id,
                l_startaddr,
                l_stopaddr,
                r_startaddr,
                r_stopaddr,
                priority=10,
                policy=3,
                is_outbound=0,
                sa_id=local_sa_id)
            cls.vapi.ipsec_spd_add_del_entry(
                spd_id,
                l_startaddr,
                l_stopaddr,
                r_startaddr,
                r_stopaddr,
                priority=10,
                policy=3,
                sa_id=remote_sa_id)
        except Exception:
            raise

    def configScapySA(self, is_tun=False):
        if is_tun:
            self.remote_tun_sa = SecurityAssociation(
                AH,
                spi=0x000003e8,
                auth_algo='HMAC-SHA1-96',
                auth_key='C91KUR9GYMm5GfkEvNjX',
                tunnel_header=IP(
                    src=self.pg0.remote_ip4,
                    dst=self.pg0.local_ip4))
            self.local_tun_sa = SecurityAssociation(
                AH,
                spi=0x000003e9,
                auth_algo='HMAC-SHA1-96',
                auth_key='C91KUR9GYMm5GfkEvNjX',
                tunnel_header=IP(
                    dst=self.pg0.remote_ip4,
                    src=self.pg0.local_ip4))
        else:
            self.remote_tra_sa = SecurityAssociation(
                AH, spi=0x000007d0, auth_algo='HMAC-SHA1-96',
                auth_key='C91KUR9GYMm5GfkEvNjX')
            self.local_tra_sa = SecurityAssociation(
                AH, spi=0x000007d1, auth_algo='HMAC-SHA1-96',
                auth_key='C91KUR9GYMm5GfkEvNjX')

    def tearDown(self):
        super(TestIpsecAh, self).tearDown()
        if not self.vpp_dead:
            self.vapi.cli("show hardware")

    def send_and_expect(self, input, pkts, output, count=1):
        input.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = output.get_capture(count)
        return rx

    def gen_encrypt_pkts(self, sa, sw_intf, src, dst, count=1):
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                sa.encrypt(IP(src=src, dst=dst) / ICMP() /
                "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
                ] * count

    def gen_pkts(self, sw_intf, src, dst, count=1):
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                IP(src=src, dst=dst) / ICMP() /
                "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
                ] * count

    def test_ipsec_ah_tra_basic(self, count=1):
        """ ipsec ah v4 transport basic test """
        try:
            self.configScapySA()
            send_pkts = self.gen_encrypt_pkts(
                self.remote_tra_sa,
                self.pg2,
                src=self.pg2.remote_ip4,
                dst=self.pg2.local_ip4,
                count=count)
            recv_pkts = self.send_and_expect(
                self.pg2, send_pkts, self.pg2, count=count)
            # ESP TRA VPP encryption/decryption verification
            for Pkts in recv_pkts:
                Pkts[AH].padding = Pkts[AH].icv[12:]
                Pkts[AH].icv = Pkts[AH].icv[:12]
                decrypt_pkt = self.local_tra_sa.decrypt(Pkts[IP])
        finally:
            self.logger.info(self.vapi.ppcli("show error"))
            self.logger.info(self.vapi.ppcli("show ipsec"))

    def test_ipsec_ah_tra_burst(self):
        """ ipsec ah v4 transport burst test """
        try:
            self.test_ipsec_ah_tra_basic(count=257)
        finally:
            self.logger.info(self.vapi.ppcli("show error"))
            self.logger.info(self.vapi.ppcli("show ipsec"))

    def test_ipsec_ah_tun_basic(self, count=1):
        """ ipsec ah 4o4 tunnel basic test """
        try:
            self.configScapySA(is_tun=True)
            send_pkts = self.gen_encrypt_pkts(
                self.remote_tun_sa,
                self.pg0,
                src=self.remote_pg0_lb_addr,
                dst=self.remote_pg1_lb_addr,
                count=count)
            recv_pkts = self.send_and_expect(
                self.pg0, send_pkts, self.pg1, count=count)
            # ESP TUN VPP decryption verification
            for recv_pkt in recv_pkts:
                self.assert_equal(recv_pkt[IP].src, self.remote_pg0_lb_addr)
                self.assert_equal(recv_pkt[IP].dst, self.remote_pg1_lb_addr)
            send_pkts = self.gen_pkts(
                self.pg1,
                src=self.remote_pg1_lb_addr,
                dst=self.remote_pg0_lb_addr,
                count=count)
            recv_pkts = self.send_and_expect(
                self.pg1, send_pkts, self.pg0, count=count)
            # ESP TUN VPP encryption verification
            for recv_pkt in recv_pkts:
                recv_pkt[IP] = recv_pkt[IP] / IP(recv_pkt[AH].icv[12:])
                recv_pkt[AH].icv = recv_pkt[AH].icv[:12]
                decrypt_pkt = self.local_tun_sa.decrypt(recv_pkt[IP])
                self.assert_equal(decrypt_pkt.src, self.remote_pg1_lb_addr)
                self.assert_equal(decrypt_pkt.dst, self.remote_pg0_lb_addr)
        finally:
            self.logger.info(self.vapi.ppcli("show error"))
            self.logger.info(self.vapi.ppcli("show ipsec"))

    def test_ipsec_ah_tun_burst(self):
        """ ipsec ah 4o4 tunnel burst test """
        try:
            self.test_ipsec_ah_tun_basic(count=257)
        finally:
            self.logger.info(self.vapi.ppcli("show error"))
            self.logger.info(self.vapi.ppcli("show ipsec"))


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
