import unittest
import socket

from scapy.layers.inet import IP, ICMP, TCP
from scapy.layers.ipsec import SecurityAssociation
from scapy.layers.l2 import Ether, Raw
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest

from framework import VppTestCase, VppTestRunner
from util import ppp


class IPsecIPv4Params(object):
    addr_type = socket.AF_INET
    addr_any = "0.0.0.0"
    addr_bcast = "255.255.255.255"
    addr_len = 32
    is_ipv6 = 0
    remote_tun_if_host = '1.1.1.1'

    scapy_tun_sa_id = 10
    scapy_tun_spi = 1001
    vpp_tun_sa_id = 20
    vpp_tun_spi = 1000

    scapy_tra_sa_id = 30
    scapy_tra_spi = 2001
    vpp_tra_sa_id = 40
    vpp_tra_spi = 2000

    auth_algo_vpp_id = 2  # internal VPP enum value for SHA1_96
    auth_algo = 'HMAC-SHA1-96'  # scapy name
    auth_key = 'C91KUR9GYMm5GfkEvNjX'

    crypt_algo_vpp_id = 1  # internal VPP enum value for AES_CBC_128
    crypt_algo = 'AES-CBC'  # scapy name
    crypt_key = 'JPjyOWBeVEQiMe7h'


class IPsecIPv6Params(object):
    addr_type = socket.AF_INET6
    addr_any = "0::0"
    addr_bcast = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
    addr_len = 128
    is_ipv6 = 1
    remote_tun_if_host = '1111:1111:1111:1111:1111:1111:1111:1111'

    scapy_tun_sa_id = 50
    scapy_tun_spi = 3001
    vpp_tun_sa_id = 60
    vpp_tun_spi = 3000

    scapy_tra_sa_id = 70
    scapy_tra_spi = 4001
    vpp_tra_sa_id = 80
    vpp_tra_spi = 4000

    auth_algo_vpp_id = 4  # internal VPP enum value for SHA_256_128
    auth_algo = 'SHA2-256-128'  # scapy name
    auth_key = 'C91KUR9GYMm5GfkEvNjX'

    crypt_algo_vpp_id = 3  # internal VPP enum value for AES_CBC_256
    crypt_algo = 'AES-CBC'  # scapy name
    crypt_key = 'JPjyOWBeVEQiMe7hJPjyOWBeVEQiMe7h'


class TemplateIpsec(VppTestCase):
    """
    TRANSPORT MODE:

     ------   encrypt   ---
    |tra_if| <-------> |VPP|
     ------   decrypt   ---

    TUNNEL MODE:

     ------   encrypt   ---   plain   ---
    |tun_if| <-------  |VPP| <------ |pg1|
     ------             ---           ---

     ------   decrypt   ---   plain   ---
    |tun_if| ------->  |VPP| ------> |pg1|
     ------             ---           ---
    """
    ipv4_params = IPsecIPv4Params()
    ipv6_params = IPsecIPv6Params()
    params = {ipv4_params.addr_type: ipv4_params,
              ipv6_params.addr_type: ipv6_params}

    payload = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

    tun_spd_id = 1
    tra_spd_id = 2

    vpp_esp_protocol = 1
    vpp_ah_protocol = 0

    @classmethod
    def ipsec_select_backend(cls):
        """ empty method to be overloaded when necessary """
        pass

    @classmethod
    def setUpClass(cls):
        super(TemplateIpsec, cls).setUpClass()
        cls.create_pg_interfaces(range(3))
        cls.interfaces = list(cls.pg_interfaces)
        for i in cls.interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()
            i.config_ip6()
            i.resolve_ndp()
        cls.ipsec_select_backend()

    def tearDown(self):
        super(TemplateIpsec, self).tearDown()
        if not self.vpp_dead:
            self.vapi.cli("show hardware")

    def gen_encrypt_pkts(self, sa, sw_intf, src, dst, count=1, payload=None):
        if payload is None:
            payload = self.payload
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                sa.encrypt(IP(src=src, dst=dst) / ICMP() / payload)
                for i in range(count)]

    def gen_encrypt_pkts6(self, sa, sw_intf, src, dst, count=1, payload=None):
        if payload is None:
            payload = self.payload
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                sa.encrypt(IPv6(src=src, dst=dst) /
                           ICMPv6EchoRequest(id=0, seq=1, data=payload))
                for i in range(count)]

    def gen_pkts(self, sw_intf, src, dst, count=1, payload=None):
        if payload is None:
            payload = self.payload
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                IP(src=src, dst=dst) / ICMP() / payload
                for i in range(count)]

    def gen_pkts6(self, sw_intf, src, dst, count=1, payload=None):
        if payload is None:
            payload = self.payload
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                IPv6(src=src, dst=dst) /
                ICMPv6EchoRequest(id=0, seq=1, data=payload)
                for i in range(count)]

    def configure_sa_tun(self, params):
        ip_class_by_addr_type = {socket.AF_INET: IP, socket.AF_INET6: IPv6}
        scapy_tun_sa = SecurityAssociation(
            self.encryption_type, spi=params.vpp_tun_spi,
            crypt_algo=params.crypt_algo, crypt_key=params.crypt_key,
            auth_algo=params.auth_algo, auth_key=params.auth_key,
            tunnel_header=ip_class_by_addr_type[params.addr_type](
                src=self.tun_if.remote_addr[params.addr_type],
                dst=self.tun_if.local_addr[params.addr_type]))
        vpp_tun_sa = SecurityAssociation(
            self.encryption_type, spi=params.scapy_tun_spi,
            crypt_algo=params.crypt_algo, crypt_key=params.crypt_key,
            auth_algo=params.auth_algo, auth_key=params.auth_key,
            tunnel_header=ip_class_by_addr_type[params.addr_type](
                dst=self.tun_if.remote_addr[params.addr_type],
                src=self.tun_if.local_addr[params.addr_type]))
        return vpp_tun_sa, scapy_tun_sa

    @classmethod
    def configure_sa_tra(cls, params):
        params.scapy_tra_sa = SecurityAssociation(cls.encryption_type,
                                                  spi=params.vpp_tra_spi,
                                                  crypt_algo=params.crypt_algo,
                                                  crypt_key=params.crypt_key,
                                                  auth_algo=params.auth_algo,
                                                  auth_key=params.auth_key)
        params.vpp_tra_sa = SecurityAssociation(cls.encryption_type,
                                                spi=params.scapy_tra_spi,
                                                crypt_algo=params.crypt_algo,
                                                crypt_key=params.crypt_key,
                                                auth_algo=params.auth_algo,
                                                auth_key=params.auth_key)


class IpsecTcpTests(object):
    def test_tcp_checksum(self):
        """ verify checksum correctness for vpp generated packets """
        self.vapi.cli("test http server")
        p = self.params[socket.AF_INET]
        vpp_tun_sa, scapy_tun_sa = self.configure_sa_tun(p)
        send = (Ether(src=self.tun_if.remote_mac, dst=self.tun_if.local_mac) /
                scapy_tun_sa.encrypt(IP(src=p.remote_tun_if_host,
                                        dst=self.tun_if.local_ip4) /
                                     TCP(flags='S', dport=80)))
        self.logger.debug(ppp("Sending packet:", send))
        recv = self.send_and_expect(self.tun_if, [send], self.tun_if)
        recv = recv[0]
        decrypted = vpp_tun_sa.decrypt(recv[IP])
        self.assert_packet_checksums_valid(decrypted)


class IpsecTraTests(object):
    def test_tra_anti_replay(self, count=1):
        """ ipsec v4 transport anti-replay test """
        p = self.params[socket.AF_INET]

        # fire in a packet with seq number 1
        pkt = (Ether(src=self.tra_if.remote_mac,
                     dst=self.tra_if.local_mac) /
               p.scapy_tra_sa.encrypt(IP(src=self.tra_if.remote_ip4,
                                         dst=self.tra_if.local_ip4) /
                                      ICMP(),
                                      seq_num=1))
        self.send_and_expect(self.tra_if, [pkt], self.tra_if)

        # now move the window over to 235
        pkt = (Ether(src=self.tra_if.remote_mac,
                     dst=self.tra_if.local_mac) /
               p.scapy_tra_sa.encrypt(IP(src=self.tra_if.remote_ip4,
                                         dst=self.tra_if.local_ip4) /
                                      ICMP(),
                                      seq_num=235))
        self.send_and_expect(self.tra_if, [pkt], self.tra_if)

        # the window size is 64 packets
        # in window are still accepted
        pkt = (Ether(src=self.tra_if.remote_mac,
                     dst=self.tra_if.local_mac) /
               p.scapy_tra_sa.encrypt(IP(src=self.tra_if.remote_ip4,
                                         dst=self.tra_if.local_ip4) /
                                      ICMP(),
                                      seq_num=172))
        self.send_and_expect(self.tra_if, [pkt], self.tra_if)

        # out of window are dropped
        pkt = (Ether(src=self.tra_if.remote_mac,
                     dst=self.tra_if.local_mac) /
               p.scapy_tra_sa.encrypt(IP(src=self.tra_if.remote_ip4,
                                         dst=self.tra_if.local_ip4) /
                                      ICMP(),
                                      seq_num=17))
        self.send_and_assert_no_replies(self.tra_if, pkt * 17)

        self.assert_packet_counter_equal(
            '/err/%s/SA replayed packet' % self.tra4_decrypt_node_name, 17)

        # a packet that does not decrypt does not move the window forward
        bogus_sa = SecurityAssociation(self.encryption_type,
                                       p.vpp_tra_spi)
        pkt = (Ether(src=self.tra_if.remote_mac,
                     dst=self.tra_if.local_mac) /
               bogus_sa.encrypt(IP(src=self.tra_if.remote_ip4,
                                   dst=self.tra_if.local_ip4) /
                                ICMP(),
                                seq_num=350))
        self.send_and_assert_no_replies(self.tra_if, pkt * 17)

        self.assert_packet_counter_equal(
            '/err/%s/Integrity check failed' % self.tra4_decrypt_node_name, 17)

        # which we can determine since this packet is still in the window
        pkt = (Ether(src=self.tra_if.remote_mac,
                     dst=self.tra_if.local_mac) /
               p.scapy_tra_sa.encrypt(IP(src=self.tra_if.remote_ip4,
                                         dst=self.tra_if.local_ip4) /
                                      ICMP(),
                                      seq_num=234))
        self.send_and_expect(self.tra_if, [pkt], self.tra_if)

        # move the security-associations seq number on to the last we used
        p.scapy_tra_sa.seq_num = 351
        p.vpp_tra_sa.seq_num = 351

    def test_tra_basic(self, count=1, payload=None):
        """ ipsec v4 transport basic test """
        self.vapi.cli("clear errors")
        try:
            p = self.params[socket.AF_INET]
            send_pkts = self.gen_encrypt_pkts(p.scapy_tra_sa, self.tra_if,
                                              src=self.tra_if.remote_ip4,
                                              dst=self.tra_if.local_ip4,
                                              count=count, payload=payload)
            recv_pkts = self.send_and_expect(self.tra_if, send_pkts,
                                             self.tra_if)
            for rx in recv_pkts:
                try:
                    decrypted = p.vpp_tra_sa.decrypt(rx[IP])
                    decrypted = decrypted.__class__(str(decrypted))
                    self.assertIn(ICMP, decrypted)
                    self.assert_packet_checksums_valid(decrypted)
                except:
                    self.logger.debug(ppp("Unexpected packet:", rx))
                    raise
        finally:
            self.logger.info(self.vapi.ppcli("show error"))
            self.logger.info(self.vapi.ppcli("show ipsec"))

        self.assert_packet_counter_equal(self.tra4_encrypt_node_name, count)
        self.assert_packet_counter_equal(self.tra4_decrypt_node_name, count)

    def test_tra_burst(self):
        """ ipsec v4 transport burst test """
        self.test_tra_basic(count=257)

    def test_tra_large_basic(self):
        """ ipsec v4 transport 8k packets basic test """
        self.test_tra_basic(payload="X"*8000)

    def test_tra_large_burst(self):
        """ ipsec v4 transport 8k packets burst test """
        self.test_tra_basic(count=257, payload="X"*8000)

    def test_tra_basic6(self, count=1, payload=None):
        """ ipsec v6 transport basic test """
        self.vapi.cli("clear errors")
        try:
            p = self.params[socket.AF_INET6]
            send_pkts = self.gen_encrypt_pkts6(p.scapy_tra_sa, self.tra_if,
                                               src=self.tra_if.remote_ip6,
                                               dst=self.tra_if.local_ip6,
                                               count=count, payload=payload)
            recv_pkts = self.send_and_expect(self.tra_if, send_pkts,
                                             self.tra_if)
            for rx in recv_pkts:
                try:
                    decrypted = p.vpp_tra_sa.decrypt(rx[IPv6])
                    self.assert_packet_checksums_valid(decrypted)
                except:
                    self.logger.debug(ppp("Unexpected packet:", rx))
                    raise
        finally:
            self.logger.info(self.vapi.ppcli("show error"))
            self.logger.info(self.vapi.ppcli("show ipsec"))

        self.assert_packet_counter_equal(self.tra6_encrypt_node_name, count)
        self.assert_packet_counter_equal(self.tra6_decrypt_node_name, count)

    def test_tra_burst6(self):
        """ ipsec v6 transport burst test """
        self.test_tra_basic6(count=257)

    def test_tra_large_basic6(self):
        """ ipsec v6 transport 8k packets basic test """
        self.test_tra_basic6(payload="X"*8000)

    def test_tra_large_burst6(self):
        """ ipsec v6 transport 8k packets burst test """
        self.test_tra_basic6(count=257, payload="X"*8000)


class IpsecTun4Tests(object):
    def test_tun_basic44(self, count=1, payload=None):
        """ ipsec 4o4 tunnel basic test """
        self.vapi.cli("clear errors")
        try:
            p = self.params[socket.AF_INET]
            vpp_tun_sa, scapy_tun_sa = self.configure_sa_tun(p)
            send_pkts = self.gen_encrypt_pkts(scapy_tun_sa, self.tun_if,
                                              src=p.remote_tun_if_host,
                                              dst=self.pg1.remote_ip4,
                                              count=count, payload=payload)
            recv_pkts = self.send_and_expect(self.tun_if, send_pkts, self.pg1)
            for recv_pkt in recv_pkts:
                self.assert_equal(recv_pkt[IP].src, p.remote_tun_if_host)
                self.assert_equal(recv_pkt[IP].dst, self.pg1.remote_ip4)
                self.assert_packet_checksums_valid(recv_pkt)
            send_pkts = self.gen_pkts(self.pg1, src=self.pg1.remote_ip4,
                                      dst=p.remote_tun_if_host, count=count,
                                      payload=payload)
            recv_pkts = self.send_and_expect(self.pg1, send_pkts, self.tun_if)
            for recv_pkt in recv_pkts:
                decrypt_pkt = None
                try:
                    # create a copy here because the decrypt method can corrupt
                    # the original packet
                    copy = recv_pkt[IP].__class__(str(recv_pkt[IP]))
                    decrypt_pkt = vpp_tun_sa.decrypt(copy)
                    if not decrypt_pkt.haslayer(IP):
                        decrypt_pkt = IP(decrypt_pkt[Raw].load)
                    self.logger.debug(ppp("After decrypt:", recv_pkt))
                    self.assert_equal(decrypt_pkt.src, self.pg1.remote_ip4)
                    self.assert_equal(decrypt_pkt.dst, p.remote_tun_if_host)
                    self.assert_packet_checksums_valid(decrypt_pkt)
                except:
                    self.logger.debug(ppp("Unexpected packet:", recv_pkt))
                    try:
                        if decrypt_pkt:
                            self.logger.debug(
                                ppp("Decrypted packet:", decrypt_pkt))
                    except:
                        pass
                    raise
        finally:
            self.logger.info(self.vapi.ppcli("show error"))
            self.logger.info(self.vapi.ppcli("show ipsec"))

        self.assert_packet_counter_equal(self.tun4_encrypt_node_name, count)
        self.assert_packet_counter_equal(self.tun4_decrypt_node_name, count)

    def test_tun_burst44(self):
        """ ipsec 4o4 tunnel burst test """
        self.test_tun_basic44(count=257)

    def test_tun_large_basic44(self):
        """ ipsec 4o4 tunnel 8K packets test """
        self.test_tun_basic44(payload="X"*8000)

    def test_tun_large_burst44(self):
        """ ipsec 4o4 tunnel 8K packets burst test """
        self.test_tun_basic44(count=257, payload="X"*8000)


class IpsecTun6Tests(object):
    def test_tun_basic66(self, count=1, payload=None):
        """ ipsec 6o6 tunnel basic test """
        self.vapi.cli("clear errors")
        try:
            p = self.params[socket.AF_INET6]
            vpp_tun_sa, scapy_tun_sa = self.configure_sa_tun(p)
            send_pkts = self.gen_encrypt_pkts6(scapy_tun_sa, self.tun_if,
                                               src=p.remote_tun_if_host,
                                               dst=self.pg1.remote_ip6,
                                               count=count, payload=payload)
            recv_pkts = self.send_and_expect(self.tun_if, send_pkts, self.pg1)
            for recv_pkt in recv_pkts:
                self.assert_equal(recv_pkt[IPv6].src, p.remote_tun_if_host)
                self.assert_equal(recv_pkt[IPv6].dst, self.pg1.remote_ip6)
                self.assert_packet_checksums_valid(recv_pkt)
            send_pkts = self.gen_pkts6(self.pg1, src=self.pg1.remote_ip6,
                                       dst=p.remote_tun_if_host,
                                       count=count)
            recv_pkts = self.send_and_expect(self.pg1, send_pkts, self.tun_if)
            for recv_pkt in recv_pkts:
                try:
                    decrypt_pkt = vpp_tun_sa.decrypt(recv_pkt[IPv6])
                    if not decrypt_pkt.haslayer(IPv6):
                        decrypt_pkt = IPv6(decrypt_pkt[Raw].load)
                    self.assert_equal(decrypt_pkt.src, self.pg1.remote_ip6)
                    self.assert_equal(decrypt_pkt.dst, p.remote_tun_if_host)
                    self.assert_packet_checksums_valid(decrypt_pkt)
                except:
                    self.logger.debug(ppp("Unexpected packet:", recv_pkt))
                    try:
                        self.logger.debug(
                            ppp("Decrypted packet:", decrypt_pkt))
                    except:
                        pass
                    raise
        finally:
            self.logger.info(self.vapi.ppcli("show error"))
            self.logger.info(self.vapi.ppcli("show ipsec"))

        self.assert_packet_counter_equal(self.tun6_encrypt_node_name, count)
        self.assert_packet_counter_equal(self.tun6_decrypt_node_name, count)

    def test_tun_burst66(self):
        """ ipsec 6o6 tunnel burst test """
        self.test_tun_basic66(count=257)

    def test_tun_large_basic66(self):
        """ ipsec 6o6 tunnel 8K packets test """
        self.test_tun_basic66(payload="X"*8000)

    def test_tun_large_burst66(self):
        """ ipsec 6o6 tunnel 8K packets burst test """
        self.test_tun_basic66(count=257, payload="X"*8000)


class IpsecTunTests(IpsecTun4Tests, IpsecTun6Tests):
    pass


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
