import unittest
import socket
import struct

from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.ipsec import SecurityAssociation, ESP
from scapy.layers.l2 import Ether
from scapy.packet import raw, Raw
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, IPv6ExtHdrHopByHop, \
    IPv6ExtHdrFragment, IPv6ExtHdrDestOpt


from framework import VppTestCase, VppTestRunner
from util import ppp, reassemble4, fragment_rfc791, fragment_rfc8200
from vpp_papi import VppEnum

from vpp_ipsec import VppIpsecSpd, VppIpsecSpdEntry, \
    VppIpsecSpdItfBinding
from ipaddress import ip_address
from re import search
from os import popen


class IPsecIPv4Params:

    addr_type = socket.AF_INET
    addr_any = "0.0.0.0"
    addr_bcast = "255.255.255.255"
    addr_len = 32
    is_ipv6 = 0

    def __init__(self):
        self.remote_tun_if_host = '1.1.1.1'
        self.remote_tun_if_host6 = '1111::1'

        self.scapy_tun_sa_id = 100
        self.scapy_tun_spi = 1000
        self.vpp_tun_sa_id = 200
        self.vpp_tun_spi = 2000

        self.scapy_tra_sa_id = 300
        self.scapy_tra_spi = 3000
        self.vpp_tra_sa_id = 400
        self.vpp_tra_spi = 4000

        self.outer_hop_limit = 64
        self.inner_hop_limit = 255
        self.outer_flow_label = 0
        self.inner_flow_label = 0x12345

        self.auth_algo_vpp_id = (VppEnum.vl_api_ipsec_integ_alg_t.
                                 IPSEC_API_INTEG_ALG_SHA1_96)
        self.auth_algo = 'HMAC-SHA1-96'  # scapy name
        self.auth_key = b'C91KUR9GYMm5GfkEvNjX'

        self.crypt_algo_vpp_id = (VppEnum.vl_api_ipsec_crypto_alg_t.
                                  IPSEC_API_CRYPTO_ALG_AES_CBC_128)
        self.crypt_algo = 'AES-CBC'  # scapy name
        self.crypt_key = b'JPjyOWBeVEQiMe7h'
        self.salt = 0
        self.flags = 0
        self.nat_header = None
        self.tun_flags = (VppEnum.vl_api_tunnel_encap_decap_flags_t.
                          TUNNEL_API_ENCAP_DECAP_FLAG_NONE)
        self.dscp = 0
        self.async_mode = False


class IPsecIPv6Params:

    addr_type = socket.AF_INET6
    addr_any = "0::0"
    addr_bcast = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
    addr_len = 128
    is_ipv6 = 1

    def __init__(self):
        self.remote_tun_if_host = '1111:1111:1111:1111:1111:1111:1111:1111'
        self.remote_tun_if_host4 = '1.1.1.1'

        self.scapy_tun_sa_id = 500
        self.scapy_tun_spi = 3001
        self.vpp_tun_sa_id = 600
        self.vpp_tun_spi = 3000

        self.scapy_tra_sa_id = 700
        self.scapy_tra_spi = 4001
        self.vpp_tra_sa_id = 800
        self.vpp_tra_spi = 4000

        self.outer_hop_limit = 64
        self.inner_hop_limit = 255
        self.outer_flow_label = 0
        self.inner_flow_label = 0x12345

        self.auth_algo_vpp_id = (VppEnum.vl_api_ipsec_integ_alg_t.
                                 IPSEC_API_INTEG_ALG_SHA1_96)
        self.auth_algo = 'HMAC-SHA1-96'  # scapy name
        self.auth_key = b'C91KUR9GYMm5GfkEvNjX'

        self.crypt_algo_vpp_id = (VppEnum.vl_api_ipsec_crypto_alg_t.
                                  IPSEC_API_CRYPTO_ALG_AES_CBC_128)
        self.crypt_algo = 'AES-CBC'  # scapy name
        self.crypt_key = b'JPjyOWBeVEQiMe7h'
        self.salt = 0
        self.flags = 0
        self.nat_header = None
        self.tun_flags = (VppEnum.vl_api_tunnel_encap_decap_flags_t.
                          TUNNEL_API_ENCAP_DECAP_FLAG_NONE)
        self.dscp = 0
        self.async_mode = False


def mk_scapy_crypt_key(p):
    if p.crypt_algo in ("AES-GCM", "AES-CTR"):
        return p.crypt_key + struct.pack("!I", p.salt)
    else:
        return p.crypt_key


def config_tun_params(p, encryption_type, tun_if):
    ip_class_by_addr_type = {socket.AF_INET: IP, socket.AF_INET6: IPv6}
    esn_en = bool(p.flags & (VppEnum.vl_api_ipsec_sad_flags_t.
                             IPSEC_API_SAD_FLAG_USE_ESN))
    p.tun_dst = tun_if.remote_addr[p.addr_type]
    p.tun_src = tun_if.local_addr[p.addr_type]
    crypt_key = mk_scapy_crypt_key(p)
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


def config_tra_params(p, encryption_type):
    esn_en = bool(p.flags & (VppEnum.vl_api_ipsec_sad_flags_t.
                             IPSEC_API_SAD_FLAG_USE_ESN))
    crypt_key = mk_scapy_crypt_key(p)
    p.scapy_tra_sa = SecurityAssociation(
        encryption_type,
        spi=p.vpp_tra_spi,
        crypt_algo=p.crypt_algo,
        crypt_key=crypt_key,
        auth_algo=p.auth_algo,
        auth_key=p.auth_key,
        nat_t_header=p.nat_header,
        esn_en=esn_en)
    p.vpp_tra_sa = SecurityAssociation(
        encryption_type,
        spi=p.scapy_tra_spi,
        crypt_algo=p.crypt_algo,
        crypt_key=crypt_key,
        auth_algo=p.auth_algo,
        auth_key=p.auth_key,
        nat_t_header=p.nat_header,
        esn_en=esn_en)


class TemplateIpsec(VppTestCase):
    """
    TRANSPORT MODE::

         ------   encrypt   ---
        |tra_if| <-------> |VPP|
         ------   decrypt   ---

    TUNNEL MODE::

         ------   encrypt   ---   plain   ---
        |tun_if| <-------  |VPP| <------ |pg1|
         ------             ---           ---

         ------   decrypt   ---   plain   ---
        |tun_if| ------->  |VPP| ------> |pg1|
         ------             ---           ---
    """
    tun_spd_id = 1
    tra_spd_id = 2

    def ipsec_select_backend(self):
        """ empty method to be overloaded when necessary """
        pass

    @classmethod
    def setUpClass(cls):
        super(TemplateIpsec, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TemplateIpsec, cls).tearDownClass()

    def setup_params(self):
        if not hasattr(self, 'ipv4_params'):
            self.ipv4_params = IPsecIPv4Params()
        if not hasattr(self, 'ipv6_params'):
            self.ipv6_params = IPsecIPv6Params()
        self.params = {self.ipv4_params.addr_type: self.ipv4_params,
                       self.ipv6_params.addr_type: self.ipv6_params}

    def config_interfaces(self):
        self.create_pg_interfaces(range(3))
        self.interfaces = list(self.pg_interfaces)
        for i in self.interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()
            i.config_ip6()
            i.resolve_ndp()

    def setUp(self):
        super(TemplateIpsec, self).setUp()

        self.setup_params()

        self.vpp_esp_protocol = (VppEnum.vl_api_ipsec_proto_t.
                                 IPSEC_API_PROTO_ESP)
        self.vpp_ah_protocol = (VppEnum.vl_api_ipsec_proto_t.
                                IPSEC_API_PROTO_AH)

        self.config_interfaces()

        self.ipsec_select_backend()

    def unconfig_interfaces(self):
        for i in self.interfaces:
            i.admin_down()
            i.unconfig_ip4()
            i.unconfig_ip6()

    def tearDown(self):
        super(TemplateIpsec, self).tearDown()

        self.unconfig_interfaces()

    def show_commands_at_teardown(self):
        self.logger.info(self.vapi.cli("show hardware"))

    def gen_encrypt_pkts(self, p, sa, sw_intf, src, dst, count=1,
                         payload_size=54):
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                sa.encrypt(IP(src=src, dst=dst) /
                           ICMP() / Raw(b'X' * payload_size))
                for i in range(count)]

    def gen_encrypt_pkts6(self, p, sa, sw_intf, src, dst, count=1,
                          payload_size=54):
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                sa.encrypt(IPv6(src=src, dst=dst,
                                hlim=p.inner_hop_limit,
                                fl=p.inner_flow_label) /
                           ICMPv6EchoRequest(id=0, seq=1,
                                             data='X' * payload_size))
                for i in range(count)]

    def gen_pkts(self, sw_intf, src, dst, count=1, payload_size=54):
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                IP(src=src, dst=dst) / ICMP() / Raw(b'X' * payload_size)
                for i in range(count)]

    def gen_pkts6(self, p, sw_intf, src, dst, count=1, payload_size=54):
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                IPv6(src=src, dst=dst,
                     hlim=p.inner_hop_limit, fl=p.inner_flow_label) /
                ICMPv6EchoRequest(id=0, seq=1, data='X' * payload_size)
                for i in range(count)]


class IpsecTcp(object):
    def verify_tcp_checksum(self):
        # start http cli server on http://0.0.0.0:80
        self.vapi.cli("http cli")
        p = self.params[socket.AF_INET]
        send = (Ether(src=self.tun_if.remote_mac, dst=self.tun_if.local_mac) /
                p.scapy_tun_sa.encrypt(IP(src=p.remote_tun_if_host,
                                          dst=self.tun_if.local_ip4) /
                                       TCP(flags='S', dport=80)))
        self.logger.debug(ppp("Sending packet:", send))
        recv = self.send_and_expect(self.tun_if, [send], self.tun_if)
        recv = recv[0]
        decrypted = p.vpp_tun_sa.decrypt(recv[IP])
        self.assert_packet_checksums_valid(decrypted)


class IpsecTcpTests(IpsecTcp):
    def test_tcp_checksum(self):
        """ verify checksum correctness for vpp generated packets """
        self.verify_tcp_checksum()


class IpsecTra4(object):
    """ verify methods for Transport v4 """
    def get_replay_counts(self, p):
        replay_node_name = ('/err/%s/SA replayed packet' %
                            self.tra4_decrypt_node_name[0])
        count = self.statistics.get_err_counter(replay_node_name)

        if p.async_mode:
            replay_post_node_name = ('/err/%s/SA replayed packet' %
                                     self.tra4_decrypt_node_name[p.async_mode])
            count += self.statistics.get_err_counter(replay_post_node_name)

        return count

    def get_hash_failed_counts(self, p):
        if ESP == self.encryption_type and p.crypt_algo == "AES-GCM":
            hash_failed_node_name = ('/err/%s/ESP decryption failed' %
                                     self.tra4_decrypt_node_name[p.async_mode])
        else:
            hash_failed_node_name = ('/err/%s/Integrity check failed' %
                                     self.tra4_decrypt_node_name[p.async_mode])
        count = self.statistics.get_err_counter(hash_failed_node_name)

        if p.async_mode:
            count += self.statistics.get_err_counter(
                '/err/crypto-dispatch/bad-hmac')

        return count

    def verify_hi_seq_num(self):
        p = self.params[socket.AF_INET]
        saf = VppEnum.vl_api_ipsec_sad_flags_t
        esn_on = p.vpp_tra_sa.esn_en
        ar_on = p.flags & saf.IPSEC_API_SAD_FLAG_USE_ANTI_REPLAY

        seq_cycle_node_name = \
            ('/err/%s/sequence number cycled (packet dropped)' %
             self.tra4_encrypt_node_name)
        replay_count = self.get_replay_counts(p)
        hash_failed_count = self.get_hash_failed_counts(p)
        seq_cycle_count = self.statistics.get_err_counter(seq_cycle_node_name)

        # a few packets so we get the rx seq number above the window size and
        # thus can simulate a wrap with an out of window packet
        pkts = [(Ether(src=self.tra_if.remote_mac,
                       dst=self.tra_if.local_mac) /
                 p.scapy_tra_sa.encrypt(IP(src=self.tra_if.remote_ip4,
                                           dst=self.tra_if.local_ip4) /
                                        ICMP(),
                                        seq_num=seq))
                for seq in range(63, 80)]
        recv_pkts = self.send_and_expect(self.tra_if, pkts, self.tra_if)

        # these 4 packets will all choose seq-num 0 to decrpyt since none
        # are out of window when first checked. however, once #200 has
        # decrypted it will move the window to 200 and has #81 is out of
        # window. this packet should be dropped.
        pkts = [(Ether(src=self.tra_if.remote_mac,
                       dst=self.tra_if.local_mac) /
                 p.scapy_tra_sa.encrypt(IP(src=self.tra_if.remote_ip4,
                                           dst=self.tra_if.local_ip4) /
                                        ICMP(),
                                        seq_num=200)),
                (Ether(src=self.tra_if.remote_mac,
                       dst=self.tra_if.local_mac) /
                 p.scapy_tra_sa.encrypt(IP(src=self.tra_if.remote_ip4,
                                           dst=self.tra_if.local_ip4) /
                                        ICMP(),
                                        seq_num=81)),
                (Ether(src=self.tra_if.remote_mac,
                       dst=self.tra_if.local_mac) /
                 p.scapy_tra_sa.encrypt(IP(src=self.tra_if.remote_ip4,
                                           dst=self.tra_if.local_ip4) /
                                        ICMP(),
                                        seq_num=201)),
                (Ether(src=self.tra_if.remote_mac,
                       dst=self.tra_if.local_mac) /
                 p.scapy_tra_sa.encrypt(IP(src=self.tra_if.remote_ip4,
                                           dst=self.tra_if.local_ip4) /
                                        ICMP(),
                                        seq_num=202))]

        # if anti-replay is off then we won't drop #81
        n_rx = 3 if ar_on else 4
        self.send_and_expect(self.tra_if, pkts, self.tra_if, n_rx=n_rx)
        # this packet is one before the wrap
        pkts = [(Ether(src=self.tra_if.remote_mac,
                       dst=self.tra_if.local_mac) /
                 p.scapy_tra_sa.encrypt(IP(src=self.tra_if.remote_ip4,
                                           dst=self.tra_if.local_ip4) /
                                        ICMP(),
                                        seq_num=203))]
        recv_pkts = self.send_and_expect(self.tra_if, pkts, self.tra_if)

        # move the window over half way to a wrap
        pkts = [(Ether(src=self.tra_if.remote_mac,
                       dst=self.tra_if.local_mac) /
                 p.scapy_tra_sa.encrypt(IP(src=self.tra_if.remote_ip4,
                                           dst=self.tra_if.local_ip4) /
                                        ICMP(),
                                        seq_num=0x80000001))]
        recv_pkts = self.send_and_expect(self.tra_if, pkts, self.tra_if)

        # anti-replay will drop old packets, no anti-replay will not
        pkts = [(Ether(src=self.tra_if.remote_mac,
                       dst=self.tra_if.local_mac) /
                 p.scapy_tra_sa.encrypt(IP(src=self.tra_if.remote_ip4,
                                           dst=self.tra_if.local_ip4) /
                                        ICMP(),
                                        seq_num=0x44000001))]

        if ar_on:
            self.send_and_assert_no_replies(self.tra_if, pkts)
        else:
            recv_pkts = self.send_and_expect(self.tra_if, pkts, self.tra_if)

        if esn_on:
            #
            # validate wrapping the ESN
            #

            # wrap scapy's TX SA SN
            p.scapy_tra_sa.seq_num = 0x100000005

            # send a packet that wraps the window for both AR and no AR
            pkts = [(Ether(src=self.tra_if.remote_mac,
                           dst=self.tra_if.local_mac) /
                     p.scapy_tra_sa.encrypt(IP(src=self.tra_if.remote_ip4,
                                               dst=self.tra_if.local_ip4) /
                                            ICMP(),
                                            seq_num=0x100000005))]

            rxs = self.send_and_expect(self.tra_if, pkts, self.tra_if)
            for rx in rxs:
                decrypted = p.vpp_tra_sa.decrypt(rx[0][IP])

            # move the window forward to half way to the next wrap
            pkts = [(Ether(src=self.tra_if.remote_mac,
                           dst=self.tra_if.local_mac) /
                     p.scapy_tra_sa.encrypt(IP(src=self.tra_if.remote_ip4,
                                               dst=self.tra_if.local_ip4) /
                                            ICMP(),
                                            seq_num=0x180000005))]

            rxs = self.send_and_expect(self.tra_if, pkts, self.tra_if)

            # a packet less than 2^30 from the current position is:
            #  - AR: out of window and dropped
            #  - non-AR: accepted
            pkts = [(Ether(src=self.tra_if.remote_mac,
                           dst=self.tra_if.local_mac) /
                     p.scapy_tra_sa.encrypt(IP(src=self.tra_if.remote_ip4,
                                               dst=self.tra_if.local_ip4) /
                                            ICMP(),
                                            seq_num=0x170000005))]

            if ar_on:
                self.send_and_assert_no_replies(self.tra_if, pkts)
            else:
                self.send_and_expect(self.tra_if, pkts, self.tra_if)

            # a packet more than 2^30 from the current position is:
            #  - AR: out of window and dropped
            #  - non-AR: considered a wrap, but since it's not a wrap
            #    it won't decrpyt and so will be dropped
            pkts = [(Ether(src=self.tra_if.remote_mac,
                           dst=self.tra_if.local_mac) /
                     p.scapy_tra_sa.encrypt(IP(src=self.tra_if.remote_ip4,
                                               dst=self.tra_if.local_ip4) /
                                            ICMP(),
                                            seq_num=0x130000005))]

            self.send_and_assert_no_replies(self.tra_if, pkts)

            # a packet less than 2^30 from the current position and is a
            # wrap; (the seq is currently at 0x180000005).
            #  - AR: out of window so considered a wrap, so accepted
            #  - non-AR: not considered a wrap, so won't decrypt
            p.scapy_tra_sa.seq_num = 0x260000005
            pkts = [(Ether(src=self.tra_if.remote_mac,
                           dst=self.tra_if.local_mac) /
                     p.scapy_tra_sa.encrypt(IP(src=self.tra_if.remote_ip4,
                                               dst=self.tra_if.local_ip4) /
                                            ICMP(),
                                            seq_num=0x260000005))]
            if ar_on:
                self.send_and_expect(self.tra_if, pkts, self.tra_if)
            else:
                self.send_and_assert_no_replies(self.tra_if, pkts)

            #
            # window positions are different now for AR/non-AR
            #  move non-AR forward
            #
            if not ar_on:
                # a packet more than 2^30 from the current position and is a
                # wrap; (the seq is currently at 0x180000005).
                #  - AR: accepted
                #  - non-AR: not considered a wrap, so won't decrypt

                pkts = [(Ether(src=self.tra_if.remote_mac,
                               dst=self.tra_if.local_mac) /
                         p.scapy_tra_sa.encrypt(IP(src=self.tra_if.remote_ip4,
                                                   dst=self.tra_if.local_ip4) /
                                                ICMP(),
                                                seq_num=0x200000005)),
                        (Ether(src=self.tra_if.remote_mac,
                               dst=self.tra_if.local_mac) /
                         p.scapy_tra_sa.encrypt(IP(src=self.tra_if.remote_ip4,
                                                   dst=self.tra_if.local_ip4) /
                                                ICMP(),
                                                seq_num=0x200000006))]
                self.send_and_expect(self.tra_if, pkts, self.tra_if)

                pkts = [(Ether(src=self.tra_if.remote_mac,
                               dst=self.tra_if.local_mac) /
                         p.scapy_tra_sa.encrypt(IP(src=self.tra_if.remote_ip4,
                                                   dst=self.tra_if.local_ip4) /
                                                ICMP(),
                                                seq_num=0x260000005))]
                self.send_and_expect(self.tra_if, pkts, self.tra_if)

    def verify_tra_anti_replay(self):
        p = self.params[socket.AF_INET]
        esn_en = p.vpp_tra_sa.esn_en

        seq_cycle_node_name = \
            ('/err/%s/sequence number cycled (packet dropped)' %
             self.tra4_encrypt_node_name)
        replay_count = self.get_replay_counts(p)
        hash_failed_count = self.get_hash_failed_counts(p)
        seq_cycle_count = self.statistics.get_err_counter(seq_cycle_node_name)

        if ESP == self.encryption_type:
            undersize_node_name = ('/err/%s/undersized packet' %
                                   self.tra4_decrypt_node_name[0])
            undersize_count = self.statistics.get_err_counter(
                undersize_node_name)

        #
        # send packets with seq numbers 1->34
        # this means the window size is still in Case B (see RFC4303
        # Appendix A)
        #
        # for reasons i haven't investigated Scapy won't create a packet with
        # seq_num=0
        #
        pkts = [(Ether(src=self.tra_if.remote_mac,
                       dst=self.tra_if.local_mac) /
                 p.scapy_tra_sa.encrypt(IP(src=self.tra_if.remote_ip4,
                                           dst=self.tra_if.local_ip4) /
                                        ICMP(),
                                        seq_num=seq))
                for seq in range(1, 34)]
        recv_pkts = self.send_and_expect(self.tra_if, pkts, self.tra_if)

        # replayed packets are dropped
        self.send_and_assert_no_replies(self.tra_if, pkts, timeout=0.2)
        replay_count += len(pkts)
        self.assertEqual(self.get_replay_counts(p), replay_count)

        #
        # now send a batch of packets all with the same sequence number
        # the first packet in the batch is legitimate, the rest bogus
        #
        self.vapi.cli("clear error")
        self.vapi.cli("clear node counters")
        pkts = (Ether(src=self.tra_if.remote_mac,
                      dst=self.tra_if.local_mac) /
                p.scapy_tra_sa.encrypt(IP(src=self.tra_if.remote_ip4,
                                          dst=self.tra_if.local_ip4) /
                                       ICMP(),
                                       seq_num=35))
        recv_pkts = self.send_and_expect(self.tra_if, pkts * 8,
                                         self.tra_if, n_rx=1)
        replay_count += 7
        self.assertEqual(self.get_replay_counts(p), replay_count)

        #
        # now move the window over to 257 (more than one byte) and into Case A
        #
        self.vapi.cli("clear error")
        pkt = (Ether(src=self.tra_if.remote_mac,
                     dst=self.tra_if.local_mac) /
               p.scapy_tra_sa.encrypt(IP(src=self.tra_if.remote_ip4,
                                         dst=self.tra_if.local_ip4) /
                                      ICMP(),
                                      seq_num=257))
        recv_pkts = self.send_and_expect(self.tra_if, [pkt], self.tra_if)

        # replayed packets are dropped
        self.send_and_assert_no_replies(self.tra_if, pkt * 3, timeout=0.2)
        replay_count += 3
        self.assertEqual(self.get_replay_counts(p), replay_count)

        # the window size is 64 packets
        # in window are still accepted
        pkt = (Ether(src=self.tra_if.remote_mac,
                     dst=self.tra_if.local_mac) /
               p.scapy_tra_sa.encrypt(IP(src=self.tra_if.remote_ip4,
                                         dst=self.tra_if.local_ip4) /
                                      ICMP(),
                                      seq_num=200))
        recv_pkts = self.send_and_expect(self.tra_if, [pkt], self.tra_if)

        # a packet that does not decrypt does not move the window forward
        bogus_sa = SecurityAssociation(self.encryption_type,
                                       p.vpp_tra_spi,
                                       crypt_algo=p.crypt_algo,
                                       crypt_key=mk_scapy_crypt_key(p)[::-1],
                                       auth_algo=p.auth_algo,
                                       auth_key=p.auth_key[::-1])
        pkt = (Ether(src=self.tra_if.remote_mac,
                     dst=self.tra_if.local_mac) /
               bogus_sa.encrypt(IP(src=self.tra_if.remote_ip4,
                                   dst=self.tra_if.local_ip4) /
                                ICMP(),
                                seq_num=350))
        self.send_and_assert_no_replies(self.tra_if, pkt * 17, timeout=0.2)

        hash_failed_count += 17
        self.assertEqual(self.get_hash_failed_counts(p), hash_failed_count)

        # a malformed 'runt' packet
        #  created by a mis-constructed SA
        if (ESP == self.encryption_type and p.crypt_algo != "NULL"):
            bogus_sa = SecurityAssociation(self.encryption_type,
                                           p.vpp_tra_spi)
            pkt = (Ether(src=self.tra_if.remote_mac,
                         dst=self.tra_if.local_mac) /
                   bogus_sa.encrypt(IP(src=self.tra_if.remote_ip4,
                                       dst=self.tra_if.local_ip4) /
                                    ICMP(),
                                    seq_num=350))
            self.send_and_assert_no_replies(self.tra_if, pkt * 17, timeout=0.2)

            undersize_count += 17
            self.assert_error_counter_equal(undersize_node_name,
                                            undersize_count)

        # which we can determine since this packet is still in the window
        pkt = (Ether(src=self.tra_if.remote_mac,
                     dst=self.tra_if.local_mac) /
               p.scapy_tra_sa.encrypt(IP(src=self.tra_if.remote_ip4,
                                         dst=self.tra_if.local_ip4) /
                                      ICMP(),
                                      seq_num=234))
        self.send_and_expect(self.tra_if, [pkt], self.tra_if)

        #
        # out of window are dropped
        #  this is Case B. So VPP will consider this to be a high seq num wrap
        #  and so the decrypt attempt will fail
        #
        pkt = (Ether(src=self.tra_if.remote_mac,
                     dst=self.tra_if.local_mac) /
               p.scapy_tra_sa.encrypt(IP(src=self.tra_if.remote_ip4,
                                         dst=self.tra_if.local_ip4) /
                                      ICMP(),
                                      seq_num=17))
        self.send_and_assert_no_replies(self.tra_if, pkt * 17, timeout=0.2)

        if esn_en:
            # an out of window error with ESN looks like a high sequence
            # wrap. but since it isn't then the verify will fail.
            hash_failed_count += 17
            self.assertEqual(self.get_hash_failed_counts(p), hash_failed_count)

        else:
            replay_count += 17
            self.assertEqual(self.get_replay_counts(p), replay_count)

        # valid packet moves the window over to 258
        pkt = (Ether(src=self.tra_if.remote_mac,
                     dst=self.tra_if.local_mac) /
               p.scapy_tra_sa.encrypt(IP(src=self.tra_if.remote_ip4,
                                         dst=self.tra_if.local_ip4) /
                                      ICMP(),
                                      seq_num=258))
        rx = self.send_and_expect(self.tra_if, [pkt], self.tra_if)
        decrypted = p.vpp_tra_sa.decrypt(rx[0][IP])

        #
        # move VPP's SA TX seq-num to just before the seq-number wrap.
        # then fire in a packet that VPP should drop on TX because it
        # causes the TX seq number to wrap; unless we're using extened sequence
        # numbers.
        #
        self.vapi.cli("test ipsec sa %d seq 0xffffffff" % p.scapy_tra_sa_id)
        self.logger.info(self.vapi.ppcli("show ipsec sa 0"))
        self.logger.info(self.vapi.ppcli("show ipsec sa 1"))

        pkts = [(Ether(src=self.tra_if.remote_mac,
                       dst=self.tra_if.local_mac) /
                 p.scapy_tra_sa.encrypt(IP(src=self.tra_if.remote_ip4,
                                           dst=self.tra_if.local_ip4) /
                                        ICMP(),
                                        seq_num=seq))
                for seq in range(259, 280)]

        if esn_en:
            rxs = self.send_and_expect(self.tra_if, pkts, self.tra_if)

            #
            # in order for scapy to decrypt its SA's high order number needs
            # to wrap
            #
            p.vpp_tra_sa.seq_num = 0x100000000
            for rx in rxs:
                decrypted = p.vpp_tra_sa.decrypt(rx[0][IP])

            #
            # wrap scapy's TX high sequence number. VPP is in case B, so it
            # will consider this a high seq wrap also.
            # The low seq num we set it to will place VPP's RX window in Case A
            #
            p.scapy_tra_sa.seq_num = 0x100000005
            pkt = (Ether(src=self.tra_if.remote_mac,
                         dst=self.tra_if.local_mac) /
                   p.scapy_tra_sa.encrypt(IP(src=self.tra_if.remote_ip4,
                                             dst=self.tra_if.local_ip4) /
                                          ICMP(),
                                          seq_num=0x100000005))
            rx = self.send_and_expect(self.tra_if, [pkt], self.tra_if)

            decrypted = p.vpp_tra_sa.decrypt(rx[0][IP])

            #
            # A packet that has seq num between (2^32-64) and 5 is within
            # the window
            #
            p.scapy_tra_sa.seq_num = 0xfffffffd
            pkt = (Ether(src=self.tra_if.remote_mac,
                         dst=self.tra_if.local_mac) /
                   p.scapy_tra_sa.encrypt(IP(src=self.tra_if.remote_ip4,
                                             dst=self.tra_if.local_ip4) /
                                          ICMP(),
                                          seq_num=0xfffffffd))
            rx = self.send_and_expect(self.tra_if, [pkt], self.tra_if)
            decrypted = p.vpp_tra_sa.decrypt(rx[0][IP])

            #
            # While in case A we cannot wrap the high sequence number again
            # because VPP will consider this packet to be one that moves the
            # window forward
            #
            pkt = (Ether(src=self.tra_if.remote_mac,
                         dst=self.tra_if.local_mac) /
                   p.scapy_tra_sa.encrypt(IP(src=self.tra_if.remote_ip4,
                                             dst=self.tra_if.local_ip4) /
                                          ICMP(),
                                          seq_num=0x200000999))
            self.send_and_assert_no_replies(self.tra_if, [pkt], self.tra_if,
                                            timeout=0.2)

            hash_failed_count += 1
            self.assertEqual(self.get_hash_failed_counts(p), hash_failed_count)

            #
            # but if we move the window forward to case B, then we can wrap
            # again
            #
            p.scapy_tra_sa.seq_num = 0x100000555
            pkt = (Ether(src=self.tra_if.remote_mac,
                         dst=self.tra_if.local_mac) /
                   p.scapy_tra_sa.encrypt(IP(src=self.tra_if.remote_ip4,
                                             dst=self.tra_if.local_ip4) /
                                          ICMP(),
                                          seq_num=0x100000555))
            rx = self.send_and_expect(self.tra_if, [pkt], self.tra_if)
            decrypted = p.vpp_tra_sa.decrypt(rx[0][IP])

            p.scapy_tra_sa.seq_num = 0x200000444
            pkt = (Ether(src=self.tra_if.remote_mac,
                         dst=self.tra_if.local_mac) /
                   p.scapy_tra_sa.encrypt(IP(src=self.tra_if.remote_ip4,
                                             dst=self.tra_if.local_ip4) /
                                          ICMP(),
                                          seq_num=0x200000444))
            rx = self.send_and_expect(self.tra_if, [pkt], self.tra_if)
            decrypted = p.vpp_tra_sa.decrypt(rx[0][IP])

        else:
            #
            # without ESN TX sequence numbers can't wrap and packets are
            # dropped from here on out.
            #
            self.send_and_assert_no_replies(self.tra_if, pkts, timeout=0.2)
            seq_cycle_count += len(pkts)
            self.assert_error_counter_equal(seq_cycle_node_name,
                                            seq_cycle_count)

        # move the security-associations seq number on to the last we used
        self.vapi.cli("test ipsec sa %d seq 0x15f" % p.scapy_tra_sa_id)
        p.scapy_tra_sa.seq_num = 351
        p.vpp_tra_sa.seq_num = 351

    def verify_tra_lost(self):
        p = self.params[socket.AF_INET]
        esn_en = p.vpp_tra_sa.esn_en

        #
        # send packets with seq numbers 1->34
        # this means the window size is still in Case B (see RFC4303
        # Appendix A)
        #
        # for reasons i haven't investigated Scapy won't create a packet with
        # seq_num=0
        #
        pkts = [(Ether(src=self.tra_if.remote_mac,
                       dst=self.tra_if.local_mac) /
                 p.scapy_tra_sa.encrypt(IP(src=self.tra_if.remote_ip4,
                                           dst=self.tra_if.local_ip4) /
                                        ICMP(),
                                        seq_num=seq))
                for seq in range(1, 3)]
        self.send_and_expect(self.tra_if, pkts, self.tra_if)

        self.assertEqual(p.tra_sa_out.get_lost(), 0)

        # skip a sequence number
        pkts = [(Ether(src=self.tra_if.remote_mac,
                       dst=self.tra_if.local_mac) /
                 p.scapy_tra_sa.encrypt(IP(src=self.tra_if.remote_ip4,
                                           dst=self.tra_if.local_ip4) /
                                        ICMP(),
                                        seq_num=seq))
                for seq in range(4, 6)]
        self.send_and_expect(self.tra_if, pkts, self.tra_if)

        self.assertEqual(p.tra_sa_out.get_lost(), 0)

        # the lost packet are counted untill we get up past the first
        # sizeof(replay_window) packets
        pkts = [(Ether(src=self.tra_if.remote_mac,
                       dst=self.tra_if.local_mac) /
                 p.scapy_tra_sa.encrypt(IP(src=self.tra_if.remote_ip4,
                                           dst=self.tra_if.local_ip4) /
                                        ICMP(),
                                        seq_num=seq))
                for seq in range(6, 100)]
        self.send_and_expect(self.tra_if, pkts, self.tra_if)

        self.assertEqual(p.tra_sa_out.get_lost(), 1)

        # lost of holes in the sequence
        pkts = [(Ether(src=self.tra_if.remote_mac,
                       dst=self.tra_if.local_mac) /
                 p.scapy_tra_sa.encrypt(IP(src=self.tra_if.remote_ip4,
                                           dst=self.tra_if.local_ip4) /
                                        ICMP(),
                                        seq_num=seq))
                for seq in range(100, 200, 2)]
        self.send_and_expect(self.tra_if, pkts, self.tra_if, n_rx=50)

        pkts = [(Ether(src=self.tra_if.remote_mac,
                       dst=self.tra_if.local_mac) /
                 p.scapy_tra_sa.encrypt(IP(src=self.tra_if.remote_ip4,
                                           dst=self.tra_if.local_ip4) /
                                        ICMP(),
                                        seq_num=seq))
                for seq in range(200, 300)]
        self.send_and_expect(self.tra_if, pkts, self.tra_if)

        self.assertEqual(p.tra_sa_out.get_lost(), 51)

        # a big hole in the seq number space
        pkts = [(Ether(src=self.tra_if.remote_mac,
                       dst=self.tra_if.local_mac) /
                 p.scapy_tra_sa.encrypt(IP(src=self.tra_if.remote_ip4,
                                           dst=self.tra_if.local_ip4) /
                                        ICMP(),
                                        seq_num=seq))
                for seq in range(400, 500)]
        self.send_and_expect(self.tra_if, pkts, self.tra_if)

        self.assertEqual(p.tra_sa_out.get_lost(), 151)

    def verify_tra_basic4(self, count=1, payload_size=54):
        """ ipsec v4 transport basic test """
        self.vapi.cli("clear errors")
        self.vapi.cli("clear ipsec sa")
        try:
            p = self.params[socket.AF_INET]
            send_pkts = self.gen_encrypt_pkts(p, p.scapy_tra_sa, self.tra_if,
                                              src=self.tra_if.remote_ip4,
                                              dst=self.tra_if.local_ip4,
                                              count=count,
                                              payload_size=payload_size)
            recv_pkts = self.send_and_expect(self.tra_if, send_pkts,
                                             self.tra_if)
            for rx in recv_pkts:
                self.assertEqual(len(rx) - len(Ether()), rx[IP].len)
                self.assert_packet_checksums_valid(rx)
                try:
                    decrypted = p.vpp_tra_sa.decrypt(rx[IP])
                    self.assert_packet_checksums_valid(decrypted)
                except:
                    self.logger.debug(ppp("Unexpected packet:", rx))
                    raise
        finally:
            self.logger.info(self.vapi.ppcli("show error"))
            self.logger.info(self.vapi.ppcli("show ipsec all"))

        pkts = p.tra_sa_in.get_stats()['packets']
        self.assertEqual(pkts, count,
                         "incorrect SA in counts: expected %d != %d" %
                         (count, pkts))
        pkts = p.tra_sa_out.get_stats()['packets']
        self.assertEqual(pkts, count,
                         "incorrect SA out counts: expected %d != %d" %
                         (count, pkts))
        self.assertEqual(p.tra_sa_out.get_lost(), 0)
        self.assertEqual(p.tra_sa_in.get_lost(), 0)

        self.assert_packet_counter_equal(self.tra4_encrypt_node_name, count)
        self.assert_packet_counter_equal(self.tra4_decrypt_node_name[0], count)


class IpsecTra4Tests(IpsecTra4):
    """ UT test methods for Transport v4 """
    def test_tra_anti_replay(self):
        """ ipsec v4 transport anti-replay test """
        self.verify_tra_anti_replay()

    def test_tra_lost(self):
        """ ipsec v4 transport lost packet test """
        self.verify_tra_lost()

    def test_tra_basic(self, count=1):
        """ ipsec v4 transport basic test """
        self.verify_tra_basic4(count=1)

    def test_tra_burst(self):
        """ ipsec v4 transport burst test """
        self.verify_tra_basic4(count=257)


class IpsecTra6(object):
    """ verify methods for Transport v6 """
    def verify_tra_basic6(self, count=1, payload_size=54):
        self.vapi.cli("clear errors")
        self.vapi.cli("clear ipsec sa")
        try:
            p = self.params[socket.AF_INET6]
            send_pkts = self.gen_encrypt_pkts6(p, p.scapy_tra_sa, self.tra_if,
                                               src=self.tra_if.remote_ip6,
                                               dst=self.tra_if.local_ip6,
                                               count=count,
                                               payload_size=payload_size)
            recv_pkts = self.send_and_expect(self.tra_if, send_pkts,
                                             self.tra_if)
            for rx in recv_pkts:
                self.assertEqual(len(rx) - len(Ether()) - len(IPv6()),
                                 rx[IPv6].plen)
                try:
                    decrypted = p.vpp_tra_sa.decrypt(rx[IPv6])
                    self.assert_packet_checksums_valid(decrypted)
                except:
                    self.logger.debug(ppp("Unexpected packet:", rx))
                    raise
        finally:
            self.logger.info(self.vapi.ppcli("show error"))
            self.logger.info(self.vapi.ppcli("show ipsec all"))

        pkts = p.tra_sa_in.get_stats()['packets']
        self.assertEqual(pkts, count,
                         "incorrect SA in counts: expected %d != %d" %
                         (count, pkts))
        pkts = p.tra_sa_out.get_stats()['packets']
        self.assertEqual(pkts, count,
                         "incorrect SA out counts: expected %d != %d" %
                         (count, pkts))
        self.assert_packet_counter_equal(self.tra6_encrypt_node_name, count)
        self.assert_packet_counter_equal(self.tra6_decrypt_node_name[0], count)

    def gen_encrypt_pkts_ext_hdrs6(self, sa, sw_intf, src, dst, count=1,
                                   payload_size=54):
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                sa.encrypt(IPv6(src=src, dst=dst) /
                           ICMPv6EchoRequest(id=0, seq=1,
                                             data='X' * payload_size))
                for i in range(count)]

    def gen_pkts_ext_hdrs6(self, sw_intf, src, dst, count=1, payload_size=54):
        return [Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac) /
                IPv6(src=src, dst=dst) /
                IPv6ExtHdrHopByHop() /
                IPv6ExtHdrFragment(id=2, offset=200) /
                Raw(b'\xff' * 200)
                for i in range(count)]

    def verify_tra_encrypted6(self, p, sa, rxs):
        decrypted = []
        for rx in rxs:
            self.assert_packet_checksums_valid(rx)
            try:
                decrypt_pkt = p.vpp_tra_sa.decrypt(rx[IPv6])
                decrypted.append(decrypt_pkt)
                self.assert_equal(decrypt_pkt.src, self.tra_if.local_ip6)
                self.assert_equal(decrypt_pkt.dst, self.tra_if.remote_ip6)
            except:
                self.logger.debug(ppp("Unexpected packet:", rx))
                try:
                    self.logger.debug(ppp("Decrypted packet:", decrypt_pkt))
                except:
                    pass
                raise
        return decrypted

    def verify_tra_66_ext_hdrs(self, p):
        count = 63

        #
        # check we can decrypt with options
        #
        tx = self.gen_encrypt_pkts_ext_hdrs6(p.scapy_tra_sa, self.tra_if,
                                             src=self.tra_if.remote_ip6,
                                             dst=self.tra_if.local_ip6,
                                             count=count)
        self.send_and_expect(self.tra_if, tx, self.tra_if)

        #
        # injecting a packet from ourselves to be routed of box is a hack
        # but it matches an outbout policy, alors je ne regrette rien
        #

        # one extension before ESP
        tx = (Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac) /
              IPv6(src=self.tra_if.local_ip6,
                   dst=self.tra_if.remote_ip6) /
              IPv6ExtHdrFragment(id=2, offset=200) /
              Raw(b'\xff' * 200))

        rxs = self.send_and_expect(self.pg2, [tx], self.tra_if)
        dcs = self.verify_tra_encrypted6(p, p.vpp_tra_sa, rxs)

        for dc in dcs:
            # for reasons i'm not going to investigate scapy does not
            # created the correct headers after decrypt. but reparsing
            # the ipv6 packet fixes it
            dc = IPv6(raw(dc[IPv6]))
            self.assert_equal(dc[IPv6ExtHdrFragment].id, 2)

        # two extensions before ESP
        tx = (Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac) /
              IPv6(src=self.tra_if.local_ip6,
                   dst=self.tra_if.remote_ip6) /
              IPv6ExtHdrHopByHop() /
              IPv6ExtHdrFragment(id=2, offset=200) /
              Raw(b'\xff' * 200))

        rxs = self.send_and_expect(self.pg2, [tx], self.tra_if)
        dcs = self.verify_tra_encrypted6(p, p.vpp_tra_sa, rxs)

        for dc in dcs:
            dc = IPv6(raw(dc[IPv6]))
            self.assertTrue(dc[IPv6ExtHdrHopByHop])
            self.assert_equal(dc[IPv6ExtHdrFragment].id, 2)

        # two extensions before ESP, one after
        tx = (Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac) /
              IPv6(src=self.tra_if.local_ip6,
                   dst=self.tra_if.remote_ip6) /
              IPv6ExtHdrHopByHop() /
              IPv6ExtHdrFragment(id=2, offset=200) /
              IPv6ExtHdrDestOpt() /
              Raw(b'\xff' * 200))

        rxs = self.send_and_expect(self.pg2, [tx], self.tra_if)
        dcs = self.verify_tra_encrypted6(p, p.vpp_tra_sa, rxs)

        for dc in dcs:
            dc = IPv6(raw(dc[IPv6]))
            self.assertTrue(dc[IPv6ExtHdrDestOpt])
            self.assertTrue(dc[IPv6ExtHdrHopByHop])
            self.assert_equal(dc[IPv6ExtHdrFragment].id, 2)


class IpsecTra6Tests(IpsecTra6):
    """ UT test methods for Transport v6 """
    def test_tra_basic6(self):
        """ ipsec v6 transport basic test """
        self.verify_tra_basic6(count=1)

    def test_tra_burst6(self):
        """ ipsec v6 transport burst test """
        self.verify_tra_basic6(count=257)


class IpsecTra6ExtTests(IpsecTra6):
    def test_tra_ext_hdrs_66(self):
        """ ipsec 6o6 tra extension headers test """
        self.verify_tra_66_ext_hdrs(self.params[socket.AF_INET6])


class IpsecTra46Tests(IpsecTra4Tests, IpsecTra6Tests):
    """ UT test methods for Transport v6 and v4"""
    pass


class IpsecTun4(object):
    """ verify methods for Tunnel v4 """
    def verify_counters4(self, p, count, n_frags=None, worker=None):
        if not n_frags:
            n_frags = count
        if (hasattr(p, "spd_policy_in_any")):
            pkts = p.spd_policy_in_any.get_stats(worker)['packets']
            self.assertEqual(pkts, count,
                             "incorrect SPD any policy: expected %d != %d" %
                             (count, pkts))

        if (hasattr(p, "tun_sa_in")):
            pkts = p.tun_sa_in.get_stats(worker)['packets']
            self.assertEqual(pkts, count,
                             "incorrect SA in counts: expected %d != %d" %
                             (count, pkts))
            pkts = p.tun_sa_out.get_stats(worker)['packets']
            self.assertEqual(pkts, n_frags,
                             "incorrect SA out counts: expected %d != %d" %
                             (count, pkts))

        self.assert_packet_counter_equal(self.tun4_encrypt_node_name, n_frags)
        self.assert_packet_counter_equal(self.tun4_decrypt_node_name[0], count)

    def verify_decrypted(self, p, rxs):
        for rx in rxs:
            self.assert_equal(rx[IP].src, p.remote_tun_if_host)
            self.assert_equal(rx[IP].dst, self.pg1.remote_ip4)
            self.assert_packet_checksums_valid(rx)

    def verify_esp_padding(self, sa, esp_payload, decrypt_pkt):
        align = sa.crypt_algo.block_size
        if align < 4:
            align = 4
        exp_len = (len(decrypt_pkt) + 2 + (align - 1)) & ~(align - 1)
        exp_len += sa.crypt_algo.iv_size
        exp_len += sa.crypt_algo.icv_size or sa.auth_algo.icv_size
        self.assertEqual(exp_len, len(esp_payload))

    def verify_encrypted(self, p, sa, rxs):
        decrypt_pkts = []
        for rx in rxs:
            if p.nat_header:
                self.assertEqual(rx[UDP].dport, 4500)
            self.assert_packet_checksums_valid(rx)
            self.assertEqual(len(rx) - len(Ether()), rx[IP].len)
            try:
                rx_ip = rx[IP]
                decrypt_pkt = p.vpp_tun_sa.decrypt(rx_ip)
                if not decrypt_pkt.haslayer(IP):
                    decrypt_pkt = IP(decrypt_pkt[Raw].load)
                if rx_ip.proto == socket.IPPROTO_ESP:
                    self.verify_esp_padding(sa, rx_ip[ESP].data, decrypt_pkt)
                decrypt_pkts.append(decrypt_pkt)
                self.assert_equal(decrypt_pkt.src, self.pg1.remote_ip4)
                self.assert_equal(decrypt_pkt.dst, p.remote_tun_if_host)
            except:
                self.logger.debug(ppp("Unexpected packet:", rx))
                try:
                    self.logger.debug(ppp("Decrypted packet:", decrypt_pkt))
                except:
                    pass
                raise
        pkts = reassemble4(decrypt_pkts)
        for pkt in pkts:
            self.assert_packet_checksums_valid(pkt)

    def verify_tun_44(self, p, count=1, payload_size=64, n_rx=None):
        self.vapi.cli("clear errors")
        self.vapi.cli("clear ipsec counters")
        self.vapi.cli("clear ipsec sa")
        if not n_rx:
            n_rx = count
        try:
            send_pkts = self.gen_encrypt_pkts(p, p.scapy_tun_sa, self.tun_if,
                                              src=p.remote_tun_if_host,
                                              dst=self.pg1.remote_ip4,
                                              count=count,
                                              payload_size=payload_size)
            recv_pkts = self.send_and_expect(self.tun_if, send_pkts, self.pg1)
            self.verify_decrypted(p, recv_pkts)

            send_pkts = self.gen_pkts(self.pg1, src=self.pg1.remote_ip4,
                                      dst=p.remote_tun_if_host, count=count,
                                      payload_size=payload_size)
            recv_pkts = self.send_and_expect(self.pg1, send_pkts,
                                             self.tun_if, n_rx)
            self.verify_encrypted(p, p.vpp_tun_sa, recv_pkts)

            for rx in recv_pkts:
                self.assertEqual(rx[IP].src, p.tun_src)
                self.assertEqual(rx[IP].dst, p.tun_dst)

        finally:
            self.logger.info(self.vapi.ppcli("show error"))
            self.logger.info(self.vapi.ppcli("show ipsec all"))

        self.logger.info(self.vapi.ppcli("show ipsec sa 0"))
        self.logger.info(self.vapi.ppcli("show ipsec sa 4"))
        self.verify_counters4(p, count, n_rx)

    def verify_tun_dropped_44(self, p, count=1, payload_size=64, n_rx=None):
        self.vapi.cli("clear errors")
        if not n_rx:
            n_rx = count
        try:
            send_pkts = self.gen_encrypt_pkts(p, p.scapy_tun_sa, self.tun_if,
                                              src=p.remote_tun_if_host,
                                              dst=self.pg1.remote_ip4,
                                              count=count)
            self.send_and_assert_no_replies(self.tun_if, send_pkts)

            send_pkts = self.gen_pkts(self.pg1, src=self.pg1.remote_ip4,
                                      dst=p.remote_tun_if_host, count=count,
                                      payload_size=payload_size)
            self.send_and_assert_no_replies(self.pg1, send_pkts)

        finally:
            self.logger.info(self.vapi.ppcli("show error"))
            self.logger.info(self.vapi.ppcli("show ipsec all"))

    def verify_tun_reass_44(self, p):
        self.vapi.cli("clear errors")
        self.vapi.ip_reassembly_enable_disable(
            sw_if_index=self.tun_if.sw_if_index, enable_ip4=True)

        try:
            send_pkts = self.gen_encrypt_pkts(p, p.scapy_tun_sa, self.tun_if,
                                              src=p.remote_tun_if_host,
                                              dst=self.pg1.remote_ip4,
                                              payload_size=1900,
                                              count=1)
            send_pkts = fragment_rfc791(send_pkts[0], 1400)
            recv_pkts = self.send_and_expect(self.tun_if, send_pkts,
                                             self.pg1, n_rx=1)
            self.verify_decrypted(p, recv_pkts)

            send_pkts = self.gen_pkts(self.pg1, src=self.pg1.remote_ip4,
                                      dst=p.remote_tun_if_host, count=1)
            recv_pkts = self.send_and_expect(self.pg1, send_pkts,
                                             self.tun_if)
            self.verify_encrypted(p, p.vpp_tun_sa, recv_pkts)

        finally:
            self.logger.info(self.vapi.ppcli("show error"))
            self.logger.info(self.vapi.ppcli("show ipsec all"))

        self.verify_counters4(p, 1, 1)
        self.vapi.ip_reassembly_enable_disable(
            sw_if_index=self.tun_if.sw_if_index, enable_ip4=False)

    def verify_tun_64(self, p, count=1):
        self.vapi.cli("clear errors")
        self.vapi.cli("clear ipsec sa")
        try:
            send_pkts = self.gen_encrypt_pkts6(p, p.scapy_tun_sa, self.tun_if,
                                               src=p.remote_tun_if_host6,
                                               dst=self.pg1.remote_ip6,
                                               count=count)
            recv_pkts = self.send_and_expect(self.tun_if, send_pkts, self.pg1)
            for recv_pkt in recv_pkts:
                self.assert_equal(recv_pkt[IPv6].src, p.remote_tun_if_host6)
                self.assert_equal(recv_pkt[IPv6].dst, self.pg1.remote_ip6)
                self.assert_packet_checksums_valid(recv_pkt)
            send_pkts = self.gen_pkts6(p, self.pg1, src=self.pg1.remote_ip6,
                                       dst=p.remote_tun_if_host6, count=count)
            recv_pkts = self.send_and_expect(self.pg1, send_pkts, self.tun_if)
            for recv_pkt in recv_pkts:
                try:
                    decrypt_pkt = p.vpp_tun_sa.decrypt(recv_pkt[IP])
                    if not decrypt_pkt.haslayer(IPv6):
                        decrypt_pkt = IPv6(decrypt_pkt[Raw].load)
                    self.assert_equal(decrypt_pkt.src, self.pg1.remote_ip6)
                    self.assert_equal(decrypt_pkt.dst, p.remote_tun_if_host6)
                    self.assert_packet_checksums_valid(decrypt_pkt)
                except:
                    self.logger.error(ppp("Unexpected packet:", recv_pkt))
                    try:
                        self.logger.debug(
                            ppp("Decrypted packet:", decrypt_pkt))
                    except:
                        pass
                    raise
        finally:
            self.logger.info(self.vapi.ppcli("show error"))
            self.logger.info(self.vapi.ppcli("show ipsec all"))

        self.verify_counters4(p, count)

    def verify_keepalive(self, p):
        pkt = (Ether(src=self.tun_if.remote_mac, dst=self.tun_if.local_mac) /
               IP(src=p.remote_tun_if_host, dst=self.tun_if.local_ip4) /
               UDP(sport=333, dport=4500) /
               Raw(b'\xff'))
        self.send_and_assert_no_replies(self.tun_if, pkt*31)
        self.assert_error_counter_equal(
            '/err/%s/NAT Keepalive' % self.tun4_input_node, 31)

        pkt = (Ether(src=self.tun_if.remote_mac, dst=self.tun_if.local_mac) /
               IP(src=p.remote_tun_if_host, dst=self.tun_if.local_ip4) /
               UDP(sport=333, dport=4500) /
               Raw(b'\xfe'))
        self.send_and_assert_no_replies(self.tun_if, pkt*31)
        self.assert_error_counter_equal(
            '/err/%s/Too Short' % self.tun4_input_node, 31)


class IpsecTun4Tests(IpsecTun4):
    """ UT test methods for Tunnel v4 """
    def test_tun_basic44(self):
        """ ipsec 4o4 tunnel basic test """
        self.verify_tun_44(self.params[socket.AF_INET], count=1)
        self.tun_if.admin_down()
        self.tun_if.resolve_arp()
        self.tun_if.admin_up()
        self.verify_tun_44(self.params[socket.AF_INET], count=1)

    def test_tun_reass_basic44(self):
        """ ipsec 4o4 tunnel basic reassembly test """
        self.verify_tun_reass_44(self.params[socket.AF_INET])

    def test_tun_burst44(self):
        """ ipsec 4o4 tunnel burst test """
        self.verify_tun_44(self.params[socket.AF_INET], count=127)


class IpsecTun6(object):
    """ verify methods for Tunnel v6 """
    def verify_counters6(self, p_in, p_out, count, worker=None):
        if (hasattr(p_in, "tun_sa_in")):
            pkts = p_in.tun_sa_in.get_stats(worker)['packets']
            self.assertEqual(pkts, count,
                             "incorrect SA in counts: expected %d != %d" %
                             (count, pkts))
        if (hasattr(p_out, "tun_sa_out")):
            pkts = p_out.tun_sa_out.get_stats(worker)['packets']
            self.assertEqual(pkts, count,
                             "incorrect SA out counts: expected %d != %d" %
                             (count, pkts))
        self.assert_packet_counter_equal(self.tun6_encrypt_node_name, count)
        self.assert_packet_counter_equal(self.tun6_decrypt_node_name[0], count)

    def verify_decrypted6(self, p, rxs):
        for rx in rxs:
            self.assert_equal(rx[IPv6].src, p.remote_tun_if_host)
            self.assert_equal(rx[IPv6].dst, self.pg1.remote_ip6)
            self.assert_packet_checksums_valid(rx)

    def verify_encrypted6(self, p, sa, rxs):
        for rx in rxs:
            self.assert_packet_checksums_valid(rx)
            self.assertEqual(len(rx) - len(Ether()) - len(IPv6()),
                             rx[IPv6].plen)
            self.assert_equal(rx[IPv6].hlim, p.outer_hop_limit)
            if p.outer_flow_label:
                self.assert_equal(rx[IPv6].fl, p.outer_flow_label)
            try:
                decrypt_pkt = p.vpp_tun_sa.decrypt(rx[IPv6])
                if not decrypt_pkt.haslayer(IPv6):
                    decrypt_pkt = IPv6(decrypt_pkt[Raw].load)
                self.assert_packet_checksums_valid(decrypt_pkt)
                self.assert_equal(decrypt_pkt.src, self.pg1.remote_ip6)
                self.assert_equal(decrypt_pkt.dst, p.remote_tun_if_host)
                self.assert_equal(decrypt_pkt.hlim, p.inner_hop_limit - 1)
                self.assert_equal(decrypt_pkt.fl, p.inner_flow_label)
            except:
                self.logger.debug(ppp("Unexpected packet:", rx))
                try:
                    self.logger.debug(ppp("Decrypted packet:", decrypt_pkt))
                except:
                    pass
                raise

    def verify_drop_tun_tx_66(self, p_in, count=1, payload_size=64):
        self.vapi.cli("clear errors")
        self.vapi.cli("clear ipsec sa")

        send_pkts = self.gen_pkts6(p_in, self.pg1, src=self.pg1.remote_ip6,
                                   dst=p_in.remote_tun_if_host, count=count,
                                   payload_size=payload_size)
        self.send_and_assert_no_replies(self.tun_if, send_pkts)
        self.logger.info(self.vapi.cli("sh punt stats"))

    def verify_drop_tun_rx_66(self, p_in, count=1, payload_size=64):
        self.vapi.cli("clear errors")
        self.vapi.cli("clear ipsec sa")

        send_pkts = self.gen_encrypt_pkts6(p_in, p_in.scapy_tun_sa,
                                           self.tun_if,
                                           src=p_in.remote_tun_if_host,
                                           dst=self.pg1.remote_ip6,
                                           count=count)
        self.send_and_assert_no_replies(self.tun_if, send_pkts)

    def verify_drop_tun_66(self, p_in, count=1, payload_size=64):
        self.verify_drop_tun_tx_66(p_in, count=count,
                                   payload_size=payload_size)
        self.verify_drop_tun_rx_66(p_in, count=count,
                                   payload_size=payload_size)

    def verify_tun_66(self, p_in, p_out=None, count=1, payload_size=64):
        self.vapi.cli("clear errors")
        self.vapi.cli("clear ipsec sa")
        if not p_out:
            p_out = p_in
        try:
            send_pkts = self.gen_encrypt_pkts6(p_in, p_in.scapy_tun_sa,
                                               self.tun_if,
                                               src=p_in.remote_tun_if_host,
                                               dst=self.pg1.remote_ip6,
                                               count=count,
                                               payload_size=payload_size)
            recv_pkts = self.send_and_expect(self.tun_if, send_pkts, self.pg1)
            self.verify_decrypted6(p_in, recv_pkts)

            send_pkts = self.gen_pkts6(p_in, self.pg1, src=self.pg1.remote_ip6,
                                       dst=p_out.remote_tun_if_host,
                                       count=count,
                                       payload_size=payload_size)
            recv_pkts = self.send_and_expect(self.pg1, send_pkts, self.tun_if)
            self.verify_encrypted6(p_out, p_out.vpp_tun_sa, recv_pkts)

            for rx in recv_pkts:
                self.assertEqual(rx[IPv6].src, p_out.tun_src)
                self.assertEqual(rx[IPv6].dst, p_out.tun_dst)

        finally:
            self.logger.info(self.vapi.ppcli("show error"))
            self.logger.info(self.vapi.ppcli("show ipsec all"))
        self.verify_counters6(p_in, p_out, count)

    def verify_tun_reass_66(self, p):
        self.vapi.cli("clear errors")
        self.vapi.ip_reassembly_enable_disable(
            sw_if_index=self.tun_if.sw_if_index, enable_ip6=True)

        try:
            send_pkts = self.gen_encrypt_pkts6(p, p.scapy_tun_sa, self.tun_if,
                                               src=p.remote_tun_if_host,
                                               dst=self.pg1.remote_ip6,
                                               count=1,
                                               payload_size=1850)
            send_pkts = fragment_rfc8200(send_pkts[0], 1, 1400, self.logger)
            recv_pkts = self.send_and_expect(self.tun_if, send_pkts,
                                             self.pg1, n_rx=1)
            self.verify_decrypted6(p, recv_pkts)

            send_pkts = self.gen_pkts6(p, self.pg1, src=self.pg1.remote_ip6,
                                       dst=p.remote_tun_if_host,
                                       count=1,
                                       payload_size=64)
            recv_pkts = self.send_and_expect(self.pg1, send_pkts,
                                             self.tun_if)
            self.verify_encrypted6(p, p.vpp_tun_sa, recv_pkts)
        finally:
            self.logger.info(self.vapi.ppcli("show error"))
            self.logger.info(self.vapi.ppcli("show ipsec all"))
        self.verify_counters6(p, p, 1)
        self.vapi.ip_reassembly_enable_disable(
            sw_if_index=self.tun_if.sw_if_index, enable_ip6=False)

    def verify_tun_46(self, p, count=1):
        """ ipsec 4o6 tunnel basic test """
        self.vapi.cli("clear errors")
        self.vapi.cli("clear ipsec sa")
        try:
            send_pkts = self.gen_encrypt_pkts(p, p.scapy_tun_sa, self.tun_if,
                                              src=p.remote_tun_if_host4,
                                              dst=self.pg1.remote_ip4,
                                              count=count)
            recv_pkts = self.send_and_expect(self.tun_if, send_pkts, self.pg1)
            for recv_pkt in recv_pkts:
                self.assert_equal(recv_pkt[IP].src, p.remote_tun_if_host4)
                self.assert_equal(recv_pkt[IP].dst, self.pg1.remote_ip4)
                self.assert_packet_checksums_valid(recv_pkt)
            send_pkts = self.gen_pkts(self.pg1, src=self.pg1.remote_ip4,
                                      dst=p.remote_tun_if_host4,
                                      count=count)
            recv_pkts = self.send_and_expect(self.pg1, send_pkts, self.tun_if)
            for recv_pkt in recv_pkts:
                try:
                    decrypt_pkt = p.vpp_tun_sa.decrypt(recv_pkt[IPv6])
                    if not decrypt_pkt.haslayer(IP):
                        decrypt_pkt = IP(decrypt_pkt[Raw].load)
                    self.assert_equal(decrypt_pkt.src, self.pg1.remote_ip4)
                    self.assert_equal(decrypt_pkt.dst, p.remote_tun_if_host4)
                    self.assert_packet_checksums_valid(decrypt_pkt)
                except:
                    self.logger.debug(ppp("Unexpected packet:", recv_pkt))
                    try:
                        self.logger.debug(ppp("Decrypted packet:",
                                              decrypt_pkt))
                    except:
                        pass
                    raise
        finally:
            self.logger.info(self.vapi.ppcli("show error"))
            self.logger.info(self.vapi.ppcli("show ipsec all"))
        self.verify_counters6(p, p, count)


class IpsecTun6Tests(IpsecTun6):
    """ UT test methods for Tunnel v6 """

    def test_tun_basic66(self):
        """ ipsec 6o6 tunnel basic test """
        self.verify_tun_66(self.params[socket.AF_INET6], count=1)

    def test_tun_reass_basic66(self):
        """ ipsec 6o6 tunnel basic reassembly test """
        self.verify_tun_reass_66(self.params[socket.AF_INET6])

    def test_tun_burst66(self):
        """ ipsec 6o6 tunnel burst test """
        self.verify_tun_66(self.params[socket.AF_INET6], count=257)


class IpsecTun6HandoffTests(IpsecTun6):
    """ UT test methods for Tunnel v6 with multiple workers """
    vpp_worker_count = 2

    def test_tun_handoff_66(self):
        """ ipsec 6o6 tunnel worker hand-off test """
        self.vapi.cli("clear errors")
        self.vapi.cli("clear ipsec sa")

        N_PKTS = 15
        p = self.params[socket.AF_INET6]

        # inject alternately on worker 0 and 1. all counts on the SA
        # should be against worker 0
        for worker in [0, 1, 0, 1]:
            send_pkts = self.gen_encrypt_pkts6(p, p.scapy_tun_sa, self.tun_if,
                                               src=p.remote_tun_if_host,
                                               dst=self.pg1.remote_ip6,
                                               count=N_PKTS)
            recv_pkts = self.send_and_expect(self.tun_if, send_pkts,
                                             self.pg1, worker=worker)
            self.verify_decrypted6(p, recv_pkts)

            send_pkts = self.gen_pkts6(p, self.pg1, src=self.pg1.remote_ip6,
                                       dst=p.remote_tun_if_host,
                                       count=N_PKTS)
            recv_pkts = self.send_and_expect(self.pg1, send_pkts,
                                             self.tun_if, worker=worker)
            self.verify_encrypted6(p, p.vpp_tun_sa, recv_pkts)

        # all counts against the first worker that was used
        self.verify_counters6(p, p, 4*N_PKTS, worker=0)


class IpsecTun4HandoffTests(IpsecTun4):
    """ UT test methods for Tunnel v4 with multiple workers """
    vpp_worker_count = 2

    def test_tun_handooff_44(self):
        """ ipsec 4o4 tunnel worker hand-off test """
        self.vapi.cli("clear errors")
        self.vapi.cli("clear ipsec sa")

        N_PKTS = 15
        p = self.params[socket.AF_INET]

        # inject alternately on worker 0 and 1. all counts on the SA
        # should be against worker 0
        for worker in [0, 1, 0, 1]:
            send_pkts = self.gen_encrypt_pkts(p, p.scapy_tun_sa, self.tun_if,
                                              src=p.remote_tun_if_host,
                                              dst=self.pg1.remote_ip4,
                                              count=N_PKTS)
            recv_pkts = self.send_and_expect(self.tun_if, send_pkts,
                                             self.pg1, worker=worker)
            self.verify_decrypted(p, recv_pkts)

            send_pkts = self.gen_pkts(self.pg1, src=self.pg1.remote_ip4,
                                      dst=p.remote_tun_if_host,
                                      count=N_PKTS)
            recv_pkts = self.send_and_expect(self.pg1, send_pkts,
                                             self.tun_if, worker=worker)
            self.verify_encrypted(p, p.vpp_tun_sa, recv_pkts)

        # all counts against the first worker that was used
        self.verify_counters4(p, 4*N_PKTS, worker=0)


class IpsecTun46Tests(IpsecTun4Tests, IpsecTun6Tests):
    """ UT test methods for Tunnel v6 & v4 """
    pass


class SpdFlowCacheTemplate(VppTestCase):
    @classmethod
    def setUpConstants(cls):
        super(SpdFlowCacheTemplate, cls).setUpConstants()
        # Override this method with required cmdline parameters e.g.
        # cls.vpp_cmdline.extend(["ipsec", "{",
        #                         "ipv4-outbound-spd-flow-cache on",
        #                         "}"])
        # cls.logger.info("VPP modified cmdline is %s" % " "
        #                 .join(cls.vpp_cmdline))

    def setUp(self):
        super(SpdFlowCacheTemplate, self).setUp()
        # store SPD objects so we can remove configs on tear down
        self.spd_objs = []
        self.spd_policies = []

    def tearDown(self):
        # remove SPD policies
        for obj in self.spd_policies:
            obj.remove_vpp_config()
        self.spd_policies = []
        # remove SPD items (interface bindings first, then SPD)
        for obj in reversed(self.spd_objs):
            obj.remove_vpp_config()
        self.spd_objs = []
        # close down pg intfs
        for pg in self.pg_interfaces:
            pg.unconfig_ip4()
            pg.admin_down()
        super(SpdFlowCacheTemplate, self).tearDown()

    def create_interfaces(self, num_ifs=2):
        # create interfaces pg0 ... pg<num_ifs>
        self.create_pg_interfaces(range(num_ifs))
        for pg in self.pg_interfaces:
            # put the interface up
            pg.admin_up()
            # configure IPv4 address on the interface
            pg.config_ip4()
            # resolve ARP, so that we know VPP MAC
            pg.resolve_arp()
        self.logger.info(self.vapi.ppcli("show int addr"))

    def spd_create_and_intf_add(self, spd_id, pg_list):
        spd = VppIpsecSpd(self, spd_id)
        spd.add_vpp_config()
        self.spd_objs.append(spd)
        for pg in pg_list:
            spdItf = VppIpsecSpdItfBinding(self, spd, pg)
            spdItf.add_vpp_config()
            self.spd_objs.append(spdItf)

    def get_policy(self, policy_type):
        e = VppEnum.vl_api_ipsec_spd_action_t
        if policy_type == "protect":
            return e.IPSEC_API_SPD_ACTION_PROTECT
        elif policy_type == "bypass":
            return e.IPSEC_API_SPD_ACTION_BYPASS
        elif policy_type == "discard":
            return e.IPSEC_API_SPD_ACTION_DISCARD
        else:
            raise Exception("Invalid policy type: %s", policy_type)

    def spd_add_rem_policy(self, spd_id, src_if, dst_if,
                           proto, is_out, priority, policy_type,
                           remove=False, all_ips=False):
        spd = VppIpsecSpd(self, spd_id)

        if all_ips:
            src_range_low = ip_address("0.0.0.0")
            src_range_high = ip_address("255.255.255.255")
            dst_range_low = ip_address("0.0.0.0")
            dst_range_high = ip_address("255.255.255.255")
        else:
            src_range_low = src_if.remote_ip4
            src_range_high = src_if.remote_ip4
            dst_range_low = dst_if.remote_ip4
            dst_range_high = dst_if.remote_ip4

        spdEntry = VppIpsecSpdEntry(self, spd, 0,
                                    src_range_low,
                                    src_range_high,
                                    dst_range_low,
                                    dst_range_high,
                                    proto,
                                    priority=priority,
                                    policy=self.get_policy(policy_type),
                                    is_outbound=is_out)

        if(remove is False):
            spdEntry.add_vpp_config()
            self.spd_policies.append(spdEntry)
        else:
            spdEntry.remove_vpp_config()
            self.spd_policies.remove(spdEntry)
        self.logger.info(self.vapi.ppcli("show ipsec all"))
        return spdEntry

    def create_stream(self, src_if, dst_if, pkt_count,
                      src_prt=1234, dst_prt=5678):
        packets = []
        for i in range(pkt_count):
            # create packet info stored in the test case instance
            info = self.create_packet_info(src_if, dst_if)
            # convert the info into packet payload
            payload = self.info_to_payload(info)
            # create the packet itself
            p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                 IP(src=src_if.remote_ip4, dst=dst_if.remote_ip4) /
                 UDP(sport=src_prt, dport=dst_prt) /
                 Raw(payload))
            # store a copy of the packet in the packet info
            info.data = p.copy()
            # append the packet to the list
            packets.append(p)
        # return the created packet list
        return packets

    def verify_capture(self, src_if, dst_if, capture):
        packet_info = None
        for packet in capture:
            try:
                ip = packet[IP]
                udp = packet[UDP]
                # convert the payload to packet info object
                payload_info = self.payload_to_info(packet)
                # make sure the indexes match
                self.assert_equal(payload_info.src, src_if.sw_if_index,
                                  "source sw_if_index")
                self.assert_equal(payload_info.dst, dst_if.sw_if_index,
                                  "destination sw_if_index")
                packet_info = self.get_next_packet_info_for_interface2(
                                src_if.sw_if_index,
                                dst_if.sw_if_index,
                                packet_info)
                # make sure we didn't run out of saved packets
                self.assertIsNotNone(packet_info)
                self.assert_equal(payload_info.index, packet_info.index,
                                  "packet info index")
                saved_packet = packet_info.data  # fetch the saved packet
                # assert the values match
                self.assert_equal(ip.src, saved_packet[IP].src,
                                  "IP source address")
                # ... more assertions here
                self.assert_equal(udp.sport, saved_packet[UDP].sport,
                                  "UDP source port")
            except Exception as e:
                self.logger.error(ppp("Unexpected or invalid packet:",
                                  packet))
                raise
        remaining_packet = self.get_next_packet_info_for_interface2(
                src_if.sw_if_index,
                dst_if.sw_if_index,
                packet_info)
        self.assertIsNone(remaining_packet,
                          "Interface %s: Packet expected from interface "
                          "%s didn't arrive" % (dst_if.name, src_if.name))

    def verify_policy_match(self, pkt_count, spdEntry):
        self.logger.info(
            "XXXX %s %s", str(spdEntry), str(spdEntry.get_stats()))
        matched_pkts = spdEntry.get_stats().get('packets')
        self.logger.info(
            "Policy %s matched: %d pkts", str(spdEntry), matched_pkts)
        self.assert_equal(pkt_count, matched_pkts)

    def get_spd_flow_cache_entries(self):
        """ 'show ipsec spd' output:
        ip4-outbound-spd-flow-cache-entries: 0
        """
        show_ipsec_reply = self.vapi.cli("show ipsec spd")
        # match the relevant section of 'show ipsec spd' output
        regex_match = re.search(
            'ip4-outbound-spd-flow-cache-entries: (.*)',
            show_ipsec_reply, re.DOTALL)
        if regex_match is None:
            raise Exception("Unable to find spd flow cache entries \
                in \'show ipsec spd\' CLI output - regex failed to match")
        else:
            try:
                num_entries = int(regex_match.group(1))
            except ValueError:
                raise Exception("Unable to get spd flow cache entries \
                from \'show ipsec spd\' string: %s", regex_match.group(0))
            self.logger.info("%s", regex_match.group(0))
        return num_entries

    def verify_num_outbound_flow_cache_entries(self, expected_elements):
        self.assertEqual(self.get_spd_flow_cache_entries(), expected_elements)

    def crc32_supported(self):
        # lscpu is part of util-linux package, available on all Linux Distros
        stream = os.popen('lscpu')
        cpu_info = stream.read()
        # feature/flag "crc32" on Aarch64 and "sse4_2" on x86
        # see vppinfra/crc32.h
        if "crc32" or "sse4_2" in cpu_info:
            self.logger.info("\ncrc32 supported:\n" + cpu_info)
            return True
        else:
            self.logger.info("\ncrc32 NOT supported:\n" + cpu_info)
            return False


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
