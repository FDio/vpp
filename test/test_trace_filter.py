#!/usr/bin/env python3

import unittest
import secrets
import socket

from framework import VppTestCase, VppTestRunner
from vpp_ipip_tun_interface import VppIpIpTunInterface
from vpp_papi import VppEnum
from vpp_ipsec import VppIpsecSA, VppIpsecSpd, VppIpsecSpdItfBinding, VppIpsecSpdEntry
from vpp_ip_route import VppIpRoute, VppRoutePath, FibPathProto

from scapy.contrib.geneve import GENEVE
from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.vxlan import VXLAN
from scapy.layers.ipsec import ESP, SecurityAssociation
from scapy.compat import raw
from scapy.utils import rdpcap


class TemplateTraceFilter(VppTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        self.create_pg_interfaces(range(2))
        self.pg0.generate_remote_hosts(11)
        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    def tearDown(self):
        super().tearDown()
        for i in self.pg_interfaces:
            i.unconfig()
            i.admin_down()

    def cli(self, cmd):
        r = self.vapi.cli_return_response(cmd)
        if r.retval != 0:
            s = (
                "reply '%s'" % r.reply
                if hasattr(r, "reply")
                else "retval '%s'" % r.retval
            )
            raise RuntimeError("cli command '%s' FAIL with %s" % (cmd, s))
        return r

    # check number of hits for classifier
    def assert_hits(self, n):
        r = self.cli("show classify table verbose")
        self.assertTrue(r.reply.find("hits %i" % n) != -1)

    def clear(self):
        self.cli("clear trace")

    def add_trace_filter(self, mask, match):
        self.cli("classify filter trace mask %s match %s" % (mask, match))
        self.clear()
        self.cli("trace add pg-input 1000 filter")

    def del_trace_filters(self):
        self.cli("classify filter trace del")
        r = self.cli("show classify filter")
        s = "packet tracer:                 first table none"
        self.assertTrue(r.reply.find(s) != -1)

    def del_pcap_filters(self):
        self.cli("classify filter pcap del")
        r = self.cli("show classify filter")
        s = "pcap rx/tx/drop:               first table none"
        self.assertTrue(r.reply.find(s) != -1)

    # install a classify rule, inject traffic and check for hits
    def assert_classify(self, mask, match, packets, n=None):
        self.add_trace_filter("hex %s" % mask, "hex %s" % match)
        self.send_and_expect(self.pg0, packets, self.pg1, trace=False)
        self.assert_hits(n if n is not None else len(packets))
        self.del_trace_filters()


class TestTracefilter(TemplateTraceFilter):
    """Packet Tracer Filter Test"""

    def test_basic(self):
        """Packet Tracer Filter Test"""
        self.add_trace_filter(
            "l3 ip4 src", "l3 ip4 src %s" % self.pg0.remote_hosts[5].ip4
        )
        self.add_trace_filter(
            "l3 ip4 proto l4 src_port", "l3 ip4 proto 17 l4 src_port 2345"
        )
        # the packet we are trying to match
        p = list()
        for i in range(100):
            src = self.pg0.remote_hosts[i % len(self.pg0.remote_hosts)].ip4
            p.append(
                (
                    Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
                    / IP(src=src, dst=self.pg1.remote_ip4)
                    / UDP(sport=1234, dport=2345)
                    / Raw("\xa5" * 100)
                )
            )
        for i in range(17):
            p.append(
                (
                    Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
                    / IP(src=self.pg0.remote_hosts[0].ip4, dst=self.pg1.remote_ip4)
                    / UDP(sport=2345, dport=1234)
                    / Raw("\xa5" * 100)
                )
            )

        self.send_and_expect(self.pg0, p, self.pg1, trace=False)

        # Check for 9 and 17 classifier hits, which is the right answer
        self.assert_hits(9)
        self.assert_hits(17)

        self.del_trace_filters()

    def test_encap(self):
        """Packet Tracer Filter Test with encap"""

        # the packet we are trying to match
        p = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4)
            / UDP()
            / VXLAN()
            / Ether()
            / IP()
            / UDP()
            / GENEVE(vni=1234)
            / Ether()
            / IP(src="192.168.4.167")
            / UDP()
            / Raw("\xa5" * 100)
        )

        #
        # compute filter mask & value
        # we compute it by XOR'ing a template packet with a modified packet
        # we need to set checksums to 0 to make sure scapy will not recompute
        # them
        #
        tmpl = (
            Ether()
            / IP(chksum=0)
            / UDP(chksum=0)
            / VXLAN()
            / Ether()
            / IP(chksum=0)
            / UDP(chksum=0)
            / GENEVE(vni=0)
            / Ether()
            / IP(src="0.0.0.0", chksum=0)
        )
        ori = raw(tmpl)

        # the mask
        tmpl[GENEVE].vni = 0xFFFFFF
        user = tmpl[GENEVE].payload
        user[IP].src = "255.255.255.255"
        new = raw(tmpl)
        mask = "".join(("{:02x}".format(o ^ n) for o, n in zip(ori, new)))

        # this does not match (wrong vni)
        tmpl[GENEVE].vni = 1
        user = tmpl[GENEVE].payload
        user[IP].src = "192.168.4.167"
        new = raw(tmpl)
        match = "".join(("{:02x}".format(o ^ n) for o, n in zip(ori, new)))
        self.assert_classify(mask, match, [p] * 11, 0)

        # this must match
        tmpl[GENEVE].vni = 1234
        new = raw(tmpl)
        match = "".join(("{:02x}".format(o ^ n) for o, n in zip(ori, new)))
        self.assert_classify(mask, match, [p] * 17)

    def test_pcap(self):
        """Packet Capture Filter Test"""
        self.cli(
            "classify filter pcap mask l3 ip4 src match l3 ip4 src %s"
            % self.pg0.remote_hosts[5].ip4
        )
        self.cli(
            "classify filter pcap "
            "mask l3 ip4 proto l4 src_port "
            "match l3 ip4 proto 17 l4 src_port 2345"
        )
        self.cli(
            "pcap trace rx tx max 1000 intfc pg0 "
            "file vpp_test_trace_filter_test_pcap.pcap filter"
        )
        # the packet we are trying to match
        p = list()
        for i in range(100):
            src = self.pg0.remote_hosts[i % len(self.pg0.remote_hosts)].ip4
            p.append(
                (
                    Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
                    / IP(src=src, dst=self.pg1.remote_ip4)
                    / UDP(sport=1234, dport=2345)
                    / Raw("\xa5" * 100)
                )
            )
        for i in range(17):
            p.append(
                (
                    Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
                    / IP(src=self.pg0.remote_hosts[0].ip4, dst=self.pg1.remote_ip4)
                    / UDP(sport=2345, dport=1234)
                    / Raw("\xa5" * 100)
                )
            )

        self.send_and_expect(self.pg0, p, self.pg1, trace=False)

        # Check for 9 and 17 classifier hits, which is the right answer
        self.assert_hits(9)
        self.assert_hits(17)

        self.cli("pcap trace rx tx off")
        self.del_pcap_filters()

        # check captured pcap
        pcap = rdpcap("/tmp/vpp_test_trace_filter_test_pcap.pcap")
        self.assertEqual(len(pcap), 9 + 17)
        p_ = str(p[5])
        for i in range(9):
            self.assertEqual(str(pcap[i]), p_)
        p_ = str(p[100])
        for i in range(9, 9 + 17):
            self.assertEqual(str(pcap[i]), p_)

    def test_pcap_drop(self):
        """Drop Packet Capture Filter Test"""
        self.cli(
            "pcap trace drop max 1000 "
            "error {ip4-udp-lookup}.{no_listener} "
            "file vpp_test_trace_filter_test_pcap_drop.pcap"
        )
        # the packet we are trying to match
        p = list()
        for i in range(17):
            # this packet should be forwarded
            p.append(
                (
                    Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
                    / IP(src=self.pg0.remote_hosts[0].ip4, dst=self.pg1.remote_ip4)
                    / UDP(sport=2345, dport=1234)
                    / Raw("\xa5" * 100)
                )
            )
            # this packet should be captured (no listener)
            p.append(
                (
                    Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
                    / IP(src=self.pg0.remote_hosts[0].ip4, dst=self.pg0.local_ip4)
                    / UDP(sport=2345, dport=1234)
                    / Raw("\xa5" * 100)
                )
            )
        # this packet will be blackholed but not captured
        p.append(
            (
                Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
                / IP(src=self.pg0.remote_hosts[0].ip4, dst="0.0.0.0")
                / UDP(sport=2345, dport=1234)
                / Raw("\xa5" * 100)
            )
        )

        self.send_and_expect(self.pg0, p, self.pg1, n_rx=17, trace=False)

        self.cli("pcap trace drop off")

        # check captured pcap
        pcap = rdpcap("/tmp/vpp_test_trace_filter_test_pcap_drop.pcap")
        self.assertEqual(len(pcap), 17)


class TestTraceFilterInner(TemplateTraceFilter):
    """Packet Tracer Filter Inner Test"""

    extra_vpp_plugin_config = [
        "plugin tracenode_plugin.so {enable}",
    ]

    def add_trace_filter(self, mask, match, tn_feature_intfc_index=None):
        if tn_feature_intfc_index is not None:
            self.logger.info("fffff")
            self.vapi.tracenode_feature(sw_if_index=tn_feature_intfc_index)
        super().add_trace_filter(mask, match)

    def del_trace_filters(self, tn_feature_intfc_index=None):
        if tn_feature_intfc_index is not None:
            self.vapi.tracenode_feature(
                sw_if_index=tn_feature_intfc_index, enable=False
            )
        super().del_trace_filters()

    def __add_sa(self, id_, tun_src, tun_dst):
        # AES-CTR-128 / SHA2-256
        crypto_key_length = 16
        salt_length = 4
        integ_key_lenght = 16
        crypto_key = secrets.token_bytes(crypto_key_length)
        salt = secrets.randbits(salt_length * 8)
        integ_key = secrets.token_bytes(integ_key_lenght)

        flags = VppEnum.vl_api_ipsec_sad_flags_t.IPSEC_API_SAD_FLAG_UDP_ENCAP

        vpp_sa_in = VppIpsecSA(
            test=self,
            id=id_,
            spi=id_,
            integ_alg=VppEnum.vl_api_ipsec_integ_alg_t.IPSEC_API_INTEG_ALG_SHA_256_128,
            integ_key=integ_key,
            crypto_alg=VppEnum.vl_api_ipsec_crypto_alg_t.IPSEC_API_CRYPTO_ALG_AES_CTR_128,
            crypto_key=crypto_key,
            proto=VppEnum.vl_api_ipsec_proto_t.IPSEC_API_PROTO_ESP,
            flags=flags,
            salt=salt,
            tun_src=tun_src,
            tun_dst=tun_dst,
            udp_src=4500,
            udp_dst=4500,
        )
        vpp_sa_in.add_vpp_config()

        scapy_sa_in = SecurityAssociation(
            ESP,
            spi=id_,
            crypt_algo="AES-CTR",
            crypt_key=crypto_key + salt.to_bytes(salt_length, "big"),
            auth_algo="SHA2-256-128",
            auth_key=integ_key,
            tunnel_header=IP(src=tun_src, dst=tun_dst),
            nat_t_header=UDP(sport=4500, dport=4500),
        )

        id_ += 1

        vpp_sa_out = VppIpsecSA(
            test=self,
            id=id_,
            spi=id_,
            integ_alg=VppEnum.vl_api_ipsec_integ_alg_t.IPSEC_API_INTEG_ALG_SHA_256_128,
            integ_key=integ_key,
            crypto_alg=VppEnum.vl_api_ipsec_crypto_alg_t.IPSEC_API_CRYPTO_ALG_AES_CTR_128,
            crypto_key=crypto_key,
            proto=VppEnum.vl_api_ipsec_proto_t.IPSEC_API_PROTO_ESP,
            flags=flags,
            salt=salt,
            tun_src=tun_dst,
            tun_dst=tun_src,
            udp_src=4500,
            udp_dst=4500,
        )
        vpp_sa_out.add_vpp_config()

        scapy_sa_out = SecurityAssociation(
            ESP,
            spi=id_,
            crypt_algo="AES-CTR",
            crypt_key=crypto_key + salt.to_bytes(salt_length, "big"),
            auth_algo="SHA2-256-128",
            auth_key=integ_key,
            tunnel_header=IP(src=tun_dst, dst=tun_src),
            nat_t_header=UDP(sport=4500, dport=4500),
        )

        return vpp_sa_in, scapy_sa_in, vpp_sa_out, scapy_sa_out

    def __gen_encrypt_pkt(self, scapy_sa, pkt):
        return Ether(
            src=self.pg0.local_mac, dst=self.pg0.remote_mac
        ) / scapy_sa.encrypt(pkt)

    def test_encrypted_encap(self):
        """Packet Tracer Filter Test with encrypted encap"""

        vpp_sa_in, scapy_sa_in, vpp_sa_out, _ = self.__add_sa(
            1, self.pg0.local_ip4, self.pg0.remote_ip4
        )

        spd = VppIpsecSpd(self, 1)
        spd.add_vpp_config()

        spd_binding = VppIpsecSpdItfBinding(self, spd, self.pg0)
        spd_binding.add_vpp_config()

        spd_entry = VppIpsecSpdEntry(
            self,
            spd,
            1,
            self.pg0.local_ip4,
            self.pg0.local_ip4,
            self.pg0.remote_ip4,
            self.pg0.remote_ip4,
            socket.IPPROTO_ESP,
            policy=VppEnum.vl_api_ipsec_spd_action_t.IPSEC_API_SPD_ACTION_PROTECT,
            is_outbound=0,
        ).add_vpp_config()

        # the inner packet we are trying to match
        inner_pkt = (
            IP(src=self.pg1.local_ip4, dst=self.pg1.remote_ip4)
            / TCP(sport=1234, dport=4321)
            / Raw(b"\xa5" * 100)
        )
        pkt = self.__gen_encrypt_pkt(scapy_sa_in, inner_pkt)

        # self.add_trace_filter("l3 ip4 src", f"l3 ip4 src {self.pg0.local_ip4}")

        self.add_trace_filter(
            "l2 none l3 ip4 src proto l4 dst_port",
            f"l2 none l3 ip4 src {self.pg1.local_ip4} proto 6 l4 dst_port 4321",
            tn_feature_intfc_index=self.pg0.sw_if_index,
        )

        self.logger.info("Sending packet with matching inner")
        self.send_and_expect(self.pg0, pkt * 67, self.pg1, trace=False)
        self.assert_hits(67)
        self.clear()

        self.logger.info("Sending packet with wrong inner port")
        inner_pkt[TCP].dport = 1111
        pkt = self.__gen_encrypt_pkt(scapy_sa_in, inner_pkt)
        self.send_and_expect(self.pg0, pkt * 67, self.pg1, trace=False)
        # the classify session should still have the 67 previous hits.
        # In another way, the delta is 0
        self.assert_hits(67)
        self.clear()

        self.logger.info("Sending packet with wrong source address")
        inner_pkt[IP].src = "1.2.3.4"
        inner_pkt[TCP].dport = 4321
        pkt = self.__gen_encrypt_pkt(scapy_sa_in, inner_pkt)
        self.send_and_expect(self.pg0, pkt * 67, self.pg1, trace=False)
        self.assert_hits(67)
        self.clear()

        self.del_trace_filters(tn_feature_intfc_index=self.pg0.sw_if_index)

        spd_entry.remove_vpp_config()
        spd_binding.remove_vpp_config()
        spd.remove_vpp_config()
        vpp_sa_in.remove_vpp_config()
        vpp_sa_out.remove_vpp_config()


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
