# -*- coding: utf-8 eval: (yapf-mode 1) -*-
# SPDX-License-Identifier: Apache-2.0
#
# July 15 2019, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2019, LabN Consulting, L.L.C.
# All Rights Reserved.
#
import socket
import struct

from scapy.layers.ipsec import ESP
from scapy.layers.inet import IP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from template_ipsec import TemplateIpsec
from util import ppp

# from vpp_ipsec_tun_interface import VppIpsecTunInterface
from vpp_ipsec import VppIpsecInterface, VppIpsecSA, VppIpsecTunProtect
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_papi import VppEnum  # pylint: disable=E0401
import scapy_handlers.iptfs as iptfs

PING_OVERHEAD = len(IP() / ICMP())
# BITRATE = 40 * 1000 * 1000
MAXDELAY = 200000
MTU = 1500
# Calculate bitrate to send a packet every 1ms (~12Mbps)
BITRATE = (MTU + 14 + 4 + 8 + 12) * 8 * 1000
REWIN = 5

if True:
    # XXX setting WORKER to 3 exceeding the workers doesn't cleanup well after failure.

    TFS_BASE_CONFIG = (
        (
            "iptfs-no-pad-only iptfs-ethernet-bitrate {BITRATE} "
            + "iptfs-packet-size {MTU} iptfs-max-delay-us {MAXDELAY} "
            + "iptfs-reorder-window {REWIN}"
        )
        .format(BITRATE=BITRATE, MTU=MTU, MAXDELAY=MAXDELAY, REWIN=REWIN)
        .encode("ascii")
    )
else:
    WORKER = 2
    DWORKER = 1
    # XXX setting WORKER to 3 exceeding the workers doesn't cleanup well after failure.

    TFS_BASE_CONFIG = (
        (
            "iptfs-no-pad-only iptfs-ethernet-bitrate {BITRATE} "
            + "iptfs-packet-size {MTU} iptfs-max-delay-us {MAXDELAY} "
            + "iptfs-reorder-window {REWIN} "
            + "iptfs-worker {WORKER}"
            + "iptfs-decap-worker {DWORKER}"
        )
        .format(
            BITRATE=BITRATE,
            MTU=MTU,
            MAXDELAY=MAXDELAY,
            REWIN=REWIN,
            WORKER=WORKER,
            DWORKER=DWORKER,
        )
        .encode("ascii")
    )


def config_tun_params(p, encryption_type, tun_if, mtu=1400, logger=None):
    ip_class_by_addr_type = {socket.AF_INET: IP, socket.AF_INET6: IPv6}
    use_esn = bool(
        p.flags & (VppEnum.vl_api_ipsec_sad_flags_t.IPSEC_API_SAD_FLAG_USE_ESN)
    )
    if logger is not None:
        logger.info("config_tun_params: auth_algo {}".format(p.auth_algo))
        logger.info("config_tun_params: crypt_algo {}".format(p.crypt_algo))
    p.scapy_tun_sa = iptfs.SecurityAssociation(
        encryption_type,
        spi=p.scapy_tun_spi,
        crypt_algo=p.crypt_algo,
        crypt_key=p.crypt_key + p.crypt_salt,
        auth_algo=p.auth_algo,
        auth_key=p.auth_key,
        tunnel_header=ip_class_by_addr_type[p.addr_type](
            src=tun_if.remote_addr[p.addr_type], dst=tun_if.local_addr[p.addr_type]
        ),
        nat_t_header=p.nat_header,
        esn_en=use_esn,
        mtu=mtu,
    )
    p.vpp_tun_sa = iptfs.SecurityAssociation(
        encryption_type,
        spi=p.vpp_tun_spi,
        crypt_algo=p.crypt_algo,
        crypt_key=p.crypt_key + p.crypt_salt,
        auth_algo=p.auth_algo,
        auth_key=p.auth_key,
        tunnel_header=ip_class_by_addr_type[p.addr_type](
            dst=tun_if.remote_addr[p.addr_type], src=tun_if.local_addr[p.addr_type]
        ),
        nat_t_header=p.nat_header,
        esn_en=use_esn,
        mtu=mtu,
    )


class TemplateIPTFS(TemplateIpsec):
    pg0 = pg1 = pg2 = None

    def gen_pkts(  # pylint: disable=W0221
        self,
        sw_intf,
        src,
        dst,
        count=1,
        payload_size=54,
        payload_spread=0,
        payload_sizes=None,
    ):
        if not payload_spread and not payload_sizes:
            return [
                Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac)
                / IP(src=src, dst=dst)
                / ICMP(seq=i + 1)
                / Raw("X" * payload_size)
                for i in range(count)
            ]

        if not payload_spread:
            pslen = len(payload_sizes)
            for i in range(count):
                return [
                    Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac)
                    / IP(src=src, dst=dst)
                    / ICMP(seq=i + 1)
                    / Raw("X" * payload_sizes[i % pslen])
                    for i in range(count)
                ]
        else:
            pkts = []
            start = payload_size
            end = payload_spread
            psize = start
            for i in range(count):
                pkts.append(
                    Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac)
                    / IP(src=src, dst=dst)
                    / ICMP(seq=i + 1)
                    / Raw("X" * (psize))
                )
                psize += 1
                if psize == end:
                    psize = start
            return pkts


class _TemplateIPTFS4(TemplateIPTFS):
    """Ipsec IPTFS/ESP - TUN tests

        TUNNEL MODE:

         ------   encrypt   ---   plain   ---
    VPP |tun_if| <-------  |VPP| <------ |pg1| Scapy
         ------             ---           ---

         ------   decrypt   ---   plain   ---
    VPP |tun_if| ------->  |VPP| ------> |pg1| Scapy
         ------             ---           ---

    """

    encryption_type = ESP
    tun4_encrypt_node_name = "esp4-encrypt-tun"
    tun4_decrypt_node_name = "esp4-decrypt-tun"
    tfs_config = (
        b"iptfs-no-pad-only iptfs-bitrate 1m "
        + b"iptfs-packet-size 1500 iptfs-max-delay-us 1000000"
    )
    num_workers = 3

    # For some reason our multi-threading is causing queue backup
    rx_qlen = 256

    dpdk_crypto_dev = ""
    """ example value: "vdev crypto_aesni_mb" """

    @classmethod
    def setUpClass(cls):
        super(_TemplateIPTFS4, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(_TemplateIPTFS4, cls).tearDownClass()

    @classmethod
    def setUpConstants(cls):
        super(_TemplateIPTFS4, cls).setUpConstants()
        i = cls.vpp_cmdline.index("nodaemon")
        cls.vpp_cmdline.insert(i + 1, "nosyslog")

        i = cls.vpp_cmdline.index("main-core")
        cls.vpp_cmdline.insert(i, "workers")
        cls.vpp_cmdline.insert(i + 1, str(cls.num_workers))

        if cls.dpdk_crypto_dev:
            i = cls.vpp_cmdline.index("api-trace")
            cls.vpp_cmdline.insert(i, "dpdk { no-pci " + cls.dpdk_crypto_dev + " }")
            i = cls.vpp_cmdline.index("dpdk_plugin.so")
            cls.vpp_cmdline[i + 2] = "enable"

        # pg is running out of buffers.
        cls.vpp_cmdline.extend(
            ["buffers", "{", "buffers-per-numa", str(32 * 1024), "}"]
        )

        # XXX this just doesn't work for some reason.
        # cls.vpp_cmdline.extend([
        #     "buffers", "{", "buffers-per-numa", "4000", "default", "data-size",
        #     str(1024 * 10), "}"
        # ])

        cls.logger.info("NEW vpp_cmdline args: %s", cls.vpp_cmdline)
        cls.logger.info("NEW vpp_cmdline: %s", " ".join(cls.vpp_cmdline))

    @classmethod
    def pg_start(cls, trace=True, clearTrace=True):
        if trace:
            if clearTrace:
                cls.vapi.cli("clear trace")
            if cls.dpdk_crypto_dev:
                cls.vapi.cli("trace add dpdk-crypto-input 1000")
            cls.vapi.cli("trace add iptfs-encap-enq 1000")
            cls.vapi.cli("trace add iptfs-encap4-tun 1000")
            cls.vapi.cli("trace add iptfs-encap6-tun 1000")
            cls.vapi.cli("trace add iptfs-output 1000")
            cls.vapi.cli("trace add iptfs-pacer 1000")
        # set clearTrace false because we don't want to wipe out
        # the trace adds we just did above
        super(_TemplateIPTFS4, cls).pg_start(trace, clearTrace=False)

    def setup_params(self):
        super(_TemplateIPTFS4, self).setup_params()

        for param in self.params.values():
            # 256 bit key
            # 32 * 8 == 256
            ####################01234567801234567899012345678901
            param.crypt_key = b"JPjyOWBeVEQiMe7hJPjyOWBeVEQiMe7h"
            param.crypt_salt = struct.pack("!L", 0)

            # Use GCM-256
            param.crypt_algo_vpp_id = (
                VppEnum.vl_api_ipsec_crypto_alg_t.IPSEC_API_CRYPTO_ALG_AES_GCM_256
            )
            param.crypt_algo = "AES-GCM"  # scapy name

            # # Use CTR-256
            # param.crypt_algo_vpp_id = (VppEnum.vl_api_ipsec_crypto_alg_t.
            #                            IPSEC_API_CRYPTO_ALG_AES_CTR_256)
            # param.crypt_algo = 'AES-CTR'  # scapy name

            # Any crypto
            if param.crypt_algo != "AES-GCM":
                param.auth_algo_vpp_id = (
                    VppEnum.vl_api_ipsec_integ_alg_t.IPSEC_API_INTEG_ALG_SHA1_96
                )
                param.auth_algo = "HMAC-SHA1-96"
                ##################01234567801234567899012345678901
                param.auth_key = b"JPjyOWBeVEQiMe7"
                # param.auth_key = ""
            else:
                param.auth_algo_vpp_id = (
                    VppEnum.vl_api_ipsec_integ_alg_t.IPSEC_API_INTEG_ALG_NONE
                )
                param.auth_algo = None
                param.auth_key = b""

    def setUp(self):
        super(_TemplateIPTFS4, self).setUp()

        self.tun_if = self.pg0

        p = self.ipv4_params

        if self.dpdk_crypto_dev:
            # self.vapi.cli("ipsec select backend esp 1")
            import time

            time.sleep(1)

        # outflags = (VppEnum.vl_api_ipsec_sad_flags_t.IPSEC_API_SAD_FLAG_IS_TUNNEL
        #             | VppEnum.vl_api_ipsec_sad_flags_t.IPSEC_API_SAD_FLAG_USE_ESN
        #             | VppEnum.vl_api_ipsec_sad_flags_t.IPSEC_API_SAD_FLAG_USE_ANTI_REPLAY)
        outflags = (
            p.flags | VppEnum.vl_api_ipsec_sad_flags_t.IPSEC_API_SAD_FLAG_IS_TUNNEL
        )
        inflags = (
            outflags | VppEnum.vl_api_ipsec_sad_flags_t.IPSEC_API_SAD_FLAG_IS_INBOUND
        )

        tfst = VppEnum.vl_api_ipsec_sad_tfs_type_t

        p.tun_sa_in = VppIpsecSA(
            self,
            id=p.scapy_tun_sa_id,
            spi=p.scapy_tun_spi,
            integ_alg=p.auth_algo_vpp_id,
            integ_key=p.auth_key,
            crypto_alg=p.crypt_algo_vpp_id,
            crypto_key=p.crypt_key,
            proto=VppEnum.vl_api_ipsec_proto_t.IPSEC_API_PROTO_ESP,
            tun_src=self.tun_if.remote_addr[p.addr_type],
            tun_dst=self.tun_if.local_addr[p.addr_type],
            flags=inflags,
            salt=p.salt,
            tfs_type=tfst.IPSEC_API_SAD_TFS_TYPE_IPTFS_NOCC,
            tfs_config=self.tfs_config,
        )
        p.tun_sa_in.add_vpp_config()

        p.tun_sa_out = VppIpsecSA(
            self,
            id=p.vpp_tun_sa_id,
            spi=p.vpp_tun_spi,
            integ_alg=p.auth_algo_vpp_id,
            integ_key=p.auth_key,
            crypto_alg=p.crypt_algo_vpp_id,
            crypto_key=p.crypt_key,
            proto=VppEnum.vl_api_ipsec_proto_t.IPSEC_API_PROTO_ESP,
            tun_src=self.tun_if.local_addr[p.addr_type],
            tun_dst=self.tun_if.remote_addr[p.addr_type],
            flags=outflags,
            salt=p.salt,
            tfs_type=tfst.IPSEC_API_SAD_TFS_TYPE_IPTFS_NOCC,
            tfs_config=self.tfs_config,
        )
        p.tun_sa_out.add_vpp_config()

        p.tun_if = VppIpsecInterface(self)
        p.tun_if.add_vpp_config()

        # Try admin up prior to protect
        # This works the other doesn't
        p.tun_if.admin_up()

        p.tun_protect_if = VppIpsecTunProtect(
            self, p.tun_if, p.tun_sa_out, [p.tun_sa_in]
        )
        p.tun_protect_if.add_vpp_config()

        # p.tun_if = VppIpsecTunInterface(self,
        #                                 self.pg0,
        #                                 p.vpp_tun_spi,
        #                                 p.scapy_tun_spi,
        #                                 p.crypt_algo_vpp_id,
        #                                 p.crypt_key,
        #                                 p.crypt_key,
        #                                 p.auth_algo_vpp_id,
        #                                 p.auth_key,
        #                                 p.auth_key,
        #                                 tfs_type=tfst.IPSEC_API_SAD_TFS_TYPE_IPTFS_NOCC,
        #                                 tfs_config=self.tfs_config)
        # p.tun_if.add_vpp_config()
        p.tun_if.config_ip4()
        # p.tun_if.config_ip6()

        VppIpRoute(
            self,
            p.remote_tun_if_host,
            32,
            [VppRoutePath(p.tun_if.remote_ip4, 0xFFFFFFFF)],
        ).add_vpp_config()

        # VppIpRoute(self,
        #            p.remote_tun_if_host6,
        #            128, [
        #                VppRoutePath(p.tun_if.remote_ip6,
        #                             0xffffffff,
        #                             proto=DpoProto.DPO_PROTO_IP6)
        #            ],
        #            is_ip6=1).add_vpp_config()
        # self.logger.info(self.vapi.cli("show ipsec backend"))
        self.logger.info(self.vapi.cli("show int"))
        self.logger.info(self.vapi.cli("show int address"))

    def tearDown(self):
        if not self.vpp_dead:
            self.vapi.cli("show hardware")
        super(_TemplateIPTFS4, self).tearDown()

    def verify_counters(self, p, count):
        if hasattr(p, "spd_policy_in_any"):
            pkts = p.spd_policy_in_any.get_stats()["packets"]
            self.assertEqual(
                pkts,
                count,
                "incorrect SPD any policy: expected %d != %d" % (count, pkts),
            )

        if hasattr(p, "tun_sa_in"):
            pkts = p.tun_sa_in.get_stats()["packets"]
            self.assertEqual(
                pkts, count, "incorrect SA in counts: expected %d != %d" % (count, pkts)
            )
            pkts = p.tun_sa_out.get_stats()["packets"]
            self.assertEqual(
                pkts,
                count,
                "incorrect SA out counts: expected %d != %d" % (count, pkts),
            )

        # We have to allow for an extra encrypted count as a packet may get sent with padding b/c
        # the timer was about to fire when we started sending in packets
        counter_value = self.get_packet_counter(self.tun4_encrypt_node_name)
        self.assert_in_range(counter_value, count, count + 1, "encypted count")
        self.assert_packet_counter_equal(self.tun4_decrypt_node_name, count)

    def verify_encrypted(self, p, sa, expected_count, rxs):
        decrypt_pkts = []
        for rx in rxs:
            self.assert_packet_checksums_valid(rx)
            self.assertEqual(len(rx) - len(Ether()), rx[IP].len)
            dpkts = sa.decrypt(rx[IP]).packets
            dpkts = [x for x in dpkts if not isinstance(x, iptfs.IPTFSPad)]
            decrypt_pkts += dpkts

            for decrypt_pkt in dpkts:
                try:
                    self.assert_equal(decrypt_pkt.src, self.pg1.remote_ip4)
                    self.assert_equal(decrypt_pkt.dst, p.remote_tun_if_host)
                except:
                    self.logger.debug(ppp("Unexpected packet:", rx))
                    try:
                        self.logger.debug(ppp("Decrypted packet:", decrypt_pkt))
                    except Exception:  # pylint: disable=W0703
                        pass
                    raise

        self.assertEqual(len(decrypt_pkts), expected_count)
        # pkts = reassemble4(decrypt_pkts)
        # for pkt in pkts:
        #     self.assert_packet_checksums_valid(pkt)

    def verify_encrypted_with_frags(self, p, sa, rxs, cmprxs):
        dpkts_pcap = []
        oldrxs = []

        for rx in rxs:
            self.assert_packet_checksums_valid(rx)
            self.assertEqual(len(rx) - len(Ether()), rx[IP].len)
            dpkts_pcap += sa.decrypt_iptfs_pkt(rx[IP], oldrxs)
            oldrxs.append(rx)

        self.logger.info("XXXYYY: decrypted packets: {}".format(len(dpkts_pcap)))

        # for x in dpkts_pcap:
        #     try:
        #         # ix = iptfs.IPTFS(x)
        #         ix = x
        #         self.logger.info("XXXYYY: decrypted pkt:")
        #         self.logger.info("dump: {}".format(ix.show(dump=True)))
        #     except Exception as expkt:
        #         self.logger.info("XXXYYY: decrypted pkt: ex: {}".format(
        #             str(expkt)))
        #         self.logger.info(
        #             "XXXYYY: decrypted pkt: len {} dump: {}".format(
        #                 len(x), x.show(dump=True)))

        for x in dpkts_pcap:
            self.logger.info("type: {}".format(type(x)))

        # Join fragments into real packets and drop padding return list of
        # real packets.
        dpkts = iptfs.decap_frag_stream(dpkts_pcap)

        self.logger.info("XXXYYY: decap packets: {}".format(len(dpkts)))

        for decrypt_pkt in dpkts:
            # self.logger.info("XXXYYY: pktlen {} pkt: {}".format(
            #     len(decrypt_pkt), decrypt_pkt.show(dump=True)))
            try:
                self.assert_equal(decrypt_pkt.src, self.pg1.remote_ip4)
                self.assert_equal(decrypt_pkt.dst, p.remote_tun_if_host)
            except:
                self.logger.debug(ppp("Unexpected packet:", decrypt_pkt))
                try:
                    self.logger.debug(ppp("Decrypted packet:", decrypt_pkt))
                except Exception:  # pylint: disable=W0703
                    pass
                raise

        # self.logger.info("XXXYYY: dpkts count {} cmprxs count {}".format(
        #     len(dpkts), len(cmprxs)))

        self.assertEqual(len(dpkts), len(cmprxs))
        # pkts = reassemble4(decrypt_pkts)
        # for pkt in pkts:
        #     self.assert_packet_checksums_valid(pkt)

    def verify_decrypted(self, p, rxs):
        for rx in rxs:
            self.assert_equal(rx[IP].src, p.remote_tun_if_host)
            self.assert_equal(rx[IP].dst, self.pg1.remote_ip4)
            self.assert_packet_checksums_valid(rx)


class TemplateIPTFS4(_TemplateIPTFS4):
    """IPTFS Tests

        TUNNEL MODE:

         ------   encrypt   ---   plain   ---
    VPP |tun_if| <-------  |VPP| <------ |pg1| Scapy
         ------             ---           ---

         ------   decrypt   ---   plain   ---
    VPP |tun_if| ------->  |VPP| ------> |pg1| Scapy
         ------             ---           ---

    """

    tfs_config = TFS_BASE_CONFIG
    MTU = MTU

    def setUp(self):
        super(TemplateIPTFS4, self).setUp()
        p = self.params[socket.AF_INET]
        config_tun_params(
            p, self.encryption_type, self.tun_if, mtu=self.MTU, logger=self.logger
        )

    def verify_inorder(self, p, recv_pkts, seqnos=None):
        del p
        if seqnos is None:
            # this code expects init_seq_num use for lists of packets.
            seqnos = [x for x in range(1, len(recv_pkts) + 1)]
        seqno = [pkt[ICMP].seq for pkt in recv_pkts]
        self.assertEqual(seqno, seqnos)

    def send_and_expect(self, intf, pkts, output, n_rx=None):
        if n_rx is None:
            n_rx = len(pkts)
        self.pg_send(self.tun_if, pkts)
        return self.pg1.get_capture(n_rx)

    def _verify_decap_44_noex(
        self, p, tunpkts, expected=None, seqnos=None, clump=None
    ):  # pylint: disable=R0913
        "Verify sent tunpkts are decrypted and returned as IP correctly.."
        count = len(tunpkts)
        if expected is None:
            if seqnos is not None:
                expected = len(seqnos)
            else:
                expected = count

        # old_input_cli = self.tun_if._input_cli  # pylint: disable=W0212
        orig_pkts = []
        if clump is None:
            clump = count
        try:
            self.pg1.maxframe = clump
            # self.tun_if._input_cli += " maxframe {}".format(clump)
            self.pg_send(self.tun_if, tunpkts)
            recv_pkts = self.pg1.get_capture(expected)
            for pkt in recv_pkts:
                orig_pkts.append(pkt.copy())
            self.verify_decrypted(p, recv_pkts[:])
            self.verify_inorder(p, recv_pkts[:], seqnos)
        except Exception as ex:
            return ex, orig_pkts, tunpkts
        finally:
            self.pg1.maxframe = None
            # self.tun_if._input_cli = old_input_cli  # pylint: disable=W0212
        return None, orig_pkts, tunpkts

    def _verify_decap_44(self, p, tunpkts, expected=None, seqnos=None, clump=None):
        "Verify sent tunpkts are decrypted and returned as IP correctly.."
        ex, _, _ = self._verify_decap_44_noex(p, tunpkts, expected, seqnos, clump)
        if ex is not None:
            raise ex  # pylint: disable=E0702

    def _verify_encap_44_noex(self, p, ippkts, clump=None, gather_timeout=1):
        # Can't send/expect b/c we should have more IP than IPTFS packets.
        orig_pkts = []
        try:
            count = len(ippkts)
            if clump is None:
                clump = count
            self.pg1.maxframe = clump
            # self.pg1._input_cli += " maxframe {}".format(clump)
            self.pg_send(self.pg1, ippkts)
            recv_pkts = self.tun_if.get_capture_any_count(timeout=gather_timeout)
            self.logger.info(self.vapi.ppcli("show trace"))
            for pkt in recv_pkts:
                orig_pkts.append(pkt.copy())
            self.verify_encrypted_with_frags(p, p.vpp_tun_sa, recv_pkts, ippkts)
        except Exception as ex:
            return ex, orig_pkts, ippkts
        self.pg1.maxframe = None
        return None, orig_pkts, ippkts

    def _verify_encap_44(self, p, ippkts, clump=None, gather_timeout=1):
        ex, o, i = self._verify_encap_44_noex(p, ippkts, clump, gather_timeout)
        if ex:
            raise ex  # pylint: disable=E0702
        return o

    def verify_encap_44(self, p, ippkts, clump=None, gather_timeout=1):
        "Verify ippkts are encrypted/encapsulated correctly.."
        try:
            return self._verify_encap_44(p, ippkts, clump, gather_timeout)
        finally:
            try:
                self.logger.info(self.vapi.ppcli("show error"))
                self.logger.info(self.vapi.ppcli("show ipsec all"))
            except Exception:
                try:
                    self.logger.info(self.vapi.ppcli("show error"))
                    self.logger.info(self.vapi.ppcli("show ipsec all"))
                except Exception:
                    self.logger.error("XXX couldn't show error/ipsec all")

    def verify_decap_44(self, p, tunpkts, expected=None, seqnos=None, clump=None):
        "Verify tunpkts are decrypted correctly.."
        try:
            self._verify_decap_44(p, tunpkts, expected, seqnos, clump)
        finally:
            self.logger.info(self.vapi.ppcli("show error"))
            self.logger.info(self.vapi.ppcli("show ipsec all"))

        # self.verify_counters(p, len(tunpkts))

    def verify_tun_44(self, p, ippkts, tunpkts, clump=None):
        "Verify ippkts are encrypted/encapsulated, and that tunpkts are decrypted correctly.."
        try:
            if ippkts:
                self._verify_encap_44(p, ippkts, clump=clump)
            if tunpkts:
                self._verify_decap_44(
                    p, tunpkts, seqnos=range(len(ippkts)), clump=clump
                )
        finally:
            self.logger.info(self.vapi.ppcli("show error"))
            self.logger.info(self.vapi.ppcli("show ipsec all"))

        # Need ot check different nodes for counters, timing affects the number.
        # self.verify_counters(p, len(tunpkts))

    def init_seq_num(self, p, tunpkts):
        "Send one packet to prime the sequence numbers in the code"
        self._verify_decap_44(p, tunpkts[:1], seqnos=[0])
        self.assert_packet_counter_equal(self.tun4_decrypt_node_name, 1)
        self.vapi.cli("clear errors")
        return tunpkts[1:]


__author__ = "Christian Hopps"
__date__ = "July 15 2019"
__version__ = "1.0"
__docformat__ = "restructuredtext en"
