# -*- coding: utf-8 eval: (yapf-mode 1) -*-
# SPDX-License-Identifier: Apache-2.0
#
# November 5 2019, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2019, LabN Consulting, L.L.C.
# All Rights Reserved.
#

import socket
import scapy_handlers.iptfs as iptfs
from iptfs_d.template_iptfs import MTU, PING_OVERHEAD, TemplateIPTFS4


def ranges(s, e, sz):
    "iterate ranges of size sz starting with s ending with e allowing for short range at end"
    while s < e:
        le = s + sz
        if le > e:
            le = e
        yield s, le
        s = le


class _TestBasicDontFragmentIPTFS4(TemplateIPTFS4):
    """IPTFS Basic Tests"""

    def verify_tun_44(self, p, ippkts, tunpkts, clump=None):
        "Verify ippkts are encrypted/encapsulated, and that tunpkts are decrypted correctly.."
        try:
            if tunpkts:
                self._verify_decap_44(
                    p, tunpkts, seqnos=range(len(ippkts)), clump=clump
                )
            if ippkts:
                self._verify_encap_44(p, ippkts)
        finally:
            self.logger.info(self.vapi.ppcli("show error"))
            self.logger.info(self.vapi.ppcli("show ipsec all"))

        self.verify_counters(p, len(tunpkts))

    def basic_verify_tun_44(
        self, p, count=1, payload_size=64, n_rx=None, clump=None, mtu=MTU
    ):
        self.vapi.cli("clear errors")
        # Generate encrypted IPTFS stream (count packets)
        tunpkts = iptfs.gen_encrypt_pktstream(
            p.scapy_tun_sa,
            self.tun_if,
            src=p.remote_tun_if_host,
            dst=self.pg1.remote_ip4,
            mtu=mtu,
            count=count,
            payload_size=payload_size,
            dontfrag=True,
        )

        # Generate IP stream (count packets)
        ippkts = self.gen_pkts(
            self.pg1,
            src=self.pg1.remote_ip4,
            dst=p.remote_tun_if_host,
            count=count,
            payload_size=payload_size,
        )

        self.verify_tun_44(p, ippkts, tunpkts, clump=clump)


class TestBasicDontFragmentIPTFS4(_TestBasicDontFragmentIPTFS4):
    """IPTFS Basic Dont-Fragment Tests"""

    tfs_config = (
        "iptfs-dont-fragment "
        + _TestBasicDontFragmentIPTFS4.tfs_config.replace("iptfs-use-chaining", "")
    )

    def test_tun_basic44(self):
        self.basic_verify_tun_44(self.params[socket.AF_INET], count=1)

    def test_tun_basic44_1466(self):
        self.basic_verify_tun_44(
            self.params[socket.AF_INET], payload_size=1438, count=10
        )

    def test_tun_basic44_full(self):
        ps = iptfs.get_payload_size(MTU, self.params[socket.AF_INET].scapy_tun_sa)

        # Compensate for Ping overhead.
        ps -= PING_OVERHEAD

        for payload_size in range(ps - 5, ps + 1):
            self.basic_verify_tun_44(
                self.params[socket.AF_INET], payload_size=payload_size, count=10
            )

    def test_tun_burst44(self):
        self.basic_verify_tun_44(self.params[socket.AF_INET], count=256)

    def test_tun_burst44_clump1(self):
        self.basic_verify_tun_44(self.params[socket.AF_INET], count=256, clump=1)


class TestBasicDontFragmentChainedIPTFS4(_TestBasicDontFragmentIPTFS4):
    """IPTFS Basic Dont-Fragment with Chaining Tests"""

    if _TestBasicDontFragmentIPTFS4.tfs_config.find("use-chaining") == -1:
        tfs_config = (
            "iptfs-dont-fragment iptfs-use-chaining "
            + _TestBasicDontFragmentIPTFS4.tfs_config
        )
    else:
        tfs_config = "iptfs-dont-fragment " + _TestBasicDontFragmentIPTFS4.tfs_config

    def test_tun_basic44(self):
        self.basic_verify_tun_44(self.params[socket.AF_INET], count=1)

    def test_tun_burst44(self):
        self.basic_verify_tun_44(self.params[socket.AF_INET], count=256)

    def test_tun_burst44_clump1(self):
        self.basic_verify_tun_44(self.params[socket.AF_INET], count=256, clump=1)
