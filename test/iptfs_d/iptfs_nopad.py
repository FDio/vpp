# -*- coding: utf-8 eval: (yapf-mode 1) -*-
# SPDX-License-Identifier: Apache-2.0
#
# November 5 2019, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2019, LabN Consulting, L.L.C.
# All Rights Reserved.
#

import pprint
import socket
import re
from scapy.layers.inet import IP
from iptfs_d.template_iptfs import TemplateIPTFS4
from scapy_handlers.iptfs import IPTFSPad as IPTFSPad
from scapy_handlers.iptfs import strip_all_pads as strip_all_pads


class TestVerifyNoPad4(TemplateIPTFS4):
    """IPTFS Verify No Pad Tests"""

    MTU = 256
    # tfs_config = re.sub(
    #     "iptfs-ethernet-bitrate [0-9]*", "iptfs-ethernet-bitrate 1000000",
    #     re.sub("iptfs-packet-size [0-9]*", "iptfs-packet-size 256",
    #            TemplateIPTFS4.tfs_config.replace("iptfs-no-pad-only ", "")))

    # 1ms packet pacing
    BITRATE = (MTU + 14 + 4 + 8 + 12) * 8 * 100
    MAXDELAY = 4000000
    tfs_config = re.sub(
        "iptfs-max-delay-us [0-9]*",
        "iptfs-max-delay-us {}".format(MAXDELAY),
        re.sub(
            "iptfs-ethernet-bitrate [0-9]*",
            "iptfs-ethernet-bitrate {}".format(BITRATE),
            re.sub(
                "iptfs-packet-size [0-9]*",
                "iptfs-packet-size 256",
                TemplateIPTFS4.tfs_config.decode("ascii").replace(
                    "iptfs-no-pad-only ", ""
                ),
            ),
        ),
    ).encode("ascii")

    def basic_verify_tun_44(self, p, count, payload_size, clump=None):
        self.vapi.cli("clear errors")
        self.vapi.cli("clear iptfs counters")
        self.vapi.cli("clear interfaces")

        self.vapi.cli("iptfs debug enable packet")

        # Generate IP stream (count packets)
        ippkts = self.gen_pkts(
            self.pg1,
            src=self.pg1.remote_ip4,
            dst=p.remote_tun_if_host,
            count=count,
            payload_size=payload_size,
        )

        recv_pkts = self.verify_encap_44(p, ippkts, clump, gather_timeout=2)
        pcount = len(recv_pkts)

        self.vapi.cli("iptfs debug disable packet")

        # Things are OK, now let's look for padding.
        drxpkts = [p.vpp_tun_sa.decrypt_iptfs_pkt(rx[IP]) for rx in recv_pkts]
        drxpkts = strip_all_pads(drxpkts)

        print("Original Packet Count: " + str(pcount))
        print("Decrypted Packets Count after removing pad ends: " + str(len(drxpkts)))
        for i, rx in enumerate(drxpkts[1:-1]):
            if rx.is_padded():
                print("Got unexpected pad @ index {}".format(i + 1))
                pprint.pprint(drxpkts)
                assert False
        print("Fully Packed")

    def test_tun_basic_nopad44(self):
        self.basic_verify_tun_44(
            self.params[socket.AF_INET], count=50, payload_size=230
        )

    def test_tun_clump5_nopad44(self):
        self.basic_verify_tun_44(
            self.params[socket.AF_INET], count=50, payload_size=230, clump=5
        )

    def test_tun_clump1_nopad44(self):
        self.basic_verify_tun_44(
            self.params[socket.AF_INET], count=50, payload_size=230, clump=1
        )
