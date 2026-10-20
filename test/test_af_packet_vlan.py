#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Vinci Consulting. All rights reserved.
"""Regression coverage for VLAN headers stripped into Linux packet metadata."""

import os
import socket
import struct
import subprocess
import unittest

from parameterized import parameterized

from scapy.layers.l2 import Ether, Dot1Q, Dot1AD
from scapy.packet import Raw

from config import config
from framework import VppTestCase
from asfframework import VppTestRunner
from vpp_papi import VppEnum


@unittest.skipIf(
    "af_packet" in config.excluded_plugins, "Exclude af_packet plugin tests"
)
@unittest.skipIf(config.skip_netns_tests, "requires Linux network administration")
class TestAfPacketVlan(VppTestCase):
    """af_packet preserves stripped VLAN TPIDs in both ring versions."""

    def setUp(self):
        super().setUp()
        self.host = "vpvt%dh" % os.getpid()
        self.peer = "vpvt%dp" % os.getpid()
        subprocess.run(
            ["ip", "link", "add", self.host, "type", "veth", "peer", "name", self.peer],
            check=True,
        )
        self.addCleanup(subprocess.run, ["ip", "link", "del", self.host], check=True)
        for interface in (self.host, self.peer):
            subprocess.run(["ip", "link", "set", interface, "up"], check=True)
        self.create_pg_interfaces([0])
        self.pg0.admin_up()

    @parameterized.expand(
        [
            (f"v{version}_{name}", version, tpid, tags)
            for version in (2, 3)
            for name, tpid, tags in (
                ("dot1q", 0x8100, Dot1Q(vlan=123, prio=5, id=1)),
                ("dot1ad", 0x88A8, Dot1AD(vlan=123, prio=5, id=1)),
                ("qinq", 0x88A8, Dot1AD(vlan=123, prio=5, id=1) / Dot1Q(vlan=456)),
            )
        ],
        doc_func=lambda func, num, param: (
            "TPACKET_V%d %s: preserve stripped VLAN TPID."
            % (param.args[1], param.args[0].split("_", 1)[1])
        ),
    )
    def test_vlan_tpid(self, name, version, tpid, tags):
        """Preserve the stripped outer VLAN tag byte for byte."""
        flags = VppEnum.vl_api_af_packet_flags_t
        result = self.vapi.af_packet_create_v3(
            host_if_name=self.host,
            use_random_hw_addr=True,
            mode=VppEnum.vl_api_af_packet_mode_t.AF_PACKET_API_MODE_ETHERNET,
            flags=flags.AF_PACKET_API_FLAG_VERSION_2 if version == 2 else 0,
        )
        self.addCleanup(self.vapi.af_packet_delete, host_if_name=self.host)
        self.vapi.sw_interface_set_flags(sw_if_index=result.sw_if_index, flags=1)
        self.vapi.sw_interface_set_l2_xconnect(
            rx_sw_if_index=result.sw_if_index,
            tx_sw_if_index=self.pg0.sw_if_index,
            enable=True,
        )
        self.vapi.sw_interface_set_l2_xconnect(
            rx_sw_if_index=self.pg0.sw_if_index,
            tx_sw_if_index=result.sw_if_index,
            enable=True,
        )
        # Read PACKET_AUXDATA directly to verify that Linux stripped the outer
        # VLAN tag and supplied its original TPID. Scapy's receive path can
        # reconstruct VLAN headers, hiding the metadata this test must inspect.
        sol_packet, packet_auxdata = 263, 8
        vlan_valid, tpid_valid = 1 << 4, 1 << 6
        with socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)
        ) as observer:
            observer.setsockopt(sol_packet, packet_auxdata, 1)
            observer.bind((self.host, 0))
            observer.settimeout(2)
            with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as sender:
                sender.bind((self.peer, 0))
                marker = ("af-packet-vlan-%d-%s" % (version, name)).encode()
                frame = Ether(dst="02:00:00:00:00:02", src="02:00:00:00:00:01")
                frame /= tags
                frame /= Raw(marker + b"x" * 64)
                wire = bytes(frame)
                self.pg0.enable_capture()
                sender.send(wire)
                while True:
                    data, ancillary, _, _ = observer.recvmsg(2048, 256)
                    if marker in data:
                        break
                aux = [
                    value
                    for level, kind, value in ancillary
                    if level == sol_packet and kind == packet_auxdata
                ]
                self.assertEqual(len(aux), 1)
                status, _, _, _, _, tci, actual_tpid = struct.unpack("=IIIHHHH", aux[0])
                self.assertTrue(status & vlan_valid)
                self.assertTrue(status & tpid_valid)
                self.assertEqual(actual_tpid, tpid)
                self.assertEqual(tci, (5 << 13) | (1 << 12) | 123)
                self.assertEqual(data, wire[:12] + wire[16:])
                captured = self.pg0.get_capture(1, timeout=2)
                actual = bytes(captured[0])
                self.assertEqual(actual, wire)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
