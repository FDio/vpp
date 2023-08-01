#!/usr/bin/env python3

import unittest

# import scapy.compat
from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP

from framework import VppTestCase, VppTestRunner
from util import StatsDiff


class TestEthernet(VppTestCase):
    """Ethernet Test Case"""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        # create 2 pg interfaces
        cls.create_pg_interfaces(range(2))

        for i in cls.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

        cls.bogus_mac = "0:2:3:4:5:6"
        for i in cls.pg_interfaces:
            assert i.local_mac != cls.bogus_mac

        cls.pg0_secondary_mac = "0:a:b:c:d:e"
        cls.pg1_secondary_mac = "0:aa:bb:cc:dd:ee"
        cls.vapi.cli(
            f"set interface secondary-mac-address pg0 {cls.pg0_secondary_mac} add"
        )
        cls.vapi.cli(
            f"set interface secondary-mac-address pg1 {cls.pg1_secondary_mac} add"
        )

    @classmethod
    def tearDownClass(cls):
        for i in cls.pg_interfaces:
            i.unconfig_ip4()
            i.admin_down()
        super().tearDownClass()

    def set_skip_dmac_check(self, state: str):
        for i in self.pg_interfaces:
            self.vapi.cli(f"set interface skip-dmac-check {state} {i.name}")

    def test_dmac_filtering(self):
        self.check_mixed_dmacs_filter_result()

    def test_skip_dmac_check(self):
        self.addCleanup(self.set_skip_dmac_check, "off")

        self.set_skip_dmac_check("on")
        self.check_mixed_dmacs_filter_result("on")
        self.set_skip_dmac_check("off")
        self.check_mixed_dmacs_filter_result("off")

    def check_mixed_dmacs_filter_result(self, skip_dmac_check_state="off"):
        """
        Send a mixture of packets using:
        - the right destination MAC
        - a destination MAC that belongs to another interface
        - a bogus destination MAC that doesn't belong to any interface

        Depending on whether the interface is configured to skip DMAC checking,
        expect the packets to be forwarded or dropped.
        """
        NB_PKTS = 50
        pkts = []
        dropped_pkts = []
        fwd_pkts = []
        for i in range(NB_PKTS):
            p = (
                Ether(dst="", src=self.pg0.remote_mac)
                / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4)
                / UDP(sport=1234, dport=1000 + i)
                / Raw("i" * 48)
            )
            if i % 5 == 0:
                p[Ether].dst = self.pg0.local_mac
            elif i % 5 == 1:
                p[Ether].dst = self.pg0_secondary_mac
            elif i % 5 == 2:
                p[Ether].dst = self.pg1.local_mac
            elif i % 5 == 3:
                p[Ether].dst = self.pg1_secondary_mac
            elif i % 5 == 4:
                p[Ether].dst = self.bogus_mac

            if p[Ether].dst in [self.pg0.local_mac, self.pg0_secondary_mac]:
                fwd_pkts += [p]
            elif skip_dmac_check_state == "on":
                fwd_pkts += [p]
            else:
                dropped_pkts += [p]

            pkts += [p]

        rxs = self.send_and_expect(
            self.pg0,
            pkts,
            self.pg1,
            n_rx=len(fwd_pkts),
            stats_diff=StatsDiff(
                {"err": {"/err/ethernet-input/l3 mac mismatch": len(dropped_pkts)}}
            ),
        )

        self.assertEqual(len(rxs), len(fwd_pkts))
        for i, rx in enumerate(rxs):
            self.assertEqual(rx[Raw], fwd_pkts[i][Raw])


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
