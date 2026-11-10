#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Meter, Inc.

"""af_packet RX mode bookkeeping.

Each test attaches VPP to veth pairs whose peers live in a Linux namespace,
then pings the VPP side and checks the interface's RX counter, so a dead RX
path shows up as a counter that does not move.
"""

import subprocess
import time
import unittest

from asfframework import VppTestRunner
from config import config
from framework import VppTestCase
from vpp_papi import VppEnum
from vpp_qemu_utils import (
    create_host_interface,
    create_namespace,
    delete_all_host_interfaces,
    delete_all_namespaces,
)


@unittest.skipIf(config.skip_netns_tests, "netns not available or disabled")
class TestAfPacketRxMode(VppTestCase):
    """af_packet RX mode"""

    # With poll-sleep-usec, epoll runs on every main loop, before the input nodes.
    extra_vpp_config = ["unix", "{", "poll-sleep-usec", "100", "}"]
    # Keep the queues on main, the only thread poll-sleep-usec applies to.
    vpp_worker_count = 0

    @classmethod
    def setUpClass(cls):
        super(TestAfPacketRxMode, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestAfPacketRxMode, cls).tearDownClass()

    def setUp(self):
        super(TestAfPacketRxMode, self).setUp()
        ns_history = f"{self.tempdir}/history_ns.txt"
        if_history = f"{self.tempdir}/history_if.txt"
        # Cleanups still run if VPP crashed, so a retry finds no leftovers.
        self.addCleanup(delete_all_namespaces, ns_history)
        self.addCleanup(delete_all_host_interfaces, if_history)
        self.namespace = create_namespace(ns_history, prefix="vpp_afprx")
        self.if_history = if_history
        self.sw_if_index = {}

    def tearDown(self):
        try:
            for name in self.sw_if_index:
                self.vapi.af_packet_delete(host_if_name=name)
        finally:
            super(TestAfPacketRxMode, self).tearDown()

    def add_host_interface(self, index, polling=False):
        """Create a veth pair, attach VPP to one end and address both ends."""
        _, vpp_end = create_host_interface(
            self.if_history, self.namespace, f"10.10.{index}.2/24"
        )
        flags = VppEnum.vl_api_af_packet_flags_t
        sw_if_index = self.vapi.af_packet_create_v3(
            mode=VppEnum.vl_api_af_packet_mode_t.AF_PACKET_API_MODE_ETHERNET,
            host_if_name=vpp_end,
            use_random_hw_addr=True,
            flags=flags.AF_PACKET_API_FLAG_QDISC_BYPASS,
        ).sw_if_index
        self.sw_if_index[vpp_end] = sw_if_index
        self.vapi.sw_interface_set_flags(sw_if_index=sw_if_index, flags=1)
        self.vapi.sw_interface_add_del_address(
            sw_if_index=sw_if_index, prefix=f"10.10.{index}.1/24"
        )
        if polling:
            self.set_rx_mode(vpp_end, polling=True)
        return vpp_end

    def set_rx_mode(self, vpp_end, polling):
        modes = VppEnum.vl_api_rx_mode_t
        self.vapi.sw_interface_set_rx_mode(
            sw_if_index=self.sw_if_index[vpp_end],
            mode=modes.RX_MODE_API_POLLING if polling else modes.RX_MODE_API_INTERRUPT,
        )

    def rx_packets(self, vpp_end):
        counters = self.statistics.get_counter("/if/rx")
        return sum(t[self.sw_if_index[vpp_end]]["packets"] for t in counters)

    def ping_from_linux(self, index):
        subprocess.run(
            ["ip", "netns", "exec", self.namespace, "ping", "-c", "3", "-i", "0.2"]
            + ["-W", "1", f"10.10.{index}.1"],
            capture_output=True,
        )
        # Let the 1 ms TPACKET_V3 block timeout retire the last block.
        time.sleep(0.1)

    def assert_receives(self, index, vpp_end):
        before = self.rx_packets(vpp_end)
        self.ping_from_linux(index)
        self.assertGreater(self.rx_packets(vpp_end), before, f"{vpp_end} RX dead")

    def test_polling_queue_survives_new_interrupt_queue(self):
        """A new interrupt queue does not stop an existing polling queue"""
        # One polling interface, then new interfaces, which start in interrupt
        # mode.
        polled = self.add_host_interface(0, polling=True)
        self.add_host_interface(1)
        self.add_host_interface(2)
        self.assert_receives(0, polled)
        self.assertIn("state polling", self.vapi.cli("show node af-packet-input"))


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
