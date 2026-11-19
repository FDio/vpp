# SPDX-License-Identifier: Apache-2.0
#!/usr/bin/env python3

import re
import unittest

from framework import VppTestCase
from asfframework import VppTestRunner
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.packet import Raw


class SFlowLengthTestCase(VppTestCase):
    """sFlow sampled packet size"""

    def setUp(self):
        super(SFlowLengthTestCase, self).setUp()
        self.create_pg_interfaces(range(2))
        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()
        self.vapi.sw_interface_set_mtu(self.pg1.sw_if_index, [9000, 0, 0, 0])
        self.vapi.sflow_sampling_rate_set(sampling_N=1)
        self.vapi.sflow_enable_disable(
            hw_if_index=self.pg0.sw_if_index, enable_disable=True
        )

    def tearDown(self):
        self.vapi.sflow_enable_disable(
            hw_if_index=self.pg0.sw_if_index, enable_disable=False
        )
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.admin_down()
        super(SFlowLengthTestCase, self).tearDown()

    def stream(self, size, count):
        p = (
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4)
            / UDP(sport=1234, dport=5678)
        )
        p = p / Raw(b"\xa5" * (size - len(p)))
        self.assertEqual(len(p), size)
        return [p] * count

    def sampled_sizes(self, size, count):
        """Send count packets of size bytes through sflow on pg0, traced,
        and return the sampled-packet-size the sflow node reports for each."""
        self.vapi.cli("clear trace")
        self.vapi.cli("trace add pg-input %d" % count)
        self.pg0.add_stream(self.stream(size, count))
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        trace = self.vapi.cli("show trace max %d" % count)
        return [int(n) for n in re.findall(r"sampled-packet-size (\d+)", trace)]

    def test_sampled_packet_size(self):
        """sampled packet size is the packet's length, also after jumbos"""
        count = 32
        # Chained buffers: 9018 bytes do not fit in one 2048-byte buffer.
        # Forwarding computes the chain's length, which is cached in the
        # head buffer's total_length_not_including_first_buffer.
        sizes = self.sampled_sizes(9018, count)
        self.assertEqual(len(sizes), count)
        self.assertEqual(set(sizes), {9018})

        # Single buffers, reusing the freed heads of those chains. Their
        # total_length_not_including_first_buffer is stale: it is not
        # valid without VLIB_BUFFER_NEXT_PRESENT and is never reset.
        sizes = self.sampled_sizes(124, count)
        self.assertEqual(len(sizes), count)
        self.assertEqual(set(sizes), {124})


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
