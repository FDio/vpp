#!/usr/bin/env python3

import unittest

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6

from framework import VppTestCase
from asfframework import VppTestRunner


class TestPgStream(VppTestCase):
    """PG Stream Test Case"""

    def __init__(self, *args):
        VppTestCase.__init__(self, *args)

    def setUp(self):
        super(TestPgStream, self).setUp()

        # Create 3 pg interfaces - one each for ethernet, IPv4, and IPv6.
        self.create_pg_interfaces(range(0, 1))
        self.pg_interfaces += self.create_pg_ip4_interfaces(range(1, 2))
        self.pg_interfaces += self.create_pg_ip6_interfaces(range(2, 3))

        for i in self.pg_interfaces:
            i.admin_up()

        for i in [self.pg0, self.pg1]:
            i.config_ip4()

        for i in [self.pg0, self.pg2]:
            i.config_ip6()

        self.pg0.resolve_arp()
        self.pg0.resolve_ndp()

    def tearDown(self):
        super(TestPgStream, self).tearDown()
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.admin_down()
            i.remove_vpp_config()

    def pg_stream(self, count=100, rate=1e6, packet_size=700):
        rate = str(rate)
        packet_size = str(packet_size)
        count = str(count)

        cmds = [
            "packet-generator new {{\n"
            "  name pg0-stream\n"
            "  limit {count}\n"
            "  node ethernet-input\n"
            "  source pg0\n"
            "  rate {rate}\n"
            "  size {packet_size}+{packet_size}\n"
            "  data {{\n"
            "    IP4: {src_mac} -> 00:02:03:04:05:06\n"
            "    UDP: 192.168.20.20 -> 192.168.10.100\n"
            "    UDP: 1234 -> 4321\n"
            "    incrementing 100\n"
            "  }}\n"
            "}}\n".format(
                count=count,
                rate=rate,
                packet_size=packet_size,
                src_mac=self.pg0.local_mac,
            ),
            "packet-generator enable",
            "packet-generator disable",
            "packet-generator delete pg0-stream",
        ]

        for cmd in cmds:
            r = self.vapi.cli_return_response(cmd)
            if r.retval != 0:
                if hasattr(r, "reply"):
                    self.logger.info(cmd + " FAIL reply " + r.reply)
                else:
                    self.logger.info(cmd + " FAIL retval " + str(r.retval))

    def test_pg_stream(self):
        """PG Stream testing"""
        self.pg_stream(rate=100, packet_size=64)
        self.pg_stream(count=1000, rate=1000)
        self.pg_stream(count=100000, rate=10000, packet_size=1500)
        self.pg_stream(packet_size=4000)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
