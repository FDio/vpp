#!/usr/bin/env python3

import unittest
import time
import re

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6

from framework import VppTestCase
from asfframework import VppTestRunner
from config import config


class TestPgStream(VppTestCase):
    """PG Stream Test Case"""

    def __init__(self, *args):
        VppTestCase.__init__(self, *args)

    @classmethod
    def setUpClass(cls):
        # increase vapi timeout, to avoid
        # failures reported on test-cov
        if config.gcov:
            cls.vapi_response_timeout = 20
        super(TestPgStream, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestPgStream, cls).tearDownClass()

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
            "clear trace",
            "trace add pg-input 1000",
            "packet-generator new {{\n"
            "  name pg0-pg1-stream\n"
            "  limit {count}\n"
            "  node ethernet-input\n"
            "  source pg0\n"
            "  rate {rate}\n"
            "  size {packet_size}+{packet_size}\n"
            "  buffer-flags ip4 offload\n"
            "  buffer-offload-flags offload-ip-cksum offload-udp-cksum\n"
            "  data {{\n"
            "    IP4: {src_mac} -> {dst_mac}\n"
            "    UDP: {src} -> {dst}\n"
            "    UDP: 1234 -> 4321\n"
            "    incrementing 100\n"
            "  }}\n"
            "}}\n".format(
                count=count,
                rate=rate,
                packet_size=packet_size,
                src_mac=self.pg0.remote_mac,
                dst_mac=self.pg0.local_mac,
                src=self.pg0.remote_ip4,
                dst=self.pg1.remote_ip4,
            ),
            "packet-generator new {{\n"
            "  name pg0-pg2-stream\n"
            "  limit {count}\n"
            "  node ethernet-input\n"
            "  source pg0\n"
            "  rate {rate}\n"
            "  size {packet_size}+{packet_size}\n"
            "  buffer-flags ip6 offload\n"
            "  buffer-offload-flags offload-udp-cksum\n"
            "  data {{\n"
            "    IP6: {src_mac} -> {dst_mac}\n"
            "    UDP: {src} -> {dst}\n"
            "    UDP: 1234 -> 4321\n"
            "    incrementing 100\n"
            "  }}\n"
            "}}\n".format(
                count=count,
                rate=rate,
                packet_size=packet_size,
                src_mac=self.pg0.remote_mac,
                dst_mac=self.pg0.local_mac,
                src=self.pg0.remote_ip6,
                dst=self.pg2.remote_ip6,
            ),
            "packet-generator new {{\n"
            "  name pg1-pg0-stream\n"
            "  limit {count}\n"
            "  node ip4-input\n"
            "  source pg1\n"
            "  rate {rate}\n"
            "  size {packet_size}+{packet_size}\n"
            "  buffer-flags ip4 offload\n"
            "  buffer-offload-flags offload-ip-cksum offload-udp-cksum\n"
            "  data {{\n"
            "    UDP: {src} -> {dst}\n"
            "    UDP: 1234 -> 4321\n"
            "    incrementing 100\n"
            "  }}\n"
            "}}\n".format(
                count=count,
                rate=rate,
                packet_size=packet_size,
                src=self.pg1.remote_ip4,
                dst=self.pg0.remote_ip4,
            ),
            "packet-generator new {{\n"
            "  name pg2-pg0-stream\n"
            "  limit {count}\n"
            "  node ip6-input\n"
            "  source pg2\n"
            "  rate {rate}\n"
            "  size {packet_size}+{packet_size}\n"
            "  buffer-flags ip6 offload\n"
            "  buffer-offload-flags offload-udp-cksum\n"
            "  data {{\n"
            "    UDP: {src} -> {dst}\n"
            "    UDP: 1234 -> 4321\n"
            "    incrementing 100\n"
            "  }}\n"
            "}}\n".format(
                count=count,
                rate=rate,
                packet_size=packet_size,
                src=self.pg2.remote_ip6,
                dst=self.pg0.remote_ip6,
            ),
            "packet-generator enable",
            "show error",
        ]

        for cmd in cmds:
            r = self.vapi.cli_return_response(cmd)
            if r.retval != 0:
                if hasattr(r, "reply"):
                    self.logger.info(cmd + " FAIL reply " + r.reply)
                else:
                    self.logger.info(cmd + " FAIL retval " + str(r.retval))
            self.assertTrue(r.retval == 0)

        deadline = time.time() + 30
        while self.vapi.cli("show packet-generator").find("Yes") != -1:
            self.sleep(0.01)  # yield
            if time.time() > deadline:
                self.logger.error("Timeout waiting for pg to stop")
                break

        r = self.vapi.cli_return_response("show trace")
        self.assertTrue(r.retval == 0)
        self.assertTrue(hasattr(r, "reply"))
        rv = r.reply
        packets = rv.split("\nPacket ")
        for packet in enumerate(packets, start=1):
            match = re.search(r"stream\s+([\w-]+)", packet[1])
            if match:
                stream_name = match.group(1)
            else:
                continue
            if stream_name == "pg0-pg1-stream":
                look_here = packet[1].find("ethernet-input")
                self.assertNotEqual(look_here, -1)
                search_string = "ip4 offload-ip-cksum offload-udp-cksum  l2-hdr-offset 0 l3-hdr-offset 14 l4-hdr-offset 34"
                look_here = packet[1].find(search_string)
                self.assertNotEqual(look_here, -1)
                p = packet[1].split(search_string)
                search_string = "ip4 l2-hdr-offset 0 l3-hdr-offset 14 l4-hdr-offset 34"
                look_here = p[1].find(search_string)
                self.assertNotEqual(look_here, -1)
            elif stream_name == "pg0-pg2-stream":
                look_here = packet[1].find("ethernet-input")
                self.assertNotEqual(look_here, -1)
                search_string = "ip6 offload-udp-cksum  l2-hdr-offset 0 l3-hdr-offset 14 l4-hdr-offset 54"
                look_here = packet[1].find(search_string)
                self.assertNotEqual(look_here, -1)
                p = packet[1].split(search_string)
                search_string = "ip6 l2-hdr-offset 0 l3-hdr-offset 14 l4-hdr-offset 54"
                look_here = p[1].find(search_string)
                self.assertNotEqual(look_here, -1)
            elif stream_name == "pg1-pg0-stream":
                look_here = packet[1].find("ethernet-input")
                self.assertEqual(look_here, -1)
                look_here = packet[1].find("ip4-input")
                self.assertNotEqual(look_here, -1)
                search_string = "ip4 offload-ip-cksum offload-udp-cksum  l2-hdr-offset 0 l3-hdr-offset 0 l4-hdr-offset 20"
                look_here = packet[1].find(search_string)
                self.assertNotEqual(look_here, -1)
                p = packet[1].split(search_string)
                search_string = "ip4 l2-hdr-offset 0 l3-hdr-offset 0 l4-hdr-offset 20"
                look_here = p[1].find(search_string)
                self.assertNotEqual(look_here, -1)
            elif stream_name == "pg2-pg0-stream":
                look_here = packet[1].find("ethernet-input")
                self.assertEqual(look_here, -1)
                look_here = packet[1].find("ip6-input")
                self.assertNotEqual(look_here, -1)
                search_string = "ip6 offload-udp-cksum  l2-hdr-offset 0 l3-hdr-offset 0 l4-hdr-offset 40"
                look_here = packet[1].find(search_string)
                self.assertNotEqual(look_here, -1)
                p = packet[1].split(search_string)
                search_string = "ip6 l2-hdr-offset 0 l3-hdr-offset 0 l4-hdr-offset 40"
                look_here = p[1].find(search_string)
                self.assertNotEqual(look_here, -1)

        self.logger.info(self.vapi.cli("packet-generator disable"))
        self.logger.info(self.vapi.cli("packet-generator delete pg0-pg1-stream"))
        self.logger.info(self.vapi.cli("packet-generator delete pg0-pg2-stream"))
        self.logger.info(self.vapi.cli("packet-generator delete pg1-pg0-stream"))
        self.logger.info(self.vapi.cli("packet-generator delete pg2-pg0-stream"))

        r = self.vapi.cli_return_response("show buffers")
        self.assertTrue(r.retval == 0)
        self.assertTrue(hasattr(r, "reply"))
        rv = r.reply
        used = int(rv.strip().split("\n")[-1].split()[-1])
        self.assertEqual(used, 0)

    def test_pg_stream(self):
        """PG Stream testing"""
        self.pg_stream(rate=100, packet_size=64)
        self.pg_stream(count=1000, rate=1000)
        self.pg_stream(count=100000, rate=10000, packet_size=1500)
        self.pg_stream(packet_size=4000)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
