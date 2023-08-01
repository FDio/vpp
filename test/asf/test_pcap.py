#!/usr/bin/env python3

import os
import unittest

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.packet import Raw

from asfframework import VppTestCase, VppTestRunner


class TestPcap(VppTestCase):
    """Pcap Unit Test Cases"""

    @classmethod
    def setUpClass(cls):
        super(TestPcap, cls).setUpClass()

        cls.create_pg_interfaces(range(1))
        for i in cls.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    @classmethod
    def tearDownClass(cls):
        for i in cls.pg_interfaces:
            i.admin_down()

        super(TestPcap, cls).tearDownClass()

    def setUp(self):
        super(TestPcap, self).setUp()

    def tearDown(self):
        super(TestPcap, self).tearDown()

    # This is a code coverage test, but it only runs for 0.3 seconds
    # might as well just run it...
    def test_pcap_unittest(self):
        """PCAP Capture Tests"""
        cmds = [
            "loop create",
            "set int ip address loop0 11.22.33.1/24",
            "set int state loop0 up",
            "loop create",
            "set int ip address loop1 11.22.34.1/24",
            "set int state loop1 up",
            "set ip neighbor loop1 11.22.34.44 03:00:11:22:34:44",
            "packet-generator new {\n"
            "  name s0\n"
            "  limit 10\n"
            "  size 128-128\n"
            "  interface loop0\n"
            "  tx-interface loop1\n"
            "  node loop1-output\n"
            "  buffer-flags ip4 offload\n"
            "  buffer-offload-flags offload-ip-cksum offload-udp-cksum\n"
            "  data {\n"
            "    IP4: 1.2.3 -> dead.0000.0001\n"
            "    UDP: 11.22.33.44 -> 11.22.34.44\n"
            "      ttl 2 checksum 13\n"
            "    UDP: 1234 -> 2345\n"
            "      checksum 11\n"
            "    incrementing 114\n"
            "  }\n"
            "}",
            "pcap dispatch trace on max 100 buffer-trace pg-input 10",
            "pa en",
            "pcap dispatch trace off",
            "pcap trace rx tx max 1000 intfc any",
            "pa en",
            "pcap trace status",
            "pcap trace rx tx off",
            "classify filter pcap mask l3 ip4 src match l3 ip4 src 11.22.33.44",
            "pcap trace rx tx max 1000 intfc any file filt.pcap filter",
            "show cla t verbose 2",
            "show cla t verbose",
            "show cla t",
            "pa en",
            "pcap trace rx tx off",
            "classify filter pcap del mask l3 ip4 src",
        ]

        for cmd in cmds:
            r = self.vapi.cli_return_response(cmd)
            if r.retval != 0:
                if hasattr(r, "reply"):
                    self.logger.info(cmd + " FAIL reply " + r.reply)
                else:
                    self.logger.info(cmd + " FAIL retval " + str(r.retval))

        self.assertTrue(os.path.exists("/tmp/dispatch.pcap"))
        self.assertTrue(os.path.exists("/tmp/rxtx.pcap"))
        self.assertTrue(os.path.exists("/tmp/filt.pcap"))
        os.remove("/tmp/dispatch.pcap")
        os.remove("/tmp/rxtx.pcap")
        os.remove("/tmp/filt.pcap")

    def test_pcap_trace_api(self):
        """PCAP API Tests"""

        pkt = (
            Ether(src=self.pg0.local_mac, dst=self.pg0.remote_mac)
            / IP(src=self.pg0.local_ip4, dst=self.pg0.remote_ip4, ttl=2)
            / UDP(sport=1234, dport=2345)
            / Raw(b"\xa5" * 128)
        )

        self.vapi.pcap_trace_on(
            capture_rx=True,
            capture_tx=True,
            max_packets=1000,
            sw_if_index=0,
            filename="trace_any.pcap",
        )
        self.pg_send(self.pg0, pkt * 10)
        self.vapi.pcap_trace_off()

        self.vapi.cli(
            f"classify filter pcap mask l3 ip4 src match l3 ip4 src {self.pg0.local_ip4}"
        )
        self.vapi.pcap_trace_on(
            capture_rx=True,
            capture_tx=True,
            filter=True,
            max_packets=1000,
            sw_if_index=0,
            filename="trace_any_filter.pcap",
        )
        self.pg_send(self.pg0, pkt * 10)
        self.vapi.pcap_trace_off()
        self.vapi.cli("classify filter pcap del mask l3 ip4 src")

        pkt = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            # wrong destination address
            / IP(src=self.pg0.local_ip4, dst=self.pg0.local_ip4, ttl=2)
            / UDP(sport=1234, dport=2345)
            / Raw(b"\xa5" * 128)
        )

        self.vapi.pcap_trace_on(
            capture_drop=True,
            max_packets=1000,
            sw_if_index=0,
            error="{ip4-local}.{spoofed_local_packets}",
            filename="trace_drop_err.pcap",
        )
        self.pg_send(self.pg0, pkt * 10)
        self.vapi.pcap_trace_off()

        self.assertTrue(os.path.exists("/tmp/trace_any.pcap"))
        self.assertTrue(os.path.exists("/tmp/trace_any_filter.pcap"))
        self.assertTrue(os.path.exists("/tmp/trace_drop_err.pcap"))
        os.remove("/tmp/trace_any.pcap")
        os.remove("/tmp/trace_any_filter.pcap")
        os.remove("/tmp/trace_drop_err.pcap")


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
