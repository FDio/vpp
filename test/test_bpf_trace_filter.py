from framework import VppTestCase
from asfframework import VppTestRunner
import unittest
from config import config
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from random import randint


@unittest.skipIf(
    "bpf_trace_filter" in config.excluded_plugins,
    "Exclude BPF Trace Filter plugin tests",
)
class TestBpfTraceFilter(VppTestCase):
    """BPF Trace filter test"""

    @classmethod
    def setUpClass(cls):
        super(TestBpfTraceFilter, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(2))
            for i in cls.pg_interfaces:
                i.config_ip4()
                i.resolve_arp()
                i.admin_up()
        except Exception:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        for i in cls.pg_interfaces:
            i.unconfig_ip4()
            i.admin_down()
        super(TestBpfTraceFilter, cls).tearDownClass()

    # reset trace filter before each test
    def setUp(self):
        super(TestBpfTraceFilter, self).setUp()
        self.vapi.cli("set trace filter function vnet_is_packet_traced")
        self.vapi.cli("clear trace")

    def create_stream(self, src_if, dst_if, count):
        packets = []
        for i in range(count):
            info = self.create_packet_info(src_if, dst_if)
            payload = self.info_to_payload(info)
            p = (
                Ether(dst=src_if.local_mac, src=src_if.remote_mac)
                / IP(src=src_if.remote_ip4, dst=dst_if.remote_ip4)
                / UDP(sport=randint(49152, 65535), dport=5678)
            )
            info.data = p.copy()
            packets.append(p)
        return packets

    def test_bpf_trace_filter_cli(self):
        """BPF Trace filter test [CLI]"""
        self.vapi.cli("set bpf trace filter {{tcp}}")
        self.vapi.cli("set trace filter function bpf_trace_filter")

        packets = self.create_stream(self.pg0, self.pg1, 3)
        self.pg0.add_stream(packets)
        self.pg_start(traceFilter=True)

        # verify that bpf trace filter has been selected
        reply = self.vapi.cli("show trace filter function")
        self.assertIn(
            "(*) name:bpf_trace_filter", reply, "BPF Trace filter is not selected"
        )

        # verify that trace is empty
        reply = self.vapi.cli("show trace")
        self.assertIn(
            "No packets in trace buffer",
            reply,
            "Unexpected packets in the trace buffer",
        )

    def test_bpf_trace_filter_vapi(self):
        """BPF Trace filter test [VAPI]"""
        self.vapi.bpf_trace_filter_set(filter="tcp")

        packets = self.create_stream(self.pg0, self.pg1, 3)
        self.pg0.add_stream(packets)
        self.pg_start(traceFilter=True)

        # verify that bpf trace filter has been selected
        reply = self.vapi.cli("show trace filter function")
        self.assertIn(
            "(*) name:bpf_trace_filter", reply, "BPF Trace filter is not selected"
        )

        # verify that trace is empty
        reply = self.vapi.cli("show trace")
        self.assertIn(
            "No packets in trace buffer",
            reply,
            "Unexpected packets in the trace buffer",
        )


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
