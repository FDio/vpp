from config import config
from asfframework import VppTestRunner
import unittest
import re
from framework import VppTestCase
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from random import randint
import ctypes


def create_stream(src_if, dst_if, count):
    packets = []
    for i in range(count):
        p = (
            Ether(dst=src_if.local_mac, src=src_if.remote_mac)
            / IP(src=src_if.remote_ip4, dst=dst_if.remote_ip4)
            / UDP(sport=randint(49152, 65535), dport=5678)
        )
        packets.append(p)

    return packets


@unittest.skipIf(
    "tracedump" in config.excluded_plugins, "Exclude tracedump plugin tests"
)
class TestTracedump(VppTestCase):
    """Tracedump plugin tests"""

    @classmethod
    def setUpClass(cls):
        super(TestTracedump, cls).setUpClass()
        cls.create_pg_interfaces(range(2))
        for i in cls.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    @classmethod
    def tearDownClass(cls):
        for i in cls.pg_interfaces:
            i.unconfig_ip4()
            i.admin_down()
        super(TestTracedump, cls).tearDownClass()

    def test_tracedump_include(self):
        """Check API/CLI output + include node"""
        packets = create_stream(self.pg0, self.pg1, 5)
        self.pg0.add_stream(packets)

        self.vapi.trace_clear_cache()
        self.vapi.trace_clear_capture()
        # get pg-input node index
        reply = self.vapi.graph_node_get(
            cursor=0xFFFFFFFF,
            index=0xFFFFFFFF,
            name="pg-input",
        )
        self.assertTrue(reply[1][0].name == "pg-input")
        pg_input_index = reply[1][0].index
        self.vapi.trace_set_filters(flag=1, node_index=pg_input_index, count=5)
        self.vapi.trace_capture_packets(
            node_index=pg_input_index,
            max_packets=5,
            use_filter=True,
            verbose=True,
            pre_capture_clear=True,
        )

        reply = self.vapi.cli(
            "show graph node want_arcs input drop output punt handoff no_free polling interrupt"
        )
        self.assertIn("af-packet-input", reply)

        self.pg_start()
        reply = self.vapi.trace_v2_dump(
            thread_id=0xFFFFFFFF, position=0, clear_cache=False
        )
        self.assertTrue(reply)
        reply = self.vapi.trace_filter_function_dump()
        self.assertTrue(reply[1].selected)

    def test_tracedump_exclude(self):
        """Exclude node (no trace output)"""
        self.vapi.trace_clear_cache()
        self.vapi.trace_clear_capture()

        packets = create_stream(self.pg0, self.pg1, 5)
        self.pg0.add_stream(packets)

        # exclude node
        reply = self.vapi.graph_node_get(
            cursor=0xFFFFFFFF,
            index=0xFFFFFFFF,
            name="pg-input",
        )
        self.assertTrue(reply[1][0].name == "pg-input")
        pg_input_index = reply[1][0].index
        self.vapi.trace_set_filters(flag=2, node_index=pg_input_index, count=5)
        self.vapi.trace_capture_packets(
            node_index=pg_input_index,
            max_packets=5,
            use_filter=True,
            verbose=True,
            pre_capture_clear=True,
        )
        self.pg_start()
        reply = self.vapi.trace_v2_dump(thread_id=0, position=1, clear_cache=False)
        self.assertFalse(reply)

    def test_trace_timestamp_formats(self):
        """Test trace timestamp format via API"""
        self.vapi.trace_clear_cache()
        self.vapi.trace_clear_capture()

        packets = create_stream(self.pg0, self.pg1, 1)
        self.pg0.add_stream(packets)

        # Setup trace capture
        reply = self.vapi.graph_node_get(
            cursor=0xFFFFFFFF,
            index=0xFFFFFFFF,
            name="pg-input",
        )
        pg_input_index = reply[1][0].index
        self.vapi.trace_capture_packets(
            node_index=pg_input_index,
            max_packets=1,
            use_filter=False,
            verbose=False,
            pre_capture_clear=True,
        )
        self.pg_start()

        # Test relative format (default): HH:MM:SS:uuuuuu
        self.vapi.cli("set trace timestamp-format relative")
        reply = self.vapi.trace_v2_dump(
            thread_id=0xFFFFFFFF, position=0, clear_cache=False
        )
        self.assertTrue(reply, "Expected trace data")
        trace_data = reply[0].trace_data
        self.assertTrue(
            re.search(r"\d{2}:\d{2}:\d{2}:\d+", trace_data),
            f"Expected relative timestamp (HH:MM:SS:uuuuuu) in: {trace_data}",
        )

        # Test unix format: ssssssssss.uuuuuu
        self.vapi.cli("set trace timestamp-format unix")
        reply = self.vapi.trace_v2_dump(
            thread_id=0xFFFFFFFF, position=0, clear_cache=False
        )
        self.assertTrue(reply, "Expected trace data")
        trace_data = reply[0].trace_data
        self.assertTrue(
            re.search(r"\d{10,}\.\d{6}", trace_data),
            f"Expected unix timestamp in: {trace_data}",
        )

        # Test datetime format: YYYY-MM-DDTHH:MM:SS.uuuuuu
        self.vapi.cli("set trace timestamp-format datetime")
        reply = self.vapi.trace_v2_dump(
            thread_id=0xFFFFFFFF, position=0, clear_cache=False
        )
        self.assertTrue(reply, "Expected trace data")
        trace_data = reply[0].trace_data
        self.assertTrue(
            re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}", trace_data),
            f"Expected ISO 8601 datetime in: {trace_data}",
        )

        # Restore default
        self.vapi.cli("set trace timestamp-format relative")
        self.vapi.trace_clear_cache()


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
