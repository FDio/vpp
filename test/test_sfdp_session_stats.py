#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2025 Cisco Systems, Inc.

"""
SFDP Session Stats Service Tests

Tests for the session_stats SFDP service that tracks per-session
packet/byte counters and exports them to a stat-segment ring buffer.
"""

import unittest
import struct
import json
from asfframework import VppTestRunner
from framework import VppTestCase
from config import config
from vpp_papi import VppEnum

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP


@unittest.skipIf(
    "sfdp_services" in config.excluded_plugins,
    "SFDP_Services plugin is required to run SFDP Session Stats tests",
)
class TestSfdpSessionStats(VppTestCase):
    """SFDP Session Stats Service tests"""

    @classmethod
    def setUpClass(cls):
        super(TestSfdpSessionStats, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(2))
            for i in cls.pg_interfaces:
                i.config_ip4()
                i.resolve_arp()
                i.admin_up()
        except Exception:
            super(TestSfdpSessionStats, cls).tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        for i in cls.pg_interfaces:
            i.unconfig_ip4()
            i.admin_down()
        super(TestSfdpSessionStats, cls).tearDownClass()

    def create_tcp_packet(
        self, src_mac, dst_mac, src_ip, dst_ip, sport, dport, flags="S", ttl=64
    ):
        return (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip, ttl=ttl)
            / TCP(sport=sport, dport=dport, flags=flags)
            / Raw(b"\xa5" * 100)
        )

    def create_udp_packet(
        self, src_mac, dst_mac, src_ip, dst_ip, sport, dport, ttl=64, payload_size=100
    ):
        return (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip, ttl=ttl)
            / UDP(sport=sport, dport=dport)
            / Raw(b"\xa5" * payload_size)
        )

    def _create_ring_buffer_decoder(self, schema_json):
        """Create a decoder function from the ring buffer schema.

        This dynamically builds a decoder based on the schema, avoiding
        hardcoded offsets and making the test resilient to schema changes.
        """
        print(f"Raw schema_json: {repr(schema_json)}")

        # Validate that schema_json is a valid JSON string
        if schema_json is None:
            raise ValueError("schema_json is None")
        if not isinstance(schema_json, str):
            raise ValueError(f"schema_json must be a string, got {type(schema_json)}")
        if not schema_json.strip():
            raise ValueError("schema_json is empty or contains only whitespace")

        try:
            schema = json.loads(schema_json)
        except json.JSONDecodeError as e:
            raise ValueError(
                f"schema_json is not valid JSON: {e}\nContent: {repr(schema_json)}"
            )
        fields = schema.get("fields", [])

        # Map schema types to struct format characters (little-endian)
        type_map = {
            "u8": ("<B", 1),
            "u16": ("<H", 2),
            "u32": ("<I", 4),
            "u64": ("<Q", 8),
            "f64": ("<d", 8),
            "ip": (None, 16),  # Special handling for IP addresses
            "bytes": (None, None),  # Variable size bytes, uses 'size' field
        }

        def decode_entry(entry_bytes):
            result = {}
            for field in fields:
                print(field)
                name = field["name"]
                ftype = field["type"]
                offset = field["offset"]

                if ftype not in type_map:
                    # Unknown type, skip
                    continue

                fmt, size = type_map[ftype]
                if ftype == "ip":
                    # IP addresses are 16 bytes (IPv4 in first 4, or full IPv6)
                    result[name] = entry_bytes[offset : offset + 16]
                elif ftype == "bytes":
                    # Variable size bytes field (e.g., decorator)
                    size = field.get("size", 0)
                    result[name] = entry_bytes[offset : offset + size]
                else:
                    result[name] = struct.unpack_from(fmt, entry_bytes, offset)[0]
            return result

        return decode_entry, schema

    def _format_ip_from_bytes(self, ip_bytes, is_ip4):
        """Format IP address bytes to string."""
        if is_ip4:
            return ".".join(str(b) for b in ip_bytes[:4])
        else:
            # IPv6: format as hex groups
            parts = []
            for i in range(0, 16, 2):
                parts.append(f"{ip_bytes[i]:02x}{ip_bytes[i+1]:02x}")
            return ":".join(parts)

    @staticmethod
    def _welford_mean_stddev(values):
        """
        Compute mean and stddev using Welford's online algorithm.

        VPP uses Welford's online algorithm for computing running mean and variance:
            For each new value x:
                count += 1
                delta = x - mean
                mean += delta / count
                delta2 = x - mean
                M2 += delta * delta2
            variance = M2 / count  (population variance)
            stddev = sqrt(variance)

        This matches VPP's incremental computation exactly.

        Args:
            values: List of numeric values to compute statistics for

        Returns:
            (mean, stddev) tuple
        """
        import math

        if not values:
            return 0.0, 0.0
        count = 0
        mean = 0.0
        M2 = 0.0
        for x in values:
            count += 1
            delta = x - mean
            mean += delta / count
            delta2 = x - mean
            M2 += delta * delta2
        if count < 2:
            return mean, 0.0
        variance = M2 / count  # Population variance
        return mean, math.sqrt(variance)

    def _configure_sfdp_session_stats(
        self,
        tenant_id=1,
        enable_ring_buffer=False,
        ring_size=256,
        enable_bidirectional=False,
        enable_periodic_export=False,
        export_interval=60.0,
        enable_decorator=False,
        decorator_type=0,
    ):
        """Configure SFDP with session stats service in the chain.

        This is a generic configuration function that can be reused across tests.

        Args:
            tenant_id: Tenant ID to use (default: 1)
            enable_ring_buffer: Enable stat segment ring buffer (default: False)
            ring_size: Ring buffer size when enabled (default: 256)
            enable_bidirectional: Enable SFDP on both pg0 and pg1 (default: False)
            enable_periodic_export: Enable periodic export (default: False)
            export_interval: Periodic export interval in seconds (default: 60.0)
            enable_decorator: Enable decorator (default: False)
            decorator_type: Decorator type when enabled (default: 0/NONE)

        Returns:
            dict with configuration details for cleanup
        """
        self.tenant_id = tenant_id
        config = {
            "tenant_id": tenant_id,
            "bidirectional": enable_bidirectional,
            "ring_buffer_enabled": enable_ring_buffer,
        }

        # Add tenant
        reply = self.vapi.sfdp_tenant_add_del(
            tenant_id=tenant_id,
            context_id=1,
            is_del=False,
        )
        self.assertEqual(reply.retval, 0)

        # Configure services - include session-stats in the chain
        for direction in [
            VppEnum.vl_api_sfdp_session_direction_t.SFDP_API_FORWARD,
            VppEnum.vl_api_sfdp_session_direction_t.SFDP_API_REVERSE,
        ]:
            reply = self.vapi.sfdp_set_services(
                tenant_id=tenant_id,
                dir=direction,
                n_services=3,
                services=[
                    {"data": "sfdp-l4-lifecycle"},
                    {"data": "sfdp-session-stats"},
                    {"data": "ip4-lookup"},
                ],
            )
            self.assertEqual(reply.retval, 0)

        # Enable on pg0
        reply = self.vapi.sfdp_interface_input_set(
            sw_if_index=self.pg0.sw_if_index,
            tenant_id=tenant_id,
            is_disable=False,
        )
        self.assertEqual(reply.retval, 0)

        # Optionally enable on pg1 for bidirectional traffic
        if enable_bidirectional:
            reply = self.vapi.sfdp_interface_input_set(
                sw_if_index=self.pg1.sw_if_index,
                tenant_id=tenant_id,
                is_disable=False,
            )
            self.assertEqual(reply.retval, 0)

        # Enable decorator if requested
        # This should be done before ring buffer is enabled
        if enable_decorator:
            reply = self.vapi.sfdp_session_stats_set_decorator(
                decorator_type=decorator_type, enable=True
            )
            self.assertEqual(reply.retval, 0)

        # Enable ring buffer if requested
        if enable_ring_buffer:
            reply = self.vapi.sfdp_session_stats_ring_enable(
                enable=True, ring_size=ring_size
            )
            self.assertEqual(reply.retval, 0)

        # Enable periodic export if requested
        if enable_periodic_export:
            reply = self.vapi.sfdp_session_stats_periodic_export(
                enable=True, interval=export_interval
            )
            self.assertEqual(reply.retval, 0)

        return config

    def _cleanup_sfdp_session_stats(self, config=None):
        """Cleanup SFDP session stats configuration.

        Args:
            config: Optional config dict returned from _configure_sfdp_session_stats.
                   If None, uses self.tenant_id and assumes single interface.
        """
        if config is None:
            config = {
                "tenant_id": getattr(self, "tenant_id", 1),
                "bidirectional": False,
            }

        tenant_id = config.get("tenant_id", 1)

        # Disable ring buffer if it was enabled
        self.vapi.sfdp_session_stats_ring_enable(enable=False)
        # # Disable ring buffer if it was enabled
        # if config.get("ring_buffer_enabled", False):
        #     self.vapi.sfdp_session_stats_ring_enable(enable=False)

        # Expire active sessions
        self.vapi.sfdp_kill_session(is_all=True)
        self.virtual_sleep(1)

        # Verify sessions are gone
        sessions = self.vapi.sfdp_session_dump()
        self.assertEqual(
            len(sessions), 0, "SFDP sessions are still present after cleanup"
        )

        # Disable SFDP on interfaces
        self.vapi.sfdp_interface_input_set(
            sw_if_index=self.pg0.sw_if_index,
            tenant_id=tenant_id,
            is_disable=True,
        )

        if config.get("bidirectional", False):
            self.vapi.sfdp_interface_input_set(
                sw_if_index=self.pg1.sw_if_index,
                tenant_id=tenant_id,
                is_disable=True,
            )

        # Delete tenant
        self.vapi.sfdp_tenant_add_del(
            tenant_id=tenant_id,
            is_del=True,
        )

    def _configure_sfdp_with_session_stats(self):
        """Configure SFDP with session stats service in the chain.

        Legacy wrapper for backward compatibility with existing tests.
        """
        self._configure_sfdp_session_stats(tenant_id=1)

    def _cleanup_sfdp(self):
        """Cleanup SFDP configuration.

        Legacy wrapper for backward compatibility with existing tests.
        """
        self._cleanup_sfdp_session_stats()

    def test_session_stats_get_config_default(self):
        """Test session stats get config with default values"""
        reply = self.vapi.sfdp_session_stats_get_config()

        self.assertEqual(reply.retval, 0)
        # By default, ring buffer and periodic export should be disabled
        print(reply)
        self.assertFalse(
            reply.ring_buffer_enabled, "Ring buffer should be disabled by default"
        )
        self.assertFalse(
            reply.periodic_export_enabled,
            "Periodic export should be disabled by default",
        )
        # Default export interval should be 60 seconds
        self.assertEqual(
            reply.export_interval, 60.0, "Default export interval should be 60 seconds"
        )

    def test_session_stats_ring_enable_disable(self):
        """Test enabling and disabling the session stats ring buffer"""
        # Enable ring buffer
        reply = self.vapi.sfdp_session_stats_ring_enable(enable=True, ring_size=1024)
        self.assertEqual(reply.retval, 0)

        # Verify it's enabled
        config = self.vapi.sfdp_session_stats_get_config()
        self.assertTrue(
            config.ring_buffer_enabled, "Ring buffer should be enabled after enable"
        )
        self.assertEqual(config.ring_size, 1024, "Ring size should be 1024")

        # Disable ring buffer
        reply = self.vapi.sfdp_session_stats_ring_enable(enable=False)
        self.assertEqual(reply.retval, 0)

        # Verify it's disabled
        config = self.vapi.sfdp_session_stats_get_config()
        self.assertFalse(
            config.ring_buffer_enabled, "Ring buffer should be disabled after disable"
        )

    def test_session_stats_periodic_export_config(self):
        """Test configuring periodic export"""
        # Enable periodic export with custom interval
        reply = self.vapi.sfdp_session_stats_periodic_export(enable=True, interval=30.0)
        self.assertEqual(reply.retval, 0)

        # Verify configuration
        config = self.vapi.sfdp_session_stats_get_config()
        self.assertTrue(
            config.periodic_export_enabled, "Periodic export should be enabled"
        )
        self.assertEqual(
            config.export_interval, 30.0, "Export interval should be 30 seconds"
        )

        # Disable periodic export
        reply = self.vapi.sfdp_session_stats_periodic_export(enable=False)
        self.assertEqual(reply.retval, 0)

        # Verify it's disabled
        config = self.vapi.sfdp_session_stats_get_config()
        self.assertFalse(
            config.periodic_export_enabled, "Periodic export should be disabled"
        )

    def test_session_stats_basic_counting(self):
        """Test basic packet and byte counting for a session"""
        self._configure_sfdp_with_session_stats()

        # Send multiple TCP packets in the forward direction
        num_packets = 5
        payload_size = 100
        packets = []
        for i in range(num_packets):
            pkt = self.create_tcp_packet(
                src_mac=self.pg0.remote_mac,
                dst_mac=self.pg0.local_mac,
                src_ip=self.pg0.remote_ip4,
                dst_ip=self.pg1.remote_ip4,
                sport=12345,
                dport=80,
                flags="S" if i == 0 else "A",  # First packet is SYN, rest are ACK
            )
            packets.append(pkt)

        for pkt in packets:
            self.pg_send(self.pg0, pkt)

        # Dump session stats
        stats = self.vapi.sfdp_session_stats_dump()

        self.assertEqual(len(stats), 1, "Should have exactly one session with stats")

        session_stats = stats[0]
        self.assertEqual(session_stats.proto, 6, "Protocol should be TCP (6)")
        self.assertEqual(
            session_stats.packets_fwd,
            num_packets,
            f"Should have counted {num_packets} forward packets",
        )
        self.assertEqual(
            session_stats.packets_rev, 0, "Should have 0 reverse packets (no replies)"
        )
        # Bytes should be > 0 (includes headers + payload)
        self.assertGreater(
            session_stats.bytes_fwd, 0, "Forward bytes should be greater than 0"
        )

        self._cleanup_sfdp()

    def test_session_stats_bidirectional_counting(self):
        """Test packet counting in both directions"""
        self._configure_sfdp_with_session_stats()

        # Also enable on pg1 for reverse traffic
        reply = self.vapi.sfdp_interface_input_set(
            sw_if_index=self.pg1.sw_if_index,
            tenant_id=self.tenant_id,
            is_disable=False,
        )
        self.assertEqual(reply.retval, 0)

        # Send packets in forward direction (pg0 -> pg1)
        fwd_packets = 3
        for i in range(fwd_packets):
            pkt = self.create_udp_packet(
                src_mac=self.pg0.remote_mac,
                dst_mac=self.pg0.local_mac,
                src_ip=self.pg0.remote_ip4,
                dst_ip=self.pg1.remote_ip4,
                sport=5000,
                dport=53,
            )
            self.pg_send(self.pg0, pkt)

        # Send packets in reverse direction (pg1 -> pg0)
        rev_packets = 2
        for i in range(rev_packets):
            pkt = self.create_udp_packet(
                src_mac=self.pg1.remote_mac,
                dst_mac=self.pg1.local_mac,
                src_ip=self.pg1.remote_ip4,
                dst_ip=self.pg0.remote_ip4,
                sport=53,
                dport=5000,
            )
            self.pg_send(self.pg1, pkt)

        sessions = self.vapi.sfdp_session_dump()
        self.assertEqual(len(sessions), 1, "Expected 1 session to be created")

        # Dump session stats
        stats = self.vapi.sfdp_session_stats_dump()

        self.assertEqual(len(stats), 1, "Should have exactly one session")

        session_stats = stats[0]
        self.assertEqual(session_stats.proto, 17, "Protocol should be UDP (17)")
        self.assertEqual(
            session_stats.packets_fwd,
            fwd_packets,
            f"Should have {fwd_packets} forward packets",
        )
        self.assertEqual(
            session_stats.packets_rev,
            rev_packets,
            f"Should have {rev_packets} reverse packets",
        )

        # Disable on pg1
        self.vapi.sfdp_interface_input_set(
            sw_if_index=self.pg1.sw_if_index,
            tenant_id=self.tenant_id,
            is_disable=True,
        )

        self._cleanup_sfdp()

    def test_session_stats_bidirectional_packets_and_bytes(self):
        """Test that packet and byte counts are tracked correctly in both directions.

        This test verifies via the ring buffer that:
        - Forward packet count matches the number of packets sent from pg0 -> pg1
        - Reverse packet count matches the number of packets sent from pg1 -> pg0
        - Forward byte count matches the total bytes sent (header + payload)
        - Reverse byte count matches the total bytes sent (header + payload)
        - TCP control packet counters (SYN, FIN, RST) are tracked correctly
        - Different packet types (control vs data) are counted properly

        The test sends a realistic TCP session with:
        - SYN, SYN-ACK, ACK (handshake)
        - Data packets with varying payload sizes
        - FIN, FIN-ACK (graceful close)
        - An additional RST packet to verify RST counting
        """
        # Use the generic configuration function with bidirectional and ring buffer enabled
        config = self._configure_sfdp_session_stats(
            enable_bidirectional=True,
            enable_ring_buffer=True,
            ring_size=256,
        )

        sport = 8000
        dport = 9000
        ip_header_size = 20
        tcp_header_size = 20  # Base TCP header without options

        # Track expected values
        expected_fwd_packets = 0
        expected_rev_packets = 0
        expected_fwd_bytes = 0
        expected_rev_bytes = 0
        expected_syn_count = 0
        expected_fin_count = 0
        expected_rst_count = 0

        # === TCP 3-Way Handshake ===
        # MSS option is 4 bytes: 1 byte kind + 1 byte length + 2 bytes value
        mss_option_size = 4
        fwd_mss = 1460
        rev_mss = 1400

        # Forward SYN (pg0 -> pg1) with MSS option
        pkt_syn = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(
                sport=sport,
                dport=dport,
                flags="S",
                seq=1000,
                ack=0,
                options=[("MSS", fwd_mss)],
            )
            / Raw(b"")
        )
        self.pg_send(self.pg0, pkt_syn)
        expected_fwd_packets += 1
        expected_fwd_bytes += ip_header_size + tcp_header_size + mss_option_size
        expected_syn_count += 1

        # Reverse SYN-ACK (pg1 -> pg0) with MSS option
        pkt_synack = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(
                sport=dport,
                dport=sport,
                flags="SA",
                seq=2000,
                ack=1001,
                options=[("MSS", rev_mss)],
            )
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_synack)
        expected_rev_packets += 1
        expected_rev_bytes += ip_header_size + tcp_header_size + mss_option_size
        expected_syn_count += 1  # SYN-ACK also has SYN flag

        # Forward ACK completing handshake
        pkt_ack = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="A", seq=1001, ack=2001)
            / Raw(b"")
        )
        self.pg_send(self.pg0, pkt_ack)
        expected_fwd_packets += 1
        expected_fwd_bytes += ip_header_size + tcp_header_size

        # === Data Transfer Phase ===

        # Forward DATA #1 - small payload (50 bytes)
        payload1_size = 50
        pkt_data1 = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="PA", seq=1001, ack=2001)
            / Raw(b"\xaa" * payload1_size)
        )
        self.pg_send(self.pg0, pkt_data1)
        expected_fwd_packets += 1
        expected_fwd_bytes += ip_header_size + tcp_header_size + payload1_size

        # Reverse ACK for data #1
        pkt_ack1 = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="A", seq=2001, ack=1051)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_ack1)
        expected_rev_packets += 1
        expected_rev_bytes += ip_header_size + tcp_header_size

        # Forward DATA #2 - larger payload (200 bytes)
        payload2_size = 200
        pkt_data2 = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="PA", seq=1051, ack=2001)
            / Raw(b"\xbb" * payload2_size)
        )
        self.pg_send(self.pg0, pkt_data2)
        expected_fwd_packets += 1
        expected_fwd_bytes += ip_header_size + tcp_header_size + payload2_size

        # Reverse DATA #1 - medium payload (100 bytes)
        payload3_size = 100
        pkt_data3 = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="PA", seq=2001, ack=1251)
            / Raw(b"\xcc" * payload3_size)
        )
        self.pg_send(self.pg1, pkt_data3)
        expected_rev_packets += 1
        expected_rev_bytes += ip_header_size + tcp_header_size + payload3_size

        # Forward ACK for reverse data
        pkt_ack2 = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="A", seq=1251, ack=2101)
            / Raw(b"")
        )
        self.pg_send(self.pg0, pkt_ack2)
        expected_fwd_packets += 1
        expected_fwd_bytes += ip_header_size + tcp_header_size

        # === TCP Graceful Close (FIN sequence) ===

        # Forward FIN (client initiates close)
        pkt_fin1 = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="FA", seq=1251, ack=2101)
            / Raw(b"")
        )
        self.pg_send(self.pg0, pkt_fin1)
        expected_fwd_packets += 1
        expected_fwd_bytes += ip_header_size + tcp_header_size
        expected_fin_count += 1

        # Reverse FIN-ACK (server acknowledges and sends FIN)
        pkt_finack = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="FA", seq=2101, ack=1252)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_finack)
        expected_rev_packets += 1
        expected_rev_bytes += ip_header_size + tcp_header_size
        expected_fin_count += 1

        # Forward final ACK
        pkt_final_ack = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="A", seq=1252, ack=2102)
            / Raw(b"")
        )
        self.pg_send(self.pg0, pkt_final_ack)
        expected_fwd_packets += 1
        expected_fwd_bytes += ip_header_size + tcp_header_size

        # === Additional RST packet (to verify RST counter) ===
        # In real scenarios, RST might come after close, or as an abort
        pkt_rst = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="R", seq=2102, ack=0)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_rst)
        expected_rev_packets += 1
        expected_rev_bytes += ip_header_size + tcp_header_size
        expected_rst_count += 1

        # Trigger export to ring buffer
        reply = self.vapi.sfdp_session_stats_export_now()
        self.assertEqual(reply.retval, 0)
        self.virtual_sleep(0.2)

        # Read from ring buffer
        ring_buffer = self.statistics.get_ring_buffer("/sfdp/session/stats")
        schema_string, _, _ = ring_buffer.get_schema_string()
        decode_entry, _ = self._create_ring_buffer_decoder(schema_string)

        data = ring_buffer.consume_data(thread_index=0)
        self.assertGreater(
            len(data), 0, "Should have at least one entry in ring buffer"
        )

        entry = decode_entry(data[0])

        # === Verify Protocol ===
        self.assertEqual(entry["proto"], 6, "Protocol should be TCP (6)")

        # === Verify Packet Counts ===
        print(f"\n=== Packet Counts ===")
        print(
            f"Forward: expected={expected_fwd_packets}, measured={entry['packets_forward']}"
        )
        print(
            f"Reverse: expected={expected_rev_packets}, measured={entry['packets_reverse']}"
        )

        self.assertEqual(
            entry["packets_forward"],
            expected_fwd_packets,
            f"Forward packet count should be {expected_fwd_packets}",
        )
        self.assertEqual(
            entry["packets_reverse"],
            expected_rev_packets,
            f"Reverse packet count should be {expected_rev_packets}",
        )

        # === Verify Byte Counts ===
        print(f"\n=== Byte Counts ===")
        print(
            f"Forward: expected={expected_fwd_bytes}, measured={entry['bytes_forward']}"
        )
        print(
            f"Reverse: expected={expected_rev_bytes}, measured={entry['bytes_reverse']}"
        )

        self.assertEqual(
            entry["bytes_forward"],
            expected_fwd_bytes,
            f"Forward byte count should be {expected_fwd_bytes}",
        )
        self.assertEqual(
            entry["bytes_reverse"],
            expected_rev_bytes,
            f"Reverse byte count should be {expected_rev_bytes}",
        )

        # === Verify TCP Control Packet Counters ===
        print(f"\n=== TCP Control Packet Counters ===")
        print(
            f"SYN: expected={expected_syn_count}, measured={entry['tcp_syn_packets']}"
        )
        print(
            f"FIN: expected={expected_fin_count}, measured={entry['tcp_fin_packets']}"
        )
        print(
            f"RST: expected={expected_rst_count}, measured={entry['tcp_rst_packets']}"
        )

        self.assertEqual(
            entry["tcp_syn_packets"],
            expected_syn_count,
            f"SYN packet count should be {expected_syn_count} (SYN + SYN-ACK)",
        )
        self.assertEqual(
            entry["tcp_fin_packets"],
            expected_fin_count,
            f"FIN packet count should be {expected_fin_count}",
        )
        self.assertEqual(
            entry["tcp_rst_packets"],
            expected_rst_count,
            f"RST packet count should be {expected_rst_count}",
        )

        # === Verify TCP Handshake Complete ===
        self.assertEqual(
            entry["tcp_handshake_complete"],
            1,
            "TCP handshake should be marked as complete",
        )

        # === Verify TCP MSS ===
        # VPP extracts MSS from the first packet in the forward flow (SYN)
        expected_mss = fwd_mss
        print(f"\n=== TCP MSS Verification ===")
        print(
            f"Forward MSS (from SYN): {fwd_mss}, Reverse MSS (from SYN-ACK): {rev_mss}"
        )
        print(
            f"Expected MSS (from forward SYN): {expected_mss}, Measured: {entry['tcp_mss']}"
        )
        self.assertEqual(
            entry["tcp_mss"],
            expected_mss,
            f"TCP MSS should be {expected_mss} (extracted from forward SYN)",
        )

        # === Summary ===
        print(f"\n=== Summary ===")
        print(f"Total packets: fwd={expected_fwd_packets}, rev={expected_rev_packets}")
        print(f"Total bytes: fwd={expected_fwd_bytes}, rev={expected_rev_bytes}")
        print(
            f"Control packets: SYN={expected_syn_count}, FIN={expected_fin_count}, RST={expected_rst_count}"
        )

        # Cleanup
        self._cleanup_sfdp_session_stats(config)

    def test_session_stats_tcp_seq_ack_tracking(self):
        """Test that TCP sequence and acknowledgment numbers are tracked correctly.

        This test verifies via the ring buffer that:
        - Forward and reverse sequence numbers track next expected byte (seq + payload_len)
        - Acknowledgment fields track acks OF each direction's data (from the opposite direction)

        VPP semantics:
        - tcp_last_seq_forward: next expected seq for forward data (seq + len of last forward data)
        - tcp_last_ack_forward: last ack OF forward data (from reverse direction)
        - tcp_last_seq_reverse: next expected seq for reverse data (seq + len of last reverse data)
        - tcp_last_ack_reverse: last ack OF reverse data (from forward direction)

        The test sends traffic in two phases:
        1. First phase: Handshake + initial data exchange, then verify seq/ack
        2. Second phase: Additional data exchange, then verify updated seq/ack
        """
        # Use the generic configuration function with bidirectional and ring buffer enabled
        config = self._configure_sfdp_session_stats(
            enable_bidirectional=True,
            enable_ring_buffer=True,
            ring_size=256,
        )

        sport = 11000
        dport = 12000

        # Track sequence numbers (next expected byte after each data packet)
        # Forward direction: client -> server
        fwd_seq = 1000  # Initial sequence number
        rev_seq = 2000  # Server's initial sequence number

        # Track what VPP should see as "last seq" (next expected byte)
        # and "last ack" (ack of this direction's data from opposite direction)
        vpp_fwd_seq = fwd_seq  # Will be updated to seq + len after data packets
        vpp_rev_seq = rev_seq  # Will be updated to seq + len after data packets
        vpp_ack_of_fwd = 0  # Last ack OF forward data (from reverse direction)
        vpp_ack_of_rev = 0  # Last ack OF reverse data (from forward direction)

        # === Phase 1: TCP Handshake + Initial Data Exchange ===
        print("\n=== Phase 1: Handshake + Initial Data ===")

        # Forward SYN (seq=1000)
        pkt_syn = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="S", seq=fwd_seq, ack=0)
            / Raw(b"")
        )
        self.pg_send(self.pg0, pkt_syn)
        # SYN consumes 1 seq number
        fwd_seq += 1  # Next seq to use = 1001
        vpp_fwd_seq = fwd_seq  # VPP tracks next expected = 1001

        # Reverse SYN-ACK (seq=2000, ack=1001)
        pkt_synack = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="SA", seq=rev_seq, ack=fwd_seq)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_synack)
        vpp_ack_of_fwd = fwd_seq  # Reverse acked forward data up to 1001
        rev_seq += 1  # SYN-ACK consumes 1 seq, next = 2001
        vpp_rev_seq = rev_seq  # VPP tracks next expected = 2001

        # Forward ACK completing handshake (seq=1001, ack=2001)
        pkt_ack = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="A", seq=fwd_seq, ack=rev_seq)
            / Raw(b"")
        )
        self.pg_send(self.pg0, pkt_ack)
        vpp_ack_of_rev = rev_seq  # Forward acked reverse data up to 2001
        # Pure ACK doesn't consume seq, vpp_fwd_seq stays at 1001

        # Forward DATA #1 (100 bytes payload, seq=1001)
        payload1_size = 100
        pkt_data1 = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="PA", seq=fwd_seq, ack=rev_seq)
            / Raw(b"\xaa" * payload1_size)
        )
        self.pg_send(self.pg0, pkt_data1)
        fwd_seq += payload1_size  # Next seq = 1001 + 100 = 1101
        vpp_fwd_seq = fwd_seq  # VPP tracks next expected = 1101

        # Reverse ACK for data #1 (seq=2001, ack=1101)
        pkt_ack1 = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="A", seq=rev_seq, ack=fwd_seq)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_ack1)
        vpp_ack_of_fwd = fwd_seq  # Reverse acked forward data up to 1101
        # Pure ACK doesn't change vpp_rev_seq

        # Reverse DATA #1 (50 bytes payload, seq=2001)
        payload2_size = 50
        pkt_data2 = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="PA", seq=rev_seq, ack=fwd_seq)
            / Raw(b"\xbb" * payload2_size)
        )
        self.pg_send(self.pg1, pkt_data2)
        rev_seq += payload2_size  # Next rev_seq = 2001 + 50 = 2051
        vpp_rev_seq = rev_seq  # VPP tracks next expected = 2051

        # Forward ACK for reverse data (seq=1101, ack=2051)
        pkt_ack2 = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="A", seq=fwd_seq, ack=rev_seq)
            / Raw(b"")
        )
        self.pg_send(self.pg0, pkt_ack2)
        vpp_ack_of_rev = rev_seq  # Forward acked reverse data up to 2051

        # Expected Phase 1 values
        expected_fwd_seq_phase1 = vpp_fwd_seq  # 1101
        expected_fwd_ack_phase1 = vpp_ack_of_fwd  # 1101 (ack OF forward from reverse)
        expected_rev_seq_phase1 = vpp_rev_seq  # 2051
        expected_rev_ack_phase1 = vpp_ack_of_rev  # 2051 (ack OF reverse from forward)

        # === Dump and Verify Phase 1 ===
        reply = self.vapi.sfdp_session_stats_export_now()
        self.assertEqual(reply.retval, 0)
        self.virtual_sleep(0.2)

        ring_buffer = self.statistics.get_ring_buffer("/sfdp/session/stats")
        schema_string, _, _ = ring_buffer.get_schema_string()
        decode_entry, _ = self._create_ring_buffer_decoder(schema_string)

        data = ring_buffer.consume_data(thread_index=0)
        self.assertGreater(
            len(data), 0, "Should have at least one entry in ring buffer"
        )

        entry1 = decode_entry(data[0])

        print(
            f"Phase 1 - Forward: seq={entry1['tcp_last_seq_forward']}, ack={entry1['tcp_last_ack_forward']}"
        )
        print(
            f"Phase 1 - Reverse: seq={entry1['tcp_last_seq_reverse']}, ack={entry1['tcp_last_ack_reverse']}"
        )
        print(
            f"Expected - Forward: seq={expected_fwd_seq_phase1}, ack={expected_fwd_ack_phase1}"
        )
        print(
            f"Expected - Reverse: seq={expected_rev_seq_phase1}, ack={expected_rev_ack_phase1}"
        )

        # Verify Phase 1 packet counts first to help debug seq/ack issues
        # Forward: SYN, ACK (handshake), DATA#1, ACK (for rev data) = 4 packets
        # Reverse: SYN-ACK, ACK (for fwd data), DATA#1 = 3 packets
        expected_fwd_packets_phase1 = 4
        expected_rev_packets_phase1 = 3
        print(
            f"Phase 1 - Packet counts: fwd={entry1['packets_forward']} (expected {expected_fwd_packets_phase1}), "
            f"rev={entry1['packets_reverse']} (expected {expected_rev_packets_phase1})"
        )

        self.assertEqual(
            entry1["packets_forward"],
            expected_fwd_packets_phase1,
            f"Phase 1: Forward packet count should be {expected_fwd_packets_phase1}",
        )
        self.assertEqual(
            entry1["packets_reverse"],
            expected_rev_packets_phase1,
            f"Phase 1: Reverse packet count should be {expected_rev_packets_phase1}",
        )

        # Verify Phase 1 seq/ack values
        self.assertEqual(
            entry1["tcp_last_seq_forward"],
            expected_fwd_seq_phase1,
            f"Phase 1: Forward seq should be {expected_fwd_seq_phase1}",
        )
        self.assertEqual(
            entry1["tcp_last_ack_forward"],
            expected_fwd_ack_phase1,
            f"Phase 1: Forward ack should be {expected_fwd_ack_phase1}",
        )
        self.assertEqual(
            entry1["tcp_last_seq_reverse"],
            expected_rev_seq_phase1,
            f"Phase 1: Reverse seq should be {expected_rev_seq_phase1}",
        )
        self.assertEqual(
            entry1["tcp_last_ack_reverse"],
            expected_rev_ack_phase1,
            f"Phase 1: Reverse ack should be {expected_rev_ack_phase1}",
        )

        # === Phase 2: Additional Data Exchange ===
        print("\n=== Phase 2: Additional Data Exchange ===")

        # Forward DATA #2 (200 bytes payload, seq=1101)
        payload3_size = 200
        pkt_data3 = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="PA", seq=fwd_seq, ack=rev_seq)
            / Raw(b"\xcc" * payload3_size)
        )
        self.pg_send(self.pg0, pkt_data3)
        fwd_seq += payload3_size  # Next seq = 1101 + 200 = 1301
        vpp_fwd_seq = fwd_seq  # VPP tracks next expected = 1301

        # Reverse ACK for data #2 (seq=2051, ack=1301)
        pkt_ack3 = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="A", seq=rev_seq, ack=fwd_seq)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_ack3)
        vpp_ack_of_fwd = fwd_seq  # Reverse acked forward data up to 1301

        # Reverse DATA #2 (150 bytes payload, seq=2051)
        payload4_size = 150
        pkt_data4 = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="PA", seq=rev_seq, ack=fwd_seq)
            / Raw(b"\xdd" * payload4_size)
        )
        self.pg_send(self.pg1, pkt_data4)
        rev_seq += payload4_size  # Next rev_seq = 2051 + 150 = 2201
        vpp_rev_seq = rev_seq  # VPP tracks next expected = 2201

        # Forward ACK for reverse data #2 (seq=1301, ack=2201)
        pkt_ack4 = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="A", seq=fwd_seq, ack=rev_seq)
            / Raw(b"")
        )
        self.pg_send(self.pg0, pkt_ack4)
        vpp_ack_of_rev = rev_seq  # Forward acked reverse data up to 2201

        # Forward DATA #3 (75 bytes payload, seq=1301)
        payload5_size = 75
        pkt_data5 = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="PA", seq=fwd_seq, ack=rev_seq)
            / Raw(b"\xee" * payload5_size)
        )
        self.pg_send(self.pg0, pkt_data5)
        fwd_seq += payload5_size  # Next seq = 1301 + 75 = 1376
        vpp_fwd_seq = fwd_seq  # VPP tracks next expected = 1376

        # Reverse ACK for data #3 (seq=2201, ack=1376)
        pkt_ack5 = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="A", seq=rev_seq, ack=fwd_seq)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_ack5)
        vpp_ack_of_fwd = fwd_seq  # Reverse acked forward data up to 1376

        # Expected Phase 2 values
        expected_fwd_seq_phase2 = vpp_fwd_seq  # 1376
        expected_fwd_ack_phase2 = vpp_ack_of_fwd  # 1376 (ack OF forward from reverse)
        expected_rev_seq_phase2 = vpp_rev_seq  # 2201
        expected_rev_ack_phase2 = vpp_ack_of_rev  # 2201 (ack OF reverse from forward)

        # === Dump and Verify Phase 2 ===
        reply = self.vapi.sfdp_session_stats_export_now()
        self.assertEqual(reply.retval, 0)
        self.virtual_sleep(0.2)

        data = ring_buffer.consume_data(thread_index=0)
        self.assertGreater(
            len(data), 0, "Should have at least one entry in ring buffer"
        )

        entry2 = decode_entry(data[0])

        print(
            f"Phase 2 - Forward: seq={entry2['tcp_last_seq_forward']}, ack={entry2['tcp_last_ack_forward']}"
        )
        print(
            f"Phase 2 - Reverse: seq={entry2['tcp_last_seq_reverse']}, ack={entry2['tcp_last_ack_reverse']}"
        )
        print(
            f"Expected - Forward: seq={expected_fwd_seq_phase2}, ack={expected_fwd_ack_phase2}"
        )
        print(
            f"Expected - Reverse: seq={expected_rev_seq_phase2}, ack={expected_rev_ack_phase2}"
        )

        # Verify Phase 2 seq/ack values
        self.assertEqual(
            entry2["tcp_last_seq_forward"],
            expected_fwd_seq_phase2,
            f"Phase 2: Forward seq should be {expected_fwd_seq_phase2}",
        )
        self.assertEqual(
            entry2["tcp_last_ack_forward"],
            expected_fwd_ack_phase2,
            f"Phase 2: Forward ack should be {expected_fwd_ack_phase2}",
        )
        self.assertEqual(
            entry2["tcp_last_seq_reverse"],
            expected_rev_seq_phase2,
            f"Phase 2: Reverse seq should be {expected_rev_seq_phase2}",
        )
        self.assertEqual(
            entry2["tcp_last_ack_reverse"],
            expected_rev_ack_phase2,
            f"Phase 2: Reverse ack should be {expected_rev_ack_phase2}",
        )

        # === Verify sequence numbers advanced between phases ===
        print("\n=== Verify Sequence Number Advancement ===")
        print(
            f"Forward seq: Phase 1={entry1['tcp_last_seq_forward']} -> Phase 2={entry2['tcp_last_seq_forward']}"
        )
        print(
            f"Forward ack: Phase 1={entry1['tcp_last_ack_forward']} -> Phase 2={entry2['tcp_last_ack_forward']}"
        )
        print(
            f"Reverse seq: Phase 1={entry1['tcp_last_seq_reverse']} -> Phase 2={entry2['tcp_last_seq_reverse']}"
        )
        print(
            f"Reverse ack: Phase 1={entry1['tcp_last_ack_reverse']} -> Phase 2={entry2['tcp_last_ack_reverse']}"
        )

        # Forward seq should have advanced: 1101 -> 1376 (by payload3 + payload5 = 275 bytes)
        self.assertGreater(
            entry2["tcp_last_seq_forward"],
            entry1["tcp_last_seq_forward"],
            "Forward seq should have advanced between phases",
        )
        # Forward ack (ack OF forward from reverse) should have advanced: 1101 -> 1376
        self.assertGreater(
            entry2["tcp_last_ack_forward"],
            entry1["tcp_last_ack_forward"],
            "Forward ack (ack OF forward data) should have advanced between phases",
        )
        # Reverse seq should have advanced: 2051 -> 2201 (by payload4 = 150 bytes)
        self.assertGreater(
            entry2["tcp_last_seq_reverse"],
            entry1["tcp_last_seq_reverse"],
            "Reverse seq should have advanced between phases",
        )
        # Reverse ack (ack OF reverse from forward) should have advanced: 2051 -> 2201
        self.assertGreater(
            entry2["tcp_last_ack_reverse"],
            entry1["tcp_last_ack_reverse"],
            "Reverse ack (ack OF reverse data) should have advanced between phases",
        )

        # Cleanup
        self._cleanup_sfdp_session_stats(config)

    def test_session_stats_tcp_partial_overlap_events(self):
        """Test that TCP partial overlap events are counted correctly.

        A partial overlap occurs when a TCP segment arrives with a sequence number
        that overlaps with already-received data, but also contains new data beyond
        the overlap. This is different from:
        - Full retransmission: entire segment is duplicate data
        - Pure new data: no overlap with previously received data

        Example scenario:
        1. Receive segment with seq=1000, len=100 (bytes 1000-1099)
        2. Receive segment with seq=1050, len=100 (bytes 1050-1149)
           -> Partial overlap: bytes 1050-1099 are duplicates, bytes 1100-1149 are new

        This test includes both regular (non-overlapping) traffic and partial overlaps
        to verify VPP correctly distinguishes between them.
        """
        # Use the generic configuration function with bidirectional and ring buffer enabled
        config = self._configure_sfdp_session_stats(
            enable_bidirectional=True,
            enable_ring_buffer=True,
            ring_size=256,
        )

        sport = 13000
        dport = 14000

        # TCP events are now tracked per direction:
        # Forward: 3 partial overlaps, Reverse: 1 partial overlap

        # === TCP 3-Way Handshake ===
        # Forward SYN
        pkt_syn = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="S", seq=1000, ack=0)
            / Raw(b"")
        )
        self.pg_send(self.pg0, pkt_syn)

        # Reverse SYN-ACK
        pkt_synack = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="SA", seq=2000, ack=1001)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_synack)

        # Forward ACK completing handshake
        pkt_ack = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="A", seq=1001, ack=2001)
            / Raw(b"")
        )
        self.pg_send(self.pg0, pkt_ack)

        # === Regular Data Transfer (no overlap) ===
        print("\n=== Regular data (no overlap) ===")

        # Forward DATA #1: seq=1001, len=100 (bytes 1001-1100) - REGULAR
        payload1_size = 100
        pkt_data1 = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="PA", seq=1001, ack=2001)
            / Raw(b"\xaa" * payload1_size)
        )
        self.pg_send(self.pg0, pkt_data1)
        print(f"DATA #1 (REGULAR): seq=1001, len={payload1_size} (bytes 1001-1100)")

        # === Partial Overlap Scenario ===
        print("\n=== Partial overlap scenario ===")

        # Forward DATA #2 - PARTIAL OVERLAP: seq=1051, len=100 (bytes 1051-1150)
        # Overlap: bytes 1051-1100 (50 bytes already received)
        # New: bytes 1101-1150 (50 bytes new)
        payload2_size = 100
        pkt_data2 = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="PA", seq=1051, ack=2001)
            / Raw(b"\xbb" * payload2_size)
        )
        self.pg_send(self.pg0, pkt_data2)
        # Forward partial overlap #1
        print(
            f"DATA #2 (PARTIAL OVERLAP): seq=1051, len={payload2_size} (bytes 1051-1150)"
        )
        print(
            f"  -> Overlap: bytes 1051-1100 (50 bytes), New: bytes 1101-1150 (50 bytes)"
        )

        # Reverse ACK acknowledging up to byte 1150
        pkt_ack1 = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="A", seq=2001, ack=1151)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_ack1)

        # === More Regular Data ===
        print("\n=== More regular data ===")

        # Forward DATA #3: seq=1151, len=200 (bytes 1151-1350) - REGULAR
        payload3_size = 200
        pkt_data3 = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="PA", seq=1151, ack=2001)
            / Raw(b"\xcc" * payload3_size)
        )
        self.pg_send(self.pg0, pkt_data3)
        print(f"DATA #3 (REGULAR): seq=1151, len={payload3_size} (bytes 1151-1350)")

        # === More Partial Overlaps ===
        print("\n=== More partial overlaps ===")

        # Forward DATA #4 - PARTIAL OVERLAP: seq=1300, len=100 (bytes 1300-1399)
        # Overlap: bytes 1300-1350 (51 bytes already received)
        # New: bytes 1351-1399 (49 bytes new)
        payload4_size = 100
        pkt_data4 = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="PA", seq=1300, ack=2001)
            / Raw(b"\xdd" * payload4_size)
        )
        self.pg_send(self.pg0, pkt_data4)
        # Forward partial overlap #2
        print(
            f"DATA #4 (PARTIAL OVERLAP): seq=1300, len={payload4_size} (bytes 1300-1399)"
        )
        print(
            f"  -> Overlap: bytes 1300-1350 (51 bytes), New: bytes 1351-1399 (49 bytes)"
        )

        # Forward DATA #5 - PARTIAL OVERLAP: seq=1350, len=150 (bytes 1350-1499)
        # Overlap: bytes 1350-1399 (50 bytes from DATA #4)
        # New: bytes 1400-1499 (100 bytes new)
        payload5_size = 150
        pkt_data5 = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="PA", seq=1350, ack=2001)
            / Raw(b"\xee" * payload5_size)
        )
        self.pg_send(self.pg0, pkt_data5)
        # Forward partial overlap #3
        print(
            f"DATA #5 (PARTIAL OVERLAP): seq=1350, len={payload5_size} (bytes 1350-1499)"
        )
        print(
            f"  -> Overlap: bytes 1350-1399 (50 bytes), New: bytes 1400-1499 (100 bytes)"
        )

        # Reverse ACK acknowledging all forward data
        pkt_ack2 = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="A", seq=2001, ack=1500)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_ack2)

        # === Regular Forward Data after overlaps ===
        print("\n=== Regular data after overlaps ===")

        # Forward DATA #6: seq=1500, len=100 (bytes 1500-1599) - REGULAR
        payload6_size = 100
        pkt_data6 = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="PA", seq=1500, ack=2001)
            / Raw(b"\xff" * payload6_size)
        )
        self.pg_send(self.pg0, pkt_data6)
        print(f"DATA #6 (REGULAR): seq=1500, len={payload6_size} (bytes 1500-1599)")

        # Reverse ACK
        pkt_ack3 = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="A", seq=2001, ack=1600)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_ack3)

        # === Reverse Direction: Regular + Partial Overlap ===
        print("\n=== Reverse direction: regular + partial overlap ===")

        # Reverse DATA #1: seq=2001, len=80 (bytes 2001-2080) - REGULAR
        rev_payload1_size = 80
        pkt_rev_data1 = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="PA", seq=2001, ack=1600)
            / Raw(b"\x11" * rev_payload1_size)
        )
        self.pg_send(self.pg1, pkt_rev_data1)
        print(
            f"REV DATA #1 (REGULAR): seq=2001, len={rev_payload1_size} (bytes 2001-2080)"
        )

        # Reverse DATA #2 - PARTIAL OVERLAP: seq=2050, len=80 (bytes 2050-2129)
        # Overlap: bytes 2050-2080 (31 bytes already received)
        # New: bytes 2081-2129 (49 bytes new)
        rev_payload2_size = 80
        pkt_rev_data2 = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="PA", seq=2050, ack=1600)
            / Raw(b"\x22" * rev_payload2_size)
        )
        self.pg_send(self.pg1, pkt_rev_data2)
        # Reverse partial overlap #1
        print(
            f"REV DATA #2 (PARTIAL OVERLAP): seq=2050, len={rev_payload2_size} (bytes 2050-2129)"
        )
        print(
            f"  -> Overlap: bytes 2050-2080 (31 bytes), New: bytes 2081-2129 (49 bytes)"
        )

        # Reverse DATA #3: seq=2130, len=70 (bytes 2130-2199) - REGULAR
        rev_payload3_size = 70
        pkt_rev_data3 = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="PA", seq=2130, ack=1600)
            / Raw(b"\x33" * rev_payload3_size)
        )
        self.pg_send(self.pg1, pkt_rev_data3)
        print(
            f"REV DATA #3 (REGULAR): seq=2130, len={rev_payload3_size} (bytes 2130-2199)"
        )

        # Forward ACK acknowledging all reverse data
        pkt_ack4 = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="A", seq=1600, ack=2200)
            / Raw(b"")
        )
        self.pg_send(self.pg0, pkt_ack4)

        # Trigger export to ring buffer
        reply = self.vapi.sfdp_session_stats_export_now()
        self.assertEqual(reply.retval, 0)
        self.virtual_sleep(0.2)

        # Read from ring buffer
        ring_buffer = self.statistics.get_ring_buffer("/sfdp/session/stats")
        schema_string, _, _ = ring_buffer.get_schema_string()
        decode_entry, _ = self._create_ring_buffer_decoder(schema_string)

        data = ring_buffer.consume_data(thread_index=0)
        self.assertGreater(
            len(data), 0, "Should have at least one entry in ring buffer"
        )

        entry = decode_entry(data[0])

        # === Verify Partial Overlap Events per direction ===
        print(f"\n=== TCP Partial Overlap Events ===")
        expected_fwd_overlaps = 3
        expected_rev_overlaps = 1
        print(
            f"Expected forward: {expected_fwd_overlaps}, reverse: {expected_rev_overlaps}"
        )
        print(
            f"Measured forward: {entry['tcp_partial_overlap_events_fwd']}, "
            f"reverse: {entry['tcp_partial_overlap_events_rev']}"
        )

        self.assertEqual(
            entry["tcp_partial_overlap_events_fwd"],
            expected_fwd_overlaps,
            f"Forward partial overlap events should be {expected_fwd_overlaps}",
        )
        self.assertEqual(
            entry["tcp_partial_overlap_events_rev"],
            expected_rev_overlaps,
            f"Reverse partial overlap events should be {expected_rev_overlaps}",
        )

        # === Verify other counters are as expected ===
        # Should have no retransmissions (partial overlaps have new data)
        print(
            f"Retransmissions fwd: {entry['tcp_retransmissions_fwd']}, "
            f"rev: {entry['tcp_retransmissions_rev']}"
        )

        # Handshake should be complete
        self.assertEqual(
            entry["tcp_handshake_complete"],
            1,
            "TCP handshake should be marked as complete",
        )

        # Verify packet counts
        # Forward: SYN + ACK (handshake) + 6 data packets + 1 ACK (for reverse data) = 9 packets
        # Reverse: SYN-ACK + 3 ACKs + 3 data packets = 7 packets
        expected_fwd_packets = 9
        expected_rev_packets = 7
        print(
            f"\nPacket counts: fwd={entry['packets_forward']} (expected {expected_fwd_packets}), "
            f"rev={entry['packets_reverse']} (expected {expected_rev_packets})"
        )

        self.assertEqual(
            entry["packets_forward"],
            expected_fwd_packets,
            f"Forward packet count should be {expected_fwd_packets}",
        )
        self.assertEqual(
            entry["packets_reverse"],
            expected_rev_packets,
            f"Reverse packet count should be {expected_rev_packets}",
        )

        # Cleanup
        self._cleanup_sfdp_session_stats(config)

    def test_session_stats_tcp_zero_window_events(self):
        """Test that TCP zero window events are counted correctly.

        A zero window event occurs when a TCP receiver advertises window=0,
        indicating its receive buffer is full and it cannot accept more data.
        This is a flow control mechanism.

        VPP counts TRANSITIONS to zero window, not every packet with window=0.
        Consecutive packets with window=0 count as a single event.

        Scenario:
        1. Complete TCP handshake with normal window sizes
        2. Receiver advertises window=0 (1st zero window event in reverse direction)
        3. Consecutive zero windows don't increment the counter
        4. Window opens (non-zero)
        5. Window goes to zero again (2nd zero window event in reverse direction)
        6. Forward direction also sends zero window (1st zero window event in forward direction)
        """
        # Use the generic configuration function with bidirectional and ring buffer enabled
        config = self._configure_sfdp_session_stats(
            enable_bidirectional=True,
            enable_ring_buffer=True,
            ring_size=256,
        )

        sport = 15000
        dport = 16000

        # TCP zero window events are tracked per direction:
        # Forward: 1 transition, Reverse: 2 transitions

        # === TCP 3-Way Handshake ===
        # Forward SYN with normal window
        pkt_syn = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="S", seq=1000, ack=0, window=65535)
            / Raw(b"")
        )
        self.pg_send(self.pg0, pkt_syn)

        # Reverse SYN-ACK with normal window
        pkt_synack = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(
                sport=dport, dport=sport, flags="SA", seq=2000, ack=1001, window=65535
            )
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_synack)

        # Forward ACK completing handshake
        pkt_ack = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="A", seq=1001, ack=2001, window=65535)
            / Raw(b"")
        )
        self.pg_send(self.pg0, pkt_ack)

        # === Data Transfer with Zero Window from Receiver ===
        print("\n=== Data transfer with zero window scenario ===")

        # Forward DATA #1
        pkt_data1 = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(
                sport=sport, dport=dport, flags="PA", seq=1001, ack=2001, window=65535
            )
            / Raw(b"\xaa" * 100)
        )
        self.pg_send(self.pg0, pkt_data1)
        print("DATA #1: seq=1001, len=100 (normal window)")

        # Reverse ACK with ZERO WINDOW - receiver buffer full
        pkt_ack_zw1 = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="A", seq=2001, ack=1101, window=0)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_ack_zw1)
        # Reverse zero window transition #1
        print("ACK #1: ack=1101 with ZERO WINDOW (window=0) - TRANSITION #1 (reverse)")

        # Forward DATA #2 (sender continues despite zero window - may be window probe)
        pkt_data2 = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(
                sport=sport, dport=dport, flags="PA", seq=1101, ack=2001, window=65535
            )
            / Raw(b"\xbb" * 100)
        )
        self.pg_send(self.pg0, pkt_data2)
        print("DATA #2: seq=1101, len=100 (normal window)")

        # Reverse ACK still with ZERO WINDOW - NOT a new transition, same zero window state
        pkt_ack_zw2 = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="A", seq=2001, ack=1201, window=0)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_ack_zw2)
        # NOT incrementing - consecutive zero windows don't count as new events
        print(
            "ACK #2: ack=1201 with ZERO WINDOW (window=0) - still zero, no new transition"
        )

        # Forward DATA #3
        pkt_data3 = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(
                sport=sport, dport=dport, flags="PA", seq=1201, ack=2001, window=65535
            )
            / Raw(b"\xcc" * 100)
        )
        self.pg_send(self.pg0, pkt_data3)
        print("DATA #3: seq=1201, len=100 (normal window)")

        # Reverse ACK with ZERO WINDOW again - NOT a new transition
        pkt_ack_zw3 = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="A", seq=2001, ack=1301, window=0)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_ack_zw3)
        # NOT incrementing - still in zero window state
        print(
            "ACK #3: ack=1301 with ZERO WINDOW (window=0) - still zero, no new transition"
        )

        # === Window Opens - Normal flow resumes ===
        print("\n=== Window opens - normal flow resumes ===")

        # Reverse ACK with window update (non-zero window)
        pkt_ack_wu = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="A", seq=2001, ack=1301, window=32768)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_ack_wu)
        print("ACK (window update): ack=1301 with window=32768 - window opens")

        # Forward DATA #4 - normal
        pkt_data4 = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(
                sport=sport, dport=dport, flags="PA", seq=1301, ack=2001, window=65535
            )
            / Raw(b"\xdd" * 100)
        )
        self.pg_send(self.pg0, pkt_data4)
        print("DATA #4: seq=1301, len=100 (normal window)")

        # Reverse ACK with ZERO WINDOW again - NEW transition (was non-zero, now zero)
        pkt_ack_zw4 = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="A", seq=2001, ack=1401, window=0)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_ack_zw4)
        # Reverse zero window transition #2
        print("ACK #4: ack=1401 with ZERO WINDOW (window=0) - TRANSITION #2 (reverse)")

        # Reverse ACK with window opening again
        pkt_ack_normal = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="A", seq=2001, ack=1401, window=65535)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_ack_normal)
        print("ACK #5: ack=1401 with normal window=65535 - window opens again")

        # === Zero Window from Forward Direction (client) ===
        print("\n=== Zero window from forward direction ===")

        # Reverse DATA #1
        pkt_rev_data1 = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(
                sport=dport, dport=sport, flags="PA", seq=2001, ack=1401, window=65535
            )
            / Raw(b"\x11" * 100)
        )
        self.pg_send(self.pg1, pkt_rev_data1)
        print("REV DATA #1: seq=2001, len=100")

        # Forward ACK with ZERO WINDOW
        pkt_fwd_ack_zw = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="A", seq=1401, ack=2101, window=0)
            / Raw(b"")
        )
        self.pg_send(self.pg0, pkt_fwd_ack_zw)
        # Forward zero window transition #1
        print("FWD ACK: ack=2101 with ZERO WINDOW (window=0) - TRANSITION #3 (forward)")

        # Reverse DATA #2
        pkt_rev_data2 = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(
                sport=dport, dport=sport, flags="PA", seq=2101, ack=1401, window=65535
            )
            / Raw(b"\x22" * 100)
        )
        self.pg_send(self.pg1, pkt_rev_data2)
        print("REV DATA #2: seq=2101, len=100")

        # Forward ACK with normal window (window opens)
        pkt_fwd_ack_normal = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="A", seq=1401, ack=2201, window=65535)
            / Raw(b"")
        )
        self.pg_send(self.pg0, pkt_fwd_ack_normal)
        print("FWD ACK: ack=2201 with normal window=65535")

        # Trigger export to ring buffer
        reply = self.vapi.sfdp_session_stats_export_now()
        self.assertEqual(reply.retval, 0)
        self.virtual_sleep(0.2)

        # Read from ring buffer
        ring_buffer = self.statistics.get_ring_buffer("/sfdp/session/stats")
        schema_string, _, _ = ring_buffer.get_schema_string()
        decode_entry, _ = self._create_ring_buffer_decoder(schema_string)

        data = ring_buffer.consume_data(thread_index=0)
        self.assertGreater(
            len(data), 0, "Should have at least one entry in ring buffer"
        )

        entry = decode_entry(data[0])

        # === Verify Zero Window Events per direction ===
        print(f"\n=== TCP Zero Window Events ===")
        expected_fwd_zero_window = 1
        expected_rev_zero_window = 2
        print(
            f"Expected forward: {expected_fwd_zero_window}, reverse: {expected_rev_zero_window}"
        )
        print(
            f"Measured forward: {entry['tcp_zero_window_events_fwd']}, "
            f"reverse: {entry['tcp_zero_window_events_rev']}"
        )

        self.assertEqual(
            entry["tcp_zero_window_events_fwd"],
            expected_fwd_zero_window,
            f"Forward zero window events should be {expected_fwd_zero_window}",
        )
        self.assertEqual(
            entry["tcp_zero_window_events_rev"],
            expected_rev_zero_window,
            f"Reverse zero window events should be {expected_rev_zero_window}",
        )

        # === Verify handshake completed ===
        self.assertEqual(
            entry["tcp_handshake_complete"],
            1,
            "TCP handshake should be marked as complete",
        )

        # === Verify packet counts ===
        # Forward: SYN + ACK (handshake) + 4 data + 2 ACKs = 8 packets
        # Reverse: SYN-ACK + 6 ACKs + 2 data = 9 packets
        expected_fwd_packets = 8
        expected_rev_packets = 9
        print(
            f"\nPacket counts: fwd={entry['packets_forward']} (expected {expected_fwd_packets}), "
            f"rev={entry['packets_reverse']} (expected {expected_rev_packets})"
        )

        self.assertEqual(
            entry["packets_forward"],
            expected_fwd_packets,
            f"Forward packet count should be {expected_fwd_packets}",
        )
        self.assertEqual(
            entry["packets_reverse"],
            expected_rev_packets,
            f"Reverse packet count should be {expected_rev_packets}",
        )

        # Cleanup
        self._cleanup_sfdp_session_stats(config)

    def test_session_stats_tcp_dupack_events(self):
        """Test that TCP duplicate ACK events are counted correctly.

        A duplicate ACK occurs when the receiver sends an ACK with the same
        acknowledgment number as a previous ACK, while there is outstanding
        data beyond that ACK. This typically indicates packet loss.

        VPP logic (from node.c):
        - dupack detected when: last_ack[ack_dir] == ack && end_seq_max[ack_dir] > ack
        - Tracks per-direction: ack_dir is the direction whose data is being acknowledged

        Scenario:
        1. Sender sends multiple data segments
        2. Receiver sends ACKs with the same ack number (indicating missing segment)
        3. Verify dupack events are counted in both directions
        """
        config = self._configure_sfdp_session_stats(
            enable_bidirectional=True,
            enable_ring_buffer=True,
            ring_size=256,
        )

        sport = 17000
        dport = 18000

        # TCP dupack events are tracked per direction:
        # Forward: 2 dupacks, Reverse: 1 dupack

        # === TCP 3-Way Handshake ===
        pkt_syn = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="S", seq=1000, ack=0)
            / Raw(b"")
        )
        self.pg_send(self.pg0, pkt_syn)

        pkt_synack = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="SA", seq=2000, ack=1001)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_synack)

        pkt_ack = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="A", seq=1001, ack=2001)
            / Raw(b"")
        )
        self.pg_send(self.pg0, pkt_ack)

        # === Forward direction dupack scenario ===
        print("\n=== Forward direction dupack scenario ===")

        # Forward DATA #1: seq=1001, len=100 (bytes 1001-1100)
        pkt_data1 = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="PA", seq=1001, ack=2001)
            / Raw(b"\xaa" * 100)
        )
        self.pg_send(self.pg0, pkt_data1)
        print("FWD DATA #1: seq=1001, len=100")

        # Forward DATA #2: seq=1101, len=100 (bytes 1101-1200)
        pkt_data2 = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="PA", seq=1101, ack=2001)
            / Raw(b"\xbb" * 100)
        )
        self.pg_send(self.pg0, pkt_data2)
        print("FWD DATA #2: seq=1101, len=100")

        # Forward DATA #3: seq=1201, len=100 (bytes 1201-1300)
        pkt_data3 = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="PA", seq=1201, ack=2001)
            / Raw(b"\xcc" * 100)
        )
        self.pg_send(self.pg0, pkt_data3)
        print("FWD DATA #3: seq=1201, len=100")

        # Now end_seq_max[forward] = 1301

        # Reverse ACK #1: ack=1101 (acknowledges DATA #1)
        pkt_ack1 = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="A", seq=2001, ack=1101)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_ack1)
        print("REV ACK #1: ack=1101 (first ACK)")

        # Reverse ACK #2: ack=1101 (same ack - DUPACK for forward data)
        # Condition: last_ack[forward] == 1101, end_seq_max[forward] = 1301 > 1101
        pkt_ack2 = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="A", seq=2001, ack=1101)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_ack2)
        # Forward dupack #1 (detected from reverse ACK)
        print("REV ACK #2: ack=1101 (DUPACK #1 for forward data)")

        # Reverse ACK #3: ack=1101 (another dupack)
        pkt_ack3 = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="A", seq=2001, ack=1101)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_ack3)
        # Forward dupack #2 (detected from reverse ACK)
        print("REV ACK #3: ack=1101 (DUPACK #2 for forward data)")

        # Reverse ACK #4: ack=1301 (acknowledges all forward data - no dupack)
        pkt_ack4 = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="A", seq=2001, ack=1301)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_ack4)
        print("REV ACK #4: ack=1301 (acknowledges all)")

        # === Reverse direction dupack scenario ===
        print("\n=== Reverse direction dupack scenario ===")

        # Reverse DATA #1: seq=2001, len=100 (bytes 2001-2100)
        pkt_rev_data1 = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="PA", seq=2001, ack=1301)
            / Raw(b"\x11" * 100)
        )
        self.pg_send(self.pg1, pkt_rev_data1)
        print("REV DATA #1: seq=2001, len=100")

        # Reverse DATA #2: seq=2101, len=100 (bytes 2101-2200)
        pkt_rev_data2 = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="PA", seq=2101, ack=1301)
            / Raw(b"\x22" * 100)
        )
        self.pg_send(self.pg1, pkt_rev_data2)
        print("REV DATA #2: seq=2101, len=100")

        # Now end_seq_max[reverse] = 2201

        # Forward ACK #1: ack=2101 (acknowledges REV DATA #1)
        pkt_fwd_ack1 = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="A", seq=1301, ack=2101)
            / Raw(b"")
        )
        self.pg_send(self.pg0, pkt_fwd_ack1)
        print("FWD ACK #1: ack=2101 (first ACK)")

        # Forward ACK #2: ack=2101 (same ack - DUPACK for reverse data)
        pkt_fwd_ack2 = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="A", seq=1301, ack=2101)
            / Raw(b"")
        )
        self.pg_send(self.pg0, pkt_fwd_ack2)
        # Reverse dupack #1 (detected from forward ACK)
        print("FWD ACK #2: ack=2101 (DUPACK #1 for reverse data)")

        # Forward ACK #3: ack=2201 (acknowledges all - no dupack)
        pkt_fwd_ack3 = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="A", seq=1301, ack=2201)
            / Raw(b"")
        )
        self.pg_send(self.pg0, pkt_fwd_ack3)
        print("FWD ACK #3: ack=2201 (acknowledges all)")

        # Trigger export to ring buffer
        reply = self.vapi.sfdp_session_stats_export_now()
        self.assertEqual(reply.retval, 0)
        self.virtual_sleep(0.2)

        # Read from ring buffer
        ring_buffer = self.statistics.get_ring_buffer("/sfdp/session/stats")
        schema_string, _, _ = ring_buffer.get_schema_string()
        decode_entry, _ = self._create_ring_buffer_decoder(schema_string)

        data = ring_buffer.consume_data(thread_index=0)
        self.assertGreater(
            len(data), 0, "Should have at least one entry in ring buffer"
        )

        entry = decode_entry(data[0])

        # === Verify Dupack Events per direction ===
        print(f"\n=== TCP Dupack Events ===")
        expected_fwd_dupack = 2
        expected_rev_dupack = 1
        print(
            f"Expected forward: {expected_fwd_dupack}, reverse: {expected_rev_dupack}"
        )
        print(
            f"Measured forward: {entry['tcp_dupack_events_fwd']}, "
            f"reverse: {entry['tcp_dupack_events_rev']}"
        )

        self.assertEqual(
            entry["tcp_dupack_events_fwd"],
            expected_fwd_dupack,
            f"Forward dupack events should be {expected_fwd_dupack}",
        )
        self.assertEqual(
            entry["tcp_dupack_events_rev"],
            expected_rev_dupack,
            f"Reverse dupack events should be {expected_rev_dupack}",
        )

        # Cleanup
        self._cleanup_sfdp_session_stats(config)

    def test_session_stats_tcp_retransmissions(self):
        """Test that TCP retransmission events are counted correctly.

        A retransmission is detected when a segment's entire range (seq to seq+len)
        falls within already-received data (end_seq <= end_seq_max).

        VPP logic (from node.c):
        - retransmission when: end_seq <= end_seq_max[direction]
        - Only for packets with payload_len > 0

        Scenario:
        1. Send data packets normally
        2. Retransmit the same packets
        3. Verify retransmissions are counted in both directions
        """
        config = self._configure_sfdp_session_stats(
            enable_bidirectional=True,
            enable_ring_buffer=True,
            ring_size=256,
        )

        sport = 21000
        dport = 22000

        # TCP retransmissions are tracked per direction:
        # Forward: 2 retransmissions, Reverse: 1 retransmission

        # === TCP 3-Way Handshake ===
        pkt_syn = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="S", seq=1000, ack=0)
            / Raw(b"")
        )
        self.pg_send(self.pg0, pkt_syn)

        pkt_synack = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="SA", seq=2000, ack=1001)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_synack)

        pkt_ack = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="A", seq=1001, ack=2001)
            / Raw(b"")
        )
        self.pg_send(self.pg0, pkt_ack)

        # === Forward direction retransmission scenario ===
        print("\n=== Forward direction retransmission scenario ===")

        # Forward DATA #1: seq=1001, len=100 (bytes 1001-1100)
        pkt_data1 = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="PA", seq=1001, ack=2001)
            / Raw(b"\xaa" * 100)
        )
        self.pg_send(self.pg0, pkt_data1)
        print("FWD DATA #1: seq=1001, len=100 -> end_seq_max=1101")

        # Forward DATA #2: seq=1101, len=100 (bytes 1101-1200)
        pkt_data2 = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="PA", seq=1101, ack=2001)
            / Raw(b"\xbb" * 100)
        )
        self.pg_send(self.pg0, pkt_data2)
        print("FWD DATA #2: seq=1101, len=100 -> end_seq_max=1201")

        # Forward DATA #3: seq=1201, len=100 (bytes 1201-1300)
        pkt_data3 = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="PA", seq=1201, ack=2001)
            / Raw(b"\xcc" * 100)
        )
        self.pg_send(self.pg0, pkt_data3)
        print("FWD DATA #3: seq=1201, len=100 -> end_seq_max=1301")

        # RETRANSMIT DATA #1: same seq=1001, len=100 (complete retransmission)
        # end_seq = 1101 <= end_seq_max = 1301
        pkt_retrans1 = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="PA", seq=1001, ack=2001)
            / Raw(b"\xaa" * 100)
        )
        self.pg_send(self.pg0, pkt_retrans1)
        # Forward retransmission #1
        print("FWD RETRANSMIT #1: seq=1001, len=100 (RETRANSMISSION)")

        # RETRANSMIT DATA #2: same seq=1101, len=100 (complete retransmission)
        pkt_retrans2 = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="PA", seq=1101, ack=2001)
            / Raw(b"\xbb" * 100)
        )
        self.pg_send(self.pg0, pkt_retrans2)
        # Forward retransmission #2
        print("FWD RETRANSMIT #2: seq=1101, len=100 (RETRANSMISSION)")

        # Reverse ACK to acknowledge all
        pkt_ack1 = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="A", seq=2001, ack=1301)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_ack1)
        print("REV ACK: ack=1301")

        # === Reverse direction retransmission scenario ===
        print("\n=== Reverse direction retransmission scenario ===")

        # Reverse DATA #1: seq=2001, len=100 (bytes 2001-2100)
        pkt_rev_data1 = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="PA", seq=2001, ack=1301)
            / Raw(b"\x11" * 100)
        )
        self.pg_send(self.pg1, pkt_rev_data1)
        print("REV DATA #1: seq=2001, len=100 -> end_seq_max=2101")

        # Reverse DATA #2: seq=2101, len=100 (bytes 2101-2200)
        pkt_rev_data2 = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="PA", seq=2101, ack=1301)
            / Raw(b"\x22" * 100)
        )
        self.pg_send(self.pg1, pkt_rev_data2)
        print("REV DATA #2: seq=2101, len=100 -> end_seq_max=2201")

        # RETRANSMIT REV DATA #1: same seq=2001, len=100 (complete retransmission)
        pkt_rev_retrans1 = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="PA", seq=2001, ack=1301)
            / Raw(b"\x11" * 100)
        )
        self.pg_send(self.pg1, pkt_rev_retrans1)
        # Reverse retransmission #1
        print("REV RETRANSMIT #1: seq=2001, len=100 (RETRANSMISSION)")

        # Forward ACK to acknowledge all reverse data
        pkt_fwd_ack = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="A", seq=1301, ack=2201)
            / Raw(b"")
        )
        self.pg_send(self.pg0, pkt_fwd_ack)
        print("FWD ACK: ack=2201")

        # Trigger export to ring buffer
        reply = self.vapi.sfdp_session_stats_export_now()
        self.assertEqual(reply.retval, 0)
        self.virtual_sleep(0.2)

        # Read from ring buffer
        ring_buffer = self.statistics.get_ring_buffer("/sfdp/session/stats")
        schema_string, _, _ = ring_buffer.get_schema_string()
        decode_entry, _ = self._create_ring_buffer_decoder(schema_string)

        data = ring_buffer.consume_data(thread_index=0)
        self.assertGreater(
            len(data), 0, "Should have at least one entry in ring buffer"
        )

        entry = decode_entry(data[0])

        # === Verify Retransmission Events per direction ===
        print(f"\n=== TCP Retransmissions ===")
        expected_fwd_retrans = 2
        expected_rev_retrans = 1
        print(
            f"Expected forward: {expected_fwd_retrans}, reverse: {expected_rev_retrans}"
        )
        print(
            f"Measured forward: {entry['tcp_retransmissions_fwd']}, "
            f"reverse: {entry['tcp_retransmissions_rev']}"
        )

        self.assertEqual(
            entry["tcp_retransmissions_fwd"],
            expected_fwd_retrans,
            f"Forward retransmissions should be {expected_fwd_retrans}",
        )
        self.assertEqual(
            entry["tcp_retransmissions_rev"],
            expected_rev_retrans,
            f"Reverse retransmissions should be {expected_rev_retrans}",
        )

        # Also verify partial overlaps are 0 (these are complete retransmissions)
        print(
            f"Partial overlaps fwd: {entry['tcp_partial_overlap_events_fwd']}, "
            f"rev: {entry['tcp_partial_overlap_events_rev']}"
        )
        self.assertEqual(
            entry["tcp_partial_overlap_events_fwd"],
            0,
            "Forward partial overlaps should be 0 (all were complete retransmissions)",
        )
        self.assertEqual(
            entry["tcp_partial_overlap_events_rev"],
            0,
            "Reverse partial overlaps should be 0 (all were complete retransmissions)",
        )

        # Cleanup
        self._cleanup_sfdp_session_stats(config)

    def test_session_stats_bidirectional_ttl(self):
        """Test that different TTL values in forward and reverse directions are tracked correctly.

        This test verifies:
        - TTL min/max are tracked correctly per direction
        - TTL mean is computed correctly using Welford's online algorithm
        - TTL stddev is computed correctly using Welford's algorithm (population stddev)
        - Forward and reverse directions maintain separate statistics
        - More samples (8 forward, 10 reverse) improve stddev accuracy, allowing tighter tolerances

        VPP uses Welford's online algorithm for computing running mean and variance:
            For each new value x:
                count += 1
                delta = x - mean
                mean += delta / count
                delta2 = x - mean
                M2 += delta * delta2
            variance = M2 / count  (population variance)
            stddev = sqrt(variance)
        """
        # Use the generic configuration function with bidirectional and ring buffer enabled
        config = self._configure_sfdp_session_stats(
            enable_bidirectional=True,
            enable_ring_buffer=True,
            ring_size=256,
        )

        # Define different TTL values for each direction
        # Using more samples improves stddev accuracy with Welford's algorithm
        # Forward direction: 8 TTL values (min=58, max=65, mean=61.5)
        fwd_ttl_values = [65, 64, 63, 62, 61, 60, 59, 58]
        # Reverse direction: 10 TTL values (min=120, max=129, mean=124.5)
        rev_ttl_values = [129, 128, 127, 126, 125, 124, 123, 122, 121, 120]

        # Calculate expected statistics using Welford's algorithm (class method)
        expected_fwd_min = min(fwd_ttl_values)
        expected_fwd_max = max(fwd_ttl_values)
        expected_fwd_mean, expected_fwd_stddev = self._welford_mean_stddev(
            fwd_ttl_values
        )

        expected_rev_min = min(rev_ttl_values)
        expected_rev_max = max(rev_ttl_values)
        expected_rev_mean, expected_rev_stddev = self._welford_mean_stddev(
            rev_ttl_values
        )

        # Tolerance for floating-point comparisons
        # With more samples (8 and 10), Welford's algorithm converges better
        # so we can use tighter tolerances (5% instead of 10%)
        def stddev_tolerance(expected_stddev):
            return max(expected_stddev * 0.10, 0.10)

        # Send packets in forward direction (pg0 -> pg1) with varying TTL
        for i, ttl in enumerate(fwd_ttl_values):
            pkt = self.create_udp_packet(
                src_mac=self.pg0.remote_mac,
                dst_mac=self.pg0.local_mac,
                src_ip=self.pg0.remote_ip4,
                dst_ip=self.pg1.remote_ip4,
                sport=6000,
                dport=53,
                ttl=ttl,
            )
            self.pg_send(self.pg0, pkt)

        # Send packets in reverse direction (pg1 -> pg0) with different TTL values
        for i, ttl in enumerate(rev_ttl_values):
            pkt = self.create_udp_packet(
                src_mac=self.pg1.remote_mac,
                dst_mac=self.pg1.local_mac,
                src_ip=self.pg1.remote_ip4,
                dst_ip=self.pg0.remote_ip4,
                sport=53,
                dport=6000,
                ttl=ttl,
            )
            self.pg_send(self.pg1, pkt)

        # Trigger export to ring buffer
        reply = self.vapi.sfdp_session_stats_export_now()
        self.assertEqual(reply.retval, 0)
        self.virtual_sleep(0.2)

        # Read from ring buffer
        ring_buffer = self.statistics.get_ring_buffer("/sfdp/session/stats")
        schema_string, _, _ = ring_buffer.get_schema_string()
        decode_entry, _ = self._create_ring_buffer_decoder(schema_string)

        data = ring_buffer.consume_data(thread_index=0)
        self.assertGreater(
            len(data), 0, "Should have at least one entry in ring buffer"
        )

        entry = decode_entry(data[0])

        # === Forward Direction TTL Statistics ===
        print(f"\n=== Forward TTL (samples: {fwd_ttl_values}) ===")
        print(
            f"Measured: min={entry['ttl_min_forward']}, max={entry['ttl_max_forward']}, "
            f"mean={entry['ttl_mean_forward']:.2f}, stddev={entry['ttl_stddev_forward']:.4f}"
        )
        print(
            f"Expected: min={expected_fwd_min}, max={expected_fwd_max}, "
            f"mean={expected_fwd_mean:.2f}, stddev={expected_fwd_stddev:.4f}"
        )

        # Verify forward min/max
        self.assertEqual(
            entry["ttl_min_forward"],
            expected_fwd_min,
            f"Forward TTL min should be {expected_fwd_min}",
        )
        self.assertEqual(
            entry["ttl_max_forward"],
            expected_fwd_max,
            f"Forward TTL max should be {expected_fwd_max}",
        )

        # Verify forward mean
        self.assertAlmostEqual(
            entry["ttl_mean_forward"],
            expected_fwd_mean,
            places=1,
            msg=f"Forward TTL mean should be approximately {expected_fwd_mean}",
        )

        # Verify forward stddev
        self.assertGreater(
            entry["ttl_stddev_forward"],
            0,
            "Forward TTL stddev should be > 0 for varying TTL values",
        )
        self.assertAlmostEqual(
            entry["ttl_stddev_forward"],
            expected_fwd_stddev,
            delta=stddev_tolerance(expected_fwd_stddev),
            msg=f"Forward TTL stddev should be ~{expected_fwd_stddev:.3f} "
            f"(+/-{stddev_tolerance(expected_fwd_stddev):.3f})",
        )

        # === Reverse Direction TTL Statistics ===
        print(f"\n=== Reverse TTL (samples: {rev_ttl_values}) ===")
        print(
            f"Measured: min={entry['ttl_min_reverse']}, max={entry['ttl_max_reverse']}, "
            f"mean={entry['ttl_mean_reverse']:.2f}, stddev={entry['ttl_stddev_reverse']:.4f}"
        )
        print(
            f"Expected: min={expected_rev_min}, max={expected_rev_max}, "
            f"mean={expected_rev_mean:.2f}, stddev={expected_rev_stddev:.4f}"
        )

        # Verify reverse min/max
        self.assertEqual(
            entry["ttl_min_reverse"],
            expected_rev_min,
            f"Reverse TTL min should be {expected_rev_min}",
        )
        self.assertEqual(
            entry["ttl_max_reverse"],
            expected_rev_max,
            f"Reverse TTL max should be {expected_rev_max}",
        )

        # Verify reverse mean
        self.assertAlmostEqual(
            entry["ttl_mean_reverse"],
            expected_rev_mean,
            places=1,
            msg=f"Reverse TTL mean should be approximately {expected_rev_mean}",
        )

        # Verify reverse stddev
        self.assertGreater(
            entry["ttl_stddev_reverse"],
            0,
            "Reverse TTL stddev should be > 0 for varying TTL values",
        )
        self.assertAlmostEqual(
            entry["ttl_stddev_reverse"],
            expected_rev_stddev,
            delta=stddev_tolerance(expected_rev_stddev),
            msg=f"Reverse TTL stddev should be ~{expected_rev_stddev:.3f} "
            f"(+/-{stddev_tolerance(expected_rev_stddev):.3f})",
        )

        # === Cross-direction Validation ===
        # Verify forward and reverse TTL ranges are distinct (no overlap)
        self.assertGreater(
            entry["ttl_min_reverse"],
            entry["ttl_max_forward"],
            "Reverse TTL values should be higher than forward TTL values in this test",
        )

        # Verify stddev values differ between directions (different sample counts and spreads)
        print(
            f"\nForward stddev: {entry['ttl_stddev_forward']:.4f}, "
            f"Reverse stddev: {entry['ttl_stddev_reverse']:.4f}"
        )
        print(
            f"Tolerance (10% or 0.10): fwd={stddev_tolerance(expected_fwd_stddev):.4f}, "
            f"rev={stddev_tolerance(expected_rev_stddev):.4f}"
        )
        print(
            f"Sample counts: forward={len(fwd_ttl_values)}, reverse={len(rev_ttl_values)}"
        )

        # === Validate packet counts ===
        self.assertEqual(
            entry["packets_forward"],
            len(fwd_ttl_values),
            f"Should have {len(fwd_ttl_values)} forward packets",
        )
        self.assertEqual(
            entry["packets_reverse"],
            len(rev_ttl_values),
            f"Should have {len(rev_ttl_values)} reverse packets",
        )

        # Cleanup using the config
        self._cleanup_sfdp_session_stats(config)

    def test_session_stats_tcp_rtt_measurement(self):
        """Test that RTT statistics are computed correctly for TCP sessions.

        RTT is measured when an ACK is received acknowledging previously sent data.
        This test simulates a bidirectional TCP exchange with controlled delays
        and verifies RTT measurements are within expected ranges.

        Virtual time is used to simulate delays between data and ACK packets.
        Uses ~500ms delays because VPP processing adds overhead.

        The test uses distinctly different RTT delays to verify the mean calculation:
        - Forward: 3 samples (400ms, 600ms, 800ms) -> expected mean = 600ms
        - Reverse: 2 samples (450ms, 650ms) -> expected mean = 550ms

        VPP uses Welford's online algorithm for computing running mean and variance:
            For each new RTT sample x:
                count += 1
                delta = x - mean
                mean += delta / count
                delta2 = x - mean
                M2 += delta * delta2
            variance = M2 / count  (population variance)
            stddev = sqrt(variance)
        """
        # Use the generic configuration function with bidirectional and ring buffer enabled
        config = self._configure_sfdp_session_stats(
            enable_bidirectional=True,
            enable_ring_buffer=True,
            ring_size=256,
        )

        sport = 7000
        dport = 80

        # Define expected RTT delays (in seconds) with distinct values
        # Using higher values (~500ms) because VPP processing adds overhead
        # Forward direction: 3 samples with different delays
        rtt_delays_fwd = [0.400, 0.600, 0.800]  # 400ms, 600ms, 800ms -> mean = 600ms
        # Reverse direction: 2 samples with different delays
        rtt_delays_rev = [0.450, 0.650]  # 450ms, 650ms -> mean = 550ms

        # Calculate expected statistics using Welford's algorithm (class method)
        expected_fwd_rtt_mean, expected_fwd_stddev = self._welford_mean_stddev(
            rtt_delays_fwd
        )
        expected_rev_rtt_mean, expected_rev_stddev = self._welford_mean_stddev(
            rtt_delays_rev
        )

        # Tolerance for RTT measurements (10% or 50ms, whichever is larger)
        # Accounts for VPP processing overhead and floating-point precision
        def rtt_tolerance(expected_rtt):
            return max(expected_rtt * 0.1, 0.050)

        # Step 1: Forward SYN (pg0 -> pg1)
        pkt_syn = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="S", seq=1000, ack=0)
            / Raw(b"")
        )
        self.pg_send(self.pg0, pkt_syn)

        # Step 2: Reverse SYN-ACK (from server)
        pkt_synack = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="SA", seq=2000, ack=1001)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_synack)

        # Step 3: Forward ACK completing handshake
        pkt_ack = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="A", seq=1001, ack=2001)
            / Raw(b"")
        )
        self.pg_send(self.pg0, pkt_ack)

        # Track sequence numbers for data packets
        fwd_seq = 1001
        rev_seq = 2001
        fwd_ack = 2001
        rev_ack = 1001

        # === Forward RTT Sample #1 (400ms) ===
        # Forward DATA #1 (100 bytes payload)
        pkt_data_fwd1 = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="PA", seq=fwd_seq, ack=fwd_ack)
            / Raw(b"\xaa" * 100)
        )
        self.pg_send(self.pg0, pkt_data_fwd1)
        fwd_seq += 100

        self.virtual_sleep(rtt_delays_fwd[0])

        # Reverse ACK #1 acknowledging forward data
        pkt_ack_rev1 = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="A", seq=rev_seq, ack=fwd_seq)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_ack_rev1)
        rev_ack = fwd_seq

        # === Reverse RTT Sample #1 (450ms) ===
        # Reverse DATA #1 (50 bytes payload)
        pkt_data_rev1 = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="PA", seq=rev_seq, ack=rev_ack)
            / Raw(b"\xbb" * 50)
        )
        self.pg_send(self.pg1, pkt_data_rev1)
        rev_seq += 50

        self.virtual_sleep(rtt_delays_rev[0])

        # Forward ACK #1 acknowledging reverse data
        pkt_ack_fwd1 = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="A", seq=fwd_seq, ack=rev_seq)
            / Raw(b"")
        )
        self.pg_send(self.pg0, pkt_ack_fwd1)
        fwd_ack = rev_seq

        # === Forward RTT Sample #2 (600ms) ===
        # Forward DATA #2 (100 bytes payload)
        pkt_data_fwd2 = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="PA", seq=fwd_seq, ack=fwd_ack)
            / Raw(b"\xcc" * 100)
        )
        self.pg_send(self.pg0, pkt_data_fwd2)
        fwd_seq += 100

        self.virtual_sleep(rtt_delays_fwd[1])

        # Reverse ACK #2 acknowledging forward data
        pkt_ack_rev2 = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="A", seq=rev_seq, ack=fwd_seq)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_ack_rev2)
        rev_ack = fwd_seq

        # === Reverse RTT Sample #2 (650ms) ===
        # Reverse DATA #2 (50 bytes payload)
        pkt_data_rev2 = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="PA", seq=rev_seq, ack=rev_ack)
            / Raw(b"\xdd" * 50)
        )
        self.pg_send(self.pg1, pkt_data_rev2)
        rev_seq += 50

        self.virtual_sleep(rtt_delays_rev[1])

        # Forward ACK #2 acknowledging reverse data
        pkt_ack_fwd2 = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="A", seq=fwd_seq, ack=rev_seq)
            / Raw(b"")
        )
        self.pg_send(self.pg0, pkt_ack_fwd2)
        fwd_ack = rev_seq

        # === Forward RTT Sample #3 (800ms) ===
        # Forward DATA #3 (100 bytes payload)
        pkt_data_fwd3 = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="PA", seq=fwd_seq, ack=fwd_ack)
            / Raw(b"\xee" * 100)
        )
        self.pg_send(self.pg0, pkt_data_fwd3)
        fwd_seq += 100

        self.virtual_sleep(rtt_delays_fwd[2])

        # Reverse ACK #3 acknowledging forward data
        pkt_ack_rev3 = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="A", seq=rev_seq, ack=fwd_seq)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_ack_rev3)

        # Trigger export to ring buffer
        reply = self.vapi.sfdp_session_stats_export_now()
        self.assertEqual(reply.retval, 0)
        self.virtual_sleep(0.01)

        # Read from ring buffer
        ring_buffer = self.statistics.get_ring_buffer("/sfdp/session/stats")
        schema_string, _, _ = ring_buffer.get_schema_string()
        decode_entry, _ = self._create_ring_buffer_decoder(schema_string)

        data = ring_buffer.consume_data(thread_index=0)
        self.assertGreater(
            len(data), 0, "Should have at least one entry in ring buffer"
        )

        entry = decode_entry(data[0])

        # Print measured vs expected values
        print(
            f"\n=== Forward RTT (3 samples: {[d*1000 for d in rtt_delays_fwd]}ms) ==="
        )
        print(
            f"Measured: mean={entry['rtt_mean_forward']*1000:.1f}ms, "
            f"stddev={entry['rtt_stddev_forward']*1000:.1f}ms"
        )
        print(
            f"Expected: mean={expected_fwd_rtt_mean*1000:.1f}ms, "
            f"stddev={expected_fwd_stddev*1000:.1f}ms"
        )

        print(
            f"\n=== Reverse RTT (2 samples: {[d*1000 for d in rtt_delays_rev]}ms) ==="
        )
        print(
            f"Measured: mean={entry['rtt_mean_reverse']*1000:.1f}ms, "
            f"stddev={entry['rtt_stddev_reverse']*1000:.1f}ms"
        )
        print(
            f"Expected: mean={expected_rev_rtt_mean*1000:.1f}ms, "
            f"stddev={expected_rev_stddev*1000:.1f}ms"
        )

        # === Verify Forward RTT Mean ===
        fwd_tolerance = rtt_tolerance(expected_fwd_rtt_mean)
        self.assertGreater(
            entry["rtt_mean_forward"],
            0.0,
            "Forward RTT mean should be > 0 (RTT was measured)",
        )
        self.assertAlmostEqual(
            entry["rtt_mean_forward"],
            expected_fwd_rtt_mean,
            delta=fwd_tolerance,
            msg=f"Forward RTT mean should be ~{expected_fwd_rtt_mean*1000:.0f}ms "
            f"(+/-{fwd_tolerance*1000:.0f}ms), got {entry['rtt_mean_forward']*1000:.0f}ms",
        )

        # Verify forward mean is NOT close to individual samples (proves averaging)
        for i, delay in enumerate(rtt_delays_fwd):
            if (
                abs(delay - expected_fwd_rtt_mean) > 0.050
            ):  # Only check if sample differs from mean
                self.assertNotAlmostEqual(
                    entry["rtt_mean_forward"],
                    delay,
                    delta=0.030,
                    msg=f"Forward RTT mean should not equal sample {i+1} ({delay*1000:.0f}ms)",
                )

        # === Verify Forward RTT Stddev ===
        # With samples 400ms, 600ms, 800ms, stddev should be ~163ms
        self.assertGreater(
            entry["rtt_stddev_forward"],
            0.0,
            "Forward RTT stddev should be > 0 with varying RTT samples",
        )
        self.assertAlmostEqual(
            entry["rtt_stddev_forward"],
            expected_fwd_stddev,
            delta=rtt_tolerance(expected_fwd_stddev),
            msg=f"Forward RTT stddev should be ~{expected_fwd_stddev*1000:.0f}ms",
        )

        # === Verify Reverse RTT Mean ===
        rev_tolerance = rtt_tolerance(expected_rev_rtt_mean)
        self.assertGreater(
            entry["rtt_mean_reverse"],
            0.0,
            "Reverse RTT mean should be > 0 (RTT was measured)",
        )
        self.assertAlmostEqual(
            entry["rtt_mean_reverse"],
            expected_rev_rtt_mean,
            delta=rev_tolerance,
            msg=f"Reverse RTT mean should be ~{expected_rev_rtt_mean*1000:.0f}ms "
            f"(+/-{rev_tolerance*1000:.0f}ms), got {entry['rtt_mean_reverse']*1000:.0f}ms",
        )

        # Verify reverse mean is NOT equal to individual samples (proves averaging)
        for i, delay in enumerate(rtt_delays_rev):
            self.assertNotAlmostEqual(
                entry["rtt_mean_reverse"],
                delay,
                delta=0.030,
                msg=f"Reverse RTT mean should not equal sample {i+1} ({delay*1000:.0f}ms)",
            )

        # === Verify Reverse RTT Stddev ===
        # With samples 450ms and 650ms, stddev should be 100ms
        self.assertGreater(
            entry["rtt_stddev_reverse"],
            0.0,
            "Reverse RTT stddev should be > 0 with varying RTT samples",
        )
        self.assertAlmostEqual(
            entry["rtt_stddev_reverse"],
            expected_rev_stddev,
            delta=rtt_tolerance(expected_rev_stddev),
            msg=f"Reverse RTT stddev should be ~{expected_rev_stddev*1000:.0f}ms",
        )

        # === Verify RTT means differ between directions ===
        self.assertNotAlmostEqual(
            entry["rtt_mean_forward"],
            entry["rtt_mean_reverse"],
            delta=0.030,
            msg="Forward and reverse RTT means should differ",
        )

        # === Verify TCP handshake was tracked ===
        self.assertEqual(
            entry["tcp_handshake_complete"],
            1,
            "TCP handshake should be marked as complete",
        )

        # === Verify TCP packet counts ===
        # Forward: SYN, ACK (handshake), DATA#1, ACK#1, DATA#2, ACK#2, DATA#3 = 7 packets
        # Reverse: SYN-ACK, ACK#1, DATA#1, ACK#2, DATA#2, ACK#3 = 6 packets
        self.assertEqual(entry["packets_forward"], 7, "Should have 7 forward packets")
        self.assertEqual(entry["packets_reverse"], 6, "Should have 6 reverse packets")

        # Verify TCP SYN count
        self.assertGreaterEqual(
            entry["tcp_syn_packets"], 1, "Should have at least 1 SYN packet"
        )

        # Print sequence tracking info
        print(
            f"\nTCP seq/ack forward: seq={entry['tcp_last_seq_forward']}, ack={entry['tcp_last_ack_forward']}"
        )
        print(
            f"TCP seq/ack reverse: seq={entry['tcp_last_seq_reverse']}, ack={entry['tcp_last_ack_reverse']}"
        )

        # Cleanup
        self._cleanup_sfdp_session_stats(config)

    def test_session_stats_multiple_sessions(self):
        """Test stats tracking across multiple sessions"""
        self._configure_sfdp_with_session_stats()

        # Create 3 different sessions with different packet counts
        sessions_config = [
            {"sport": 10001, "dport": 80, "packets": 2},
            {"sport": 10002, "dport": 443, "packets": 5},
            {"sport": 10003, "dport": 8080, "packets": 1},
        ]

        for sess_cfg in sessions_config:
            for i in range(sess_cfg["packets"]):
                pkt = self.create_tcp_packet(
                    src_mac=self.pg0.remote_mac,
                    dst_mac=self.pg0.local_mac,
                    src_ip=self.pg0.remote_ip4,
                    dst_ip=self.pg1.remote_ip4,
                    sport=sess_cfg["sport"],
                    dport=sess_cfg["dport"],
                    flags="S" if i == 0 else "A",
                )
                self.pg_send(self.pg0, pkt)

        # Dump session stats
        stats = self.vapi.sfdp_session_stats_dump()

        self.assertEqual(len(stats), 3, "Should have exactly 3 sessions with stats")

        # Verify each session has the correct packet count
        for sess_stats in stats:
            # Find corresponding config
            found = False
            for sess_cfg in sessions_config:
                if sess_stats.dst_port == sess_cfg["dport"]:
                    self.assertEqual(
                        sess_stats.packets_fwd,
                        sess_cfg["packets"],
                        f"Session to port {sess_cfg['dport']} should have "
                        f"{sess_cfg['packets']} packets",
                    )
                    found = True
                    break
            self.assertTrue(
                found, f"Found unexpected session to port {sess_stats.dst_port}"
            )

        self._cleanup_sfdp()

    def test_session_stats_clear(self):
        """Test clearing session stats"""
        self._configure_sfdp_with_session_stats()

        # Send some packets
        for i in range(3):
            pkt = self.create_tcp_packet(
                src_mac=self.pg0.remote_mac,
                dst_mac=self.pg0.local_mac,
                src_ip=self.pg0.remote_ip4,
                dst_ip=self.pg1.remote_ip4,
                sport=20000,
                dport=80,
                flags="S" if i == 0 else "A",
            )
            self.pg_send(self.pg0, pkt)

        # Verify stats exist
        stats = self.vapi.sfdp_session_stats_dump()
        self.assertEqual(len(stats), 1, "Should have one session")
        self.assertEqual(stats[0].packets_fwd, 3, "Should have 3 packets")

        # Clear all stats
        reply = self.vapi.sfdp_session_stats_clear()
        self.assertEqual(reply.retval, 0)

        # Verify stats are cleared (dump should return empty since counters are 0)
        stats = self.vapi.sfdp_session_stats_dump()
        self.assertEqual(len(stats), 0, "Stats should be cleared")

        self._cleanup_sfdp()

    def test_session_stats_filter_by_tenant(self):
        """Test filtering session stats dump by tenant"""
        # Configure two tenants
        for tenant_id in [1, 2]:
            reply = self.vapi.sfdp_tenant_add_del(
                tenant_id=tenant_id,
                context_id=tenant_id,
                is_del=False,
            )
            self.assertEqual(reply.retval, 0)

            reply = self.vapi.sfdp_set_services(
                tenant_id=tenant_id,
                dir=VppEnum.vl_api_sfdp_session_direction_t.SFDP_API_FORWARD,
                n_services=3,
                services=[
                    {"data": "sfdp-l4-lifecycle"},
                    {"data": "sfdp-session-stats"},
                    {"data": "ip4-lookup"},
                ],
            )
            self.assertEqual(reply.retval, 0)

            reply = self.vapi.sfdp_set_services(
                tenant_id=tenant_id,
                dir=VppEnum.vl_api_sfdp_session_direction_t.SFDP_API_REVERSE,
                n_services=3,
                services=[
                    {"data": "sfdp-l4-lifecycle"},
                    {"data": "sfdp-session-stats"},
                    {"data": "ip4-lookup"},
                ],
            )
            self.assertEqual(reply.retval, 0)

        # Enable tenant 1 on pg0
        reply = self.vapi.sfdp_interface_input_set(
            sw_if_index=self.pg0.sw_if_index,
            tenant_id=1,
            is_disable=False,
        )
        self.assertEqual(reply.retval, 0)

        # Enable tenant 2 on pg1
        reply = self.vapi.sfdp_interface_input_set(
            sw_if_index=self.pg1.sw_if_index,
            tenant_id=2,
            is_disable=False,
        )
        self.assertEqual(reply.retval, 0)

        # Send traffic for tenant 1 (pg0)
        pkt1 = self.create_tcp_packet(
            src_mac=self.pg0.remote_mac,
            dst_mac=self.pg0.local_mac,
            src_ip=self.pg0.remote_ip4,
            dst_ip=self.pg1.remote_ip4,
            sport=30000,
            dport=80,
        )
        self.pg_send(self.pg0, pkt1)

        # Send traffic for tenant 2 (pg1)
        pkt2 = self.create_tcp_packet(
            src_mac=self.pg1.remote_mac,
            dst_mac=self.pg1.local_mac,
            src_ip=self.pg1.remote_ip4,
            dst_ip=self.pg0.remote_ip4,
            sport=40000,
            dport=443,
        )
        self.pg_send(self.pg1, pkt2)

        # Get all stats
        all_stats = self.vapi.sfdp_session_stats_dump()
        self.assertEqual(len(all_stats), 2, "Should have 2 sessions total")

        # Filter by tenant 1
        tenant1_stats = self.vapi.sfdp_session_stats_dump(tenant_idx=0)
        self.assertEqual(len(tenant1_stats), 1, "Should have 1 session for tenant 1")

        # Filter by tenant 2
        tenant2_stats = self.vapi.sfdp_session_stats_dump(tenant_idx=1)
        self.assertEqual(len(tenant2_stats), 1, "Should have 1 session for tenant 2")

        # Cleanup
        self.vapi.sfdp_kill_session(is_all=True)
        self.virtual_sleep(1)

        self.vapi.sfdp_interface_input_set(
            sw_if_index=self.pg0.sw_if_index,
            tenant_id=1,
            is_disable=True,
        )
        self.vapi.sfdp_interface_input_set(
            sw_if_index=self.pg1.sw_if_index,
            tenant_id=2,
            is_disable=True,
        )

        self.vapi.sfdp_tenant_add_del(tenant_id=1, is_del=True)
        self.vapi.sfdp_tenant_add_del(tenant_id=2, is_del=True)

    def test_session_stats_export_now(self):
        """Test triggering immediate export to ring buffer"""
        self._configure_sfdp_with_session_stats()

        # Enable ring buffer first
        reply = self.vapi.sfdp_session_stats_ring_enable(enable=True, ring_size=256)
        self.assertEqual(reply.retval, 0)

        # Send some packets to create a session with stats
        for i in range(3):
            pkt = self.create_tcp_packet(
                src_mac=self.pg0.remote_mac,
                dst_mac=self.pg0.local_mac,
                src_ip=self.pg0.remote_ip4,
                dst_ip=self.pg1.remote_ip4,
                sport=50000,
                dport=80,
                flags="S" if i == 0 else "A",
            )
            self.pg_send(self.pg0, pkt)

        # Get initial export count
        config_before = self.vapi.sfdp_session_stats_get_config()
        exports_before = config_before.total_exports

        # Trigger export
        reply = self.vapi.sfdp_session_stats_export_now()
        self.assertEqual(reply.retval, 0)

        # Give a moment for the export to happen
        self.virtual_sleep(0.1)

        # Verify export count increased
        config_after = self.vapi.sfdp_session_stats_get_config()
        exports_after = config_after.total_exports

        self.assertGreater(
            exports_after,
            exports_before,
            "Total exports should have increased after export_now",
        )

        # Disable ring buffer
        self.vapi.sfdp_session_stats_ring_enable(enable=False)

        self._cleanup_sfdp()

    def test_session_stats_timestamps(self):
        """Test that first_seen and last_seen timestamps are set correctly"""
        self._configure_sfdp_with_session_stats()

        # Send first packet
        pkt = self.create_tcp_packet(
            src_mac=self.pg0.remote_mac,
            dst_mac=self.pg0.local_mac,
            src_ip=self.pg0.remote_ip4,
            dst_ip=self.pg1.remote_ip4,
            sport=60000,
            dport=80,
            flags="S",
        )
        self.pg_send(self.pg0, pkt)

        # Get stats after first packet
        stats1 = self.vapi.sfdp_session_stats_dump()
        self.assertEqual(len(stats1), 1)
        first_seen = stats1[0].first_seen
        last_seen_1 = stats1[0].last_seen

        self.assertGreater(first_seen, 0, "first_seen should be set")
        self.assertGreater(last_seen_1, 0, "last_seen should be set")
        self.assertGreaterEqual(
            last_seen_1, first_seen, "last_seen should be >= first_seen"
        )

        # Wait a bit and send another packet
        self.virtual_sleep(0.5)

        pkt2 = self.create_tcp_packet(
            src_mac=self.pg0.remote_mac,
            dst_mac=self.pg0.local_mac,
            src_ip=self.pg0.remote_ip4,
            dst_ip=self.pg1.remote_ip4,
            sport=60000,
            dport=80,
            flags="A",
        )
        self.pg_send(self.pg0, pkt2)

        # Get stats after second packet
        stats2 = self.vapi.sfdp_session_stats_dump()
        self.assertEqual(len(stats2), 1)
        last_seen_2 = stats2[0].last_seen

        # first_seen should remain the same
        self.assertEqual(
            stats2[0].first_seen, first_seen, "first_seen should not change"
        )
        # last_seen should have been updated
        self.assertGreater(
            last_seen_2, last_seen_1, "last_seen should have been updated"
        )

        self._cleanup_sfdp()

    def test_session_stats_cli_show(self):
        """Test session stats CLI commands"""
        self._configure_sfdp_with_session_stats()

        # Send some packets
        for i in range(2):
            pkt = self.create_udp_packet(
                src_mac=self.pg0.remote_mac,
                dst_mac=self.pg0.local_mac,
                src_ip=self.pg0.remote_ip4,
                dst_ip=self.pg1.remote_ip4,
                sport=7000,
                dport=53,
            )
            self.pg_send(self.pg0, pkt)

        # Test show command
        output = self.vapi.cli("show sfdp session stats")
        print(output)
        self.assertIn("Session", output, "CLI output should contain session info")

        # Test verbose output
        output_verbose = self.vapi.cli("show sfdp session stats verbose")
        print(output_verbose)
        self.assertIn("Session", output_verbose)

        self._cleanup_sfdp()

    def test_session_stats_decorator_config(self):
        """Test decorator configuration via API"""
        # Get default decorator config
        reply = self.vapi.sfdp_session_stats_get_decorator()
        self.assertEqual(reply.retval, 0)
        self.assertFalse(
            reply.decorator_enabled, "Decorator should be disabled by default"
        )
        # decorator_type 0 = NONE
        self.assertEqual(
            reply.decorator_type, 0, "Decorator type should be NONE by default"
        )

        # Enable decorator with CUSTOM_U64 type (1)
        reply = self.vapi.sfdp_session_stats_set_decorator(
            decorator_type=1, enable=True  # CUSTOM_U64
        )
        self.assertEqual(reply.retval, 0)

        # Verify decorator is enabled
        reply = self.vapi.sfdp_session_stats_get_decorator()
        self.assertEqual(reply.retval, 0)
        self.assertTrue(reply.decorator_enabled, "Decorator should be enabled")
        self.assertEqual(
            reply.decorator_type, 1, "Decorator type should be CUSTOM_U64 (1)"
        )

        # Also verify via get_config
        config = self.vapi.sfdp_session_stats_get_config()
        self.assertTrue(
            config.decorator_enabled, "Decorator should be enabled in config"
        )
        self.assertEqual(
            config.decorator_type, 1, "Decorator type should be CUSTOM_U64 in config"
        )

        # Change to CUSTOM_U32 type (2)
        reply = self.vapi.sfdp_session_stats_set_decorator(
            decorator_type=2, enable=True  # CUSTOM_U32
        )
        self.assertEqual(reply.retval, 0)

        reply = self.vapi.sfdp_session_stats_get_decorator()
        self.assertEqual(
            reply.decorator_type, 2, "Decorator type should be CUSTOM_U32 (2)"
        )

        # Disable decorator
        reply = self.vapi.sfdp_session_stats_set_decorator(
            decorator_type=0, enable=False
        )
        self.assertEqual(reply.retval, 0)

        reply = self.vapi.sfdp_session_stats_get_decorator()
        self.assertFalse(reply.decorator_enabled, "Decorator should be disabled")

    def test_session_stats_cli_ring_enable(self):
        """Test session stats ring buffer CLI commands"""
        # Enable ring buffer via CLI
        self.vapi.cli("sfdp session stats ring enable size 512")

        # Verify via API
        config = self.vapi.sfdp_session_stats_get_config()
        self.assertTrue(config.ring_buffer_enabled, "Ring should be enabled via CLI")
        self.assertEqual(config.ring_size, 512, "Ring size should be 512")

        # Disable via CLI
        self.vapi.cli("sfdp session stats ring disable")

        config = self.vapi.sfdp_session_stats_get_config()
        self.assertFalse(config.ring_buffer_enabled, "Ring should be disabled via CLI")

    def test_session_stats_cli_periodic_export(self):
        """Test session stats periodic export CLI commands"""
        # Enable periodic export via CLI
        self.vapi.cli("sfdp session stats periodic enable interval 45")

        # Verify via API
        config = self.vapi.sfdp_session_stats_get_config()
        self.assertTrue(
            config.periodic_export_enabled, "Periodic export should be enabled"
        )
        self.assertEqual(config.export_interval, 45.0, "Interval should be 45 seconds")

        # Reset interval
        self.vapi.cli("sfdp session stats periodic enable interval 60")

        # Disable via CLI
        self.vapi.cli("sfdp session stats periodic disable")

        config = self.vapi.sfdp_session_stats_get_config()
        self.assertFalse(
            config.periodic_export_enabled, "Periodic export should be disabled"
        )

    def test_session_stats_read_ring_buffer_directly(self):
        """Test reading session stats directly from the stat segment ring buffer"""
        self._configure_sfdp_with_session_stats()

        # Enable ring buffer
        reply = self.vapi.sfdp_session_stats_ring_enable(enable=True, ring_size=256)
        self.assertEqual(reply.retval, 0)

        # Send some TCP packets to create a session with known stats
        num_packets = 3
        for i in range(num_packets):
            pkt = self.create_tcp_packet(
                src_mac=self.pg0.remote_mac,
                dst_mac=self.pg0.local_mac,
                src_ip=self.pg0.remote_ip4,
                dst_ip=self.pg1.remote_ip4,
                sport=55555,
                dport=8080,
                flags="S" if i == 0 else "A",
            )
            self.pg_send(self.pg0, pkt)

        # Trigger export to ring buffer
        reply = self.vapi.sfdp_session_stats_export_now()
        self.assertEqual(reply.retval, 0)

        # Give a moment for the export to happen
        self.virtual_sleep(0.2)

        # Read directly from the stat segment ring buffer
        ring_buffer_name = "/sfdp/session/stats"

        try:
            ring_buffer = self.statistics.get_ring_buffer(ring_buffer_name)
        except (KeyError, ValueError) as e:
            self.fail(f"Failed to get ring buffer '{ring_buffer_name}': {e}")

        # Get the schema and create a dynamic decoder
        # schema_string, schema_size, schema_version = ring_buffer.get_schema_string()
        # print(len(schema_string))
        # print(schema_size)
        schema_string, schema_size, schema_version = ring_buffer.get_schema_string()
        print("SCHEMA STRING LENGTH: " + str(len(schema_string)))
        print("REPORTED SCHEMA LENGTH: " + str(schema_size))
        print("ACTUAL SCHEMA: " + schema_string)
        self.assertIsNotNone(schema_string, "Schema should be present")
        self.assertGreater(schema_size, 0, "Schema size should be > 0")

        # Create decoder from schema
        decode_entry, schema = self._create_ring_buffer_decoder(schema_string)
        self.assertEqual(schema["version"], 3, "Schema version should be 3")
        self.assertEqual(schema["entry_size"], 512, "Entry size should be 512 bytes")
        self.assertIn("fields", schema, "Schema should have 'fields'")

        # Consume data from ring buffer (thread 0)
        data = ring_buffer.consume_data(thread_index=0)
        self.assertGreater(
            len(data), 0, "Should have at least one entry in ring buffer"
        )

        # Decode the first entry using the schema-based decoder
        entry_bytes = data[0]
        self.assertEqual(len(entry_bytes), 512, "Entry should be 512 bytes")

        entry = decode_entry(entry_bytes)
        print("ENTRY Bytes: " + str(entry_bytes))
        print("\n\n\nENTRY JSON: " + str(entry))

        # Validate the parsed data using named fields from schema
        self.assertGreater(entry["session_id"], 0, "Session ID should be set")
        self.assertEqual(entry["proto"], 6, "Protocol should be TCP (6)")
        self.assertEqual(
            entry["export_reason"], 2, "Export reason should be API_REQUEST (2)"
        )  # Triggered by export_now

        # Validate packet counts match what we sent
        self.assertEqual(
            entry["packets_forward"],
            num_packets,
            f"Should have {num_packets} forward packets in ring buffer entry",
        )
        self.assertEqual(
            entry["packets_reverse"], 0, "Should have 0 reverse packets (no replies)"
        )

        # Validate bytes are reasonable
        self.assertGreater(entry["bytes_forward"], 0, "Forward bytes should be > 0")
        self.assertEqual(entry["bytes_reverse"], 0, "Reverse bytes should be 0")

        # Validate timestamps
        self.assertGreater(entry["first_seen"], 0, "first_seen should be set")
        self.assertGreater(entry["last_seen"], 0, "last_seen should be set")
        self.assertGreaterEqual(
            entry["last_seen"], entry["first_seen"], "last_seen should be >= first_seen"
        )
        self.assertGreater(entry["export_time"], 0, "export_time should be set")

        # Validate IP address format
        self.assertEqual(entry["is_ip4"], 1, "Should be IPv4")
        self.assertEqual(entry["fwd_src_port"], 55555, "Source port should be 55555")
        self.assertEqual(entry["fwd_dst_port"], 8080, "Destination port should be 8080")

        # Format and validate forward five-tuple IP addresses
        fwd_src_ip = self._format_ip_from_bytes(entry["fwd_src_ip"], entry["is_ip4"])
        fwd_dst_ip = self._format_ip_from_bytes(entry["fwd_dst_ip"], entry["is_ip4"])

        print(
            f"Forward: {fwd_src_ip}:{entry['fwd_src_port']} -> {fwd_dst_ip}:{entry['fwd_dst_port']}"
        )
        print(f"Expected: {self.pg0.remote_ip4}:55555 -> {self.pg1.remote_ip4}:8080")

        # Validate forward five-tuple
        self.assertRegex(
            fwd_src_ip, r"^\d+\.\d+\.\d+\.\d+$", "Forward source IP should be valid"
        )
        self.assertRegex(
            fwd_dst_ip, r"^\d+\.\d+\.\d+\.\d+$", "Forward dest IP should be valid"
        )
        self.assertEqual(
            entry["fwd_src_port"], 55555, "Forward source port should match"
        )
        self.assertEqual(entry["fwd_dst_port"], 8080, "Forward dest port should match")

        # Validate reverse five-tuple (should be swapped)
        rev_src_ip = self._format_ip_from_bytes(entry["rev_src_ip"], entry["is_ip4"])
        rev_dst_ip = self._format_ip_from_bytes(entry["rev_dst_ip"], entry["is_ip4"])
        print(
            f"Reverse: {rev_src_ip}:{entry['rev_src_port']} -> {rev_dst_ip}:{entry['rev_dst_port']}"
        )

        self.assertRegex(
            rev_src_ip, r"^\d+\.\d+\.\d+\.\d+$", "Reverse source IP should be valid"
        )
        self.assertRegex(
            rev_dst_ip, r"^\d+\.\d+\.\d+\.\d+$", "Reverse dest IP should be valid"
        )
        self.assertEqual(
            entry["rev_src_port"],
            8080,
            "Reverse source port should be forward dst port",
        )
        self.assertEqual(
            entry["rev_dst_port"], 55555, "Reverse dest port should be forward src port"
        )

        # Validate duration field (schema v3)
        self.assertGreaterEqual(entry["duration"], 0, "Duration should be >= 0")

        # Validate TTL statistics (schema v3)
        # For TCP packets sent from pg0, TTL should be captured in forward direction
        self.assertGreater(entry["ttl_min_forward"], 0, "TTL min forward should be > 0")
        self.assertGreater(entry["ttl_max_forward"], 0, "TTL max forward should be > 0")
        self.assertGreaterEqual(
            entry["ttl_max_forward"],
            entry["ttl_min_forward"],
            "TTL max should be >= TTL min",
        )
        self.assertGreater(
            entry["ttl_mean_forward"], 0, "TTL mean forward should be > 0"
        )
        self.assertGreaterEqual(
            entry["ttl_stddev_forward"], 0, "TTL stddev forward should be >= 0"
        )

        # Reverse direction TTL stats should be 0 (no reverse traffic)
        self.assertEqual(
            entry["ttl_min_reverse"],
            0,
            "TTL min reverse should be 0 (no reverse traffic)",
        )
        self.assertEqual(entry["ttl_max_reverse"], 0, "TTL max reverse should be 0")

        # Validate RTT statistics (schema v3)
        # RTT can be 0 if not measured yet
        self.assertGreaterEqual(
            entry["rtt_mean_forward"], 0, "RTT mean forward should be >= 0"
        )
        self.assertGreaterEqual(
            entry["rtt_stddev_forward"], 0, "RTT stddev forward should be >= 0"
        )
        self.assertGreaterEqual(
            entry["rtt_mean_reverse"], 0, "RTT mean reverse should be >= 0"
        )
        self.assertGreaterEqual(
            entry["rtt_stddev_reverse"], 0, "RTT stddev reverse should be >= 0"
        )

        # Validate TCP-specific fields (schema v3)
        self.assertGreaterEqual(entry["tcp_mss"], 0, "TCP MSS should be >= 0")
        self.assertIn(
            entry["tcp_handshake_complete"],
            [0, 1],
            "Handshake complete should be 0 or 1",
        )

        # TCP packet counters
        self.assertEqual(entry["tcp_syn_packets"], 1, "Should have 1 SYN packet")
        self.assertEqual(entry["tcp_fin_packets"], 0, "Should have 0 FIN packets")
        self.assertEqual(entry["tcp_rst_packets"], 0, "Should have 0 RST packets")

        # TCP event counters per direction
        self.assertGreaterEqual(
            entry["tcp_retransmissions_fwd"],
            0,
            "Forward retransmissions should be >= 0",
        )
        self.assertGreaterEqual(
            entry["tcp_retransmissions_rev"],
            0,
            "Reverse retransmissions should be >= 0",
        )
        self.assertGreaterEqual(
            entry["tcp_zero_window_events_fwd"],
            0,
            "Forward zero window events should be >= 0",
        )
        self.assertGreaterEqual(
            entry["tcp_zero_window_events_rev"],
            0,
            "Reverse zero window events should be >= 0",
        )
        self.assertGreaterEqual(
            entry["tcp_dupack_events_fwd"], 0, "Forward dupack events should be >= 0"
        )
        self.assertGreaterEqual(
            entry["tcp_dupack_events_rev"], 0, "Reverse dupack events should be >= 0"
        )
        self.assertGreaterEqual(
            entry["tcp_partial_overlap_events_fwd"],
            0,
            "Forward partial overlap events should be >= 0",
        )
        self.assertGreaterEqual(
            entry["tcp_partial_overlap_events_rev"],
            0,
            "Reverse partial overlap events should be >= 0",
        )

        # TCP sequence window (should have non-zero values for forward direction after sending packets)
        # Note: These may be 0 if sequence tracking is not yet implemented for this direction
        print(
            f"TCP seq/ack forward: seq={entry['tcp_last_seq_forward']}, ack={entry['tcp_last_ack_forward']}"
        )
        print(
            f"TCP seq/ack reverse: seq={entry['tcp_last_seq_reverse']}, ack={entry['tcp_last_ack_reverse']}"
        )

        # Validate decorator metadata (should be NONE/disabled by default)
        self.assertEqual(
            entry["decorator_type"], 0, "Decorator type should be NONE by default"
        )

        # Disable ring buffer
        self.vapi.sfdp_session_stats_ring_enable(enable=False)

        self._cleanup_sfdp()

    def test_session_stats_ring_buffer_multiple_sessions(self):
        """Test that multiple sessions are correctly exported to ring buffer"""
        config = self._configure_sfdp_session_stats(
            enable_ring_buffer=True,
            ring_size=256,
        )

        # Create multiple sessions with different characteristics
        sessions_info = [
            {"sport": 11111, "dport": 80, "packets": 2},
            {"sport": 22222, "dport": 443, "packets": 4},
            {"sport": 33333, "dport": 8000, "packets": 1},
        ]

        for sess in sessions_info:
            for i in range(sess["packets"]):
                pkt = self.create_tcp_packet(
                    src_mac=self.pg0.remote_mac,
                    dst_mac=self.pg0.local_mac,
                    src_ip=self.pg0.remote_ip4,
                    dst_ip=self.pg1.remote_ip4,
                    sport=sess["sport"],
                    dport=sess["dport"],
                    flags="S" if i == 0 else "A",
                )
                self.pg_send(self.pg0, pkt)

        # Trigger export
        reply = self.vapi.sfdp_session_stats_export_now()
        self.assertEqual(reply.retval, 0)
        self.virtual_sleep(0.2)

        # Read from ring buffer
        ring_buffer = self.statistics.get_ring_buffer("/sfdp/session/stats")
        data = ring_buffer.consume_data(thread_index=0)

        self.assertEqual(len(data), 3, "Should have 3 entries in ring buffer")

        # Parse all entries and verify packet counts
        # Schema v3 offsets: fwd_dst_port at 118, packets_forward at 20
        parsed_entries = []
        for entry_bytes in data:
            # Use schema offsets: fwd_dst_port is at offset 118, packets_forward at offset 20
            fwd_dst_port = struct.unpack_from("<H", entry_bytes, 118)[0]
            packets_forward = struct.unpack_from("<Q", entry_bytes, 20)[0]
            parsed_entries.append(
                {"dst_port": fwd_dst_port, "packets": packets_forward}
            )

        # Verify each session's packet count
        for sess in sessions_info:
            found = False
            for parsed in parsed_entries:
                if parsed["dst_port"] == sess["dport"]:
                    self.assertEqual(
                        parsed["packets"],
                        sess["packets"],
                        f"Session to port {sess['dport']} should have "
                        f"{sess['packets']} packets",
                    )
                    found = True
                    break
            self.assertTrue(
                found, f"Session to port {sess['dport']} not found in ring buffer"
            )

        # Cleanup
        self._cleanup_sfdp_session_stats(config)

    def test_session_stats_ring_buffer_with_decorator(self):
        """Test that decorator configuration is reflected in ring buffer entries"""
        # Configure SFDP with ring buffer and CUSTOM_U64 decorator enabled
        config = self._configure_sfdp_session_stats(
            enable_ring_buffer=True,
            ring_size=256,
            enable_decorator=True,
            decorator_type=1,  # CUSTOM_U64
        )

        # Verify decorator is enabled
        decorator_config = self.vapi.sfdp_session_stats_get_decorator()
        self.assertTrue(decorator_config.decorator_enabled)
        self.assertEqual(decorator_config.decorator_type, 1)

        # Send some TCP packets to create a session
        num_packets = 2
        for i in range(num_packets):
            pkt = self.create_tcp_packet(
                src_mac=self.pg0.remote_mac,
                dst_mac=self.pg0.local_mac,
                src_ip=self.pg0.remote_ip4,
                dst_ip=self.pg1.remote_ip4,
                sport=44444,
                dport=9090,
                flags="S" if i == 0 else "A",
            )
            self.pg_send(self.pg0, pkt)

        # Trigger export to ring buffer
        reply = self.vapi.sfdp_session_stats_export_now()
        self.assertEqual(reply.retval, 0)
        self.virtual_sleep(0.2)

        # Read from ring buffer
        ring_buffer = self.statistics.get_ring_buffer("/sfdp/session/stats")
        data = ring_buffer.consume_data(thread_index=0)

        self.assertGreater(len(data), 0, "Should have at least one entry")

        # Parse the entry and verify decorator type is set
        # Schema v3 offsets: decorator_type at 288, decorator at 296 (64 bytes)
        entry_bytes = data[0]
        self.assertEqual(len(entry_bytes), 512, "Entry should be 512 bytes")

        # Extract decorator metadata
        decorator_type = struct.unpack_from("<B", entry_bytes, 288)[0]
        decorator_flags = struct.unpack_from("<B", entry_bytes, 289)[0]

        print(f"Decorator type from ring buffer: {decorator_type}")
        print(f"Decorator flags from ring buffer: {decorator_flags}")

        # Verify decorator_type matches what we configured (CUSTOM_U64 = 1)
        self.assertEqual(
            decorator_type, 1, "Decorator type in ring buffer should be CUSTOM_U64 (1)"
        )

        # Extract decorator data area (64 bytes at offset 296)
        decorator_data = entry_bytes[296 : 296 + 64]
        print(f"Decorator data (first 16 bytes): {decorator_data[:16].hex()}")

        # The decorator data area should exist and be accessible
        # (actual content depends on whether a callback populated it)
        self.assertEqual(len(decorator_data), 64, "Decorator area should be 64 bytes")

        # Test with a different decorator type - CUSTOM_U32 (2)
        reply = self.vapi.sfdp_session_stats_set_decorator(
            decorator_type=2, enable=True  # CUSTOM_U32
        )
        self.assertEqual(reply.retval, 0)

        # Send another packet (same session)
        pkt = self.create_tcp_packet(
            src_mac=self.pg0.remote_mac,
            dst_mac=self.pg0.local_mac,
            src_ip=self.pg0.remote_ip4,
            dst_ip=self.pg1.remote_ip4,
            sport=44444,
            dport=9090,
            flags="PA",  # PUSH+ACK
        )
        self.pg_send(self.pg0, pkt)

        # Export again
        reply = self.vapi.sfdp_session_stats_export_now()
        self.assertEqual(reply.retval, 0)
        self.virtual_sleep(0.2)

        # Read new entries
        data = ring_buffer.consume_data(thread_index=0)
        self.assertGreater(len(data), 0, "Should have new entry after second export")

        # Verify new entry has CUSTOM_U32 decorator type
        entry_bytes = data[0]
        decorator_type = struct.unpack_from("<B", entry_bytes, 288)[0]
        self.assertEqual(
            decorator_type, 2, "Decorator type in ring buffer should be CUSTOM_U32 (2)"
        )

        # Disable decorator and verify it's reflected
        reply = self.vapi.sfdp_session_stats_set_decorator(
            decorator_type=0, enable=False
        )
        self.assertEqual(reply.retval, 0)

        # Export one more time
        reply = self.vapi.sfdp_session_stats_export_now()
        self.assertEqual(reply.retval, 0)
        self.virtual_sleep(0.2)

        data = ring_buffer.consume_data(thread_index=0)
        if len(data) > 0:
            entry_bytes = data[0]
            decorator_type = struct.unpack_from("<B", entry_bytes, 288)[0]
            self.assertEqual(
                decorator_type, 0, "Decorator type should be NONE (0) when disabled"
            )

        # Cleanup
        self._cleanup_sfdp_session_stats(config)

    def test_session_stats_custom_decorator_values(self):
        """Test that custom decorator values set via API appear in ring buffer"""
        # Set custom u64 values BEFORE enabling decorator
        custom_values = [
            0xDEADBEEFCAFEBABE,  # value[0]
            0x1234567890ABCDEF,  # value[1]
            0xFEDCBA0987654321,  # value[2]
            42,  # value[3]
            0,  # value[4]
            0,  # value[5]
            0,  # value[6]
            0xFFFFFFFFFFFFFFFF,  # value[7]
        ]

        reply = self.vapi.sfdp_session_stats_set_custom_u64(
            n_values=8, values=custom_values
        )
        self.assertEqual(reply.retval, 0)

        # Configure SFDP with ring buffer and CUSTOM_U64 decorator enabled
        config = self._configure_sfdp_session_stats(
            enable_ring_buffer=True,
            ring_size=256,
            enable_decorator=True,
            decorator_type=1,  # CUSTOM_U64
        )

        # Send some TCP packets to create a session
        for i in range(2):
            pkt = self.create_tcp_packet(
                src_mac=self.pg0.remote_mac,
                dst_mac=self.pg0.local_mac,
                src_ip=self.pg0.remote_ip4,
                dst_ip=self.pg1.remote_ip4,
                sport=55555,
                dport=7777,
                flags="S" if i == 0 else "A",
            )
            self.pg_send(self.pg0, pkt)

        # Trigger export to ring buffer
        reply = self.vapi.sfdp_session_stats_export_now()
        self.assertEqual(reply.retval, 0)
        self.virtual_sleep(0.2)

        # Read from ring buffer
        ring_buffer = self.statistics.get_ring_buffer("/sfdp/session/stats")
        data = ring_buffer.consume_data(thread_index=0)

        self.assertGreater(len(data), 0, "Should have at least one entry")

        entry_bytes = data[0]
        self.assertEqual(len(entry_bytes), 512, "Entry should be 512 bytes")

        # Verify decorator type is CUSTOM_U64 (1)
        decorator_type = struct.unpack_from("<B", entry_bytes, 288)[0]
        self.assertEqual(decorator_type, 1, "Decorator type should be CUSTOM_U64")

        # Extract and verify custom u64 values from decorator area (offset 296)
        # custom_u64 struct has 8 u64 values
        for i, expected_val in enumerate(custom_values):
            offset = 296 + (i * 8)  # 8 bytes per u64
            actual_val = struct.unpack_from("<Q", entry_bytes, offset)[0]
            print(
                f"custom_u64[{i}]: expected=0x{expected_val:016X}, actual=0x{actual_val:016X}"
            )
            self.assertEqual(
                actual_val,
                expected_val,
                f"custom_u64.values[{i}] should be 0x{expected_val:016X}, got 0x{actual_val:016X}",
            )

        # Now test with custom u32 values
        custom_u32_values = [
            0xDEADBEEF,  # value[0]
            0xCAFEBABE,  # value[1]
            12345678,  # value[2]
            0x12345678,  # value[3]
            0,  # value[4]
            0,  # value[5]
            0,  # value[6]
            0,  # value[7]
            0xFFFFFFFF,  # value[8]
            0,  # value[9]
            0,  # value[10]
            0,  # value[11]
            0,  # value[12]
            0,  # value[13]
            0,  # value[14]
            0x87654321,  # value[15]
        ]

        reply = self.vapi.sfdp_session_stats_set_custom_u32(
            n_values=16, values=custom_u32_values
        )
        self.assertEqual(reply.retval, 0)

        # Switch decorator type to CUSTOM_U32 (2)
        reply = self.vapi.sfdp_session_stats_set_decorator(
            decorator_type=2, enable=True  # CUSTOM_U32
        )
        self.assertEqual(reply.retval, 0)

        # Export again
        reply = self.vapi.sfdp_session_stats_export_now()
        self.assertEqual(reply.retval, 0)
        self.virtual_sleep(0.2)

        # Read new entries
        data = ring_buffer.consume_data(thread_index=0)
        self.assertGreater(len(data), 0, "Should have new entry")

        entry_bytes = data[0]

        # Verify decorator type is CUSTOM_U32 (2)
        decorator_type = struct.unpack_from("<B", entry_bytes, 288)[0]
        self.assertEqual(decorator_type, 2, "Decorator type should be CUSTOM_U32")

        # Extract and verify custom u32 values from decorator area (offset 296)
        # custom_u32 struct has 16 u32 values
        for i, expected_val in enumerate(custom_u32_values):
            offset = 296 + (i * 4)  # 4 bytes per u32
            actual_val = struct.unpack_from("<I", entry_bytes, offset)[0]
            print(
                f"custom_u32[{i}]: expected=0x{expected_val:08X}, actual=0x{actual_val:08X}"
            )
            self.assertEqual(
                actual_val,
                expected_val,
                f"custom_u32.values[{i}] should be 0x{expected_val:08X}, got 0x{actual_val:08X}",
            )

        # Cleanup
        self.vapi.sfdp_session_stats_set_decorator(decorator_type=0, enable=False)
        self._cleanup_sfdp_session_stats(config)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
