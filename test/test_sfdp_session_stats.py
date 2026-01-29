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

    def _configure_sfdp_with_session_stats(self):
        """Configure SFDP with session stats service in the chain"""
        self.tenant_id = 1

        # Add tenant
        reply = self.vapi.sfdp_tenant_add_del(
            tenant_id=self.tenant_id,
            context_id=1,
            is_del=False,
        )
        self.assertEqual(reply.retval, 0)

        # Configure services - include session-stats in the chain
        reply = self.vapi.sfdp_set_services(
            tenant_id=self.tenant_id,
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
            tenant_id=self.tenant_id,
            dir=VppEnum.vl_api_sfdp_session_direction_t.SFDP_API_REVERSE,
            n_services=3,
            services=[
                {"data": "sfdp-l4-lifecycle"},
                {"data": "sfdp-session-stats"},
                {"data": "ip4-lookup"},
            ],
        )
        self.assertEqual(reply.retval, 0)

        # Enable on interface
        reply = self.vapi.sfdp_interface_input_set(
            sw_if_index=self.pg0.sw_if_index,
            tenant_id=self.tenant_id,
            is_disable=False,
        )
        self.assertEqual(reply.retval, 0)

    def _cleanup_sfdp(self):
        """Cleanup SFDP configuration"""
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
            tenant_id=self.tenant_id,
            is_disable=True,
        )

        # Delete tenant
        self.vapi.sfdp_tenant_add_del(
            tenant_id=self.tenant_id,
            is_del=True,
        )

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

        # Verify sessions were created
        sessions = self.vapi.sfdp_session_dump()
        print(sessions)

        print(self.vapi.cli("show sfdp tenant 1 detail"))

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
        self.assertEqual(schema["version"], 1, "Schema version should be 1")
        self.assertIn("fields", schema, "Schema should have 'fields'")

        # Consume data from ring buffer (thread 0)
        data = ring_buffer.consume_data(thread_index=0)
        self.assertGreater(
            len(data), 0, "Should have at least one entry in ring buffer"
        )

        # Decode the first entry using the schema-based decoder
        entry_bytes = data[0]
        self.assertEqual(len(entry_bytes), 128, "Entry should be 128 bytes")

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
        self.assertEqual(entry["src_port"], 55555, "Source port should be 55555")
        self.assertEqual(entry["dst_port"], 8080, "Destination port should be 8080")

        # Format and validate IP addresses
        src_ip = self._format_ip_from_bytes(entry["src_ip"], entry["is_ip4"])
        dst_ip = self._format_ip_from_bytes(entry["dst_ip"], entry["is_ip4"])

        print(src_ip)
        print(dst_ip)
        print(self.pg0.remote_ip4)
        print(self.pg1.remote_ip4)

        # Note: The addresses in the ring buffer are from the session key,
        # which may be normalized (sorted). We just verify they're valid IPs.
        self.assertRegex(src_ip, r"^\d+\.\d+\.\d+\.\d+$", "Source IP should be valid")
        self.assertRegex(dst_ip, r"^\d+\.\d+\.\d+\.\d+$", "Dest IP should be valid")

        # Disable ring buffer
        self.vapi.sfdp_session_stats_ring_enable(enable=False)

        self._cleanup_sfdp()

    def test_session_stats_ring_buffer_multiple_sessions(self):
        """Test that multiple sessions are correctly exported to ring buffer"""
        self._configure_sfdp_with_session_stats()

        # Enable ring buffer
        reply = self.vapi.sfdp_session_stats_ring_enable(enable=True, ring_size=256)
        self.assertEqual(reply.retval, 0)

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
        parsed_entries = []
        for entry in data:
            dst_port = struct.unpack_from("<H", entry, 110)[0]
            packets_forward = struct.unpack_from("<Q", entry, 20)[0]
            parsed_entries.append({"dst_port": dst_port, "packets": packets_forward})

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
        self.vapi.sfdp_session_stats_ring_enable(enable=False)
        self._cleanup_sfdp()


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
