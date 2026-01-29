#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2025 Cisco Systems, Inc.

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

    def create_ring_buffer_decoder(self, schema_json):
        # Create decoder of Session Statistics ring-buffer entries
        # based on JSON schema expoed in ring-buffer metadata

        # StatsRingBuffer.get_schema_string() returns a tuple:
        # (schema_string_or_bytes, schema_size, schema_version).
        if isinstance(schema_json, tuple):
            schema_json = schema_json[0]

        if isinstance(schema_json, bytes):
            schema_json = schema_json.decode("utf-8")

        if not isinstance(schema_json, str):
            raise ValueError(
                f"Provided schema has unsupported type: {type(schema_json).__name__}"
            )

        # Attempt to decode provided schema_json string
        try:
            schema = json.loads(schema_json)
        except json.JSONDecodeError as e:
            raise ValueError("Provided schema is not in valid JSON format")
        fields = schema.get("fields", [])
        # Maps schema types to packet binary data format
        # https://docs.python.org/3/library/struct.html
        type_map = {
            "u8": ("<B", 1),
            "u16": ("<H", 2),
            "u32": ("<I", 4),
            "u64": ("<Q", 8),
            "f64": ("<d", 8),
            "ip": (None, 16),
            "bytes": (None, None),
        }

        def decode_entry(entry_bytes):
            result = {}
            for field in fields:
                name = field["name"]
                ftype = field["type"]
                offset = field["offset"]

                if ftype not in type_map:
                    # Skip unknown type
                    print(f"Field type not recognized, could not decode field {field}")
                    continue

                fmt, size = type_map[ftype]
                # Special processing for IP type, which can represent either an IPv4 or IPv6 address
                # (IPv4 in first 4, or full IPv6)
                if ftype == "ip":
                    result[name] = entry_bytes[offset : offset + 16]
                elif ftype == "bytes":
                    # Variable size bytes field (e.g., custom data, padding)
                    size = field.get("size", 0)
                    result[name] = entry_bytes[offset : offset + size]
                else:
                    result[name] = struct.unpack_from(fmt, entry_bytes, offset)[0]
            return result

        return decode_entry, schema

    def format_ip_from_bytes(self, ip_bytes, is_ip4):
        # Format IPv4/IPv6 address from serialized format
        # into string
        if is_ip4:
            return ".".join(str(b) for b in ip_bytes[:4])
        else:
            parts = []
            for i in range(0, 16, 2):
                parts.append(f"{ip_bytes[i]:02x}{ip_bytes[i+1]:02x}")
            return ":".join(parts)

    def _configure_sfdp_session_stats(
        self,
        tenant_id=1,
        enable_ring_buffer=False,
        ring_size=256,
        enable_bidirectional=False,
        enable_periodic_export=False,
        export_interval=60.0,
        custom_api_data=0,
    ):
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

        # Configure services for forward/reverse flow direction
        # include session-stats in the chain
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

        # Set custom API data for tenant if requested
        if custom_api_data:
            reply = self.vapi.sfdp_session_stats_set_custom_api_data(
                tenant_id=tenant_id, value=custom_api_data
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

    def test_session_stats_cli_configuration(self):
        """Test CLI enabling of stats ring buffer and periodic export"""
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

    def test_session_stats_configuration_api(self):
        """Test API enabling of stats ring buffer and periodic export"""
        # === Ring buffer configuration ===
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

        # === Periodic export configuration ===
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

        # Reset periodic export interval to 60.0 seconds
        reply = self.vapi.sfdp_session_stats_periodic_export(enable=True, interval=60.0)
        # Disable periodic export
        reply = self.vapi.sfdp_session_stats_periodic_export(enable=False)
        self.assertEqual(reply.retval, 0)

        # Verify it's disabled
        config = self.vapi.sfdp_session_stats_get_config()
        self.assertFalse(
            config.periodic_export_enabled, "Periodic export should be disabled"
        )

    def test_session_stats_api_dump(self):
        """Test single session statistics"""
        self._configure_sfdp_session_stats()

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

        self._cleanup_sfdp_session_stats()

    def test_session_stats_packet_byte_and_seq_ack_counters(self):
        """Test tracking of session packet/byte counts, TCP seq/ack, and TTL"""
        config = self._configure_sfdp_session_stats(
            enable_bidirectional=True,
        )

        sport = 8000
        dport = 9000
        ip_header_size = 20
        tcp_header_size = 20

        def get_session_stats():
            """Helper to get the single session's stats"""
            stats = self.vapi.sfdp_session_stats_dump()
            self.assertEqual(len(stats), 1, "Should have exactly one session")
            return stats[0]

        # === Forward SYN (seq=1000, ttl=60) ===
        pkt_syn = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=60)
            / TCP(sport=sport, dport=dport, flags="S", seq=1000, ack=0)
            / Raw(b"")
        )
        self.pg_send(self.pg0, pkt_syn)

        s = get_session_stats()
        self.assertEqual(s.packets_fwd, 1)
        self.assertEqual(s.packets_rev, 0)
        self.assertEqual(s.bytes_fwd, ip_header_size + tcp_header_size)
        self.assertEqual(s.tcp_syn_packets, 1)
        self.assertEqual(s.tcp_handshake_complete, False)
        self.assertEqual(s.ttl_min_fwd, 60)
        self.assertEqual(s.ttl_max_fwd, 60)

        # === Reverse SYN-ACK (seq=2000, ack=1001, ttl=128) ===
        pkt_synack = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="SA", seq=2000, ack=1001)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_synack)

        s = get_session_stats()
        self.assertEqual(s.packets_fwd, 1)
        self.assertEqual(s.packets_rev, 1)
        self.assertEqual(s.bytes_rev, ip_header_size + tcp_header_size)
        self.assertEqual(s.tcp_syn_packets, 2)  # SYN + SYN-ACK
        self.assertEqual(s.tcp_handshake_complete, False)  # Still need final ACK
        self.assertEqual(s.ttl_min_rev, 128)
        self.assertEqual(s.ttl_max_rev, 128)

        # === Forward ACK completing handshake (seq=1001, ack=2001, ttl=64) ===
        pkt_ack = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="A", seq=1001, ack=2001)
            / Raw(b"")
        )
        self.pg_send(self.pg0, pkt_ack)

        s = get_session_stats()
        self.assertEqual(s.packets_fwd, 2)
        self.assertEqual(s.tcp_handshake_complete, True)  # Handshake now complete
        self.assertEqual(s.ttl_max_fwd, 64)  # Updated from 60 to 64

        # === Forward DATA (100 bytes, seq=1001, ttl=62) ===
        payload_size = 100
        pkt_data = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=62)
            / TCP(sport=sport, dport=dport, flags="PA", seq=1001, ack=2001)
            / Raw(b"\xaa" * payload_size)
        )
        self.pg_send(self.pg0, pkt_data)

        s = get_session_stats()
        self.assertEqual(s.packets_fwd, 3)
        self.assertEqual(
            s.bytes_fwd, 3 * (ip_header_size + tcp_header_size) + payload_size
        )
        # seq advanced by payload: 1001 + 100 = 1101
        self.assertEqual(s.tcp_last_seq_fwd, 1101)

        # === Reverse ACK (seq=2001, ack=1101, ttl=125) ===
        pkt_rev_ack = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=125)
            / TCP(sport=dport, dport=sport, flags="A", seq=2001, ack=1101)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_rev_ack)

        s = get_session_stats()
        self.assertEqual(s.packets_rev, 2)
        self.assertEqual(s.ttl_min_rev, 125)  # Dropped from 128 to 125

        # === Reverse DATA (50 bytes, seq=2001, ttl=130) ===
        rev_payload_size = 50
        pkt_rev_data = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=130)
            / TCP(sport=dport, dport=sport, flags="PA", seq=2001, ack=1101)
            / Raw(b"\xbb" * rev_payload_size)
        )
        self.pg_send(self.pg1, pkt_rev_data)

        s = get_session_stats()
        self.assertEqual(s.packets_rev, 3)
        self.assertEqual(
            s.bytes_rev, 3 * (ip_header_size + tcp_header_size) + rev_payload_size
        )
        # seq advanced: 2001 + 50 = 2051
        self.assertEqual(s.tcp_last_seq_rev, 2051)
        self.assertEqual(s.ttl_max_rev, 130)  # Increased from 128 to 130

        # === Forward FIN (seq=1101, ack=2051, ttl=64) ===
        pkt_fin = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="FA", seq=1101, ack=2051)
            / Raw(b"")
        )
        self.pg_send(self.pg0, pkt_fin)

        s = get_session_stats()
        self.assertEqual(s.packets_fwd, 4)
        self.assertEqual(s.tcp_fin_packets, 1)

        # === Reverse RST (seq=2051, ttl=127) ===
        pkt_rst = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=127)
            / TCP(sport=dport, dport=sport, flags="R", seq=2051, ack=0)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_rst)

        s = get_session_stats()
        self.assertEqual(s.packets_rev, 4)
        self.assertEqual(s.tcp_rst_packets, 1)

        # === Forward extra packet with lowest TTL (ttl=58) ===
        pkt_extra = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=58)
            / TCP(sport=sport, dport=dport, flags="A", seq=1102, ack=2051)
            / Raw(b"")
        )
        self.pg_send(self.pg0, pkt_extra)

        s = get_session_stats()
        self.assertEqual(s.packets_fwd, 5)
        self.assertEqual(s.ttl_min_fwd, 58)  # Now the minimum
        self.assertEqual(s.ttl_max_fwd, 64)

        # === Final verification of all counters ===
        expected_fwd_bytes = 5 * (ip_header_size + tcp_header_size) + payload_size
        expected_rev_bytes = 4 * (ip_header_size + tcp_header_size) + rev_payload_size

        self.assertEqual(s.packets_fwd, 5)
        self.assertEqual(s.packets_rev, 4)
        self.assertEqual(s.bytes_fwd, expected_fwd_bytes)
        self.assertEqual(s.bytes_rev, expected_rev_bytes)
        self.assertEqual(s.tcp_syn_packets, 2)
        self.assertEqual(s.tcp_fin_packets, 1)
        self.assertEqual(s.tcp_rst_packets, 1)
        self.assertEqual(s.tcp_handshake_complete, True)
        self.assertEqual(s.tcp_last_seq_fwd, 1101)
        self.assertEqual(s.tcp_last_ack_fwd, 1101)
        self.assertEqual(s.tcp_last_seq_rev, 2051)
        self.assertEqual(s.tcp_last_ack_rev, 2051)
        self.assertEqual(s.ttl_min_fwd, 58)
        self.assertEqual(s.ttl_max_fwd, 64)
        self.assertEqual(s.ttl_min_rev, 125)
        self.assertEqual(s.ttl_max_rev, 130)

        self._cleanup_sfdp_session_stats(config)

    def test_session_stats_tcp_events(self):
        """Test tracking of TCP events (retransmissions, duplicates, ECN, etc.)"""
        config = self._configure_sfdp_session_stats(
            enable_bidirectional=True,
        )

        sport = 13000
        dport = 14000

        def get_session_stats():
            """Helper to get the single session's stats"""
            stats = self.vapi.sfdp_session_stats_dump()
            self.assertEqual(len(stats), 1, "Should have exactly one session")
            return stats[0]

        # === TCP 3-Way Handshake ===
        pkt_syn = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="S", seq=1000, ack=0, window=65535)
            / Raw(b"")
        )
        self.pg_send(self.pg0, pkt_syn)

        pkt_synack = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(
                sport=dport, dport=sport, flags="SA", seq=2000, ack=1001, window=65535
            )
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_synack)

        pkt_ack = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="A", seq=1001, ack=2001, window=65535)
            / Raw(b"")
        )
        self.pg_send(self.pg0, pkt_ack)

        s = get_session_stats()
        self.assertEqual(s.tcp_handshake_complete, True)
        self.assertEqual(s.tcp_syn_packets, 2)

        # === Forward DATA #1: seq=1001, len=100 ===
        pkt_data1 = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(
                sport=sport, dport=dport, flags="PA", seq=1001, ack=2001, window=65535
            )
            / Raw(b"\xaa" * 100)
        )
        self.pg_send(self.pg0, pkt_data1)

        # === Forward DATA #2: seq=1101, len=100 ===
        pkt_data2 = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(
                sport=sport, dport=dport, flags="PA", seq=1101, ack=2001, window=65535
            )
            / Raw(b"\xbb" * 100)
        )
        self.pg_send(self.pg0, pkt_data2)

        s = get_session_stats()
        self.assertEqual(s.packets_fwd, 4)  # SYN + ACK + DATA1 + DATA2
        self.assertEqual(s.tcp_retransmissions_fwd, 0)
        self.assertEqual(s.tcp_partial_overlap_events_fwd, 0)

        # === Trigger Partial Overlap (forward) ===
        # seq=1150 overlaps with 1101-1200, but extends to 1250
        pkt_partial_overlap = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(
                sport=sport, dport=dport, flags="PA", seq=1150, ack=2001, window=65535
            )
            / Raw(b"\xcc" * 100)
        )
        self.pg_send(self.pg0, pkt_partial_overlap)

        s = get_session_stats()
        self.assertGreaterEqual(
            s.tcp_partial_overlap_events_fwd,
            1,
            "Should have at least 1 partial overlap after overlapping packet",
        )

        # === Trigger Retransmission (forward) ===
        # Resend DATA #1 (complete retransmission, seq=1001, entirely within received)
        pkt_retrans = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(
                sport=sport, dport=dport, flags="PA", seq=1001, ack=2001, window=65535
            )
            / Raw(b"\xaa" * 100)
        )
        self.pg_send(self.pg0, pkt_retrans)

        s = get_session_stats()
        self.assertGreaterEqual(
            s.tcp_retransmissions_fwd,
            1,
            "Should have at least 1 retransmission after resending old data",
        )

        # ACK forward data
        pkt_ack1 = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="A", seq=2001, ack=1201, window=65535)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_ack1)

        s = get_session_stats()
        self.assertEqual(s.tcp_dupack_events_fwd, 0)  # First ACK, not a duplicate

        # === Trigger Duplicate ACK (for forward data) ===
        # Send same ACK again with outstanding data beyond it
        pkt_dupack = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="A", seq=2001, ack=1201, window=65535)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_dupack)

        s = get_session_stats()
        self.assertGreaterEqual(
            s.tcp_dupack_events_fwd,
            1,
            "Should have at least 1 dupack event after duplicate ACK",
        )

        # === Trigger Zero Window (reverse) ===
        prev_zero_window = s.tcp_zero_window_events_rev
        pkt_zero_window = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="A", seq=2001, ack=1250, window=0)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_zero_window)

        s = get_session_stats()
        self.assertGreaterEqual(
            s.tcp_zero_window_events_rev,
            prev_zero_window + 1,
            "Should have zero window event after window=0 packet",
        )

        # Window opens again (should not increment zero window counter)
        pkt_window_open = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="A", seq=2001, ack=1250, window=65535)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_window_open)

        # === ECN ECT(0) packet (tos=2) ===
        prev_ecn_ect = s.tcp_ecn_ect_packets
        pkt_ecn_ect = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64, tos=2)
            / TCP(sport=sport, dport=dport, flags="A", seq=1250, ack=2001, window=65535)
            / Raw(b"\xdd" * 50)
        )
        self.pg_send(self.pg0, pkt_ecn_ect)

        s = get_session_stats()
        self.assertGreater(
            s.tcp_ecn_ect_packets,
            prev_ecn_ect,
            "ECN ECT counter should increment after ECT packet",
        )

        # === ECN CE packet (tos=3) ===
        prev_ecn_ce = s.tcp_ecn_ce_packets
        pkt_ecn_ce = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64, tos=3)
            / TCP(sport=sport, dport=dport, flags="A", seq=1300, ack=2001, window=65535)
            / Raw(b"\xee" * 50)
        )
        self.pg_send(self.pg0, pkt_ecn_ce)

        s = get_session_stats()
        self.assertGreater(
            s.tcp_ecn_ce_packets,
            prev_ecn_ce,
            "ECN CE counter should increment after CE packet",
        )

        # === TCP ECE flag packet ===
        prev_ece = s.tcp_ece_packets
        pkt_ece = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128, tos=0)
            / TCP(
                sport=dport, dport=sport, flags="AE", seq=2001, ack=1350, window=65535
            )
            / Raw(b"\x11" * 50)
        )
        self.pg_send(self.pg1, pkt_ece)

        s = get_session_stats()
        self.assertGreater(
            s.tcp_ece_packets,
            prev_ece,
            "TCP ECE counter should increment after ECE flag packet",
        )

        # === TCP CWR flag packet ===
        prev_cwr = s.tcp_cwr_packets
        pkt_cwr = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64, tos=0)
            / TCP(
                sport=sport, dport=dport, flags="AC", seq=1350, ack=2001, window=65535
            )
            / Raw(b"\xff" * 50)
        )
        self.pg_send(self.pg0, pkt_cwr)

        s = get_session_stats()
        self.assertGreater(
            s.tcp_cwr_packets,
            prev_cwr,
            "TCP CWR counter should increment after CWR flag packet",
        )

        # Final ACK
        pkt_final_ack = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="A", seq=2001, ack=1400, window=65535)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_final_ack)

        # === Final verification of all TCP event counters ===
        s = get_session_stats()
        self.assertGreaterEqual(s.tcp_partial_overlap_events_fwd, 1)
        self.assertGreaterEqual(s.tcp_retransmissions_fwd, 1)
        self.assertGreaterEqual(s.tcp_dupack_events_fwd, 1)
        self.assertGreaterEqual(s.tcp_zero_window_events_rev, 1)
        self.assertGreaterEqual(s.tcp_ecn_ect_packets, 1)
        self.assertGreaterEqual(s.tcp_ecn_ce_packets, 1)
        self.assertGreaterEqual(s.tcp_ece_packets, 1)
        self.assertGreaterEqual(s.tcp_cwr_packets, 1)
        # Out-of-order detection not yet implemented
        self.assertEqual(s.tcp_out_of_order_events_fwd, 0)
        self.assertEqual(s.tcp_out_of_order_events_rev, 0)

        self._cleanup_sfdp_session_stats(config)

    def test_session_stats_multiple_sessions(self):
        """Test stats tracking across multiple sessions"""
        self._configure_sfdp_session_stats()

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

        self._cleanup_sfdp_session_stats()

    def test_session_stats_clear(self):
        """Test clearing session stats"""
        self._configure_sfdp_session_stats()

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

        # Verify stats are cleared (session still exists but counters are 0)
        stats = self.vapi.sfdp_session_stats_dump()
        self.assertEqual(
            len(stats), 1, "Session should still be in dump after clearing"
        )
        self.assertEqual(
            stats[0].packets_fwd, 0, "Forward packets should be 0 after clear"
        )
        self.assertEqual(
            stats[0].packets_rev, 0, "Reverse packets should be 0 after clear"
        )
        self.assertEqual(stats[0].bytes_fwd, 0, "Forward bytes should be 0 after clear")
        self.assertEqual(stats[0].bytes_rev, 0, "Reverse bytes should be 0 after clear")

        self._cleanup_sfdp_session_stats()

    def test_session_stats_filter_by_tenant(self):
        """Test filtering session stats dump by tenant"""
        # Configure two tenants
        for tenant_id in [1, 2]:
            reply = self.vapi.sfdp_tenant_add_del(
                tenant_id=tenant_id,
                context_id=1,
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

    def test_session_stats_custom_data_config(self):
        """Test custom data configuration via API"""
        # Verify no tenant has API data by default
        config = self.vapi.sfdp_session_stats_get_config()
        self.assertFalse(
            config.ring_buffer_enabled, "Ring buffer should be disabled by default"
        )

        # Set custom API data for tenant_id 1
        test_data = 0x123456789ABCDEF0
        tenant_id = 1
        reply = self.vapi.sfdp_session_stats_set_custom_api_data(
            tenant_id=tenant_id, value=test_data
        )
        self.assertEqual(reply.retval, 0)

        # Verify API data is set for tenant 1 using get_tenant_custom_data
        reply = self.vapi.sfdp_session_stats_get_tenant_custom_data(tenant_id=tenant_id)
        self.assertTrue(reply.has_api_data, "API data should be set for tenant 1")
        self.assertEqual(
            reply.api_data_value, test_data, "API data should match for tenant 1"
        )
        self.assertEqual(reply.tenant_id, tenant_id, "Tenant ID should match")

        # Clear custom API data for tenant 1
        reply = self.vapi.sfdp_session_stats_clear_custom_api_data(tenant_id=tenant_id)
        self.assertEqual(reply.retval, 0)

        reply = self.vapi.sfdp_session_stats_get_tenant_custom_data(tenant_id=tenant_id)
        self.assertFalse(reply.has_api_data, "API data should be cleared for tenant 1")

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
        decode_entry, schema = self.create_ring_buffer_decoder(
            ring_buffer.get_schema_string(thread_index=0)
        )

        self.assertEqual(len(data), 3, "Should have 3 entries in ring buffer")

        # Parse all entries and verify packet counts using schema-driven offsets
        parsed_entries = []
        for entry_bytes in data:
            decoded = decode_entry(entry_bytes)
            dst_port = decoded["dst_port"]
            packets_forward = decoded["packets_forward"]
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
        self._cleanup_sfdp_session_stats(config)

    def test_session_stats_ring_buffer_with_custom_data(self):
        """Test that custom data configuration is reflected in ring buffer entries"""
        # Configure SFDP with ring buffer and custom API data for tenant
        config = self._configure_sfdp_session_stats(
            enable_ring_buffer=True,
            ring_size=256,
            custom_api_data=0xDEADBEEFCAFEBABE,
        )

        # Verify custom data is set for tenant_id 1
        tenant_data = self.vapi.sfdp_session_stats_get_tenant_custom_data(tenant_id=1)
        self.assertTrue(tenant_data.has_api_data)
        self.assertEqual(tenant_data.api_data_value, 0xDEADBEEFCAFEBABE)

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
        decode_entry, _ = self.create_ring_buffer_decoder(
            ring_buffer.get_schema_string(thread_index=0)
        )

        self.assertGreater(len(data), 0, "Should have at least one entry")

        # Parse the entry and verify custom data flags
        entry_bytes = data[0]
        self.assertEqual(len(entry_bytes), 384, "Entry should be 384 bytes")
        decoded = decode_entry(entry_bytes)

        # Extract custom data flags
        custom_data_flags = decoded["custom_data_flags"]

        # Verify flag bit 0 is set (API data present)
        self.assertTrue(custom_data_flags & 0x01, "Custom data API flag should be set")

        # Extract custom API data
        custom_api_data = decoded["custom_api_data"]

        self.assertEqual(
            custom_api_data, 0xDEADBEEFCAFEBABE, "Custom API data should match"
        )

        # Update custom API data for tenant_id 1
        reply = self.vapi.sfdp_session_stats_set_custom_api_data(
            tenant_id=1, value=0x1234567890ABCDEF
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

        # Verify new entry has updated API data
        entry_bytes = data[0]
        decoded = decode_entry(entry_bytes)
        custom_api_data = decoded["custom_api_data"]
        self.assertEqual(
            custom_api_data, 0x1234567890ABCDEF, "Custom API data should be updated"
        )

        # Clear custom API data for tenant_id 1 and verify it's reflected
        reply = self.vapi.sfdp_session_stats_clear_custom_api_data(tenant_id=1)
        self.assertEqual(reply.retval, 0)

        # Export one more time
        reply = self.vapi.sfdp_session_stats_export_now()
        self.assertEqual(reply.retval, 0)
        self.virtual_sleep(0.2)

        data = ring_buffer.consume_data(thread_index=0)
        if len(data) > 0:
            entry_bytes = data[0]
            decoded = decode_entry(entry_bytes)
            custom_data_flags = decoded["custom_data_flags"]
            # API flag should be cleared (bit 0 = 0)
            self.assertFalse(
                custom_data_flags & 0x01, "Custom data API flag should be cleared"
            )

        # Cleanup
        self._cleanup_sfdp_session_stats(config)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
