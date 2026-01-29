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
        enable_custom_data=False,
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

        # Enable custom data if requested
        # This should be done before ring buffer is enabled
        if enable_custom_data:
            reply = self.vapi.sfdp_session_stats_custom_data_enable(enable=True)
            self.assertEqual(reply.retval, 0)
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

    def test_session_stats_configuration_api(self):
        """Test enabling and disabling ring buffer and periodic export via API"""
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
        """Test basic packet and byte counting for a session"""
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
        """Test that packet/byte counts, TCP seq/ack, and TTL are tracked correctly.

        This test verifies via the ring buffer that:
        - Forward/reverse packet counts are incremented correctly
        - Forward/reverse byte counts track header + payload sizes
        - TCP seq/ack fields track values as packets are sent
        - TCP control flags (SYN, FIN, RST) are counted
        - TTL min/max are tracked per direction
        """
        config = self._configure_sfdp_session_stats(
            enable_bidirectional=True,
            enable_ring_buffer=True,
            ring_size=256,
        )

        sport = 8000
        dport = 9000
        ip_header_size = 20
        tcp_header_size = 20

        # Track expected counters
        expected_fwd_packets = 0
        expected_rev_packets = 0
        expected_fwd_bytes = 0
        expected_rev_bytes = 0

        # Use varying TTL values to test TTL tracking
        # Forward: 60, 64, 62, 64, 58 -> min=58, max=64
        # Reverse: 128, 125, 130, 127 -> min=125, max=130

        # Forward SYN (seq=1000, ttl=60)
        pkt_syn = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=60)
            / TCP(sport=sport, dport=dport, flags="S", seq=1000, ack=0)
            / Raw(b"")
        )
        self.pg_send(self.pg0, pkt_syn)
        expected_fwd_packets += 1
        expected_fwd_bytes += ip_header_size + tcp_header_size

        # Reverse SYN-ACK (seq=2000, ack=1001, ttl=128)
        pkt_synack = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="SA", seq=2000, ack=1001)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_synack)
        expected_rev_packets += 1
        expected_rev_bytes += ip_header_size + tcp_header_size

        # Forward ACK completing handshake (seq=1001, ack=2001, ttl=64)
        pkt_ack = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="A", seq=1001, ack=2001)
            / Raw(b"")
        )
        self.pg_send(self.pg0, pkt_ack)
        expected_fwd_packets += 1
        expected_fwd_bytes += ip_header_size + tcp_header_size

        # Forward DATA (100 bytes, seq=1001, ttl=62)
        payload_size = 100
        pkt_data = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=62)
            / TCP(sport=sport, dport=dport, flags="PA", seq=1001, ack=2001)
            / Raw(b"\xaa" * payload_size)
        )
        self.pg_send(self.pg0, pkt_data)
        expected_fwd_packets += 1
        expected_fwd_bytes += ip_header_size + tcp_header_size + payload_size

        # Reverse ACK (seq=2001, ack=1101, ttl=125)
        pkt_rev_ack = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=125)
            / TCP(sport=dport, dport=sport, flags="A", seq=2001, ack=1101)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_rev_ack)
        expected_rev_packets += 1
        expected_rev_bytes += ip_header_size + tcp_header_size

        # Reverse DATA (50 bytes, seq=2001, ttl=130)
        rev_payload_size = 50
        pkt_rev_data = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=130)
            / TCP(sport=dport, dport=sport, flags="PA", seq=2001, ack=1101)
            / Raw(b"\xbb" * rev_payload_size)
        )
        self.pg_send(self.pg1, pkt_rev_data)
        expected_rev_packets += 1
        expected_rev_bytes += ip_header_size + tcp_header_size + rev_payload_size

        # Forward FIN (seq=1101, ack=2051, ttl=64)
        pkt_fin = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(sport=sport, dport=dport, flags="FA", seq=1101, ack=2051)
            / Raw(b"")
        )
        self.pg_send(self.pg0, pkt_fin)
        expected_fwd_packets += 1
        expected_fwd_bytes += ip_header_size + tcp_header_size

        # Reverse RST (ttl=127)
        pkt_rst = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=127)
            / TCP(sport=dport, dport=sport, flags="R", seq=2051, ack=0)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_rst)
        expected_rev_packets += 1
        expected_rev_bytes += ip_header_size + tcp_header_size

        # Forward extra packet with lowest TTL (ttl=58)
        pkt_extra = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=58)
            / TCP(sport=sport, dport=dport, flags="A", seq=1102, ack=2051)
            / Raw(b"")
        )
        self.pg_send(self.pg0, pkt_extra)
        expected_fwd_packets += 1
        expected_fwd_bytes += ip_header_size + tcp_header_size

        # Export and verify
        reply = self.vapi.sfdp_session_stats_export_now()
        self.assertEqual(reply.retval, 0)
        self.virtual_sleep(0.2)

        ring_buffer = self.statistics.get_ring_buffer("/sfdp/session/stats")
        schema_string, _, _ = ring_buffer.get_schema_string()
        decode_entry, _ = self.create_ring_buffer_decoder(schema_string)

        data = ring_buffer.consume_data(thread_index=0)
        self.assertGreater(len(data), 0, "Should have at least one entry")

        entry = decode_entry(data[0])

        # Verify packet counts
        self.assertEqual(entry["packets_forward"], expected_fwd_packets)
        self.assertEqual(entry["packets_reverse"], expected_rev_packets)

        # Verify byte counts
        self.assertEqual(entry["bytes_forward"], expected_fwd_bytes)
        self.assertEqual(entry["bytes_reverse"], expected_rev_bytes)

        # Verify TCP control flags
        self.assertEqual(entry["tcp_syn_packets"], 2)  # SYN + SYN-ACK
        self.assertEqual(entry["tcp_fin_packets"], 1)
        self.assertEqual(entry["tcp_rst_packets"], 1)

        # Verify TCP handshake marked complete
        self.assertEqual(entry["tcp_handshake_complete"], 1)

        # Verify TCP seq/ack tracking
        # Forward seq tracks seq + payload_len: 1001 + 100 = 1101 (FIN has 0 payload)
        self.assertEqual(entry["tcp_last_seq_forward"], 1101)
        # Reverse acknowledged forward data up to 1101
        self.assertEqual(entry["tcp_last_ack_forward"], 1101)
        # Reverse seq after DATA: 2001 + 50 = 2051
        self.assertEqual(entry["tcp_last_seq_reverse"], 2051)
        # Forward acknowledged reverse up to 2051 (from FIN ack)
        self.assertEqual(entry["tcp_last_ack_reverse"], 2051)

        # Verify TTL min/max per direction
        # Forward TTL values: 60, 64, 62, 64, 58 -> min=58, max=64
        self.assertEqual(entry["ttl_min_forward"], 58)
        self.assertEqual(entry["ttl_max_forward"], 64)
        # Reverse TTL values: 128, 125, 130, 127 -> min=125, max=130
        self.assertEqual(entry["ttl_min_reverse"], 125)
        self.assertEqual(entry["ttl_max_reverse"], 130)

        self._cleanup_sfdp_session_stats(config)

    def test_session_stats_tcp_anomalies(self):
        """Test that TCP anomaly events are counted correctly in a single session.

        This test verifies that a single session tracks all TCP anomaly events:
        - Partial overlaps: segment overlaps with received data but has new data
        - Zero window events: receiver advertises window=0
        - Duplicate ACKs: same ACK number repeated with outstanding data
        - Retransmissions: segment's entire range already received
        - ECN/CWR metrics: ECN ECT, CE, ECE and CWR packets
        """
        config = self._configure_sfdp_session_stats(
            enable_bidirectional=True,
            enable_ring_buffer=True,
            ring_size=256,
        )

        sport = 13000
        dport = 14000

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

        # === Send data packets to establish sequence tracking ===
        # Forward DATA #1: seq=1001, len=100
        pkt_data1 = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(
                sport=sport, dport=dport, flags="PA", seq=1001, ack=2001, window=65535
            )
            / Raw(b"\xaa" * 100)
        )
        self.pg_send(self.pg0, pkt_data1)

        # Forward DATA #2: seq=1101, len=100
        pkt_data2 = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64)
            / TCP(
                sport=sport, dport=dport, flags="PA", seq=1101, ack=2001, window=65535
            )
            / Raw(b"\xbb" * 100)
        )
        self.pg_send(self.pg0, pkt_data2)

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

        # ACK forward data
        pkt_ack1 = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="A", seq=2001, ack=1201, window=65535)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_ack1)

        # === Trigger Duplicate ACK (for forward data) ===
        # Send same ACK again with outstanding data beyond it
        pkt_dupack = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="A", seq=2001, ack=1201, window=65535)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_dupack)

        # === Trigger Zero Window (reverse) ===
        pkt_zero_window = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="A", seq=2001, ack=1250, window=0)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_zero_window)

        # Window opens again
        pkt_window_open = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="A", seq=2001, ack=1250, window=65535)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_window_open)

        # === ECN ECT(0) packet (tos=2) ===
        pkt_ecn_ect = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64, tos=2)
            / TCP(sport=sport, dport=dport, flags="A", seq=1250, ack=2001, window=65535)
            / Raw(b"\xdd" * 50)
        )
        self.pg_send(self.pg0, pkt_ecn_ect)

        # === ECN CE packet (tos=3) ===
        pkt_ecn_ce = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64, tos=3)
            / TCP(sport=sport, dport=dport, flags="A", seq=1300, ack=2001, window=65535)
            / Raw(b"\xee" * 50)
        )
        self.pg_send(self.pg0, pkt_ecn_ce)

        # === TCP ECE flag packet ===
        pkt_ece = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128, tos=0)
            / TCP(
                sport=dport, dport=sport, flags="AE", seq=2001, ack=1350, window=65535
            )
            / Raw(b"\x11" * 50)
        )
        self.pg_send(self.pg1, pkt_ece)

        # === TCP CWR flag packet ===
        pkt_cwr = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=64, tos=0)
            / TCP(
                sport=sport, dport=dport, flags="AC", seq=1350, ack=2001, window=65535
            )
            / Raw(b"\xff" * 50)
        )
        self.pg_send(self.pg0, pkt_cwr)

        # Final ACK
        pkt_final_ack = (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=128)
            / TCP(sport=dport, dport=sport, flags="A", seq=2001, ack=1400, window=65535)
            / Raw(b"")
        )
        self.pg_send(self.pg1, pkt_final_ack)

        # Trigger export to ring buffer
        reply = self.vapi.sfdp_session_stats_export_now()
        self.assertEqual(reply.retval, 0)
        self.virtual_sleep(0.2)

        # Read from ring buffer
        ring_buffer = self.statistics.get_ring_buffer("/sfdp/session/stats")
        schema_string, _, _ = ring_buffer.get_schema_string()
        decode_entry, _ = self.create_ring_buffer_decoder(schema_string)

        data = ring_buffer.consume_data(thread_index=0)
        self.assertGreater(
            len(data), 0, "Should have at least one entry in ring buffer"
        )

        entry = decode_entry(data[0])

        # === Verify all TCP anomaly counters ===

        # Partial overlap: 1 forward (seq=1150 overlapping 1101-1200)
        self.assertGreaterEqual(
            entry["tcp_partial_overlap_events_fwd"],
            1,
            "Should have at least 1 forward partial overlap event",
        )

        # Retransmission: 1 forward (resent seq=1001)
        self.assertGreaterEqual(
            entry["tcp_retransmissions_fwd"],
            1,
            "Should have at least 1 forward retransmission event",
        )

        # Duplicate ACK: 1 (for forward data)
        self.assertGreaterEqual(
            entry["tcp_dupack_events_fwd"],
            1,
            "Should have at least 1 forward dupack event",
        )

        # Zero window: 1 reverse
        self.assertGreaterEqual(
            entry["tcp_zero_window_events_rev"],
            1,
            "Should have at least 1 reverse zero window event",
        )

        # Out-of-order: 0 (detection not yet implemented)
        self.assertEqual(
            entry["tcp_out_of_order_events_fwd"],
            0,
            "Out-of-order detection not implemented yet",
        )
        self.assertEqual(
            entry["tcp_out_of_order_events_rev"],
            0,
            "Out-of-order detection not implemented yet",
        )

        # ECN ECT: 1 packet
        self.assertGreaterEqual(
            entry["tcp_ecn_ect_packets"],
            1,
            "Should have at least 1 ECN ECT packet",
        )

        # ECN CE: 1 packet
        self.assertGreaterEqual(
            entry["tcp_ecn_ce_packets"],
            1,
            "Should have at least 1 ECN CE packet",
        )

        # TCP ECE: 1 packet
        self.assertGreaterEqual(
            entry["tcp_ece_packets"],
            1,
            "Should have at least 1 TCP ECE packet",
        )

        # TCP CWR: 1 packet
        self.assertGreaterEqual(
            entry["tcp_cwr_packets"],
            1,
            "Should have at least 1 TCP CWR packet",
        )

        # Cleanup
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
        # Get default global custom data config
        reply = self.vapi.sfdp_session_stats_get_custom_data_config()

        self.assertEqual(reply.retval, 0)
        self.assertFalse(
            reply.custom_data_enabled, "Custom data should be disabled by default"
        )
        self.assertFalse(
            reply.has_any_api_data, "No tenant should have API data by default"
        )

        # Enable custom data
        reply = self.vapi.sfdp_session_stats_custom_data_enable(enable=True)
        self.assertEqual(reply.retval, 0)

        # Verify custom data is enabled
        reply = self.vapi.sfdp_session_stats_get_custom_data_config()
        self.assertEqual(reply.retval, 0)
        self.assertTrue(reply.custom_data_enabled, "Custom data should be enabled")

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

        # Verify global config shows some tenant has API data
        reply = self.vapi.sfdp_session_stats_get_custom_data_config()
        self.assertTrue(
            reply.has_any_api_data, "Should indicate some tenant has API data"
        )

        # Also verify via get_config
        config = self.vapi.sfdp_session_stats_get_config()
        self.assertTrue(
            config.custom_data_enabled, "Custom data should be enabled in config"
        )
        self.assertTrue(
            config.has_api_custom_data, "API custom data should be set in config"
        )

        # Clear custom API data for tenant 1
        reply = self.vapi.sfdp_session_stats_clear_custom_api_data(tenant_id=tenant_id)
        self.assertEqual(reply.retval, 0)

        reply = self.vapi.sfdp_session_stats_get_tenant_custom_data(tenant_id=tenant_id)
        self.assertFalse(reply.has_api_data, "API data should be cleared for tenant 1")

        # Disable custom data
        reply = self.vapi.sfdp_session_stats_custom_data_enable(enable=False)
        self.assertEqual(reply.retval, 0)

        reply = self.vapi.sfdp_session_stats_get_custom_data_config()
        self.assertFalse(reply.custom_data_enabled, "Custom data should be disabled")

    def test_session_stats_cli_configuration(self):
        """Test session stats CLI commands for ring buffer and periodic export"""
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
        # Schema v4 offsets: fwd_dst_port at 118, packets_forward at 20
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

    def test_session_stats_ring_buffer_with_custom_data(self):
        """Test that custom data configuration is reflected in ring buffer entries"""
        # Configure SFDP with ring buffer and custom data enabled
        # Set custom API data for tenant index 0 (default tenant)
        config = self._configure_sfdp_session_stats(
            enable_ring_buffer=True,
            ring_size=256,
            enable_custom_data=True,
            custom_api_data=0xDEADBEEFCAFEBABE,
        )

        # Verify custom data is enabled and set for tenant_id 1
        custom_data_config = self.vapi.sfdp_session_stats_get_custom_data_config()
        self.assertTrue(custom_data_config.custom_data_enabled)
        self.assertTrue(custom_data_config.has_any_api_data)

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

        self.assertGreater(len(data), 0, "Should have at least one entry")

        # Parse the entry and verify custom data flags
        # Schema v6 offsets: custom_data_flags at 312, custom_api_data at 320
        entry_bytes = data[0]
        self.assertEqual(len(entry_bytes), 384, "Entry should be 384 bytes")

        # Extract custom data flags
        custom_data_flags = struct.unpack_from("<B", entry_bytes, 312)[0]

        # Verify flag bit 0 is set (API data present)
        self.assertTrue(custom_data_flags & 0x01, "Custom data API flag should be set")

        # Extract custom API data (u64 at offset 320)
        custom_api_data = struct.unpack_from("<Q", entry_bytes, 320)[0]

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
        custom_api_data = struct.unpack_from("<Q", entry_bytes, 320)[0]
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
            custom_data_flags = struct.unpack_from("<B", entry_bytes, 312)[0]
            # API flag should be cleared (bit 0 = 0)
            self.assertFalse(
                custom_data_flags & 0x01, "Custom data API flag should be cleared"
            )

        # Cleanup
        self._cleanup_sfdp_session_stats(config)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
