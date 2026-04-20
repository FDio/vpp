#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2025 Cisco Systems, Inc.

import unittest
from asfframework import VppTestRunner
from framework import VppTestCase
from config import config
from vpp_papi import VppEnum
from test_sfdp import BaseSfdpTest

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP


@unittest.skipIf(
    "sfdp_services" in config.excluded_plugins,
    "SFDP_Services plugin is required to run SFDP Session Stats tests",
)
class TestSfdpSessionStats(BaseSfdpTest):
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

    def _get_single_session_stats(self):
        stats = self.vapi.sfdp_session_stats_dump()
        self.assertEqual(len(stats), 1, "Should have exactly one session")
        return stats[0]

    def _make_fwd_pkt(self, sport, dport, flags, seq, ack, payload=b"", options=[]):
        return self.create_tcp_packet(
            self.pg0.remote_mac,
            self.pg0.local_mac,
            self.pg0.remote_ip4,
            self.pg1.remote_ip4,
            sport,
            dport,
            flags=flags,
            seq=seq,
            ack=ack,
            payload=payload,
            options=options,
        )

    def _make_rev_pkt(self, sport, dport, flags, seq, ack, payload=b"", options=[]):
        return self.create_tcp_packet(
            self.pg1.remote_mac,
            self.pg1.local_mac,
            self.pg1.remote_ip4,
            self.pg0.remote_ip4,
            dport,
            sport,
            flags=flags,
            seq=seq,
            ack=ack,
            payload=payload,
            options=options,
        )

    def create_ring_buffer_decoder(self, schema_data, ring_entry_size):
        # Create decoder of Session Statistics ring-buffer entries
        # Entries are serialized in API wire format and decoded with shared API typedefs.

        # StatsRingBuffer.get_schema_string() returns a tuple:
        # (schema_string_or_bytes, schema_size, schema_version).
        schema_size = None
        schema_version = None
        if isinstance(schema_data, tuple):
            schema_data, schema_size, schema_version = schema_data

        if isinstance(schema_data, bytes):
            schema_data = schema_data.decode("utf-8")

        if not isinstance(schema_data, str):
            raise ValueError(
                f"Provided schema has unsupported type: {type(schema_data).__name__}"
            )

        # Reconstruct ABI ID for api define sfdp_session_stats_ring_entry_abi_id
        abi_prefix = "sfdp_session_stats_ring_entry_abi_id_"
        expected_abi_id = None
        msg = self.vapi.vpp.messages.get("sfdp_session_stats_ring_entry_abi_id")
        msg_crc = getattr(msg, "crc", None)
        msg_crc = msg_crc.lower()
        msg_crc = msg_crc[2:]  # Remove prefix '0x' from msg crc string
        expected_abi_id = f"{abi_prefix}{msg_crc.zfill(8)}"

        if expected_abi_id is None:
            raise ValueError("Unable to derive expected ABI ID from vapi.vpp.messages")

        # Verify that ABI ID stored in schema string matches msg ABI ID.
        if schema_data != expected_abi_id:
            raise ValueError(
                f"Unsupported ring ABI identifier: {schema_data!r}, expected {expected_abi_id!r}"
            )

        # Get common ring buffer entry type defined in VPP API
        ring_entry_type = self.vapi.vpp.get_type(
            "vl_api_sfdp_session_stats_ring_entry_t"
        )
        if ring_entry_type is None:
            raise ValueError(
                "vl_api_sfdp_session_stats_ring_entry_t type does not exist"
            )

        # Check that ring entry size from stats ring config matches API typedef size.
        entry_size = ring_entry_type.size
        if ring_entry_size != entry_size:
            raise ValueError(
                f"Ring entry size mismatch: schema/config={ring_entry_size}, api={entry_size}"
            )

        schema = {
            "abi_id": schema_data,
            "abi_id_size": schema_size,
            "schema_version": schema_version,
            "entry_size": entry_size,
        }

        def decode_entry(entry_bytes):
            # Decode entry from ring buffer
            if len(entry_bytes) < entry_size:
                raise ValueError(
                    f"Entry too short for static ring ABI: {len(entry_bytes)} < {entry_size}"
                )

            decoded, consumed = ring_entry_type.unpack(entry_bytes[:entry_size], 0)
            if consumed != entry_size:
                raise ValueError(
                    f"Ring entry decode size mismatch: consumed {consumed}, expected {entry_size}"
                )
            return decoded._asdict()

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
        batch_interval=1.0,
        tenant_custom_data=0,
        tenant_custom_data2=0,
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

        # Set tenant custom data for tenant if requested
        if tenant_custom_data or tenant_custom_data2:
            reply = self.vapi.sfdp_session_stats_set_tenant_custom_data(
                tenant_id=tenant_id,
                value=tenant_custom_data,
                value2=tenant_custom_data2,
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
                enable=True, interval=export_interval, batch_interval=batch_interval
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
        self.wait_no_sessions()

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

        # Enable periodic export via CLI with custom batch interval
        self.vapi.cli("sfdp session stats periodic enable interval 45 batch-interval 5")

        # Verify via API
        config = self.vapi.sfdp_session_stats_get_config()
        self.assertTrue(
            config.periodic_export_enabled, "Periodic export should be enabled"
        )
        self.assertEqual(config.export_interval, 45.0, "Interval should be 45 seconds")
        self.assertEqual(
            config.export_batch_interval,
            5.0,
            "Batch interval should be 5 seconds",
        )

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
        # Enable periodic export with custom interval and batch interval
        reply = self.vapi.sfdp_session_stats_periodic_export(
            enable=True, interval=30.0, batch_interval=3.0
        )
        self.assertEqual(reply.retval, 0)

        # Verify configuration
        config = self.vapi.sfdp_session_stats_get_config()
        self.assertTrue(
            config.periodic_export_enabled, "Periodic export should be enabled"
        )
        self.assertEqual(
            config.export_interval, 30.0, "Export interval should be 30 seconds"
        )
        self.assertEqual(
            config.export_batch_interval, 3.0, "Batch interval should be 3 seconds"
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

        # === Forward SYN (seq=1000, ttl=60) ===
        pkt_syn = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=60)
            / TCP(sport=sport, dport=dport, flags="S", seq=1000, ack=0)
            / Raw(b"")
        )
        self.pg_send(self.pg0, pkt_syn)

        s = self._get_single_session_stats()
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

        s = self._get_single_session_stats()
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

        s = self._get_single_session_stats()
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

        s = self._get_single_session_stats()
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

        s = self._get_single_session_stats()
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

        s = self._get_single_session_stats()
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

        s = self._get_single_session_stats()
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

        s = self._get_single_session_stats()
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

        s = self._get_single_session_stats()
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

        sport = 13000
        dport = 14000

        def make_initiator_tcp(
            flags, seq, ack, payload=b"", ttl=64, tos=0, window=65535, options=[]
        ):
            return (
                Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
                / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, ttl=ttl, tos=tos)
                / TCP(
                    sport=sport,
                    dport=dport,
                    flags=flags,
                    seq=seq,
                    ack=ack,
                    window=window,
                    options=options,
                )
                / Raw(payload)
            )

        def make_responder_tcp(
            flags, seq, ack, payload=b"", ttl=128, tos=0, window=65535, options=[]
        ):
            return (
                Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
                / IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4, ttl=ttl, tos=tos)
                / TCP(
                    sport=dport,
                    dport=sport,
                    flags=flags,
                    seq=seq,
                    ack=ack,
                    window=window,
                    options=options,
                )
                / Raw(payload)
            )

        config = self._configure_sfdp_session_stats(
            enable_bidirectional=True,
        )

        # === TCP 3-Way Handshake ===
        # Use deliberately different MSS values per direction to verify bidirectional tracking
        MSS_FWD = 1400
        MSS_REV = 1460
        self.pg_send(
            self.pg0,
            make_initiator_tcp(flags="S", seq=1000, ack=0, options=[("MSS", MSS_FWD)]),
        )
        self.pg_send(
            self.pg1,
            make_responder_tcp(
                flags="SA", seq=2000, ack=1001, options=[("MSS", MSS_REV)]
            ),
        )
        self.virtual_sleep(0.5)  # Add delay so that handshake rtt is non-zero
        self.pg_send(self.pg0, make_initiator_tcp(flags="A", seq=1001, ack=2001))

        s = self._get_single_session_stats()
        self.assertEqual(s.tcp_handshake_complete, True)
        self.assertEqual(s.tcp_syn_packets, 2)
        self.assertGreaterEqual(
            s.syn_rtt, 0.5
        )  # handshake rtt must be at least the sleep duration
        self.assertEqual(
            s.tcp_mss_fwd, MSS_FWD, "Forward MSS should be set from initiator SYN"
        )
        self.assertEqual(
            s.tcp_mss_rev, MSS_REV, "Reverse MSS should be set from responder SYN-ACK"
        )

        # === Forward DATA #1: seq=1001, len=100 ===
        self.pg_send(
            self.pg0,
            make_initiator_tcp(flags="PA", seq=1001, ack=2001, payload=b"\xaa" * 100),
        )

        # === Forward DATA #2: seq=1101, len=100 ===
        self.pg_send(
            self.pg0,
            make_initiator_tcp(flags="PA", seq=1101, ack=2001, payload=b"\xbb" * 100),
        )

        s = self._get_single_session_stats()
        self.assertEqual(s.packets_fwd, 4)  # SYN + ACK + DATA1 + DATA2
        self.assertEqual(s.tcp_retransmissions_fwd, 0)

        # === Trigger Retransmission (forward) ===
        # Resend DATA #1 (complete retransmission, seq=1001, entirely within received)
        self.pg_send(
            self.pg0,
            make_initiator_tcp(flags="PA", seq=1001, ack=2001, payload=b"\xaa" * 100),
        )

        s = self._get_single_session_stats()
        self.assertGreaterEqual(
            s.tcp_retransmissions_fwd,
            1,
            "Should have at least 1 retransmission after resending old data",
        )

        # ACK forward data
        self.pg_send(self.pg1, make_responder_tcp(flags="A", seq=2001, ack=1201))

        # === Trigger Zero Window (reverse) ===
        prev_zero_window = s.tcp_zero_window_events_rev
        self.pg_send(
            self.pg1, make_responder_tcp(flags="A", seq=2001, ack=1250, window=0)
        )

        s = self._get_single_session_stats()
        self.assertGreaterEqual(
            s.tcp_zero_window_events_rev,
            prev_zero_window + 1,
            "Should have zero window event after window=0 packet",
        )

        # Window opens again (should not increment zero window counter)
        self.pg_send(self.pg1, make_responder_tcp(flags="A", seq=2001, ack=1250))

        # === ECN ECT(0) packet (tos=2) ===
        prev_ecn_ect = s.tcp_ecn_ect_packets
        self.pg_send(
            self.pg0,
            make_initiator_tcp(
                flags="A", seq=1250, ack=2001, payload=b"\xdd" * 50, tos=2
            ),
        )

        s = self._get_single_session_stats()
        self.assertGreater(
            s.tcp_ecn_ect_packets,
            prev_ecn_ect,
            "ECN ECT counter should increment after ECT packet",
        )

        # === ECN CE packet (tos=3) ===
        prev_ecn_ce = s.tcp_ecn_ce_packets
        self.pg_send(
            self.pg0,
            make_initiator_tcp(
                flags="A", seq=1300, ack=2001, payload=b"\xee" * 50, tos=3
            ),
        )

        s = self._get_single_session_stats()
        self.assertGreater(
            s.tcp_ecn_ce_packets,
            prev_ecn_ce,
            "ECN CE counter should increment after CE packet",
        )

        # === TCP ECE flag packet ===
        prev_ece = s.tcp_ece_packets
        self.pg_send(
            self.pg1,
            make_responder_tcp(flags="AE", seq=2001, ack=1350, payload=b"\x11" * 50),
        )

        s = self._get_single_session_stats()
        self.assertGreater(
            s.tcp_ece_packets,
            prev_ece,
            "TCP ECE counter should increment after ECE flag packet",
        )

        # === TCP CWR flag packet ===
        prev_cwr = s.tcp_cwr_packets
        self.pg_send(
            self.pg0,
            make_initiator_tcp(flags="AC", seq=1350, ack=2001, payload=b"\xff" * 50),
        )

        s = self._get_single_session_stats()
        self.assertGreater(
            s.tcp_cwr_packets,
            prev_cwr,
            "TCP CWR counter should increment after CWR flag packet",
        )

        # Final ACK for the ECN/CWR section
        self.pg_send(self.pg1, make_responder_tcp(flags="A", seq=2001, ack=1400))

        # Out-of-Order event detection
        # fwd max end_seq (seq + payload_len) is at 1400, last_ack[fwd] = 1400
        # Send seq=1400 (normal), skip seq=1500, send seq=1600 (gap),
        # then fill with seq=1500 (should be OOO, not retransmit)
        DATA = b"\xaa" * 100
        self.pg_send(
            self.pg0, make_initiator_tcp(flags="PA", seq=1400, ack=2001, payload=DATA)
        )
        self.pg_send(self.pg1, make_responder_tcp(flags="A", seq=2001, ack=1500))

        s = self._get_single_session_stats()
        prev_ooo = s.tcp_out_of_order_events_fwd
        prev_retrans = s.tcp_retransmissions_fwd

        # Open a gap: seq=1600 skipped, seq=1700 arrives first
        self.pg_send(
            self.pg0, make_initiator_tcp(flags="PA", seq=1700, ack=2001, payload=DATA)
        )  # gap: end_seq_max advances to 1800, gap_start_seq=1500, snapshot dupack_like
        # Fill the gap immediately (no dupacks sent - dupack_like unchanged -> OOO)
        self.pg_send(
            self.pg0, make_initiator_tcp(flags="PA", seq=1600, ack=2001, payload=DATA)
        )

        s = self._get_single_session_stats()
        self.assertEqual(
            s.tcp_out_of_order_events_fwd,
            prev_ooo + 1,
            "Gap fill with no intervening dupacks should be classified as OOO",
        )
        self.assertEqual(
            s.tcp_retransmissions_fwd,
            prev_retrans,
            "Retransmission counter should not change for OOO fill",
        )

        # ACK everything so far
        self.pg_send(self.pg1, make_responder_tcp(flags="A", seq=2001, ack=1800))

        # Retransmission detection: gap + dupacks -> fill is classified retransmission
        s = self._get_single_session_stats()
        prev_ooo = s.tcp_out_of_order_events_fwd
        prev_retrans = s.tcp_retransmissions_fwd

        # Open a gap: seq=1900 skipped, seq=2000 arrives first
        self.pg_send(
            self.pg0, make_initiator_tcp(flags="PA", seq=2000, ack=2001, payload=DATA)
        )  # gap: gap_start_seq=1800, snapshot dupack_like
        # Send 3 reverse pure-ACKs at the same ack value to bump dupack_like on the fwd direction
        for _ in range(3):
            self.pg_send(self.pg1, make_responder_tcp(flags="A", seq=2001, ack=1800))
        # Fill the gap (dupack_like has advanced past snapshot → retransmission)
        self.pg_send(
            self.pg0, make_initiator_tcp(flags="PA", seq=1900, ack=2001, payload=DATA)
        )

        s = self._get_single_session_stats()
        self.assertEqual(
            s.tcp_retransmissions_fwd,
            prev_retrans + 1,
            "Gap fill after dupacks should be classified as retransmission",
        )
        self.assertEqual(
            s.tcp_out_of_order_events_fwd,
            prev_ooo,
            "OOO counter should not change for dupack-driven retransmission fill",
        )

        # ACK everything
        self.pg_send(self.pg1, make_responder_tcp(flags="A", seq=2001, ack=2100))

        # === Final verification of all TCP event counters ===
        s = self._get_single_session_stats()
        self.assertGreaterEqual(s.tcp_retransmissions_fwd, 2)
        self.assertGreaterEqual(s.tcp_zero_window_events_rev, 1)
        self.assertGreaterEqual(s.tcp_ecn_ect_packets, 1)
        self.assertGreaterEqual(s.tcp_ecn_ce_packets, 1)
        self.assertGreaterEqual(s.tcp_ece_packets, 1)
        self.assertGreaterEqual(s.tcp_cwr_packets, 1)
        self.assertGreaterEqual(s.tcp_out_of_order_events_fwd, 1)
        self.assertEqual(s.tcp_out_of_order_events_rev, 0)

        self._cleanup_sfdp_session_stats(config)

    def test_session_stats_tcp_data_packets(self):
        """Test that TCP data packet counter is incremented correctly"""
        config = self._configure_sfdp_session_stats(
            enable_bidirectional=True,
        )

        sport = 15000
        dport = 16000

        # TCP Hanshake traffic, tcp data packets counter is not expected to be incremented
        self.pg_send(
            self.pg0, self._make_fwd_pkt(sport, dport, flags="S", seq=1000, ack=0)
        )
        self.pg_send(
            self.pg1, self._make_rev_pkt(sport, dport, flags="SA", seq=2000, ack=1001)
        )
        self.pg_send(
            self.pg0, self._make_fwd_pkt(sport, dport, flags="A", seq=1001, ack=2001)
        )

        s = self._get_single_session_stats()
        self.assertEqual(
            s.tcp_data_packets_fwd,
            0,
            "No payload sent yet - fwd data counter must be 0",
        )
        self.assertEqual(
            s.tcp_data_packets_rev,
            0,
            "No payload sent yet - rev data counter must be 0",
        )

        # Three forward payload-carrying segments.
        seq_fwd = 1001
        for i in range(3):
            self.pg_send(
                self.pg0,
                self._make_fwd_pkt(
                    sport,
                    dport,
                    flags="PA",
                    seq=seq_fwd,
                    ack=2001,
                    payload=b"\xaa" * 100,
                ),
            )
            seq_fwd += 100

        # pure-ACK reverse packet
        self.pg_send(
            self.pg1, self._make_rev_pkt(sport, dport, flags="A", seq=2001, ack=seq_fwd)
        )

        # Two reverse payload-carrying segments.
        seq_rev = 2001
        for i in range(2):
            self.pg_send(
                self.pg1,
                self._make_rev_pkt(
                    sport,
                    dport,
                    flags="PA",
                    seq=seq_rev,
                    ack=seq_fwd,
                    payload=b"\xbb" * 50,
                ),
            )
            seq_rev += 50

        # pure-ACK forward packet
        self.pg_send(
            self.pg0,
            self._make_fwd_pkt(sport, dport, flags="A", seq=seq_fwd, ack=seq_rev),
        )

        s = self._get_single_session_stats()
        self.assertEqual(
            s.tcp_data_packets_fwd,
            3,
            "Three forward payload-carrying segments should increment fwd counter",
        )
        self.assertEqual(
            s.tcp_data_packets_rev,
            2,
            "Two reverse payload-carrying segments should increment rev counter",
        )

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

        # Set tenant custom data for tenant_id 1
        test_data = 0x123456789ABCDEF0
        test_data2 = 0x0FEDCBA987654321
        tenant_id = 1
        reply = self.vapi.sfdp_session_stats_set_tenant_custom_data(
            tenant_id=tenant_id, value=test_data, value2=test_data2
        )
        self.assertEqual(reply.retval, 0)

        # Verify API data is set for tenant 1 using get_tenant_custom_data
        reply = self.vapi.sfdp_session_stats_get_tenant_custom_data(tenant_id=tenant_id)
        self.assertTrue(reply.has_api_data, "API data should be set for tenant 1")
        self.assertEqual(
            reply.api_data_value, test_data, "API data should match for tenant 1"
        )
        self.assertEqual(
            reply.api_data_value2,
            test_data2,
            "API data value2 should match for tenant 1",
        )
        self.assertEqual(reply.tenant_id, tenant_id, "Tenant ID should match")

        # Clear tenant custom data for tenant 1
        reply = self.vapi.sfdp_session_stats_clear_tenant_custom_data(
            tenant_id=tenant_id
        )
        self.assertEqual(reply.retval, 0)

        reply = self.vapi.sfdp_session_stats_get_tenant_custom_data(tenant_id=tenant_id)
        self.assertFalse(reply.has_api_data, "API data should be cleared for tenant 1")
        self.assertEqual(
            reply.api_data_value2,
            0,
            "API data value2 should default to 0 once cleared",
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
        schema_data = ring_buffer.get_schema_string(thread_index=0)
        ring_config = ring_buffer.get_config()
        decode_entry, _ = self.create_ring_buffer_decoder(
            schema_data, ring_config["entry_size"]
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
        # Configure SFDP with ring buffer and tenant custom data for tenant
        config = self._configure_sfdp_session_stats(
            enable_ring_buffer=True,
            ring_size=256,
            tenant_custom_data=0xDEADBEEFCAFEBABE,
            tenant_custom_data2=0x0011223344556677,
        )

        # Verify custom data is set for tenant_id 1
        tenant_data = self.vapi.sfdp_session_stats_get_tenant_custom_data(tenant_id=1)
        self.assertTrue(tenant_data.has_api_data)
        self.assertEqual(tenant_data.api_data_value, 0xDEADBEEFCAFEBABE)
        self.assertEqual(tenant_data.api_data_value2, 0x0011223344556677)

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
        schema_data = ring_buffer.get_schema_string(thread_index=0)
        ring_config = ring_buffer.get_config()
        decode_entry, schema = self.create_ring_buffer_decoder(
            schema_data, ring_config["entry_size"]
        )

        self.assertGreater(len(data), 0, "Should have at least one entry")

        # Parse the entry and verify opaque data.
        entry_bytes = data[0]
        expected_entry_size = schema.get("entry_size", len(entry_bytes))
        self.assertEqual(
            len(entry_bytes),
            expected_entry_size,
            f"Entry should be {expected_entry_size} bytes",
        )
        decoded = decode_entry(entry_bytes)

        # Extract opaque data.
        tenant_custom_data = decoded["opaque"]
        tenant_custom_data2 = decoded["opaque2"]

        self.assertEqual(
            tenant_custom_data, 0xDEADBEEFCAFEBABE, "Tenant custom data should match"
        )
        self.assertEqual(
            tenant_custom_data2,
            0x0011223344556677,
            "Tenant custom data (opaque2) should match",
        )

        # Update tenant custom data for tenant_id 1
        reply = self.vapi.sfdp_session_stats_set_tenant_custom_data(
            tenant_id=1,
            value=0x1234567890ABCDEF,
            value2=0x7EDCBA9876543210,
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
        tenant_custom_data = decoded["opaque"]
        tenant_custom_data2 = decoded["opaque2"]
        self.assertEqual(
            tenant_custom_data,
            0x1234567890ABCDEF,
            "Tenant custom data should be updated",
        )
        self.assertEqual(
            tenant_custom_data2,
            0x7EDCBA9876543210,
            "Tenant custom data (opaque2) should be updated",
        )

        # Clear tenant custom data for tenant_id 1 and verify it's reflected
        reply = self.vapi.sfdp_session_stats_clear_tenant_custom_data(tenant_id=1)
        self.assertEqual(reply.retval, 0)

        # Export one more time
        reply = self.vapi.sfdp_session_stats_export_now()
        self.assertEqual(reply.retval, 0)
        self.virtual_sleep(0.2)

        data = ring_buffer.consume_data(thread_index=0)
        if len(data) > 0:
            entry_bytes = data[0]
            decoded = decode_entry(entry_bytes)
            tenant_custom_data = decoded["opaque"]
            tenant_custom_data2 = decoded["opaque2"]
            self.assertEqual(
                tenant_custom_data, 0, "Opaque data should default to zero"
            )
            self.assertEqual(
                tenant_custom_data2, 0, "Opaque2 data should default to zero"
            )

        # Cleanup
        self._cleanup_sfdp_session_stats(config)

    def test_session_stats_batched_ring_buffer_export(self):
        """Test batched periodic export with ring_size < number of sessions"""
        # TODO - Upon session expiration, a worker thread will export the session stats to the ring buffer from its dedicated thread
        # In this test, we currently only test periodic export which occurs in main thread
        ring_size = 3
        num_sessions = 8
        export_interval = 5.0
        batch_interval = 1.0

        config = self._configure_sfdp_session_stats(
            enable_ring_buffer=True,
            ring_size=ring_size,
            enable_periodic_export=True,
            export_interval=export_interval,
            batch_interval=batch_interval,
        )

        # Increase default embryonic timeout, as we are testing with an export interval
        # going beyond default timeout
        reply = self.vapi.sfdp_set_timeout(
            tenant_id=config["tenant_id"], timeout_id=0, timeout_value=120
        )
        self.assertEqual(reply.retval, 0)

        # Create distinct TCP sessions (varying dport is enough for unique 5-tuples)
        sport = 50000
        base_dport = 6000
        sessions_info = []
        for i in range(num_sessions):
            dport = base_dport + i
            sessions_info.append({"sport": sport, "dport": dport})
            pkt = self.create_tcp_packet(
                src_mac=self.pg0.remote_mac,
                dst_mac=self.pg0.local_mac,
                src_ip=self.pg0.remote_ip4,
                dst_ip=self.pg1.remote_ip4,
                sport=sport,
                dport=dport,
                flags="S",
            )
            self.pg_send(self.pg0, pkt)

        # Verify all sessions were created
        stats = self.vapi.sfdp_session_stats_dump()
        self.assertEqual(
            len(stats),
            num_sessions,
            "We do not have the expected number of created sessions",
        )

        # Set up ring buffer decoder
        ring_buffer = self.statistics.get_ring_buffer("/sfdp/session/stats")

        # Using periodic export, all session information is expected
        # to be written on main-thread ring buffer data
        schema_data = ring_buffer.get_schema_string(thread_index=0)
        ring_config = ring_buffer.get_config()
        decode_entry, _ = self.create_ring_buffer_decoder(
            schema_data, ring_config["entry_size"]
        )

        all_exported_dports = []
        batch_count = 0
        expected_batches = (
            3  # Three batches are expected with 8 sessions and ring buffer size 3
        )

        # Record initial sequence to track ring buffer writes
        prev_sequence = ring_buffer._get_thread_metadata(0)["sequence"]

        for batch_num in range(expected_batches):
            # Send traffic for each session
            for sess in sessions_info:
                pkt = self.create_tcp_packet(
                    src_mac=self.pg0.remote_mac,
                    dst_mac=self.pg0.local_mac,
                    src_ip=self.pg0.remote_ip4,
                    dst_ip=self.pg1.remote_ip4,
                    sport=sess["sport"],
                    dport=sess["dport"],
                    flags="A",
                )
                self.pg_send(self.pg0, pkt)

            # For first batch,ensure periodic timer has fired
            if batch_num == 0:
                self.virtual_sleep(export_interval + 0.1)
            else:
                # For subsequent batches, ensure batch interval timer has fired
                self.virtual_sleep(batch_interval + 0.1)

            # Verify sessions have not expired during timer sleep
            stats = self.vapi.sfdp_session_stats_dump()
            self.assertEqual(
                len(stats),
                num_sessions,
                "SFDP sessions have expired unexpectedly",
            )

            # Use ring buffer metadata to check how many entries were written
            metadata = ring_buffer._get_thread_metadata(0)
            curr_sequence = metadata["sequence"]
            new_entries = curr_sequence - prev_sequence

            # Consume all available entries from the ring buffer
            data = ring_buffer.consume_data(thread_index=0)

            # Ensure we read non-zero number of entries from ring buffer
            self.assertGreater(
                new_entries,
                0,
            )
            self.assertEqual(
                len(data),
                new_entries,
            )

            for entry_bytes in data:
                decoded = decode_entry(entry_bytes)
                all_exported_dports.append(decoded["dst_port"])

            prev_sequence = curr_sequence
            batch_count += 1

        # Verify that exactly three batches were needed
        self.assertEqual(
            batch_count,
            3,
            "Should have required three batches total to dump all sessions",
        )

        # Verify all sessions were exported across all batches
        for sess in sessions_info:
            self.assertIn(
                sess["dport"],
                all_exported_dports,
                f"Session with dport {sess['dport']} should have been exported",
            )

        self._cleanup_sfdp_session_stats(config)

    def test_session_stats_rtt_timestamps(self):
        """RTT measured with timestamps options when available"""

        sport = 17000
        dport = 18000

        config = self._configure_sfdp_session_stats(enable_bidirectional=True)

        ts_fwd = 1000
        ts_rev = 5000
        self.pg_send(
            self.pg0,
            self._make_fwd_pkt(
                sport,
                dport,
                "S",
                seq=1000,
                ack=0,
                options=[("Timestamp", (ts_fwd, 0)), ("MSS", 1460)],
            ),
        )
        self.pg_send(
            self.pg1,
            self._make_rev_pkt(
                sport,
                dport,
                "SA",
                seq=2000,
                ack=1001,
                options=[("Timestamp", (ts_rev, ts_fwd)), ("MSS", 1460)],
            ),
        )
        ts_fwd += 1
        ts_rev += 1
        self.virtual_sleep(0.5)
        self.pg_send(
            self.pg0,
            self._make_fwd_pkt(
                sport,
                dport,
                "A",
                seq=1001,
                ack=2001,
                options=[("Timestamp", (ts_fwd, ts_rev))],
            ),
        )
        s = self._get_single_session_stats()
        self.assertTrue(s.tcp_handshake_complete)
        self.assertGreater(s.syn_rtt, 0.0, "syn_rtt should be set after handshake")
        self.assertEqual(
            s.rtt_mean_fwd, 0.0, "data RTT should not be set before any data exchange"
        )
        self.assertTrue(
            s.tcp_ts_negotiated, "Timestamps should be negotiated in both directions"
        )

        # First data exchange - TS echo triggers RTT sample
        ts_fwd += 1
        self.virtual_sleep(0.01)
        self.pg_send(
            self.pg0,
            self._make_fwd_pkt(
                sport,
                dport,
                "PA",
                seq=1001,
                ack=2001,
                payload=b"\xaa" * 100,
                options=[("Timestamp", (ts_fwd, ts_rev))],
            ),
        )
        ts_rev += 1
        self.virtual_sleep(0.01)
        self.pg_send(
            self.pg1,
            self._make_rev_pkt(
                sport,
                dport,
                "A",
                seq=2001,
                ack=1101,
                options=[("Timestamp", (ts_rev, ts_fwd))],
            ),
        )

        s = self._get_single_session_stats()
        self.assertGreater(
            s.rtt_mean_fwd, 0.0, "TS-based RTT sample should have been taken"
        )
        self.assertGreater(s.rtt_min_fwd, 0.0)
        self.assertLessEqual(s.rtt_min_fwd, s.rtt_mean_fwd)
        self.assertGreaterEqual(s.rtt_max_fwd, s.rtt_mean_fwd)
        rtt_max_after_first = s.rtt_max_fwd

        # Second exchange with longer delay - max should update
        ts_fwd += 1
        self.virtual_sleep(0.05)
        self.pg_send(
            self.pg0,
            self._make_fwd_pkt(
                sport,
                dport,
                "PA",
                seq=1101,
                ack=2001,
                payload=b"\xbb" * 100,
                options=[("Timestamp", (ts_fwd, ts_rev))],
            ),
        )
        ts_rev += 1
        self.virtual_sleep(0.05)
        self.pg_send(
            self.pg1,
            self._make_rev_pkt(
                sport,
                dport,
                "A",
                seq=2001,
                ack=1201,
                options=[("Timestamp", (ts_rev, ts_fwd))],
            ),
        )

        s = self._get_single_session_stats()
        self.assertGreater(
            s.rtt_max_fwd,
            rtt_max_after_first,
            "RTT max should increase after slower exchange",
        )
        self.assertGreaterEqual(s.rtt_max_fwd, s.rtt_mean_fwd)
        self.assertLessEqual(s.rtt_min_fwd, s.rtt_mean_fwd)

        self._cleanup_sfdp_session_stats(config)

    def test_session_stats_rtt_probe_fallback(self):
        """RTT measured with default probe-based approach"""

        sport = 19000
        dport = 20000

        config = self._configure_sfdp_session_stats(enable_bidirectional=True)

        self.pg_send(self.pg0, self._make_fwd_pkt(sport, dport, "S", seq=1000, ack=0))
        self.pg_send(
            self.pg1, self._make_rev_pkt(sport, dport, "SA", seq=2000, ack=1001)
        )
        self.virtual_sleep(0.1)
        self.pg_send(
            self.pg0, self._make_fwd_pkt(sport, dport, "A", seq=1001, ack=2001)
        )
        s = self._get_single_session_stats()
        self.assertTrue(s.tcp_handshake_complete)
        self.assertGreater(s.syn_rtt, 0.0, "syn_rtt should be set after handshake")
        self.assertEqual(
            s.rtt_mean_fwd, 0.0, "data RTT should not be set before any data exchange"
        )
        self.assertFalse(
            s.tcp_ts_negotiated, "Timestamps should not be negotiated without options"
        )

        self.virtual_sleep(0.01)
        self.pg_send(
            self.pg0,
            self._make_fwd_pkt(
                sport, dport, "PA", seq=1001, ack=2001, payload=b"\xaa" * 100
            ),
        )
        self.virtual_sleep(0.02)
        self.pg_send(
            self.pg1, self._make_rev_pkt(sport, dport, "A", seq=2001, ack=1101)
        )

        s = self._get_single_session_stats()
        self.assertGreater(
            s.rtt_mean_fwd, 0.0, "Probe-based RTT should fire without Timestamps"
        )
        self.assertGreater(s.rtt_min_fwd, 0.0)
        self.assertGreaterEqual(s.rtt_max_fwd, s.rtt_min_fwd)

        # Retransmit - probe must NOT be zeroed, so the subsequent ACK still takes a sample
        self.pg_send(
            self.pg0,
            self._make_fwd_pkt(
                sport, dport, "PA", seq=1101, ack=2001, payload=b"\xbb" * 100
            ),
        )
        self.pg_send(
            self.pg0,
            self._make_fwd_pkt(
                sport, dport, "PA", seq=1001, ack=2001, payload=b"\xaa" * 100
            ),
        )
        self.virtual_sleep(0.02)
        self.pg_send(
            self.pg1, self._make_rev_pkt(sport, dport, "A", seq=2001, ack=1201)
        )

        s = self._get_single_session_stats()
        self.assertGreaterEqual(
            s.tcp_retransmissions_fwd, 1, "Retransmission counter should increment"
        )
        self.assertGreater(
            s.rtt_mean_fwd, 0.0, "RTT mean must remain valid after a retransmit"
        )

        self._cleanup_sfdp_session_stats(config)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
