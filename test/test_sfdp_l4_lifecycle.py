#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2026 Cisco Systems, Inc.

import unittest
from asfframework import VppTestRunner
from config import config
from vpp_papi import VppEnum
from test_sfdp import BaseSfdpTest


@unittest.skipIf(
    "sfdp_services" in config.excluded_plugins,
    "SFDP_Services plugin is required to run SFDP tests",
)
class TestSfdpL4LifecycleBase(BaseSfdpTest):
    is_ip6 = False

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        try:
            cls.create_pg_interfaces(range(2))
            for i in cls.pg_interfaces:
                i.config_ip4()
                i.config_ip6()
                i.resolve_arp()
                i.resolve_ndp()
                i.admin_up()
        except Exception:
            super().tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        for i in cls.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.admin_down()
        super().tearDownClass()

    def setUp(self):
        super().setUp()

        # Initialize tenant
        self.vapi.sfdp_tenant_add_del(tenant_id=1, context_id=1, is_del=False)

        # sfdp setup with l4-lifecycle enabled
        # for either ip4/ip6, with tenant 1
        lookup = "ip6-lookup" if self.is_ip6 else "ip4-lookup"
        self.vapi.sfdp_set_services(
            tenant_id=1,
            dir=VppEnum.vl_api_sfdp_session_direction_t.SFDP_API_FORWARD,
            n_services=2,
            services=[{"data": "sfdp-l4-lifecycle"}, {"data": lookup}],
        )
        self.vapi.sfdp_set_services(
            tenant_id=1,
            dir=VppEnum.vl_api_sfdp_session_direction_t.SFDP_API_REVERSE,
            n_services=2,
            services=[{"data": "sfdp-l4-lifecycle"}, {"data": lookup}],
        )

        # Configure all timeout to a default 10s value
        # This exceeds default timeout value set in wait_no_sessions (5s)
        # which is used to verify that sessions have been killed/reaped
        # outside of the expected timeout process.
        self.set_timeout("embryonic", 10)  # SFDP_TIMEOUT_EMBRYONIC       = 10s
        self.set_timeout("established", 10)  # SFDP_TIMEOUT_ESTABLISHED     = 10s
        self.set_timeout("tcp-established", 10)  # SFDP_TIMEOUT_TCP_ESTABLISHED = 10s
        self.vapi.cli("set sfdp tcp-check time-wait disable")

        # Enable sfdp on pg0/pg1 interfaces
        self.vapi.sfdp_interface_input_set(
            sw_if_index=self.pg0.sw_if_index,
            tenant_id=1,
            is_ip6=self.is_ip6,
            is_disable=False,
        )
        self.vapi.sfdp_interface_input_set(
            sw_if_index=self.pg1.sw_if_index,
            tenant_id=1,
            is_ip6=self.is_ip6,
            is_disable=False,
        )

    def tearDown(self):
        # Cleanup existing sessions
        self.vapi.sfdp_kill_session(is_all=True)
        self.wait_no_sessions()

        # Disable sfdp on pg0/pg1 interfaces
        self.vapi.sfdp_interface_input_set(
            sw_if_index=self.pg0.sw_if_index,
            tenant_id=1,
            is_ip6=self.is_ip6,
            is_disable=True,
        )

        self.vapi.sfdp_interface_input_set(
            sw_if_index=self.pg1.sw_if_index,
            tenant_id=1,
            is_ip6=self.is_ip6,
            is_disable=True,
        )

        # Cleanup tenant
        self.vapi.sfdp_tenant_add_del(tenant_id=1, is_del=True)
        super().tearDown()

    def _tcp_establish(self, sport, is_ip6=None):
        if is_ip6 is None:
            is_ip6 = self.is_ip6
        if is_ip6:
            tcp_packet_fn = self.create_tcp6_packet
            src_ip, dst_ip = self.pg0.remote_ip6, self.pg1.remote_ip6
            rev_src_ip, rev_dst_ip = self.pg1.remote_ip6, self.pg0.remote_ip6
        else:
            tcp_packet_fn = self.create_tcp_packet
            src_ip, dst_ip = self.pg0.remote_ip4, self.pg1.remote_ip4
            rev_src_ip, rev_dst_ip = self.pg1.remote_ip4, self.pg0.remote_ip4

        # SYN: session should be in FSOL
        self.send_and_expect(
            self.pg0,
            tcp_packet_fn(
                self.pg0.remote_mac,
                self.pg0.local_mac,
                src_ip,
                dst_ip,
                sport=sport,
                dport=80,
                flags="S",
                seq=1000,
            ),
            self.pg1,
        )
        session_type = (
            VppEnum.vl_api_sfdp_session_type_t.SFDP_API_SESSION_TYPE_IP6
            if is_ip6
            else VppEnum.vl_api_sfdp_session_type_t.SFDP_API_SESSION_TYPE_IP4
        )
        sessions = self.sessions()
        self.assertEqual(len(sessions), 1, "Expected exactly one session")
        self.verify_basic_session_state(
            sessions[0],
            6,
            VppEnum.vl_api_sfdp_session_state_t.SFDP_API_SESSION_STATE_FSOL,
            session_type,
        )

        # SYN-ACK: session should still be in FSOL
        self.send_and_expect(
            self.pg1,
            tcp_packet_fn(
                self.pg1.remote_mac,
                self.pg1.local_mac,
                rev_src_ip,
                rev_dst_ip,
                sport=80,
                dport=sport,
                flags="SA",
                seq=2000,
                ack=1001,
            ),
            self.pg0,
        )
        sessions = self.sessions()
        self.assertEqual(len(sessions), 1, "Expected exactly one session")
        self.verify_basic_session_state(
            sessions[0],
            6,
            VppEnum.vl_api_sfdp_session_state_t.SFDP_API_SESSION_STATE_FSOL,
            session_type,
        )

        # ACK: session should be ESTABLISHED
        self.send_and_expect(
            self.pg0,
            tcp_packet_fn(
                self.pg0.remote_mac,
                self.pg0.local_mac,
                src_ip,
                dst_ip,
                sport=sport,
                dport=80,
                flags="A",
                seq=1001,
                ack=2001,
            ),
            self.pg1,
        )
        sessions = self.sessions()
        self.assertEqual(len(sessions), 1, "Expected exactly one session")
        self.verify_basic_session_state(
            sessions[0],
            6,
            VppEnum.vl_api_sfdp_session_state_t.SFDP_API_SESSION_STATE_ESTABLISHED,
            session_type,
        )

    def _send_tcp(self, from_initiator, sport, flags, seq, is_ip6, ack=0):
        src_if, dst_if = (
            (self.pg0, self.pg1) if from_initiator else (self.pg1, self.pg0)
        )
        if is_ip6:
            packet_fn = self.create_tcp6_packet
            src_ip, dst_ip = src_if.remote_ip6, dst_if.remote_ip6
        else:
            packet_fn = self.create_tcp_packet
            src_ip, dst_ip = src_if.remote_ip4, dst_if.remote_ip4

        self.send_and_expect(
            src_if,
            packet_fn(
                src_if.remote_mac,
                src_if.local_mac,
                src_ip,
                dst_ip,
                sport=sport if from_initiator else 80,
                dport=80 if from_initiator else sport,
                flags=flags,
                seq=seq,
                ack=ack,
                payload=b"",
            ),
            dst_if,
        )

    def _test_tcp_time_wait_supersession(self, sport, is_ip6):
        self.vapi.cli("set sfdp tcp-check time-wait enable")
        self._tcp_establish(sport=sport)
        self._send_tcp(True, sport, "FA", seq=1001, is_ip6=is_ip6, ack=2001)
        self._send_tcp(False, sport, "FA", seq=2001, is_ip6=is_ip6, ack=1002)
        self._send_tcp(True, sport, "A", seq=1002, is_ip6=is_ip6, ack=2002)

        sessions = self.sessions()
        self.assertEqual(len(sessions), 1)
        old_session_index = sessions[0].session_idx
        self.assertEqual(
            sessions[0].state,
            VppEnum.vl_api_sfdp_session_state_t.SFDP_API_SESSION_STATE_TIME_WAIT,
        )

        if is_ip6:
            packet_fn = self.create_tcp6_packet
            src_ip, dst_ip = self.pg0.remote_ip6, self.pg1.remote_ip6
        else:
            packet_fn = self.create_tcp_packet
            src_ip, dst_ip = self.pg0.remote_ip4, self.pg1.remote_ip4

        # Both packets enter tcp-check with the old flow index. The SYN
        # supersedes it; the following ACK must refresh through the bihash.
        packets = [
            packet_fn(
                self.pg0.remote_mac,
                self.pg0.local_mac,
                src_ip,
                dst_ip,
                sport=sport,
                dport=80,
                flags="S",
                seq=3000,
                payload=b"",
            ),
            packet_fn(
                self.pg0.remote_mac,
                self.pg0.local_mac,
                src_ip,
                dst_ip,
                sport=sport,
                dport=80,
                flags="A",
                seq=3001,
                payload=b"",
            ),
        ]
        self.send_and_expect(self.pg0, packets, self.pg1)

        fresh_session = None
        timeout = 5.0
        tick = 0.02
        for _ in range(int(timeout / tick) + 1):
            sessions = self.sessions()
            if len(sessions) == 1 and sessions[0].session_idx != old_session_index:
                fresh_session = sessions[0]
                break
            self.virtual_sleep(0.02)

        self.assertIsNotNone(
            fresh_session,
            "Old TIME_WAIT session was not replaced by one fresh session",
        )
        self.assertEqual(
            fresh_session.state,
            VppEnum.vl_api_sfdp_session_state_t.SFDP_API_SESSION_STATE_FSOL,
        )

        self._send_tcp(False, sport, "SA", seq=4000, is_ip6=is_ip6, ack=3001)
        self._send_tcp(True, sport, "A", seq=3001, is_ip6=is_ip6, ack=4001)

        sessions = self.sessions()
        self.assertEqual(len(sessions), 1)
        self.assertEqual(sessions[0].session_idx, fresh_session.session_idx)
        self.assertEqual(
            sessions[0].state,
            VppEnum.vl_api_sfdp_session_state_t.SFDP_API_SESSION_STATE_ESTABLISHED,
        )


@unittest.skipIf(
    "sfdp_services" in config.excluded_plugins,
    "SFDP_Services plugin is required to run SFDP tests",
)
class TestSfdpL4LifecycleIp4(TestSfdpL4LifecycleBase):
    """SFDP L4 Lifecycle - IPv4 (UDP/TCP)"""

    is_ip6 = False

    def test_udp_states(self):
        """UDP - Test UDP lifecycle states and timeout"""

        # Session A - Verify UDP FSOL timeout works
        self.send_and_expect(
            self.pg0,
            self.create_udp_packet(
                self.pg0.remote_mac,
                self.pg0.local_mac,
                self.pg0.remote_ip4,
                self.pg1.remote_ip4,
                sport=10002,
                dport=53,
            ),
            self.pg1,
        )
        sessions = self.sessions()
        self.assertEqual(len(sessions), 1, "Expected exactly one session")
        self.verify_basic_session_state(
            sessions[0],
            17,
            VppEnum.vl_api_sfdp_session_state_t.SFDP_API_SESSION_STATE_FSOL,
            VppEnum.vl_api_sfdp_session_type_t.SFDP_API_SESSION_TYPE_IP4,
        )

        # Verify Session A reaped after FSOL timeout
        self.virtual_sleep(11)  # embryonic timeout = 10s
        self.wait_no_sessions()

        # Session B - Verify UDP ESTABLISHED states and timeout work
        # First fwd packet -> FSOL
        self.send_and_expect(
            self.pg0,
            self.create_udp_packet(
                self.pg0.remote_mac,
                self.pg0.local_mac,
                self.pg0.remote_ip4,
                self.pg1.remote_ip4,
                sport=10000,
                dport=53,
            ),
            self.pg1,
        )
        sessions = self.sessions()
        self.assertEqual(len(sessions), 1, "Expected exactly one session")
        self.verify_basic_session_state(
            sessions[0],
            17,
            VppEnum.vl_api_sfdp_session_state_t.SFDP_API_SESSION_STATE_FSOL,
            VppEnum.vl_api_sfdp_session_type_t.SFDP_API_SESSION_TYPE_IP4,
        )

        # First rev packet -> ESTABLISHED
        self.send_and_expect(
            self.pg1,
            self.create_udp_packet(
                self.pg1.remote_mac,
                self.pg1.local_mac,
                self.pg1.remote_ip4,
                self.pg0.remote_ip4,
                sport=53,
                dport=10000,
            ),
            self.pg0,
        )
        sessions = self.sessions()
        self.assertEqual(len(sessions), 1, "Expected exactly one session")
        self.verify_basic_session_state(
            sessions[0],
            17,
            VppEnum.vl_api_sfdp_session_state_t.SFDP_API_SESSION_STATE_ESTABLISHED,
            VppEnum.vl_api_sfdp_session_type_t.SFDP_API_SESSION_TYPE_IP4,
        )

        # Verify Session B reaped after established timeout
        self.virtual_sleep(11)  # established timeout = 10s
        self.wait_no_sessions()

    def test_tcp_states(self):
        """TCP - Verify states and timeout"""
        # Session A in FSOL state
        self.send_and_expect(
            self.pg0,
            self.create_tcp_packet(
                self.pg0.remote_mac,
                self.pg0.local_mac,
                self.pg0.remote_ip4,
                self.pg1.remote_ip4,
                sport=10000,
                dport=80,
                flags="S",
                seq=1000,
            ),
            self.pg1,
        )
        # Verify Session A reaped after FSOL timeout
        self.virtual_sleep(11)  # embryonic timeout = 10s
        self.wait_no_sessions()

        # Session B established after 3-way handshake
        self._tcp_establish(sport=20000)
        # Session reaped after tcp_established timeout
        self.virtual_sleep(11)  # tcp_established timeout = 10s
        self.wait_no_sessions()

    def test_tcp_time_wait_mode_switch(self):
        """TCP - enable TIME_WAIT and expire retained sessions on disable"""
        self.vapi.cli("set sfdp tcp-check time-wait enable")
        self._tcp_establish(sport=20012)
        self._send_tcp(True, 20012, "FA", seq=1001, is_ip6=False, ack=2001)
        self._send_tcp(False, 20012, "FA", seq=2001, is_ip6=False, ack=1002)
        self._send_tcp(True, 20012, "A", seq=1002, is_ip6=False, ack=2002)

        sessions = self.sessions()
        self.assertEqual(len(sessions), 1)
        self.assertEqual(
            sessions[0].state,
            VppEnum.vl_api_sfdp_session_state_t.SFDP_API_SESSION_STATE_TIME_WAIT,
        )

        self.vapi.cli("set sfdp tcp-check time-wait disable")
        self.wait_no_sessions()

    def test_tcp_time_wait_supersession(self):
        self._test_tcp_time_wait_supersession(sport=20013, is_ip6=False)

    def test_tcp_rst_from_initiator(self):
        """TCP - RST from initiator on established session reaps session"""
        # TCP Session established with 3-way handshake
        self._tcp_establish(sport=20003)

        # Send RST from initiator, expect session to be reaped
        self.send_and_expect(
            self.pg0,
            self.create_tcp_packet(
                self.pg0.remote_mac,
                self.pg0.local_mac,
                self.pg0.remote_ip4,
                self.pg1.remote_ip4,
                sport=20003,
                dport=80,
                flags="R",
                seq=1001,
                payload=b"",
            ),
            self.pg1,
        )
        self.wait_no_sessions()

    def test_tcp_rst_from_responder(self):
        """TCP - RST from responder on established session reaps session"""
        # TCP Session established with 3-way handshake
        self._tcp_establish(sport=20004)

        # Send RST from responder, expect session to be reaped
        self.send_and_expect(
            self.pg1,
            self.create_tcp_packet(
                self.pg1.remote_mac,
                self.pg1.local_mac,
                self.pg1.remote_ip4,
                self.pg0.remote_ip4,
                sport=80,
                dport=20004,
                flags="R",
                seq=2001,
                ack=1001,
                payload=b"",
            ),
            self.pg0,
        )

        # Session should be reaped
        self.wait_no_sessions()

    def test_tcp_fin_ack_initiator_closes(self):
        """TCP - initiator initializes connection teardown with FIN"""

        # TCP Session established with 3-way handshake
        self._tcp_establish(sport=20005)

        # (1) Send initiator FIN+ACK
        # TCP state machine should have flag SEEN_FIN_INIT set
        self.send_and_expect(
            self.pg0,
            self.create_tcp_packet(
                self.pg0.remote_mac,
                self.pg0.local_mac,
                self.pg0.remote_ip4,
                self.pg1.remote_ip4,
                sport=20005,
                dport=80,
                flags="FA",
                seq=1001,
                ack=2001,
                payload=b"",
            ),
            self.pg1,
        )

        # (2) Send responder FIN+ACK
        # TCP state machine should have SEEN_FIN_RESP flag set
        self.send_and_expect(
            self.pg1,
            self.create_tcp_packet(
                self.pg1.remote_mac,
                self.pg1.local_mac,
                self.pg1.remote_ip4,
                self.pg0.remote_ip4,
                sport=80,
                dport=20005,
                flags="FA",
                seq=2001,
                ack=1002,
                payload=b"",
            ),
            self.pg0,
        )

        # (3) Send initiator ACK
        # TCP state machine should have SEEN_ACK_TO_FIN_INIT flag set
        # Since all FIN flags have been set, session is tagged for removal
        self.send_and_expect(
            self.pg0,
            self.create_tcp_packet(
                self.pg0.remote_mac,
                self.pg0.local_mac,
                self.pg0.remote_ip4,
                self.pg1.remote_ip4,
                sport=20005,
                dport=80,
                flags="A",
                seq=1002,
                ack=2002,
                payload=b"",
            ),
            self.pg1,
        )

        # Session should be expired during next execution of sfdp-expire
        self.wait_no_sessions()

    def test_tcp_fin_ack_responder_closes(self):
        """TCP - responder initializes connection teardown with FIN"""
        # TCP Session established with 3-way handshake
        self._tcp_establish(sport=20008)

        # (1) Send responder FIN+ACK
        # TCP state machine should have flag SEEN_FIN_RESP set
        self.send_and_expect(
            self.pg1,
            self.create_tcp_packet(
                self.pg1.remote_mac,
                self.pg1.local_mac,
                self.pg1.remote_ip4,
                self.pg0.remote_ip4,
                sport=80,
                dport=20008,
                flags="FA",
                seq=2001,
                ack=1001,
                payload=b"",
            ),
            self.pg0,
        )

        # (2) Send initiator FIN+ACK
        # TCP state machine should have SEEN_FIN_RESP flag set
        self.send_and_expect(
            self.pg0,
            self.create_tcp_packet(
                self.pg0.remote_mac,
                self.pg0.local_mac,
                self.pg0.remote_ip4,
                self.pg1.remote_ip4,
                sport=20008,
                dport=80,
                flags="FA",
                seq=1001,
                ack=2002,
                payload=b"",
            ),
            self.pg1,
        )

        # (3) Send responder ACK
        # TCP state machine should have SEEN_ACK_TO_FIN_INIT flag set
        # Since all FIN flags have been set, session is tagged for removal
        self.send_and_expect(
            self.pg1,
            self.create_tcp_packet(
                self.pg1.remote_mac,
                self.pg1.local_mac,
                self.pg1.remote_ip4,
                self.pg0.remote_ip4,
                sport=80,
                dport=20008,
                flags="A",
                seq=2002,
                ack=1002,
                payload=b"",
            ),
            self.pg0,
        )

        # Session should be expired during next execution of sfdp-expire
        self.wait_no_sessions()

    def test_tcp_fsol_non_syn_pkt_security(self):
        """TCP - verify session with first non-SYN pkt is set to state 'security'"""
        self.vapi.cli("set sfdp tcp-check fsol-non-syn security")
        # First non-SYN packet must be dropped
        self.send_and_assert_no_replies(
            self.pg0,
            self.create_tcp_packet(
                self.pg0.remote_mac,
                self.pg0.local_mac,
                self.pg0.remote_ip4,
                self.pg1.remote_ip4,
                sport=20011,
                dport=80,
                flags="A",
                seq=1000,
                ack=1,
            ),
        )
        # Session must still be present (blocked, not removed)
        self.assertEqual(len(self.sessions()), 1)

        # Subsequent packet is also dropped (session bitmaps locked to drop)
        self.send_and_assert_no_replies(
            self.pg0,
            self.create_tcp_packet(
                self.pg0.remote_mac,
                self.pg0.local_mac,
                self.pg0.remote_ip4,
                self.pg1.remote_ip4,
                sport=20011,
                dport=80,
                flags="S",
                seq=1000,
            ),
        )

        # Session should expire at security timeout (30s), well after initial embryonic timeout (10s)
        self.virtual_sleep(20)
        self.assertEqual(len(self.sessions()), 1)  # Session still present after 20s

        self.virtual_sleep(11)
        self.wait_no_sessions()  # Session must not be present after 30s

        # Cleanup
        self.vapi.cli("set sfdp tcp-check fsol-non-syn remove")

    def test_tcp_fsol_non_syn_pkt_remove(self):
        """TCP - verify session with first non-SYN pkt is tagged for removal (default)"""
        # Change default action if fsol is non-syn, to remove the session from
        # SFDP without dropping traffic
        # Create SFDP session by sending initial non-SYN packet
        self.send_and_expect(
            self.pg0,
            self.create_tcp_packet(
                self.pg0.remote_mac,
                self.pg0.local_mac,
                self.pg0.remote_ip4,
                self.pg1.remote_ip4,
                sport=20010,
                dport=80,
                flags="A",
                seq=1000,
                ack=1,
            ),
            self.pg1,
        )
        # Send SYN as second session packet
        self.send_and_expect(
            self.pg0,
            self.create_tcp_packet(
                self.pg0.remote_mac,
                self.pg0.local_mac,
                self.pg0.remote_ip4,
                self.pg1.remote_ip4,
                sport=20010,
                dport=80,
                flags="S",
                seq=1000,
            ),
            self.pg1,
        )

        # Session should be removed before initial embryonic timeout
        self.wait_no_sessions()

    def test_tcp_fin_with_payload_initiator_closes(self):
        """TCP - initiator FIN/ACK with payload"""

        # Check that we support use-cases where TCP FIN packet contains data payload
        # TCP Session established with 3-way handshake
        self._tcp_establish(sport=20009)

        # (1) Send initiator FIN+ACK
        # TCP state machine should have flag SEEN_FIN_INIT set
        # FIN carries 50 bytes of payload; the ACK must cover seq + 50 + 1
        fin_payload = b"\xab" * 50
        self.send_and_expect(
            self.pg0,
            self.create_tcp_packet(
                self.pg0.remote_mac,
                self.pg0.local_mac,
                self.pg0.remote_ip4,
                self.pg1.remote_ip4,
                sport=20009,
                dport=80,
                flags="FA",
                seq=1001,
                ack=2001,
                payload=fin_payload,
            ),
            self.pg1,
        )

        # (2) Send responder FIN+ACK
        # TCP state machine should have SEEN_FIN_RESP flag set
        self.send_and_expect(
            self.pg1,
            self.create_tcp_packet(
                self.pg1.remote_mac,
                self.pg1.local_mac,
                self.pg1.remote_ip4,
                self.pg0.remote_ip4,
                sport=80,
                dport=20009,
                flags="FA",
                seq=2001,
                ack=1052,
                payload=b"",
            ),
            self.pg0,
        )

        # (3) Send responder ACK
        # TCP state machine should have SEEN_ACK_TO_FIN_INIT flag set
        # Since all FIN flags have been set, session is tagged for removal
        self.send_and_expect(
            self.pg0,
            self.create_tcp_packet(
                self.pg0.remote_mac,
                self.pg0.local_mac,
                self.pg0.remote_ip4,
                self.pg1.remote_ip4,
                sport=20009,
                dport=80,
                flags="A",
                seq=1052,
                ack=2002,
                payload=b"",
            ),
            self.pg1,
        )

        # Session should be expired during next execution of sfdp-expire
        self.wait_no_sessions()


@unittest.skipIf(
    "sfdp_services" in config.excluded_plugins,
    "SFDP_Services plugin is required to run SFDP tests",
)
class TestSfdpL4LifecycleIp6(TestSfdpL4LifecycleBase):
    """SFDP L4 Lifecycle - IPv6 (UDP/TCP)"""

    is_ip6 = True

    def test_udp_states(self):
        """UDP - Verify states and timeout"""
        # Session A - Verify UDP FSOL timeout works
        self.send_and_expect(
            self.pg0,
            self.create_udp6_packet(
                self.pg0.remote_mac,
                self.pg0.local_mac,
                self.pg0.remote_ip6,
                self.pg1.remote_ip6,
                sport=10002,
                dport=53,
            ),
            self.pg1,
        )
        sessions = self.sessions()
        self.assertEqual(len(sessions), 1, "Expected exactly one session")
        self.verify_basic_session_state(
            sessions[0],
            17,
            VppEnum.vl_api_sfdp_session_state_t.SFDP_API_SESSION_STATE_FSOL,
            VppEnum.vl_api_sfdp_session_type_t.SFDP_API_SESSION_TYPE_IP6,
        )

        # Verify Session A reaped after FSOL timeout
        self.virtual_sleep(11)  # embryonic timeout = 10s
        self.wait_no_sessions()

        # Session B
        # First fwd packet -> FSOL
        self.send_and_expect(
            self.pg0,
            self.create_udp6_packet(
                self.pg0.remote_mac,
                self.pg0.local_mac,
                self.pg0.remote_ip6,
                self.pg1.remote_ip6,
                sport=30000,
                dport=53,
            ),
            self.pg1,
        )
        sessions = self.sessions()
        self.assertEqual(len(sessions), 1, "Expected exactly one session")
        self.verify_basic_session_state(
            sessions[0],
            17,
            VppEnum.vl_api_sfdp_session_state_t.SFDP_API_SESSION_STATE_FSOL,
            VppEnum.vl_api_sfdp_session_type_t.SFDP_API_SESSION_TYPE_IP6,
        )

        # First rev packet -> ESTABLISHED
        self.send_and_expect(
            self.pg1,
            self.create_udp6_packet(
                self.pg1.remote_mac,
                self.pg1.local_mac,
                self.pg1.remote_ip6,
                self.pg0.remote_ip6,
                sport=53,
                dport=30000,
            ),
            self.pg0,
        )
        sessions = self.sessions()
        self.assertEqual(len(sessions), 1, "Expected exactly one session")
        self.verify_basic_session_state(
            sessions[0],
            17,
            VppEnum.vl_api_sfdp_session_state_t.SFDP_API_SESSION_STATE_ESTABLISHED,
            VppEnum.vl_api_sfdp_session_type_t.SFDP_API_SESSION_TYPE_IP6,
        )

        # Established session reaped after timeout
        self.virtual_sleep(11)  # established timeout = 10s
        self.wait_no_sessions()

    def test_tcp_states(self):
        """TCP - Verify states and timeout"""
        # Session A in FSOL state
        self.send_and_expect(
            self.pg0,
            self.create_tcp6_packet(
                self.pg0.remote_mac,
                self.pg0.local_mac,
                self.pg0.remote_ip6,
                self.pg1.remote_ip6,
                sport=10000,
                dport=80,
                flags="S",
                seq=1000,
            ),
            self.pg1,
        )
        # Verify Session A reaped after FSOL timeout
        self.virtual_sleep(11)  # embryonic timeout = 10s
        self.wait_no_sessions()

        # Session B established after handshake
        self._tcp_establish(sport=30001)
        self.virtual_sleep(11)  # tcp_established timeout = 10s
        self.wait_no_sessions()

    def test_tcp_time_wait_supersession(self):
        self._test_tcp_time_wait_supersession(sport=30013, is_ip6=True)

    def test_tcp_rst_from_initiator(self):
        """TCP - RST from initiator on established session reaps session"""
        self._tcp_establish(sport=30003)

        # Send RST from initiator
        self.send_and_expect(
            self.pg0,
            self.create_tcp6_packet(
                self.pg0.remote_mac,
                self.pg0.local_mac,
                self.pg0.remote_ip6,
                self.pg1.remote_ip6,
                sport=30003,
                dport=80,
                flags="R",
                seq=1001,
                payload=b"",
            ),
            self.pg1,
        )
        self.wait_no_sessions()

    def test_tcp_rst_from_responder(self):
        """TCP - RST from responder on established session reaps session"""
        self._tcp_establish(sport=30004)

        # Send RST from responder
        self.send_and_expect(
            self.pg1,
            self.create_tcp6_packet(
                self.pg1.remote_mac,
                self.pg1.local_mac,
                self.pg1.remote_ip6,
                self.pg0.remote_ip6,
                sport=80,
                dport=30004,
                flags="R",
                seq=2001,
                ack=1001,
                payload=b"",
            ),
            self.pg0,
        )
        self.wait_no_sessions()

    def test_tcp_fin_ack_initiator_closes(self):
        """TCP - initiator initializes connection teardown with FIN"""
        self._tcp_establish(sport=30005)

        # (1) Send initiator FIN+ACK
        self.send_and_expect(
            self.pg0,
            self.create_tcp6_packet(
                self.pg0.remote_mac,
                self.pg0.local_mac,
                self.pg0.remote_ip6,
                self.pg1.remote_ip6,
                sport=30005,
                dport=80,
                flags="FA",
                seq=1001,
                ack=2001,
                payload=b"",
            ),
            self.pg1,
        )

        # (2) Send responder FIN+ACK
        self.send_and_expect(
            self.pg1,
            self.create_tcp6_packet(
                self.pg1.remote_mac,
                self.pg1.local_mac,
                self.pg1.remote_ip6,
                self.pg0.remote_ip6,
                sport=80,
                dport=30005,
                flags="FA",
                seq=2001,
                ack=1002,
                payload=b"",
            ),
            self.pg0,
        )

        # (3) Send initiator ACK - session tagged for removal
        self.send_and_expect(
            self.pg0,
            self.create_tcp6_packet(
                self.pg0.remote_mac,
                self.pg0.local_mac,
                self.pg0.remote_ip6,
                self.pg1.remote_ip6,
                sport=30005,
                dport=80,
                flags="A",
                seq=1002,
                ack=2002,
                payload=b"",
            ),
            self.pg1,
        )
        self.wait_no_sessions()

    def test_tcp_fin_ack_responder_closes(self):
        """TCP - responder initializes connection teardown with FIN"""
        self._tcp_establish(sport=30008)

        # (1) Send responder FIN+ACK
        self.send_and_expect(
            self.pg1,
            self.create_tcp6_packet(
                self.pg1.remote_mac,
                self.pg1.local_mac,
                self.pg1.remote_ip6,
                self.pg0.remote_ip6,
                sport=80,
                dport=30008,
                flags="FA",
                seq=2001,
                ack=1001,
                payload=b"",
            ),
            self.pg0,
        )

        # (2) Send initiator FIN+ACK
        self.send_and_expect(
            self.pg0,
            self.create_tcp6_packet(
                self.pg0.remote_mac,
                self.pg0.local_mac,
                self.pg0.remote_ip6,
                self.pg1.remote_ip6,
                sport=30008,
                dport=80,
                flags="FA",
                seq=1001,
                ack=2002,
                payload=b"",
            ),
            self.pg1,
        )

        # (3) Send responder ACK - session tagged for removal
        self.send_and_expect(
            self.pg1,
            self.create_tcp6_packet(
                self.pg1.remote_mac,
                self.pg1.local_mac,
                self.pg1.remote_ip6,
                self.pg0.remote_ip6,
                sport=80,
                dport=30008,
                flags="A",
                seq=2002,
                ack=1002,
                payload=b"",
            ),
            self.pg0,
        )
        self.wait_no_sessions()

    def test_tcp_fsol_non_syn_pkt_security(self):
        """TCP - verify session with first non-SYN pkt is set to state 'security'"""
        # First non-SYN packet must be dropped
        self.vapi.cli("set sfdp tcp-check fsol-non-syn security")
        self.send_and_assert_no_replies(
            self.pg0,
            self.create_tcp6_packet(
                self.pg0.remote_mac,
                self.pg0.local_mac,
                self.pg0.remote_ip6,
                self.pg1.remote_ip6,
                sport=30011,
                dport=80,
                flags="A",
                seq=1000,
                ack=1,
            ),
        )
        # Session must still be present (blocked, not removed)
        self.assertEqual(len(self.sessions()), 1)

        # Subsequent packet is also dropped (session bitmaps locked to drop)
        self.send_and_assert_no_replies(
            self.pg0,
            self.create_tcp6_packet(
                self.pg0.remote_mac,
                self.pg0.local_mac,
                self.pg0.remote_ip6,
                self.pg1.remote_ip6,
                sport=30011,
                dport=80,
                flags="S",
                seq=1000,
            ),
        )

        # Session should expire at security timeout (30s), well after initial embryonic timeout (10s)
        self.virtual_sleep(20)
        self.assertEqual(len(self.sessions()), 1)  # Session still present after 20s

        self.virtual_sleep(11)
        self.wait_no_sessions()  # Session must not be present after 30s

        # Cleanup
        self.vapi.cli("set sfdp tcp-check fsol-non-syn remove")

    def test_tcp_fsol_non_syn_pkt_remove(self):
        """TCP - verify session with first non-SYN pkt is tagged for removal (default)"""
        # Change default action if fsol is non-syn, to remove the session from
        # SFDP without dropping traffic
        # Create SFDP session by sending initial non-SYN packet
        self.send_and_expect(
            self.pg0,
            self.create_tcp6_packet(
                self.pg0.remote_mac,
                self.pg0.local_mac,
                self.pg0.remote_ip6,
                self.pg1.remote_ip6,
                sport=30010,
                dport=80,
                flags="A",
                seq=1000,
                ack=1,
            ),
            self.pg1,
        )
        # Send SYN as second session packet
        self.send_and_expect(
            self.pg0,
            self.create_tcp6_packet(
                self.pg0.remote_mac,
                self.pg0.local_mac,
                self.pg0.remote_ip6,
                self.pg1.remote_ip6,
                sport=30010,
                dport=80,
                flags="S",
                seq=1000,
            ),
            self.pg1,
        )
        # Session should be removed before initial embryonic timeout
        self.wait_no_sessions()


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
