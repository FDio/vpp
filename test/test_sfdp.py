#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2025 Cisco Systems, Inc.
import re
import unittest
from asfframework import VppTestRunner
from framework import VppTestCase
from config import config
from vpp_papi import VppEnum

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest


class BaseSfdpTest(VppTestCase):
    def create_tcp_packet(
        self,
        src_mac,
        dst_mac,
        src_ip,
        dst_ip,
        sport,
        dport,
        flags="S",
        ttl=64,
        seq=0,
        ack=0,
        payload=b"\xa5" * 100,
    ):
        return (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip, ttl=ttl)
            / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
            / Raw(payload)
        )

    def create_udp_packet(self, src_mac, dst_mac, src_ip, dst_ip, sport, dport, ttl=64):
        return (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip, ttl=ttl)
            / UDP(sport=sport, dport=dport)
            / Raw(b"\xa5" * 100)
        )

    def create_tcp6_packet(
        self,
        src_mac,
        dst_mac,
        src_ip,
        dst_ip,
        sport,
        dport,
        flags="S",
        hlim=64,
        seq=0,
        ack=0,
        payload=b"\xa5" * 100,
    ):
        return (
            Ether(src=src_mac, dst=dst_mac)
            / IPv6(src=src_ip, dst=dst_ip, hlim=hlim)
            / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
            / Raw(payload)
        )

    def create_udp6_packet(
        self, src_mac, dst_mac, src_ip, dst_ip, sport, dport, hlim=64
    ):
        return (
            Ether(src=src_mac, dst=dst_mac)
            / IPv6(src=src_ip, dst=dst_ip, hlim=hlim)
            / UDP(sport=sport, dport=dport)
            / Raw(b"\xa5" * 100)
        )

    def udp(self, dport, sport=12345):
        return self.create_udp_packet(
            self.pg0.remote_mac,
            self.pg0.local_mac,
            self.pg0.remote_ip4,
            self.pg1.remote_ip4,
            sport=sport,
            dport=dport,
        )

    def udp6(self, dport, sport=12345):
        return self.create_udp6_packet(
            self.pg0.remote_mac,
            self.pg0.local_mac,
            self.pg0.remote_ip6,
            self.pg1.remote_ip6,
            sport=sport,
            dport=dport,
        )

    def get_timeout_index(self, timeout_name):

        # Get timeout entries matching provided timeout_name
        timeouts = [
            timeout
            for timeout in self.vapi.sfdp_timeout_dump()
            if timeout.name == timeout_name
        ]

        # Verify there is only one entry matching this timeout_name
        self.assertEqual(
            1, len(timeouts), f"Expected exactly one timeout named {timeout_name}"
        )
        return timeouts[0].index

    def set_timeout(self, timeout_name, value):
        self.vapi.sfdp_set_timeout(
            tenant_id=1,
            timeout_id=self.get_timeout_index(timeout_name),
            timeout_value=value,
        )

    def sessions(self):
        return list(self.vapi.sfdp_session_dump())

    def wait_no_sessions(self, timeout=5.0, tick=0.02):
        steps = int(timeout / tick) + 1
        for _ in range(steps):
            if len(self.sessions()) == 0:
                return
            self.virtual_sleep(tick)
        remaining = self.sessions()
        self.assertEqual(
            len(remaining),
            0,
            f"Sessions still present after {timeout}s: "
            f"{[(s.session_idx, s.state) for s in remaining]}",
        )

    def verify_basic_session_state(
        self,
        sess,
        expected_protocol,
        expected_state,
        expected_session_type,
        expected_src_ip=None,
        expected_dst_ip=None,
    ):
        self.assertEqual(
            sess.protocol, expected_protocol, f"Protocol should be {expected_protocol}"
        )
        self.assertEqual(sess.state, expected_state, "Unexpected session state")
        self.assertEqual(
            sess.session_type, expected_session_type, "Unexpected session type"
        )

        if expected_src_ip and expected_dst_ip:
            detail_output = self.vapi.cli(
                f"show sfdp session-detail {hex(sess.session_id)}"
            )
            self.assertIn(
                expected_src_ip,
                detail_output,
                "cli output does not show expected source IP",
            )
            self.assertIn(
                expected_dst_ip,
                detail_output,
                "cli output does not show expected destination IP",
            )

    def _configure_sfdp(self, enable_ip4=True, enable_ip6=False):
        """Base SFDP Configuration"""
        self.assertTrue(
            enable_ip4 or enable_ip6,
            "SFDP must be configured with either ip4/ip6 enabled",
        )

        # Add tenant with ID 1 with ip4 support
        self.tenant_id_ip4 = 1
        reply = self.vapi.sfdp_tenant_add_del(
            tenant_id=self.tenant_id_ip4,
            context_id=1,
            is_del=False,
        )
        self.assertEqual(reply.retval, 0)

        # Add tenant with ID 2 with ip6 support
        self.tenant_id_ip6 = 2
        reply = self.vapi.sfdp_tenant_add_del(
            tenant_id=self.tenant_id_ip6,
            context_id=1,
            is_del=False,
        )
        self.assertEqual(reply.retval, 0)

        if enable_ip4:
            # Configure ip4 services - minimal chain for session tracking
            service_chain = [{"data": "sfdp-l4-lifecycle"}, {"data": "ip4-lookup"}]
            reply = self.vapi.sfdp_set_services(
                tenant_id=self.tenant_id_ip4,
                dir=VppEnum.vl_api_sfdp_session_direction_t.SFDP_API_FORWARD,
                n_services=len(service_chain),
                services=service_chain,
            )
            self.assertEqual(reply.retval, 0)

            reply = self.vapi.sfdp_set_services(
                tenant_id=self.tenant_id_ip4,
                dir=VppEnum.vl_api_sfdp_session_direction_t.SFDP_API_REVERSE,
                n_services=len(service_chain),
                services=service_chain,
            )
            self.assertEqual(reply.retval, 0)

            reply = self.vapi.sfdp_interface_input_set(
                sw_if_index=self.pg0.sw_if_index,
                tenant_id=1,
                is_disable=False,
            )
            self.assertEqual(reply.retval, 0)

            # Verify that SFDP IPv4 feature arc is enabled
            reply = self.vapi.feature_is_enabled(
                arc_name="ip4-unicast",
                feature_name="sfdp-interface-input-ip4",
                sw_if_index=self.pg0.sw_if_index,
            )
            self.assertTrue(reply.is_enabled, "sfdp ip4 feature arc should be enabled")

        if enable_ip6:
            # Configure ip6 services - minimal chain for session tracking
            service_chain = [{"data": "sfdp-l4-lifecycle"}, {"data": "ip6-lookup"}]
            reply = self.vapi.sfdp_set_services(
                tenant_id=self.tenant_id_ip6,
                dir=VppEnum.vl_api_sfdp_session_direction_t.SFDP_API_FORWARD,
                n_services=len(service_chain),
                services=service_chain,
            )
            self.assertEqual(reply.retval, 0)

            reply = self.vapi.sfdp_set_services(
                tenant_id=self.tenant_id_ip6,
                dir=VppEnum.vl_api_sfdp_session_direction_t.SFDP_API_REVERSE,
                n_services=len(service_chain),
                services=service_chain,
            )
            self.assertEqual(reply.retval, 0)
            reply = self.vapi.sfdp_interface_input_set(
                sw_if_index=self.pg0.sw_if_index,
                tenant_id=self.tenant_id_ip6,
                is_disable=False,
                is_ip6=True,
            )
            self.assertEqual(reply.retval, 0)

            # Verify that SFDP IPv6 feature arc is enabled
            reply = self.vapi.feature_is_enabled(
                arc_name="ip6-unicast",
                feature_name="sfdp-interface-input-ip6",
                sw_if_index=self.pg0.sw_if_index,
            )
            self.assertTrue(reply.is_enabled, "sfdp ip6 feature arc should be enabled")

    def _cleanup_sfdp(self, disable_ip4=True, disable_ip6=False):
        """Cleanup SFDP configuration"""
        self.assertTrue(
            disable_ip4 or disable_ip6, "SFDP must be disabled for either ip4/ip6"
        )
        # Cleanup existing sessions
        self.vapi.sfdp_kill_session(is_all=True)
        self.wait_no_sessions()

        # Disable SFDP on interfaces
        if disable_ip4:
            self.vapi.sfdp_interface_input_set(
                sw_if_index=self.pg0.sw_if_index,
                tenant_id=self.tenant_id_ip4,
                is_disable=True,
            )
            # Verify that IPv4 SFDP feature arc is disabled
            reply = self.vapi.feature_is_enabled(
                arc_name="ip4-unicast",
                feature_name="sfdp-interface-input-ip4",
                sw_if_index=self.pg0.sw_if_index,
            )
            self.assertFalse(
                reply.is_enabled,
                "sfdp ip4 feature arc should be disabled after cleanup",
            )

        if disable_ip6:
            self.vapi.sfdp_interface_input_set(
                sw_if_index=self.pg0.sw_if_index,
                tenant_id=self.tenant_id_ip6,
                is_disable=True,
                is_ip6=True,
            )
            # Verify that IPv6 SFDP feature arc is disabled
            reply = self.vapi.feature_is_enabled(
                arc_name="ip6-unicast",
                feature_name="sfdp-interface-input-ip6",
                sw_if_index=self.pg0.sw_if_index,
            )
            self.assertFalse(
                reply.is_enabled,
                "sfdp ip6 feature arc should be disabled after cleanup",
            )

        # Delete ip4/ip6 tenant
        self.vapi.sfdp_tenant_add_del(
            tenant_id=self.tenant_id_ip4,
            is_del=True,
        )
        self.vapi.sfdp_tenant_add_del(
            tenant_id=self.tenant_id_ip6,
            is_del=True,
        )


@unittest.skipIf(
    "sfdp_services" in config.excluded_plugins,
    "SFDP_Services plugin is required to run SFDP tests",
)
class TestSfdp(BaseSfdpTest):
    """SFDP Infrastructure tests"""

    @classmethod
    def setUpClass(cls):
        super(TestSfdp, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(4))
            for i in cls.pg_interfaces:
                i.config_ip4()
                i.config_ip6()
                i.resolve_arp()
                i.resolve_ndp()
                i.admin_up()
        except Exception:
            super(TestSfdp, cls).tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        for i in cls.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.admin_down()
        super(TestSfdp, cls).tearDownClass()

    def test_sfdp_api_configuration(self):
        """Test SFDP configuration"""
        # Dump services to build index mapping and verify scope
        service_index_by_name = {}
        services = self.vapi.sfdp_service_dump()
        for svc in services:
            service_index_by_name[svc.node_name] = svc.index
            # Verify all services have 'default' scope
            self.assertEqual(
                svc.scope, "default", "Service does not have 'default' scope"
            )

        # Verify default timeouts are registered with their initial values
        expected_timeouts = {
            "embryonic": 5,
            "established": 120,
            "tcp-established": 3600,
            "security": 30,
        }
        timeouts = {timeout.name: timeout for timeout in self.vapi.sfdp_timeout_dump()}
        for name, timeout_value in expected_timeouts.items():
            self.assertIn(name, timeouts)
            self.assertEqual(timeouts[name].timeout_value, timeout_value)

        # Test tenant add
        reply = self.vapi.sfdp_tenant_add_del(
            tenant_id=100,
            context_id=100,
            is_del=False,
        )
        self.assertEqual(reply.retval, 0)

        # Verify tenant exists via dump
        tenants = self.vapi.sfdp_tenant_dump()
        tenant_found = False
        for t in tenants:
            if t.context_id == 100:
                tenant_found = True

        self.assertEqual(len(tenants), 1, "There should only be one tenant")
        self.assertTrue(tenant_found, "Tenant with id 100 should exist")

        # Test service configuration for forward direction
        forward_services = ["sfdp-l4-lifecycle", "sfdp-drop"]
        reply = self.vapi.sfdp_set_services(
            tenant_id=100,
            dir=VppEnum.vl_api_sfdp_session_direction_t.SFDP_API_FORWARD,
            n_services=len(forward_services),
            services=[{"data": s} for s in forward_services],
        )
        self.assertEqual(reply.retval, 0)

        # Test service configuration for reverse direction
        reverse_services = ["sfdp-drop"]
        reply = self.vapi.sfdp_set_services(
            tenant_id=100,
            dir=VppEnum.vl_api_sfdp_session_direction_t.SFDP_API_REVERSE,
            n_services=len(reverse_services),
            services=[{"data": s} for s in reverse_services],
        )
        self.assertEqual(reply.retval, 0)

        # Calculate expected bitmaps based on service indices
        expected_forward_bitmap = 0
        for service_name in forward_services:
            idx = service_index_by_name[service_name]
            expected_forward_bitmap |= 1 << idx

        expected_reverse_bitmap = 0
        for service_name in reverse_services:
            idx = service_index_by_name[service_name]
            expected_reverse_bitmap |= 1 << idx

        # Verify services are set correctly via tenant dump
        tenants = self.vapi.sfdp_tenant_dump()
        tenant = tenants[0]
        self.assertEqual(
            tenant.forward_bitmap, expected_forward_bitmap, "Forward bitmap mismatch"
        )
        self.assertEqual(
            tenant.reverse_bitmap, expected_reverse_bitmap, "Reverse bitmap mismatch"
        )

        # Test timeout configuration
        reply = self.vapi.sfdp_set_timeout(
            tenant_id=100,
            timeout_id=self.get_timeout_index("embryonic"),
            timeout_value=31,
        )
        self.assertEqual(reply.retval, 0)

        reply = self.vapi.sfdp_set_timeout(
            tenant_id=100,
            timeout_id=self.get_timeout_index("established"),
            timeout_value=3601,
        )
        self.assertEqual(reply.retval, 0)

        # Get timeouts values configured for this specific tenant
        current_timeouts = {
            timeout.name: timeout
            for timeout in self.vapi.sfdp_timeout_dump(tenant_id=100)
        }
        self.assertEqual(current_timeouts["embryonic"].timeout_value, 31)
        self.assertEqual(current_timeouts["established"].timeout_value, 3601)

        # Verify timeouts are set correctly via tenant dump
        tenants = self.vapi.sfdp_tenant_dump()
        tenant = tenants[0]
        self.assertEqual(
            tenant.timeout[self.get_timeout_index("embryonic")],
            31,
            "embryonic timeout should be 31 seconds",
        )
        self.assertEqual(
            tenant.timeout[self.get_timeout_index("established")],
            3601,
            "established timeout should be 3601 seconds",
        )

        # Negative test - invalid timeout ID should return an API error
        with self.vapi.assert_negative_api_retval():
            rv = self.vapi.sfdp_set_timeout(
                tenant_id=100,
                timeout_id=0xFF,
                timeout_value=30,
            )
        self.assertEqual(rv.retval, -1)

        # Test tenant delete
        reply = self.vapi.sfdp_tenant_add_del(
            tenant_id=100,
            is_del=True,
        )
        self.assertEqual(reply.retval, 0)

        # Verify tenant is gone
        tenants = self.vapi.sfdp_tenant_dump()
        self.assertEqual(len(tenants), 0, "Tenant should not exist after delete")

    def test_sfdp_cli_configuration(self):
        """Test SFDP configuration through CLI"""
        # Dump services to build index mapping
        services = self.vapi.sfdp_service_dump()
        service_index_by_name = {}
        for svc in services:
            service_index_by_name[svc.node_name] = svc.index

        # Test tenant add via CLI
        self.vapi.cli("sfdp tenant add 200 context 200")

        # Verify tenant exists via dump
        tenants = self.vapi.sfdp_tenant_dump()
        tenant_found = False
        for t in tenants:
            if t.context_id == 200:
                tenant_found = True

        self.assertTrue(tenant_found, "Tenant with id 200 should exist")
        self.assertEqual(len(tenants), 1, "There should only be one tenant")

        # Test service configuration via CLI
        forward_services = ["sfdp-l4-lifecycle", "ip4-lookup"]
        reverse_services = ["ip4-lookup"]
        self.vapi.cli(
            "set sfdp services tenant 200 sfdp-l4-lifecycle ip4-lookup forward"
        )
        self.vapi.cli("set sfdp services tenant 200 ip4-lookup reverse")

        # Calculate expected bitmaps based on service indices
        expected_forward_bitmap = 0
        for service_name in forward_services:
            idx = service_index_by_name[service_name]
            expected_forward_bitmap |= 1 << idx

        expected_reverse_bitmap = 0
        for service_name in reverse_services:
            idx = service_index_by_name[service_name]
            expected_reverse_bitmap |= 1 << idx

        # Verify services are set correctly via tenant dump
        tenants = self.vapi.sfdp_tenant_dump()
        tenant = tenants[0]
        self.assertEqual(
            tenant.forward_bitmap, expected_forward_bitmap, "Forward bitmap mismatch"
        )
        self.assertEqual(
            tenant.reverse_bitmap, expected_reverse_bitmap, "Reverse bitmap mismatch"
        )

        # Test timeout configuration via CLI
        self.vapi.cli("set sfdp timeout tenant 200 embryonic 35")

        # Verify timeouts are set correctly via tenant dump
        tenants = self.vapi.sfdp_tenant_dump()
        tenant = tenants[0]
        self.assertEqual(
            tenant.timeout[self.get_timeout_index("embryonic")],
            35,
            "embryonic timeout should be 35 seconds",
        )

        # Test tenant delete via CLI
        self.vapi.cli("sfdp tenant del 200")

        # Verify tenant is gone
        tenants = self.vapi.sfdp_tenant_dump()
        self.assertEqual(len(tenants), 0, "Tenant should not exist after delete")

    def test_sfdp_tcp_session_creation(self):
        """Test SFDP TCP session creation"""
        self._configure_sfdp()

        # Send a TCP SYN packet
        # from pg0 to pg1
        pkt = self.create_tcp_packet(
            src_mac=self.pg0.remote_mac,
            dst_mac=self.pg0.local_mac,
            src_ip=self.pg0.remote_ip4,
            dst_ip=self.pg1.remote_ip4,
            sport=12345,
            dport=80,
            flags="S",
        )

        self.send_and_expect(self.pg0, pkt, self.pg1)

        # Verify session was created
        sessions = self.vapi.sfdp_session_dump()
        found = False
        for sess in sessions:
            if sess.protocol == 6:  # TCP
                found = True
                self.verify_basic_session_state(
                    sess,
                    6,
                    VppEnum.vl_api_sfdp_session_state_t.SFDP_API_SESSION_STATE_FSOL,
                    VppEnum.vl_api_sfdp_session_type_t.SFDP_API_SESSION_TYPE_IP4,
                    self.pg0.remote_ip4,
                    self.pg1.remote_ip4,
                )
                break

        self.assertEqual(
            len(sessions), 1, "There should only be one SFDP session present"
        )
        self.assertTrue(found, "TCP session should have been created")
        self._cleanup_sfdp()

    def test_sfdp_udp_session_creation(self):
        """Test SFDP UDP session creation"""
        self._configure_sfdp()

        # Send a UDP packet
        # from pg0 to pg1
        pkt = self.create_udp_packet(
            src_mac=self.pg0.remote_mac,
            dst_mac=self.pg0.local_mac,
            src_ip=self.pg0.remote_ip4,
            dst_ip=self.pg1.remote_ip4,
            sport=54321,
            dport=53,
        )

        self.send_and_expect(self.pg0, pkt, self.pg1)

        # Verify session was created
        # Find our UDP session
        sessions = self.vapi.sfdp_session_dump()
        found = False
        for sess in sessions:
            if sess.protocol == 17:  # UDP
                found = True
                self.verify_basic_session_state(
                    sess,
                    17,
                    VppEnum.vl_api_sfdp_session_state_t.SFDP_API_SESSION_STATE_FSOL,
                    VppEnum.vl_api_sfdp_session_type_t.SFDP_API_SESSION_TYPE_IP4,
                    self.pg0.remote_ip4,
                    self.pg1.remote_ip4,
                )
                break

        self.assertEqual(
            len(sessions), 1, "There should only be one SFDP session present"
        )
        self.assertTrue(found, "UDP session should have been created")
        self._cleanup_sfdp()

    def test_sfdp_tcp6_session_creation(self):
        """Test SFDP TCP IPv6 session creation"""
        self._configure_sfdp(enable_ip6=True)

        # Send IPv6 TCP SYN packet
        pkt = self.create_tcp6_packet(
            src_mac=self.pg0.remote_mac,
            dst_mac=self.pg0.local_mac,
            src_ip=self.pg0.remote_ip6,
            dst_ip=self.pg1.remote_ip6,
            sport=12345,
            dport=80,
            flags="S",
        )

        self.send_and_expect(self.pg0, pkt, self.pg1)

        # Verify session was created
        sessions = self.vapi.sfdp_session_dump()
        found = False
        for sess in sessions:
            if sess.protocol == 6:  # TCP
                found = True
                self.verify_basic_session_state(
                    sess,
                    6,
                    VppEnum.vl_api_sfdp_session_state_t.SFDP_API_SESSION_STATE_FSOL,
                    VppEnum.vl_api_sfdp_session_type_t.SFDP_API_SESSION_TYPE_IP6,
                    self.pg0.remote_ip6,
                    self.pg1.remote_ip6,
                )
                break

        self.assertEqual(len(sessions), 1, "There should only be one session present")
        self.assertTrue(found, "No TCP IPv6 session found")
        self._cleanup_sfdp(disable_ip6=True)

    def test_sfdp_udp6_session_creation(self):
        """Test SFDP UDP IPv6 session creation"""
        self._configure_sfdp(enable_ip6=True)

        # Send IPv6 UDP packet
        pkt = self.create_udp6_packet(
            src_mac=self.pg0.remote_mac,
            dst_mac=self.pg0.local_mac,
            src_ip=self.pg0.remote_ip6,
            dst_ip=self.pg1.remote_ip6,
            sport=54321,
            dport=53,
        )

        self.send_and_expect(self.pg0, pkt, self.pg1)

        # Verify session was created
        sessions = self.vapi.sfdp_session_dump()
        found = False
        for sess in sessions:
            if sess.protocol == 17:  # UDP
                found = True
                self.verify_basic_session_state(
                    sess,
                    17,
                    VppEnum.vl_api_sfdp_session_state_t.SFDP_API_SESSION_STATE_FSOL,
                    VppEnum.vl_api_sfdp_session_type_t.SFDP_API_SESSION_TYPE_IP6,
                    self.pg0.remote_ip6,
                    self.pg1.remote_ip6,
                )
                break

        self.assertEqual(
            len(sessions), 1, "There should only be one SFDP session present"
        )
        self.assertTrue(found, "UDP IPv6 session should have been created")
        self._cleanup_sfdp(disable_ip6=True)

    def test_sfdp_tcp46_session_creation(self):
        """Test SFDP TCP IPv4/IPv6 simultaneous session creation"""
        self._configure_sfdp(enable_ip4=True, enable_ip6=True)

        pkt_v4 = self.create_tcp_packet(
            src_mac=self.pg0.remote_mac,
            dst_mac=self.pg0.local_mac,
            src_ip=self.pg0.remote_ip4,
            dst_ip=self.pg1.remote_ip4,
            sport=12345,
            dport=80,
            flags="S",
        )

        pkt_v6 = self.create_tcp6_packet(
            src_mac=self.pg0.remote_mac,
            dst_mac=self.pg0.local_mac,
            src_ip=self.pg0.remote_ip6,
            dst_ip=self.pg1.remote_ip6,
            sport=12345,
            dport=80,
            flags="S",
        )

        # Send IPv4 and IPv6 TCP SYN packets
        self.send_and_expect(self.pg0, [pkt_v4, pkt_v6], self.pg1)

        # Verify sessions are created
        sessions = self.vapi.sfdp_session_dump()
        found_v4 = False
        found_v6 = False
        for sess in sessions:
            if (
                sess.protocol == 6
                and sess.session_type
                == VppEnum.vl_api_sfdp_session_type_t.SFDP_API_SESSION_TYPE_IP4
            ):  # TCP V4
                found_v4 = True
                self.assertEqual(sess.tenant_id, self.tenant_id_ip4)
                self.verify_basic_session_state(
                    sess,
                    6,
                    VppEnum.vl_api_sfdp_session_state_t.SFDP_API_SESSION_STATE_FSOL,
                    VppEnum.vl_api_sfdp_session_type_t.SFDP_API_SESSION_TYPE_IP4,
                    self.pg0.remote_ip4,
                    self.pg1.remote_ip4,
                )
            if (
                sess.protocol == 6
                and sess.session_type
                == VppEnum.vl_api_sfdp_session_type_t.SFDP_API_SESSION_TYPE_IP6
            ):  # TCP V6
                found_v6 = True
                self.assertEqual(sess.tenant_id, self.tenant_id_ip6)
                self.verify_basic_session_state(
                    sess,
                    6,
                    VppEnum.vl_api_sfdp_session_state_t.SFDP_API_SESSION_STATE_FSOL,
                    VppEnum.vl_api_sfdp_session_type_t.SFDP_API_SESSION_TYPE_IP6,
                    self.pg0.remote_ip6,
                    self.pg1.remote_ip6,
                )

        self.assertEqual(len(sessions), 2, "There should be two sessions present")
        self.assertTrue(found_v4, "No TCP IPv4 session found")
        self.assertTrue(found_v6, "No TCP IPv6 session found")
        self._cleanup_sfdp(disable_ip4=True, disable_ip6=True)

    def test_sfdp_single_tenant_multiple_tcp_flows(self):
        """Test single tenant processing multiple TCP flows"""
        self._configure_sfdp()

        # Create five TCP flows with different source ports
        packets = []
        for i in range(5):
            pkt = self.create_tcp_packet(
                src_mac=self.pg0.remote_mac,
                dst_mac=self.pg0.local_mac,
                src_ip=self.pg0.remote_ip4,
                dst_ip=self.pg1.remote_ip4,
                sport=10000 + i,
                dport=80,
                flags="S",
            )
            packets.append(pkt)

        # Send all packets from pg0 to pg1
        for pkt in packets:
            self.send_and_expect(self.pg0, pkt, self.pg1)

        # Verify all sessions were created
        sessions = self.vapi.sfdp_session_dump()

        self.assertEqual(len(sessions), 5, "Did not get expected number of sessions")

        # Verify all sessions are in FSOL state and belong to tenant 1
        for sess in sessions:
            self.assertEqual(sess.tenant_id, 1, "Session should belong to tenant 1")
            self.verify_basic_session_state(
                sess,
                6,
                VppEnum.vl_api_sfdp_session_state_t.SFDP_API_SESSION_STATE_FSOL,
                VppEnum.vl_api_sfdp_session_type_t.SFDP_API_SESSION_TYPE_IP4,
            )

        self._cleanup_sfdp()

    def test_sfdp_kill_session_batch(self):
        """Test api to kill sfdp sessions in batches"""
        self._configure_sfdp()
        self.vapi.sfdp_set_timeout(
            tenant_id=1,
            timeout_id=self.get_timeout_index("embryonic"),
            timeout_value=3600,
        )

        # Create 10 sessions
        for sport in range(12346, 12356):
            self.send_and_expect(
                self.pg0,
                self.create_tcp_packet(
                    src_mac=self.pg0.remote_mac,
                    dst_mac=self.pg0.local_mac,
                    src_ip=self.pg0.remote_ip4,
                    dst_ip=self.pg1.remote_ip4,
                    sport=sport,
                    dport=80,
                ),
                self.pg1,
            )

        # Verify 10 sessions are active
        self.assertEqual(len(self.sessions()), 10)

        # Expire two consecutive batches of 5 sessions
        # can be killed, and verify state is as expected
        self.vapi.sfdp_kill_session_batch(max=5)
        self.virtual_sleep(2)
        self.assertEqual(len(self.sessions()), 5)

        self.vapi.sfdp_kill_session_batch(max=5)
        self.virtual_sleep(2)
        self.assertEqual(len(self.sessions()), 0)

        self._cleanup_sfdp()

    def test_sfdp_kill_session_batch_consecutive(self):
        """Test api to kill sfdp sessions in consecutive batches"""
        self._configure_sfdp()
        self.vapi.sfdp_set_timeout(
            tenant_id=1,
            timeout_id=self.get_timeout_index("embryonic"),
            timeout_value=3600,
        )

        # Create 10 sessions
        for sport in range(12346, 12356):
            self.send_and_expect(
                self.pg0,
                self.create_tcp_packet(
                    src_mac=self.pg0.remote_mac,
                    dst_mac=self.pg0.local_mac,
                    src_ip=self.pg0.remote_ip4,
                    dst_ip=self.pg1.remote_ip4,
                    sport=sport,
                    dport=80,
                ),
                self.pg1,
            )

        # Verify 10 sessions are active
        self.assertEqual(len(self.sessions()), 10)

        # Disable sfdp expiry node, then stack two requests. The second request
        # spends three of its seven inspected-session budget on the first batch.
        self.vapi.cli("test sfdp expiry disable")
        self.vapi.sfdp_kill_session_batch(max=3)
        self.vapi.sfdp_kill_session_batch(max=7)

        # Sessions should remain present until we re-enable the expiry node
        self.virtual_sleep(2)
        self.assertEqual(len(self.sessions()), 10)

        # Re-enable expiry; only seven sessions were marked across both requests.
        self.vapi.cli("test sfdp expiry enable")
        self.virtual_sleep(2)
        self.assertEqual(len(self.sessions()), 3)

        self.vapi.sfdp_kill_session_batch(max=3)
        self.wait_no_sessions()

        self._cleanup_sfdp()

    def test_sfdp_multiple_tenants_flows(self):
        """Test multiple tenants each handling one flow in parallel"""
        # Configure tenant 1 on pg0
        reply = self.vapi.sfdp_tenant_add_del(
            tenant_id=1,
            context_id=1,
            is_del=False,
        )
        self.assertEqual(reply.retval, 0)

        reply = self.vapi.sfdp_set_services(
            tenant_id=1,
            dir=VppEnum.vl_api_sfdp_session_direction_t.SFDP_API_FORWARD,
            n_services=2,
            services=[{"data": "sfdp-l4-lifecycle"}, {"data": "ip4-lookup"}],
        )
        self.assertEqual(reply.retval, 0)

        reply = self.vapi.sfdp_set_services(
            tenant_id=1,
            dir=VppEnum.vl_api_sfdp_session_direction_t.SFDP_API_REVERSE,
            n_services=2,
            services=[{"data": "sfdp-l4-lifecycle"}, {"data": "ip4-lookup"}],
        )
        self.assertEqual(reply.retval, 0)

        reply = self.vapi.sfdp_interface_input_set(
            sw_if_index=self.pg0.sw_if_index,
            tenant_id=1,
            is_disable=False,
        )
        self.assertEqual(reply.retval, 0)

        # Configure tenant 2 on pg1
        reply = self.vapi.sfdp_tenant_add_del(
            tenant_id=2,
            context_id=2,
            is_del=False,
        )
        self.assertEqual(reply.retval, 0)

        reply = self.vapi.sfdp_set_services(
            tenant_id=2,
            dir=VppEnum.vl_api_sfdp_session_direction_t.SFDP_API_FORWARD,
            n_services=2,
            services=[{"data": "sfdp-l4-lifecycle"}, {"data": "ip4-lookup"}],
        )
        self.assertEqual(reply.retval, 0)

        reply = self.vapi.sfdp_set_services(
            tenant_id=2,
            dir=VppEnum.vl_api_sfdp_session_direction_t.SFDP_API_REVERSE,
            n_services=2,
            services=[{"data": "sfdp-l4-lifecycle"}, {"data": "ip4-lookup"}],
        )
        self.assertEqual(reply.retval, 0)

        reply = self.vapi.sfdp_interface_input_set(
            sw_if_index=self.pg1.sw_if_index,
            tenant_id=2,
            is_disable=False,
        )
        self.assertEqual(reply.retval, 0)

        # Send TCP SYN on pg0 (tenant 1)
        pkt1 = self.create_tcp_packet(
            src_mac=self.pg0.remote_mac,
            dst_mac=self.pg0.local_mac,
            src_ip=self.pg0.remote_ip4,
            dst_ip=self.pg1.remote_ip4,
            sport=11111,
            dport=80,
            flags="S",
        )
        self.send_and_expect(self.pg0, pkt1, self.pg1)

        # Send TCP SYN on pg1 (tenant 2)
        pkt2 = self.create_tcp_packet(
            src_mac=self.pg1.remote_mac,
            dst_mac=self.pg1.local_mac,
            src_ip=self.pg1.remote_ip4,
            dst_ip=self.pg0.remote_ip4,
            sport=22222,
            dport=443,
            flags="S",
        )
        self.send_and_expect(self.pg1, pkt2, self.pg0)

        # Verify sessions were created
        sessions = self.vapi.sfdp_session_dump()

        self.assertEqual(len(sessions), 2, "Expected 2 sessions in total")

        # Verify each tenant has exactly one session
        tenant_1_sessions = [s for s in sessions if s.tenant_id == 1]
        tenant_2_sessions = [s for s in sessions if s.tenant_id == 2]

        self.assertEqual(
            len(tenant_1_sessions), 1, "Tenant 1 should have exactly 1 session"
        )
        self.assertEqual(
            len(tenant_2_sessions), 1, "Tenant 2 should have exactly 1 session"
        )

        # Verify both sessions are in FSOL state
        for sess in sessions:
            self.verify_basic_session_state(
                sess,
                6,
                VppEnum.vl_api_sfdp_session_state_t.SFDP_API_SESSION_STATE_FSOL,
                VppEnum.vl_api_sfdp_session_type_t.SFDP_API_SESSION_TYPE_IP4,
            )

        # Cleanup existing sessions
        self.vapi.sfdp_kill_session(is_all=True)
        self.wait_no_sessions()

        # Disable SFDP on interfaces
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

        # Delete tenants
        self.vapi.sfdp_tenant_add_del(tenant_id=1, is_del=True)
        self.vapi.sfdp_tenant_add_del(tenant_id=2, is_del=True)


@unittest.skipIf(
    "sfdp_services" in config.excluded_plugins
    or "sfdp_services_sample" in config.excluded_plugins,
    "SFDP services and SFDP sample services plugins are required to run this test",
)
class TestSfdpSampleTimeout(BaseSfdpTest):
    """Test SFDP custom timeout infrastructure"""

    tenant_id = 100

    # sfdp_services_sample plugin is disabled by default.
    # Enabling it triggers registration of custom timeout "sample-timeout"
    extra_vpp_plugin_config = [
        "plugin sfdp_services_sample_plugin.so { enable }",
    ]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        try:
            cls.create_pg_interfaces(range(2))
            for interface in cls.pg_interfaces:
                interface.config_ip4()
                interface.resolve_arp()
                interface.admin_up()
        except Exception:
            super().tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        for interface in cls.pg_interfaces:
            interface.unconfig_ip4()
            interface.admin_down()
        super().tearDownClass()

    def setUp(self):
        super().setUp()

        reply = self.vapi.sfdp_tenant_add_del(
            tenant_id=100,
            is_del=False,
        )
        self.assertEqual(reply.retval, 0)

        # Set tenant service chain to go through sample service
        # which sets 'sample-timeout' for each session
        reply = self.vapi.sfdp_set_services(
            tenant_id=self.tenant_id,
            dir=VppEnum.vl_api_sfdp_session_direction_t.SFDP_API_FORWARD,
            n_services=2,
            services=[
                {"data": "sample-non-terminal"},
                {"data": "ip4-lookup"},
            ],
        )
        self.assertEqual(reply.retval, 0)

        reply = self.vapi.sfdp_set_services(
            tenant_id=self.tenant_id,
            dir=VppEnum.vl_api_sfdp_session_direction_t.SFDP_API_REVERSE,
            n_services=2,
            services=[
                {"data": "sample-non-terminal"},
                {"data": "ip4-lookup"},
            ],
        )
        self.assertEqual(reply.retval, 0)

        self.vapi.sfdp_interface_input_set(
            sw_if_index=self.pg0.sw_if_index,
            tenant_id=self.tenant_id,
            is_disable=False,
        )

    def tearDown(self):
        self.vapi.sfdp_kill_session(is_all=True)
        self.wait_no_sessions()
        self.vapi.sfdp_interface_input_set(
            sw_if_index=self.pg0.sw_if_index,
            tenant_id=self.tenant_id,
            is_disable=True,
        )
        self.vapi.sfdp_tenant_add_del(tenant_id=self.tenant_id, is_del=True)
        super().tearDown()

    def test_sample_timeout_registration(self):
        # Dump registered timeouts and verify that sample-timeout is registered.
        timeouts = list(self.vapi.sfdp_timeout_dump())
        self.assertEqual(len(timeouts), 5)

        # Verify that there is only a single 'sample-timeout' entry
        custom_timeouts = [
            timeout for timeout in timeouts if timeout.name == "sample-timeout"
        ]
        self.assertEqual(len(custom_timeouts), 1)

        # Verify that custom timeout has default value of 120 seconds
        custom_timeout = custom_timeouts[0]
        self.assertEqual(custom_timeout.timeout_value, 120)

        # Verify that tenant has default custom timeout value configured
        tenant_timeouts = {
            timeout.name: timeout
            for timeout in self.vapi.sfdp_timeout_dump(tenant_id=self.tenant_id)
        }
        self.assertEqual(tenant_timeouts["sample-timeout"].timeout_value, 120)

        # Update custom timeout value for tenant & verify it was updated
        reply = self.vapi.sfdp_set_timeout(
            tenant_id=self.tenant_id,
            timeout_id=custom_timeout.index,
            timeout_value=10,
        )
        self.assertEqual(reply.retval, 0)

        tenant_timeouts = {
            timeout.name: timeout
            for timeout in self.vapi.sfdp_timeout_dump(tenant_id=self.tenant_id)
        }
        self.assertEqual(tenant_timeouts["sample-timeout"].timeout_value, 10)

        # Verify that modifying a tenant timeout does not affect global default
        timeouts = {timeout.name: timeout for timeout in self.vapi.sfdp_timeout_dump()}
        self.assertEqual(timeouts["sample-timeout"].timeout_value, 120)

        # Send traffic & create SFDP session associated with tenant
        self.send_and_expect(
            self.pg0,
            self.create_udp_packet(
                self.pg0.remote_mac,
                self.pg0.local_mac,
                self.pg0.remote_ip4,
                self.pg1.remote_ip4,
                sport=12345,
                dport=23456,
            ),
            self.pg1,
        )

        # Verify single session has been created
        # Sample service should set it to "established" state
        sessions = self.sessions()
        self.assertEqual(len(sessions), 1)
        self.verify_basic_session_state(
            sessions[0],
            17,
            VppEnum.vl_api_sfdp_session_state_t.SFDP_API_SESSION_STATE_ESTABLISHED,
            VppEnum.vl_api_sfdp_session_type_t.SFDP_API_SESSION_TYPE_IP4,
        )

        # Verify that SFDP session only expires after the specified
        # 'sample-timeout' timeout value
        self.virtual_sleep(7)  # Session should still exist after 7 seconds
        self.assertEqual(len(self.sessions()), 1)
        self.virtual_sleep(6)  # Once 10 second threshold is reached, session is deleted
        self.wait_no_sessions()


@unittest.skipIf(
    "sfdp_services" in config.excluded_plugins
    or "sfdp_services_sample" in config.excluded_plugins,
    "SFDP services and SFDP sample services plugins are required to run this test",
)
class TestSfdpSamplePreFilter(BaseSfdpTest):
    """Test SFDP pre-filters"""

    tenant_id = 100
    pre_filter_refused = "/err/sfdp-lookup-ip4/pre-filter refused session creation"
    pre_filter_refused6 = "/err/sfdp-lookup-ip6/pre-filter refused session creation"
    pre_filter_counters = ("sample-discard", "sample-echo")

    extra_vpp_plugin_config = [
        "plugin sfdp_services_sample_plugin.so { enable }",
    ]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        try:
            cls.create_pg_interfaces(range(2))
            for interface in cls.pg_interfaces:
                interface.admin_up()
                interface.config_ip4()
                interface.resolve_arp()
                interface.config_ip6()
                interface.resolve_ndp()
        except Exception:
            super().tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        for interface in cls.pg_interfaces:
            interface.unconfig_ip4()
            interface.unconfig_ip6()
            interface.admin_down()
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        reply = self.vapi.sfdp_tenant_add_del(tenant_id=self.tenant_id, is_del=False)
        self.assertEqual(reply.retval, 0)
        for direction in (
            VppEnum.vl_api_sfdp_session_direction_t.SFDP_API_FORWARD,
            VppEnum.vl_api_sfdp_session_direction_t.SFDP_API_REVERSE,
        ):
            reply = self.vapi.sfdp_set_services(
                tenant_id=self.tenant_id,
                dir=direction,
                n_services=1,
                services=[{"data": "ip4-lookup"}],
            )
            self.assertEqual(reply.retval, 0)
        self.vapi.sfdp_interface_input_set(
            sw_if_index=self.pg0.sw_if_index,
            tenant_id=self.tenant_id,
            is_disable=False,
        )

    def tearDown(self):
        self.vapi.sfdp_kill_session(is_all=True)
        self.wait_no_sessions()
        self.vapi.sfdp_interface_input_set(
            sw_if_index=self.pg0.sw_if_index,
            tenant_id=self.tenant_id,
            is_disable=True,
        )
        self.vapi.sfdp_tenant_add_del(tenant_id=self.tenant_id, is_del=True)
        super().tearDown()

    def pre_filter_calls(self, before=None):
        calls = self.statistics.get_counter("/sfdp/sample/pre-filter-calls")
        now = {
            name: sum(thread[index] for thread in calls)
            for index, name in enumerate(self.pre_filter_counters)
        }
        return {name: now[name] - (before or {}).get(name, 0) for name in now}

    def set_pre_filter(self, name, tenant_id=None):
        reply = self.vapi.sfdp_set_pre_filter(
            tenant_id=self.tenant_id if tenant_id is None else tenant_id,
            is_disable=name is None,
            name={"data": name or ""},
        )
        self.assertEqual(reply.retval, 0)

    def set_sp_node(self, tenant_id, sp_node, node):
        out = self.vapi.cli(
            f"set sfdp sp-node tenant {tenant_id} {sp_node} node {node}"
        )
        self.assertEqual(out.strip(), "")

    def get_pre_filter(self, tenant_id=None):
        reply = self.vapi.sfdp_get_pre_filter(
            tenant_id=self.tenant_id if tenant_id is None else tenant_id
        )
        self.assertEqual(reply.retval, 0)
        return reply.name.data if reply.is_set else None

    def show_pre_filter(self, tenant_id=None):
        tenant_id = self.tenant_id if tenant_id is None else tenant_id
        out = self.vapi.cli(f"show sfdp tenant {tenant_id}")
        return re.search(r"pre-filter: (\S+)", out).group(1)

    def test_pre_filter_api(self):
        """A pre-filter set over the API accepts or refuses new sessions"""
        self.set_pre_filter("sample-discard")
        self.assertEqual(self.get_pre_filter(), "sample-discard")
        before = self.statistics.get_err_counter(self.pre_filter_refused)

        self.send_and_assert_no_replies(self.pg0, self.udp(9))
        self.assertEqual(
            self.statistics.get_err_counter(self.pre_filter_refused) - before, 1
        )
        self.assertEqual(len(self.sessions()), 0)
        self.send_and_expect(self.pg0, self.udp(7), self.pg1)
        self.send_and_expect(self.pg0, self.udp(80), self.pg1)
        self.assertEqual(len(self.sessions()), 2)

        self.set_pre_filter("sample-echo")
        self.assertEqual(self.get_pre_filter(), "sample-echo")
        self.send_and_expect(self.pg0, self.udp(9), self.pg1)
        self.send_and_assert_no_replies(self.pg0, self.udp(7, sport=1000))
        self.assertEqual(len(self.sessions()), 3)
        self.assertEqual(
            self.statistics.get_err_counter(self.pre_filter_refused) - before, 2
        )

        self.set_pre_filter(None)
        self.assertIsNone(self.get_pre_filter())
        self.send_and_expect(self.pg0, self.udp(7, sport=1000), self.pg1)
        self.assertEqual(len(self.sessions()), 4)
        self.assertEqual(
            self.statistics.get_err_counter(self.pre_filter_refused) - before, 2
        )

    def test_pre_filter_sp_node(self):
        """Refused packets go to the tenant's pre-filtered slow-path node"""
        self.set_pre_filter("sample-discard")
        before = self.statistics.get_err_counter(self.pre_filter_refused)
        self.set_sp_node(self.tenant_id, "sp-ip4-pre-filtered", "ip4-lookup")

        self.send_and_expect(self.pg0, self.udp(9), self.pg1)
        self.assertEqual(
            self.statistics.get_err_counter(self.pre_filter_refused) - before, 1
        )
        self.assertEqual(len(self.sessions()), 0)

    def test_pre_filter_only_on_miss(self):
        """The pre-filter runs only for packets that match no session"""
        self.send_and_expect(self.pg0, self.udp(9), self.pg1)
        self.assertEqual(len(self.sessions()), 1)

        self.set_pre_filter("sample-discard")
        before = self.pre_filter_calls()
        self.send_and_expect(self.pg0, self.udp(9) * 5, self.pg1)
        self.assertEqual(
            self.pre_filter_calls(before), {"sample-discard": 0, "sample-echo": 0}
        )

        self.send_and_expect(self.pg0, self.udp(80), self.pg1)
        self.send_and_expect(self.pg0, self.udp(80) * 5, self.pg1)
        self.assertEqual(
            self.pre_filter_calls(before), {"sample-discard": 1, "sample-echo": 0}
        )
        self.assertEqual(len(self.sessions()), 2)

    def test_pre_filter_ip6(self):
        """A pre-filter accepts or refuses new IPv6 sessions"""
        tenant_id = self.tenant_id + 1
        reply = self.vapi.sfdp_tenant_add_del(tenant_id=tenant_id, is_del=False)
        self.assertEqual(reply.retval, 0)
        try:
            for direction in (
                VppEnum.vl_api_sfdp_session_direction_t.SFDP_API_FORWARD,
                VppEnum.vl_api_sfdp_session_direction_t.SFDP_API_REVERSE,
            ):
                reply = self.vapi.sfdp_set_services(
                    tenant_id=tenant_id,
                    dir=direction,
                    n_services=1,
                    services=[{"data": "ip6-lookup"}],
                )
                self.assertEqual(reply.retval, 0)
            self.vapi.sfdp_interface_input_set(
                sw_if_index=self.pg0.sw_if_index,
                tenant_id=tenant_id,
                is_disable=False,
                is_ip6=True,
            )
            self.set_pre_filter("sample-discard", tenant_id)
            before = self.statistics.get_err_counter(self.pre_filter_refused6)

            self.send_and_assert_no_replies(self.pg0, self.udp6(9))
            self.assertEqual(
                self.statistics.get_err_counter(self.pre_filter_refused6) - before, 1
            )
            self.assertEqual(len(self.sessions()), 0)

            self.send_and_expect(self.pg0, self.udp6(80), self.pg1)
            self.assertEqual(len(self.sessions()), 1)

            self.set_sp_node(tenant_id, "sp-ip6-pre-filtered", "ip6-lookup")
            self.send_and_expect(self.pg0, self.udp6(9), self.pg1)
            self.assertEqual(
                self.statistics.get_err_counter(self.pre_filter_refused6) - before, 2
            )
            self.assertEqual(len(self.sessions()), 1)
        finally:
            self.vapi.sfdp_kill_session(is_all=True)
            self.wait_no_sessions()
            self.vapi.sfdp_interface_input_set(
                sw_if_index=self.pg0.sw_if_index,
                tenant_id=tenant_id,
                is_disable=True,
                is_ip6=True,
            )
            self.vapi.sfdp_tenant_add_del(tenant_id=tenant_id, is_del=True)

    def test_pre_filter_unknown(self):
        """Unknown pre-filters and tenants are rejected and change nothing"""
        self.set_pre_filter("sample-discard")
        with self.vapi.assert_negative_api_retval():
            self.vapi.sfdp_set_pre_filter(
                tenant_id=self.tenant_id, name={"data": "no-such-pre-filter"}
            )
        with self.vapi.assert_negative_api_retval():
            self.vapi.sfdp_set_pre_filter(
                tenant_id=self.tenant_id, name={"data": "sample-discard".ljust(31, "x")}
            )
        with self.vapi.assert_negative_api_retval():
            self.vapi.sfdp_set_pre_filter(
                tenant_id=self.tenant_id + 1, name={"data": "sample-discard"}
            )
        with self.vapi.assert_negative_api_retval():
            self.vapi.sfdp_set_pre_filter(tenant_id=self.tenant_id + 1, is_disable=True)
        self.assertEqual(self.get_pre_filter(), "sample-discard")
        self.send_and_assert_no_replies(self.pg0, self.udp(9))
        self.assertEqual(len(self.sessions()), 0)

    def test_pre_filter_get(self):
        """The tenant's pre-filter is read back over the API"""
        reply = self.vapi.sfdp_get_pre_filter(tenant_id=self.tenant_id)
        self.assertEqual(reply.retval, 0)
        self.assertFalse(reply.is_set)
        self.assertEqual(reply.name.data, "")

        self.set_pre_filter("sample-echo")
        reply = self.vapi.sfdp_get_pre_filter(tenant_id=self.tenant_id)
        self.assertTrue(reply.is_set)
        self.assertEqual(reply.name.data, "sample-echo")

        self.set_pre_filter(None)
        self.assertFalse(self.vapi.sfdp_get_pre_filter(tenant_id=self.tenant_id).is_set)

        with self.vapi.assert_negative_api_retval():
            self.vapi.sfdp_get_pre_filter(tenant_id=self.tenant_id + 1)

    def test_pre_filter_dump(self):
        """The registered pre-filters are listed over the API"""
        names = {d.name.data for d in self.vapi.sfdp_pre_filter_dump()}
        self.assertEqual(names, {"sample-discard", "sample-echo"})

    def test_pre_filter_tenant_readd(self):
        """A deleted and re-added tenant starts without a pre-filter"""
        tenant_id = self.tenant_id + 2
        for _ in range(2):
            reply = self.vapi.sfdp_tenant_add_del(tenant_id=tenant_id, is_del=False)
            self.assertEqual(reply.retval, 0)
            self.assertIsNone(self.get_pre_filter(tenant_id))
            self.set_pre_filter("sample-echo", tenant_id)
            self.assertEqual(self.get_pre_filter(tenant_id), "sample-echo")
            reply = self.vapi.sfdp_tenant_add_del(tenant_id=tenant_id, is_del=True)
            self.assertEqual(reply.retval, 0)

    def test_pre_filter_cli(self):
        """The pre-filter is configured and shown over the CLI"""
        out = self.vapi.cli("show sfdp pre-filters")
        self.assertIn("sample-discard", out)
        self.assertIn("sample-echo", out)

        self.vapi.cli(f"set sfdp pre-filter tenant {self.tenant_id} sample-echo")
        self.assertEqual(self.show_pre_filter(), "sample-echo")
        self.assertEqual(self.get_pre_filter(), "sample-echo")
        self.send_and_assert_no_replies(self.pg0, self.udp(7))

        self.vapi.cli(f"set sfdp pre-filter tenant {self.tenant_id} none")
        self.assertEqual(self.show_pre_filter(), "none")
        self.assertIsNone(self.get_pre_filter())
        self.send_and_expect(self.pg0, self.udp(7), self.pg1)
        self.assertEqual(len(self.sessions()), 1)

        for args, error in (
            (f"tenant {self.tenant_id} no-such", "unknown pre-filter no-such"),
            (f"tenant {self.tenant_id}", "missing pre-filter name or none"),
            ("sample-echo", "missing tenant id"),
            (
                f"tenant {self.tenant_id} none sample-echo",
                "none can't be combined with a pre-filter name",
            ),
            (
                f"tenant {self.tenant_id} sample-echo none",
                "none can't be combined with a pre-filter name",
            ),
            (
                f"tenant {self.tenant_id} sample-echo sample-discard",
                "only one pre-filter per tenant",
            ),
            (f"tenant {self.tenant_id + 1} sample-echo", "not found"),
        ):
            reply = self.vapi.cli_return_response(f"set sfdp pre-filter {args}")
            self.assertNotEqual(reply.retval, 0, args)
            self.assertIn(error, reply.reply)
        self.assertEqual(self.show_pre_filter(), "none")


@unittest.skipIf(
    "sfdp_services" in config.excluded_plugins
    or "sfdp_services_sample" in config.excluded_plugins,
    "SFDP services and SFDP sample services plugins are required to run this test",
)
class TestSfdpSampleParser(BaseSfdpTest):
    """Test SFDP custom parser registration"""

    extra_vpp_plugin_config = [
        "plugin sfdp_services_sample_plugin.so { enable }",
    ]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        try:
            cls.create_pg_interfaces(range(2))
            for interface in cls.pg_interfaces:
                interface.config_ip4()
                interface.resolve_arp()
                interface.admin_up()
        except Exception:
            super().tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        for interface in cls.pg_interfaces:
            interface.unconfig_ip4()
            interface.admin_down()
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        self._configure_sfdp()

        # Disable SFDP interface_input, and rather configure
        # our custom parser_input
        self.vapi.sfdp_interface_input_set(
            sw_if_index=self.pg0.sw_if_index,
            tenant_id=self.tenant_id_ip4,
            is_disable=True,
        )

        self.vapi.cli(
            f"set sfdp sample-parser {self.pg0.name} tenant {self.tenant_id_ip4}"
        )
        self.vapi.cli(
            f"set sfdp sample-parser {self.pg1.name} tenant {self.tenant_id_ip4}"
        )

    def tearDown(self):
        # Disable our custom parser_input and
        # re-enable interface_input on interface
        self.vapi.cli(
            f"set sfdp sample-parser {self.pg0.name} "
            f"tenant {self.tenant_id_ip4} disable"
        )
        self.vapi.cli(
            f"set sfdp sample-parser {self.pg1.name} "
            f"tenant {self.tenant_id_ip4} disable"
        )
        self.vapi.sfdp_interface_input_set(
            sw_if_index=self.pg0.sw_if_index,
            tenant_id=self.tenant_id_ip4,
            is_disable=False,
        )
        self._cleanup_sfdp()
        super().tearDown()

    def test_sample_parser_lookup(self):
        """Test SFDP lookup using custom parser"""
        # Send forward and reverse traffic
        # and expect the custom parser to match
        # them against the appropriate session
        sport = 10000
        dport = 20000
        forward = self.create_udp_packet(
            self.pg0.remote_mac,
            self.pg0.local_mac,
            self.pg0.remote_ip4,
            self.pg1.remote_ip4,
            sport=sport,
            dport=dport,
        )
        reverse = self.create_udp_packet(
            self.pg1.remote_mac,
            self.pg1.local_mac,
            self.pg1.remote_ip4,
            self.pg0.remote_ip4,
            sport=dport,
            dport=sport,
        )

        self.send_and_expect(
            self.pg0, [forward] * 5, self.pg1
        )  # Send five forward packets to exercise vector and tail lookup paths
        self.send_and_expect(self.pg1, reverse, self.pg0)  # Send one reverse packet

        # Single session is expected to be created
        sessions = self.sessions()
        self.assertEqual(len(sessions), 1)
        session = sessions[0]
        self.assertEqual(
            session.session_type,
            VppEnum.vl_api_sfdp_session_type_t.SFDP_API_SESSION_TYPE_USER,  # Session type 'user' with custom parsers
        )
        self.assertEqual(session.protocol, 17)

        # Check CLI output, and verify sessions created with custom parser are present
        output = self.vapi.cli("show sfdp session-table")
        self.assertIn("custom-parser: sample-ip4-parser", output)
        self.assertIn(f"{self.pg0.remote_ip4}:{sport}", output)
        self.assertIn(f"{self.pg1.remote_ip4}:{dport}", output)

        # Verify custom parser's context/ingress/egress format function
        details = self.vapi.cli(f"show sfdp session-detail {hex(session.session_id)}")
        self.assertRegex(details, r"forward flow:\n\s+bytes: \d+\n\s+packets: 5")
        self.assertRegex(details, r"reverse flow:\n\s+bytes: \d+\n\s+packets: 1")


@unittest.skipIf(
    "sfdp_services" in config.excluded_plugins,
    "SFDP_Services plugin is required to run SFDP tests",
)
class TestSfdpLookupGuard(BaseSfdpTest):
    """SFDP lookup guard: bit-shift bounds and slow-path normalization"""

    @classmethod
    def setUpClass(cls):
        super(TestSfdpLookupGuard, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(4))
            for i in cls.pg_interfaces:
                i.config_ip4()
                i.config_ip6()
                i.resolve_arp()
                i.resolve_ndp()
                i.admin_up()
        except Exception:
            super(TestSfdpLookupGuard, cls).tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        for i in cls.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.admin_down()
        super(TestSfdpLookupGuard, cls).tearDownClass()

    def test_icmpv6_out_of_range_type_no_session(self):
        """ICMPv6 type>=192 (t128 shift >= 64) must not create a session"""
        self._configure_sfdp(enable_ip4=False, enable_ip6=True)

        pkt_icmp6_oor = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IPv6(src=self.pg0.remote_ip6, dst=self.pg1.remote_ip6)
            / ICMPv6EchoRequest(type=200)
        )
        self.send_and_assert_no_replies(self.pg0, pkt_icmp6_oor)

        self.assertEqual(
            len(self.vapi.sfdp_session_dump()),
            0,
            "ICMPv6 type=200 must not create a session",
        )

        self._cleanup_sfdp(disable_ip4=False, disable_ip6=True)

    def test_tcp4_slowpath_creates_session(self):
        """TCP IPv4 in slow-path vector (batched with unknown-proto) creates a session

        Sending a TCP packet after an unknown-protocol packet forces SFDP to
        re-process the tail of the vector via the slow-path, exercising the
        norm masking for non-ICMP protocols.
        """
        self._configure_sfdp(enable_ip4=True, enable_ip6=False)

        pkt_unknown = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, proto=253)
            / Raw(b"\x00" * 4)
        )
        pkt_tcp4 = self.create_tcp_packet(
            src_mac=self.pg0.remote_mac,
            dst_mac=self.pg0.local_mac,
            src_ip=self.pg0.remote_ip4,
            dst_ip=self.pg1.remote_ip4,
            sport=10001,
            dport=80,
            flags="S",
        )
        self.pg0.add_stream([pkt_unknown, pkt_tcp4])
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        sessions = self.vapi.sfdp_session_dump()
        self.assertEqual(len(sessions), 1, "TCP IPv4 slow-path session must be created")
        self.verify_basic_session_state(
            sessions[0],
            6,
            VppEnum.vl_api_sfdp_session_state_t.SFDP_API_SESSION_STATE_FSOL,
            VppEnum.vl_api_sfdp_session_type_t.SFDP_API_SESSION_TYPE_IP4,
        )

        self._cleanup_sfdp(disable_ip4=True, disable_ip6=False)

    def test_tcp6_slowpath_creates_session(self):
        """TCP IPv6 in slow-path vector (batched with unknown-proto) creates a session"""
        self._configure_sfdp(enable_ip4=False, enable_ip6=True)

        pkt_unknown6 = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IPv6(src=self.pg0.remote_ip6, dst=self.pg1.remote_ip6, nh=253)
            / Raw(b"\x00" * 4)
        )
        pkt_tcp6 = self.create_tcp6_packet(
            src_mac=self.pg0.remote_mac,
            dst_mac=self.pg0.local_mac,
            src_ip=self.pg0.remote_ip6,
            dst_ip=self.pg1.remote_ip6,
            sport=10002,
            dport=80,
            flags="S",
        )
        self.pg0.add_stream([pkt_unknown6, pkt_tcp6])
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        sessions = self.vapi.sfdp_session_dump()
        self.assertEqual(len(sessions), 1, "TCP IPv6 slow-path session must be created")
        self.verify_basic_session_state(
            sessions[0],
            6,
            VppEnum.vl_api_sfdp_session_state_t.SFDP_API_SESSION_STATE_FSOL,
            VppEnum.vl_api_sfdp_session_type_t.SFDP_API_SESSION_TYPE_IP6,
        )

        self._cleanup_sfdp(disable_ip4=False, disable_ip6=True)


@unittest.skipIf(
    "sfdp_services" in config.excluded_plugins,
    "SFDP_Services plugin is required to run SFDP tests",
)
class TestSfdpTimer(BaseSfdpTest):
    """SFDP timer wheel behavior"""

    # 20ms makes one wheel turn (2048 slots) in 40.96s.
    extra_vpp_config = ["sfdp { timer-interval 0.02 }"]

    @classmethod
    def setUpClass(cls):
        super(TestSfdpTimer, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(1))
            cls.pg0.config_ip4()
            cls.pg0.admin_up()
        except Exception:
            super(TestSfdpTimer, cls).tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.pg0.unconfig_ip4()
        cls.pg0.admin_down()
        super(TestSfdpTimer, cls).tearDownClass()

    def setUp(self):
        super(TestSfdpTimer, self).setUp()
        self.vapi.cli("sfdp tenant add 1 context 100")
        self.vapi.cli("set sfdp interface-input pg0 tenant 1")

    def tearDown(self):
        self.vapi.sfdp_kill_session(is_all=True)
        # One tick to let the expire node process the killed sessions
        self.virtual_sleep(0.02)
        self.vapi.cli("set sfdp interface-input pg0 tenant 1 disable")
        self.vapi.cli("sfdp tenant del 1")
        super(TestSfdpTimer, self).tearDown()

    def _session_ids(self):
        # session_idx is the u32 pool index used by the kill API
        return {sess.session_idx for sess in self.vapi.sfdp_session_dump()}

    def _wait_for_session_appear(self):
        session_ids = self._session_ids()
        self.assertTrue(session_ids, "No SFDP session created")
        return next(iter(session_ids))

    def _wait_for_session_disappear(self, session_id, timeout):
        self.virtual_sleep(timeout)
        # Extra tick: ensures the expire node has been dispatched after the
        # clock advance, without relying on wall-clock time
        self.virtual_sleep(0.02)
        self.assertNotIn(session_id, self._session_ids())

    def _send_embryonic_tcp_syn(self, dst_ip, sport):
        pkt = self.create_tcp_packet(
            src_mac=self.pg0.remote_mac,
            dst_mac=self.pg0.local_mac,
            src_ip=self.pg0.remote_ip4,
            dst_ip=dst_ip,
            sport=sport,
            dport=80,
            flags="S",
        )
        self.pg0.add_stream(pkt)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg0.assert_nothing_captured()

    def test_sfdp_timer_interval_shown_in_status(self):
        """Configured timer interval is reported by show sfdp status"""
        status = self.vapi.cli("show sfdp status")

        self.assertRegex(status, r"timer tick interval \(s\): 0?\.020000")

    def test_sfdp_timer_interval_rearm_after_wheel_turn(self):
        """Session still expires after a rearm beyond one wheel turn"""
        self.vapi.sfdp_set_timeout(
            tenant_id=1,
            timeout_id=self.get_timeout_index("embryonic"),
            timeout_value=50,
        )

        self._send_embryonic_tcp_syn("198.51.100.2", 12346)
        session_id = self._wait_for_session_appear()
        self._wait_for_session_disappear(session_id, timeout=55.0)

    def test_sfdp_kill_is_faster_than_timeout(self):
        """Killing a session expires it within one tick, not after its timeout"""
        # Very long timeout so natural expiry won't interfere
        self.vapi.sfdp_set_timeout(
            tenant_id=1,
            timeout_id=self.get_timeout_index("embryonic"),
            timeout_value=3600,
        )

        self._send_embryonic_tcp_syn("198.51.100.2", 12346)
        session_id = self._wait_for_session_appear()

        self.vapi.sfdp_kill_session(
            session_index=session_id, is_all=False
        )  # session_id is session_idx (u32)

        # One tick is enough: kill moves the timer to the current wheel slot
        # and sends an interrupt to the expire node
        self.virtual_sleep(0.02)
        self.assertNotIn(session_id, self._session_ids())

    def test_sfdp_kill_all_is_faster_than_timeout(self):
        """kill_all expires all sessions within one tick"""
        self.vapi.sfdp_set_timeout(
            tenant_id=1,
            timeout_id=self.get_timeout_index("embryonic"),
            timeout_value=3600,
        )

        for sport in [12346, 12347, 12348]:
            self._send_embryonic_tcp_syn("198.51.100.2", sport)

        session_ids = self._session_ids()
        self.assertGreater(len(session_ids), 0)

        self.vapi.sfdp_kill_session(is_all=True)

        self.virtual_sleep(0.02)
        self.assertEqual(len(self._session_ids()), 0)

    def test_sfdp_kill_rearmed_session(self):
        """Killing a rearmed session (past first wheel revolution) works within one tick"""
        # Timeout > one wheel turn (2048 * 0.02 = 40.96s) to force a rearm
        self.vapi.sfdp_set_timeout(
            tenant_id=1,
            timeout_id=self.get_timeout_index("embryonic"),
            timeout_value=50,
        )

        self._send_embryonic_tcp_syn("198.51.100.2", 12346)
        session_id = self._wait_for_session_appear()

        # Advance past the first wheel revolution: session is rearmed, still alive
        self.virtual_sleep(41)
        self.assertIn(session_id, self._session_ids())

        # Kill it: should be gone within one tick despite the rearmed state
        self.vapi.sfdp_kill_session(
            session_index=session_id, is_all=False
        )  # session_id is session_idx (u32)
        self.virtual_sleep(0.02)
        self.assertNotIn(session_id, self._session_ids())


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
