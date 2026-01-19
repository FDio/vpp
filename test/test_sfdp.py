#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2025 Cisco Systems, Inc.
import unittest
from asfframework import VppTestRunner
from framework import VppTestCase
from config import config
from vpp_papi import VppEnum

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP, ICMP


class TestSfdp(VppTestCase):
    """SFDP Infrastructure tests"""

    @classmethod
    def setUpClass(cls):
        super(TestSfdp, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(4))
            for i in cls.pg_interfaces:
                i.config_ip4()
                i.resolve_arp()
                i.admin_up()
        except Exception:
            super(TestSfdp, cls).tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        for i in cls.pg_interfaces:
            i.unconfig_ip4()
            i.admin_down()
        super(TestSfdp, cls).tearDownClass()

    def create_tcp_packet(
        self, src_mac, dst_mac, src_ip, dst_ip, sport, dport, flags="S", ttl=64
    ):
        return (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip, ttl=ttl)
            / TCP(sport=sport, dport=dport, flags=flags)
            / Raw(b"\xa5" * 100)
        )

    def create_udp_packet(self, src_mac, dst_mac, src_ip, dst_ip, sport, dport, ttl=64):
        return (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip, ttl=ttl)
            / UDP(sport=sport, dport=dport)
            / Raw(b"\xa5" * 100)
        )

    def _configure_sfdp(self):
        """Base SFDP Configuration"""
        # Add tenant with ID 1
        self.tenant_id = 1
        reply = self.vapi.sfdp_tenant_add_del(
            tenant_id=self.tenant_id,
            context_id=1,
            is_del=False,
        )
        self.assertEqual(reply.retval, 0)

        # Configure services - minimal chain for session tracking
        # Use l4-lifecycle for session state management, and drop as terminal
        reply = self.vapi.sfdp_set_services(
            tenant_id=1,
            dir=VppEnum.vl_api_sfdp_session_direction_t.SFDP_API_FORWARD,
            n_services=2,
            services=[{"data": "sfdp-l4-lifecycle"}, {"data": "sfdp-drop"}],
        )
        self.assertEqual(reply.retval, 0)

        reply = self.vapi.sfdp_set_services(
            tenant_id=1,
            dir=VppEnum.vl_api_sfdp_session_direction_t.SFDP_API_REVERSE,
            n_services=2,
            services=[{"data": "sfdp-l4-lifecycle"}, {"data": "sfdp-drop"}],
        )
        self.assertEqual(reply.retval, 0)

        # Enable on interface
        reply = self.vapi.sfdp_interface_input_set(
            sw_if_index=self.pg0.sw_if_index,
            tenant_id=1,
            is_disable=False,
        )
        self.assertEqual(reply.retval, 0)

    def _cleanup_sfdp(self):
        """Cleanup SFDP configuration"""
        self.vapi.sfdp_interface_input_set(
            sw_if_index=self.pg0.sw_if_index,
            tenant_id=self.tenant_id,
            is_disable=True,
        )
        self.vapi.sfdp_tenant_add_del(
            tenant_id=self.tenant_id,
            is_del=True,
        )

    def _verify_basic_session_state(self, sess, expected_protocol, expected_state):
        """Verify basic session state"""
        self.assertEqual(
            sess.protocol, expected_protocol, f"Protocol should be {expected_protocol}"
        )
        self.assertEqual(sess.state, expected_state, "Unexpected session state")

    def test_sfdp_api_configuration(self):
        """Test SFDP configuration"""
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

        self.assertTrue(tenant_found, "Tenant with id 100 should exist")
        self.assertEqual(len(tenants), 1, "There should only be one tenant")

        # Test service configuration for forward direction
        reply = self.vapi.sfdp_set_services(
            tenant_id=100,
            dir=VppEnum.vl_api_sfdp_session_direction_t.SFDP_API_FORWARD,
            n_services=2,
            services=[{"data": "sfdp-l4-lifecycle"}, {"data": "sfdp-drop"}],
        )
        self.assertEqual(reply.retval, 0)

        # Test service configuration for reverse direction
        reply = self.vapi.sfdp_set_services(
            tenant_id=100,
            dir=VppEnum.vl_api_sfdp_session_direction_t.SFDP_API_REVERSE,
            n_services=1,
            services=[{"data": "sfdp-drop"}],
        )
        self.assertEqual(reply.retval, 0)

        # Verify services are set correctly via tenant dump
        # TODO - We currently have no API to dump available services
        # and which index they correspond to in the bitmap.
        tenants = self.vapi.sfdp_tenant_dump()
        tenant = tenants[0]
        self.assertNotEqual(
            tenant.forward_bitmap, 0, "Forward service bitmap should be non-zero"
        )
        self.assertNotEqual(
            tenant.reverse_bitmap, 0, "Reverse service bitmap should be non-zero"
        )

        # Test timeout configuration
        reply = self.vapi.sfdp_set_timeout(
            tenant_id=100,
            timeout_id=0,  # Timeout ID 0 / embryonic
            timeout_value=31,
        )
        self.assertEqual(reply.retval, 0)

        reply = self.vapi.sfdp_set_timeout(
            tenant_id=100,
            timeout_id=1,  # Timeout ID 1 / established
            timeout_value=3601,
        )
        self.assertEqual(reply.retval, 0)

        # Verify timeouts are set correctly via tenant dump
        tenants = self.vapi.sfdp_tenant_dump()
        tenant = tenants[0]
        self.assertEqual(tenant.timeout[0], 31, "Timeout ID 0 should be 31 seconds")
        self.assertEqual(tenant.timeout[1], 3601, "Timeout ID 1 should be 3601 seconds")

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
        self.vapi.cli(
            "set sfdp services tenant 200 sfdp-l4-lifecycle sfdp-drop forward"
        )
        self.vapi.cli("set sfdp services tenant 200 sfdp-drop reverse")

        # Verify services are set correctly via tenant dump
        # TODO - We currently have no API to dump available services
        # and which index they correspond to in the bitmap.
        tenants = self.vapi.sfdp_tenant_dump()
        tenant = tenants[0]
        self.assertNotEqual(
            tenant.forward_bitmap, 0, "Forward service bitmap should be non-zero"
        )
        self.assertNotEqual(
            tenant.reverse_bitmap, 0, "Reverse service bitmap should be non-zero"
        )

        # Test timeout configuration via CLI
        self.vapi.cli("set sfdp timeout tenant 200 embryonic 35")

        # Verify timeouts are set correctly via tenant dump
        tenants = self.vapi.sfdp_tenant_dump()
        tenant = tenants[0]

        self.assertEqual(
            tenant.timeout[0], 35, "Timeout ID 0 (embryonic) should be 35 seconds"
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
        pkt = self.create_tcp_packet(
            src_mac=self.pg0.remote_mac,
            dst_mac=self.pg0.local_mac,
            src_ip=self.pg0.remote_ip4,
            dst_ip=self.pg1.remote_ip4,
            sport=12345,
            dport=80,
            flags="S",
        )

        self.pg_send(self.pg0, pkt)

        # Verify session was created
        sessions = self.vapi.sfdp_session_dump()
        found = False
        for sess in sessions:
            if sess.protocol == 6:  # TCP
                found = True
                self._verify_basic_session_state(
                    sess,
                    6,
                    VppEnum.vl_api_sfdp_session_state_t.SFDP_API_SESSION_STATE_FSOL,
                )
                break

        self.assertTrue(found, "TCP session should have been created")
        self._cleanup_sfdp()

    def test_sfdp_udp_session_creation(self):
        """Test SFDP UDP session creation"""
        self._configure_sfdp()

        # Send a UDP packet
        pkt = self.create_udp_packet(
            src_mac=self.pg0.remote_mac,
            dst_mac=self.pg0.local_mac,
            src_ip=self.pg0.remote_ip4,
            dst_ip=self.pg1.remote_ip4,
            sport=54321,
            dport=53,
        )

        self.pg_send(self.pg0, pkt)

        # Verify session was created
        # Find our UDP session
        sessions = self.vapi.sfdp_session_dump()
        found = False
        for sess in sessions:
            if sess.protocol == 17:  # UDP
                found = True
                self._verify_basic_session_state(
                    sess,
                    17,
                    VppEnum.vl_api_sfdp_session_state_t.SFDP_API_SESSION_STATE_FSOL,
                )
                break

        self.assertTrue(found, "UDP session should have been created")
        self._cleanup_sfdp()

    # TODO - Having scenario to test multi-tenant traffic would be interesting
    # However, we would need to add API to clear existing sessions, as
    # we can end in a scenario where we delete tenants with valid sessions
    # which leads to a crash when dumping all sessions (tenant ID does not exist anymore)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
