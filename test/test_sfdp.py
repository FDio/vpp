#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2025 Cisco Systems, Inc.
import unittest
import socket
from asfframework import VppTestRunner
from framework import VppTestCase
from config import config
from vpp_papi import VppEnum

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP, ICMP


@unittest.skipIf(
    "sfdp_services" in config.excluded_plugins,
    "SFDP_Services plugin is required to run SFDP tests",
)
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

    def create_ip4_mask(self, src_ip=False, dst_ip=False, proto=False):
        mask = bytearray(32)  # 2 match vectors = 32 bytes

        if proto:
            mask[9] = 0xFF  # Protocol at offset 9
        if src_ip:
            mask[12:16] = b"\xff\xff\xff\xff"  # Source IP at offset 12
        if dst_ip:
            mask[16:20] = b"\xff\xff\xff\xff"  # Destination IP at offset 16

        return bytes(mask)

    def create_ip4_match(self, src_ip=None, dst_ip=None, proto=None):
        match = bytearray(32)  # 2 match vectors = 32 bytes

        if proto is not None:
            match[9] = proto
        if src_ip is not None:
            match[12:16] = socket.inet_aton(src_ip)
        if dst_ip is not None:
            match[16:20] = socket.inet_aton(dst_ip)

        return bytes(match)

    def _configure_sfdp(self, use_classifier_input=False):
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

        # Enable on interface
        if use_classifier_input:
            reply = self.vapi.sfdp_classifier_input_enable_disable(
                sw_if_index=self.pg0.sw_if_index,
                is_disable=False,
            )
            self.assertEqual(reply.retval, 0)
        else:
            reply = self.vapi.sfdp_interface_input_set(
                sw_if_index=self.pg0.sw_if_index,
                tenant_id=1,
                is_disable=False,
            )
            self.assertEqual(reply.retval, 0)

    def _cleanup_sfdp(self, use_classifier_input=False):
        """Cleanup SFDP configuration"""
        # Expire active sessions
        self.vapi.sfdp_kill_session(is_all=True)
        # Sleep one second to ensure expired sessions
        # are removed by process node 'sfdp_expire_node'
        self.virtual_sleep(1)

        sessions = self.vapi.sfdp_session_dump()
        self.assertEqual(
            len(sessions), 0, "SFDP sessions are still present after cleanup"
        )

        # Disable SFDP on interfaces
        if use_classifier_input:
            reply = self.vapi.sfdp_classifier_input_enable_disable(
                sw_if_index=self.pg0.sw_if_index,
                is_disable=True,
            )
            self.assertEqual(reply.retval, 0)
        else:
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

    def _create_classifier_table(self, mask, skip=0, match=2):
        reply = self.vapi.classify_add_del_table(
            is_add=True,
            mask=mask,
            mask_len=len(mask),
            skip_n_vectors=skip,
            match_n_vectors=match,
            nbuckets=64,
            memory_size=1 << 20,  # 1MB
        )
        self.assertEqual(reply.retval, 0)
        return reply.new_table_index

    def _delete_classifier_table(self, table_index):
        self.vapi.classify_add_del_table(
            is_add=False,
            table_index=table_index,
            mask_len=0,
            match_n_vectors=0,
        )

    def _verify_basic_session_state(
        self,
        sess,
        expected_protocol,
        expected_state,
        expected_src_ip=None,
        expected_dst_ip=None,
    ):
        """Verify basic session state"""
        self.assertEqual(
            sess.protocol, expected_protocol, f"Protocol should be {expected_protocol}"
        )
        self.assertEqual(sess.state, expected_state, "Unexpected session state")

        # Verify session detail via CLI if IPs are provided
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
                self._verify_basic_session_state(
                    sess,
                    6,
                    VppEnum.vl_api_sfdp_session_state_t.SFDP_API_SESSION_STATE_FSOL,
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
                self._verify_basic_session_state(
                    sess,
                    17,
                    VppEnum.vl_api_sfdp_session_state_t.SFDP_API_SESSION_STATE_FSOL,
                    self.pg0.remote_ip4,
                    self.pg1.remote_ip4,
                )
                break

        self.assertEqual(
            len(sessions), 1, "There should only be one SFDP session present"
        )
        self.assertTrue(found, "UDP session should have been created")
        self._cleanup_sfdp()

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
            self._verify_basic_session_state(
                sess, 6, VppEnum.vl_api_sfdp_session_state_t.SFDP_API_SESSION_STATE_FSOL
            )

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
            self._verify_basic_session_state(
                sess, 6, VppEnum.vl_api_sfdp_session_state_t.SFDP_API_SESSION_STATE_FSOL
            )

        # Cleanup - expire sessions + wait until they
        # are deleted by expiry node
        self.vapi.sfdp_kill_session(is_all=True)
        self.virtual_sleep(1)

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

    def test_sfdp_classifier_input(self):
        """Test SFDP input classifier node"""
        self._configure_sfdp(use_classifier_input=True)

        # Create a classifier table matching on src and dst IP
        mask = self.create_ip4_mask(src_ip=True, dst_ip=True)
        table_index = self._create_classifier_table(mask)

        # Set the classifier table
        reply = self.vapi.sfdp_classifier_input_set_table(
            table_index=table_index,
            is_del=False,
        )
        self.assertEqual(reply.retval, 0)

        # Add classifier session for specific traffic pattern:
        match = self.create_ip4_match(
            src_ip=self.pg0.remote_ip4, dst_ip=self.pg1.remote_ip4
        )

        reply = self.vapi.sfdp_classifier_input_add_del_session(
            tenant_id=self.tenant_id,
            is_del=False,
            match=match,
            match_len=len(match),
        )
        self.assertEqual(reply.retval, 0)

        # Enable classifier input on pg0
        reply = self.vapi.sfdp_classifier_input_enable_disable(
            sw_if_index=self.pg0.sw_if_index,
            is_disable=False,
        )
        self.assertEqual(reply.retval, 0)

        matching_pkt = self.create_tcp_packet(
            src_mac=self.pg0.remote_mac,
            dst_mac=self.pg0.local_mac,
            src_ip=self.pg0.remote_ip4,
            dst_ip=self.pg1.remote_ip4,
            sport=11111,
            dport=80,
            flags="S",
        )
        self.send_and_expect(self.pg0, matching_pkt, self.pg1)

        # Verify SFDP session was created for matching traffic
        sessions = self.vapi.sfdp_session_dump()
        self.assertEqual(len(sessions), 1, "Expected one SFDP session")
        self.assertEqual(sessions[0].tenant_id, self.tenant_id)
        self.assertEqual(sessions[0].protocol, 6)  # TCP

        passthrough_pkt1 = self.create_tcp_packet(
            src_mac=self.pg0.remote_mac,
            dst_mac=self.pg0.local_mac,
            src_ip=self.pg0.remote_ip4,  # Same source
            dst_ip=self.pg2.remote_ip4,  # Different dest - no match
            sport=22222,
            dport=443,
            flags="S",
        )
        self.send_and_expect(self.pg0, passthrough_pkt1, self.pg2)

        # Still only one SFDP session - no session
        # created by passthrough traffic
        sessions = self.vapi.sfdp_session_dump()
        self.assertEqual(
            len(sessions), 1, "Passthrough traffic should not create SFDP session"
        )

        # Cleanup
        self.vapi.sfdp_classifier_input_add_del_session(
            tenant_id=self.tenant_id,
            is_del=True,
            match=match,
            match_len=len(match),
        )

        self.vapi.sfdp_classifier_input_enable_disable(
            sw_if_index=self.pg0.sw_if_index,
            is_disable=True,
        )

        self.vapi.sfdp_classifier_input_set_table(
            table_index=table_index,
            is_del=True,
        )
        self._delete_classifier_table(table_index)
        self._cleanup_sfdp(use_classifier_input=True)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
