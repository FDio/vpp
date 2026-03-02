#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0

import time
import unittest
from asfframework import VppTestRunner
from framework import VppTestCase
from config import config
from vpp_papi import VppEnum

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.layers.inet6 import IPv6


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

    def create_tcp6_packet(
        self, src_mac, dst_mac, src_ip, dst_ip, sport, dport, flags="S", hlim=64
    ):
        return (
            Ether(src=src_mac, dst=dst_mac)
            / IPv6(src=src_ip, dst=dst_ip, hlim=hlim)
            / TCP(sport=sport, dport=dport, flags=flags)
            / Raw(b"\xa5" * 100)
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

    # SFDP is configured on IPv4 feat-arc by default
    def _configure_sfdp(self, enable_ip4=True, enable_ip6=False, bidir=False):
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
            if bidir:
                reply = self.vapi.sfdp_interface_input_set(
                    sw_if_index=self.pg1.sw_if_index,
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
            if bidir:
                reply = self.vapi.sfdp_interface_input_set(
                    sw_if_index=self.pg1.sw_if_index,
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

    def _cleanup_sfdp(self, disable_ip4=True, disable_ip6=False, bidir=False):
        """Cleanup SFDP configuration"""
        self.assertTrue(
            disable_ip4 or disable_ip6, "SFDP must be disabled for either ip4/ip6"
        )
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
        if disable_ip4:
            self.vapi.sfdp_interface_input_set(
                sw_if_index=self.pg0.sw_if_index,
                tenant_id=self.tenant_id_ip4,
                is_disable=True,
            )
            if bidir:
                self.vapi.sfdp_interface_input_set(
                    sw_if_index=self.pg1.sw_if_index,
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
            if bidir:
                self.vapi.sfdp_interface_input_set(
                    sw_if_index=self.pg1.sw_if_index,
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

    def _verify_basic_session_state(
        self,
        sess,
        expected_protocol,
        expected_state,
        expected_session_type,
        expected_src_ip=None,
        expected_dst_ip=None,
    ):
        """Verify basic session state"""
        self.assertEqual(
            sess.protocol, expected_protocol, f"Protocol should be {expected_protocol}"
        )
        self.assertEqual(sess.state, expected_state, "Unexpected session state")
        self.assertEqual(
            sess.session_type, expected_session_type, "Unexpected session type"
        )

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
                self._verify_basic_session_state(
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
                self._verify_basic_session_state(
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
                self._verify_basic_session_state(
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
                self._verify_basic_session_state(
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
                self._verify_basic_session_state(
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
            self._verify_basic_session_state(
                sess,
                6,
                VppEnum.vl_api_sfdp_session_state_t.SFDP_API_SESSION_STATE_FSOL,
                VppEnum.vl_api_sfdp_session_type_t.SFDP_API_SESSION_TYPE_IP4,
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
                sess,
                6,
                VppEnum.vl_api_sfdp_session_state_t.SFDP_API_SESSION_STATE_FSOL,
                VppEnum.vl_api_sfdp_session_type_t.SFDP_API_SESSION_TYPE_IP4,
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

    # This test was originally written by Gemini 3.1 Pro Preview,
    # with only minor touches (sleep timining, code comments, test case name) by Vratko.
    def test_sfdp_tcp_retransmit_of_last_fin(self):
        """Test TCP late retransmit of receiver FIN+ACK."""
        self._configure_sfdp(bidir=True)

        mac0, mac1 = self.pg0.remote_mac, self.pg1.remote_mac
        lmac0, lmac1 = self.pg0.local_mac, self.pg1.local_mac
        ip0, ip1 = self.pg0.remote_ip4, self.pg1.remote_ip4
        sport, dport = 12345, 80

        # 1. Establish connection (Full Handshake)
        syn = (
            Ether(src=mac0, dst=lmac0)
            / IP(src=ip0, dst=ip1)
            / TCP(sport=sport, dport=dport, flags="S", seq=100)
        )
        self.send_and_expect(self.pg0, syn, self.pg1)

        syn_ack = (
            Ether(src=mac1, dst=lmac1)
            / IP(src=ip1, dst=ip0)
            / TCP(sport=dport, dport=sport, flags="SA", seq=200, ack=101)
        )
        self.send_and_expect(self.pg1, syn_ack, self.pg0)

        ack = (
            Ether(src=mac0, dst=lmac0)
            / IP(src=ip0, dst=ip1)
            / TCP(sport=sport, dport=dport, flags="A", seq=101, ack=201)
        )
        self.send_and_expect(self.pg0, ack, self.pg1)

        # 2. Teardown (Clean close to trigger remove_session = 1)
        fin = (
            Ether(src=mac0, dst=lmac0)
            / IP(src=ip0, dst=ip1)
            / TCP(sport=sport, dport=dport, flags="F", seq=101, ack=201)
        )
        self.send_and_expect(self.pg0, fin, self.pg1)

        # Responder ACKs the FIN and sends its own FIN
        fin_ack = (
            Ether(src=mac1, dst=lmac1)
            / IP(src=ip1, dst=ip0)
            / TCP(sport=dport, dport=sport, flags="FA", seq=201, ack=102)
        )
        self.send_and_expect(self.pg1, fin_ack, self.pg0)

        # Initiator sends the final ACK. VPP marks the session for eventual removal.
        last_ack = (
            Ether(src=mac0, dst=lmac0)
            / IP(src=ip0, dst=ip1)
            / TCP(sport=sport, dport=dport, flags="A", seq=102, ack=202)
        )
        self.send_and_expect(self.pg0, last_ack, self.pg1)

        # Wait for the worker thread to maybe remove the session too early.
        time.sleep(1.5)

        # 3. The Late Packet
        # Simulated retransmission of FIN+ACK from Responder
        late_fin_ack = (
            Ether(src=mac1, dst=lmac1)
            / IP(src=ip1, dst=ip0)
            / TCP(sport=dport, dport=sport, flags="FA", seq=201, ack=102)
        )

        # # Because the session is gone, VPP treats this as a brand new forward flow.
        # # Since flags != SYN, it creates a BLOCKED session with sfdp-drop.
        # # We assert no replies because VPP drops it.
        # self.send_and_assert_no_replies(self.pg1, [late_fin_ack], self.pg0)
        self.pg_send(self.pg1, [late_fin_ack])

        time.sleep(0.5)

        # 4. Port Reuse: New SYN from Initiator
        new_syn = (
            Ether(src=mac0, dst=lmac0)
            / IP(src=ip0, dst=ip1)
            / TCP(sport=sport, dport=dport, flags="S", seq=50)
        )

        # Confirm the new SYN packet passes. This fails if VPP deleted the session too early.
        self.send_and_expect(self.pg0, new_syn, self.pg1)

        self._cleanup_sfdp(bidir=True)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
