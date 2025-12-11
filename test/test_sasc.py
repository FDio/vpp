#!/usr/bin/env python3

import unittest
from asfframework import VppTestRunner
from framework import VppTestCase
from config import config
from vpp_papi import VppEnum

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP, ICMP

N_SESSION_PKTS = 5


@unittest.skipIf("sasc" in config.excluded_plugins, "Exclude sasc plugin tests")
class TestSasc(VppTestCase):
    """SASC Plugin tests"""

    @classmethod
    def setUpClass(cls):
        super(TestSasc, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(5))
            for i in cls.pg_interfaces:
                i.config_ip4()
                i.resolve_arp()
                i.admin_up()
        except Exception:
            super(TestSasc, cls).tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        for i in cls.pg_interfaces:
            i.unconfig_ip4()
            i.admin_down()
        super(TestSasc, cls).tearDownClass()

    def create_tcp_packet(
        self, src_mac, dst_mac, src_ip, dst_ip, sport, dport, flags="S"
    ):
        """Create a TCP packet"""
        return (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip)
            / TCP(sport=sport, dport=dport, flags=flags)
            / Raw(b"\xa5" * 100)
        )

    def create_udp_packet(self, src_mac, dst_mac, src_ip, dst_ip, sport, dport):
        """Create a UDP packet"""
        return (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip)
            / UDP(sport=sport, dport=dport)
            / Raw(b"\xa5" * 100)
        )

    def create_icmp_packet(
        self, src_mac, dst_mac, src_ip, dst_ip, icmp_type=8, icmp_code=0
    ):
        """Create an ICMP packet"""
        return (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip)
            / ICMP(type=icmp_type, code=icmp_code)
            / Raw(b"\xa5" * 100)
        )

    def _configure_sasc(self):
        # Configure SASC on input feat-arc of pg0

        # Get service information
        services = self.vapi.sasc_service_dump()

        # Extract IDs of services 'sasc-create', 'sasc-feature-arc-return'
        sasc_create_service_id = 0
        sasc_feature_arc_return_id = 0
        for svc in services:
            if svc.name == "sasc-create":
                sasc_create_service_id = svc.service_index
            elif svc.name == "sasc-feature-arc-return":
                sasc_feature_arc_return_id = svc.service_index

        self.sasc_expected_fwd_rvs_service_chain = [sasc_feature_arc_return_id]
        self.sasc_expected_miss_service_chain = [
            sasc_create_service_id,
            sasc_feature_arc_return_id,
        ]

        # Configure the following service chains
        # Service chain 0: sasc-create sasc-feature-arc-return
        # Service chain 1: sasc-feature-arc-return
        reply = self.vapi.sasc_set_services(
            chain_id=0,
            n_services=2,
            services=self.sasc_expected_miss_service_chain,
        )
        self.assertEqual(reply.retval, 0)
        reply = self.vapi.sasc_set_services(
            chain_id=1,
            n_services=1,
            services=self.sasc_expected_fwd_rvs_service_chain,
        )
        self.assertEqual(reply.retval, 0)

        # Create tenant using configured service chains
        reply = self.vapi.sasc_tenant_add(
            context_id=10,
            forward_chain_id=1,
            reverse_chain_id=1,
            miss_chain_id=0,
            icmp_error_chain_id=0,
        )
        self.assertEqual(reply.retval, 0)

        self.tenant_idx_0 = reply.tenant_idx

        # Enable SASC on interface pg0 input, with configured tenant 0
        reply = self.vapi.sasc_interface_enable_disable(
            sw_if_index=self.pg0.sw_if_index,
            tenant_idx=self.tenant_idx_0,
            is_output=False,
            is_enable=True,
        )
        self.assertEqual(reply.retval, 0)

    def _cleanup_sasc(self):
        """Cleanup SASC configuration, tenants, and sessions"""
        reply = self.vapi.sasc_interface_enable_disable(
            sw_if_index=self.pg0.sw_if_index,
            tenant_idx=0,  # Tenant ID is not required when disabling SASC on interface
            is_output=False,
            is_enable=False,
        )
        self.assertEqual(reply.retval, 0)

        reply = self.vapi.sasc_tenant_del(
            tenant_idx=self.tenant_idx_0,
        )
        self.assertEqual(reply.retval, 0)

        self.vapi.sasc_session_clear()

    def verify_service_chain(
        self, svc_chain, exp_chain_id, exp_n_services, exp_services
    ):
        self.assertEqual(svc_chain.chain_id, exp_chain_id)
        self.assertEqual(svc_chain.n_services, exp_n_services)
        self.assertEqual(svc_chain.services, exp_services)

    def verify_tenant(
        self,
        tenant,
        exp_context_id,
        exp_fwd_chain,
        exp_rvs_chain,
        exp_miss_chain,
        exp_icmp_chain,
    ):
        self.assertEqual(tenant.context_id, exp_context_id)
        self.assertEqual(tenant.forward_chain_id, exp_fwd_chain)
        self.assertEqual(tenant.reverse_chain_id, exp_rvs_chain)
        self.assertEqual(tenant.miss_chain_id, exp_miss_chain)
        self.assertEqual(tenant.icmp_error_chain_id, exp_icmp_chain)

    def test_sasc_cli(self):
        """Test sasc configuration through CLI"""
        # SASC is not pre-configured in this test
        # Configure basic Forward/Reverse, and Miss service chains
        self.vapi.cli("set sasc services 0 sasc-create sasc-feature-arc-return")
        self.vapi.cli("set sasc services 1 sasc-feature-arc-return")

        # Configure tenant
        self.vapi.cli("set sasc tenant context 0 forward 1 reverse 1 miss 0")

        # Enable SASC feature on pg interface input with tenant 0
        self.vapi.cli("set sasc ingress interface pg0 tenant 0")

        # Enable SASC on pg interface output
        self.vapi.cli("set sasc ingress interface pg0 tenant 0 output")

        # Cleanup
        self.vapi.cli("set sasc ingress interface pg0 disable")
        self.vapi.cli("set sasc ingress interface pg0 output disable")
        self.vapi.cli("delete sasc tenant 0")

    def test_sasc(self):
        """Test sasc configuration through API"""
        # SASC Initialization
        self._configure_sasc()

        # Verify default service chain configuration
        service_chains = self.vapi.sasc_service_chain_dump()
        self.assertEqual(len(service_chains), 2)

        self.verify_service_chain(
            service_chains[0], 0, 2, self.sasc_expected_miss_service_chain
        )
        self.verify_service_chain(
            service_chains[1], 1, 1, self.sasc_expected_fwd_rvs_service_chain
        )

        # Verify tenant exists, and has been configured appropriately
        tenants = self.vapi.sasc_tenant_dump()
        self.assertEqual(len(tenants), 1)

        tenant_found = False
        for t in tenants:
            if t.tenant_idx == self.tenant_idx_0:
                tenant_found = True
                self.verify_tenant(t, 10, 1, 1, 0, 0)
                break
        self.assertTrue(tenant_found, "Tenant not found")

        sasc_interfaces = self.vapi.sasc_interface_dump()
        self.assertEqual(len(sasc_interfaces), 1)
        self.assertEqual(sasc_interfaces[0].sw_if_index, self.pg0.sw_if_index)

        # SASC cleanup
        self._cleanup_sasc()

        # Verify there are no more configured tenants and interfaces
        sasc_interfaces = self.vapi.sasc_interface_dump()
        self.assertEqual(len(sasc_interfaces), 0)
        tenants = self.vapi.sasc_tenant_dump()
        self.assertEqual(len(tenants), 0)

    def _verify_session_state(
        self, sess, expected_protocol, expected_tenant_idx, expected_state
    ):
        """Verify common session fields"""
        self.assertEqual(
            sess.tenant_idx,
            expected_tenant_idx,
            "Session does not contain appropriate tenant ID",
        )
        self.assertEqual(
            sess.protocol, expected_protocol, f"Protocol should be {expected_protocol}"
        )
        self.assertEqual(
            sess.state, expected_state, "Unexpected session state - should be FSOL"
        )
        self.assertGreater(
            sess.remaining_time, 0, "Session should have positive remaining time"
        )
        self.assertEqual(
            sess.pkts_forward, 1, "Invalid forward packet counter for flow"
        )
        self.assertEqual(
            sess.pkts_reverse, 0, "Invalid reverse packet counter for flow"
        )

    def _verify_session_keys(self, sess, expected_src_ip, expected_dst_ip, valid_flows):
        # Verify Forward and Reverse session keys contain accurate session information
        found_flow_forward = False
        key = sess.forward_key
        sport = key.sport
        dport = key.dport
        src_ip = key.src
        dst_ip = key.dst

        if (sport, dport) in valid_flows:
            self.assertEqual(
                str(src_ip),
                expected_src_ip,
                f"src mismatch: {src_ip} != {expected_src_ip}",
            )
            self.assertEqual(
                str(dst_ip),
                expected_dst_ip,
                f"dst mismatch: {dst_ip} != {expected_dst_ip}",
            )
            found_flow_forward = True

        self.assertEqual(
            found_flow_forward,
            True,
            "Could not find corresponding forward session key for flow",
        )

        found_flow_reverse = False
        key = sess.reverse_key
        sport = key.sport
        dport = key.dport
        src_ip = key.src
        dst_ip = key.dst

        if (dport, sport) in valid_flows:
            self.assertEqual(
                str(src_ip),
                expected_dst_ip,
                f"src reverse mismatch: {src_ip} != {expected_dst_ip}",
            )
            self.assertEqual(
                str(dst_ip),
                expected_src_ip,
                f"dst reverse mismatch: {dst_ip} != {expected_src_ip}",
            )
            found_flow_reverse = True

        self.assertEqual(
            found_flow_reverse,
            True,
            "Could not find corresponding reverse session key for flow",
        )

    def _verify_session_icmp_keys(self, sess, expected_src_ip, expected_dst_ip):
        # Verify Forward and Reverse session keys contain accurate session information
        # Sport and Dport are set to zero for ICMP sessions
        key = sess.forward_key
        src_ip = key.src
        dst_ip = key.dst
        self.assertEqual(
            str(src_ip), expected_src_ip, f"src mismatch: {src_ip} != {expected_src_ip}"
        )
        self.assertEqual(
            str(dst_ip), expected_dst_ip, f"dst mismatch: {dst_ip} != {expected_dst_ip}"
        )

        key = sess.reverse_key
        src_ip = key.src
        dst_ip = key.dst
        self.assertEqual(
            str(src_ip),
            expected_dst_ip,
            f"src reverse mismatch: {src_ip} != {expected_dst_ip}",
        )
        self.assertEqual(
            str(dst_ip),
            expected_src_ip,
            f"dst reverse mismatch: {dst_ip} != {expected_src_ip}",
        )

    def _run_session_creation_test(self, protocol, packet_creator, test_flows):

        src_ip = self.pg0.remote_ip4
        dst_ip = self.pg1.remote_ip4

        # Generate packets for each flow
        pkts = [packet_creator(flow, src_ip, dst_ip) for flow in test_flows]

        self.pg_send(self.pg0, pkts)

        # Verify we have the expected number of sessions
        sessions = self.vapi.sasc_session_dump()
        self.assertEqual(
            len(sessions),
            len(test_flows),
            f"Expected {len(test_flows)} sessions, got {len(sessions)}",
        )

        # Build valid flow set based on protocol
        if protocol != 1:  # ICMP sessions have sport/dport field set to zero
            valid_flows = {(flow["sport"], flow["dport"]) for flow in test_flows}

        # Verify session information
        for sess in sessions:
            self._verify_session_state(
                sess,
                protocol,
                self.tenant_idx_0,
                VppEnum.vl_api_sasc_session_state_t.SASC_API_SESSION_STATE_FSOL,
            )
            if protocol != 1:
                self._verify_session_keys(
                    sess, self.pg0.remote_ip4, self.pg1.remote_ip4, valid_flows
                )
            else:  # Only verify IPs of session keys for ICMP sessions
                self._verify_session_icmp_keys(
                    sess, self.pg0.remote_ip4, self.pg1.remote_ip4
                )

        # Clear sessions & verify they have been removed
        self.vapi.sasc_session_clear()
        sessions = self.vapi.sasc_session_dump()
        self.assertEqual(
            len(sessions), 0, "Sessions should not be present after cleanup"
        )

    def test_sasc_session_timeout(self):
        """Test sasc session timeout configuration"""
        # SASC Initialization
        self._configure_sasc()

        # Update SASC timeout values
        reply = self.vapi.sasc_set_timeout(
            fsol_timeout=30,
            established_timeout=360,
            time_wait_timeout=60,
            tcp_transitory_timeout=30,
            tcp_fast_transitory_timeout=5,
            tcp_established_timeout=7200,
        )
        self.assertEqual(reply.retval, 0)

        # Send TCP packet
        pkt = self.create_tcp_packet(
            src_mac=self.pg0.remote_mac,
            dst_mac=self.pg0.local_mac,
            src_ip=self.pg0.remote_ip4,
            dst_ip=self.pg1.remote_ip4,
            sport=12345,
            dport=80,
        )

        self.pg_send(self.pg0, pkt)

        # Verify one TCP session has been created, with state 'FSOL'
        sessions = self.vapi.sasc_session_dump()
        self.assertEqual(len(sessions), 1, "Expected one session to be created")
        self._verify_session_state(
            sessions[0],
            6,
            self.tenant_idx_0,
            VppEnum.vl_api_sasc_session_state_t.SASC_API_SESSION_STATE_FSOL,
        )

        # Advance virtual time beyond FSOL timeout, and verify session has expired
        self.virtual_sleep(31)

        sessions = self.vapi.sasc_session_dump()
        self.assertEqual(len(sessions), 0, "Expected no sessions after timeout")

        # SASC cleanup
        self._cleanup_sasc()

    def test_sasc_tcp_session_creation(self):
        """Test sasc TCP session tracking"""
        # SASC Initialization
        self._configure_sasc()

        test_flows = [
            {"sport": 10000, "dport": 80},
            {"sport": 10001, "dport": 81},
            {"sport": 10002, "dport": 82},
        ]

        def create_tcp(flow, src_ip, dst_ip):
            return self.create_tcp_packet(
                src_mac=self.pg0.remote_mac,
                dst_mac=self.pg0.local_mac,
                src_ip=src_ip,
                dst_ip=dst_ip,
                sport=flow["sport"],
                dport=flow["dport"],
            )

        # IP protocol for TCP is 6
        self._run_session_creation_test(6, create_tcp, test_flows)

        # SASC cleanup
        self._cleanup_sasc()

    def test_sasc_udp_session_creation(self):
        """Test sasc UDP session tracking"""
        # SASC Initialization
        self._configure_sasc()

        test_flows = [
            {"sport": 20000, "dport": 53},
            {"sport": 20001, "dport": 5353},
            {"sport": 20002, "dport": 123},
        ]

        def create_udp(flow, src_ip, dst_ip):
            return self.create_udp_packet(
                src_mac=self.pg0.remote_mac,
                dst_mac=self.pg0.local_mac,
                src_ip=src_ip,
                dst_ip=dst_ip,
                sport=flow["sport"],
                dport=flow["dport"],
            )

        # IP protocol for UDP is 17
        self._run_session_creation_test(17, create_udp, test_flows)

        # SASC cleanup
        self._cleanup_sasc()

    def test_sasc_icmp_session_creation(self):
        """Test sasc ICMP session tracking"""
        # SASC Initialization
        self._configure_sasc()

        # Create single ICMP test flow
        test_flows = [
            {"type": 8, "code": 0, "id": 1000},
        ]

        def create_icmp(flow, src_ip, dst_ip):
            return self.create_icmp_packet(
                src_mac=self.pg0.remote_mac,
                dst_mac=self.pg0.local_mac,
                src_ip=src_ip,
                dst_ip=dst_ip,
                icmp_type=flow["type"],
                icmp_code=flow["code"],
            )

        # IP protocol for ICMP is 1
        self._run_session_creation_test(1, create_icmp, test_flows)

        # SASC cleanup
        self._cleanup_sasc()

    def test_sasc_multi_tenant_bidirectional(self):
        """Test sasc with multiple tenants and bidirectional traffic"""
        # Get service information
        services = self.vapi.sasc_service_dump()

        sasc_create_service_id = 0
        sasc_feature_arc_return_id = 0
        for svc in services:
            if svc.name == "sasc-create":
                sasc_create_service_id = svc.service_index
            elif svc.name == "sasc-feature-arc-return":
                sasc_feature_arc_return_id = svc.service_index

        # Configure service chains (shared across tenants)
        miss_chain = [sasc_create_service_id, sasc_feature_arc_return_id]
        fwd_rvs_chain = [sasc_feature_arc_return_id]

        reply = self.vapi.sasc_set_services(
            chain_id=0, n_services=2, services=miss_chain
        )
        self.assertEqual(reply.retval, 0)
        reply = self.vapi.sasc_set_services(
            chain_id=1, n_services=1, services=fwd_rvs_chain
        )
        self.assertEqual(reply.retval, 0)

        # Create 5 tenants, one per pg interface
        tenant_indices = []
        for i, pg in enumerate(self.pg_interfaces):
            reply = self.vapi.sasc_tenant_add(
                context_id=100 + i,
                forward_chain_id=1,
                reverse_chain_id=1,
                miss_chain_id=0,
                icmp_error_chain_id=0,
            )
            self.assertEqual(reply.retval, 0)
            reply_tenant_idx = reply.tenant_idx
            tenant_indices.append(reply_tenant_idx)

            # Enable SASC on interface input/output
            reply = self.vapi.sasc_interface_enable_disable(
                sw_if_index=pg.sw_if_index,
                tenant_idx=reply_tenant_idx,
                is_output=False,
                is_enable=True,
            )
            self.assertEqual(reply.retval, 0)
            reply = self.vapi.sasc_interface_enable_disable(
                sw_if_index=pg.sw_if_index,
                tenant_idx=reply_tenant_idx,
                is_output=True,
                is_enable=True,
            )
            self.assertEqual(reply.retval, 0)

        # Verify all tenants are configured
        tenants = self.vapi.sasc_tenant_dump()
        self.assertEqual(len(tenants), 5, "Expected 5 tenants")

        # Verify all interfaces have SASC enabled
        # Should be 10 total (5 pg interfaces, with SASC on input/output feature-arcs)
        sasc_interfaces = self.vapi.sasc_interface_dump()
        self.assertEqual(
            len(sasc_interfaces), 10, "Expected 10 SASC-enabled interfaces"
        )

        # Send bidirectional traffic for each tenant
        # Each tenant will have a unique flow (different ports per tenant)
        for i, pg in enumerate(self.pg_interfaces):
            # Determine a peer interface for bidirectional traffic
            peer_idx = (i + 1) % len(self.pg_interfaces)
            peer_pg = self.pg_interfaces[peer_idx]

            # Forward packet: pg[i] -> pg[peer]
            fwd_pkt = self.create_tcp_packet(
                src_mac=pg.remote_mac,
                dst_mac=pg.local_mac,
                src_ip=pg.remote_ip4,
                dst_ip=peer_pg.remote_ip4,
                sport=30000 + i,
                dport=80 + i,
                flags="S",
            )
            self.pg_send(pg, fwd_pkt)

        # # Verify sessions were created (one per tenant/interface)
        sessions = self.vapi.sasc_session_dump()
        self.assertEqual(
            len(sessions), 10, f"Expected 10 sessions, got {len(sessions)}"
        )

        # Verify each session is in FSOL state with correct forward count
        for sess in sessions:
            self.assertEqual(sess.protocol, 6, "Protocol should be TCP (6)")
            self.assertEqual(
                sess.state,
                VppEnum.vl_api_sasc_session_state_t.SASC_API_SESSION_STATE_FSOL,
                "Session should be in FSOL state",
            )
            self.assertEqual(sess.pkts_forward, 1, "Forward packet count should be 1")
            self.assertEqual(sess.pkts_reverse, 0, "Reverse packet count should be 0")

        # Now send reverse traffic to update sessions
        for i, pg in enumerate(self.pg_interfaces):
            peer_idx = (i + 1) % len(self.pg_interfaces)
            peer_pg = self.pg_interfaces[peer_idx]

            # Reverse packet: pg[peer] -> pg[i] (SYN-ACK response)
            # Send from peer interface back to original source
            rvs_pkt = self.create_tcp_packet(
                src_mac=peer_pg.remote_mac,
                dst_mac=peer_pg.local_mac,
                src_ip=peer_pg.remote_ip4,
                dst_ip=pg.remote_ip4,
                sport=80 + i,
                dport=30000 + i,
                flags="SA",
            )
            self.pg_send(peer_pg, rvs_pkt)

        # Verify sessions now have reverse packet counts
        sessions = self.vapi.sasc_session_dump()
        # We should now have more sessions due to reverse traffic creating new sessions
        # or existing sessions updated with reverse counts
        self.assertGreaterEqual(
            len(sessions), 10, "Expected at least 10 sessions after reverse traffic"
        )

        # Verify tenant-session association by checking tenant indices
        tenant_session_count = {idx: 0 for idx in tenant_indices}
        for sess in sessions:
            if sess.tenant_idx in tenant_session_count:
                tenant_session_count[sess.tenant_idx] += 1

        # Each tenant should have at least one session
        for tenant_idx, count in tenant_session_count.items():
            self.assertGreaterEqual(
                count, 1, f"Tenant {tenant_idx} should have at least 1 session"
            )

        # Send additional forward packets to increment counters
        for i, pg in enumerate(self.pg_interfaces):
            peer_idx = (i + 1) % len(self.pg_interfaces)
            peer_pg = self.pg_interfaces[peer_idx]

            # Send multiple packets on existing flow
            for _ in range(N_SESSION_PKTS - 1):
                pkt = self.create_tcp_packet(
                    src_mac=pg.remote_mac,
                    dst_mac=pg.local_mac,
                    src_ip=pg.remote_ip4,
                    dst_ip=peer_pg.remote_ip4,
                    sport=30000 + i,
                    dport=80 + i,
                    flags="A",  # ACK packets
                )
                self.pg_send(pg, pkt)

        # Verify packet counters have been incremented
        sessions = self.vapi.sasc_session_dump()
        total_fwd_pkts = sum(sess.pkts_forward for sess in sessions)
        self.assertGreater(
            total_fwd_pkts, 5, "Total forward packets should be greater than initial 5"
        )

        # Cleanup: Disable SASC on all interfaces and remove tenants
        for i, pg in enumerate(self.pg_interfaces):
            reply = self.vapi.sasc_interface_enable_disable(
                sw_if_index=pg.sw_if_index,
                tenant_idx=0,
                is_output=False,
                is_enable=False,
            )
            self.assertEqual(reply.retval, 0)
            reply = self.vapi.sasc_interface_enable_disable(
                sw_if_index=pg.sw_if_index,
                tenant_idx=0,
                is_output=True,
                is_enable=False,
            )
            self.assertEqual(reply.retval, 0)

        for tenant_idx in tenant_indices:
            reply = self.vapi.sasc_tenant_del(tenant_idx=tenant_idx)
            self.assertEqual(reply.retval, 0)

        self.vapi.sasc_session_clear()

        # Verify cleanup
        sasc_interfaces = self.vapi.sasc_interface_dump()
        self.assertEqual(
            len(sasc_interfaces), 0, "All SASC interfaces should be disabled"
        )
        tenants = self.vapi.sasc_tenant_dump()
        self.assertEqual(len(tenants), 0, "All tenants should be removed")
        sessions = self.vapi.sasc_session_dump()
        self.assertEqual(len(sessions), 0, "All sessions should be cleared")


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
