#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2026 Cisco Systems, Inc.

import unittest

from asfframework import VppTestRunner
from config import config
from scapy.layers.inet import IP, TCP, UDP
from test_sfdp import BaseSfdpTest
from vpp_papi import VppEnum


@unittest.skipIf(
    "sfdp_services" in config.excluded_plugins,
    "SFDP_Services plugin is required to run SFDP tests",
)
class TestSfdpNat(BaseSfdpTest):
    """SFDP NAT IPv4 translation tests"""

    INSIDE_TENANT_ID = 1
    OUTSIDE_TENANT_ID = 2
    NAT_POOL_ID = 1
    NAT_IP = "198.18.0.1"

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

        # Add 'inside' tenant, and set services
        self.vapi.sfdp_tenant_add_del(
            tenant_id=self.INSIDE_TENANT_ID,
            context_id=self.INSIDE_TENANT_ID,
            is_del=False,
        )
        self._set_services(self.INSIDE_TENANT_ID, ["sfdp-nat-output"], "FORWARD")
        self._set_services(self.INSIDE_TENANT_ID, ["ip4-lookup"], "REVERSE")

        # Enable sfdp interface-input on pg0 with 'inside' tenant
        self.vapi.sfdp_interface_input_set(
            sw_if_index=self.pg0.sw_if_index,
            tenant_id=self.INSIDE_TENANT_ID,
            is_disable=False,
        )

        # Add 'outside' tenant, and set services
        self.vapi.sfdp_tenant_add_del(
            tenant_id=self.OUTSIDE_TENANT_ID,
            context_id=self.OUTSIDE_TENANT_ID,
            is_del=False,
        )

        # Default services for 'outside' tenant are a no-op in our tests
        # All sessions are created with traffic sent to the 'inside' tenant, which
        # will rewrite the session forward/reverse bitmap at runtime.
        self._set_services(self.OUTSIDE_TENANT_ID, ["sfdp-drop"], "FORWARD")
        self._set_services(self.OUTSIDE_TENANT_ID, ["sfdp-drop"], "REVERSE")

        # Enable sfdp nat external interface input on pg1 with 'outside' tenant
        # TODO - sfdp nat external interface input functionality is currently similar to interface_input
        # it either needs to be removed or updated to handle additional use-cases i.e. external traffic
        # not matching any NAT session
        self.vapi.sfdp_nat_set_external_interface(
            sw_if_index=self.pg1.sw_if_index,
            tenant_id=self.OUTSIDE_TENANT_ID,
            is_disable=False,
        )

        # Allocate SFDP NAT pool and associate inside/outside tenant mapping
        self.vapi.sfdp_nat_alloc_pool_add_del(
            alloc_pool_id=self.NAT_POOL_ID,
            is_del=False,
            n_addr=1,
            addr=[self.NAT_IP],
        )
        self.vapi.sfdp_nat_snat_set_unset(
            tenant_id=self.INSIDE_TENANT_ID,
            outside_tenant_id=self.OUTSIDE_TENANT_ID,
            table_id=0,
            alloc_pool_id=self.NAT_POOL_ID,
            is_disable=False,
        )

    def tearDown(self):
        self.vapi.sfdp_kill_session(is_all=True)
        self.wait_no_sessions()

        # Remove inside/outside tenant mapping and delete nat pool
        self.vapi.sfdp_nat_snat_set_unset(
            tenant_id=self.INSIDE_TENANT_ID,
            outside_tenant_id=self.OUTSIDE_TENANT_ID,
            table_id=0,
            alloc_pool_id=self.NAT_POOL_ID,
            is_disable=True,
        )
        self.vapi.sfdp_nat_alloc_pool_add_del(
            alloc_pool_id=self.NAT_POOL_ID,
            is_del=True,
            n_addr=0,
            addr=[],
        )

        # Unset SFDP interface input
        self.vapi.sfdp_nat_set_external_interface(
            sw_if_index=self.pg1.sw_if_index,
            tenant_id=self.OUTSIDE_TENANT_ID,
            is_disable=True,
        )
        self.vapi.sfdp_interface_input_set(
            sw_if_index=self.pg0.sw_if_index,
            tenant_id=self.INSIDE_TENANT_ID,
            is_disable=True,
        )

        # Delete internal/external tenants
        self.vapi.sfdp_tenant_add_del(tenant_id=self.INSIDE_TENANT_ID, is_del=True)
        self.vapi.sfdp_tenant_add_del(tenant_id=self.OUTSIDE_TENANT_ID, is_del=True)
        super().tearDown()

    def _set_services(self, tenant_id, services, direction):
        # Set tenant service bitmap in specified direction
        reply = self.vapi.sfdp_set_services(
            tenant_id=tenant_id,
            dir=getattr(
                VppEnum.vl_api_sfdp_session_direction_t,
                f"SFDP_API_{direction}",
            ),
            n_services=len(services),
            services=[{"data": service} for service in services],
        )
        self.assertEqual(reply.retval, 0)

    def _verify_snat_round_trip(self, protocol):
        sport = 12345
        dport = 53
        if protocol is TCP:
            forward = self.create_tcp_packet(
                self.pg0.remote_mac,
                self.pg0.local_mac,
                self.pg0.remote_ip4,
                self.pg1.remote_ip4,
                sport,
                dport,
                flags="S",
            )
        else:
            forward = self.create_udp_packet(
                self.pg0.remote_mac,
                self.pg0.local_mac,
                self.pg0.remote_ip4,
                self.pg1.remote_ip4,
                sport,
                dport,
            )

        # Send packet from inside-to-outside
        # Expect session creation and response of pg1
        capture = self.send_and_expect(self.pg0, forward, self.pg1)
        self.assertEqual(len(capture), 1)
        self.assertEqual(len(self.sessions()), 1)

        # Verify packet has been NAT'd
        translated = capture[0]
        self.assert_packet_checksums_valid(translated)
        self.assertEqual(translated[IP].src, self.NAT_IP)
        self.assertEqual(translated[IP].dst, self.pg1.remote_ip4)
        translated_sport = translated[protocol].sport

        if protocol is TCP:
            reverse = self.create_tcp_packet(
                self.pg1.remote_mac,
                self.pg1.local_mac,
                self.pg1.remote_ip4,
                self.NAT_IP,
                dport,
                translated_sport,
                flags="SA",
            )
        else:
            reverse = self.create_udp_packet(
                self.pg1.remote_mac,
                self.pg1.local_mac,
                self.pg1.remote_ip4,
                self.NAT_IP,
                dport,
                translated_sport,
            )

        # Send packet outside-to-inside
        capture = self.send_and_expect(self.pg1, reverse, self.pg0)
        self.assertEqual(len(capture), 1)

        # Verify packet has been reverse NAT'd
        restored = capture[0]
        self.assert_packet_checksums_valid(restored)
        self.assertEqual(restored[IP].dst, self.pg0.remote_ip4)
        self.assertEqual(restored[protocol].dport, sport)

        # Verify only one session still exists i.e. no second session was created
        self.assertEqual(len(self.sessions()), 1)

    # TODO - need to add a test-case where we receive traffic on 'external/outside'
    # tenant that does not match any of our NAT sessions.
    # Today, we naively create a new session, rather than drop traffic

    def test_tcp_snat_and_reverse_translation(self):
        """TCP flow is source-NATed and restored on the reverse path"""
        self._verify_snat_round_trip(TCP)

    def test_udp_snat_and_reverse_translation(self):
        """UDP flow is source-NATed and restored on the reverse path"""
        self._verify_snat_round_trip(UDP)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
