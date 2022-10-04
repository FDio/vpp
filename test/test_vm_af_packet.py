#!/usr/bin/env python3
import unittest
from ipaddress import ip_interface
from vpp_qemu_utils import (
    create_namespace,
    delete_namespace,
    create_host_interface,
    delete_host_interfaces,
)
from vpp_iperf import start_iperf, stop_iperf
from framework import VppTestCase, VppTestRunner
from config import config
from vpp_papi import VppEnum
import time

#
# Tests for:
# - af-packet v2 and v3 interfaces.
# - Uses iPerf to send TCP/IP streams to VPP.
#   - af_packet ingress interface runs the iperf client
#   - af_packet egress interface runs the iperf server
# - Verifies that TCP over IPv4 and IPv6 is enabled correctly
#


class TestAfPacketQemu(VppTestCase):
    """Test VPP af_packet interfaces inside a QEMU VM for IPv4/v6.

    Test Setup:
    Linux_ns1--iperfClient--host-int1--vpp-af_packet-int1--VPP-BD
             --vppaf_packet_int2--host-int2--iperfServer--Linux_ns2
    """

    @classmethod
    def setUpClass(cls):
        super(TestAfPacketQemu, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestAfPacketQemu, cls).tearDownClass()

    def setUp(self):
        """Setup the test topology.

        1. Create Linux Namespaces for iPerf Client & Server
        2. Create host and af-packet interfaces.
        3. Cross-Connect af_packet interfaces in VPP using a bridge-domain.
        """
        super(TestAfPacketQemu, self).setUp()
        self.client_namespace = "iprf_client_ns"
        self.server_namespace = "iprf_server_ns"
        self.client_ip4_prefix = "10.0.0.101/24"
        self.server_ip4_prefix = "10.0.0.102/24"
        self.client_ip6_prefix = "2001:1::1/64"
        self.server_ip6_prefix = "2001:1::2/64"
        # Host interface names on VPP for iperf client and server
        self.client_host_if_name = "vppclientout"
        self.server_host_if_name = "vppserverout"
        create_namespace([self.client_namespace, self.server_namespace])
        # Host interface for iperf client
        create_host_interface(
            "hostintclient",
            self.client_host_if_name,
            self.client_namespace,
            self.client_ip4_prefix,
            self.client_ip6_prefix,
        )
        # Host interface for iperf server
        create_host_interface(
            "hostintserver",
            self.server_host_if_name,
            self.server_namespace,
            self.server_ip4_prefix,
            self.server_ip6_prefix,
        )
        # Wait for Linux IPv4/IPv6 stack to become ready
        # before starting a test.
        time.sleep(2)

    def tearDown(self):
        try:
            self.vapi.af_packet_delete(self.client_host_if_name)
            self.vapi.af_packet_delete(self.server_host_if_name)
            delete_host_interfaces(self.client_host_if_name, self.server_host_if_name)
            delete_namespace(
                [
                    self.client_namespace,
                    self.server_namespace,
                ]
            )
            stop_iperf()
        except Exception as e:
            print(f"Error tearing down test setup: {e}")

    def create_af_packet(self, version, host_if_name):
        """Create an af_packetv3 interface in VPP.

        Parameters:
        version -- 2 for af_packet_create_v2
                -- 3 for af_packet_create_v3
        host_if_name -- host interface name
        """
        af_packet_mode = VppEnum.vl_api_af_packet_mode_t
        af_packet_interface_mode = af_packet_mode.AF_PACKET_API_MODE_ETHERNET
        api_args = {
            "use_random_hw_addr": True,
            "host_if_name": host_if_name,
        }
        if version == 3:
            api_args["mode"] = af_packet_interface_mode
            result = self.vapi.af_packet_create_v3(**api_args)
        elif version == 2:
            result = self.vapi.af_packet_create_v2(**api_args)
        sw_if_index = result.sw_if_index
        self.vapi.sw_interface_set_flags(sw_if_index=sw_if_index, flags=1)
        return sw_if_index

    def dump_bridge_domain_details(self, bd_id):
        return self.vapi.bridge_domain_dump(bd_id=bd_id)

    def l2_connect_interfaces(self, bridge_id, *sw_if_idxs):
        for if_idx in sw_if_idxs:
            self.vapi.sw_interface_set_l2_bridge(
                rx_sw_if_index=if_idx, bd_id=bridge_id, shg=0, port_type=0, enable=True
            )

    # Tests for af_packet v2 & v3 interface with for IPv4 & IPv6
    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_af_packet_v3_ipv4(self):
        """Test af_packet_v3 interface for TCP/IPv4."""
        self.ingress_if_idx = self.create_af_packet(
            version=3, host_if_name=self.client_host_if_name
        )
        self.egress_if_idx = self.create_af_packet(
            version=3, host_if_name=self.server_host_if_name
        )
        self.l2_connect_interfaces(1, self.ingress_if_idx, self.egress_if_idx)
        self.assertTrue(start_iperf(ip_version=4))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_af_packet_v2_ipv4(self):
        """Test af_packet_v2 interface for TCP/IPv4."""
        self.ingress_if_idx = self.create_af_packet(
            version=2, host_if_name=self.client_host_if_name
        )
        self.egress_if_idx = self.create_af_packet(
            version=2, host_if_name=self.server_host_if_name
        )
        self.l2_connect_interfaces(1, self.ingress_if_idx, self.egress_if_idx)
        self.assertTrue(start_iperf(ip_version=4))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_af_packet_v3_ipv6(self):
        """Test af_packet_v3 interface for TCP/IPv6."""
        self.ingress_if_idx = self.create_af_packet(
            version=3, host_if_name=self.client_host_if_name
        )
        self.egress_if_idx = self.create_af_packet(
            version=3, host_if_name=self.server_host_if_name
        )
        self.l2_connect_interfaces(1, self.ingress_if_idx, self.egress_if_idx)
        self.assertTrue(start_iperf(ip_version=6))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_af_packet_v2_ipv6(self):
        """Test af_packet_v2 interface for TCP/IPv6."""
        self.ingress_if_idx = self.create_af_packet(
            version=2, host_if_name=self.client_host_if_name
        )
        self.egress_if_idx = self.create_af_packet(
            version=2, host_if_name=self.server_host_if_name
        )
        self.l2_connect_interfaces(1, self.ingress_if_idx, self.egress_if_idx)
        self.assertTrue(start_iperf(ip_version=4))


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
