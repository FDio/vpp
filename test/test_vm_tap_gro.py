#!/usr/bin/env python3
import unittest
from ipaddress import ip_interface
from vpp_qemu_utils import create_namespace, delete_namespace
from vpp_iperf import start_iperf, stop_iperf
from framework import VppTestCase, VppTestRunner
from config import config
from vpp_papi import VppEnum
import time

#
# Tests for GSO/GRO-coalesing features on tapv2 ingress & egress interfaces.
# - Uses iPerf to send TCP/IP streams to VPP running inside a QEMU VM.
# - Verifies the below for both IPv4 and IPv6 pkts:
#     sending jumbo frames(9000 MTU) with GSO/GRO enabled correctly.
#     sending VPP buffer-sized frames(2048 MTU) with GSO/GRO is enabled correctly.
#     sending standard frame(1500 MTU) with GSO/GRO is enabled correctly.
#     sending smaller frames(512 MTU) with GSO/GRO is enabled correctly.
#     sending odd sized frames(9001, 2049 MTU) with GSO/GRO is enabled correctly.
#


class TestTapQemuGro(VppTestCase):
    """Test VPP tapv2 interfaces inside a QEMU VM with GRO for IPv4/v6.

    Test Setup:
    Linux_ns1--iperfClient--vpptap1--VPP-BD--vpptap2--iperfServer--Linux_ns2
    """

    @classmethod
    def setUpClass(cls):
        super(TestTapQemuGro, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestTapQemuGro, cls).tearDownClass()

    def setUp(self):
        """Setup the test topology.

        1. Create Linux Namespaces for iPerf Client & Server for IPv4 & V6
        2. Create tap interfaces in VPP and connect to the above host NS'es.
        3. Cross-Connect tap interfaces in VPP using a bridge-domain.
        """
        super(TestTapQemuGro, self).setUp()
        self.client_namespace = "iprf_client_ns"
        self.server_namespace = "iprf_server_ns"
        self.client_ip4_prefix = "10.0.0.101/24"
        self.server_ip4_prefix = "10.0.0.102/24"
        self.client_ip6_prefix = "2001:1::1/64"
        self.server_ip6_prefix = "2001:1::2/64"
        create_namespace([self.client_namespace, self.server_namespace])

    def tearDown(self):
        try:
            delete_namespace(
                [
                    self.client_namespace,
                    self.server_namespace,
                ]
            )
            self.vapi.tap_delete_v2(self.ingress_tap_if_idx)
            self.vapi.tap_delete_v2(self.egress_tap_if_idx)
            stop_iperf()
        except:
            pass

    def create_tap(
        self,
        id,
        host_namespace,
        host_ip4_prefix=None,
        host_ip6_prefix=None,
        tap_flags=0,
    ):
        """Create a tapv2 interface in VPP and attach to the host.

        Parameters:
        id -- interface ID
        host_namespace -- host namespace to attach the tap interface to
        host_ip4_prefix -- ipv4 host interface address in CIDR notation
                           (Optional)
        host_ip6_prefix -- ipv6 host interface address in CIDR notation
                           (Optional)
        tap_flags -- Flags for tap interface creation in VPP
        """
        api_args = {
            "id": id,
            "use_random_mac": True,
            "host_namespace_set": True,
            "host_namespace": host_namespace,
            "host_if_name_set": False,
            "host_bridge_set": False,
            "host_mac_addr_set": False,
        }
        if host_ip4_prefix:
            api_args["host_ip4_prefix"] = ip_interface(host_ip4_prefix)
            api_args["host_ip4_prefix_set"] = True
        if host_ip6_prefix:
            api_args["host_ip6_prefix"] = ip_interface(host_ip6_prefix)
            api_args["host_ip6_prefix_set"] = True
        if tap_flags:
            api_args["tap_flags"] = tap_flags

        result = self.vapi.tap_create_v2(**api_args)
        sw_if_index = result.sw_if_index
        self.vapi.sw_interface_set_flags(sw_if_index=sw_if_index, flags=1)
        return sw_if_index

    def create_tap_ingress_gro_net(self, mtu):
        """Create a L2 net with GSO/GRO-Coalesce enabled only on the ingress."""
        TapFlags = VppEnum.vl_api_tap_flags_t
        tap_flags = TapFlags.TAP_API_FLAG_GSO | TapFlags.TAP_API_FLAG_GRO_COALESCE
        # ingress tap with GSO/GRO_COALESCE
        self.ingress_tap_if_idx = self.create_tap(
            id=101,
            host_namespace=self.client_namespace,
            host_ip4_prefix=self.client_ip4_prefix,
            host_ip6_prefix=self.client_ip6_prefix,
            tap_flags=tap_flags,
        )
        # Egress tap with no GSO/GRO_COALESCE
        self.egress_tap_if_idx = self.create_tap(
            id=102,
            host_namespace=self.server_namespace,
            host_ip4_prefix=self.server_ip4_prefix,
            host_ip6_prefix=self.server_ip6_prefix,
        )
        self.l2_connect_interfaces(1, self.ingress_tap_if_idx, self.egress_tap_if_idx)
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.ingress_tap_if_idx, mtu=[mtu, 0, 0, 0]
        )
        # Wait for Linux IPv4/IPv6 stack to become ready
        time.sleep(2)

    def create_tap_egress_gro_net(self, mtu):
        """Create a L2 net with GSO/GRO-Coalesce enabled only on the egress."""
        TapFlags = VppEnum.vl_api_tap_flags_t
        tap_flags = TapFlags.TAP_API_FLAG_GSO | TapFlags.TAP_API_FLAG_GRO_COALESCE
        # Egress tap with GSO/GRO_COALESCE
        self.egress_tap_if_idx = self.create_tap(
            id=102,
            host_namespace=self.server_namespace,
            host_ip4_prefix=self.server_ip4_prefix,
            host_ip6_prefix=self.server_ip6_prefix,
            tap_flags=tap_flags,
        )
        # Ingress tap with no GSO/GRO_COALESCE
        self.ingress_tap_if_idx = self.create_tap(
            id=101,
            host_namespace=self.client_namespace,
            host_ip4_prefix=self.client_ip4_prefix,
            host_ip6_prefix=self.client_ip6_prefix,
        )
        self.l2_connect_interfaces(1, self.ingress_tap_if_idx, self.egress_tap_if_idx)
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.egress_tap_if_idx, mtu=[mtu, 0, 0, 0]
        )
        # Wait for Linux IPv4/IPv6 stack to become ready
        time.sleep(2)

    def create_tap_ingress_egress_gro_net(self, mtu):
        """Create a L2 net with GSO/GRO enabled on both ingress & egress."""
        TapFlags = VppEnum.vl_api_tap_flags_t
        tap_flags = TapFlags.TAP_API_FLAG_GSO | TapFlags.TAP_API_FLAG_GRO_COALESCE
        # Ingress tap with GSO/GRO_COALESCE
        self.ingress_tap_if_idx = self.create_tap(
            id=101,
            host_namespace=self.client_namespace,
            host_ip4_prefix=self.client_ip4_prefix,
            host_ip6_prefix=self.client_ip6_prefix,
            tap_flags=tap_flags,
        )
        # Igress tap with GSO/GRO_COALESCE
        self.egress_tap_if_idx = self.create_tap(
            id=102,
            host_namespace=self.server_namespace,
            host_ip4_prefix=self.server_ip4_prefix,
            host_ip6_prefix=self.server_ip6_prefix,
            tap_flags=tap_flags,
        )
        self.l2_connect_interfaces(1, self.ingress_tap_if_idx, self.egress_tap_if_idx)
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.ingress_tap_if_idx, mtu=[mtu, 0, 0, 0]
        )
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.egress_tap_if_idx, mtu=[mtu, 0, 0, 0]
        )
        # Wait for Linux IPv4/IPv6 stack to become ready
        time.sleep(2)

    def dump_vpp_tap_interfaces(self):
        return self.vapi.sw_interface_tap_v2_dump()

    def dump_bridge_domain_details(self, bd_id):
        return self.vapi.bridge_domain_dump(bd_id=bd_id)

    def l2_connect_interfaces(self, bridge_id, *sw_if_idxs):
        for if_idx in sw_if_idxs:
            self.vapi.sw_interface_set_l2_bridge(
                rx_sw_if_index=if_idx, bd_id=bridge_id, shg=0, port_type=0, enable=True
            )

    # Tests with GRO Coalesce enabled only on the ingress tapv2 interface.
    # MTUs: 9000, 9001, 2049, 2048, 1500 & 512
    # TCP over IPv4
    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_gro_9000_mtu_ipv4(self):
        """Enable GRO-Coalese on ingress tap - 9000 MTU, IPv4."""
        self.create_tap_ingress_gro_net(mtu=9000)
        self.assertTrue(start_iperf(ip_version=4))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_gro_9001_mtu_ipv4(self):
        """Enable GRO-Coalese on ingress tap - 9001 MTU, IPv4."""
        self.create_tap_ingress_gro_net(mtu=9001)
        self.assertTrue(start_iperf(ip_version=4))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_gro_2048_mtu_ipv4(self):
        """Enable GRO-Coalese on ingress tap - 2048 MTU, IPv4."""
        self.create_tap_ingress_gro_net(mtu=2048)
        self.assertTrue(start_iperf(ip_version=4))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_gro_2049_mtu_ipv4(self):
        """Enable GRO-Coalese on ingress tap - 2049 MTU, IPv4."""
        self.create_tap_ingress_gro_net(mtu=2049)
        self.assertTrue(start_iperf(ip_version=4))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_gro_1500_mtu_ipv4(self):
        """Enable GRO-Coalese on ingress tap  - 1500 MTU, IPv4."""
        self.create_tap_ingress_gro_net(mtu=1500)
        self.assertTrue(start_iperf(ip_version=4))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_gro_512_mtu_ipv4(self):
        """Enable GRO-Coalese on ingress tap - 512 MTU, IPv4."""
        self.create_tap_ingress_gro_net(mtu=512)
        self.assertTrue(start_iperf(ip_version=4))

    # Tests with GRO Coalesce enabled only on the ingress tapv2 interface.
    # MTUs: 9000, 9001, 2049, 2048, 1500 & 512
    # TCP over IPv6
    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_gro_9000_mtu_ipv6(self):
        """Enable GRO-Coalese on ingress tap - 9000 MTU, IPv6."""
        self.create_tap_ingress_gro_net(mtu=9000)
        self.assertTrue(start_iperf(ip_version=6))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_gro_9001_mtu_ipv6(self):
        """Enable GRO-Coalese on ingress tap - 9001 MTU, IPv6."""
        self.create_tap_ingress_gro_net(mtu=9001)
        self.assertTrue(start_iperf(ip_version=6))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_gro_2048_mtu_ipv6(self):
        """Enable GRO-Coalese on ingress tap - 2048 MTU, IPv6."""
        self.create_tap_ingress_gro_net(mtu=2048)
        self.assertTrue(start_iperf(ip_version=6))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_gro_2049_mtu_ipv6(self):
        """Enable GRO-Coalese on ingress tap - 2049 MTU, IPv6."""
        self.create_tap_ingress_gro_net(mtu=2049)
        self.assertTrue(start_iperf(ip_version=6))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_gro_1500_mtu_ipv6(self):
        """Enable GRO-Coalese on ingress tap - 1500 MTU, IPv6."""
        self.create_tap_ingress_gro_net(mtu=1500)
        self.assertTrue(start_iperf(ip_version=6))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_gro_512_mtu_ipv6(self):
        """Enable GRO-Coalese on ingress tap - 512 MTU, IPv6."""
        self.create_tap_ingress_gro_net(mtu=512)
        self.assertTrue(start_iperf(ip_version=6))

    # Tests with GRO Coalesce enabled on the egress interface.
    # MTUs: 9000, 9001, 2049, 2048, 1500 & 512
    # IPv4 packets
    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_egress_gro_9000_mtu_ipv4(self):
        """Enable GRO-Coalese on egress tap - 9000 MTU, IPv4."""
        self.create_tap_egress_gro_net(mtu=9000)
        self.assertTrue(start_iperf(ip_version=4))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_egress_gro_9001_mtu_ipv4(self):
        """Enable GRO-Coalese on egress tap - 9001 MTU, IPv4."""
        self.create_tap_egress_gro_net(mtu=9001)
        self.assertTrue(start_iperf(ip_version=4))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_egress_gro_2048_mtu_ipv4(self):
        """Enable GRO-Coalese on egress tap - 2048 MTU, IPv4."""
        self.create_tap_egress_gro_net(mtu=2048)
        self.assertTrue(start_iperf(ip_version=4))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_egress_gro_2049_mtu_ipv4(self):
        """Enable GRO-Coalese on egress tap - 2049 MTU, IPv4."""
        self.create_tap_egress_gro_net(mtu=2049)
        self.assertTrue(start_iperf(ip_version=4))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_egress_gro_1500_mtu_ipv4(self):
        """Enable GRO-Coalese on egress tap - 1500 MTU, IPv4."""
        self.create_tap_egress_gro_net(mtu=1500)
        self.assertTrue(start_iperf(ip_version=4))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_egress_gro_512_mtu_ipv4(self):
        """Enable GRO-Coalese on egress tap - 512 MTU, IPv4."""
        self.create_tap_egress_gro_net(mtu=512)
        self.assertTrue(start_iperf(ip_version=4))

    # Tests with GRO enabled on the egress interface.
    # MTUs: 9000, 9001, 2049, 2048, 1500 & 512
    # IPv6
    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_egress_gro_9000_mtu_ipv6(self):
        """Enable GRO-Coalese on egress tap - 9000 MTU, IPv6."""
        self.create_tap_egress_gro_net(mtu=9000)
        self.assertTrue(start_iperf(ip_version=6))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_egress_gro_9001_mtu_ipv6(self):
        """Enable GRO-Coalese on egress tap - 9001 MTU, IPv6."""
        self.create_tap_egress_gro_net(mtu=9001)
        self.assertTrue(start_iperf(ip_version=6))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_egress_gro_2048_mtu_ipv6(self):
        """Enable GRO-Coalese on egress tap - 2048 MTU, IPv6."""
        self.create_tap_egress_gro_net(mtu=2048)
        self.assertTrue(start_iperf(ip_version=6))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_egress_gro_2049_mtu_ipv6(self):
        """Enable GRO-Coalese on egress tap - 2049 MTU, IPv6."""
        self.create_tap_egress_gro_net(mtu=2049)
        self.assertTrue(start_iperf(ip_version=6))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_egress_gro_1500_mtu_ipv6(self):
        """Enable GRO-Coalese on egress tap - 1500 MTU, IPv6."""
        self.create_tap_egress_gro_net(mtu=1500)
        self.assertTrue(start_iperf(ip_version=6))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_egress_gro_512_mtu_ipv6(self):
        """Enable GRO-Coalese on egress tap - 512 MTU, IPv6."""
        self.create_tap_egress_gro_net(mtu=512)
        self.assertTrue(start_iperf(ip_version=6))

    # Tests with GRO Coalesce enabled on both ingress & egress interfaces.
    # MTUs: 9000, 9001, 2049, 2048, 1500 & 512
    # IPv4 packets
    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_egress_gro_9000_mtu_ipv4(self):
        """Enable GRO-Coalese on ingress & egress tap intfs - 9000 MTU, IPv4."""
        self.create_tap_ingress_egress_gro_net(mtu=9000)
        self.assertTrue(start_iperf(ip_version=4))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_egress_gro_9001_mtu_ipv4(self):
        """Enable GRO-Coalese on ingress & egress tap intfs - 9001 MTU, IPv4."""
        self.create_tap_ingress_egress_gro_net(mtu=9001)
        self.assertTrue(start_iperf(ip_version=4))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_egress_gro_2048_mtu_ipv4(self):
        """Enable GRO-Coalese on ingress & egress tap intfs - 2048 MTU, IPv4."""
        self.create_tap_ingress_egress_gro_net(mtu=2048)
        self.assertTrue(start_iperf(ip_version=4))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_egress_gro_2049_mtu_ipv4(self):
        """Enable GRO-Coalese on ingress & egress tap intfs - 2049 MTU, IPv4."""
        self.create_tap_ingress_egress_gro_net(mtu=2049)
        self.assertTrue(start_iperf(ip_version=4))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_egress_gro_1500_mtu_ipv4(self):
        """Enable GRO-Coalese on ingress & egress tap intfs - 1500 MTU, IPv4."""
        self.create_tap_ingress_egress_gro_net(mtu=1500)
        self.assertTrue(start_iperf(ip_version=4))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_egress_gro_512_mtu_ipv4(self):
        """Enable GRO-Coalese on ingress & egress tap intfs - 512 MTU, IPv4."""
        self.create_tap_ingress_egress_gro_net(mtu=512)
        self.assertTrue(start_iperf(ip_version=4))

    # Tests with GRO Coalesce enabled on both ingress & egress interfaces.
    # MTUs: 9000, 9001, 2049, 2048, 1500 & 512
    # IPv6 packets
    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_egress_gro_9000_mtu_ipv6(self):
        """Enable GRO-Coalese on ingress & egress tap intfs - 9000 MTU, IPv6."""
        self.create_tap_ingress_egress_gro_net(mtu=9000)
        self.assertTrue(start_iperf(ip_version=6))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_egress_gro_9001_mtu_ipv6(self):
        """Enable GRO-Coalese on ingress & egress tap intfs - 9001 MTU, IPv6."""
        self.create_tap_ingress_egress_gro_net(mtu=9001)
        self.assertTrue(start_iperf(ip_version=6))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_egress_gro_2048_mtu_ipv6(self):
        """Enable GRO-Coalese on ingress & egress tap intfs - 2048 MTU, IPv6."""
        self.create_tap_ingress_egress_gro_net(mtu=2048)
        self.assertTrue(start_iperf(ip_version=6))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_egress_gro_2049_mtu_ipv6(self):
        """Enable GRO-Coalese on ingress & egress tap intfs - 2049 MTU, IPv6."""
        self.create_tap_ingress_egress_gro_net(mtu=2049)
        self.assertTrue(start_iperf(ip_version=6))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_egress_gro_1500_mtu_ipv6(self):
        """Enable GRO-Coalese on ingress & egress tap intfs - 1500 MTU, IPv6."""
        self.create_tap_ingress_egress_gro_net(mtu=1500)
        self.assertTrue(start_iperf(ip_version=6))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_egress_gro_512_mtu_ipv6(self):
        """Enable GRO-Coalese on ingress & egress tap intfs - 512 MTU, IPv6."""
        self.create_tap_ingress_egress_gro_net(mtu=512)
        self.assertTrue(start_iperf(ip_version=6))


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
