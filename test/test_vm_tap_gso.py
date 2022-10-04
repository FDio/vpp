#!/usr/bin/env python3
import unittest
from ipaddress import ip_interface
from vpp_qemu_utils import create_namespace, delete_namespace
from vpp_iperf import start_iperf, stop_iperf
from framework import VppTestCase, VppTestRunner
from config import config
import time

#
# Tests for:
# - GSO features on tapv2 ingress & egress interfaces.
# - Uses iPerf to send TCP/IP streams to VPP (running inside a QEMU VM).
# - Verifies the below for TCP over IPv4 and IPv6:
#    sending jumbo frames(9000 MTU) with GSO on ingress is enabled correctly.
#    sending standard frames(1500 MTU) with GSO on ingress is enabled correctly.
#    sending smaller frames(512 MTU) with GSO on ingress is enabled correctly.
#    sending frames with 9001, 2049 and 2048 MTU with GSO on ingress
#    is enabled correctly.
# - Repeats the above verification with GSO on egress & GSO on both ingress
#   & egress.
#


class TestTapQemuGso(VppTestCase):
    """Test VPP tapv2 interfaces inside a QEMU VM with GSO for IPv4/v6.

    Test Setup:
    Linux_ns1--iperfClient--vpptap1--VPP-BD--vpptap2--iperfServer--Linux_ns2
    """

    @classmethod
    def setUpClass(cls):
        super(TestTapQemuGso, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestTapQemuGso, cls).tearDownClass()

    def setUp(self):
        """Setup the test topology.

        1. Create Linux Namespaces for iPerf Client & Server for IPv4 & V6
        2. Create tap interfaces in VPP and connect to the above host NS'es.
        3. Cross-Connect tap interfaces in VPP using a bridge-domain.
        """
        super(TestTapQemuGso, self).setUp()
        self.client_namespace = "iprf_client_ns"
        self.server_namespace = "iprf_server_ns"
        self.client_ip4_prefix = "10.0.0.101/24"
        self.server_ip4_prefix = "10.0.0.102/24"
        self.client_ip6_prefix = "2001:1::1/64"
        self.server_ip6_prefix = "2001:1::2/64"
        create_namespace([self.client_namespace, self.server_namespace])
        self.ingress_tap_if_idx = self.create_tap(
            101, self.client_namespace, self.client_ip4_prefix, self.client_ip6_prefix
        )
        self.egress_tap_if_idx = self.create_tap(
            102, self.server_namespace, self.server_ip4_prefix, self.server_ip6_prefix
        )
        self.l2_connect_interfaces(1, self.ingress_tap_if_idx, self.egress_tap_if_idx)
        # Wait for Linux IPv4/IPv6 stack to become ready
        # before starting a test.
        time.sleep(2)

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
        self, id, host_namespace, host_ip4_prefix=None, host_ip6_prefix=None
    ):
        """Create a tapv2 interface in VPP and attach to the host.

        Parameters:
        id -- interface ID
        host_namespace -- host namespace to attach the tap interface to
        host_ip4_prefix -- ipv4 host interface address in CIDR notation
                           (Optional)
        host_ip6_prefix -- ipv6 host interface address in CIDR notation
                           (Optional)
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

        result = self.vapi.tap_create_v2(**api_args)
        sw_if_index = result.sw_if_index
        self.vapi.sw_interface_set_flags(sw_if_index=sw_if_index, flags=1)
        return sw_if_index

    def dump_vpp_tap_interfaces(self):
        return self.vapi.sw_interface_tap_v2_dump()

    def dump_bridge_domain_details(self, bd_id):
        return self.vapi.bridge_domain_dump(bd_id=bd_id)

    def l2_connect_interfaces(self, bridge_id, *sw_if_idxs):
        for if_idx in sw_if_idxs:
            self.vapi.sw_interface_set_l2_bridge(
                rx_sw_if_index=if_idx, bd_id=bridge_id, shg=0, port_type=0, enable=True
            )

    # Tests with GSO enabled on the ingress interface.
    # MTUs: 9000, 9001, 2049, 2048, 1500 & 512
    # IPv4 packets
    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_gso_9000_mtu_ipv4(self):
        """Enable GSO on ingress tap interface with 9000 MTU, IPv4."""
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.ingress_tap_if_idx, mtu=[9000, 0, 0, 0]
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.ingress_tap_if_idx, enable_disable=1
        )
        self.assertTrue(start_iperf(ip_version=4))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_gso_9001_mtu_ipv4(self):
        """Enable GSO on ingress tap interface with 9001 MTU, IPv4."""
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.ingress_tap_if_idx, mtu=[9001, 0, 0, 0]
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.ingress_tap_if_idx, enable_disable=1
        )
        self.assertTrue(start_iperf(ip_version=4))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_gso_2049_mtu_ipv4(self):
        """Enable GSO on ingress tap interface with 2049 MTU, IPv4."""
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.ingress_tap_if_idx, mtu=[2049, 0, 0, 0]
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.ingress_tap_if_idx, enable_disable=1
        )
        self.assertTrue(start_iperf(ip_version=4))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_gso_2048_mtu_ipv4(self):
        """Enable GSO on ingress tap interface with 2048 MTU, IPv4."""
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.ingress_tap_if_idx, mtu=[2048, 0, 0, 0]
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.ingress_tap_if_idx, enable_disable=1
        )
        self.assertTrue(start_iperf(ip_version=4))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_gso_1500_mtu_ipv4(self):
        """Enable GSO on ingress tap interface with 1500 MTU, IPv4."""
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.ingress_tap_if_idx, mtu=[1500, 0, 0, 0]
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.ingress_tap_if_idx, enable_disable=1
        )
        self.assertTrue(start_iperf(ip_version=4))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_gso_512_mtu_ipv4(self):
        """Enable GSO on ingress tap interface with 512 MTU, IPv4."""
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.ingress_tap_if_idx, mtu=[512, 0, 0, 0]
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.ingress_tap_if_idx, enable_disable=1
        )
        self.assertTrue(start_iperf(ip_version=4))

    # Tests with GSO enabled on the ingress interface.
    # MTUs: 9000, 9001, 2049, 2048, 1500 & 512
    # IPv6
    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_gso_9000_mtu_ipv6(self):
        """Enable GSO on ingress tap interface with 9000 MTU, IPv6."""
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.ingress_tap_if_idx, mtu=[9000, 0, 0, 0]
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.ingress_tap_if_idx, enable_disable=1
        )
        self.assertTrue(start_iperf(ip_version=6))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_gso_9001_mtu_ipv6(self):
        """Enable GSO on ingress tap interface with 9001 MTU, IPv6."""
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.ingress_tap_if_idx, mtu=[9001, 0, 0, 0]
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.ingress_tap_if_idx, enable_disable=1
        )
        self.assertTrue(start_iperf(ip_version=6))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_gso_2049_mtu_ipv6(self):
        """Enable GSO on ingress tap interface with 2049 MTU, IPv6."""
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.ingress_tap_if_idx, mtu=[2049, 0, 0, 0]
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.ingress_tap_if_idx, enable_disable=1
        )
        self.assertTrue(start_iperf(ip_version=6))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_gso_2048_mtu_ipv6(self):
        """Enable GSO on ingress tap interface with 2048 MTU, IPv6."""
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.ingress_tap_if_idx, mtu=[2048, 0, 0, 0]
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.ingress_tap_if_idx, enable_disable=1
        )
        self.assertTrue(start_iperf(ip_version=6))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_gso_1500_mtu_ipv6(self):
        """Enable GSO on ingress tap interface with 1500 MTU, IPv6."""
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.ingress_tap_if_idx, mtu=[1500, 0, 0, 0]
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.ingress_tap_if_idx, enable_disable=1
        )
        self.assertTrue(start_iperf(ip_version=6))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_gso_512_mtu_ipv6(self):
        """Enable GSO on ingress tap interface with 512 MTU, IPv6."""
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.ingress_tap_if_idx, mtu=[512, 0, 0, 0]
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.ingress_tap_if_idx, enable_disable=1
        )
        self.assertTrue(start_iperf(ip_version=6))

    # Tests with GSO enabled on the egress interface.
    # MTUs: 9000, 9001, 2049, 2048, 1500 & 512
    # IPv4 packets
    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_egress_gso_9000_mtu_ipv4(self):
        """Enable GSO on egress tap interface with 9000 MTU, IPv4."""
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.egress_tap_if_idx, mtu=[9000, 0, 0, 0]
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.egress_tap_if_idx, enable_disable=1
        )
        self.assertTrue(start_iperf(ip_version=4))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_egress_gso_9001_mtu_ipv4(self):
        """Enable GSO on egress tap interface with 9001 MTU, IPv4."""
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.egress_tap_if_idx, mtu=[9001, 0, 0, 0]
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.egress_tap_if_idx, enable_disable=1
        )
        self.assertTrue(start_iperf(ip_version=4))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_egress_gso_2049_mtu_ipv4(self):
        """Enable GSO on egress tap interface with 2049 MTU, IPv4."""
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.egress_tap_if_idx, mtu=[2049, 0, 0, 0]
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.egress_tap_if_idx, enable_disable=1
        )
        self.assertTrue(start_iperf(ip_version=4))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_egress_gso_2048_mtu_ipv4(self):
        """Enable GSO on egress tap interface with 2048 MTU, IPv4."""
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.egress_tap_if_idx, mtu=[2048, 0, 0, 0]
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.egress_tap_if_idx, enable_disable=1
        )
        self.assertTrue(start_iperf(ip_version=4))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_egress_gso_1500_mtu_ipv4(self):
        """Enable GSO on egress tap interface with 1500 MTU, IPv4."""
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.egress_tap_if_idx, mtu=[1500, 0, 0, 0]
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.egress_tap_if_idx, enable_disable=1
        )
        self.assertTrue(start_iperf(ip_version=4))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_egress_gso_512_mtu_ipv4(self):
        """Enable GSO on egress tap interface with 512 MTU, IPv4."""
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.egress_tap_if_idx, mtu=[512, 0, 0, 0]
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.egress_tap_if_idx, enable_disable=1
        )
        self.assertTrue(start_iperf(ip_version=4))

    # Tests with GSO enabled on the egress interface.
    # MTUs: 9000, 9001, 2049, 2048, 1500 & 512
    # IPv6
    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_egress_gso_9000_mtu_ipv6(self):
        """Enable GSO on egress tap interface with 9000 MTU, IPv6."""
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.egress_tap_if_idx, mtu=[9000, 0, 0, 0]
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.egress_tap_if_idx, enable_disable=1
        )
        self.assertTrue(start_iperf(ip_version=6))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_egress_gso_9001_mtu_ipv6(self):
        """Enable GSO on egress tap interface with 9001 MTU, IPv6."""
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.egress_tap_if_idx, mtu=[9001, 0, 0, 0]
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.egress_tap_if_idx, enable_disable=1
        )
        self.assertTrue(start_iperf(ip_version=6))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_egress_gso_2049_mtu_ipv6(self):
        """Enable GSO on egress tap interface with 2049 MTU, IPv6."""
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.egress_tap_if_idx, mtu=[2049, 0, 0, 0]
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.egress_tap_if_idx, enable_disable=1
        )
        self.assertTrue(start_iperf(ip_version=6))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_egress_gso_2048_mtu_ipv6(self):
        """Enable GSO on egress tap interface with 2048 MTU, IPv6."""
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.egress_tap_if_idx, mtu=[2048, 0, 0, 0]
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.egress_tap_if_idx, enable_disable=1
        )
        self.assertTrue(start_iperf(ip_version=6))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_egress_gso_1500_mtu_ipv6(self):
        """Enable GSO on egress tap interface with 1500 MTU, IPv6."""
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.egress_tap_if_idx, mtu=[1500, 0, 0, 0]
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.egress_tap_if_idx, enable_disable=1
        )
        self.assertTrue(start_iperf(ip_version=6))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_egress_gso_512_mtu_ipv6(self):
        """Enable GSO on egress tap interface with 512 MTU, IPv6."""
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.egress_tap_if_idx, mtu=[512, 0, 0, 0]
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.egress_tap_if_idx, enable_disable=1
        )
        self.assertTrue(start_iperf(ip_version=6))

    # Tests with GSO enabled on both ingress & egress interfaces.
    # MTUs: 9000, 9001, 2049, 2048, 1500 & 512
    # IPv4 packets
    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_egress_gso_9000_mtu_ipv4(self):
        """Enable GSO on ingress & egress tap interfaces with 9000 MTU, IPv4."""
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.ingress_tap_if_idx, mtu=[9000, 0, 0, 0]
        )
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.egress_tap_if_idx, mtu=[9000, 0, 0, 0]
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.ingress_tap_if_idx, enable_disable=1
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.egress_tap_if_idx, enable_disable=1
        )
        self.assertTrue(start_iperf(ip_version=4))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_egress_gso_9001_mtu_ipv4(self):
        """Enable GSO on ingress & egress tap interfaces with 9001 MTU, IPv4."""
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.ingress_tap_if_idx, mtu=[9001, 0, 0, 0]
        )
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.egress_tap_if_idx, mtu=[9001, 0, 0, 0]
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.ingress_tap_if_idx, enable_disable=1
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.egress_tap_if_idx, enable_disable=1
        )
        self.assertTrue(start_iperf(ip_version=4))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_egress_gso_2049_mtu_ipv4(self):
        """Enable GSO on ingress & egress tap interfaces with 2049 MTU, IPv4."""
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.ingress_tap_if_idx, mtu=[2049, 0, 0, 0]
        )
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.egress_tap_if_idx, mtu=[2049, 0, 0, 0]
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.ingress_tap_if_idx, enable_disable=1
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.egress_tap_if_idx, enable_disable=1
        )
        self.assertTrue(start_iperf(ip_version=4))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_egress_gso_2048_mtu_ipv4(self):
        """Enable GSO on ingress & egress tap interfaces with 2048 MTU, IPv4."""
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.ingress_tap_if_idx, mtu=[2048, 0, 0, 0]
        )
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.egress_tap_if_idx, mtu=[2048, 0, 0, 0]
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.ingress_tap_if_idx, enable_disable=1
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.egress_tap_if_idx, enable_disable=1
        )
        self.assertTrue(start_iperf(ip_version=4))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_egress_gso_1500_mtu_ipv4(self):
        """Enable GSO on ingress & egress tap interfaces with 1500 MTU, IPv4."""
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.ingress_tap_if_idx, mtu=[1500, 0, 0, 0]
        )
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.egress_tap_if_idx, mtu=[1500, 0, 0, 0]
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.ingress_tap_if_idx, enable_disable=1
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.egress_tap_if_idx, enable_disable=1
        )
        self.assertTrue(start_iperf(ip_version=4))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_egress_gso_512_mtu_ipv4(self):
        """Enable GSO on egress tap interface with 512 MTU, IPv4."""
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.ingress_tap_if_idx, mtu=[512, 0, 0, 0]
        )
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.egress_tap_if_idx, mtu=[512, 0, 0, 0]
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.ingress_tap_if_idx, enable_disable=1
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.egress_tap_if_idx, enable_disable=1
        )
        self.assertTrue(start_iperf(ip_version=4))

    # Tests with GSO enabled on both ingress & egress interfaces.
    # MTUs: 9000, 9001, 2049, 2048, 1500 & 512
    # IPv6 packets
    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_egress_gso_9000_mtu_ipv6(self):
        """Enable GSO on ingress & egress tap interfaces with 9000 MTU, IPv6."""
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.ingress_tap_if_idx, mtu=[9000, 0, 0, 0]
        )
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.egress_tap_if_idx, mtu=[9000, 0, 0, 0]
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.ingress_tap_if_idx, enable_disable=1
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.egress_tap_if_idx, enable_disable=1
        )
        self.assertTrue(start_iperf(ip_version=6))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_egress_gso_9001_mtu_ipv6(self):
        """Enable GSO on ingress & egress tap interfaces with 9001 MTU, IPv6."""
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.ingress_tap_if_idx, mtu=[9001, 0, 0, 0]
        )
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.egress_tap_if_idx, mtu=[9001, 0, 0, 0]
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.ingress_tap_if_idx, enable_disable=1
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.egress_tap_if_idx, enable_disable=1
        )
        self.assertTrue(start_iperf(ip_version=6))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_egress_gso_2049_mtu_ipv6(self):
        """Enable GSO on ingress & egress tap interfaces with 2049 MTU, IPv6."""
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.ingress_tap_if_idx, mtu=[2049, 0, 0, 0]
        )
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.egress_tap_if_idx, mtu=[2049, 0, 0, 0]
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.ingress_tap_if_idx, enable_disable=1
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.egress_tap_if_idx, enable_disable=1
        )
        self.assertTrue(start_iperf(ip_version=6))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_egress_gso_2048_mtu_ipv6(self):
        """Enable GSO on ingress & egress tap interfaces with 2048 MTU, IPv6."""
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.ingress_tap_if_idx, mtu=[2048, 0, 0, 0]
        )
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.egress_tap_if_idx, mtu=[2048, 0, 0, 0]
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.ingress_tap_if_idx, enable_disable=1
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.egress_tap_if_idx, enable_disable=1
        )
        self.assertTrue(start_iperf(ip_version=6))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_egress_gso_1500_mtu_ipv6(self):
        """Enable GSO on ingress & egress tap interfaces with 1500 MTU, IPv6."""
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.ingress_tap_if_idx, mtu=[1500, 0, 0, 0]
        )
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.egress_tap_if_idx, mtu=[1500, 0, 0, 0]
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.ingress_tap_if_idx, enable_disable=1
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.egress_tap_if_idx, enable_disable=1
        )
        self.assertTrue(start_iperf(ip_version=6))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_ingress_egress_gso_512_mtu_ipv6(self):
        """Enable GSO on egress tap interface with 512 MTU, IPv6."""
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.ingress_tap_if_idx, mtu=[512, 0, 0, 0]
        )
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.egress_tap_if_idx, mtu=[512, 0, 0, 0]
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.ingress_tap_if_idx, enable_disable=1
        )
        self.vapi.feature_gso_enable_disable(
            sw_if_index=self.egress_tap_if_idx, enable_disable=1
        )
        self.assertTrue(start_iperf(ip_version=6))


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
