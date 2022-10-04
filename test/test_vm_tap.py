#!/usr/bin/env python3
import unittest
from ipaddress import ip_interface
from vpp_qemu_utils import create_namespace, delete_namespace
from vpp_iperf import start_iperf, stop_iperf
from framework import VppTestCase, VppTestRunner
from config import config
import time

#
# This VM test:
#  - Creates 2 VPP tapv2 interfaces.
#     - One end of the interface is attached to a VPP bridge-domain.
#     - The other end is attached to a Linux namespace on the host.
#  - Verifies that TCP/IP connection stream is successful using iPerf
#    between the two Linux namespaces over IPv4 and IPv6
#


class TestTapQemu(VppTestCase):
    """Test Tap interfaces inside a QEMU VM.

    Start an iPerf connection stream between QEMU and VPP via
    tap v2 interfaces for IPv4 and IPv6.

    Linux_ns1 -- iperf_client -- tap1 -- VPP-BD -- tap2 --
                              -- iperfServer -- Linux_ns2
    """

    @classmethod
    def setUpClass(cls):
        super(TestTapQemu, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestTapQemu, cls).tearDownClass()

    def setUp(self):
        """Perform test setup before running QEMU tests.

        1. Create a namespace for the iPerf Server & Client.
        2. Create 2 tap interfaces in VPP & add them to each namespace.
        3. Add the tap interfaces to a bridge-domain.
        """
        super(TestTapQemu, self).setUp()
        self.client_namespace = "iprf_client_ns"
        self.server_namespace = "iprf_server_ns"
        self.client_ip4_prefix = "10.0.0.101/24"
        self.server_ip4_prefix = "10.0.0.102/24"
        self.client_ip6_prefix = "2001:1::1/64"
        self.server_ip6_prefix = "2001:1::2/64"
        create_namespace(self.client_namespace)
        create_namespace(self.server_namespace)
        # Ingress tap
        self.tap1_if_idx = self.create_tap(
            101, self.client_namespace, self.client_ip4_prefix, self.client_ip6_prefix
        )
        # Egress tap
        self.tap2_if_idx = self.create_tap(
            102, self.server_namespace, self.server_ip4_prefix, self.server_ip6_prefix
        )
        self.l2_connect_interfaces(self.tap1_if_idx, self.tap2_if_idx)
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
            self.vapi.tap_delete_v2(self.tap1_if_idx)
            self.vapi.tap_delete_v2(self.tap2_if_idx)
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
        return self.vapi.api(self.vapi.papi.sw_interface_tap_v2_dump, {})

    def dump_bridge_domain_details(self):
        return self.vapi.api(self.vapi.papi.bridge_domain_dump, {"bd_id": 1})

    def l2_connect_interfaces(self, *sw_if_idxs):
        for if_idx in sw_if_idxs:
            self.vapi.api(
                self.vapi.papi.sw_interface_set_l2_bridge,
                {
                    "rx_sw_if_index": if_idx,
                    "bd_id": 1,
                    "shg": 0,
                    "port_type": 0,
                    "enable": True,
                },
            )

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_iperf_v4(self):
        """Start an iperf Ipv4 connection stream between QEMU & VPP via tap."""
        self.assertTrue(start_iperf(ip_version=4))

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_tap_iperf_v6(self):
        """Start an iperf IPv6 connection stream between QEMU & VPP via tap."""
        self.assertTrue(start_iperf(ip_version=6))


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
