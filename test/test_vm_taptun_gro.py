#!/usr/bin/env python3
import unittest
from ipaddress import ip_address, ip_interface
from vpp_qemu_utils import create_namespace, delete_namespace
from vpp_iperf import start_iperf, stop_iperf
from framework import VppTestCase, VppTestRunner
from config import config
from vpp_papi import VppEnum
import time

#
# - Tests for tapv2 and tunv2 interfaces in a routed topology with:
#        1. tapv2 as the ingress & tunv2 as the egress with GRO on the egress.
# -      2. tunv2 as the ingress & tapv2 as the egress with GRO on the egress.
# - Uses iPerf to send TCP/IP streams to VPP running inside a QEMU VM.
# - Verifies the below for TCP over IPv4 and IPv6:
#     sending jumbo frames (9000 MTU) with is enabled correctly.
#     sending VPP buffer-sized frames(2048 MTU) is enabled correctly.
#     sending standard frame (1500 MTU) is enabled correctly.
#     sending smaller frames (512 MTU) is enabled correctly.
#     sending odd sized frames (9001, 2049 MTU) is enabled correctly.
#


class TestTapTunQemuGro(VppTestCase):
    """Test VPP tapv2 & tunv2 interfaces with GRO on egress for IPv4/v6.

    Test Topology #1:                          (gro)
    Linux_ns1--iperfClient--vpptap1--VPP-vrf--vpptun1--iperfServer--Linux_ns2

    Test Topology #2:                          (gro)
    Linux_ns1--iperfClient--vpptun1--VPP-vrf--vpptap1--iperfServer--Linux_ns2
    """

    @classmethod
    def setUpClass(cls):
        super(TestTapTunQemuGro, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestTapTunQemuGro, cls).tearDownClass()

    def setUp(self):
        """Setup the test topology.

        Create Linux namespaces & set IP v4 and v6 addresses for iPerf
        client & server for IPv4 & V6.
        """
        super(TestTapTunQemuGro, self).setUp()
        self.client_namespace = "iprf_client_ns"
        self.server_namespace = "iprf_server_ns"
        self.client_ip4_prefix = "10.0.0.101/24"
        self.server_ip4_prefix = "10.0.1.102/24"
        self.client_ip6_prefix = "2001:1::1/64"
        self.server_ip6_prefix = "2001:2::2/64"
        create_namespace([self.client_namespace, self.server_namespace])

    def tearDown(self):
        try:
            delete_namespace(
                [
                    self.client_namespace,
                    self.server_namespace,
                ]
            )
            self.vapi.tap_delete_v2(self.ingress_if_idx)
            self.vapi.tap_delete_v2(self.egress_if_idx)
            self.vapi.ip_table_add_del(is_add=0, table={"table_id": 1})
            stop_iperf()
        except:
            pass

    def create_tap_tun(
        self,
        id,
        host_namespace,
        ip_version,
        host_ip4_prefix=None,
        host_ip6_prefix=None,
        host_ip4_gw=None,
        host_ip6_gw=None,
        int_type="tap",
        tap_flags=0,
    ):
        """Create a tapv2 or tunv2 interface in VPP and attach to host.

        Parameters:
        id -- interface ID
        host_namespace -- host namespace to attach the tap interface to
        ip_version -- 4 or 6
        host_ip4_prefix -- ipv4 host interface address in CIDR notation
                           if ip_version=4
        host_ip6_prefix -- ipv6 host interface address in CIDR notation
                           if ip_version=6
        host_ip4_gw -- Host IPv4 default gateway IP Address
        host_ip6_gw -- Host IPv6 default gateway IP address
        int_type -- "tap" for tapv2  &  "tun" for tunv2 interface
        flags -- Additional flags for interface creation in VPP
        """
        TapFlags = VppEnum.vl_api_tap_flags_t
        if int_type == "tun":
            tap_flags = tap_flags | TapFlags.TAP_API_FLAG_TUN
        api_args = {
            "id": id,
            "host_namespace_set": True,
            "host_namespace": host_namespace,
            "host_if_name_set": False,
            "host_bridge_set": False,
            "host_mac_addr_set": False,
            "tap_flags": tap_flags,
        }
        if ip_version == 4:
            api_args["host_ip4_prefix"] = ip_interface(host_ip4_prefix)
            api_args["host_ip4_prefix_set"] = True
            if host_ip4_gw:
                api_args["host_ip4_gw"] = ip_address(host_ip4_gw)
                api_args["host_ip4_gw_set"] = True
        if ip_version == 6:
            api_args["host_ip6_prefix"] = ip_interface(host_ip6_prefix)
            api_args["host_ip6_prefix_set"] = True
            if host_ip6_gw:
                api_args["host_ip6_gw"] = ip_address(host_ip6_gw)
                api_args["host_ip6_gw_set"] = True

        result = self.vapi.tap_create_v2(**api_args)
        sw_if_index = result.sw_if_index
        # Admin up
        self.vapi.sw_interface_set_flags(sw_if_index=sw_if_index, flags=1)
        return sw_if_index

    def create_tap_tun_egress_gro_net(
        self, ingress_int_type, egress_int_type, ip_version, mtu
    ):
        """Create an IP routed n/w topology with GRO enabled on egress int.

        Parameters:
        ingress_int_type -- Type of the ingress interface - "tap" or "tun"
        egress_int_type -- Type of the egress interface - "tap" or "tun"
        ip_version -- 4 or 6
        mtu -- ingress and egress layer 3 interface MTU
        """
        TapFlags = VppEnum.vl_api_tap_flags_t
        gro_flags = TapFlags.TAP_API_FLAG_GSO | TapFlags.TAP_API_FLAG_GRO_COALESCE
        # VPP interface IPv4 and IPv6 addresses on ingress & egress
        vpp_client_ip4_prefix = ip_interface("10.0.0.102/24")
        vpp_server_ip4_prefix = ip_interface("10.0.1.101/24")
        vpp_client_ip6_prefix = ip_interface("2001:1::2/64")
        vpp_server_ip6_prefix = ip_interface("2001:2::1/64")
        # Host Gateways
        client_ip4_gw = str(vpp_client_ip4_prefix.ip)
        client_ip6_gw = str(vpp_client_ip6_prefix.ip)
        server_ip4_gw = str(vpp_server_ip4_prefix.ip)
        server_ip6_gw = str(vpp_server_ip6_prefix.ip)
        # ingress interface - no GRO
        self.ingress_if_idx = self.create_tap_tun(
            id=101,
            host_namespace=self.client_namespace,
            ip_version=ip_version,
            host_ip4_prefix=self.client_ip4_prefix if ip_version == 4 else None,
            host_ip6_prefix=self.client_ip6_prefix if ip_version == 6 else None,
            host_ip4_gw=client_ip4_gw if ip_version == 4 else None,
            host_ip6_gw=client_ip6_gw if ip_version == 6 else None,
            int_type=ingress_int_type,
        )
        # egress interface with GSO/GRO_COALESCE
        self.egress_if_idx = self.create_tap_tun(
            id=102,
            host_namespace=self.server_namespace,
            ip_version=ip_version,
            host_ip4_prefix=self.server_ip4_prefix if ip_version == 4 else None,
            host_ip6_prefix=self.server_ip6_prefix if ip_version == 6 else None,
            host_ip4_gw=server_ip4_gw if ip_version == 4 else None,
            host_ip6_gw=server_ip6_gw if ip_version == 6 else None,
            int_type=egress_int_type,
            tap_flags=gro_flags,
        )
        # Create VRF & Set Ipv4 or IPv6 address on the VPP ingress & egress intfs.
        is_ipv6 = 0 if ip_version == 4 else 1
        # Create VRF=1
        self.vapi.ip_table_add_del(is_add=1, table={"table_id": 1, "is_ip6": is_ipv6})
        # Set interfaces in VRF=1
        for sw_if_index in (self.ingress_if_idx, self.egress_if_idx):
            self.vapi.sw_interface_set_table(
                sw_if_index=sw_if_index, is_ipv6=is_ipv6, vrf_id=1
            )
        # Set IPv4 or IPv6 address on VPP's ingress & egress interfaces
        self.vapi.sw_interface_add_del_address(
            sw_if_index=self.ingress_if_idx,
            is_add=1,
            prefix=vpp_client_ip4_prefix if not is_ipv6 else vpp_client_ip6_prefix,
        )
        self.vapi.sw_interface_add_del_address(
            sw_if_index=self.egress_if_idx,
            is_add=1,
            prefix=vpp_server_ip4_prefix if not is_ipv6 else vpp_server_ip6_prefix,
        )
        # Set MTU on ingress & egress interfaces
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.ingress_if_idx, mtu=[mtu, 0, 0, 0]
        )
        self.vapi.sw_interface_set_mtu(
            sw_if_index=self.egress_if_idx, mtu=[mtu, 0, 0, 0]
        )
        # Wait for Linux IPv4/IPv6 stack to become ready
        time.sleep(2)

    def dump_vpp_tap_interfaces(self):
        return self.vapi.sw_interface_tap_v2_dump()

    # Tests for tapv2 and tunv2 with egress GRO-Coalesce.
    # MTUs: 9000, 9001, 2049, 2048, 1500 & 512
    # TCP over IPv4
    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_ingress_tap_egress_tun_gro_9000_mtu_ipv4(self):
        """tapv2 ingress, tunv2 egress with GRO on egress - 9000 MTU, IPv4."""
        self.create_tap_tun_egress_gro_net(
            ingress_int_type="tap", egress_int_type="tun", ip_version=4, mtu=9000
        )
        server_ipv4_address = str(ip_interface(self.server_ip4_prefix).ip)
        self.assertTrue(
            start_iperf(
                ip_version=4,
                server_ipv4_address=server_ipv4_address,
            )
        )

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_ingress_tap_egress_tun_gro_9001_mtu_ipv4(self):
        """tapv2 ingress, tunv2 egress with GRO on egress - 9001 MTU, IPv4."""
        self.create_tap_tun_egress_gro_net(
            ingress_int_type="tap", egress_int_type="tun", ip_version=4, mtu=9001
        )
        server_ipv4_address = str(ip_interface(self.server_ip4_prefix).ip)
        self.assertTrue(
            start_iperf(
                ip_version=4,
                server_ipv4_address=server_ipv4_address,
            )
        )

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_ingress_tap_egress_tun_gro_2048_mtu_ipv4(self):
        """tapv2 ingress, tunv2 egress with GRO on egress - 2048 MTU, IPv4."""
        self.create_tap_tun_egress_gro_net(
            ingress_int_type="tap", egress_int_type="tun", ip_version=4, mtu=2048
        )
        server_ipv4_address = str(ip_interface(self.server_ip4_prefix).ip)
        self.assertTrue(
            start_iperf(
                ip_version=4,
                server_ipv4_address=server_ipv4_address,
            )
        )

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_ingress_tap_egress_tun_gro_2049_mtu_ipv4(self):
        """tapv2 ingress, tunv2 egress with GRO on egress - 2049 MTU, IPv4."""
        self.create_tap_tun_egress_gro_net(
            ingress_int_type="tap", egress_int_type="tun", ip_version=4, mtu=2049
        )
        server_ipv4_address = str(ip_interface(self.server_ip4_prefix).ip)
        self.assertTrue(
            start_iperf(
                ip_version=4,
                server_ipv4_address=server_ipv4_address,
            )
        )

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_ingress_tap_egress_tun_gro_1500_mtu_ipv4(self):
        """tapv2 ingress, tunv2 egress with GRO on egress - 1500 MTU, IPv4."""
        self.create_tap_tun_egress_gro_net(
            ingress_int_type="tap", egress_int_type="tun", ip_version=4, mtu=1500
        )
        server_ipv4_address = str(ip_interface(self.server_ip4_prefix).ip)
        self.assertTrue(
            start_iperf(
                ip_version=4,
                server_ipv4_address=server_ipv4_address,
            )
        )

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_ingress_tap_egress_tun_gro_512_mtu_ipv4(self):
        """tapv2 ingress, tunv2 egress with GRO on egress - 512 MTU, IPv4."""
        self.create_tap_tun_egress_gro_net(
            ingress_int_type="tap", egress_int_type="tun", ip_version=4, mtu=512
        )
        server_ipv4_address = str(ip_interface(self.server_ip4_prefix).ip)
        self.assertTrue(
            start_iperf(
                ip_version=4,
                server_ipv4_address=server_ipv4_address,
            )
        )

    # Tests for tapv2 and tunv2 with egress GRO-Coalesce.
    # # MTUs: 9000, 9001, 2049, 2048, 1500 & 512
    # # TCP over IPv6
    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_ingress_tap_egress_tun_gro_9000_mtu_ipv6(self):
        """tapv2 ingress, tunv2 egress with GRO on egress - 9000 MTU, IPv6."""
        self.create_tap_tun_egress_gro_net(
            ingress_int_type="tap", egress_int_type="tun", ip_version=6, mtu=9000
        )
        server_ipv6_address = str(ip_interface(self.server_ip6_prefix).ip)
        self.assertTrue(
            start_iperf(
                ip_version=6,
                server_ipv6_address=server_ipv6_address,
            )
        )

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_ingress_tap_egress_tun_gro_9001_mtu_ipv6(self):
        """tapv2 ingress, tunv2 egress with GRO on egress - 9001 MTU, IPv6."""
        self.create_tap_tun_egress_gro_net(
            ingress_int_type="tap", egress_int_type="tun", ip_version=6, mtu=9001
        )
        server_ipv6_address = str(ip_interface(self.server_ip6_prefix).ip)
        self.assertTrue(
            start_iperf(
                ip_version=6,
                server_ipv6_address=server_ipv6_address,
            )
        )

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_ingress_tap_egress_tun_gro_2048_mtu_ipv6(self):
        """tapv2 ingress, tunv2 egress with GRO on egress - 2048 MTU, IPv6."""
        self.create_tap_tun_egress_gro_net(
            ingress_int_type="tap", egress_int_type="tun", ip_version=6, mtu=2048
        )
        server_ipv6_address = str(ip_interface(self.server_ip6_prefix).ip)
        self.assertTrue(
            start_iperf(
                ip_version=6,
                server_ipv6_address=server_ipv6_address,
            )
        )

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_ingress_tap_egress_tun_gro_2049_mtu_ipv6(self):
        """tapv2 ingress, tunv2 egress with GRO on egress - 2049 MTU, IPv6."""
        self.create_tap_tun_egress_gro_net(
            ingress_int_type="tap", egress_int_type="tun", ip_version=6, mtu=2049
        )
        server_ipv6_address = str(ip_interface(self.server_ip6_prefix).ip)
        self.assertTrue(
            start_iperf(
                ip_version=6,
                server_ipv6_address=server_ipv6_address,
            )
        )

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_ingress_tap_egress_tun_gro_1500_mtu_ipv6(self):
        """tapv2 ingress, tunv2 egress with GRO on egress - 1500 MTU, IPv6."""
        self.create_tap_tun_egress_gro_net(
            ingress_int_type="tap", egress_int_type="tun", ip_version=6, mtu=1500
        )
        server_ipv6_address = str(ip_interface(self.server_ip6_prefix).ip)
        self.assertTrue(
            start_iperf(
                ip_version=6,
                server_ipv6_address=server_ipv6_address,
            )
        )

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_ingress_tap_egress_tun_gro_512_mtu_ipv6(self):
        """tapv2 ingress, tunv2 egress with GRO on egress - 512 MTU, IPv6."""
        self.create_tap_tun_egress_gro_net(
            ingress_int_type="tap", egress_int_type="tun", ip_version=6, mtu=512
        )
        server_ipv6_address = str(ip_interface(self.server_ip6_prefix).ip)
        self.assertTrue(
            start_iperf(
                ip_version=6,
                server_ipv6_address=server_ipv6_address,
            )
        )

    # Tests for tapv2 and tunv2 with egress GRO-Coalesce.
    # # MTUs: 9000, 9001, 2049, 2048, 1500 & 512
    # # IPv4 packets
    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_ingress_tun_egress_tap_gro_9000_mtu_ipv4(self):
        """tunv2 ingress, tapv2 egress with GRO on egress - 9000 MTU, IPv4."""
        self.create_tap_tun_egress_gro_net(
            ingress_int_type="tun", egress_int_type="tap", ip_version=4, mtu=9000
        )
        server_ipv4_address = str(ip_interface(self.server_ip4_prefix).ip)
        self.assertTrue(
            start_iperf(
                ip_version=4,
                server_ipv4_address=server_ipv4_address,
            )
        )

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_ingress_tun_egress_tap_gro_9001_mtu_ipv4(self):
        """tunv2 ingress, tapv2 egress with GRO on egress - 9001 MTU, IPv4."""
        self.create_tap_tun_egress_gro_net(
            ingress_int_type="tun", egress_int_type="tap", ip_version=4, mtu=9001
        )
        server_ipv4_address = str(ip_interface(self.server_ip4_prefix).ip)
        self.assertTrue(
            start_iperf(
                ip_version=4,
                server_ipv4_address=server_ipv4_address,
            )
        )

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_ingress_tun_egress_tap_gro_2048_mtu_ipv4(self):
        """tunv2 ingress, tapv2 egress with GRO on egress - 2048 MTU, IPv4."""
        self.create_tap_tun_egress_gro_net(
            ingress_int_type="tun", egress_int_type="tap", ip_version=4, mtu=2048
        )
        server_ipv4_address = str(ip_interface(self.server_ip4_prefix).ip)
        self.assertTrue(
            start_iperf(
                ip_version=4,
                server_ipv4_address=server_ipv4_address,
            )
        )

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_ingress_tun_egress_tap_gro_2049_mtu_ipv4(self):
        """tunv2 ingress, tapv2 egress with GRO on egress - 2049 MTU, IPv4."""
        self.create_tap_tun_egress_gro_net(
            ingress_int_type="tun", egress_int_type="tap", ip_version=4, mtu=2049
        )
        server_ipv4_address = str(ip_interface(self.server_ip4_prefix).ip)
        self.assertTrue(
            start_iperf(
                ip_version=4,
                server_ipv4_address=server_ipv4_address,
            )
        )

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_ingress_tun_egress_tap_gro_1500_mtu_ipv4(self):
        """tunv2 ingress, tapv2 egress with GRO on egress - 1500 MTU, IPv4."""
        self.create_tap_tun_egress_gro_net(
            ingress_int_type="tun", egress_int_type="tap", ip_version=4, mtu=1500
        )
        server_ipv4_address = str(ip_interface(self.server_ip4_prefix).ip)
        self.assertTrue(
            start_iperf(
                ip_version=4,
                server_ipv4_address=server_ipv4_address,
            )
        )

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_ingress_tun_egress_tap_gro_512_mtu_ipv4(self):
        """tunv2 ingress, tapv2 egress with GRO on egress - 512 MTU, IPv4."""
        self.create_tap_tun_egress_gro_net(
            ingress_int_type="tun", egress_int_type="tap", ip_version=4, mtu=512
        )
        server_ipv4_address = str(ip_interface(self.server_ip4_prefix).ip)
        self.assertTrue(
            start_iperf(
                ip_version=4,
                server_ipv4_address=server_ipv4_address,
            )
        )

    # Tests for tapv2 and tunv2 with egress GRO-Coalesce.
    # # MTUs: 9000, 9001, 2049, 2048, 1500 & 512
    # # IPv6
    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_ingress_tun_egress_tap_gro_9000_mtu_ipv6(self):
        """tunv2 ingress, tapv2 egress with GRO on egress - 9000 MTU, IPv6."""
        self.create_tap_tun_egress_gro_net(
            ingress_int_type="tun", egress_int_type="tap", ip_version=6, mtu=9000
        )
        server_ipv6_address = str(ip_interface(self.server_ip6_prefix).ip)
        self.assertTrue(
            start_iperf(
                ip_version=6,
                server_ipv6_address=server_ipv6_address,
            )
        )

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_ingress_tun_egress_tap_gro_9001_mtu_ipv6(self):
        """tunv2 ingress, tapv2 egress with GRO on egress - 9001 MTU, IPv6."""
        self.create_tap_tun_egress_gro_net(
            ingress_int_type="tun", egress_int_type="tap", ip_version=6, mtu=9001
        )
        server_ipv6_address = str(ip_interface(self.server_ip6_prefix).ip)
        self.assertTrue(
            start_iperf(
                ip_version=6,
                server_ipv6_address=server_ipv6_address,
            )
        )

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_ingress_tun_egress_tap_gro_2048_mtu_ipv6(self):
        """tunv2 ingress, tapv2 egress with GRO on egress - 2048 MTU, IPv6."""
        self.create_tap_tun_egress_gro_net(
            ingress_int_type="tun", egress_int_type="tap", ip_version=6, mtu=2048
        )
        server_ipv6_address = str(ip_interface(self.server_ip6_prefix).ip)
        self.assertTrue(
            start_iperf(
                ip_version=6,
                server_ipv6_address=server_ipv6_address,
            )
        )

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_ingress_tun_egress_tap_gro_2049_mtu_ipv6(self):
        """tunv2 ingress, tapv2 egress with GRO on egress - 2049 MTU, IPv6."""
        self.create_tap_tun_egress_gro_net(
            ingress_int_type="tun", egress_int_type="tap", ip_version=6, mtu=2049
        )
        server_ipv6_address = str(ip_interface(self.server_ip6_prefix).ip)
        self.assertTrue(
            start_iperf(
                ip_version=6,
                server_ipv6_address=server_ipv6_address,
            )
        )

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_ingress_tun_egress_tap_gro_1500_mtu_ipv6(self):
        """tunv2 ingress, tapv2 egress with GRO on egress - 1500 MTU, IPv6."""
        self.create_tap_tun_egress_gro_net(
            ingress_int_type="tun", egress_int_type="tap", ip_version=6, mtu=1500
        )
        server_ipv6_address = str(ip_interface(self.server_ip6_prefix).ip)
        self.assertTrue(
            start_iperf(
                ip_version=6,
                server_ipv6_address=server_ipv6_address,
            )
        )

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_ingress_tun_egress_tap_gro_512_mtu_ipv6(self):
        """tunv2 ingress, tapv2 egress with GRO on egress - 512 MTU, IPv6."""
        self.create_tap_tun_egress_gro_net(
            ingress_int_type="tun", egress_int_type="tap", ip_version=6, mtu=512
        )
        server_ipv6_address = str(ip_interface(self.server_ip6_prefix).ip)
        self.assertTrue(
            start_iperf(
                ip_version=6,
                server_ipv6_address=server_ipv6_address,
            )
        )


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
