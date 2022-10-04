#!/usr/bin/env python3
import unittest
from ipaddress import ip_address, ip_interface
from vpp_qemu_utils import (
    create_namespace,
    delete_namespace,
    create_host_interface,
    delete_host_interfaces,
    set_interface_mtu,
    add_namespace_route,
)
from vpp_iperf import start_iperf, stop_iperf
from framework import VppTestCase, VppTestRunner
from config import config
from vpp_papi import VppEnum
import time
import sys
from vm_test_config import test_config

#
# Tests for:
# - af_packet_v2 & v3 interfaces.
# - Uses iPerf to send TCP/IP streams to VPP.
#   - af_packet ingress interface runs the iperf client
#   - af_packet egress interface runs the iperf server
# - Verifies that:
#   - TCP over IPv4 and IPv6 is enabled correctly
#     sending jumbo frames (9000/9001 MTUs) with is enabled correctly.
#     sending VPP buffer-sized frames(2048 MTU) with GSO/GRO is enabled correctly.
#     sending standard frames (1500 MTU) with GSO/GRO is enabled correctly.
#     sending smaller frames (512 MTU) with GSO/GRO is enabled correctly for IPv4
#     sending odd sized frames (9001, 2049 MTU) with GSO/GRO is enabled correctly.
#


def filter_tests(test):
    """Filter test IDs to include only those selected to run."""
    selection = test_config["tests_to_run"]
    if not selection or selection == " ":
        return True
    else:
        test_ids_to_run = []
        for test_id in selection.split(","):
            if "-" in test_id.strip():
                start, end = map(int, test_id.split("-"))
                test_ids_to_run.extend(list(range(start, end + 1)))
            elif test_id.strip():
                test_ids_to_run.append(int(test_id))
        return test["id"] in test_ids_to_run


# Test Config variables
client_namespace = test_config["client_namespace"]
server_namespace = test_config["server_namespace"]
tests = filter(filter_tests, test_config["tests"])
af_packet_config = test_config["af_packet"]
layer2 = test_config["L2"]
layer3 = test_config["L3"]


class TestAfPacketV2Qemu(VppTestCase):
    """Test VPP af_packet interfaces inside a QEMU VM for IPv4/v6.

    Test Setup:
    Linux_ns1--iperfClient--host-int1--vpp-af_packet-int1--VPP-BD
             --vppaf_packet_int2--host-int2--iperfServer--Linux_ns2
    """

    @classmethod
    def setUpClass(cls):
        super(TestAfPacketV2Qemu, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestAfPacketV2Qemu, cls).tearDownClass()

    def setUpTestToplogy(self, test, ip_version):
        """Setup the test topology.

        1. Create Linux Namespaces for iPerf Client & Server.
        2. Create VPP iPerf client and server virtual interfaces.
        3. Enable desired vif features such as GSO & GRO.
        3. Cross-Connect interfaces in VPP using L2 or L3.
        """
        super(TestAfPacketV2Qemu, self).setUp()
        client_if_type = test["client_if_type"]
        server_if_type = test["server_if_type"]
        client_if_version = test["client_if_version"]
        server_if_version = test["server_if_version"]
        x_connect_mode = test["x_connect_mode"]
        # server ip4/ip6 addresses required by iperf
        server_ip4_prefix = (
            layer2["server_ip4_prefix"]
            if x_connect_mode == "L2"
            else layer3["server_ip4_prefix"]
        )
        server_ip6_prefix = (
            layer2["server_ip6_prefix"]
            if x_connect_mode == "L2"
            else layer3["server_ip6_prefix"]
        )
        self.server_ip4_address = str(ip_interface(server_ip4_prefix).ip)
        self.server_ip6_address = str(ip_interface(server_ip6_prefix).ip)
        create_namespace([client_namespace, server_namespace])
        self.vpp_interfaces = []
        self.linux_interfaces = []
        if client_if_type == "af_packet":
            create_host_interface(
                af_packet_config["iprf_client_interface_on_linux"],
                af_packet_config["iprf_client_interface_on_vpp"],
                client_namespace,
                layer2["client_ip4_prefix"]
                if x_connect_mode == "L2"
                else layer3["client_ip4_prefix"],
                layer2["client_ip6_prefix"]
                if x_connect_mode == "L2"
                else layer3["client_ip6_prefix"],
            )
            self.ingress_if_idx = self.create_af_packet(
                version=client_if_version,
                host_if_name=af_packet_config["iprf_client_interface_on_vpp"],
                enable_gso=test["client_if_gso"],
            )
            self.vpp_interfaces.append(self.ingress_if_idx)
            self.linux_interfaces.append(
                [client_namespace, af_packet_config["iprf_client_interface_on_linux"]]
            )
        if server_if_type == "af_packet":
            create_host_interface(
                af_packet_config["iprf_server_interface_on_linux"],
                af_packet_config["iprf_server_interface_on_vpp"],
                server_namespace,
                server_ip4_prefix,
                server_ip6_prefix,
            )
            self.egress_if_idx = self.create_af_packet(
                version=server_if_version,
                host_if_name=af_packet_config["iprf_server_interface_on_vpp"],
                enable_gso=test["server_if_gso"],
            )
            self.vpp_interfaces.append(self.egress_if_idx)
            self.linux_interfaces.append(
                [server_namespace, af_packet_config["iprf_server_interface_on_linux"]]
            )
        if x_connect_mode == "L2":
            self.l2_connect_interfaces(1, self.ingress_if_idx, self.egress_if_idx)
        elif x_connect_mode == "L3":
            # L3 connect client & server side
            vrf_id = layer3["ip4_vrf"] if ip_version == 4 else layer3["ip6_vrf"]
            # IP addresses on VPP side for Iperf client and server
            vpp_client_prefix = (
                layer3["vpp_client_ip4_prefix"]
                if ip_version == 4
                else layer3["vpp_client_ip6_prefix"]
            )
            vpp_client_nexthop = str(ip_interface(vpp_client_prefix).ip)
            vpp_server_prefix = (
                layer3["vpp_server_ip4_prefix"]
                if ip_version == 4
                else layer3["vpp_server_ip6_prefix"]
            )
            vpp_server_nexthop = str(ip_interface(vpp_server_prefix).ip)
            self.l3_connect_interfaces(
                ip_version,
                vrf_id,
                (self.ingress_if_idx, vpp_client_prefix),
                (self.egress_if_idx, vpp_server_prefix),
            )
            # Setup namespace routing
            if ip_version == 4:
                add_namespace_route(client_namespace, "0.0.0.0/0", vpp_client_nexthop)
                add_namespace_route(server_namespace, "0.0.0.0/0", vpp_server_nexthop)
            else:
                add_namespace_route(client_namespace, "::/0", vpp_client_nexthop)
                add_namespace_route(server_namespace, "::/0", vpp_server_nexthop)
        # Wait for Linux IPv6 stack to become ready
        if ip_version == 6:
            time.sleep(2)

    def tearDown(self):
        try:
            self.vapi.af_packet_delete(af_packet_config["iprf_client_interface_on_vpp"])
            self.vapi.af_packet_delete(af_packet_config["iprf_server_interface_on_vpp"])
            delete_host_interfaces(
                af_packet_config["iprf_client_interface_on_linux"],
                af_packet_config["iprf_server_interface_on_linux"],
                af_packet_config["iprf_client_interface_on_vpp"],
                af_packet_config["iprf_server_interface_on_vpp"],
            )
            delete_namespace(
                [
                    client_namespace,
                    server_namespace,
                ]
            )
            stop_iperf()
        except Exception:
            pass

    def create_af_packet(self, version, host_if_name, enable_gso=0):
        """Create an af_packetv3 interface in VPP.

        Parameters:
        version -- 2 for af_packet_create_v2
                -- 3 for af_packet_create_v3
        host_if_name -- host interface name
        enable_gso -- Enable GSO on the interface when True
        """
        af_packet_mode = VppEnum.vl_api_af_packet_mode_t
        af_packet_interface_mode = af_packet_mode.AF_PACKET_API_MODE_ETHERNET
        af_packet_flags = VppEnum.vl_api_af_packet_flags_t
        af_packet_interface_flags = 0
        if enable_gso:
            af_packet_interface_flags = (
                af_packet_flags.AF_PACKET_API_FLAG_CKSUM_GSO
                | af_packet_flags.AF_PACKET_API_FLAG_QDISC_BYPASS
            )
        api_args = {
            "use_random_hw_addr": True,
            "host_if_name": host_if_name,
            "flags": af_packet_interface_flags,
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

    def l3_connect_interfaces(self, ip_version, vrf_id, *if_idx_ip_prefixes):
        """Setup routing for (if_idx, ip_prefix) inside VPP.

        arguments:
        if_idx_ip_prefixes -- sequence of (if_idx, ip_prefix) tuples
        ip_version -- 4 or 6
        vrf_id -- vrf_id
        """
        is_ipv6 = 0 if ip_version == 4 else 1
        self.vapi.ip_table_add_del(
            is_add=1, table={"table_id": vrf_id, "is_ip6": is_ipv6}
        )
        for sw_if_index, ip_prefix in if_idx_ip_prefixes:
            self.vapi.sw_interface_set_table(
                sw_if_index=sw_if_index, is_ipv6=is_ipv6, vrf_id=vrf_id
            )
            self.vapi.sw_interface_add_del_address(
                sw_if_index=sw_if_index, is_add=1, prefix=ip_interface(ip_prefix)
            )

    def set_interfaces_mtu(self, mtu, ip_version, **kwargs):
        """Set MTUs on VPP and Linux interfaces.

        arguments --
        mtu -- mtu value
        ip_version - 4 or 6
        kwargs['vpp_interfaces'] -- list of vpp interface if indexes
        kwargs['linux_interfaces'] -- list of tuples (namespace, interface_names)
        return True if mtu is set, else False
        """
        vpp_interfaces = kwargs.get("vpp_interfaces")
        linux_interfaces = kwargs.get("linux_interfaces")
        if (ip_version == 6 and mtu >= 1280) or ip_version == 4:
            for sw_if_idx in vpp_interfaces:
                self.vapi.sw_interface_set_mtu(
                    sw_if_index=sw_if_idx, mtu=[mtu, 0, 0, 0]
                )
            for namespace, interface_name in linux_interfaces:
                set_interface_mtu(
                    namespace=namespace, interface=interface_name, mtu=mtu
                )
            return True
        else:
            return False

    @unittest.skipUnless(config.extended, "part of extended tests")
    def test_vpp_interfaces(self):
        """Test vpp interfaces with various MTU values for TCP/IPv4 & IPv6."""
        for test in tests:
            for ip_version in test_config["ip_versions"]:
                self.setUpTestToplogy(test=test, ip_version=ip_version)
                # Start the Iperf server in dual stack mode
                start_iperf(ip_version=6, server_only=True)
                for mtu in test_config["mtus"]:
                    result = self.set_interfaces_mtu(
                        mtu=mtu,
                        ip_version=ip_version,
                        vpp_interfaces=self.vpp_interfaces,
                        linux_interfaces=self.linux_interfaces,
                    )
                    if result is True:
                        print(
                            f"Testing VPP interface: "
                            f"client_af_packet_v{test['client_if_version']} "
                            f"gso:{test['client_if_gso']} "
                            f"--> server_af_packet_v{test['server_if_version']} "
                            f"gso:{test['server_if_gso']} "
                            f"mtu:{mtu} mode:{test['x_connect_mode']} "
                            f"TCP/IPv{ip_version}"
                        )
                        with self.subTest(ip_version=ip_version):
                            self.assertTrue(
                                start_iperf(
                                    ip_version=ip_version,
                                    server_ipv4_address=self.server_ip4_address,
                                    server_ipv6_address=self.server_ip6_address,
                                    client_only=True,
                                )
                            )
                    else:
                        print(
                            f"Skipping test as mtu:{mtu} is invalid "
                            f"for TCP/IPv{ip_version}"
                        )
                self.tearDown()


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
