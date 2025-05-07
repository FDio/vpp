#!/usr/bin/env python3
import unittest
from ipaddress import ip_address, ip_interface, ip_network
from vpp_qemu_utils import (
    create_namespace,
    delete_all_namespaces,
    create_host_interface,
    delete_all_host_interfaces,
    set_interface_mtu,
    disable_interface_gso,
    add_namespace_route,
    libmemif_test_app,
    create_ipip_tunnel_linux,
    assign_loopback_ips,
)
from vpp_iperf import start_iperf, stop_iperf
from framework import VppTestCase
from asfframework import VppTestRunner, tag_fixme_debian11, is_distro_debian11
from config import config
from vpp_papi import VppEnum
import time
import sys
import os
from vm_test_config import test_config
from vpp_ip_route import VppRoutePath, VppIpRoute

#
# Tests for:
# - tapv2, tunv2, af_packet_v2/v3 & memif interfaces.
# - reads test config from the file vm_test_config.py
# - Uses iPerf to send TCP/IP streams to VPP
#   - VPP ingress interface runs the iperf client
#   - VPP egress interface runs the iperf server
# - Runs tests specified in the vm_test_config module and verifies that:
#   - TCP over IPv4 and IPv6 is enabled correctly for Bridged and Routed topologies.
#     sending jumbo frames (9000/9001 MTUs) with GSO/GRO is enabled correctly.
#     sending VPP buffer-sized frames(2048 MTU) with GSO/GRO is enabled correctly.
#     sending standard frames (1500 MTU) with GSO/GRO is enabled correctly.
#     sending smaller frames (512 MTU) with GSO/GRO is enabled correctly for IPv4
#     sending odd sized frames (9001, 2049 MTU) with GSO/GRO is enabled correctly.
#


class TestSelector:
    """Selects specified test(s) from vm_test_config to run

    The selected_test field specifies a comma separated or range(s) of
    tests to run (default='' i.e all_tests) e.g. setting the selected_tests
    attribute to "1,3-4,19-23" runs tests with ID's 1, 3, 4, 19, 20, 21,
    22 & 23 from the spec file vm_test_config
    """

    def __init__(self, selected_tests="") -> None:
        self.selected_tests = selected_tests

    def filter_tests(self, test):
        """Works with the filter fn. to include only selected tests."""

        if self.selected_tests:
            selection = self.selected_tests
        else:
            selection = test_config["tests_to_run"]

        if not selection or selection == " ":
            return True

        test_ids_to_run = []
        for test_id in selection.split(","):
            if "-" in test_id.strip():
                start, end = map(int, test_id.split("-"))
                test_ids_to_run.extend(list(range(start, end + 1)))
            elif test_id.strip():
                test_ids_to_run.append(int(test_id))
        return test["id"] in test_ids_to_run


# Test Config variables
af_packet_config = test_config["af_packet"]
layer2 = test_config["L2"]
layer3 = test_config["L3"]


def create_test(test_name, test, ip_version, mtu):
    """Create and return a unittest method for a test."""

    @unittest.skipIf(
        is_distro_debian11, "FIXME intermittent test failures on debian11 distro"
    )
    @unittest.skipIf(
        config.skip_netns_tests, "netns not available or disabled from cli"
    )
    def test_func(self):
        self.logger.debug(f"Starting unittest:{test_name}")
        self.setUpTestToplogy(test=test, ip_version=ip_version)
        result = self.set_interfaces_mtu(
            mtu=mtu,
            ip_version=ip_version,
            vpp_interfaces=self.vpp_interfaces,
            linux_interfaces=self.linux_interfaces,
        )
        if "memif" in self.if_types:
            self.logger.debug("Starting libmemif test_app for memif test")
            self.memif_process = libmemif_test_app(
                memif_sock_path=self.get_memif_sock_path(), logger=self.logger
            )
        if result is True:
            # Determine server and client IPs for iperf
            # Defaults are interface IPs
            server_ip_for_iperf_v4 = self.server_ip4_address
            server_ip_for_iperf_v6 = self.server_ip6_address
            client_bind_ip_for_iperf_v4 = self.client_ip4_address
            client_bind_ip_for_iperf_v6 = self.client_ip6_address

            if "ipip" in self.if_types:
                server_ip_for_iperf_v4 = str(
                    ip_interface(layer3["server_loopback_ip4_prefix"]).ip
                )
                server_ip_for_iperf_v6 = str(
                    ip_interface(layer3["server_loopback_ip6_prefix"]).ip
                )
                client_bind_ip_for_iperf_v4 = str(
                    ip_interface(layer3["client_loopback_ip4_prefix"]).ip
                )
                client_bind_ip_for_iperf_v6 = str(
                    ip_interface(layer3["client_loopback_ip6_prefix"]).ip
                )

            # Start an instance of an iperf server using
            # a unique port. Save the iperf cmdline for
            # terminating the iperf_server process after the test.
            self.iperf_cmd = start_iperf(
                ip_version=ip_version,
                client_ns=self.client_namespace,
                server_ns=self.server_namespace,
                server_ipv4_address=server_ip_for_iperf_v4,
                server_ipv6_address=server_ip_for_iperf_v6,
                server_only=True,
                server_args=f"-p {self.iperf_port}",
                logger=self.logger,
            )
            # Send traffic between iperf client & server
            self.assertTrue(
                start_iperf(
                    ip_version=ip_version,
                    client_ns=self.client_namespace,
                    server_ns=self.server_namespace,
                    server_ipv4_address=server_ip_for_iperf_v4,  # Client connects to this server IP if ip_version=4
                    server_ipv6_address=server_ip_for_iperf_v6,  # Client connects to this server IP if ip_version=6
                    client_ipv4_address=client_bind_ip_for_iperf_v4,  # Client binds to this IP if ip_version=4
                    client_ipv6_address=client_bind_ip_for_iperf_v6,  # Client binds to this IP if ip_version=6
                    client_args=f"-p {self.iperf_port}",
                    client_only=True,
                    duration=2,
                    logger=self.logger,
                )
            )
        else:
            return unittest.skip(
                f"Skipping test:{test_name} as mtu:{mtu} is "
                f"invalid for TCP/IPv{ip_version}"
            )

    test_func.__name__ = test_name
    return test_func


def generate_vpp_interface_tests(tests, test_class, ip_versions=None, mtus=None):
    """Generate unittests for testing vpp interfaces

    Generates unittests from test spec. and sets them as attributes
    to the test_class.
    Args:
       tests      : list of test specs from vm_test_config['tests']
       test_class : the name of the test class to which the
                    generated tests are set as attributes.
       ip_versions : list of ip versions to run the tests for
       mtus       : list of MTU sizes to run the tests for
    """
    if ip_versions is None:
        ip_versions = test_config["ip_versions"]
    if mtus is None:
        mtus = test_config["mtus"]

    for test in tests:
        for ip_version in ip_versions:
            for mtu in mtus:
                test_name = (
                    f"test_id_{test['id']}_"
                    + f"client_{test['client_if_type']}"
                    + f"_v{test['client_if_version']}_"
                    + f"gso_{test.get('client_if_gso', 0)}_"
                    + f"gro_{test.get('client_if_gro', 0)}_"
                    + f"checksum_{test.get('client_if_checksum_offload', 0)}_"
                    + f"to_server_{test['server_if_type']}"
                    + f"_v{test['server_if_version']}_"
                    + f"gso_{test.get('server_if_gso', 0)}_"
                    + f"gro_{test.get('server_if_gro', 0)}_"
                    + f"checksum_{test.get('server_if_checksum_offload', 0)}_"
                    + f"mtu_{mtu}_mode_{test['x_connect_mode']}_"
                    + f"tcp_ipv{ip_version}"
                )
                test_func = create_test(
                    test_name=test_name, test=test, ip_version=ip_version, mtu=mtu
                )
                setattr(test_class, test_name, test_func)


@tag_fixme_debian11
class TestVPPInterfacesQemu:
    """Test VPP interfaces inside a QEMU VM for IPv4/v6.

    Test Setup:
    Linux_ns1--iperfClient--host-int1--vpp-af_packet-int1--VPP-BD
             --vppaf_packet_int2--host-int2--iperfServer--Linux_ns2
    """

    def setUpTestToplogy(self, test, ip_version):
        """Setup the test topology.

        1. Create Linux Namespaces for iPerf Client & Server.
        2. Create VPP iPerf client and server virtual interfaces.
        3. Enable desired vif features such as GSO & GRO.
        3. Cross-Connect interfaces in VPP using L2 or L3.
        """

        # Need to support multiple interface types as the memif interface
        # in VPP is connected to the iPerf client & server by x-connecting
        # to a tap interface in their respective namespaces.
        client_if_types = test["client_if_type"].split(",")
        server_if_types = test["server_if_type"].split(",")
        client_if_version = test["client_if_version"]
        server_if_version = test["server_if_version"]
        x_connect_mode = test["x_connect_mode"]
        # server ip4/ip6 addresses required by iperf client
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
        # client ip4/ip6 addresses required by ipip tunnel termination
        client_ip4_prefix = (
            layer2["client_ip4_prefix"]
            if x_connect_mode == "L2"
            else layer3["client_ip4_prefix"]
        )
        client_ip6_prefix = (
            layer2["client_ip6_prefix"]
            if x_connect_mode == "L2"
            else layer3["client_ip6_prefix"]
        )
        self.server_ip4_address = str(ip_interface(server_ip4_prefix).ip)
        self.server_ip6_address = str(ip_interface(server_ip6_prefix).ip)
        self.client_ip4_address = str(ip_interface(client_ip4_prefix).ip)
        self.client_ip6_address = str(ip_interface(client_ip6_prefix).ip)
        # next-hop IP address on VPP for routing from client & server namespaces
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
        # Create unique namespaces for iperf client & iperf server to
        # prevent conflicts when TEST_JOBS > 1
        self.client_namespace = test_config["client_namespace"] + str(test["id"])
        self.server_namespace = test_config["server_namespace"] + str(test["id"])
        self.ns_history_file = (
            f"{config.tmp_dir}/vpp-unittest-{self.__class__.__name__}/history_ns.txt"
        )
        self.if_history_name = (
            f"{config.tmp_dir}/vpp-unittest-{self.__class__.__name__}/history_if.txt"
        )
        delete_all_namespaces(self.ns_history_file)
        create_namespace(
            self.ns_history_file, ns=[self.client_namespace, self.server_namespace]
        )
        # Set a unique iPerf port for parallel server and client runs
        self.iperf_port = 5000 + test["id"]
        # IPerf client & server ingress/egress interface indexes in VPP
        self.tap_interfaces = []
        self.memif_interfaces = []
        self.ingress_if_idxes = []
        self.egress_if_idxes = []
        self.vpp_interfaces = []
        self.linux_interfaces = []
        vrf_id = layer3["ip4_vrf"] if ip_version == 4 else layer3["ip6_vrf"]
        # ipip tunnel ingress and egress interfaces on VPP
        self.ipip_tunnel_interfaces = []
        self.ipip_tunnel_instance_ingress = test_config["ipip_tunnel_instance_ingress"]
        self.ipip_tunnel_instance_egress = test_config["ipip_tunnel_instance_egress"]
        # ipip tunnel ingress and egress prefixes on VPP
        # ingress == iperf_client namespace facing tunnel endpoint IP on VPP
        # egress == iperf_server namespace facing tunnel endpoint IP on VPP
        self.ipip_ingress_prefix_vpp_ip4 = layer3["vpp_ipip_client_ip4_prefix"]
        self.ipip_egress_prefix_vpp_ip4 = layer3["vpp_ipip_server_ip4_prefix"]
        self.ipip_ingress_prefix_vpp_ip6 = layer3["vpp_ipip_client_ip6_prefix"]
        self.ipip_egress_prefix_vpp_ip6 = layer3["vpp_ipip_server_ip6_prefix"]
        # Linux side of the tunnel endpoint IP address that corresponds to the
        # VPP's tunnel endpoint IP network
        self.ipip_ingress_prefix_linux_ip4 = layer3["linux_ipip_client_ip4_prefix"]
        self.ipip_egress_prefix_linux_ip4 = layer3["linux_ipip_server_ip4_prefix"]
        self.ipip_ingress_prefix_linux_ip6 = layer3["linux_ipip_client_ip6_prefix"]
        self.ipip_egress_prefix_linux_ip6 = layer3["linux_ipip_server_ip6_prefix"]
        # Setup loopback interfaces in Linux for tunnelling traffic
        # between iperf client & server for tunnel mode tests
        assign_loopback_ips(
            self.client_namespace,
            ipv4=layer3["client_loopback_ip4_prefix"],
            ipv6=layer3["client_loopback_ip6_prefix"],
        )
        assign_loopback_ips(
            self.server_namespace,
            ipv4=layer3["server_loopback_ip4_prefix"],
            ipv6=layer3["server_loopback_ip6_prefix"],
        )
        enable_client_if_gso = test.get("client_if_gso", 0)
        enable_server_if_gso = test.get("server_if_gso", 0)
        enable_client_if_gro = test.get("client_if_gro", 0)
        enable_server_if_gro = test.get("server_if_gro", 0)
        enable_client_if_checksum_offload = test.get("client_if_checksum_offload", 0)
        enable_server_if_checksum_offload = test.get("server_if_checksum_offload", 0)

        # Create unique host interfaces in Linux and VPP for connecting to iperf
        # client & iperf server to prevent conflicts when TEST_JOBS > 1
        self.iprf_client_host_interface_on_linux = af_packet_config[
            "iprf_client_interface_on_linux"
        ] + str(test["id"])
        self.iprf_client_host_interface_on_vpp = af_packet_config[
            "iprf_client_interface_on_vpp"
        ] + str(test["id"])
        self.iprf_server_host_interface_on_linux = af_packet_config[
            "iprf_server_interface_on_linux"
        ] + str(test["id"])
        self.iprf_server_host_interface_on_vpp = af_packet_config[
            "iprf_server_interface_on_vpp"
        ] + str(test["id"])
        # Handle client interface types
        delete_all_host_interfaces(self.if_history_name)
        for client_if_type in client_if_types:
            if client_if_type == "af_packet":
                create_host_interface(
                    self.if_history_name,
                    self.client_namespace,
                    (
                        layer2["client_ip4_prefix"]
                        if x_connect_mode == "L2"
                        else layer3["client_ip4_prefix"]
                    ),
                    (
                        layer2["client_ip6_prefix"]
                        if x_connect_mode == "L2"
                        else layer3["client_ip6_prefix"]
                    ),
                    vpp_if_name=self.iprf_client_host_interface_on_vpp,
                    host_if_name=self.iprf_client_host_interface_on_linux,
                )
                self.ingress_if_idx = self.create_af_packet(
                    version=client_if_version,
                    host_if_name=self.iprf_client_host_interface_on_vpp,
                    enable_gso=enable_client_if_gso,
                )
                self.ingress_if_idxes.append(self.ingress_if_idx)
                self.vpp_interfaces.append(self.ingress_if_idx)
                self.linux_interfaces.append(
                    ["", self.iprf_client_host_interface_on_vpp]
                )
                self.linux_interfaces.append(
                    [
                        self.client_namespace,
                        self.iprf_client_host_interface_on_linux,
                    ]
                )
                if enable_client_if_gso == 0:
                    disable_interface_gso("", self.iprf_client_host_interface_on_vpp)
                    disable_interface_gso(
                        self.client_namespace,
                        self.iprf_client_host_interface_on_linux,
                    )
            elif client_if_type == "tap" or client_if_type == "tun":
                self.ingress_if_idx = self.create_tap_tun(
                    id=101,
                    host_namespace=self.client_namespace,
                    ip_version=ip_version,
                    host_ip4_prefix=(
                        layer2["client_ip4_prefix"]
                        if x_connect_mode == "L2"
                        else layer3["client_ip4_prefix"]
                    ),
                    host_ip6_prefix=(
                        layer2["client_ip6_prefix"]
                        if x_connect_mode == "L2"
                        else layer3["client_ip6_prefix"]
                    ),
                    int_type=client_if_type,
                    host_if_name=f"{client_if_type}0",
                    enable_gso=enable_client_if_gso,
                    enable_gro=enable_client_if_gro,
                    enable_checksum_offload=enable_client_if_checksum_offload,
                )
                self.tap_interfaces.append(self.ingress_if_idx)
                self.ingress_if_idxes.append(self.ingress_if_idx)
                self.vpp_interfaces.append(self.ingress_if_idx)
                self.linux_interfaces.append(
                    [self.client_namespace, f"{client_if_type}0"]
                )
                # Seeing TCP timeouts if tx=on & rx=on Linux tap & tun interfaces
                disable_interface_gso(self.client_namespace, f"{client_if_type}0")
            elif client_if_type == "memif":
                self.ingress_if_idx = self.create_memif(
                    memif_id=0, mode=0 if x_connect_mode == "L2" else 1
                )
                self.memif_interfaces.append(self.ingress_if_idx)
                self.ingress_if_idxes.append(self.ingress_if_idx)
                self.vpp_interfaces.append(self.ingress_if_idx)
            elif client_if_type == "ipip":
                # Create ipip tunnel interface in VPP from iperf client
                # to iperf server
                if ip_version == 4:
                    self.ingress_ipip_if_idx = self.create_ipip_tunnel_vpp(
                        # interface ip on VPP connecting to iperf client
                        src_ip=vpp_client_nexthop,
                        # interface ip on Linux on iperf server connecting
                        # to VPP terminates the tunnel
                        dst_ip=self.server_ip4_address,
                        tunnel_instance=self.ipip_tunnel_instance_ingress,
                        table_id=vrf_id,
                        ip_version=ip_version,
                    )
                    # Create the other end of ipip tunnel interface on the Linux
                    # iperf_server namespace
                    create_ipip_tunnel_linux(
                        ip_version=4,
                        tunnel_name=f"ipip{self.ipip_tunnel_instance_ingress}",
                        src_ip=self.server_ip4_address,
                        dst_ip=vpp_client_nexthop,
                        tunnel_ip=self.ipip_ingress_prefix_linux_ip4,
                        namespace=self.server_namespace,
                    )
                else:
                    self.ingress_ipip_if_idx = self.create_ipip_tunnel_vpp(
                        src_ip=vpp_client_nexthop,
                        dst_ip=self.server_ip6_address,
                        tunnel_instance=self.ipip_tunnel_instance_ingress,
                        table_id=vrf_id,
                        ip_version=ip_version,
                    )
                    create_ipip_tunnel_linux(
                        ip_version=6,
                        tunnel_name=f"ipip{self.ipip_tunnel_instance_ingress}",
                        src_ip=self.server_ip6_address,
                        dst_ip=vpp_client_nexthop,
                        tunnel_ip=self.ipip_ingress_prefix_linux_ip6,
                        namespace=self.server_namespace,
                    )
                self.ipip_tunnel_interfaces.append(self.ingress_ipip_if_idx)
                self.vpp_interfaces.append(self.ingress_ipip_if_idx)
                self.linux_interfaces.append(
                    [self.server_namespace, f"ipip{self.ipip_tunnel_instance_ingress}"]
                )
            else:
                print(
                    f"Unsupported client interface type: {client_if_type} "
                    f"for test - ID={test['id']}"
                )
                sys.exit(1)
        for server_if_type in server_if_types:
            if server_if_type == "af_packet":
                create_host_interface(
                    self.if_history_name,
                    self.server_namespace,
                    server_ip4_prefix,
                    server_ip6_prefix,
                    vpp_if_name=self.iprf_server_host_interface_on_vpp,
                    host_if_name=self.iprf_server_host_interface_on_linux,
                )
                self.egress_if_idx = self.create_af_packet(
                    version=server_if_version,
                    host_if_name=self.iprf_server_host_interface_on_vpp,
                    enable_gso=enable_server_if_gso,
                )
                self.egress_if_idxes.append(self.egress_if_idx)
                self.vpp_interfaces.append(self.egress_if_idx)
                self.linux_interfaces.append(
                    ["", self.iprf_server_host_interface_on_vpp]
                )
                self.linux_interfaces.append(
                    [
                        self.server_namespace,
                        self.iprf_server_host_interface_on_linux,
                    ]
                )
                if enable_server_if_gso == 0:
                    disable_interface_gso("", self.iprf_server_host_interface_on_vpp)
                    disable_interface_gso(
                        self.server_namespace,
                        self.iprf_server_host_interface_on_linux,
                    )
            elif server_if_type == "tap" or server_if_type == "tun":
                self.egress_if_idx = self.create_tap_tun(
                    id=102,
                    host_namespace=self.server_namespace,
                    ip_version=ip_version,
                    host_ip4_prefix=(
                        layer2["server_ip4_prefix"]
                        if x_connect_mode == "L2"
                        else layer3["server_ip4_prefix"]
                    ),
                    host_ip6_prefix=(
                        layer2["server_ip6_prefix"]
                        if x_connect_mode == "L2"
                        else layer3["server_ip6_prefix"]
                    ),
                    int_type=server_if_type,
                    host_if_name=f"{server_if_type}0",
                    enable_gso=enable_server_if_gso,
                    enable_gro=enable_server_if_gro,
                    enable_checksum_offload=enable_server_if_checksum_offload,
                )
                self.tap_interfaces.append(self.egress_if_idx)
                self.egress_if_idxes.append(self.egress_if_idx)
                self.vpp_interfaces.append(self.egress_if_idx)
                self.linux_interfaces.append(
                    [self.server_namespace, f"{server_if_type}0"]
                )
                # Seeing TCP timeouts if tx=on & rx=on Linux tap & tun interfaces
                disable_interface_gso(self.server_namespace, f"{server_if_type}0")
            elif server_if_type == "memif":
                self.egress_if_idx = self.create_memif(
                    memif_id=1, mode=0 if x_connect_mode == "L2" else 1
                )
                self.memif_interfaces.append(self.egress_if_idx)
                self.egress_if_idxes.append(self.egress_if_idx)
                self.vpp_interfaces.append(self.egress_if_idx)
            elif server_if_type == "ipip":
                # Create ipip tunnel interface in VPP originating from
                # iperf server to iperf client
                if ip_version == 4:
                    self.egress_ipip_if_idx = self.create_ipip_tunnel_vpp(
                        # interface ip on VPP connecting to iperf server
                        src_ip=vpp_server_nexthop,
                        # interface ip on Linux on iperf client connecting
                        # to VPP
                        dst_ip=self.client_ip4_address,
                        tunnel_instance=self.ipip_tunnel_instance_egress,
                        table_id=vrf_id,
                        ip_version=ip_version,
                    )
                    # Create the ipip tunnel interface on the Linux host
                    # connecting to the VPP ipip tunnel interface on iperf server
                    create_ipip_tunnel_linux(
                        ip_version=4,
                        tunnel_name=f"ipip{self.ipip_tunnel_instance_egress}",
                        src_ip=self.client_ip4_address,
                        dst_ip=vpp_server_nexthop,
                        tunnel_ip=self.ipip_egress_prefix_linux_ip4,
                        namespace=self.client_namespace,
                    )
                else:
                    self.egress_ipip_if_idx = self.create_ipip_tunnel_vpp(
                        src_ip=vpp_server_nexthop,
                        dst_ip=self.client_ip6_address,
                        tunnel_instance=self.ipip_tunnel_instance_egress,
                        table_id=vrf_id,
                        ip_version=ip_version,
                    )
                    create_ipip_tunnel_linux(
                        ip_version=6,
                        tunnel_name=f"ipip{self.ipip_tunnel_instance_egress}",
                        src_ip=self.client_ip6_address,
                        dst_ip=vpp_server_nexthop,
                        tunnel_ip=self.ipip_egress_prefix_linux_ip6,
                        namespace=self.client_namespace,
                    )
                self.ipip_tunnel_interfaces.append(self.egress_ipip_if_idx)
                self.vpp_interfaces.append(self.egress_ipip_if_idx)
                # ipip tunnel interface on Linux connecting to VPP is on the iperf client
                # Linux namespace
                self.linux_interfaces.append(
                    [self.client_namespace, f"ipip{self.ipip_tunnel_instance_egress}"]
                )
            else:
                print(
                    f"Unsupported server interface type: {server_if_type} "
                    f"for test - ID={test['id']}"
                )
                sys.exit(1)
        self.if_types = set(client_if_types).union(set(server_if_types))
        # for memif testing: tapv2, memif & libmemif_app are connected
        if (
            "tap" in self.if_types
            or "af_packet" in self.if_types
            or "tun" in self.if_types
        ):
            if x_connect_mode == "L2":
                self.l2_connect_interfaces(1, self.ingress_if_idx, self.egress_if_idx)
            elif x_connect_mode == "L3":
                # L3 connect client & server side
                self.l3_connect_interfaces(
                    ip_version,
                    vrf_id,
                    (self.ingress_if_idx, vpp_client_prefix),
                    (self.egress_if_idx, vpp_server_prefix),
                )
                # Setup namespace routing for pure tap, af_packet or tun interfaces
                # Exclude default route setup when any ipip tunnel interfaces
                # are present as the default routing is done via the ipip tunnel
                if "ipip" not in client_if_types and "ipip" not in server_if_types:
                    if ip_version == 4:
                        add_namespace_route(
                            self.client_namespace, "0.0.0.0/0", vpp_client_nexthop
                        )
                        add_namespace_route(
                            self.server_namespace, "0.0.0.0/0", vpp_server_nexthop
                        )
                    else:
                        add_namespace_route(
                            self.client_namespace, "::/0", vpp_client_nexthop
                        )
                        add_namespace_route(
                            self.server_namespace, "::/0", vpp_server_nexthop
                        )
        if "memif" in self.if_types:
            # connect: ingress tap & memif & egress tap and memif interfaces
            if x_connect_mode == "L2":
                self.l2_connect_interfaces(1, *self.ingress_if_idxes)
                self.l2_connect_interfaces(2, *self.egress_if_idxes)
        if "ipip" in self.if_types:
            # Determine if tunnel is bidirectional
            bi_directional_tunnel = (
                "ipip" in client_if_types and "ipip" in server_if_types
            )

            def setup_ipip_tunnel(is_client, ip_version):
                """Setup ipip tunnel routing in VPP and Linux namespaces."""
                if is_client:
                    if_idx = self.ingress_ipip_if_idx
                    vpp_tunnel_prefix = (
                        self.ipip_ingress_prefix_vpp_ip4
                        if ip_version == 4
                        else self.ipip_ingress_prefix_vpp_ip6
                    )
                    linux_tunnel_prefix = (
                        self.ipip_ingress_prefix_linux_ip4
                        if ip_version == 4
                        else self.ipip_ingress_prefix_linux_ip6
                    )
                    ns_to = self.server_namespace
                    ns_from = self.client_namespace
                    peer_prefix = (
                        layer3["vpp_client_ip4_prefix"]
                        if ip_version == 4
                        else layer3["vpp_client_ip6_prefix"]
                    )
                    peer_nexthop = vpp_server_nexthop
                    local_nexthop = vpp_client_nexthop
                    default_route = "0.0.0.0/0" if ip_version == 4 else "::/0"
                    remote_lo_network = str(
                        ip_interface(
                            layer3["server_loopback_ip4_prefix"]
                            if ip_version == 4
                            else layer3["server_loopback_ip6_prefix"]
                        ).network
                    )
                    local_lo_network = str(
                        ip_interface(
                            layer3["client_loopback_ip4_prefix"]
                            if ip_version == 4
                            else layer3["client_loopback_ip6_prefix"]
                        ).network
                    )
                    ns_from_host_ip = str(
                        ip_interface(
                            layer3["client_ip4_prefix"]
                            if ip_version == 4
                            else layer3["client_ip6_prefix"]
                        ).ip
                    )
                else:
                    if_idx = self.egress_ipip_if_idx
                    vpp_tunnel_prefix = (
                        self.ipip_egress_prefix_vpp_ip4
                        if ip_version == 4
                        else self.ipip_egress_prefix_vpp_ip6
                    )
                    linux_tunnel_prefix = (
                        self.ipip_egress_prefix_linux_ip4
                        if ip_version == 4
                        else self.ipip_egress_prefix_linux_ip6
                    )
                    ns_to = self.client_namespace
                    ns_from = self.server_namespace
                    peer_prefix = (
                        layer3["vpp_server_ip4_prefix"]
                        if ip_version == 4
                        else layer3["vpp_server_ip6_prefix"]
                    )
                    peer_nexthop = vpp_client_nexthop
                    local_nexthop = vpp_server_nexthop
                    default_route = "0.0.0.0/0" if ip_version == 4 else "::/0"
                    remote_lo_network = str(
                        ip_interface(
                            layer3["client_loopback_ip4_prefix"]
                            if ip_version == 4
                            else layer3["client_loopback_ip6_prefix"]
                        ).network
                    )
                    local_lo_network = str(
                        ip_interface(
                            layer3["server_loopback_ip4_prefix"]
                            if ip_version == 4
                            else layer3["server_loopback_ip6_prefix"]
                        ).network
                    )
                    ns_from_host_ip = str(
                        ip_interface(
                            layer3["server_ip4_prefix"]
                            if ip_version == 4
                            else layer3["server_ip6_prefix"]
                        ).ip
                    )

                vpp_tunnel_ip = str(ip_interface(vpp_tunnel_prefix).ip)
                linux_tunnel_ip = str(ip_interface(linux_tunnel_prefix).ip)
                self.l3_connect_interfaces(
                    ip_version, vrf_id, (if_idx, vpp_tunnel_prefix)
                )

                # Setup routing on namespace receiving tunneled traffic
                # Default route via VPP ipip tunnel IP
                add_namespace_route(ns_to, default_route, vpp_tunnel_ip)
                # Route to the ipip peer IP via the connected VPP tap interface
                add_namespace_route(ns_to, peer_prefix, peer_nexthop)

                # Setup routing in VPP to route remote loopback network via tunnel
                self.vpp_route(remote_lo_network, linux_tunnel_ip, vrf_id, if_idx)

                if not bi_directional_tunnel:
                    # If not bidirectional, route other direction via VPP
                    add_namespace_route(ns_from, default_route, local_nexthop)
                    # Setup routing in VPP to route local loopback network via next-hop Linux interface
                    if set(client_if_types) == {"tap", "ipip"}:
                        # Add route to loopback via the tap interface on the ingress side
                        self.vpp_route(
                            local_lo_network,
                            ns_from_host_ip,
                            vrf_id,
                            self.ingress_if_idx,
                        )
                    elif set(server_if_types) == {"tap", "ipip"}:
                        # Add route to loopback via tap interface on the egress side
                        self.vpp_route(
                            local_lo_network,
                            ns_from_host_ip,
                            vrf_id,
                            self.egress_if_idx,
                        )

            if ip_version == 4:
                if "ipip" in client_if_types:
                    setup_ipip_tunnel(is_client=True, ip_version=4)
                if "ipip" in server_if_types:
                    setup_ipip_tunnel(is_client=False, ip_version=4)

            if ip_version == 6:
                if "ipip" in client_if_types:
                    setup_ipip_tunnel(is_client=True, ip_version=6)
                if "ipip" in server_if_types:
                    setup_ipip_tunnel(is_client=False, ip_version=6)

        # Wait for Linux IPv6 stack to become ready
        if ip_version == 6:
            time.sleep(2)

    def tearDown(self):
        """Tear down the test topology."""

        for route in self.vapi.ip_route_dump(layer3["ip4_vrf"], False):
            try:
                prefix = route.route.prefix
                path = route.route.paths[0]
                next_hop_ip = ip_address(path.nh.address.ip4)
                if_idx = path.sw_if_index
                vrf = route.route.table_id
                self.vpp_route(prefix, next_hop_ip, vrf, if_idx, is_add=0)
            except Exception:
                pass
        for route in self.vapi.ip_route_dump(layer3["ip6_vrf"], True):
            try:
                prefix = route.route.prefix
                path = route.route.paths[0]
                next_hop_ip = ip_address(path.nh.address.ip6)
                if_idx = path.sw_if_index
                vrf = route.route.table_id
                self.vpp_route(prefix, next_hop_ip, vrf, if_idx, is_add=0)
            except Exception:
                pass
        try:
            # Delete interfaces one by one with individual error handling
            for interface_if_idx in self.tap_interfaces:
                try:
                    self.vapi.tap_delete_v2(sw_if_index=interface_if_idx)
                except Exception:
                    pass

            for interface_if_idx in self.ipip_tunnel_interfaces:
                try:
                    self.vapi.ipip_del_tunnel(interface_if_idx)
                except Exception:
                    pass

            for interface_if_idx in self.memif_interfaces:
                try:
                    self.vapi.memif_delete(sw_if_index=interface_if_idx)
                except Exception:
                    pass

            try:
                for interface in self.vapi.af_packet_dump():
                    try:
                        if (
                            interface.host_if_name
                            == self.iprf_client_host_interface_on_vpp
                        ):
                            self.vapi.af_packet_delete(
                                self.iprf_client_host_interface_on_vpp
                            )
                        elif (
                            interface.host_if_name
                            == self.iprf_server_host_interface_on_vpp
                        ):
                            self.vapi.af_packet_delete(
                                self.iprf_server_host_interface_on_vpp
                            )
                    except Exception:
                        pass
            except Exception:
                pass
        except Exception:
            pass
        try:
            delete_all_host_interfaces(self.if_history_name)
        except Exception:
            pass
        try:
            self.vapi.ip_table_add_del_v2(
                is_add=0, table={"table_id": layer3["ip4_vrf"]}
            )
        except Exception:
            pass
        try:
            self.vapi.ip_table_add_del_v2(
                is_add=0, table={"table_id": layer3["ip6_vrf"]}
            )
        except Exception:
            pass
        try:

            def check_bridge_domain_exists(bd_id):
                try:
                    bd_details = self.vapi.bridge_domain_dump(bd_id=bd_id)
                    return len(bd_details) > 0
                except Exception:
                    return False

            # Delete bridge domains if they exist
            for bd_id in [1, 2]:
                if check_bridge_domain_exists(bd_id):
                    try:
                        self.vapi.bridge_domain_add_del_v2(bd_id=bd_id, is_add=0)
                    except Exception:
                        pass
                else:
                    pass
        except Exception:
            pass
        try:
            delete_all_namespaces(self.ns_history_file)
        except Exception:
            pass
        try:
            if hasattr(self, "iperf_cmd"):
                stop_iperf(" ".join(self.iperf_cmd))
        except Exception:
            pass
        try:
            if self.memif_process:
                self.memif_process.terminate()
                self.memif_process.join()
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
        af_packet_interface_flags = af_packet_flags.AF_PACKET_API_FLAG_QDISC_BYPASS
        if enable_gso:
            af_packet_interface_flags = (
                af_packet_interface_flags | af_packet_flags.AF_PACKET_API_FLAG_CKSUM_GSO
            )
        if version == 2:
            af_packet_interface_flags = (
                af_packet_interface_flags | af_packet_flags.AF_PACKET_API_FLAG_VERSION_2
            )
        api_args = {
            "use_random_hw_addr": True,
            "host_if_name": host_if_name,
            "flags": af_packet_interface_flags,
        }
        api_args["mode"] = af_packet_interface_mode
        result = self.vapi.af_packet_create_v3(**api_args)
        sw_if_index = result.sw_if_index
        # Enable software GSO chunking when interface doesn't support GSO offload
        if enable_gso == 0:
            self.vapi.feature_gso_enable_disable(
                sw_if_index=sw_if_index, enable_disable=1
            )
        else:
            self.vapi.feature_gso_enable_disable(
                sw_if_index=sw_if_index, enable_disable=0
            )
        self.vapi.sw_interface_set_flags(sw_if_index=sw_if_index, flags=1)
        return sw_if_index

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
        host_if_name=None,
        enable_gso=0,
        enable_gro=0,
        enable_checksum_offload=0,
    ):
        """Create a tapv2 or tunv2 interface in VPP and attach to host.

        Parameters:
        id -- interface ID
        host_namespace -- host namespace to attach the tap/tun interface to
        ip_version -- 4 or 6
        host_ip4_prefix -- ipv4 host interface address in CIDR notation
                           if ip_version=4
        host_ip6_prefix -- ipv6 host interface address in CIDR notation
                           if ip_version=6
        host_ip4_gw -- host IPv4 default gateway IP Address
        host_ip6_gw -- host IPv6 default gateway IP address
        int_type -- "tap" for tapv2  &  "tun" for tunv2 interface
        host_if_name -- host side interface name
        enable_gso -- enable GSO
        enable_gro -- enable GSO/GRO-Coalesce
        enable_checksum_offload -- enable checksum offload without gso
        """
        TapFlags = VppEnum.vl_api_tap_flags_t
        tap_flags = 0
        if int_type == "tun":
            tap_flags = TapFlags.TAP_API_FLAG_TUN
            if enable_gro:
                tap_flags = tap_flags | (
                    TapFlags.TAP_API_FLAG_GSO | TapFlags.TAP_API_FLAG_GRO_COALESCE
                )
            elif enable_gso:
                tap_flags = tap_flags | TapFlags.TAP_API_FLAG_GSO
            elif enable_checksum_offload:
                tap_flags = tap_flags | TapFlags.TAP_API_FLAG_CSUM_OFFLOAD
        elif int_type == "tap":
            if enable_gro:
                tap_flags = (
                    TapFlags.TAP_API_FLAG_GSO | TapFlags.TAP_API_FLAG_GRO_COALESCE
                )
            elif enable_gso:
                tap_flags = TapFlags.TAP_API_FLAG_GSO
            elif enable_checksum_offload:
                tap_flags = tap_flags | TapFlags.TAP_API_FLAG_CSUM_OFFLOAD

        api_args = {
            "id": id,
            "host_namespace_set": True,
            "host_namespace": host_namespace,
            "host_if_name_set": False,
            "host_bridge_set": False,
            "host_mac_addr_set": False,
        }
        if tap_flags != 0:
            api_args["tap_flags"] = tap_flags
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
        if host_if_name:
            api_args["host_if_name"] = host_if_name
            api_args["host_if_name_set"] = True

        result = self.vapi.tap_create_v2(**api_args)
        sw_if_index = result.sw_if_index
        # Enable software GSO chunking when interface doesn't support GSO offload and
        # GRO coalesce
        if enable_gso == 0 and enable_gro == 0:
            self.vapi.feature_gso_enable_disable(
                sw_if_index=sw_if_index, enable_disable=1
            )
        else:
            self.vapi.feature_gso_enable_disable(
                sw_if_index=sw_if_index, enable_disable=0
            )
        # Admin up
        self.vapi.sw_interface_set_flags(sw_if_index=sw_if_index, flags=1)
        return sw_if_index

    def create_memif(self, memif_id, mode):
        """Create memif interface in VPP.

        Parameters:
        memif_id: A unique ID for the memif interface
        mode: 0 = ethernet, 1 = ip, 2 = punt/inject
        """
        # create memif interface with role=0 (i.e. master)
        result = self.vapi.memif_create_v2(
            role=0, mode=mode, id=memif_id, buffer_size=9216
        )
        sw_if_index = result.sw_if_index
        self.vapi.sw_interface_set_flags(sw_if_index=sw_if_index, flags=1)
        return sw_if_index

    def create_ipip_tunnel_vpp(
        self, src_ip, dst_ip, tunnel_instance=0xFFFFFFFF, table_id=0, ip_version=4
    ):
        """Create a P2P IPIP tunnel in VPP.

        Parameters:
        src_ip -- source IPv4 address
        dst_ip -- destination IPv4 address
        tunnel_instance -- tunnel instance ID
        table_id -- VRF_ID for the tunnel
        """
        is_ipv6 = 0 if ip_version == 4 else 1
        self.create_vrf_if_not_exists(table_id, is_ipv6)
        tunnel = {
            "src": src_ip,
            "dst": dst_ip,
            "table_id": table_id,
            "instance": tunnel_instance,
            "mode": VppEnum.vl_api_tunnel_mode_t.TUNNEL_API_MODE_P2P,
        }
        result = self.vapi.ipip_add_tunnel(tunnel=tunnel)
        sw_if_index = result.sw_if_index
        self.vapi.sw_interface_set_flags(sw_if_index=sw_if_index, flags=1)
        return sw_if_index

    def vpp_route(self, prefix, next_hop, vrf_id=0, if_idx=0xFFFFFFFF, is_add=1):
        """Add or remove a route in VPP.

        Parameters:
        prefix -- destination prefix in CIDR notation
        next_hop -- next-hop IP address
        vrf_id -- VRF ID
        if_idx -- outgoing interface index
        is_add -- 1 to add, 0 to remove
        """
        prefix_obj = ip_network(prefix)
        prefix_len = prefix_obj.prefixlen

        path = VppRoutePath(
            nh_addr=next_hop,  # next-hop IP as string
            nh_sw_if_index=if_idx,  # outgoing interface index
        )
        route = VppIpRoute(
            self,
            dest_addr=str(prefix_obj.network_address),
            dest_addr_len=prefix_len,
            paths=[path],
            table_id=vrf_id,
        )
        if is_add:
            route.add_vpp_config()
        else:
            route.remove_vpp_config()

    def dump_bridge_domain_details(self, bd_id):
        return self.vapi.bridge_domain_dump(bd_id=bd_id)

    def l2_connect_interfaces(self, bridge_id, *sw_if_idxs):
        for if_idx in sw_if_idxs:
            self.vapi.sw_interface_set_l2_bridge(
                rx_sw_if_index=if_idx, bd_id=bridge_id, shg=0, port_type=0, enable=True
            )

    def vrf_exists(self, vrf_id, is_ipv6):
        tables = self.vapi.ip_table_dump()
        for table in tables:
            if table.table.table_id == vrf_id and table.table.is_ip6 == is_ipv6:
                return True
        return False

    def create_vrf_if_not_exists(self, vrf_id, is_ipv6):
        """Create a VRF in VPP if it doesn't exist.

        Parameters:
        vrf_id -- VRF ID
        is_ipv6 -- 0 for IPv4, 1 for IPv6
        """
        if not self.vrf_exists(vrf_id, is_ipv6):
            self.vapi.ip_table_add_del_v2(
                is_add=1, table={"table_id": vrf_id, "is_ip6": is_ipv6}
            )

    def l3_connect_interfaces(self, ip_version, vrf_id, *if_idx_ip_prefixes):
        """Setup routing for (if_idx, ip_prefix) inside VPP.

        arguments:
        if_idx_ip_prefixes -- sequence of (if_idx, ip_prefix) tuples
        ip_version -- 4 or 6
        vrf_id -- vrf_id
        """
        is_ipv6 = 0 if ip_version == 4 else 1
        self.create_vrf_if_not_exists(vrf_id, is_ipv6)
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
        # IPv6 on Linux requires an MTU value >=1280
        if (ip_version == 6 and mtu >= 1280) or ip_version == 4:
            for sw_if_idx in vpp_interfaces:
                self.vapi.sw_interface_set_mtu(
                    sw_if_index=sw_if_idx, mtu=[mtu, 0, 0, 0]
                )
            for namespace, interface_name in linux_interfaces:
                set_interface_mtu(
                    namespace=namespace,
                    interface=interface_name,
                    mtu=mtu,
                    logger=self.logger,
                )
            return True
        else:
            return False


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
