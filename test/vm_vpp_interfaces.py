#!/usr/bin/env python3
import unittest
from ipaddress import ip_address, ip_interface
from vpp_qemu_utils import (
    create_namespace,
    delete_all_namespaces,
    create_host_interface,
    delete_all_host_interfaces,
    set_interface_mtu,
    disable_interface_gso,
    add_namespace_route,
    libmemif_test_app,
)
from vpp_iperf import start_iperf, stop_iperf
from framework import VppTestCase
from asfframework import VppTestRunner, tag_fixme_debian12, is_distro_debian12
from config import config
from vpp_papi import VppEnum
import time
import sys
import os
from vm_test_config import test_config
import random
import string
import subprocess

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
af_xdp_config = test_config["af_xdp"]
layer2 = test_config["L2"]
layer3 = test_config["L3"]


def create_test(test_name, test, ip_version, mtu):
    """Create and return a unittest method for a test."""

    @unittest.skipIf(
        is_distro_debian12, "FIXME intermittent test failures on debian12 distro"
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
            # Start an instance of an iperf server using
            # a unique port. Save the iperf cmdline for
            # terminating the iperf_server process after the test.
            self.iperf_cmd = start_iperf(
                ip_version=6,
                client_ns=self.client_namespace,
                server_ns=self.server_namespace,
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
                    server_ipv4_address=self.server_ip4_address,
                    server_ipv6_address=self.server_ip6_address,
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


def generate_vpp_interface_tests(tests, test_class):
    """Generate unittests for testing vpp interfaces

    Generates unittests from test spec. and sets them as attributes
    to the test_class.
    Args:
       tests      : list of test specs from vm_test_config['tests']
       test_class : the name of the test class to which the
                    generated tests are set as attributes.
    """

    def get_valid_mtus(test):
        client_if_types = test["client_if_type"].split(",")
        server_if_types = test["server_if_type"].split(",")
        contains_af_xdp = any(
            if_type == "af_xdp" for if_type in client_if_types + server_if_types
        )

        # MTU <= 2048 Bytes for af_xdp interfaces
        if contains_af_xdp:
            return [mtu for mtu in test_config["mtus"] if mtu <= 2048]
        else:
            return test_config["mtus"]

    for test in tests:
        for ip_version in test_config["ip_versions"]:
            for mtu in get_valid_mtus(test):
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


@tag_fixme_debian12
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
        self.server_ip4_address = str(ip_interface(server_ip4_prefix).ip)
        self.server_ip6_address = str(ip_interface(server_ip6_prefix).ip)
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
                    host_ip4_gw=(
                        vpp_client_nexthop
                        if x_connect_mode == "L3" and ip_version == 4
                        else None
                    ),
                    host_ip6_gw=(
                        vpp_client_nexthop
                        if x_connect_mode == "L3" and ip_version == 6
                        else None
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
            elif client_if_type == "af_xdp":
                self.ingress_if_idx = self.create_af_xdp(
                    namespace=self.client_namespace,
                    host_side_name=af_xdp_config["iprf_client_interface_on_linux"],
                    vpp_side_name=af_xdp_config["iprf_client_interface_on_vpp"],
                    ip4_prefix=(
                        layer2["client_ip4_prefix"]
                        if x_connect_mode == "L2"
                        else layer3["client_ip4_prefix"]
                    ),
                    ip6_prefix=(
                        layer2["client_ip6_prefix"]
                        if x_connect_mode == "L2"
                        else layer3["client_ip6_prefix"]
                    ),
                    version=client_if_version,
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
            elif server_if_type == "af_xdp":
                self.egress_if_idx = self.create_af_xdp(
                    namespace=self.server_namespace,
                    host_side_name=af_xdp_config["iprf_server_interface_on_linux"],
                    vpp_side_name=af_xdp_config["iprf_server_interface_on_vpp"],
                    ip4_prefix=server_ip4_prefix,
                    ip6_prefix=server_ip6_prefix,
                    version=server_if_version,
                )
            else:
                print(
                    f"Unsupported server interface type: {server_if_type} "
                    f"for test - ID={test['id']}"
                )
                sys.exit(1)
        self.if_types = set(client_if_types).union(set(server_if_types))
        # for memif testing: tapv2, memif & libmemif_app are connected
        if "memif" not in self.if_types:
            if x_connect_mode == "L2":
                self.l2_connect_interfaces(1, self.ingress_if_idx, self.egress_if_idx)
            elif x_connect_mode == "L3":
                # L3 connect client & server side
                vrf_id = layer3["ip4_vrf"] if ip_version == 4 else layer3["ip6_vrf"]
                self.l3_connect_interfaces(
                    ip_version,
                    vrf_id,
                    (self.ingress_if_idx, vpp_client_prefix),
                    (self.egress_if_idx, vpp_server_prefix),
                )
                # Setup namespace routing
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
        else:
            # connect: ingress tap & memif & egress tap and memif interfaces
            if x_connect_mode == "L2":
                self.l2_connect_interfaces(1, *self.ingress_if_idxes)
                self.l2_connect_interfaces(2, *self.egress_if_idxes)
        # Wait for Linux IPv6 stack to become ready
        if ip_version == 6:
            time.sleep(2)

    def tearDown(self):
        # Delete tap interfaces
        for interface_if_idx in self.tap_interfaces:
            try:
                self.vapi.tap_delete_v2(sw_if_index=interface_if_idx)
            except Exception:
                pass

        # Delete memif interfaces
        for interface_if_idx in self.memif_interfaces:
            try:
                self.vapi.memif_delete(sw_if_index=interface_if_idx)
            except Exception:
                pass

        # Delete af_packet interfaces
        try:
            for interface in self.vapi.af_packet_dump():
                if interface.host_if_name == self.iprf_client_host_interface_on_vpp:
                    try:
                        self.vapi.af_packet_delete(
                            self.iprf_client_host_interface_on_vpp
                        )
                    except Exception:
                        pass
                elif interface.host_if_name == self.iprf_server_host_interface_on_vpp:
                    try:
                        self.vapi.af_packet_delete(
                            self.iprf_server_host_interface_on_vpp
                        )
                    except Exception:
                        pass
        except Exception:
            pass

        # Delete AF_XDP interfaces
        if hasattr(self, "af_xdp_interfaces"):
            for interface_if_idx in self.af_xdp_interfaces:
                try:
                    self.vapi.af_xdp_delete(interface_if_idx)
                except Exception:
                    pass

        # Delete host interfaces
        try:
            delete_all_host_interfaces(self.if_history_name)
        except Exception:
            pass

        # Delete VRF tables
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

        # Delete bridge domains
        try:
            # Check if bridge domains exist before trying to delete them
            for bd_id in [1, 2]:
                try:
                    bd_details = self.vapi.bridge_domain_dump(bd_id=bd_id)
                    if len(bd_details) > 0:
                        self.vapi.bridge_domain_add_del_v2(bd_id=bd_id, is_add=0)
                except Exception:
                    pass
        except Exception:
            pass

        # Clean up namespaces and processes
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
            if hasattr(self, "memif_process") and self.memif_process:
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
        self.vapi.ip_table_add_del_v2(
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

    def create_af_xdp(
        self, namespace, host_side_name, vpp_side_name, ip4_prefix, ip6_prefix, version
    ):
        """Create an AF_XDP interface and configure it in VPP and Linux."""
        try:
            # Generate unique random suffixes for interface names to prevent conflicts
            random_suffix = "".join(
                random.choices(string.ascii_lowercase + string.digits, k=8)
            )
            unique_host_side_name = f"{host_side_name}{random_suffix}"
            unique_vpp_side_name = f"{vpp_side_name}{random_suffix}"

            self.logger.debug(
                f"Creating AF_XDP interfaces with names: {unique_host_side_name} and {unique_vpp_side_name}"
            )

            # Clean up any existing interfaces with the same name
            os.system(
                f"ip netns exec {namespace} ip link del {unique_host_side_name} 2>/dev/null || true"
            )
            os.system(f"ip link del {unique_vpp_side_name} 2>/dev/null || true")

            # Create the host interface
            create_host_interface(
                self.if_history_name,
                namespace,
                ip4_prefix,
                ip6_prefix,
                vpp_if_name=unique_vpp_side_name,
                host_if_name=unique_host_side_name,
            )

            # Verify that the host interfaces were created successfully
            max_check_attempts = 5
            check_interval = 0.5

            # Check for VPP-side interface
            for attempt in range(max_check_attempts):
                vpp_if_check = subprocess.run(
                    ["ip", "link", "show", "dev", unique_vpp_side_name],
                    capture_output=True,
                    text=True,
                )
                if vpp_if_check.returncode == 0:
                    self.logger.debug(
                        f"VPP-side interface {unique_vpp_side_name} exists"
                    )
                    break
                self.logger.warning(
                    f"VPP-side interface {unique_vpp_side_name} not ready, attempt {attempt+1}/{max_check_attempts}"
                )
                time.sleep(check_interval)
            else:
                raise Exception(
                    f"VPP-side interface {unique_vpp_side_name} does not exist after {max_check_attempts} checks"
                )

            # Check for namespace-side interface
            for attempt in range(max_check_attempts):
                host_if_check = subprocess.run(
                    [
                        "ip",
                        "netns",
                        "exec",
                        namespace,
                        "ip",
                        "link",
                        "show",
                        "dev",
                        unique_host_side_name,
                    ],
                    capture_output=True,
                    text=True,
                )
                if host_if_check.returncode == 0:
                    self.logger.debug(
                        f"Host-side interface {unique_host_side_name} exists in namespace {namespace}"
                    )
                    break
                self.logger.warning(
                    f"Host-side interface {unique_host_side_name} not ready, attempt {attempt+1}/{max_check_attempts}"
                )
                time.sleep(check_interval)
            else:
                raise Exception(
                    f"Host-side interface {unique_host_side_name} does not exist in namespace {namespace} after {max_check_attempts} checks"
                )

            # Add delay to ensure host interface is fully initialized
            time.sleep(1)

            api_args = {
                "host_if": unique_vpp_side_name,
                "rxq_num": 1,
            }

            # Clean any stale XDP sockets
            os.system(
                f"rm -f /dev/shm/vpp_*{unique_vpp_side_name}* 2>/dev/null || true"
            )

            # Set retry mechanism to ensure correct AF_XDP creation
            retries = 3
            last_error = None

            for attempt in range(retries):
                try:
                    if version == 1:
                        result = self.vapi.af_xdp_create(**api_args)
                    elif version == 2:
                        result = self.vapi.af_xdp_create_v2(**api_args)
                    elif version == 3:
                        result = self.vapi.af_xdp_create_v3(**api_args)
                    else:
                        raise ValueError(f"Unsupported AF_XDP version: {version}")
                    break
                except Exception as e:
                    last_error = e
                    self.logger.warning(
                        f"AF_XDP creation attempt {attempt+1} failed: {e}"
                    )
                    time.sleep(1)  # Wait before retry
            else:
                # All retries failed
                raise Exception(
                    f"Failed to create AF_XDP interface after {retries} attempts: {last_error}"
                )

            sw_if_index = result.sw_if_index

            # Set interface up
            self.vapi.sw_interface_set_flags(sw_if_index=sw_if_index, flags=1)

            # Add the interface to the VPP interface list
            self.vpp_interfaces.append(sw_if_index)
            self.linux_interfaces.append(["", unique_vpp_side_name])
            self.linux_interfaces.append([namespace, unique_host_side_name])

            # Track AF_XDP interfaces for tearDown
            if not hasattr(self, "af_xdp_interfaces"):
                self.af_xdp_interfaces = []
            self.af_xdp_interfaces.append(sw_if_index)

            # Add to ingress/egress lists based on namespace
            if namespace == self.client_namespace:
                self.ingress_if_idxes.append(sw_if_index)
            elif namespace == self.server_namespace:
                self.egress_if_idxes.append(sw_if_index)

            # AF_XDP doesn't support GSO/checksum offload, so disable them
            disable_interface_gso("", unique_vpp_side_name)
            disable_interface_gso(namespace, unique_host_side_name)

            return sw_if_index

        except Exception as e:
            self.logger.error(f"Error creating AF_XDP interface: {e}")
            # Cleanup on failure
            try:
                os.system(
                    f"ip netns exec {namespace} ip link del {unique_host_side_name} 2>/dev/null || true"
                )
                os.system(f"ip link del {unique_vpp_side_name} 2>/dev/null || true")
            except:
                pass
            raise


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
