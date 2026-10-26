#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2026 Intel Corporation

import subprocess
import re
import sys
import threading
import unittest
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_interface

from scapy.all import AsyncSniffer, sendp
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from asfframework import VppTestRunner
from config import config
from framework import VppTestCase


@unittest.skipUnless(sys.platform.startswith("freebsd"), "FreeBSD only")
@unittest.skipIf("freebsd-cp" in config.excluded_plugins, "Exclude freebsd-cp plugin tests")
class TestFreeBSDCP(VppTestCase):
    """FreeBSD Control Plane TAP forwarding."""

    extra_vpp_plugin_config = ["plugin freebsd_cp_plugin.so { enable }"]

    def setUp(self):
        super().setUp()

        self.tap_if = subprocess.check_output(
            ["ifconfig", "tap", "create"], text=True
        ).strip()
        if not self.tap_if.startswith("tap"):
            self.fail(f"Unexpected TAP interface name: {self.tap_if!r}")
        subprocess.run(
            ["ifconfig", self.tap_if, "up"], check=True, stdout=subprocess.DEVNULL
        )
        self.pair_created = False
        self.ip_configured = False
        self.synced_addresses = set()
        self.host_neighbors = []
        self.host_addresses = set()
        self.addCleanup(self._destroy_tap)
        defer_pair = self._testMethodName in {
            "test_freebsd_cp_sync_route_ipv4",
            "test_freebsd_cp_sync_neighbor_ipv6",
        }
        self.create_pg_interfaces(range(1))
        self.phy = self.pg0
        self.phy.set_l3_mtu(1500)
        self.phy.admin_up()
        self.addCleanup(self._cleanup_host_addresses)
        self.addCleanup(self._cleanup_host_neighbors)
        self.addCleanup(self._delete_pair)
        self.addCleanup(self._cleanup_synced_addresses)
        self.addCleanup(self._unconfigure_phy)
        if not defer_pair:
            self._create_pair()

    def tearDown(self):
        self._unconfigure_phy()
        self._cleanup_synced_addresses()
        self._delete_pair()
        self._cleanup_host_neighbors()
        self._cleanup_host_addresses()
        for intf in self.pg_interfaces:
            intf.admin_down()
        super().tearDown()

    def _unconfigure_phy(self):
        if self.ip_configured:
            self.phy.unconfig_ip4()
            self.ip_configured = False

    def _add_synced_address(self, prefix):
        self.vapi.sw_interface_add_del_address(
            sw_if_index=self.phy.sw_if_index, prefix=prefix
        )
        self.synced_addresses.add(prefix)

    def _delete_synced_address(self, prefix):
        if prefix in self.synced_addresses:
            self.vapi.sw_interface_add_del_address(
                sw_if_index=self.phy.sw_if_index, prefix=prefix, is_add=0
            )
            self.synced_addresses.remove(prefix)

    def _cleanup_synced_addresses(self):
        for prefix in list(self.synced_addresses):
            self._delete_synced_address(prefix)

    def _add_host_address(self, family, prefix):
        interface = ip_interface(prefix)
        if family == "inet":
            command = [
                "ifconfig",
                self.tap_if,
                "inet",
                str(interface.ip),
                "netmask",
                str(interface.network.netmask),
                "alias",
            ]
        else:
            command = [
                "ifconfig",
                self.tap_if,
                "inet6",
                str(interface.ip),
                "prefixlen",
                str(interface.network.prefixlen),
                "alias",
            ]
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL)
        subprocess.run(
            ["ifconfig", self.tap_if, "up"], check=True, stdout=subprocess.DEVNULL
        )
        self.host_addresses.add((family, str(interface.ip)))

    def _delete_host_address(self, family, address):
        if (family, address) not in self.host_addresses:
            return
        subprocess.run(
            ["ifconfig", self.tap_if, family, address, "-alias"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.host_addresses.remove((family, address))

    def _cleanup_host_addresses(self):
        for family, address in list(self.host_addresses):
            self._delete_host_address(family, address)

    def _add_host_neighbor(self, family, address, mac):
        if family == "inet":
            command = ["arp", "-S", address, mac]
        else:
            command = ["ndp", "-s", address, mac]
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode:
            raise RuntimeError(
                f"{command!r} failed: {result.stderr.strip()}"
            )
        self.host_neighbors.append((family, address))

    def _delete_host_neighbor(self, family, address, check=True):
        command = (
            ["arp", "-d", address]
            if family == "inet"
            else ["ndp", "-d", address]
        )
        subprocess.run(
            command,
            check=check,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.host_neighbors.remove((family, address))

    def _cleanup_host_neighbors(self):
        for family, address in list(self.host_neighbors):
            self._delete_host_neighbor(family, address, check=False)

    def _delete_pair(self):
        if self.pair_created:
            self.vapi.cli(f"fcp delete {self.phy.name}")
            self.pair_created = False

    def _create_pair(self):
        if not self.pair_created:
            self.vapi.cli(f"fcp create {self.phy.name} host-if {self.tap_if}")
            self.pair_created = True

    def _destroy_tap(self):
        subprocess.run(
            ["ifconfig", self.tap_if, "destroy"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def _tap_ifconfig(self):
        return subprocess.check_output(
            ["ifconfig", self.tap_if], text=True
        )

    def _tap_is_up(self):
        output = self._tap_ifconfig()
        match = re.search(r"flags=\d+<([^>]*)>", output)
        self.assertIsNotNone(match, f"Could not read flags for {self.tap_if}")
        return "UP" in match.group(1).split(",")

    def _tap_mtu(self):
        output = self._tap_ifconfig()
        match = re.search(r"\bmtu (\d+)", output)
        self.assertIsNotNone(match, f"Could not read MTU for {self.tap_if}")
        return int(match.group(1))

    def _tap_ipv4_addresses(self):
        addresses = set()
        for address, mask in re.findall(
            r"\binet\s+([0-9.]+)\s+netmask\s+(\S+)", self._tap_ifconfig()
        ):
            mask_value = (
                int(mask, 16)
                if mask.startswith("0x")
                else int(IPv4Address(mask))
            )
            addresses.add((address, bin(mask_value).count("1")))
        return addresses

    def _tap_global_ipv6_addresses(self):
        addresses = set()
        for address, prefix in re.findall(
            r"\binet6\s+([0-9a-fA-F:]+(?:%[0-9A-Za-z_.-]+)?)"
            r"\s+prefixlen\s+(\d+)",
            self._tap_ifconfig(),
        ):
            ip = IPv6Address(address.split("%", 1)[0])
            if not ip.is_link_local:
                addresses.add((str(ip), int(prefix)))
        return addresses

    def _poll_for(self, description, fn, expected, timeout=3.0, interval=0.1):
        actual = None
        for _ in range(int(timeout / interval)):
            actual = fn()
            if actual == expected:
                return
            self.sleep(interval)
        self.assertEqual(actual, expected, description)

    def _has_neighbor(self, address, mac):
        ip = ip_address(address)
        neighbors = self.vapi.ip_neighbor_dump(
            sw_if_index=self.phy.sw_if_index, af=ip.vapi_af
        )
        return any(
            n.neighbor.sw_if_index == self.phy.sw_if_index
            and n.neighbor.ip_address == ip
            and str(n.neighbor.mac_address).lower() == mac.lower()
            for n in neighbors
        )

    def _has_route_path(self, prefix, gateway):
        try:
            route = self.vapi.api(
                self.vapi.papi.ip_route_lookup,
                {"table_id": 0, "exact": True, "prefix": prefix},
            ).route
        except Exception:
            return False
        return any(
            path.sw_if_index == self.phy.sw_if_index
            and str(path.nh.address.ip4) == gateway
            for path in route.paths
        )

    def _has_host_neighbor(self, family, address, mac):
        command = ["arp", "-an"] if family == "inet" else ["ndp", "-an"]
        output = subprocess.check_output(command, text=True).lower()
        return (
            address.lower() in output
            and mac.lower() in output
            and self.tap_if.lower() in output
        )

    def _send_from_tap(self, packet):
        self.phy.enable_capture()
        expected = bytes(packet)
        sendp(packet, iface=self.tap_if, verbose=False)
        captured = self.phy.get_capture(
            1, filter_out_fn=lambda captured_packet: bytes(captured_packet) != expected
        )
        self.assertEqual(packet.show2(True), captured[0].show2(True))

    def _send_to_tap(self, packet, matches):
        started = threading.Event()
        sniffer = AsyncSniffer(
            iface=self.tap_if,
            store=True,
            lfilter=matches,
            timeout=3,
            started_callback=started.set,
        )
        sniffer.start()
        self.assertTrue(started.wait(5), f"Could not start capture on {self.tap_if}")
        self.pg_enable_capture(self.pg_interfaces)
        self.phy.add_stream([packet])
        self.pg_start()
        sniffer.join()

        captured = sniffer.results
        self.assertEqual(1, len(captured), f"Unexpected capture on {self.tap_if}")
        self.assertEqual(packet.show2(True), captured[0].show2(True))

    def test_freebsd_cp_tap(self):
        """Forward IPv4 UDP and ARP packets between VPP and a FreeBSD TAP."""
        phy = self.phy
        phy.config_ip4()
        self.ip_configured = True
        phy.generate_remote_hosts(4)
        phy.configure_ipv4_neighbors()

        for remote in phy.remote_hosts:
            udp_to_phy = (
                Ether(src=phy.local_mac, dst=remote.mac)
                / IP(src=phy.local_ip4, dst=remote.ip4)
                / UDP(sport=1234, dport=1234)
                / Raw()
            )
            self._send_from_tap(udp_to_phy)

            arp_request = Ether(
                dst="ff:ff:ff:ff:ff:ff", src=phy.local_mac
            ) / ARP(
                op="who-has",
                hwdst=remote.mac,
                hwsrc=phy.local_mac,
                psrc=phy.local_ip4,
                pdst=remote.ip4,
            )
            self._send_from_tap(arp_request)

        for remote in phy.remote_hosts:
            udp_to_tap = (
                Ether(dst=phy.local_mac, src=remote.mac)
                / IP(dst=phy.local_ip4, src=remote.ip4)
                / UDP(sport=1234, dport=1234)
                / Raw()
            )
            self._send_to_tap(
                udp_to_tap,
                lambda pkt, src=remote.ip4: pkt.haslayer(IP)
                and pkt[IP].src == src
                and pkt[UDP].dport == 1234,
            )

            arp_reply = Ether(
                dst="ff:ff:ff:ff:ff:ff", src=remote.mac
            ) / ARP(
                op="is-at",
                hwsrc=remote.mac,
                hwdst=phy.local_mac,
                pdst=phy.local_ip4,
                psrc=remote.ip4,
            )
            self._send_to_tap(
                arp_reply,
                lambda pkt, src=remote.ip4: pkt.haslayer(ARP)
                and pkt[ARP].op == 2
                and pkt[ARP].psrc == src,
            )

    def test_freebsd_cp_sync_admin_state(self):
        """VPP admin state changes sync to the FreeBSD TAP."""
        self.assertTrue(self._tap_is_up())

        self.phy.admin_down()
        self._poll_for("TAP down after VPP admin_down", self._tap_is_up, False)

        self.phy.admin_up()
        self._poll_for("TAP up after VPP admin_up", self._tap_is_up, True)

    def test_freebsd_cp_sync_mtu(self):
        """VPP L3 MTU changes sync to the FreeBSD TAP."""
        for mtu in (1600, 1400, 1500):
            self.phy.set_l3_mtu(mtu)
            self._poll_for(
                f"TAP MTU {mtu}", lambda: self._tap_mtu(), mtu
            )

    def test_freebsd_cp_sync_ipv4_addr(self):
        """VPP IPv4 address changes sync to the FreeBSD TAP."""
        prefix_a = "192.0.2.2/24"
        prefix_b = "198.51.100.2/24"
        expected_a = (str(ip_interface(prefix_a).ip), 24)
        expected_b = (str(ip_interface(prefix_b).ip), 24)

        self.assertEqual(set(), self._tap_ipv4_addresses())

        self._add_synced_address(prefix_a)
        self._poll_for(
            f"TAP has {prefix_a}", self._tap_ipv4_addresses, {expected_a}
        )

        self._add_synced_address(prefix_b)
        self._poll_for(
            "TAP has both IPv4 addresses",
            self._tap_ipv4_addresses,
            {expected_a, expected_b},
        )

        self._delete_synced_address(prefix_a)
        self._poll_for(
            f"TAP only has {prefix_b}", self._tap_ipv4_addresses, {expected_b}
        )

        self._delete_synced_address(prefix_b)
        self._poll_for("TAP has no IPv4 addresses", self._tap_ipv4_addresses, set())

    def test_freebsd_cp_sync_ipv6_addr(self):
        """VPP IPv6 address changes sync to the FreeBSD TAP."""
        prefix_a = "2001:db8:1::2/64"
        prefix_b = "2001:db8:2::2/64"
        expected_a = (str(ip_interface(prefix_a).ip), 64)
        expected_b = (str(ip_interface(prefix_b).ip), 64)

        self.assertEqual(set(), self._tap_global_ipv6_addresses())

        self._add_synced_address(prefix_a)
        self._poll_for(
            f"TAP has {prefix_a}", self._tap_global_ipv6_addresses, {expected_a}
        )

        self._add_synced_address(prefix_b)
        self._poll_for(
            "TAP has both IPv6 addresses",
            self._tap_global_ipv6_addresses,
            {expected_a, expected_b},
        )

        self._delete_synced_address(prefix_a)
        self._poll_for(
            f"TAP only has {prefix_b}",
            self._tap_global_ipv6_addresses,
            {expected_b},
        )

        self._delete_synced_address(prefix_b)
        self._poll_for(
            "TAP has no global IPv6 addresses",
            self._tap_global_ipv6_addresses,
            set(),
        )

    def test_freebsd_cp_sync_route_ipv4(self):
        """FreeBSD IPv4 gateway route changes sync to VPP."""
        tap_prefix = "192.0.2.2/24"
        route_prefix = "198.51.100.0/24"
        gateway = "192.0.2.1"
        self._add_host_address("inet", tap_prefix)
        self._create_pair()

        add_route = ["route", "-4", "add", "-net", route_prefix, gateway]
        delete_route = ["route", "-4", "delete", "-net", route_prefix, gateway]
        route_added = False
        try:
            subprocess.run(add_route, check=True, stdout=subprocess.DEVNULL)
            route_added = True
            self._poll_for(
                f"VPP has route {route_prefix} via {gateway}",
                lambda: self._has_route_path(route_prefix, gateway),
                True,
            )

            subprocess.run(delete_route, check=True, stdout=subprocess.DEVNULL)
            route_added = False
            self._poll_for(
                f"VPP removes route {route_prefix}",
                lambda: self._has_route_path(route_prefix, gateway),
                False,
            )
        finally:
            if route_added:
                subprocess.run(
                    delete_route,
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )

        self._delete_host_address("inet", str(ip_interface(tap_prefix).ip))

    def test_freebsd_cp_sync_neighbor_ipv4_live(self):
        """Import FreeBSD ARP neighbors added after an FCP pair is created."""
        self.vapi.cli("set logging class freebsd-cp level debug")
        prefix = "192.0.2.2/24"
        address = "192.0.2.100"
        mac = "02:01:02:03:04:05"
        self._add_host_address("inet", prefix)
        self._create_pair()

        self._add_host_neighbor("inet", address, mac)
        self._poll_for(
            f"FreeBSD ARP neighbor {address} exists on {self.tap_if}",
            lambda: self._has_host_neighbor("inet", address, mac),
            True,
        )
        self._poll_for(
            f"VPP learns ARP neighbor {address} after pair creation",
            lambda: self._has_neighbor(address, mac),
            True,
        )

        self._delete_pair()
        self._poll_for(
            f"VPP removes ARP neighbor {address} when pair is deleted",
            lambda: self._has_neighbor(address, mac),
            False,
        )
        self._delete_host_neighbor("inet", address)
        self._delete_host_address("inet", str(ip_interface(prefix).ip))

    def test_freebsd_cp_sync_neighbor_ipv6(self):
        """Import existing FreeBSD NDP neighbors when an FCP pair is created."""
        self.vapi.cli("set logging class freebsd-cp level debug")
        prefix = "2001:db8:10::2/64"
        address = "2001:db8:10::100"
        mac = "02:01:02:03:04:06"
        self._add_host_address("inet6", prefix)
        self._add_host_neighbor("inet6", address, mac)
        self._poll_for(
            f"FreeBSD NDP neighbor {address} exists on {self.tap_if}",
            lambda: self._has_host_neighbor("inet6", address, mac),
            True,
        )

        self._create_pair()
        self._poll_for(
            f"VPP has NDP neighbor {address}",
            lambda: self._has_neighbor(address, mac),
            True,
        )

        self._delete_pair()
        self._poll_for(
            f"VPP removes NDP neighbor {address} when pair is deleted",
            lambda: self._has_neighbor(address, mac),
            False,
        )
        self._delete_host_neighbor("inet6", address)
        self._delete_host_address("inet6", str(ip_interface(prefix).ip))

    def test_freebsd_cp_sync_neighbor_ipv6_live(self):
        """Import FreeBSD NDP neighbors added after an FCP pair is created."""
        self.vapi.cli("set logging class freebsd-cp level debug")
        prefix = "2001:db8:20::2/64"
        address = "2001:db8:20::100"
        mac = "02:01:02:03:04:07"
        self._add_host_address("inet6", prefix)
        self._create_pair()

        self._add_host_neighbor("inet6", address, mac)
        self._poll_for(
            f"FreeBSD NDP neighbor {address} exists on {self.tap_if}",
            lambda: self._has_host_neighbor("inet6", address, mac),
            True,
        )
        self._poll_for(
            f"VPP learns NDP neighbor {address} after pair creation",
            lambda: self._has_neighbor(address, mac),
            True,
        )

        self._delete_pair()
        self._poll_for(
            f"VPP removes NDP neighbor {address} when pair is deleted",
            lambda: self._has_neighbor(address, mac),
            False,
        )
        self._delete_host_neighbor("inet6", address)
        self._delete_host_address("inet6", str(ip_interface(prefix).ip))


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
