#!/usr/bin/env python3

import unittest

from framework import VppTestCase
from asfframework import VppTestRunner, tag_fixme_vpp_workers
from vpp_ip_route import (
    VppIpMRoute,
    VppMRoutePath,
    VppMFibSignal,
    VppIpTable,
    VppIpInterfaceAddress,
    FibPathProto,
    FibPathType,
)
from vpp_gre_interface import VppGreInterface
from vpp_lo_interface import VppLoInterface
from vpp_neighbor import find_nbr
from vpp_papi import VppEnum
from config import config

from scapy.packet import Raw
from scapy.layers.l2 import Ether, GRE
from scapy.layers.inet import IP, UDP, getmacbyip, ICMP
from scapy.layers.inet6 import IPv6, getmacbyip6

#
# The number of packets sent is set to 91 so that when we replicate more than 3
# times, which we do for some entries, we will generate more than 256 packets
# to the next node in the VLIB graph. Thus we are testing the code's
# correctness handling this over-flow.
# It's also an odd number so we hit any single loops.
#
N_PKTS_IN_STREAM = 91


class TestMFIB(VppTestCase):
    """MFIB Test Case"""

    @classmethod
    def setUpClass(cls):
        super(TestMFIB, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestMFIB, cls).tearDownClass()

    def setUp(self):
        super(TestMFIB, self).setUp()

    def test_mfib(self):
        """MFIB Unit Tests"""
        error = self.vapi.cli("test mfib")

        if error:
            self.logger.critical(error)
        self.assertNotIn("Failed", error)


@tag_fixme_vpp_workers
class TestIPMcast(VppTestCase):
    """IP Multicast Test Case"""

    @classmethod
    def setUpClass(cls):
        super(TestIPMcast, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestIPMcast, cls).tearDownClass()

    def setUp(self):
        super(TestIPMcast, self).setUp()

        # create 8 pg interfaces
        self.create_pg_interfaces(range(9))

        # setup interfaces
        for i in self.pg_interfaces[:8]:
            i.admin_up()
            i.config_ip4()
            i.config_ip6()
            i.resolve_arp()
            i.resolve_ndp()

        # one more in a vrf
        tbl4 = VppIpTable(self, 10)
        tbl4.add_vpp_config()
        self.pg8.set_table_ip4(10)
        self.pg8.config_ip4()

        tbl6 = VppIpTable(self, 10, is_ip6=1)
        tbl6.add_vpp_config()
        self.pg8.set_table_ip6(10)
        self.pg8.config_ip6()

    def tearDown(self):
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.admin_down()

        self.pg8.set_table_ip4(0)
        self.pg8.set_table_ip6(0)
        super(TestIPMcast, self).tearDown()

    def create_stream_ip4(self, src_if, src_ip, dst_ip, payload_size=0):
        pkts = []
        # default to small packet sizes
        p = (
            Ether(dst=getmacbyip(dst_ip), src=src_if.remote_mac)
            / IP(src=src_ip, dst=dst_ip)
            / UDP(sport=1234, dport=1234)
        )
        if not payload_size:
            payload_size = 64 - len(p)
            p = p / Raw(b"\xa5" * payload_size)

        for i in range(0, N_PKTS_IN_STREAM):
            pkts.append(p)
        return pkts

    def create_stream_ip6(self, src_if, src_ip, dst_ip):
        pkts = []
        for i in range(0, N_PKTS_IN_STREAM):
            info = self.create_packet_info(src_if, src_if)
            payload = self.info_to_payload(info)
            p = (
                Ether(dst=getmacbyip6(dst_ip), src=src_if.remote_mac)
                / IPv6(src=src_ip, dst=dst_ip)
                / UDP(sport=1234, dport=1234)
                / Raw(payload)
            )
            info.data = p.copy()
            pkts.append(p)
        return pkts

    def verify_filter(self, capture, sent):
        if not len(capture) == len(sent):
            # filter out any IPv6 RAs from the capture
            for p in capture:
                if p.haslayer(IPv6):
                    capture.remove(p)
        return capture

    def verify_capture_ip4(self, rx_if, sent, dst_mac=None):
        rxd = rx_if.get_capture(len(sent))

        try:
            capture = self.verify_filter(rxd, sent)

            self.assertEqual(len(capture), len(sent))

            for i in range(len(capture)):
                tx = sent[i]
                rx = capture[i]

                eth = rx[Ether]
                self.assertEqual(eth.type, 0x800)

                tx_ip = tx[IP]
                rx_ip = rx[IP]

                if dst_mac is None:
                    dst_mac = getmacbyip(rx_ip.dst)

                # check the MAC address on the RX'd packet is correctly formed
                self.assertEqual(eth.dst, dst_mac)

                self.assertEqual(rx_ip.src, tx_ip.src)
                self.assertEqual(rx_ip.dst, tx_ip.dst)
                # IP processing post pop has decremented the TTL
                self.assertEqual(rx_ip.ttl + 1, tx_ip.ttl)

        except:
            raise

    def verify_capture_ip6(self, rx_if, sent):
        capture = rx_if.get_capture(len(sent))

        self.assertEqual(len(capture), len(sent))

        for i in range(len(capture)):
            tx = sent[i]
            rx = capture[i]

            eth = rx[Ether]
            self.assertEqual(eth.type, 0x86DD)

            tx_ip = tx[IPv6]
            rx_ip = rx[IPv6]

            # check the MAC address on the RX'd packet is correctly formed
            self.assertEqual(eth.dst, getmacbyip6(rx_ip.dst))

            self.assertEqual(rx_ip.src, tx_ip.src)
            self.assertEqual(rx_ip.dst, tx_ip.dst)
            # IP processing post pop has decremented the TTL
            self.assertEqual(rx_ip.hlim + 1, tx_ip.hlim)

    def test_mfib_zero_flags_ip4(self):
        """IPv4 MFIB zero flag path removal"""
        self.mfib_zero_flags(False)

    def test_mfib_zero_flags_ip6(self):
        """IPv6 MFIB zero flag path removal"""
        self.mfib_zero_flags(True)

    def mfib_zero_flags(self, is_ip6):
        flags = VppEnum.vl_api_mfib_itf_flags_t
        none = flags.MFIB_API_ITF_FLAG_NONE
        proto = (
            FibPathProto.FIB_PATH_NH_PROTO_IP6
            if is_ip6
            else FibPathProto.FIB_PATH_NH_PROTO_IP4
        )
        source, length = ("::", 128) if is_ip6 else ("0.0.0.0", 32)
        route_id = 0

        def path(interface, itf_flags, nh=None):
            return VppMRoutePath(interface.sw_if_index, itf_flags, nh=nh, proto=proto)

        def route(paths):
            nonlocal route_id
            route_id += 1
            group = f"ff3e::43:{route_id}" if is_ip6 else f"239.43.43.{route_id}"
            return VppIpMRoute(
                self,
                source,
                group,
                length,
                VppEnum.vl_api_mfib_entry_flags_t.MFIB_API_ENTRY_FLAG_NONE,
                paths,
            )

        mroute = route([path(self.pg0, none)]).add_vpp_config()
        self.mfib_check_paths(mroute, mroute.paths)
        mroute.remove_vpp_config()
        self.mfib_check_paths(mroute, [])
        self.mfib_zero_flags_transitions(path, route)
        self.mfib_zero_flags_shared_interface(path, route, is_ip6)
        self.mfib_zero_flags_batch(path, route)

    def mfib_check_paths(self, mroute, expected):
        is_ip6 = mroute.prefix.version == 6
        entries = [
            entry.route
            for entry in self.vapi.ip_mroute_dump(0, is_ip6)
            if mroute.prefix == entry.route.prefix
        ]
        if not expected:
            self.assertEqual(entries, [])
            return
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].n_paths, len(expected))
        interface_flags = {}
        for expected_path in expected:
            interface_flags[expected_path.nh_itf] = (
                interface_flags.get(expected_path.nh_itf, 0) | expected_path.nh_i_flags
            )
        self.assertCountEqual(
            [
                (
                    p.path.sw_if_index,
                    p.itf_flags,
                    str(p.path.nh.address.ip6 if is_ip6 else p.path.nh.address.ip4),
                )
                for p in entries[0].paths
            ],
            [(p.nh_itf, interface_flags[p.nh_itf], str(p.nh.addr)) for p in expected],
        )

    def mfib_zero_flags_transitions(self, path, route):
        flags = VppEnum.vl_api_mfib_itf_flags_t
        none = flags.MFIB_API_ITF_FLAG_NONE
        forward = flags.MFIB_API_ITF_FLAG_FORWARD
        accept = flags.MFIB_API_ITF_FLAG_ACCEPT
        for initial, updated in (
            (none, none),
            (forward, none),
            (accept, none),
            (none, forward),
        ):
            with self.subTest(initial=initial, updated=updated):
                mroute = route([path(self.pg0, initial)]).add_vpp_config()
                self.mfib_check_paths(mroute, mroute.paths)
                for _ in range(2):
                    mroute.update_path_flags(self.pg0.sw_if_index, updated)
                    self.mfib_check_paths(mroute, mroute.paths)
                mroute.remove_vpp_config()
                self.mfib_check_paths(mroute, [])

    def mfib_zero_flags_shared_interface(self, path, route, is_ip6):
        flags = VppEnum.vl_api_mfib_itf_flags_t
        neighbor = self.pg0.remote_ip6 if is_ip6 else self.pg0.remote_ip4
        for remove_zero_first in (True, False):
            with self.subTest(remove_zero_first=remove_zero_first):
                zero_path = path(self.pg0, flags.MFIB_API_ITF_FLAG_NONE)
                forward_path = path(self.pg0, flags.MFIB_API_ITF_FLAG_FORWARD, neighbor)
                mroute = route([zero_path, forward_path]).add_vpp_config()
                self.mfib_check_paths(mroute, mroute.paths)
                first, last = (
                    (zero_path, forward_path)
                    if remove_zero_first
                    else (forward_path, zero_path)
                )
                reply = self.vapi.ip_mroute_add_del(
                    route=mroute.encode(paths=[first.encode()]),
                    is_multipath=1,
                    is_add=0,
                )
                self.assertEqual(reply.retval, 0)
                self.mfib_check_paths(mroute, [last])
                mroute.remove_vpp_config()
                self.mfib_check_paths(mroute, [])

    def mfib_zero_flags_batch(self, path, route):
        flags = VppEnum.vl_api_mfib_itf_flags_t
        zero_path = path(self.pg0, flags.MFIB_API_ITF_FLAG_NONE)
        accept_path = path(self.pg1, flags.MFIB_API_ITF_FLAG_ACCEPT)
        remaining_path = path(self.pg2, flags.MFIB_API_ITF_FLAG_FORWARD)
        mroute = route([zero_path, accept_path, remaining_path]).add_vpp_config()
        self.mfib_check_paths(mroute, mroute.paths)
        reply = self.vapi.ip_mroute_add_del(
            route=mroute.encode(paths=[zero_path.encode(), accept_path.encode()]),
            is_multipath=1,
            is_add=0,
        )
        self.assertEqual(reply.retval, 0)
        self.mfib_check_paths(mroute, [remaining_path])
        mroute.remove_vpp_config()
        self.mfib_check_paths(mroute, [])

    def mfib_special_paths(self):
        paths = {}
        for table_id in (0, 10):
            routes = [
                entry.route for entry in self.vapi.ip_mroute_dump(table_id, False)
            ]
            for group in ("224.0.0.1", "224.0.0.2"):
                matches = [
                    route
                    for route in routes
                    if route.table_id == table_id
                    and route.prefix.af == VppEnum.vl_api_address_family_t.ADDRESS_IP4
                    and route.prefix.grp_address_length == 32
                    and str(route.prefix.src_address.ip4) == "0.0.0.0"
                    and str(route.prefix.grp_address.ip4) == group
                ]
                self.assertEqual(len(matches), 1)
                self.assertEqual(matches[0].n_paths, len(matches[0].paths))
                paths[table_id, group] = list(matches[0].paths)
        return paths

    def mfib_special_baseline(self):
        paths = self.mfib_special_paths()
        flags = VppEnum.vl_api_mfib_itf_flags_t
        for (table_id, group), entries in paths.items():
            interfaces = self.pg_interfaces[:8] if table_id == 0 else [self.pg8]
            self.assertCountEqual(
                [
                    entry.path.sw_if_index
                    for entry in entries
                    if entry.itf_flags == flags.MFIB_API_ITF_FLAG_ACCEPT
                ],
                [interface.sw_if_index for interface in interfaces],
            )
            local = [
                entry
                for entry in entries
                if entry.path.type == FibPathType.FIB_PATH_TYPE_LOCAL
            ]
            self.assertEqual(len(local), 1)
            self.assertEqual(local[0].itf_flags, flags.MFIB_API_ITF_FLAG_NONE)
            self.assertEqual(len(entries), len(interfaces) + 1)
        return paths

    def mfib_assert_special_paths(self, expected):
        actual = self.mfib_special_paths()
        self.assertEqual(set(actual), set(expected))
        for key in expected:
            with self.subTest(table=key[0], group=key[1]):
                self.assertCountEqual(actual[key], expected[key])

    def mfib_special_interface(self, baseline, sw_if_index, table_id=None):
        accept = VppEnum.vl_api_mfib_itf_flags_t.MFIB_API_ITF_FLAG_ACCEPT
        expected = {
            key: [entry for entry in entries if entry.path.sw_if_index != sw_if_index]
            for key, entries in baseline.items()
        }
        if table_id is not None:
            for group in ("224.0.0.1", "224.0.0.2"):
                template = next(
                    entry
                    for entry in baseline[0, group]
                    if entry.path.sw_if_index == self.pg0.sw_if_index
                    and entry.itf_flags == accept
                )
                expected[table_id, group].append(
                    template._replace(
                        path=template.path._replace(sw_if_index=sw_if_index)
                    )
                )
        return expected

    def mfib_fib_pool_counts(self):
        counts = {}
        for line in self.vapi.cli("show fib memory").splitlines():
            fields = line.split()
            if fields and fields[0] in ("Entry", "Path", "Path-list"):
                if fields[0] == "Entry" and not fields[1].isdigit():
                    continue
                counts[fields[0]] = int(fields[2])
        self.assertEqual(set(counts), {"Entry", "Path", "Path-list"})
        return counts

    def mfib_assert_addresses(self, interface, prefixes):
        self.assertCountEqual(
            [
                str(entry.prefix)
                for entry in self.vapi.ip_address_dump(interface.sw_if_index)
            ],
            prefixes,
        )

    def mfib_remove_addresses(self, addresses):
        for address in addresses:
            prefixes = [
                str(entry.prefix)
                for entry in self.vapi.ip_address_dump(address.intf.sw_if_index)
            ]
            if address.prefix in prefixes:
                address.remove_vpp_config()

    def mfib_restore_ip4_neighbor(self):
        self.pg0.resolve_arp()
        self.assertTrue(
            find_nbr(
                self,
                self.pg0.sw_if_index,
                self.pg0.remote_ip4,
                mac=self.pg0.remote_mac,
            )
        )

    def mfib_address_removal(self, baseline, extras, remove_index):
        addresses = [
            VppIpInterfaceAddress(self, self.pg0, address, 24) for address in extras
        ]
        prefixes = [self.pg0.local_ip4_prefix] + [
            address.prefix for address in addresses
        ]
        try:
            for address in addresses:
                address.add_vpp_config()
            self.mfib_assert_addresses(self.pg0, prefixes)
            self.mfib_assert_special_paths(baseline)
            if remove_index == 0:
                self.pg0.unconfig_ip4()
            else:
                addresses[remove_index - 1].remove_vpp_config()
            self.mfib_assert_addresses(
                self.pg0,
                [
                    prefix
                    for index, prefix in enumerate(prefixes)
                    if index != remove_index
                ],
            )
            self.mfib_assert_special_paths(baseline)
        finally:
            if not self.pg0.has_ip4_config:
                self.pg0.config_ip4()
            self.mfib_remove_addresses(addresses)
        self.mfib_assert_addresses(self.pg0, [self.pg0.local_ip4_prefix])
        self.mfib_assert_special_paths(baseline)
        self.mfib_restore_ip4_neighbor()

    def test_mfib_ip4_address_lifetime(self):
        """IPv4 special ACCEPT survives removal of any non-final address"""
        baseline = self.mfib_special_baseline()
        pools = self.mfib_fib_pool_counts()
        subnet = self.pg0.local_ip4.rsplit(".", 1)[0]
        scenarios = (
            (f"{subnet}.10", f"{subnet}.20"),
            ("198.18.43.1", "198.18.44.1"),
        )
        for extras in scenarios:
            for remove_index in range(3):
                with self.subTest(extras=extras, remove_index=remove_index):
                    self.mfib_address_removal(baseline, extras, remove_index)
                    self.assertEqual(self.mfib_fib_pool_counts(), pools)
        self.pg0.admin_down()
        try:
            self.mfib_assert_special_paths(baseline)
        finally:
            self.pg0.admin_up()
        self.mfib_assert_special_paths(baseline)
        self.mfib_restore_ip4_neighbor()
        self.pg0.resolve_ndp()
        self.assertTrue(
            find_nbr(
                self,
                self.pg0.sw_if_index,
                self.pg0.remote_ip6,
                mac=self.pg0.remote_mac,
            )
        )
        self.assertEqual(self.mfib_fib_pool_counts(), pools)

    def mfib_rebound_addresses(self, baseline):
        empty = self.mfib_special_interface(baseline, self.pg0.sw_if_index)
        rebound = self.mfib_special_interface(baseline, self.pg0.sw_if_index, 10)
        addresses = [
            VppIpInterfaceAddress(self, self.pg0, address, 24)
            for address in ("198.18.45.1", "198.18.45.2")
        ]
        try:
            self.mfib_assert_special_paths(empty)
            for address in addresses:
                address.add_vpp_config()
                self.mfib_assert_special_paths(rebound)
            self.mfib_assert_addresses(
                self.pg0, [address.prefix for address in addresses]
            )
            for index, address in enumerate(addresses):
                address.remove_vpp_config()
                remaining = addresses[index + 1 :]
                self.mfib_assert_addresses(
                    self.pg0, [entry.prefix for entry in remaining]
                )
                self.mfib_assert_special_paths(rebound if remaining else empty)
        finally:
            self.mfib_remove_addresses(addresses)

    def test_mfib_ip4_address_rebind(self):
        """IPv4 special ACCEPT follows first and last address across tables"""
        baseline = self.mfib_special_baseline()
        pools = self.mfib_fib_pool_counts()
        with self.vapi.assert_negative_api_retval():
            reply = self.vapi.sw_interface_set_table(self.pg0.sw_if_index, 0, 10)
        self.assertLess(reply.retval, 0)
        self.mfib_assert_special_paths(baseline)
        self.mfib_assert_addresses(self.pg0, [self.pg0.local_ip4_prefix])
        try:
            self.pg0.unconfig_ip4()
            self.mfib_assert_addresses(self.pg0, [])
            self.mfib_assert_special_paths(
                self.mfib_special_interface(baseline, self.pg0.sw_if_index)
            )
            self.pg0.set_table_ip4(10)
            self.mfib_rebound_addresses(baseline)
        finally:
            self.pg0.set_table_ip4(0)
            if not self.pg0.has_ip4_config:
                self.pg0.config_ip4()
            self.mfib_assert_addresses(self.pg0, [self.pg0.local_ip4_prefix])
            self.mfib_assert_special_paths(baseline)
            self.mfib_restore_ip4_neighbor()
        self.assertEqual(self.mfib_fib_pool_counts(), pools)

    def mfib_delete_addressed_loopback(self, baseline, table_id):
        interface = VppLoInterface(self)
        deleted = False
        try:
            self.mfib_assert_special_paths(baseline)
            interface.set_table_ip4(table_id)
            expected = self.mfib_special_interface(
                baseline, interface.sw_if_index, table_id
            )
            for address in ("198.18.46.1", "198.18.46.2"):
                self.vapi.sw_interface_add_del_address(
                    sw_if_index=interface.sw_if_index, prefix=f"{address}/24"
                )
                self.mfib_assert_special_paths(expected)
            self.mfib_assert_addresses(interface, ["198.18.46.1/24", "198.18.46.2/24"])
            interface.remove_vpp_config()
            deleted = True
            self.mfib_assert_special_paths(baseline)
        finally:
            if not deleted:
                interface.remove_vpp_config()

    def mfib_recreated_loopback(self, baseline):
        interface = VppLoInterface(self)
        try:
            self.mfib_assert_special_paths(baseline)
            interface.config_ip4()
            self.mfib_assert_special_paths(
                self.mfib_special_interface(baseline, interface.sw_if_index, 0)
            )
            interface.unconfig_ip4()
            self.mfib_assert_special_paths(baseline)
        finally:
            interface.remove_vpp_config()
        self.mfib_assert_special_paths(baseline)

    def test_mfib_ip4_interface_delete(self):
        """IPv4 special ACCEPT is removed when an addressed interface is deleted"""
        baseline = self.mfib_special_baseline()
        pools = self.mfib_fib_pool_counts()
        for table_id in (0, 10):
            with self.subTest(table=table_id):
                self.mfib_delete_addressed_loopback(baseline, table_id)
                self.assertEqual(self.mfib_fib_pool_counts(), pools)
                self.mfib_recreated_loopback(baseline)
                self.assertEqual(self.mfib_fib_pool_counts(), pools)

    def mfib_unnumbered_lifetime(self, baseline, interface):
        donor = self.pg0.sw_if_index
        try:
            for _ in range(2):
                interface.set_unnumbered(donor)
                self.mfib_assert_special_paths(baseline)
            for _ in range(2):
                interface.unset_unnumbered(donor)
                self.mfib_assert_special_paths(baseline)
            self.mfib_assert_addresses(interface, [])
            interface.config_ip4()
            self.mfib_assert_special_paths(
                self.mfib_special_interface(baseline, interface.sw_if_index, 0)
            )
            interface.unconfig_ip4()
            self.mfib_assert_special_paths(baseline)
            interface.set_unnumbered(donor)
            self.mfib_assert_special_paths(baseline)
        finally:
            interface.unconfig_ip4()
            interface.unset_unnumbered(donor)

    def test_mfib_ip4_unnumbered_lifetime(self):
        """IPv4 unnumbered borrowing does not create special ACCEPT paths"""
        baseline = self.mfib_special_baseline()
        pools = self.mfib_fib_pool_counts()
        interface = VppLoInterface(self)
        try:
            self.mfib_unnumbered_lifetime(baseline, interface)
            interface.set_unnumbered(self.pg0.sw_if_index)
            self.mfib_assert_special_paths(baseline)
        finally:
            interface.remove_vpp_config()
        self.mfib_assert_special_paths(baseline)
        self.assertEqual(self.mfib_fib_pool_counts(), pools)

    def mfib_assert_local_address(self, interface, prefix, present):
        routes = [
            entry.route
            for entry in self.vapi.ip_route_dump(0, False)
            if str(entry.route.prefix) == f"{prefix.split('/')[0]}/32"
        ]
        if not present:
            self.assertEqual(routes, [])
            return
        self.assertEqual(len(routes), 1)
        self.assertEqual(routes[0].n_paths, 1)
        self.assertEqual(routes[0].paths[0].sw_if_index, interface.sw_if_index)
        self.assertEqual(routes[0].paths[0].type, FibPathType.FIB_PATH_TYPE_LOCAL)

    def mfib_mixed_address(self, interface, prefix, is_add):
        self.vapi.sw_interface_add_del_address(
            sw_if_index=interface.sw_if_index, prefix=prefix, is_add=is_add
        )
        self.mfib_assert_local_address(interface, prefix, bool(is_add))

    def mfib_mixed_borrower_removal(self, baseline, donor, borrower):
        expected = self.mfib_special_interface(baseline, donor.sw_if_index, 0)
        expected = self.mfib_special_interface(expected, borrower.sw_if_index, 0)
        active = []
        try:
            borrower.set_unnumbered(donor.sw_if_index)
            for prefix in ("198.18.48.1/24", "198.18.49.1/24"):
                self.vapi.sw_interface_add_del_address(
                    sw_if_index=borrower.sw_if_index, prefix=prefix
                )
                active.append(prefix)
                self.mfib_assert_local_address(borrower, prefix, True)
                self.mfib_assert_special_paths(expected)
            borrower.unset_unnumbered(donor.sw_if_index)
            self.mfib_assert_special_paths(expected)
            for prefix in list(active):
                self.vapi.sw_interface_add_del_address(
                    sw_if_index=borrower.sw_if_index, prefix=prefix, is_add=0
                )
                active.remove(prefix)
                self.mfib_assert_local_address(borrower, prefix, False)
                remaining = (
                    expected
                    if active
                    else self.mfib_special_interface(expected, borrower.sw_if_index)
                )
                self.mfib_assert_special_paths(remaining)
                for retained in active:
                    self.mfib_assert_local_address(borrower, retained, True)
                self.mfib_assert_local_address(donor, donor.local_ip4_prefix, True)
        finally:
            borrower.unset_unnumbered(donor.sw_if_index)
            for prefix in active:
                self.mfib_mixed_address(borrower, prefix, 0)

    def test_mfib_ip4_mixed_borrower_removal(self):
        """IPv4 special ACCEPT follows borrower-owned address deletion"""
        baseline = self.mfib_special_baseline()
        pools = self.mfib_fib_pool_counts()
        donor = VppLoInterface(self)
        borrower = VppLoInterface(self)
        try:
            donor.admin_up()
            borrower.admin_up()
            donor.config_ip4()
            self.mfib_mixed_borrower_removal(baseline, donor, borrower)
            self.mfib_assert_local_address(donor, donor.local_ip4_prefix, True)
        finally:
            borrower.remove_vpp_config()
            donor.remove_vpp_config()
        self.mfib_assert_special_paths(baseline)
        self.assertEqual(self.mfib_fib_pool_counts(), pools)

    def mfib_set_borrowed_address(self, interface, donor, is_add):
        reply = self.vapi.sw_interface_set_unnumbered(
            sw_if_index=donor.sw_if_index,
            unnumbered_sw_if_index=interface.sw_if_index,
            is_add=is_add,
        )
        self.assertEqual(reply.retval, 0)

    def mfib_assert_prefix_absent(self, prefix):
        self.assertEqual(
            [
                entry.route
                for entry in self.vapi.ip_route_dump(0, False)
                if str(entry.route.prefix) == prefix
            ],
            [],
        )

    def mfib_delete_loopback(self, interface):
        reply = self.vapi.delete_loopback(interface.sw_if_index)
        self.assertEqual(reply.retval, 0)
        self.assertEqual(
            self.vapi.sw_interface_dump(sw_if_index=interface.sw_if_index), []
        )

    def mfib_clear_donor_head(self, donor):
        self.mfib_set_borrowed_address(donor, self.pg0, True)
        self.mfib_set_borrowed_address(donor, self.pg0, False)

    def mfib_mixed_donor_cleanup(self, donor, borrower, active):
        self.mfib_set_borrowed_address(borrower, donor, False)
        if not active["donor"]:
            self.mfib_clear_donor_head(donor)
        if active["borrower"]:
            self.vapi.sw_interface_add_del_address(
                sw_if_index=borrower.sw_if_index,
                prefix="198.18.50.1/24",
                is_add=0,
            )
            active["borrower"] = False
        if active["donor"]:
            donor.unconfig_ip4()
            active["donor"] = False

    def mfib_mixed_donor_removal(self, baseline, donor, borrower, active):
        donor.config_ip4()
        active["donor"] = True
        self.mfib_set_borrowed_address(borrower, donor, True)
        self.vapi.sw_interface_add_del_address(
            sw_if_index=borrower.sw_if_index, prefix="198.18.50.1/24"
        )
        active["borrower"] = True
        self.mfib_set_borrowed_address(borrower, donor, False)
        donor.unconfig_ip4()
        active["donor"] = False
        expected = self.mfib_special_interface(baseline, borrower.sw_if_index, 0)
        self.mfib_assert_special_paths(expected)
        self.mfib_assert_local_address(donor, donor.local_ip4_prefix, False)
        subnet = donor.local_ip4.rsplit(".", 1)[0]
        self.mfib_assert_prefix_absent(f"{subnet}.0/24")
        self.mfib_assert_local_address(borrower, "198.18.50.1/24", True)

    def mfib_assert_mixed_cleanup(self, baseline, donor, borrower):
        self.mfib_assert_special_paths(baseline)
        self.mfib_assert_local_address(borrower, "198.18.50.1/24", False)
        self.mfib_assert_prefix_absent("198.18.50.0/24")
        self.mfib_assert_local_address(donor, donor.local_ip4_prefix, False)
        for interface in (donor, borrower):
            self.assertEqual(self.vapi.ip_unnumbered_dump(interface.sw_if_index), [])

    def test_mfib_ip4_mixed_donor_removal(self):
        """IPv4 special ACCEPT uses address owner when donor loses its address"""
        baseline = self.mfib_special_baseline()
        pools = self.mfib_fib_pool_counts()
        donor = VppLoInterface(self)
        borrower = VppLoInterface(self)
        active = {"donor": False, "borrower": False}
        try:
            donor.admin_up()
            borrower.admin_up()
            self.mfib_mixed_donor_removal(baseline, donor, borrower, active)
        finally:
            self.mfib_mixed_donor_cleanup(donor, borrower, active)
            try:
                self.mfib_assert_mixed_cleanup(baseline, donor, borrower)
            finally:
                self.mfib_delete_loopback(borrower)
                self.mfib_delete_loopback(donor)
        self.mfib_assert_special_paths(baseline)
        self.assertEqual(self.mfib_fib_pool_counts(), pools)

    def test_ip_mcast(self):
        """IP Multicast Replication"""

        MRouteItfFlags = VppEnum.vl_api_mfib_itf_flags_t
        MRouteEntryFlags = VppEnum.vl_api_mfib_entry_flags_t

        #
        # a stream that matches the default route. gets dropped.
        #
        self.vapi.cli("clear trace")
        self.vapi.cli("packet mac-filter pg0 on")
        self.vapi.cli("packet mac-filter pg1 on")
        self.vapi.cli("packet mac-filter pg2 on")
        self.vapi.cli("packet mac-filter pg4 on")
        self.vapi.cli("packet mac-filter pg5 on")
        self.vapi.cli("packet mac-filter pg6 on")
        self.vapi.cli("packet mac-filter pg7 on")

        tx = self.create_stream_ip4(self.pg0, "1.1.1.1", "232.1.1.1")
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        self.pg0.assert_nothing_captured(
            remark="IP multicast packets forwarded on default route"
        )
        count = self.statistics.get_err_counter("/err/ip4-input/rpf_failure")
        self.assertEqual(count, len(tx))

        #
        # A (*,G).
        # one accepting interface, pg0, 7 forwarding interfaces
        #  many forwarding interfaces test the case where the replicate DPO
        #  needs to use extra cache lines for the buckets.
        #
        route_232_1_1_1 = VppIpMRoute(
            self,
            "0.0.0.0",
            "232.1.1.1",
            32,
            MRouteEntryFlags.MFIB_API_ENTRY_FLAG_NONE,
            [
                VppMRoutePath(
                    self.pg0.sw_if_index, MRouteItfFlags.MFIB_API_ITF_FLAG_ACCEPT
                ),
                VppMRoutePath(
                    self.pg1.sw_if_index, MRouteItfFlags.MFIB_API_ITF_FLAG_FORWARD
                ),
                VppMRoutePath(
                    self.pg2.sw_if_index, MRouteItfFlags.MFIB_API_ITF_FLAG_FORWARD
                ),
                VppMRoutePath(
                    self.pg3.sw_if_index, MRouteItfFlags.MFIB_API_ITF_FLAG_FORWARD
                ),
                VppMRoutePath(
                    self.pg4.sw_if_index, MRouteItfFlags.MFIB_API_ITF_FLAG_FORWARD
                ),
                VppMRoutePath(
                    self.pg5.sw_if_index, MRouteItfFlags.MFIB_API_ITF_FLAG_FORWARD
                ),
                VppMRoutePath(
                    self.pg6.sw_if_index, MRouteItfFlags.MFIB_API_ITF_FLAG_FORWARD
                ),
                VppMRoutePath(
                    self.pg7.sw_if_index, MRouteItfFlags.MFIB_API_ITF_FLAG_FORWARD
                ),
            ],
        )
        route_232_1_1_1.add_vpp_config()

        #
        # An (S,G).
        # one accepting interface, pg0, 2 forwarding interfaces
        #
        route_1_1_1_1_232_1_1_1 = VppIpMRoute(
            self,
            "1.1.1.1",
            "232.1.1.1",
            27,  # any grp-len is ok when src is set
            MRouteEntryFlags.MFIB_API_ENTRY_FLAG_NONE,
            [
                VppMRoutePath(
                    self.pg0.sw_if_index, MRouteItfFlags.MFIB_API_ITF_FLAG_ACCEPT
                ),
                VppMRoutePath(
                    self.pg1.sw_if_index, MRouteItfFlags.MFIB_API_ITF_FLAG_FORWARD
                ),
                VppMRoutePath(
                    self.pg2.sw_if_index, MRouteItfFlags.MFIB_API_ITF_FLAG_FORWARD
                ),
            ],
        )
        route_1_1_1_1_232_1_1_1.add_vpp_config()

        #
        # An (S,G).
        # one accepting interface, pg0, 2 forwarding interfaces
        # that use unicast next-hops
        #
        route_1_1_1_1_232_1_1_2 = VppIpMRoute(
            self,
            "1.1.1.1",
            "232.1.1.2",
            64,
            MRouteEntryFlags.MFIB_API_ENTRY_FLAG_NONE,
            [
                VppMRoutePath(
                    self.pg0.sw_if_index, MRouteItfFlags.MFIB_API_ITF_FLAG_ACCEPT
                ),
                VppMRoutePath(
                    self.pg1.sw_if_index,
                    MRouteItfFlags.MFIB_API_ITF_FLAG_FORWARD,
                    nh=self.pg1.remote_ip4,
                ),
                VppMRoutePath(
                    self.pg2.sw_if_index,
                    MRouteItfFlags.MFIB_API_ITF_FLAG_FORWARD,
                    nh=self.pg2.remote_ip4,
                ),
            ],
        )
        route_1_1_1_1_232_1_1_2.add_vpp_config()

        #
        # An (*,G/m).
        # one accepting interface, pg0, 1 forwarding interfaces
        #
        route_232 = VppIpMRoute(
            self,
            "0.0.0.0",
            "232.0.0.0",
            8,
            MRouteEntryFlags.MFIB_API_ENTRY_FLAG_NONE,
            [
                VppMRoutePath(
                    self.pg0.sw_if_index, MRouteItfFlags.MFIB_API_ITF_FLAG_ACCEPT
                ),
                VppMRoutePath(
                    self.pg1.sw_if_index, MRouteItfFlags.MFIB_API_ITF_FLAG_FORWARD
                ),
            ],
        )
        route_232.add_vpp_config()

        #
        # a stream that matches the route for (1.1.1.1,232.1.1.1)
        #  small packets
        #
        self.vapi.cli("clear trace")
        tx = self.create_stream_ip4(self.pg0, "1.1.1.1", "232.1.1.1")
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        self.assertEqual(route_1_1_1_1_232_1_1_1.get_stats()["packets"], len(tx))

        # We expect replications on Pg1->7
        self.verify_capture_ip4(self.pg1, tx)
        self.verify_capture_ip4(self.pg2, tx)

        # no replications on Pg0
        self.pg0.assert_nothing_captured(remark="IP multicast packets forwarded on PG0")
        self.pg3.assert_nothing_captured(remark="IP multicast packets forwarded on PG3")

        #
        # a stream that matches the route for (1.1.1.1,232.1.1.1)
        #  large packets
        #
        self.vapi.cli("clear trace")
        tx = self.create_stream_ip4(self.pg0, "1.1.1.1", "232.1.1.1", payload_size=1024)
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # We expect replications on Pg1->7
        self.verify_capture_ip4(self.pg1, tx)
        self.verify_capture_ip4(self.pg2, tx)

        self.assertEqual(route_1_1_1_1_232_1_1_1.get_stats()["packets"], 2 * len(tx))

        # no replications on Pg0
        self.pg0.assert_nothing_captured(remark="IP multicast packets forwarded on PG0")
        self.pg3.assert_nothing_captured(remark="IP multicast packets forwarded on PG3")

        #
        # a stream to the unicast next-hops
        #
        self.vapi.cli("clear trace")
        tx = self.create_stream_ip4(self.pg0, "1.1.1.1", "232.1.1.2")
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # We expect replications on Pg1->7
        self.verify_capture_ip4(self.pg1, tx, dst_mac=self.pg1.remote_mac)
        self.verify_capture_ip4(self.pg2, tx, dst_mac=self.pg2.remote_mac)

        # no replications on Pg0 nor pg3
        self.pg0.assert_nothing_captured(remark="IP multicast packets forwarded on PG0")
        self.pg3.assert_nothing_captured(remark="IP multicast packets forwarded on PG3")

        #
        # a stream that matches the route for (*,232.0.0.0/8)
        # Send packets with the 9th bit set so we test the correct clearing
        # of that bit in the mac rewrite
        #
        self.vapi.cli("clear trace")
        tx = self.create_stream_ip4(self.pg0, "1.1.1.1", "232.255.255.255")
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # We expect replications on Pg1 only
        self.verify_capture_ip4(self.pg1, tx)
        self.assertEqual(route_232.get_stats()["packets"], len(tx))

        # no replications on Pg0, Pg2 not Pg3
        self.pg0.assert_nothing_captured(remark="IP multicast packets forwarded on PG0")
        self.pg2.assert_nothing_captured(remark="IP multicast packets forwarded on PG2")
        self.pg3.assert_nothing_captured(remark="IP multicast packets forwarded on PG3")

        #
        # a stream that matches the route for (*,232.1.1.1)
        #
        self.vapi.cli("clear trace")
        tx = self.create_stream_ip4(self.pg0, "1.1.1.2", "232.1.1.1")
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # We expect replications on Pg1->7
        self.verify_capture_ip4(self.pg1, tx)
        self.verify_capture_ip4(self.pg2, tx)
        self.verify_capture_ip4(self.pg3, tx)
        self.verify_capture_ip4(self.pg4, tx)
        self.verify_capture_ip4(self.pg5, tx)
        self.verify_capture_ip4(self.pg6, tx)
        self.verify_capture_ip4(self.pg7, tx)

        # no replications on Pg0
        self.pg0.assert_nothing_captured(remark="IP multicast packets forwarded on PG0")

        self.vapi.cli("packet mac-filter pg0 off")
        self.vapi.cli("packet mac-filter pg1 off")
        self.vapi.cli("packet mac-filter pg2 off")
        self.vapi.cli("packet mac-filter pg4 off")
        self.vapi.cli("packet mac-filter pg5 off")
        self.vapi.cli("packet mac-filter pg6 off")
        self.vapi.cli("packet mac-filter pg7 off")

    def test_ip6_mcast(self):
        """IPv6 Multicast Replication"""

        MRouteItfFlags = VppEnum.vl_api_mfib_itf_flags_t
        MRouteEntryFlags = VppEnum.vl_api_mfib_entry_flags_t

        self.vapi.cli("packet mac-filter pg0 on")
        self.vapi.cli("packet mac-filter pg1 on")
        self.vapi.cli("packet mac-filter pg2 on")
        self.vapi.cli("packet mac-filter pg4 on")
        self.vapi.cli("packet mac-filter pg5 on")
        self.vapi.cli("packet mac-filter pg6 on")
        self.vapi.cli("packet mac-filter pg7 on")
        #
        # a stream that matches the default route. gets dropped.
        #
        self.vapi.cli("clear trace")
        tx = self.create_stream_ip6(self.pg0, "2001::1", "ff01::1")
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        self.pg0.assert_nothing_captured(
            remark="IPv6 multicast packets forwarded on default route"
        )

        #
        # A (*,G).
        # one accepting interface, pg0, 3 forwarding interfaces
        #
        route_ff01_1 = VppIpMRoute(
            self,
            "::",
            "ff01::1",
            128,
            MRouteEntryFlags.MFIB_API_ENTRY_FLAG_NONE,
            [
                VppMRoutePath(
                    self.pg0.sw_if_index,
                    MRouteItfFlags.MFIB_API_ITF_FLAG_ACCEPT,
                    proto=FibPathProto.FIB_PATH_NH_PROTO_IP6,
                ),
                VppMRoutePath(
                    self.pg1.sw_if_index,
                    MRouteItfFlags.MFIB_API_ITF_FLAG_FORWARD,
                    proto=FibPathProto.FIB_PATH_NH_PROTO_IP6,
                ),
                VppMRoutePath(
                    self.pg2.sw_if_index,
                    MRouteItfFlags.MFIB_API_ITF_FLAG_FORWARD,
                    proto=FibPathProto.FIB_PATH_NH_PROTO_IP6,
                ),
                VppMRoutePath(
                    self.pg3.sw_if_index,
                    MRouteItfFlags.MFIB_API_ITF_FLAG_FORWARD,
                    proto=FibPathProto.FIB_PATH_NH_PROTO_IP6,
                ),
            ],
        )
        route_ff01_1.add_vpp_config()

        #
        # An (S,G).
        # one accepting interface, pg0, 2 forwarding interfaces
        #
        route_2001_ff01_1 = VppIpMRoute(
            self,
            "2001::1",
            "ff01::1",
            0,  # any grp-len is ok when src is set
            MRouteEntryFlags.MFIB_API_ENTRY_FLAG_NONE,
            [
                VppMRoutePath(
                    self.pg0.sw_if_index,
                    MRouteItfFlags.MFIB_API_ITF_FLAG_ACCEPT,
                    proto=FibPathProto.FIB_PATH_NH_PROTO_IP6,
                ),
                VppMRoutePath(
                    self.pg1.sw_if_index,
                    MRouteItfFlags.MFIB_API_ITF_FLAG_FORWARD,
                    proto=FibPathProto.FIB_PATH_NH_PROTO_IP6,
                ),
                VppMRoutePath(
                    self.pg2.sw_if_index,
                    MRouteItfFlags.MFIB_API_ITF_FLAG_FORWARD,
                    proto=FibPathProto.FIB_PATH_NH_PROTO_IP6,
                ),
            ],
        )
        route_2001_ff01_1.add_vpp_config()

        #
        # An (*,G/m).
        # one accepting interface, pg0, 1 forwarding interface
        #
        route_ff01 = VppIpMRoute(
            self,
            "::",
            "ff01::",
            16,
            MRouteEntryFlags.MFIB_API_ENTRY_FLAG_NONE,
            [
                VppMRoutePath(
                    self.pg0.sw_if_index,
                    MRouteItfFlags.MFIB_API_ITF_FLAG_ACCEPT,
                    proto=FibPathProto.FIB_PATH_NH_PROTO_IP6,
                ),
                VppMRoutePath(
                    self.pg1.sw_if_index,
                    MRouteItfFlags.MFIB_API_ITF_FLAG_FORWARD,
                    proto=FibPathProto.FIB_PATH_NH_PROTO_IP6,
                ),
            ],
        )
        route_ff01.add_vpp_config()

        #
        # a stream that matches the route for (*, ff01::/16)
        # sent on the non-accepting interface
        #
        self.vapi.cli("clear trace")
        tx = self.create_stream_ip6(self.pg1, "2002::1", "ff01:2::255")
        self.send_and_assert_no_replies(self.pg1, tx, "RPF miss")
        count = self.statistics.get_err_counter("/err/ip6-input/rpf_failure")
        self.assertEqual(count, 2 * len(tx))

        #
        # a stream that matches the route for (*, ff01::/16)
        # sent on the accepting interface
        #
        self.vapi.cli("clear trace")
        tx = self.create_stream_ip6(self.pg0, "2002::1", "ff01:2::255")
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # We expect replications on Pg1
        self.verify_capture_ip6(self.pg1, tx)

        # no replications on Pg0, Pg3
        self.pg0.assert_nothing_captured(remark="IP multicast packets forwarded on PG0")
        self.pg2.assert_nothing_captured(remark="IP multicast packets forwarded on PG2")
        self.pg3.assert_nothing_captured(remark="IP multicast packets forwarded on PG3")

        #
        # Bounce the interface and it should still work
        #
        self.pg1.admin_down()
        self.pg0.add_stream(tx)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg1.assert_nothing_captured(
            remark="IP multicast packets forwarded on down PG1"
        )

        self.pg1.admin_up()
        self.pg0.add_stream(tx)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.verify_capture_ip6(self.pg1, tx)

        #
        # a stream that matches the route for (*,ff01::1)
        #
        self.vapi.cli("clear trace")
        tx = self.create_stream_ip6(self.pg0, "2002::2", "ff01::1")
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # We expect replications on Pg1, 2, 3.
        self.verify_capture_ip6(self.pg1, tx)
        self.verify_capture_ip6(self.pg2, tx)
        self.verify_capture_ip6(self.pg3, tx)

        # no replications on Pg0
        self.pg0.assert_nothing_captured(
            remark="IPv6 multicast packets forwarded on PG0"
        )

        #
        # a stream that matches the route for (2001::1, ff00::1)
        #
        self.vapi.cli("clear trace")
        tx = self.create_stream_ip6(self.pg0, "2001::1", "ff01::1")
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # We expect replications on Pg1, 2,
        self.verify_capture_ip6(self.pg1, tx)
        self.verify_capture_ip6(self.pg2, tx)

        # no replications on Pg0, Pg3
        self.pg0.assert_nothing_captured(remark="IP multicast packets forwarded on PG0")
        self.pg3.assert_nothing_captured(remark="IP multicast packets forwarded on PG3")

        self.vapi.cli("packet mac-filter pg0 off")
        self.vapi.cli("packet mac-filter pg1 off")
        self.vapi.cli("packet mac-filter pg2 off")
        self.vapi.cli("packet mac-filter pg4 off")
        self.vapi.cli("packet mac-filter pg5 off")
        self.vapi.cli("packet mac-filter pg6 off")
        self.vapi.cli("packet mac-filter pg7 off")

    def _mcast_connected_send_stream(self, dst_ip):
        self.vapi.cli("clear trace")
        tx = self.create_stream_ip4(self.pg0, self.pg0.remote_ip4, dst_ip)
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # We expect replications on Pg1.
        self.verify_capture_ip4(self.pg1, tx)

        return tx

    def test_ip_mcast_connected(self):
        """IP Multicast Connected Source check"""

        MRouteItfFlags = VppEnum.vl_api_mfib_itf_flags_t
        MRouteEntryFlags = VppEnum.vl_api_mfib_entry_flags_t

        #
        # A (*,G).
        # one accepting interface, pg0, 1 forwarding interfaces
        #
        route_232_1_1_1 = VppIpMRoute(
            self,
            "0.0.0.0",
            "232.1.1.1",
            32,
            MRouteEntryFlags.MFIB_API_ENTRY_FLAG_NONE,
            [
                VppMRoutePath(
                    self.pg0.sw_if_index, MRouteItfFlags.MFIB_API_ITF_FLAG_ACCEPT
                ),
                VppMRoutePath(
                    self.pg1.sw_if_index, MRouteItfFlags.MFIB_API_ITF_FLAG_FORWARD
                ),
            ],
        )

        route_232_1_1_1.add_vpp_config()
        route_232_1_1_1.update_entry_flags(
            MRouteEntryFlags.MFIB_API_ENTRY_FLAG_CONNECTED
        )

        #
        # Now the (*,G) is present, send from connected source
        #
        tx = self._mcast_connected_send_stream("232.1.1.1")

        #
        # Constrct a representation of the signal we expect on pg0
        #
        signal_232_1_1_1_itf_0 = VppMFibSignal(
            self, route_232_1_1_1, self.pg0.sw_if_index, tx[0]
        )

        #
        # read the only expected signal
        #
        signals = self.vapi.mfib_signal_dump()

        self.assertEqual(1, len(signals))

        signal_232_1_1_1_itf_0.compare(signals[0])

        #
        # reading the signal allows for the generation of another
        # so send more packets and expect the next signal
        #
        tx = self._mcast_connected_send_stream("232.1.1.1")

        signals = self.vapi.mfib_signal_dump()
        self.assertEqual(1, len(signals))
        signal_232_1_1_1_itf_0.compare(signals[0])

        #
        # A Second entry with connected check
        # one accepting interface, pg0, 1 forwarding interfaces
        #
        route_232_1_1_2 = VppIpMRoute(
            self,
            "0.0.0.0",
            "232.1.1.2",
            32,
            MRouteEntryFlags.MFIB_API_ENTRY_FLAG_NONE,
            [
                VppMRoutePath(
                    self.pg0.sw_if_index, MRouteItfFlags.MFIB_API_ITF_FLAG_ACCEPT
                ),
                VppMRoutePath(
                    self.pg1.sw_if_index, MRouteItfFlags.MFIB_API_ITF_FLAG_FORWARD
                ),
            ],
        )

        route_232_1_1_2.add_vpp_config()
        route_232_1_1_2.update_entry_flags(
            MRouteEntryFlags.MFIB_API_ENTRY_FLAG_CONNECTED
        )

        #
        # Send traffic to both entries. One read should net us two signals
        #
        signal_232_1_1_2_itf_0 = VppMFibSignal(
            self, route_232_1_1_2, self.pg0.sw_if_index, tx[0]
        )
        tx = self._mcast_connected_send_stream("232.1.1.1")
        tx2 = self._mcast_connected_send_stream("232.1.1.2")

        #
        # read the only expected signal
        #
        signals = self.vapi.mfib_signal_dump()

        self.assertEqual(2, len(signals))

        signal_232_1_1_1_itf_0.compare(signals[1])
        signal_232_1_1_2_itf_0.compare(signals[0])

        route_232_1_1_1.update_entry_flags(MRouteEntryFlags.MFIB_API_ENTRY_FLAG_NONE)
        route_232_1_1_2.update_entry_flags(MRouteEntryFlags.MFIB_API_ENTRY_FLAG_NONE)

    def test_ip_mcast_signal(self):
        """IP Multicast Signal"""

        MRouteItfFlags = VppEnum.vl_api_mfib_itf_flags_t
        MRouteEntryFlags = VppEnum.vl_api_mfib_entry_flags_t

        #
        # A (*,G).
        # one accepting interface, pg0, 1 forwarding interfaces
        #
        route_232_1_1_1 = VppIpMRoute(
            self,
            "0.0.0.0",
            "232.1.1.1",
            32,
            MRouteEntryFlags.MFIB_API_ENTRY_FLAG_NONE,
            [
                VppMRoutePath(
                    self.pg0.sw_if_index, MRouteItfFlags.MFIB_API_ITF_FLAG_ACCEPT
                ),
                VppMRoutePath(
                    self.pg1.sw_if_index, MRouteItfFlags.MFIB_API_ITF_FLAG_FORWARD
                ),
            ],
        )

        route_232_1_1_1.add_vpp_config()

        route_232_1_1_1.update_entry_flags(MRouteEntryFlags.MFIB_API_ENTRY_FLAG_SIGNAL)

        #
        # Now the (*,G) is present, send from connected source
        #
        tx = self._mcast_connected_send_stream("232.1.1.1")

        #
        # Constrct a representation of the signal we expect on pg0
        #
        signal_232_1_1_1_itf_0 = VppMFibSignal(
            self, route_232_1_1_1, self.pg0.sw_if_index, tx[0]
        )

        #
        # read the only expected signal
        #
        signals = self.vapi.mfib_signal_dump()

        self.assertEqual(1, len(signals))

        signal_232_1_1_1_itf_0.compare(signals[0])

        #
        # reading the signal allows for the generation of another
        # so send more packets and expect the next signal
        #
        tx = self._mcast_connected_send_stream("232.1.1.1")

        signals = self.vapi.mfib_signal_dump()
        self.assertEqual(1, len(signals))
        signal_232_1_1_1_itf_0.compare(signals[0])

        #
        # Set the negate-signal on the accepting interval - the signals
        # should stop
        #
        route_232_1_1_1.update_path_flags(
            self.pg0.sw_if_index,
            (
                MRouteItfFlags.MFIB_API_ITF_FLAG_ACCEPT
                | MRouteItfFlags.MFIB_API_ITF_FLAG_NEGATE_SIGNAL
            ),
        )

        self.vapi.cli("clear trace")
        tx = self._mcast_connected_send_stream("232.1.1.1")

        signals = self.vapi.mfib_signal_dump()
        self.assertEqual(0, len(signals))

        #
        # Clear the SIGNAL flag on the entry and the signals should
        # come back since the interface is still NEGATE-SIGNAL
        #
        route_232_1_1_1.update_entry_flags(MRouteEntryFlags.MFIB_API_ENTRY_FLAG_NONE)

        tx = self._mcast_connected_send_stream("232.1.1.1")

        signals = self.vapi.mfib_signal_dump()
        self.assertEqual(1, len(signals))
        signal_232_1_1_1_itf_0.compare(signals[0])

        #
        # Lastly remove the NEGATE-SIGNAL from the interface and the
        # signals should stop
        #
        route_232_1_1_1.update_path_flags(
            self.pg0.sw_if_index, MRouteItfFlags.MFIB_API_ITF_FLAG_ACCEPT
        )

        tx = self._mcast_connected_send_stream("232.1.1.1")
        signals = self.vapi.mfib_signal_dump()
        self.assertEqual(0, len(signals))

    @unittest.skipIf(
        "ping" in config.excluded_plugins, "Exclude tests requiring Ping plugin"
    )
    def test_ip_mcast_vrf(self):
        """IP Multicast Replication in non-default table"""

        MRouteItfFlags = VppEnum.vl_api_mfib_itf_flags_t
        MRouteEntryFlags = VppEnum.vl_api_mfib_entry_flags_t

        #
        # An (S,G).
        # one accepting interface, pg0, 2 forwarding interfaces
        #
        route_1_1_1_1_232_1_1_1 = VppIpMRoute(
            self,
            "1.1.1.1",
            "232.1.1.1",
            64,
            MRouteEntryFlags.MFIB_API_ENTRY_FLAG_NONE,
            [
                VppMRoutePath(
                    self.pg8.sw_if_index, MRouteItfFlags.MFIB_API_ITF_FLAG_ACCEPT
                ),
                VppMRoutePath(
                    self.pg1.sw_if_index, MRouteItfFlags.MFIB_API_ITF_FLAG_FORWARD
                ),
                VppMRoutePath(
                    self.pg2.sw_if_index, MRouteItfFlags.MFIB_API_ITF_FLAG_FORWARD
                ),
            ],
            table_id=10,
        )
        route_1_1_1_1_232_1_1_1.add_vpp_config()

        #
        # a stream that matches the route for (1.1.1.1,232.1.1.1)
        #  small packets
        #
        self.vapi.cli("clear trace")
        tx = self.create_stream_ip4(self.pg8, "1.1.1.1", "232.1.1.1")
        self.pg8.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # We expect replications on Pg1 & 2
        self.verify_capture_ip4(self.pg1, tx)
        self.verify_capture_ip4(self.pg2, tx)

        #
        # An (S,G). for for-us
        #
        route_0_0_0_0_224_0_0_5 = VppIpMRoute(
            self,
            "0.0.0.0",
            "224.0.0.5",
            32,
            MRouteEntryFlags.MFIB_API_ENTRY_FLAG_NONE,
            [
                VppMRoutePath(
                    self.pg8.sw_if_index, MRouteItfFlags.MFIB_API_ITF_FLAG_ACCEPT
                ),
                VppMRoutePath(
                    0xFFFFFFFF,
                    MRouteItfFlags.MFIB_API_ITF_FLAG_FORWARD,
                    type=FibPathType.FIB_PATH_TYPE_LOCAL,
                ),
            ],
            table_id=10,
        )
        route_0_0_0_0_224_0_0_5.add_vpp_config()

        #
        # a stream that matches the route for (0.0.0.0, 224.0.0.5)
        #  small packets
        #
        self.vapi.cli("clear trace")
        self.pg8.resolve_arp()

        #
        # send a ping to mcast address from peer on pg8
        #  expect a response
        #
        icmp_id = 0xB
        icmp_seq = 5
        icmp_load = b"\x0a" * 18
        tx = (
            Ether(dst=getmacbyip("224.0.0.5"), src=self.pg8.remote_mac)
            / IP(src=self.pg8.remote_ip4, dst="224.0.0.5")
            / ICMP(id=icmp_id, seq=icmp_seq)
            / Raw(load=icmp_load)
        ) * 2

        self.send_and_expect(self.pg8, tx, self.pg8)

    @unittest.skipIf(
        "gre" in config.excluded_plugins, "Exclude tests requiring GRE plugin"
    )
    def test_ip_mcast_gre(self):
        """IP Multicast Replication over GRE"""

        MRouteItfFlags = VppEnum.vl_api_mfib_itf_flags_t
        MRouteEntryFlags = VppEnum.vl_api_mfib_entry_flags_t

        gre_if_1 = VppGreInterface(
            self, self.pg1.local_ip4, self.pg1.remote_ip4
        ).add_vpp_config()
        gre_if_2 = VppGreInterface(
            self, self.pg2.local_ip4, self.pg2.remote_ip4
        ).add_vpp_config()
        gre_if_3 = VppGreInterface(
            self, self.pg3.local_ip4, self.pg3.remote_ip4
        ).add_vpp_config()

        gre_if_1.admin_up()
        gre_if_1.config_ip4()
        gre_if_2.admin_up()
        gre_if_2.config_ip4()
        gre_if_3.admin_up()
        gre_if_3.config_ip4()

        #
        # An (S,G).
        # one accepting interface, pg0, 2 forwarding interfaces
        #
        route_1_1_1_1_232_1_1_1 = VppIpMRoute(
            self,
            "1.1.1.1",
            "232.2.2.2",
            64,
            MRouteEntryFlags.MFIB_API_ENTRY_FLAG_NONE,
            [
                VppMRoutePath(
                    gre_if_1.sw_if_index, MRouteItfFlags.MFIB_API_ITF_FLAG_ACCEPT
                ),
                VppMRoutePath(
                    gre_if_2.sw_if_index, MRouteItfFlags.MFIB_API_ITF_FLAG_FORWARD
                ),
                VppMRoutePath(
                    gre_if_3.sw_if_index, MRouteItfFlags.MFIB_API_ITF_FLAG_FORWARD
                ),
            ],
        )
        route_1_1_1_1_232_1_1_1.add_vpp_config()

        #
        # a stream that matches the route for (1.1.1.1,232.2.2.2)
        #  small packets
        #
        tx = (
            Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg1.local_ip4)
            / GRE()
            / IP(src="1.1.1.1", dst="232.2.2.2")
            / UDP(sport=1234, dport=1234)
            / Raw(b"\a5" * 64)
        ) * 63

        self.vapi.cli("clear trace")
        self.pg1.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # We expect replications on Pg2 & 3
        # check the encap headers are as expected based on the egress tunnel
        rxs = self.pg2.get_capture(len(tx))
        for rx in rxs:
            self.assertEqual(rx[IP].src, gre_if_2.t_src)
            self.assertEqual(rx[IP].dst, gre_if_2.t_dst)
            self.assert_packet_checksums_valid(rx)

        rxs = self.pg3.get_capture(len(tx))
        for rx in rxs:
            self.assertEqual(rx[IP].src, gre_if_3.t_src)
            self.assertEqual(rx[IP].dst, gre_if_3.t_dst)
            self.assert_packet_checksums_valid(rx)

    @unittest.skipIf(
        "gre" in config.excluded_plugins, "Exclude tests requiring GRE plugin"
    )
    def test_ip6_mcast_gre(self):
        """IP6 Multicast Replication over GRE"""

        MRouteItfFlags = VppEnum.vl_api_mfib_itf_flags_t
        MRouteEntryFlags = VppEnum.vl_api_mfib_entry_flags_t

        gre_if_1 = VppGreInterface(
            self, self.pg1.local_ip4, self.pg1.remote_ip4
        ).add_vpp_config()
        gre_if_2 = VppGreInterface(
            self, self.pg2.local_ip4, self.pg2.remote_ip4
        ).add_vpp_config()
        gre_if_3 = VppGreInterface(
            self, self.pg3.local_ip4, self.pg3.remote_ip4
        ).add_vpp_config()

        gre_if_1.admin_up()
        gre_if_1.config_ip6()
        gre_if_2.admin_up()
        gre_if_2.config_ip6()
        gre_if_3.admin_up()
        gre_if_3.config_ip6()

        #
        # An (S,G).
        # one accepting interface, pg0, 2 forwarding interfaces
        #
        route_1_1_FF_1 = VppIpMRoute(
            self,
            "1::1",
            "FF00::1",
            256,
            MRouteEntryFlags.MFIB_API_ENTRY_FLAG_NONE,
            [
                VppMRoutePath(
                    gre_if_1.sw_if_index, MRouteItfFlags.MFIB_API_ITF_FLAG_ACCEPT
                ),
                VppMRoutePath(
                    gre_if_2.sw_if_index, MRouteItfFlags.MFIB_API_ITF_FLAG_FORWARD
                ),
                VppMRoutePath(
                    gre_if_3.sw_if_index, MRouteItfFlags.MFIB_API_ITF_FLAG_FORWARD
                ),
            ],
        )
        route_1_1_FF_1.add_vpp_config()

        #
        # a stream that matches the route for (1::1, FF::1)
        #  small packets
        #
        tx = (
            Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg1.local_ip4)
            / GRE()
            / IPv6(src="1::1", dst="FF00::1")
            / UDP(sport=1234, dport=1234)
            / Raw(b"\a5" * 64)
        ) * 63

        self.vapi.cli("clear trace")
        self.pg1.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # We expect replications on Pg2 & 3
        # check the encap headers are as expected based on the egress tunnel
        rxs = self.pg2.get_capture(len(tx))
        for rx in rxs:
            self.assertEqual(rx[IP].src, gre_if_2.t_src)
            self.assertEqual(rx[IP].dst, gre_if_2.t_dst)
            self.assert_packet_checksums_valid(rx)

        rxs = self.pg3.get_capture(len(tx))
        for rx in rxs:
            self.assertEqual(rx[IP].src, gre_if_3.t_src)
            self.assertEqual(rx[IP].dst, gre_if_3.t_dst)
            self.assert_packet_checksums_valid(rx)

    def test_ip6_mcast_vrf(self):
        """IPv6 Multicast Replication in non-default table"""

        MRouteItfFlags = VppEnum.vl_api_mfib_itf_flags_t
        MRouteEntryFlags = VppEnum.vl_api_mfib_entry_flags_t

        #
        # An (S,G).
        # one accepting interface, pg0, 2 forwarding interfaces
        #
        route_2001_ff01_1 = VppIpMRoute(
            self,
            "2001::1",
            "ff01::1",
            256,
            MRouteEntryFlags.MFIB_API_ENTRY_FLAG_NONE,
            [
                VppMRoutePath(
                    self.pg8.sw_if_index,
                    MRouteItfFlags.MFIB_API_ITF_FLAG_ACCEPT,
                    proto=FibPathProto.FIB_PATH_NH_PROTO_IP6,
                ),
                VppMRoutePath(
                    self.pg1.sw_if_index,
                    MRouteItfFlags.MFIB_API_ITF_FLAG_FORWARD,
                    proto=FibPathProto.FIB_PATH_NH_PROTO_IP6,
                ),
                VppMRoutePath(
                    self.pg2.sw_if_index,
                    MRouteItfFlags.MFIB_API_ITF_FLAG_FORWARD,
                    proto=FibPathProto.FIB_PATH_NH_PROTO_IP6,
                ),
            ],
            table_id=10,
        )
        route_2001_ff01_1.add_vpp_config()

        #
        # a stream that matches the route for (2001::1, ff00::1)
        #
        self.vapi.cli("clear trace")
        tx = self.create_stream_ip6(self.pg8, "2001::1", "ff01::1")
        self.pg8.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # We expect replications on Pg1, 2,
        self.verify_capture_ip6(self.pg1, tx)
        self.verify_capture_ip6(self.pg2, tx)

    def test_bidir(self):
        """IP Multicast Bi-directional"""

        MRouteItfFlags = VppEnum.vl_api_mfib_itf_flags_t
        MRouteEntryFlags = VppEnum.vl_api_mfib_entry_flags_t

        #
        # A (*,G). The set of accepting interfaces matching the forwarding
        #
        route_232_1_1_1 = VppIpMRoute(
            self,
            "0.0.0.0",
            "232.1.1.1",
            32,
            MRouteEntryFlags.MFIB_API_ENTRY_FLAG_NONE,
            [
                VppMRoutePath(
                    self.pg0.sw_if_index,
                    MRouteItfFlags.MFIB_API_ITF_FLAG_ACCEPT
                    | MRouteItfFlags.MFIB_API_ITF_FLAG_FORWARD,
                ),
                VppMRoutePath(
                    self.pg1.sw_if_index,
                    MRouteItfFlags.MFIB_API_ITF_FLAG_ACCEPT
                    | MRouteItfFlags.MFIB_API_ITF_FLAG_FORWARD,
                ),
                VppMRoutePath(
                    self.pg2.sw_if_index,
                    MRouteItfFlags.MFIB_API_ITF_FLAG_ACCEPT
                    | MRouteItfFlags.MFIB_API_ITF_FLAG_FORWARD,
                ),
                VppMRoutePath(
                    self.pg3.sw_if_index,
                    MRouteItfFlags.MFIB_API_ITF_FLAG_ACCEPT
                    | MRouteItfFlags.MFIB_API_ITF_FLAG_FORWARD,
                ),
            ],
        )
        route_232_1_1_1.add_vpp_config()

        tx = self.create_stream_ip4(self.pg0, "1.1.1.1", "232.1.1.1")
        self.pg0.add_stream(tx)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # We expect replications on Pg1, 2, 3, but not on pg0
        self.verify_capture_ip4(self.pg1, tx)
        self.verify_capture_ip4(self.pg2, tx)
        self.verify_capture_ip4(self.pg3, tx)
        self.pg0.assert_nothing_captured(remark="IP multicast packets forwarded on PG0")


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
