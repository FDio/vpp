#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0

"""
Performance harness for inner-aware flow hash.

Reuses the ECMP fixture from test_inner_aware_hash but instead of asserting
on distribution, it measures wall-clock send/receive throughput for a
fixed packet count and exports the result so a higher-level test plan can
compare PEEK_INNER on vs off.

The measurement is intentionally simple:

  * For each scenario (plain v4 TCP, plain v6 TCP, IPinIP v4/v4 with random
    inner ports, NVGRE v4/v4 with random inner ports) we send N packets,
    time the send + capture loop, and divide.

  * We then dump VPP's ``show runtime`` so the human reading the test log
    can see the per-node clocks/vector for the ip4-lookup / ip6-lookup
    nodes - which is where the helper runs.

  * Both PEEK_INNER off (default fib) and PEEK_INNER on are run inside one
    test class via ``setUp`` toggling.

This file also covers the LAG TX side of the feature:

  * ``TestInnerAwareLAGPerf`` builds an XOR bond with two members and the
    new ``BOND_API_LB_ALGO_L34_INNER`` algorithm, then measures clocks/pkt
    at the bond TX node (``BondEthernet0-tx``) for plain, IPinIP and NVGRE.

  * ``TestInnerAwareLAGLegacyPerf`` repeats the same scenarios pinned to
    the upstream-compatible ``BOND_API_LB_ALGO_L34`` for direct A/B
    comparison.  The two classes write separate JSON sidecars
    (``..._lag.json`` and ``..._lag_legacy.json``).

This is NOT a rigorous PPS benchmark - VPP unit tests run inside a
software-only scapy harness without DPDK and are bottlenecked by the
test framework.  But it is enough to confirm there is no order-of-
magnitude regression.

Results are appended to a JSON sidecar next to the test log so the
operator can copy them into release notes.
"""

import json
import os
import random
import time
import unittest

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6

from framework import VppTestCase
from asfframework import VppTestRunner
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_bond_interface import VppBondInterface
from vpp_papi import VppEnum, MACAddress
from config import config

N_PKTS = 1024
N_HOSTS = 4
PROTO_IPINIP4 = 4
PROTO_GRE = 47
PAYLOAD_TAG = b"perf-inner-aware-hash"


def _rand_v4(rng):
    return "10.%d.%d.%d" % (
        rng.randint(0, 255),
        rng.randint(0, 255),
        rng.randint(1, 254),
    )


class TestInnerAwarePerf(VppTestCase):
    """Performance harness for inner-aware flow hash"""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.create_pg_interfaces(range(4))
        for i in cls.pg_interfaces:
            i.admin_up()
            i.generate_remote_hosts(N_HOSTS)
            i.config_ip4()
            i.resolve_arp()
            i.configure_ipv4_neighbors()
            i.config_ip6()
            i.resolve_ndp()
            i.configure_ipv6_neighbors()
        cls.perf_results = []

    @classmethod
    def tearDownClass(cls):
        try:
            results_path = os.path.join(config.tmp_dir, "test_inner_aware_perf.json")
            with open(results_path, "w") as f:
                json.dump(cls.perf_results, f, indent=2)
            cls.logger.info("Wrote perf JSON: %s" % results_path)
        except Exception as e:
            cls.logger.warning("could not write perf JSON: %s" % e)
        if not cls.vpp_dead:
            for i in cls.pg_interfaces:
                i.unconfig_ip4()
                i.unconfig_ip6()
                i.admin_down()
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        self.reset_packet_infos()

    def _set_peek_inner(self, on):
        kw = "peek_inner" if on else ""
        self.vapi.cli("set ip flow-hash table 0 src dst sport dport proto %s" % kw)
        self.vapi.cli("set ip6 flow-hash table 0 src dst sport dport proto %s" % kw)

    def _add_ecmp_route(self, dst_net, prefix_len, is_ipv6):
        paths = []
        for pg_if in self.pg_interfaces[1:]:
            for nh in pg_if.remote_hosts:
                nh_ip = nh.ip6 if is_ipv6 else nh.ip4
                paths.append(VppRoutePath(nh_ip, pg_if.sw_if_index))
        rip = VppIpRoute(self, dst_net, prefix_len, paths)
        rip.add_vpp_config()
        return rip

    def _build_plain_v4(self, rng):
        return IP(src=_rand_v4(rng), dst="203.0.113.5") / UDP(
            sport=rng.randint(1024, 65535), dport=rng.randint(1024, 65535)
        )

    def _build_plain_v6(self, rng):
        return IPv6(src="2001:db8:dead::1", dst="2001:db8:beef::5") / UDP(
            sport=rng.randint(1024, 65535), dport=rng.randint(1024, 65535)
        )

    def _build_ipinip(self, rng):
        inner = IP(src=_rand_v4(rng), dst=_rand_v4(rng)) / UDP(
            sport=rng.randint(1024, 65535), dport=rng.randint(1024, 65535)
        )
        outer = IP(src="192.0.2.1", dst="203.0.113.5", proto=PROTO_IPINIP4, ttl=64)
        return outer / inner

    def _build_nvgre(self, rng):
        inner_eth = Ether(dst="00:11:22:33:44:55", src="00:aa:bb:cc:dd:ee")
        inner = (
            inner_eth
            / IP(src=_rand_v4(rng), dst=_rand_v4(rng))
            / UDP(sport=rng.randint(1024, 65535), dport=rng.randint(1024, 65535))
        )
        gre = Raw(b"\x00\x00\x65\x58" + b"\x00\x00\x00\x00")
        outer = IP(src="192.0.2.1", dst="203.0.113.5", proto=PROTO_GRE, ttl=64)
        return outer / gre / inner

    @staticmethod
    def _parse_runtime(runtime, node_names):
        """Extract clocks/vector and vectors-processed for a list of nodes
        from VPP `show runtime` output.  Returns {node: {"clocks": X,
        "vectors": Y, "calls": Z}} (zeros if node not found)."""
        out = {n: {"clocks": 0.0, "vectors": 0, "calls": 0} for n in node_names}
        for line in runtime.splitlines():
            cols = line.split()
            if len(cols) < 7:
                continue
            name = cols[0]
            if name not in node_names:
                continue
            try:
                calls = int(cols[2])
                vectors = int(cols[3])
                clocks_per_pkt = float(cols[5])
            except (ValueError, IndexError):
                continue
            out[name] = {"calls": calls, "vectors": vectors, "clocks": clocks_per_pkt}
        return out

    def _measure(self, name, builder, is_ipv6=False, peek_inner=True):
        self._set_peek_inner(peek_inner)
        rng = random.Random(0xC0FFEE if peek_inner else 0xDEADBEEF)
        pkts = []
        for _ in range(N_PKTS):
            inner = builder(rng)
            pkts.append(
                Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
                / inner
                / Raw(PAYLOAD_TAG)
            )
        dst_net, prefix = ("2001:db8:beef::", 64) if is_ipv6 else ("203.0.113.0", 24)
        rip = self._add_ecmp_route(dst_net, prefix, is_ipv6=is_ipv6)
        try:
            self.vapi.cli("clear runtime")
            self.pg_enable_capture(self.pg_interfaces)
            self.pg0.add_stream(pkts)
            t0 = time.perf_counter()
            self.pg_start()
            # _get_capture() blocks on wait_for_pg_stop() internally, so a
            # single call per pg interface is enough to drain everything VPP
            # produced for this stream.
            total = 0
            primary = self.pg_interfaces[1]
            primary_cap = primary._get_capture() or []
            total += len(primary_cap)
            for pg in self.pg_interfaces[2:]:
                cap = pg._get_capture() or []
                total += len(cap)
            elapsed = time.perf_counter() - t0
            runtime = self.vapi.cli("show runtime")
        finally:
            rip.remove_vpp_config()
        pps = total / elapsed if elapsed > 0 else 0.0
        lookup_node = "ip6-lookup" if is_ipv6 else "ip4-lookup"
        lb_node = "ip6-load-balance" if is_ipv6 else "ip4-load-balance"
        node_stats = self._parse_runtime(runtime, [lookup_node, lb_node])
        result = {
            "scenario": name,
            "peek_inner": peek_inner,
            "packets_sent": N_PKTS,
            "packets_received": total,
            "elapsed_s": round(elapsed, 4),
            "pps": round(pps, 1),
            "nodes": node_stats,
        }
        self.logger.info("PERF %s" % json.dumps(result))
        self.logger.info("PERF runtime\n%s" % runtime)
        self.__class__.perf_results.append(result)
        return result

    # --- scenarios --------------------------------------------------------

    def test_perf_plain_v4_off(self):
        self._measure("plain_v4", self._build_plain_v4, peek_inner=False)

    def test_perf_plain_v4_on(self):
        self._measure("plain_v4", self._build_plain_v4, peek_inner=True)

    def test_perf_plain_v6_off(self):
        self._measure("plain_v6", self._build_plain_v6, is_ipv6=True, peek_inner=False)

    def test_perf_plain_v6_on(self):
        self._measure("plain_v6", self._build_plain_v6, is_ipv6=True, peek_inner=True)

    def test_perf_ipinip_off(self):
        self._measure("ipinip_v4_v4", self._build_ipinip, peek_inner=False)

    def test_perf_ipinip_on(self):
        self._measure("ipinip_v4_v4", self._build_ipinip, peek_inner=True)

    def test_perf_nvgre_off(self):
        self._measure("nvgre_v4_v4", self._build_nvgre, peek_inner=False)

    def test_perf_nvgre_on(self):
        self._measure("nvgre_v4_v4", self._build_nvgre, peek_inner=True)


# =========================================================================
#                           LAG TX-side perf harness
# =========================================================================


@unittest.skipIf(
    "lacp" in config.excluded_plugins, "Exclude tests requiring LACP plugin"
)
class TestInnerAwareLAGPerf(VppTestCase):
    """Performance harness for the LAG TX hash function.

    Measures wall-clock pps and per-node clocks/vector at the bond TX
    graph node for plain v4, IPinIP v4/v4 (random inner) and NVGRE
    v4/v4 (random inner) traffic.  The default class uses the new
    ``BOND_API_LB_ALGO_L34_INNER`` (i.e. ``hash-eth-l34-inner``);
    the legacy subclass below repeats with ``BOND_API_LB_ALGO_L34``
    so an operator can directly compare the per-packet cost of the
    inner-peek hash function vs the upstream-compatible one.
    """

    # Bond load-balance algo under test.  Override in subclass for A/B.
    lb_algo_name = "BOND_API_LB_ALGO_L34_INNER"
    # Distinct MAC per class to avoid collisions if the framework reuses
    # VPP state across classes.
    bond_mac = "02:fe:38:30:59:4c"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.create_pg_interfaces(range(4))
        for i in cls.pg_interfaces:
            i.admin_up()

        # bond0 = (pg2, pg3); pg0 = ingress.  We never send to pg1 here
        # but configure it consistently with the functional LAG fixture.
        cls.bond0 = VppBondInterface(
            cls,
            mode=VppEnum.vl_api_bond_mode_t.BOND_API_MODE_XOR,
            lb=getattr(VppEnum.vl_api_bond_lb_algo_t, cls.lb_algo_name),
            numa_only=0,
            use_custom_mac=1,
            mac_address=MACAddress(cls.bond_mac).packed,
        )
        cls.bond0.add_vpp_config()
        cls.bond0.admin_up()
        cls.bond0.add_member_vpp_bond_interface(sw_if_index=cls.pg2.sw_if_index)
        cls.bond0.add_member_vpp_bond_interface(sw_if_index=cls.pg3.sw_if_index)

        cls.vapi.sw_interface_add_del_address(
            sw_if_index=cls.bond0.sw_if_index, prefix="10.99.99.1/24"
        )
        cls.pg0.config_ip4()
        cls.pg0.resolve_arp()
        cls.vapi.cli("set ip neighbor static BondEthernet0 10.99.99.99 abcd.abcd.0001")
        cls.perf_results = []

    @classmethod
    def tearDownClass(cls):
        try:
            suffix = "_legacy" if cls.lb_algo_name == "BOND_API_LB_ALGO_L34" else ""
            results_path = os.path.join(
                config.tmp_dir, f"test_inner_aware_lag_perf{suffix}.json"
            )
            with open(results_path, "w") as f:
                json.dump(cls.perf_results, f, indent=2)
            cls.logger.info("Wrote LAG perf JSON: %s" % results_path)
        except Exception as e:
            cls.logger.warning("could not write LAG perf JSON: %s" % e)
        if not cls.vpp_dead:
            cls.pg0.unconfig_ip4()
            cls.bond0.remove_vpp_config()
            for i in cls.pg_interfaces:
                i.admin_down()
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        self.reset_packet_infos()
        # VppTestCase tearDown auto-removes registered VppObjects (including
        # routes).  Recreate the route to the bond next-hop here so each
        # test starts with a clean, freshly-installed FIB entry.
        self.route4 = VppIpRoute(
            self,
            "203.0.113.0",
            24,
            [VppRoutePath("10.99.99.99", self.bond0.sw_if_index)],
        )
        self.route4.add_vpp_config()

    # --- packet builders -- destination is always in 203.0.113/24 so the
    #     packet routes via bond0; tunnel scenarios use a constant outer
    #     5-tuple (one tunnel between two endpoints) and a random inner.

    def _build_plain_v4(self, rng):
        return IP(
            src="10.0.%d.%d" % (rng.randint(0, 255), rng.randint(1, 254)),
            dst="203.0.113.%d" % rng.randint(1, 254),
        ) / UDP(sport=rng.randint(1024, 65535), dport=rng.randint(1024, 65535))

    def _build_ipinip(self, rng):
        outer = IP(src="192.0.2.1", dst="203.0.113.5", proto=PROTO_IPINIP4, ttl=64)
        inner = IP(
            src="10.10.%d.%d" % (rng.randint(0, 255), rng.randint(1, 254)),
            dst="10.20.%d.%d" % (rng.randint(0, 255), rng.randint(1, 254)),
        ) / UDP(sport=rng.randint(1024, 65535), dport=rng.randint(1024, 65535))
        return outer / inner

    def _build_nvgre(self, rng):
        outer = IP(src="192.0.2.1", dst="203.0.113.5", proto=PROTO_GRE, ttl=64)
        # GRE+TEB header (NVGRE): 4-byte base + 4-byte VSID/flow-id.
        gre = Raw(b"\x20\x00\x65\x58" + b"\x00\x12\x34\x00")
        inner_eth = Ether(dst="00:11:22:33:44:55", src="00:aa:bb:cc:dd:ee")
        inner = (
            inner_eth
            / IP(
                src="10.10.%d.%d" % (rng.randint(0, 255), rng.randint(1, 254)),
                dst="10.20.%d.%d" % (rng.randint(0, 255), rng.randint(1, 254)),
            )
            / UDP(sport=rng.randint(1024, 65535), dport=rng.randint(1024, 65535))
        )
        return outer / gre / inner

    def _measure(self, name, builder):
        rng = random.Random(0xC0FFEE)
        pkts = []
        for _ in range(N_PKTS):
            pkts.append(
                Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
                / builder(rng)
                / Raw(PAYLOAD_TAG)
            )
        self.vapi.cli("clear runtime")
        self.pg_enable_capture(self.pg_interfaces)
        self.pg0.add_stream(pkts)
        t0 = time.perf_counter()
        self.pg_start()
        # The bond fans out to pg2 and pg3 only; collect both.
        total = 0
        for pg in (self.pg2, self.pg3):
            cap = pg._get_capture() or []
            total += len(cap)
        elapsed = time.perf_counter() - t0
        runtime = self.vapi.cli("show runtime")

        pps = total / elapsed if elapsed > 0 else 0.0
        # Hash function runs inside the bond TX path; include
        # BondEthernet0-tx (the hash + member-pick site), BondEthernet0-
        # output (interface-output node) and the upstream FIB nodes for
        # context.
        node_stats = TestInnerAwarePerf._parse_runtime(
            runtime,
            [
                "ip4-lookup",
                "ip4-rewrite",
                "BondEthernet0-output",
                "BondEthernet0-tx",
            ],
        )
        result = {
            "scenario": name,
            "lb_algo": self.lb_algo_name,
            "packets_sent": N_PKTS,
            "packets_received": total,
            "elapsed_s": round(elapsed, 4),
            "pps": round(pps, 1),
            "nodes": node_stats,
        }
        self.logger.info("LAG PERF %s" % json.dumps(result))
        self.logger.info("LAG PERF runtime\n%s" % runtime)
        self.__class__.perf_results.append(result)
        return result

    # --- scenarios --------------------------------------------------------

    def test_lag_perf_plain_v4(self):
        """LAG perf: plain UDP-over-IPv4 (no inner peek path exercised)"""
        self._measure("plain_v4", self._build_plain_v4)

    def test_lag_perf_ipinip_v4(self):
        """LAG perf: IPinIPv4 random inner (exercises inner-v4 peek)"""
        self._measure("ipinip_v4_v4", self._build_ipinip)

    def test_lag_perf_nvgre_v4(self):
        """LAG perf: NVGRE v4/v4 random inner (exercises GRE+inner-v4 peek)"""
        self._measure("nvgre_v4_v4", self._build_nvgre)


class TestInnerAwareLAGLegacyPerf(TestInnerAwareLAGPerf):
    """Same perf scenarios as TestInnerAwareLAGPerf but pinned to the
    upstream-compatible ``BOND_API_LB_ALGO_L34`` (``hash-eth-l34``).

    Tunnel scenarios on this class only exercise the outer 5-tuple and
    therefore collapse to a single member (pps figures are still
    measured for cycle-cost comparison; the distribution itself is
    covered functionally by ``TestLagL34LegacyOuterOnly`` in
    ``test_inner_aware_hash.py``).
    """

    lb_algo_name = "BOND_API_LB_ALGO_L34"
    bond_mac = "02:fe:38:30:59:4d"


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
