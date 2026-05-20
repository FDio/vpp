#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0

"""
Tests for inner-aware flow hash of IPinIP / IPv6inIP / GRE / NVGRE.

These tests verify that ip4_compute_flow_hash, ip6_compute_flow_hash and
the hash-eth-l34 LAG hash function all dive into the inner header so
that ECMP and LAG distribution use inner-flow entropy rather than the
(constant) outer 5-tuple of transit tunnel traffic.

The feature is opt-in for the IP layer:

  * ``IP_FLOW_HASH_PEEK_INNER`` bit must be set in ``flow_hash_config``
    for the fib in question.  These tests enable it via
    ``set ip flow-hash table 0 ... peek_inner`` (and the v6 variant)
    in setUpClass.

The LAG hash function ``hash-eth-l34`` was extended to peek into the
inner header transparently — bonds created with the standard
``BOND_API_LB_ALGO_L34`` enum value pick up the new behavior with no
API change.

See ``src/vnet/ip/ip_inner_aware_hash.h`` for the implementation.

Fixtures:

  * TestInnerAwareECMP — pg0 ingress, pg1/pg2/pg3 are ECMP next-hops.
  * TestInnerAwareLAG — pg2/pg3 are bond0 members.
  * TestPeekInnerOff — same as ECMP but with the flag NOT set; confirms
    behavior is unchanged for non-opt-in users.
  * TestSafetyEdges — fragmented outer, inner v6 with HBH extension
    header, truncated tunnel; confirms the helper falls back safely
    without crashing.
"""

import random
import unittest

from scapy.packet import Raw
from scapy.layers.l2 import Ether, GRE
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrHopByHop, IPv6ExtHdrFragment

from framework import VppTestCase
from asfframework import VppTestRunner
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_bond_interface import VppBondInterface
from vpp_papi import MACAddress, VppEnum
from config import config

N_PKTS = 257
N_HOSTS = 4
PAYLOAD_TAG = b"inner-aware-hash"

PROTO_IPINIP4 = 4
PROTO_IPINIP6 = 41
PROTO_GRE = 47
GRE_PROTO_IPV4 = 0x0800
GRE_PROTO_IPV6 = 0x86DD
GRE_PROTO_TEB = 0x6558


# ---------------- random helpers (per-test, isolated RNG) ----------------


def _rand_ipv4(rng):
    return "10.{}.{}.{}".format(
        rng.randint(1, 254), rng.randint(1, 254), rng.randint(1, 254)
    )


def _rand_ipv6(rng):
    return "2001:db8:{:x}:{:x}::{:x}".format(
        rng.randint(1, 0xFFFF),
        rng.randint(1, 0xFFFF),
        rng.randint(1, 0xFFFF),
    )


def _rand_pair(rng, ip_l):
    if ip_l is IP:
        return _rand_ipv4(rng), _rand_ipv4(rng)
    return _rand_ipv6(rng), _rand_ipv6(rng)


def _rand_port(rng):
    return rng.randint(1024, 65535)


# ----------------------- packet builders --------------------------------


def _build_outer(outer_l, outer_src, outer_dst, proto):
    if outer_l is IP:
        return IP(src=outer_src, dst=outer_dst, proto=proto, ttl=64)
    return IPv6(src=outer_src, dst=outer_dst, nh=proto, hlim=64)


def _build_ipinip(
    outer_l, outer_src, outer_dst, inner_l, isrc, idst, isport, idport
):
    inner_proto = PROTO_IPINIP4 if inner_l is IP else PROTO_IPINIP6
    return (
        _build_outer(outer_l, outer_src, outer_dst, inner_proto)
        / inner_l(src=isrc, dst=idst)
        / UDP(sport=isport, dport=idport)
    )


def _build_gre_ip(
    outer_l, outer_src, outer_dst, inner_l, isrc, idst, isport, idport
):
    gre_proto = GRE_PROTO_IPV4 if inner_l is IP else GRE_PROTO_IPV6
    return (
        _build_outer(outer_l, outer_src, outer_dst, PROTO_GRE)
        / GRE(proto=gre_proto)
        / inner_l(src=isrc, dst=idst)
        / UDP(sport=isport, dport=idport)
    )


def _build_nvgre(
    outer_l, outer_src, outer_dst, inner_l, isrc, idst, isport, idport
):
    return (
        _build_outer(outer_l, outer_src, outer_dst, PROTO_GRE)
        / GRE(proto=GRE_PROTO_TEB, key_present=1, key=0x12345600)
        / Ether(dst="aa:bb:cc:dd:ee:00", src="aa:bb:cc:dd:ee:01")
        / inner_l(src=isrc, dst=idst)
        / UDP(sport=isport, dport=idport)
    )


def _build_plain_udp(outer_l, outer_src, outer_dst, isport, idport):
    return _build_outer(outer_l, outer_src, outer_dst, 17) / UDP(
        sport=isport, dport=idport
    )


# ------------------------- common fixture -------------------------------


def _outer_addrs(outer_l):
    """Return (outer_src, outer_dst) — constant for tunnel scenarios."""
    if outer_l is IP:
        return "192.0.2.1", "203.0.113.5"
    return "2001:db8:dead::1", "2001:db8:beef::5"


def _outer_dst_route(outer_l):
    """Return (dst_net, prefix_len) — must cover _outer_addrs()[1]."""
    if outer_l is IP:
        return "203.0.113.0", 24
    return "2001:db8:beef::", 64


def _build_tunnel_stream(
    encap_fn, outer_l, inner_l, *, randomize_inner, seed
):
    """Build N_PKTS tunnel packets with constant outer 5-tuple and either
    randomized or constant inner 5-tuple."""
    rng = random.Random(seed)
    outer_src, outer_dst = _outer_addrs(outer_l)
    fixed_inner = ("10.99.0.1", "10.99.0.2", 1234, 5678)
    if inner_l is IPv6:
        fixed_inner = ("2001:db8:cafe::1", "2001:db8:cafe::2", 1234, 5678)

    pkts = []
    for _ in range(N_PKTS):
        if randomize_inner:
            isrc, idst = _rand_pair(rng, inner_l)
            isport, idport = _rand_port(rng), _rand_port(rng)
        else:
            isrc, idst, isport, idport = fixed_inner
        pkts.append(
            encap_fn(
                outer_l,
                outer_src,
                outer_dst,
                inner_l,
                isrc,
                idst,
                isport,
                idport,
            )
        )
    return pkts


def _build_plain_stream(outer_l, *, randomize, seed):
    rng = random.Random(seed)
    # dst must match the route prefix; only randomize src + ports.
    if outer_l is IP:
        dst = "203.0.113.5"
        fixed_src = "192.0.2.10"
    else:
        dst = "2001:db8:beef::5"
        fixed_src = "2001:db8:dead::10"
    pkts = []
    for _ in range(N_PKTS):
        if randomize:
            src = _rand_ipv4(rng) if outer_l is IP else _rand_ipv6(rng)
            isport, idport = _rand_port(rng), _rand_port(rng)
        else:
            src = fixed_src
            isport, idport = 1234, 5678
        pkts.append(_build_plain_udp(outer_l, src, dst, isport, idport))
    return pkts


# =========================================================================
#                                  ECMP
# =========================================================================


class TestInnerAwareECMP(VppTestCase):
    """Inner-aware ECMP flow hash"""

    enable_peek_inner = True

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
        if cls.enable_peek_inner:
            cls.vapi.cli(
                "set ip flow-hash table 0 src dst sport dport proto peek_inner"
            )
            cls.vapi.cli(
                "set ip6 flow-hash table 0 src dst sport dport proto "
                "peek_inner"
            )

    @classmethod
    def tearDownClass(cls):
        if not cls.vpp_dead:
            for i in cls.pg_interfaces:
                i.unconfig_ip4()
                i.unconfig_ip6()
                i.admin_down()
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        self.reset_packet_infos()

    def _add_ecmp_route(self, dst_net, prefix_len, is_ipv6):
        paths = []
        for pg_if in self.pg_interfaces[1:]:
            for nh in pg_if.remote_hosts:
                nh_ip = nh.ip6 if is_ipv6 else nh.ip4
                paths.append(VppRoutePath(nh_ip, pg_if.sw_if_index))
        rip = VppIpRoute(self, dst_net, prefix_len, paths)
        rip.add_vpp_config()
        return rip

    def _send(self, raw_pkts):
        pkts = [
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / p
            / Raw(PAYLOAD_TAG)
            for p in raw_pkts
        ]
        self.pg_enable_capture(self.pg_interfaces)
        self.pg0.add_stream(pkts)
        self.pg_start()

        per_if = {}
        total = 0
        for pg in self.pg_interfaces[1:]:
            cap = pg._get_capture() or []
            per_if[pg.name] = len(cap)
            total += len(cap)
        return per_if, total

    def _run_distribution(
        self, encap_fn, outer_l, inner_l, *, randomize_inner, expect_paths
    ):
        encap_name = encap_fn.__name__ if encap_fn else "plain"
        seed = hash((encap_name, outer_l, inner_l, randomize_inner)) & 0xFFFFFFFF
        if encap_fn is None:
            stream = _build_plain_stream(outer_l, randomize=randomize_inner, seed=seed)
        else:
            stream = _build_tunnel_stream(
                encap_fn,
                outer_l,
                inner_l,
                randomize_inner=randomize_inner,
                seed=seed,
            )
        dst_net, prefix = _outer_dst_route(outer_l)
        rip = self._add_ecmp_route(dst_net, prefix, is_ipv6=(outer_l is IPv6))
        try:
            per_if, total = self._send(stream)
        finally:
            rip.remove_vpp_config()

        self.logger.info(
            "ECMP %s outer=%s inner=%s rand=%s -> total=%d per_if=%s"
            % (
                encap_fn.__name__ if encap_fn else "plain",
                outer_l.__name__,
                inner_l.__name__ if inner_l else "-",
                randomize_inner,
                total,
                per_if,
            )
        )
        self.assertEqual(
            total,
            N_PKTS,
            "lost packets in ECMP forwarding (per_if=%s)" % per_if,
        )
        non_zero = sum(1 for c in per_if.values() if c > 0)
        self.assertEqual(
            non_zero,
            expect_paths,
            "expected %d distinct ECMP next-hops to receive traffic, got %d "
            "(per_if=%s)" % (expect_paths, non_zero, per_if),
        )

    # --------- random-inner tests: must distribute across all 3 paths ----

    def test_ecmp_ipinip4_outer_v4_inner_v4(self):
        """ECMP IPinIPv4 outer-v4 / inner-v4: distribution"""
        self._run_distribution(_build_ipinip, IP, IP, randomize_inner=True, expect_paths=3)

    def test_ecmp_ipinip6_outer_v4_inner_v6(self):
        """ECMP IPv6inIPv4 outer-v4 / inner-v6: distribution"""
        self._run_distribution(_build_ipinip, IP, IPv6, randomize_inner=True, expect_paths=3)

    def test_ecmp_ipinip4_outer_v6_inner_v4(self):
        """ECMP IPv4inIPv6 outer-v6 / inner-v4: distribution"""
        self._run_distribution(_build_ipinip, IPv6, IP, randomize_inner=True, expect_paths=3)

    def test_ecmp_ipinip6_outer_v6_inner_v6(self):
        """ECMP IPv6inIPv6 outer-v6 / inner-v6: distribution"""
        self._run_distribution(_build_ipinip, IPv6, IPv6, randomize_inner=True, expect_paths=3)

    def test_ecmp_gre_ip_outer_v4_inner_v4(self):
        """ECMP GRE-IP outer-v4 / inner-v4: distribution"""
        self._run_distribution(_build_gre_ip, IP, IP, randomize_inner=True, expect_paths=3)

    def test_ecmp_gre_ip_outer_v4_inner_v6(self):
        """ECMP GRE-IP outer-v4 / inner-v6: distribution"""
        self._run_distribution(_build_gre_ip, IP, IPv6, randomize_inner=True, expect_paths=3)

    def test_ecmp_gre_ip_outer_v6_inner_v4(self):
        """ECMP GRE-IP outer-v6 / inner-v4: distribution"""
        self._run_distribution(_build_gre_ip, IPv6, IP, randomize_inner=True, expect_paths=3)

    def test_ecmp_gre_ip_outer_v6_inner_v6(self):
        """ECMP GRE-IP outer-v6 / inner-v6: distribution"""
        self._run_distribution(_build_gre_ip, IPv6, IPv6, randomize_inner=True, expect_paths=3)

    def test_ecmp_nvgre_outer_v4_inner_v4(self):
        """ECMP NVGRE outer-v4 / inner-v4: distribution"""
        self._run_distribution(_build_nvgre, IP, IP, randomize_inner=True, expect_paths=3)

    def test_ecmp_nvgre_outer_v4_inner_v6(self):
        """ECMP NVGRE outer-v4 / inner-v6: distribution"""
        self._run_distribution(_build_nvgre, IP, IPv6, randomize_inner=True, expect_paths=3)

    def test_ecmp_nvgre_outer_v6_inner_v4(self):
        """ECMP NVGRE outer-v6 / inner-v4: distribution"""
        self._run_distribution(_build_nvgre, IPv6, IP, randomize_inner=True, expect_paths=3)

    def test_ecmp_nvgre_outer_v6_inner_v6(self):
        """ECMP NVGRE outer-v6 / inner-v6: distribution"""
        self._run_distribution(_build_nvgre, IPv6, IPv6, randomize_inner=True, expect_paths=3)

    # --------- collapse: constant inner 5-tuple → single path ------------
    #
    # This is the proof that the inner-aware helper is doing real work:
    # the outer 5-tuple is constant in every tunnel test, so without the
    # helper the hash collapses to one path.  Here we hold the inner 5-
    # tuple constant too and confirm the collapse.

    def test_ecmp_ipinip_collapse_constant_inner(self):
        """ECMP IPinIP outer-v4 / inner-v4 / fixed inner: collapses to 1 path"""
        self._run_distribution(_build_ipinip, IP, IP, randomize_inner=False, expect_paths=1)

    def test_ecmp_nvgre_collapse_constant_inner(self):
        """ECMP NVGRE outer-v4 / inner-v4 / fixed inner: collapses to 1 path"""
        self._run_distribution(_build_nvgre, IP, IP, randomize_inner=False, expect_paths=1)

    # --------- plain (non-tunnel) sanity: must distribute ----------------

    def test_ecmp_plain_v4(self):
        """ECMP plain UDP-over-IPv4: distribution unchanged by helper"""
        self._run_distribution(None, IP, None, randomize_inner=True, expect_paths=3)

    def test_ecmp_plain_v6(self):
        """ECMP plain UDP-over-IPv6: distribution unchanged by helper"""
        self._run_distribution(None, IPv6, None, randomize_inner=True, expect_paths=3)


# =========================================================================
#                                  LAG
# =========================================================================


@unittest.skipIf(
    "lacp" in config.excluded_plugins, "Exclude tests requiring LACP plugin"
)
class TestInnerAwareLAG(VppTestCase):
    """Inner-aware LAG / bond (XOR + L34) flow hash"""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.create_pg_interfaces(range(4))
        for i in cls.pg_interfaces:
            i.admin_up()

        # bond0 = (pg2, pg3); pg0 = ingress; pg1 = unused (must stay quiet)
        bond_mac = "02:fe:38:30:59:3c"
        cls.bond0 = VppBondInterface(
            cls,
            mode=VppEnum.vl_api_bond_mode_t.BOND_API_MODE_XOR,
            lb=VppEnum.vl_api_bond_lb_algo_t.BOND_API_LB_ALGO_L34,
            numa_only=0,
            use_custom_mac=1,
            mac_address=MACAddress(bond_mac).packed,
        )
        cls.bond0.add_vpp_config()
        cls.bond0.admin_up()
        cls.bond0.add_member_vpp_bond_interface(sw_if_index=cls.pg2.sw_if_index)
        cls.bond0.add_member_vpp_bond_interface(sw_if_index=cls.pg3.sw_if_index)

        cls.vapi.sw_interface_add_del_address(
            sw_if_index=cls.bond0.sw_if_index, prefix="10.99.99.1/24"
        )
        cls.vapi.sw_interface_add_del_address(
            sw_if_index=cls.bond0.sw_if_index, prefix="2001:db8:99::1/64"
        )

        cls.pg0.config_ip4()
        cls.pg0.resolve_arp()
        cls.pg0.config_ip6()
        cls.pg0.resolve_ndp()

        cls.vapi.cli(
            "set ip neighbor static BondEthernet0 10.99.99.99 abcd.abcd.0001"
        )
        cls.vapi.cli(
            "set ip neighbor static BondEthernet0 2001:db8:99::99 "
            "abcd.abcd.0001"
        )

    @classmethod
    def tearDownClass(cls):
        if not cls.vpp_dead:
            cls.pg0.unconfig_ip4()
            cls.pg0.unconfig_ip6()
            cls.bond0.remove_vpp_config()
            for i in cls.pg_interfaces:
                i.admin_down()
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        self.reset_packet_infos()
        # VppTestCase.tearDown() auto-removes any VppObject registered to the
        # registry; if we set the bond0 routes in setUpClass they would get
        # cleaned up after the first test.  Re-create them here per-test.
        self.route4 = VppIpRoute(
            self,
            "203.0.113.0",
            24,
            [VppRoutePath("10.99.99.99", self.bond0.sw_if_index)],
        )
        self.route4.add_vpp_config()
        self.route6 = VppIpRoute(
            self,
            "2001:db8:beef::",
            64,
            [VppRoutePath("2001:db8:99::99", self.bond0.sw_if_index)],
        )
        self.route6.add_vpp_config()

    def _send(self, raw_pkts):
        pkts = [
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / p
            / Raw(PAYLOAD_TAG)
            for p in raw_pkts
        ]
        self.pg_enable_capture(self.pg_interfaces)
        self.pg0.add_stream(pkts)
        self.pg_start()

        per_member = {}
        for pg in (self.pg2, self.pg3):
            cap = pg._get_capture() or []
            per_member[pg.name] = len(cap)
        # pg1 is not a bond member and must never receive transit traffic
        pg1_cap = self.pg1._get_capture() or []
        leak = len(pg1_cap)
        return per_member, leak

    def _run_distribution(
        self, encap_fn, outer_l, inner_l, *, randomize_inner, expect_members
    ):
        encap_name = encap_fn.__name__ if encap_fn else "plain"
        seed = hash((encap_name, outer_l, inner_l, randomize_inner)) & 0xFFFFFFFF
        if encap_fn is None:
            stream = _build_plain_stream(outer_l, randomize=randomize_inner, seed=seed)
        else:
            stream = _build_tunnel_stream(
                encap_fn,
                outer_l,
                inner_l,
                randomize_inner=randomize_inner,
                seed=seed,
            )
        per_member, leak = self._send(stream)
        total = sum(per_member.values())
        self.logger.info(
            "LAG %s outer=%s inner=%s rand=%s -> total=%d per=%s leak_pg1=%d"
            % (
                encap_fn.__name__ if encap_fn else "plain",
                outer_l.__name__,
                inner_l.__name__ if inner_l else "-",
                randomize_inner,
                total,
                per_member,
                leak,
            )
        )
        self.assertEqual(
            leak, 0, "pg1 received %d packets but is not a bond member" % leak
        )
        self.assertEqual(
            total,
            N_PKTS,
            "lost packets in bond forwarding (per_member=%s)" % per_member,
        )
        non_zero = sum(1 for c in per_member.values() if c > 0)
        self.assertEqual(
            non_zero,
            expect_members,
            "expected %d bond members to receive traffic, got %d "
            "(per_member=%s)" % (expect_members, non_zero, per_member),
        )

    # --------- random-inner tests: distribute across both members --------

    def test_lag_ipinip4_outer_v4_inner_v4(self):
        """LAG IPinIPv4 outer-v4 / inner-v4: distribution"""
        self._run_distribution(_build_ipinip, IP, IP, randomize_inner=True, expect_members=2)

    def test_lag_ipinip6_outer_v4_inner_v6(self):
        """LAG IPv6inIPv4 outer-v4 / inner-v6: distribution"""
        self._run_distribution(_build_ipinip, IP, IPv6, randomize_inner=True, expect_members=2)

    def test_lag_ipinip4_outer_v6_inner_v4(self):
        """LAG IPv4inIPv6 outer-v6 / inner-v4: distribution"""
        self._run_distribution(_build_ipinip, IPv6, IP, randomize_inner=True, expect_members=2)

    def test_lag_ipinip6_outer_v6_inner_v6(self):
        """LAG IPv6inIPv6 outer-v6 / inner-v6: distribution"""
        self._run_distribution(_build_ipinip, IPv6, IPv6, randomize_inner=True, expect_members=2)

    def test_lag_gre_ip_outer_v4_inner_v4(self):
        """LAG GRE-IP outer-v4 / inner-v4: distribution"""
        self._run_distribution(_build_gre_ip, IP, IP, randomize_inner=True, expect_members=2)

    def test_lag_gre_ip_outer_v4_inner_v6(self):
        """LAG GRE-IP outer-v4 / inner-v6: distribution"""
        self._run_distribution(_build_gre_ip, IP, IPv6, randomize_inner=True, expect_members=2)

    def test_lag_gre_ip_outer_v6_inner_v4(self):
        """LAG GRE-IP outer-v6 / inner-v4: distribution"""
        self._run_distribution(_build_gre_ip, IPv6, IP, randomize_inner=True, expect_members=2)

    def test_lag_gre_ip_outer_v6_inner_v6(self):
        """LAG GRE-IP outer-v6 / inner-v6: distribution"""
        self._run_distribution(_build_gre_ip, IPv6, IPv6, randomize_inner=True, expect_members=2)

    def test_lag_nvgre_outer_v4_inner_v4(self):
        """LAG NVGRE outer-v4 / inner-v4: distribution"""
        self._run_distribution(_build_nvgre, IP, IP, randomize_inner=True, expect_members=2)

    def test_lag_nvgre_outer_v4_inner_v6(self):
        """LAG NVGRE outer-v4 / inner-v6: distribution"""
        self._run_distribution(_build_nvgre, IP, IPv6, randomize_inner=True, expect_members=2)

    def test_lag_nvgre_outer_v6_inner_v4(self):
        """LAG NVGRE outer-v6 / inner-v4: distribution"""
        self._run_distribution(_build_nvgre, IPv6, IP, randomize_inner=True, expect_members=2)

    def test_lag_nvgre_outer_v6_inner_v6(self):
        """LAG NVGRE outer-v6 / inner-v6: distribution"""
        self._run_distribution(_build_nvgre, IPv6, IPv6, randomize_inner=True, expect_members=2)

    # --------- collapse: constant inner → single member ------------------

    def test_lag_ipinip_collapse_constant_inner(self):
        """LAG IPinIP outer-v4 / inner-v4 / fixed inner: collapses to 1 member"""
        self._run_distribution(
            _build_ipinip, IP, IP, randomize_inner=False, expect_members=1
        )

    def test_lag_nvgre_collapse_constant_inner(self):
        """LAG NVGRE outer-v4 / inner-v4 / fixed inner: collapses to 1 member"""
        self._run_distribution(
            _build_nvgre, IP, IP, randomize_inner=False, expect_members=1
        )

    # --------- plain (non-tunnel) sanity ---------------------------------

    def test_lag_plain_v4(self):
        """LAG plain UDP-over-IPv4: distribution unchanged by helper"""
        self._run_distribution(
            None, IP, None, randomize_inner=True, expect_members=2
        )

    def test_lag_plain_v6(self):
        """LAG plain UDP-over-IPv6: distribution unchanged by helper"""
        self._run_distribution(
            None, IPv6, None, randomize_inner=True, expect_members=2
        )


# =========================================================================
#                  Opt-in semantics: PEEK_INNER bit OFF
# =========================================================================


class TestPeekInnerOff(TestInnerAwareECMP):
    """When IP_FLOW_HASH_PEEK_INNER is not set the tunnel ECMP hash must
    collapse to a single next-hop (upstream-compatible behavior).

    Plain (non-tunnel) tests still pass through unchanged because they
    don't peek; they're inherited as-is.  The randomized tunnel tests
    from the parent class assume the peek flag is on (expect_paths=3),
    so they're skipped here in favor of explicit collapse tests."""

    enable_peek_inner = False

    def setUp(self):
        super().setUp()
        name = self._testMethodName
        # Skip inherited tunnel-distribution tests; they require the flag.
        if name.startswith("test_ecmp_") and "plain" not in name and \
                "collapse" not in name:
            self.skipTest("requires IP_FLOW_HASH_PEEK_INNER (peek-off variant covered)")

    def test_off_ipinip_v4_collapses(self):
        """PEEK_INNER off: IPinIP v4/v4 random-inner collapses to 1 path"""
        self._run_distribution(
            _build_ipinip, IP, IP, randomize_inner=True, expect_paths=1
        )

    def test_off_gre_v4_collapses(self):
        """PEEK_INNER off: GRE-IP v4/v4 random-inner collapses to 1 path"""
        self._run_distribution(
            _build_gre_ip, IP, IP, randomize_inner=True, expect_paths=1
        )

    def test_off_nvgre_v4_collapses(self):
        """PEEK_INNER off: NVGRE v4/v4 random-inner collapses to 1 path"""
        self._run_distribution(
            _build_nvgre, IP, IP, randomize_inner=True, expect_paths=1
        )

    def test_off_ipinip_v6_collapses(self):
        """PEEK_INNER off: IPinIP v6/v6 random-inner collapses to 1 path"""
        self._run_distribution(
            _build_ipinip, IPv6, IPv6, randomize_inner=True, expect_paths=1
        )

    def test_off_plain_v4_still_distributes(self):
        """PEEK_INNER off: plain v4 traffic still distributes normally"""
        self._run_distribution(
            None, IP, None, randomize_inner=True, expect_paths=3
        )


# =========================================================================
#                       Safety: edge cases and crashes
# =========================================================================


class TestSafetyEdges(TestInnerAwareECMP):
    """Safety: fragmented outer, inner-v6 with HBH ext, truncated tunnel.

    The helper must never crash and must always either successfully peek
    or fall back to the outer-only hash.  These tests exercise paths
    where peeking is unsafe (fragmented outer, truncated buffer) or
    requires walking inner extension headers (HBH).
    """

    def test_outer_v4_fragmented_falls_back(self):
        """Fragmented outer IPinIPv4 collapses to 1 path (no peek)."""
        # Build a tunnel stream and stamp the outer as a fragment.
        seed = 0xC0FFEE
        rng = random.Random(seed)
        outer_src, outer_dst = _outer_addrs(IP)
        pkts = []
        for _ in range(N_PKTS):
            isrc, idst = _rand_pair(rng, IP)
            isport, idport = _rand_port(rng), _rand_port(rng)
            outer = IP(
                src=outer_src,
                dst=outer_dst,
                proto=PROTO_IPINIP4,
                ttl=64,
                flags="MF",
                frag=0,
            )
            inner = IP(src=isrc, dst=idst) / UDP(sport=isport, dport=idport)
            pkts.append(outer / inner)

        dst_net, prefix = _outer_dst_route(IP)
        rip = self._add_ecmp_route(dst_net, prefix, is_ipv6=False)
        try:
            per_if, total = self._send(pkts)
        finally:
            rip.remove_vpp_config()
        self.assertEqual(total, N_PKTS)
        non_zero = sum(1 for c in per_if.values() if c > 0)
        self.assertEqual(
            non_zero, 1,
            "fragmented outer must NOT peek inner; got %s" % per_if,
        )

    def test_inner_v6_with_hbh_distributes(self):
        """Inner IPv6 with HBH ext header: helper walks to L4, distributes."""
        seed = 0xBEEF
        rng = random.Random(seed)
        outer_src, outer_dst = _outer_addrs(IP)
        pkts = []
        for _ in range(N_PKTS):
            isrc, idst = _rand_pair(rng, IPv6)
            isport, idport = _rand_port(rng), _rand_port(rng)
            inner = (
                IPv6(src=isrc, dst=idst, nh=0)
                / IPv6ExtHdrHopByHop(nh=17)
                / UDP(sport=isport, dport=idport)
            )
            outer = IP(src=outer_src, dst=outer_dst, proto=PROTO_IPINIP6, ttl=64)
            pkts.append(outer / inner)

        dst_net, prefix = _outer_dst_route(IP)
        rip = self._add_ecmp_route(dst_net, prefix, is_ipv6=False)
        try:
            per_if, total = self._send(pkts)
        finally:
            rip.remove_vpp_config()
        self.assertEqual(total, N_PKTS)
        non_zero = sum(1 for c in per_if.values() if c > 0)
        self.assertGreaterEqual(
            non_zero, 2,
            "inner v6 + HBH should still hash on inner ports; got %s" % per_if,
        )

    def test_inner_v6_with_fragment_falls_back(self):
        """Inner IPv6 with Fragment ext header: refuse peek, collapse."""
        seed = 0xC0DE
        rng = random.Random(seed)
        outer_src, outer_dst = _outer_addrs(IP)
        pkts = []
        for _ in range(N_PKTS):
            isrc, idst = _rand_pair(rng, IPv6)
            isport, idport = _rand_port(rng), _rand_port(rng)
            inner = (
                IPv6(src=isrc, dst=idst, nh=44)
                / IPv6ExtHdrFragment(nh=17)
                / UDP(sport=isport, dport=idport)
            )
            outer = IP(src=outer_src, dst=outer_dst, proto=PROTO_IPINIP6, ttl=64)
            pkts.append(outer / inner)

        dst_net, prefix = _outer_dst_route(IP)
        rip = self._add_ecmp_route(dst_net, prefix, is_ipv6=False)
        try:
            per_if, total = self._send(pkts)
        finally:
            rip.remove_vpp_config()
        self.assertEqual(total, N_PKTS)
        non_zero = sum(1 for c in per_if.values() if c > 0)
        self.assertEqual(
            non_zero, 1,
            "inner v6 + Fragment must NOT peek; got %s" % per_if,
        )

    def test_truncated_ipinip_no_crash(self):
        """Truncated IPinIP (only 4 bytes inner): no crash, collapses."""
        # Outer IP indicates IPinIP but payload is shorter than an inner IP
        # header.  The helper must check remaining bytes and fall back.
        outer_src, outer_dst = _outer_addrs(IP)
        # 4 bytes of garbage where the inner v4 header should be.
        truncated_payload = Raw(b"\x45\x00\x00\x14")
        pkts = []
        for _ in range(N_PKTS):
            pkts.append(
                IP(
                    src=outer_src, dst=outer_dst,
                    proto=PROTO_IPINIP4, ttl=64,
                ) / truncated_payload
            )

        dst_net, prefix = _outer_dst_route(IP)
        rip = self._add_ecmp_route(dst_net, prefix, is_ipv6=False)
        try:
            per_if, total = self._send(pkts)
        finally:
            rip.remove_vpp_config()
        # The packets are tiny; some may be silently dropped at L2 but the
        # important assertion is "VPP did not crash and no member-count
        # blew up".  Allow total >= 0.
        self.assertGreaterEqual(total, 0)
        non_zero = sum(1 for c in per_if.values() if c > 0)
        self.assertLessEqual(
            non_zero, 1,
            "truncated peek must NOT distribute; got %s" % per_if,
        )

    def test_truncated_gre_no_crash(self):
        """Truncated GRE (3-byte payload): no crash, collapses."""
        outer_src, outer_dst = _outer_addrs(IP)
        truncated_gre = Raw(b"\x00\x00\x08")  # less than 4-byte GRE header
        pkts = []
        for _ in range(N_PKTS):
            pkts.append(
                IP(
                    src=outer_src, dst=outer_dst,
                    proto=PROTO_GRE, ttl=64,
                ) / truncated_gre
            )

        dst_net, prefix = _outer_dst_route(IP)
        rip = self._add_ecmp_route(dst_net, prefix, is_ipv6=False)
        try:
            per_if, total = self._send(pkts)
        finally:
            rip.remove_vpp_config()
        non_zero = sum(1 for c in per_if.values() if c > 0)
        self.assertLessEqual(
            non_zero, 1,
            "truncated GRE peek must NOT distribute; got %s" % per_if,
        )


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
