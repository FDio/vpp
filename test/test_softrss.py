#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Soft-RSS plugin tests (baseline + ip-offset PPPoE mode)."""

import os
import unittest
from pathlib import Path

from framework import VppTestCase
from asfframework import VppTestRunner
from vpp_l2 import VppBridgeDomain, VppBridgeDomainPort
from vpp_papi import VppEnum

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.ppp import PPPoE, PPP
from scapy.packet import Raw

# PPPoE-session preamble on an untagged link:
#   Ether (14) + PPPoE (6) + PPP (2) = 22 bytes before the inner IP header.
PPPOE_IP_OFFSET = 22

KEY_FIELD_LEN = 64  # fixed-size key field in the API message


def _zero_key():
    return b"\x00" * KEY_FIELD_LEN


class _SoftRssTestBase(VppTestCase):
    """Shared fixture for soft-rss tests.

    Provides:
      * two pg interfaces admin-up on the class
      * a bridge domain with both pg's as members, per test
      * cached enum aliases self.T / self.F
      * a fast tearDown that skips VppAsfTestCase.tearDown()'s diagnostic
        CLIs (show run, show interface, show hardware, show log,
        show bihash, set_errors_str). show run is O(n_nodes * n_workers)
        and dominates per-test time, especially with high worker counts.
        Essential cleanup (registry teardown + pcap removal) is kept.
        When a test fails its own assertion message is typically enough;
        VPP's log.txt in /tmp/vpp-unittest-* still has the details.

    Subclasses must set vpp_worker_count.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.create_pg_interfaces(range(2))
        for i in cls.pg_interfaces:
            i.admin_up()

    @classmethod
    def tearDownClass(cls):
        for i in cls.pg_interfaces:
            i.admin_down()
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        self.T = VppEnum.vl_api_soft_rss_type_t
        self.F = VppEnum.vl_api_soft_rss_config_flags_t
        self.bd = VppBridgeDomain(self, bd_id=1).add_vpp_config()
        self.port0 = VppBridgeDomainPort(self, self.bd, self.pg0).add_vpp_config()
        self.port1 = VppBridgeDomainPort(self, self.bd, self.pg1).add_vpp_config()

    def tearDown(self):
        # Plugin-level cleanup: disable and clear soft-rss on any interface
        # that might have been configured during the test. Safe to run on
        # interfaces that were never configured (errors are ignored).
        for i in self.pg_interfaces:
            try:
                self.vapi.soft_rss_enable_disable(
                    sw_if_index=i.sw_if_index, enable=False
                )
            except Exception:
                pass
            try:
                self.vapi.soft_rss_config_clear(sw_if_index=i.sw_if_index)
            except Exception:
                pass
        self.port0.remove_vpp_config()
        self.port1.remove_vpp_config()
        self.bd.remove_vpp_config()

        # Fast tearDown: skip the parent's diagnostic show commands.
        # See class docstring for rationale.
        if not self.vpp_dead:
            try:
                if self.remove_configured_vpp_objects_on_tear_down:
                    self.registry.remove_vpp_config(self.logger)
                self.registry.unregister_all(self.logger)
            except Exception:
                pass
        if hasattr(self, "pg_interfaces") and self.pg_interfaces:
            testcase_dir = os.path.dirname(self.pg_interfaces[0].out_path)
            for p in Path(testcase_dir).glob("pg*.pcap"):
                try:
                    p.unlink()
                except FileNotFoundError:
                    pass


class TestSoftRss(_SoftRssTestBase):
    """Soft-RSS plugin test case"""

    vpp_worker_count = 2

    # ---------------------------------------------------------------- helpers

    def _config_set(self, iface, **overrides):
        """soft_rss_config_set() with sensible defaults"""
        kwargs = dict(
            sw_if_index=iface.sw_if_index,
            default_type=self.T.SOFT_RSS_TYPE_API_4_TUPLE,
            ipv4_type=self.T.SOFT_RSS_TYPE_API_NOT_SET,
            ipv6_type=self.T.SOFT_RSS_TYPE_API_NOT_SET,
            flags=self.F.SOFT_RSS_CFG_F_NONE,
            offset=0,
            key_len=0,
            key=_zero_key(),
            n_threads=0,
            threads=[],
        )
        kwargs.update(overrides)
        return self.vapi.soft_rss_config_set(**kwargs)

    def _ipv4_udp_stream(self, count, base_sport=1000):
        """Ether/IP/UDP stream with varying UDP source port."""
        pkts = []
        for i in range(count):
            p = (
                Ether(dst=self.pg1.remote_mac, src=self.pg0.remote_mac)
                / IP(src="10.0.0.1", dst="10.0.0.2")
                / UDP(sport=base_sport + i, dport=8298)
                / Raw(b"x" * 48)
            )
            pkts.append(p)
        return pkts

    def _pppoe_ipv4_udp_stream(self, count, base_sport=1000, session_id=1):
        """Ether/PPPoE/PPP/IP/UDP stream -- inner IPv4 UDP flows vary by sport."""
        pkts = []
        for i in range(count):
            p = (
                Ether(dst=self.pg1.remote_mac, src=self.pg0.remote_mac)
                / PPPoE(sessionid=session_id)
                / PPP(proto=0x0021)
                / IP(src="192.0.2.1", dst="192.0.2.2")
                / UDP(sport=base_sport + i, dport=8298)
                / Raw(b"x" * 48)
            )
            pkts.append(p)
        return pkts

    def _pppoe_ipv6_udp_stream(self, count, base_sport=1000, session_id=1):
        """Ether/PPPoE/PPP/IPv6/UDP stream."""
        pkts = []
        for i in range(count):
            p = (
                Ether(dst=self.pg1.remote_mac, src=self.pg0.remote_mac)
                / PPPoE(sessionid=session_id)
                / PPP(proto=0x0057)
                / IPv6(src="2001:db8::1", dst="2001:db8::2")
                / UDP(sport=base_sport + i, dport=8298)
                / Raw(b"x" * 48)
            )
            pkts.append(p)
        return pkts

    # ------------------------------------------------------------------ tests

    def test_api_config_roundtrip(self):
        """config_set() and config_get() returns matching fields"""
        self._config_set(
            self.pg0,
            default_type=self.T.SOFT_RSS_TYPE_API_4_TUPLE,
        )

        reply = self.vapi.soft_rss_config_get(sw_if_index=self.pg0.sw_if_index)
        self.assertEqual(reply.retval, 0)
        self.assertEqual(reply.sw_if_index, self.pg0.sw_if_index)
        self.assertFalse(reply.enabled)
        self.assertEqual(reply.ipv4_type, self.T.SOFT_RSS_TYPE_API_4_TUPLE)
        self.assertEqual(reply.ipv6_type, self.T.SOFT_RSS_TYPE_API_4_TUPLE)
        # default mode: match_offset = 12 (EtherType position)
        self.assertEqual(reply.match_offset, 12)
        self.assertEqual(reply.n_threads, self.vpp_worker_count)
        # by default main thread is excluded
        self.assertFalse(reply.flags & self.F.SOFT_RSS_CFG_F_WITH_MAIN_THREAD)
        self.assertFalse(reply.flags & self.F.SOFT_RSS_CFG_F_L3_OFFSET)

    def test_api_config_l3_offset(self):
        """config_set() with L3_OFFSET stores the absolute IP offset"""
        self._config_set(
            self.pg0,
            flags=self.F.SOFT_RSS_CFG_F_L3_OFFSET,
            offset=PPPOE_IP_OFFSET,
        )

        reply = self.vapi.soft_rss_config_get(sw_if_index=self.pg0.sw_if_index)
        self.assertEqual(reply.retval, 0)
        self.assertEqual(reply.match_offset, PPPOE_IP_OFFSET)
        self.assertTrue(reply.flags & self.F.SOFT_RSS_CFG_F_L3_OFFSET)

    def test_api_enable_disable(self):
        """enable_disable() flips the 'enabled' field"""
        self._config_set(self.pg0)

        self.vapi.soft_rss_enable_disable(sw_if_index=self.pg0.sw_if_index, enable=True)
        reply = self.vapi.soft_rss_config_get(sw_if_index=self.pg0.sw_if_index)
        self.assertTrue(reply.enabled)

        self.vapi.soft_rss_enable_disable(
            sw_if_index=self.pg0.sw_if_index, enable=False
        )
        reply = self.vapi.soft_rss_config_get(sw_if_index=self.pg0.sw_if_index)
        self.assertFalse(reply.enabled)

    def test_api_interface_dump(self):
        """interface_dump() returns configured interfaces"""
        self._config_set(self.pg0)
        self._config_set(
            self.pg1,
            flags=self.F.SOFT_RSS_CFG_F_L3_OFFSET,
            offset=PPPOE_IP_OFFSET,
        )

        details = self.vapi.soft_rss_interface_dump()
        by_sw = {d.sw_if_index: d for d in details}
        self.assertIn(self.pg0.sw_if_index, by_sw)
        self.assertIn(self.pg1.sw_if_index, by_sw)
        self.assertEqual(by_sw[self.pg0.sw_if_index].match_offset, 12)
        self.assertEqual(by_sw[self.pg1.sw_if_index].match_offset, PPPOE_IP_OFFSET)
        self.assertTrue(
            by_sw[self.pg1.sw_if_index].flags & self.F.SOFT_RSS_CFG_F_L3_OFFSET
        )

    def test_api_config_clear(self):
        """config_clear() removes the entry"""
        self._config_set(self.pg0)
        self.vapi.soft_rss_enable_disable(sw_if_index=self.pg0.sw_if_index, enable=True)

        self.vapi.soft_rss_config_clear(sw_if_index=self.pg0.sw_if_index)

        # After clearing, the interface no longer appears in the dump.
        details = self.vapi.soft_rss_interface_dump()
        self.assertNotIn(self.pg0.sw_if_index, {d.sw_if_index for d in details})

        # A direct config_get now returns a non-zero retval.
        with self.vapi.assert_negative_api_retval():
            self.vapi.soft_rss_config_get(sw_if_index=self.pg0.sw_if_index)

    def test_dataplane_baseline(self):
        """Plain Ether/IPv4/UDP traffic is forwarded"""
        self._config_set(self.pg0)
        self.vapi.soft_rss_enable_disable(sw_if_index=self.pg0.sw_if_index, enable=True)

        pkts = self._ipv4_udp_stream(count=64)
        rxs = self.send_and_expect(self.pg0, pkts, self.pg1)
        self.assertEqual(len(rxs), 64)

    def test_dataplane_pppoe_l3_offset(self):
        """L3-offset mode hashes inner IPv4 of PPPoE frames"""
        self._config_set(
            self.pg0,
            flags=self.F.SOFT_RSS_CFG_F_L3_OFFSET,
            offset=PPPOE_IP_OFFSET,
        )
        self.vapi.soft_rss_enable_disable(sw_if_index=self.pg0.sw_if_index, enable=True)

        pkts = self._pppoe_ipv4_udp_stream(count=64)
        rxs = self.send_and_expect(self.pg0, pkts, self.pg1)
        self.assertEqual(len(rxs), 64)

        # Also verify IPv6 inner works
        pkts6 = self._pppoe_ipv6_udp_stream(count=32)
        rxs6 = self.send_and_expect(self.pg0, pkts6, self.pg1)
        self.assertEqual(len(rxs6), 32)

    def test_dataplane_pppoe_distribution(self):
        """Varied inner 5-tuple produces distinct hashes"""
        self._config_set(
            self.pg0,
            flags=self.F.SOFT_RSS_CFG_F_L3_OFFSET,
            offset=PPPOE_IP_OFFSET,
        )
        self.vapi.soft_rss_enable_disable(sw_if_index=self.pg0.sw_if_index, enable=True)

        # Capture a trace so we can inspect per-packet thread_index assignments.
        self.vapi.cli("clear trace")
        self.vapi.cli("trace add pg-input 128")

        pkts = self._pppoe_ipv4_udp_stream(count=128)
        self.send_and_expect(self.pg0, pkts, self.pg1)

        trace = self.vapi.cli("show trace")
        # Look for soft-rss trace lines; expect at least 2 distinct thread
        # indices across the flow when worker_count > 1.
        threads = set()
        for line in trace.splitlines():
            if "soft-rss:" in line and "thread " in line:
                try:
                    tid = int(line.rsplit("thread ", 1)[1].split()[0])
                    threads.add(tid)
                except (ValueError, IndexError):
                    pass
        self.assertGreaterEqual(
            len(threads),
            2,
            f"expected RSS to hit >=2 worker threads, got {threads}",
        )


class TestSoftRssPPPoEDistribution(_SoftRssTestBase):
    """Per-hash-type PPPoE distribution tests.

    Runs with 16 worker threads so that reta_mask is 15 and each packet's
    low-nibble hash selects 1 of 16 buckets -- giving a meaningful spread
    metric. For each RSS type we verify:

      * a "spread" case where the fields that the hash is supposed to cover
        vary -> pinned exact unique-thread count
      * a "collapse" case where only fields the hash is supposed to IGNORE
        vary -> unique thread count == 1 (proves the hash is not secretly
        peeking at those fields)

    All packets are PPPoE-session encapsulated on an untagged Ethernet port
    (ip-offset = 22).
    """

    vpp_worker_count = 16
    PKT_COUNT = 64

    # Toeplitz hash is deterministic: same key + same packet bytes gives the
    # same 16-bit output, and thread assignment is (hash & 15). With the
    # fixed inputs below the unique-thread count is a constant, which we
    # pin so that any future bug (off-by-one in key offsets, wrong field
    # masked in, wrong byte order, truncation change, default-key change,
    # ...) breaks the test immediately rather than silently still landing
    # above some lower bound.
    EXPECTED_4_TUPLE_UNIQUE = 16
    EXPECTED_2_TUPLE_UNIQUE = 15
    EXPECTED_SRC_IP_UNIQUE = 16
    EXPECTED_DST_IP_UNIQUE = 16

    # ---------------------------------------------------------------- helpers

    def _pppoe_pkt(self, src_ip, dst_ip, sport, dport):
        return (
            Ether(dst=self.pg1.remote_mac, src=self.pg0.remote_mac)
            / PPPoE(sessionid=1)
            / PPP(proto=0x0021)
            / IP(src=src_ip, dst=dst_ip)
            / UDP(sport=sport, dport=dport)
            / Raw(b"x" * 48)
        )

    def _ip_from_idx(self, base, idx):
        """Turn an index 0..255 into 'base.idx' (e.g. '10.0.0.5')."""
        return f"{base}.{idx}"

    @staticmethod
    def _varied_ip(scope, idx):
        """Deterministic pseudo-random IP with entropy in every byte.

        Sequential /24-style addresses give poor Toeplitz spread because
        only one byte varies and both src/dst vary in lockstep. This
        helper scrambles the low three bytes using coprime multipliers
        so every byte shows independent variation across the input set,
        which is what the hash needs to distribute well.
        """
        a = (idx * 37 + 17) & 0xFF
        b = (idx * 53 + 29) & 0xFF
        c = ((idx * 101 + 7) & 0x7F) + 1  # 1..128, avoid .0 and broadcast
        # 'scope' lets us keep src and dst in disjoint /8s so they never
        # collide even when the scrambled bytes coincide.
        return f"{scope}.{a}.{b}.{c}"

    def _configure(self, rss_type):
        self.vapi.soft_rss_config_set(
            sw_if_index=self.pg0.sw_if_index,
            default_type=rss_type,
            ipv4_type=self.T.SOFT_RSS_TYPE_API_NOT_SET,
            ipv6_type=self.T.SOFT_RSS_TYPE_API_NOT_SET,
            flags=self.F.SOFT_RSS_CFG_F_L3_OFFSET,
            offset=PPPOE_IP_OFFSET,
            key_len=0,
            key=_zero_key(),
            n_threads=0,
            threads=[],
        )
        self.vapi.soft_rss_enable_disable(sw_if_index=self.pg0.sw_if_index, enable=True)

    def _distribution(self, pkts):
        """Send pkts through pg0, return the set of thread_index values
        observed in the soft-rss traces."""
        self.vapi.cli("clear trace")
        self.vapi.cli(f"trace add pg-input {len(pkts) + 8}")
        self.send_and_expect(self.pg0, pkts, self.pg1)
        trace = self.vapi.cli("show trace max %d" % (len(pkts) + 8))
        threads = set()
        for line in trace.splitlines():
            if "soft-rss:" in line and "thread " in line:
                try:
                    tid = int(line.rsplit("thread ", 1)[1].split()[0])
                    threads.add(tid)
                except (ValueError, IndexError):
                    pass
        self.logger.info(
            f"soft-rss distribution: {len(threads)} unique threads {threads}"
        )
        return threads

    # ------------------------------- test matrix: spread + collapse per type

    def test_flow_affinity(self):
        """Repeats of the same 5-tuple"""
        self._configure(self.T.SOFT_RSS_TYPE_API_4_TUPLE)
        pkts = [self._pppoe_pkt("10.0.0.1", "10.0.0.2", 1000, 2000)] * self.PKT_COUNT
        threads = self._distribution(pkts)
        self.assertEqual(
            len(threads), 1, f"same flow should pin to one worker, got {threads}"
        )

    def test_4_tuple_spread(self):
        """4-tuple: varied IPs and ports"""
        self._configure(self.T.SOFT_RSS_TYPE_API_4_TUPLE)
        pkts = [
            self._pppoe_pkt(
                self._varied_ip(10, i),
                self._varied_ip(20, i),
                1000 + i,
                2000 + i,
            )
            for i in range(self.PKT_COUNT)
        ]
        threads = self._distribution(pkts)
        self.assertEqual(
            len(threads),
            self.EXPECTED_4_TUPLE_UNIQUE,
            f"4-tuple: expected exactly {self.EXPECTED_4_TUPLE_UNIQUE} unique "
            f"threads for the pinned input set, got {len(threads)} ({threads})",
        )

    def test_2_tuple_spread(self):
        """2-tuple: varied IPs, fixed ports"""
        self._configure(self.T.SOFT_RSS_TYPE_API_2_TUPLE)
        pkts = [
            self._pppoe_pkt(
                self._varied_ip(10, i),
                self._varied_ip(20, i),
                1000,
                2000,
            )
            for i in range(self.PKT_COUNT)
        ]
        threads = self._distribution(pkts)
        self.assertEqual(
            len(threads),
            self.EXPECTED_2_TUPLE_UNIQUE,
            f"2-tuple: expected exactly {self.EXPECTED_2_TUPLE_UNIQUE} unique "
            f"threads for the pinned input set, got {len(threads)} ({threads})",
        )

    def test_2_tuple_ignores_ports(self):
        """2-tuple: fixed IPs, varied ports"""
        self._configure(self.T.SOFT_RSS_TYPE_API_2_TUPLE)
        pkts = [
            self._pppoe_pkt("10.0.0.1", "10.0.0.2", 1000 + i, 2000 + i)
            for i in range(self.PKT_COUNT)
        ]
        threads = self._distribution(pkts)
        self.assertEqual(
            len(threads), 1, f"2-tuple must not depend on ports, got {threads}"
        )

    def test_src_ip_spread(self):
        """src-ip: varied src IP"""
        self._configure(self.T.SOFT_RSS_TYPE_API_SRC_IP)
        pkts = [
            self._pppoe_pkt(
                self._varied_ip(10, i),
                "20.0.0.254",
                1000,
                2000,
            )
            for i in range(self.PKT_COUNT)
        ]
        threads = self._distribution(pkts)
        self.assertEqual(
            len(threads),
            self.EXPECTED_SRC_IP_UNIQUE,
            f"src-ip: expected exactly {self.EXPECTED_SRC_IP_UNIQUE} unique "
            f"threads for the pinned input set, got {len(threads)} ({threads})",
        )

    def test_src_ip_ignores_others(self):
        """src-ip: fixed src, varied dst+ports"""
        self._configure(self.T.SOFT_RSS_TYPE_API_SRC_IP)
        pkts = [
            self._pppoe_pkt(
                "10.0.0.1",
                self._ip_from_idx("10.1.0", i + 1),
                1000 + i,
                2000 + i,
            )
            for i in range(self.PKT_COUNT)
        ]
        threads = self._distribution(pkts)
        self.assertEqual(
            len(threads), 1, f"src-ip must ignore non-src fields, got {threads}"
        )

    def test_dst_ip_spread(self):
        """dst-ip: varied dst IP"""
        self._configure(self.T.SOFT_RSS_TYPE_API_DST_IP)
        pkts = [
            self._pppoe_pkt(
                "10.0.0.254",
                self._varied_ip(20, i),
                1000,
                2000,
            )
            for i in range(self.PKT_COUNT)
        ]
        threads = self._distribution(pkts)
        self.assertEqual(
            len(threads),
            self.EXPECTED_DST_IP_UNIQUE,
            f"dst-ip: expected exactly {self.EXPECTED_DST_IP_UNIQUE} unique "
            f"threads for the pinned input set, got {len(threads)} ({threads})",
        )

    def test_dst_ip_ignores_others(self):
        """dst-ip: fixed dst IP, varied src+ports"""
        self._configure(self.T.SOFT_RSS_TYPE_API_DST_IP)
        pkts = [
            self._pppoe_pkt(
                self._ip_from_idx("10.0.0", i + 1),
                "10.1.0.254",
                1000 + i,
                2000 + i,
            )
            for i in range(self.PKT_COUNT)
        ]
        threads = self._distribution(pkts)
        self.assertEqual(
            len(threads), 1, f"dst-ip must ignore non-dst fields, got {threads}"
        )


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
