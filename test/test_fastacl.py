#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 FastNetMon (fastnetmon.com)

"""FastACL FlowSpec filter tests.

Each test drives the binary API the way a controller would - add a rule,
arm the interface, put packets through - and then checks both the datapath
verdict and what the API reports back about it.
"""

import unittest

from framework import VppTestCase
from asfframework import VppTestRunner

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment

from vpp_papi import VppEnum
from vpp_ip_route import VppIpRoute, VppRoutePath
from config import config

N_PKTS = 17

# fastacl_match.flags is an opaque u32 on the wire; these are its bits.
MATCH_DST_PREFIX = 1 << 0
MATCH_SRC_PREFIX = 1 << 1
MATCH_PROTO = 1 << 2
MATCH_DST_PORT = 1 << 3
MATCH_PKT_LEN = 1 << 9
MATCH_FRAGMENT = 1 << 11
MATCH_IS_IP6 = 1 << 15

FRAG_ISF = 1 << 1

IP_PROTO_TCP = 6
IP_PROTO_UDP = 17


def mk_match(af=0, **kw):
    """A fastacl_match with every field defaulted, overridden by kw."""
    ip_key = "ip6" if af else "ip4"
    any_addr = "::" if af else "0.0.0.0"
    m = {
        "flags": 0,
        "dst_addr": {"af": af, "un": {ip_key: kw.pop("dst_ip", any_addr)}},
        "src_addr": {"af": af, "un": {ip_key: kw.pop("src_ip", any_addr)}},
        "dst_prefix_len": 0,
        "src_prefix_len": 0,
        "proto": 0,
        "dst_port_min": 0,
        "dst_port_max": 0,
        "src_port_min": 0,
        "src_port_max": 0,
        "either_port_min": 0,
        "either_port_max": 0,
        "icmp_type": 0,
        "icmp_code": 0,
        "tcp_flags_value": 0,
        "tcp_flags_mask": 0,
        "pkt_len_min": 0,
        "pkt_len_max": 0,
        "dscp": 0,
        "fragment_flags": 0,
        "fragment_mask": 0,
    }
    m.update(kw)
    return m


def mk_action(action_type, sample_ratio=0, sample_group=0):
    return {
        "type": action_type,
        "sample_ratio": sample_ratio,
        "sample_group": sample_group,
    }


@unittest.skipIf("fastacl" in config.excluded_plugins, "Exclude FastACL plugin tests")
class TestFastACL(VppTestCase):
    """FastACL FlowSpec Filter Test Case"""

    tuple_merge = True

    @classmethod
    def setUpClass(cls):
        super(TestFastACL, cls).setUpClass()
        e = VppEnum.vl_api_fastacl_action_type_t
        cls.DROP = e.FASTACL_ACTION_DROP
        cls.PERMIT = e.FASTACL_ACTION_PERMIT

    @classmethod
    def tearDownClass(cls):
        super(TestFastACL, cls).tearDownClass()

    def setUp(self):
        super(TestFastACL, self).setUp()

        self.create_pg_interfaces(range(2))
        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()
            i.config_ip6()
            i.resolve_ndp()

        self.vapi.fastacl_interface_enable_disable(
            sw_if_index=self.pg0.sw_if_index, enable_disable=True
        )

    def tearDown(self):
        self.vapi.fastacl_interface_enable_disable(
            sw_if_index=self.pg0.sw_if_index, enable_disable=False
        )
        self.vapi.fastacl_rule_del_all()

        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.admin_down()
        super(TestFastACL, self).tearDown()

    def add_rule(self, order, match, action):
        self.vapi.fastacl_rule_add(order=order, match=match, action=action)

    def dump(self):
        return self.vapi.fastacl_rule_dump()

    def pkts4(self, dst, proto=UDP, dport=4444, count=N_PKTS):
        l4 = proto(sport=1234, dport=dport)
        return [
            (
                Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
                / IP(src=self.pg0.remote_ip4, dst=dst)
                / l4
                / Raw(b"\xa5" * 64)
            )
            for _ in range(count)
        ]

    def pkts6(self, dst, count=N_PKTS):
        return [
            (
                Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
                / IPv6(src=self.pg0.remote_ip6, dst=dst)
                / UDP(sport=1234, dport=4444)
                / Raw(b"\xa5" * 64)
            )
            for _ in range(count)
        ]

    def tuples(self):
        """(tuple count, set of destination prefix lengths) of the classifier"""
        out = self.vapi.cli("show fastacl tuples")
        count, dplens, deepest = None, set(), 0
        for line in out.splitlines():
            parts = line.split()
            if line.startswith("tuples:"):
                count = int(parts[1])
            elif len(parts) == 10 and parts[0].isdigit():
                dplens.add(int(parts[2]))
                deepest = max(deepest, int(parts[9]))
        self.assertIsNotNone(count)
        return count, dplens, deepest

    def route_10_8(self):
        VppIpRoute(
            self,
            "10.0.0.0",
            8,
            [VppRoutePath(self.pg1.remote_ip4, self.pg1.sw_if_index)],
        ).add_vpp_config()

    def drop4(self, order, prefix, action=None):
        addr, plen = prefix.split("/")
        self.add_rule(
            order,
            mk_match(flags=MATCH_DST_PREFIX, dst_ip=addr, dst_prefix_len=int(plen)),
            mk_action(self.DROP if action is None else action),
        )

    def assert_dropped(self, dst):
        self.send_and_assert_no_replies(self.pg0, self.pkts4(dst))

    def assert_forwarded(self, dst):
        rx = self.send_and_expect(self.pg0, self.pkts4(dst), self.pg1)
        self.assertEqual(len(rx), N_PKTS)

    def test_drop_by_dst_prefix(self):
        """a destination-prefix rule drops only what it names"""
        self.add_rule(
            100,
            mk_match(
                flags=MATCH_DST_PREFIX,
                dst_ip=self.pg1.remote_ip4,
                dst_prefix_len=32,
            ),
            mk_action(self.DROP),
        )

        self.send_and_assert_no_replies(self.pg0, self.pkts4(self.pg1.remote_ip4))

    def test_unmatched_traffic_is_forwarded(self):
        """traffic outside the rule is forwarded untouched"""
        self.add_rule(
            100,
            mk_match(flags=MATCH_DST_PREFIX, dst_ip="192.0.2.0", dst_prefix_len=24),
            mk_action(self.DROP),
        )

        rx = self.send_and_expect(self.pg0, self.pkts4(self.pg1.remote_ip4), self.pg1)
        self.assertEqual(len(rx), N_PKTS)

    def test_permit_action_forwards(self):
        """an explicit permit at a lower order beats a later drop"""
        self.add_rule(
            100,
            mk_match(
                flags=MATCH_DST_PREFIX | MATCH_PROTO,
                dst_ip=self.pg1.remote_ip4,
                dst_prefix_len=32,
                proto=IP_PROTO_UDP,
            ),
            mk_action(self.PERMIT),
        )
        self.add_rule(
            200,
            mk_match(
                flags=MATCH_DST_PREFIX,
                dst_ip=self.pg1.remote_ip4,
                dst_prefix_len=32,
            ),
            mk_action(self.DROP),
        )

        rx = self.send_and_expect(self.pg0, self.pkts4(self.pg1.remote_ip4), self.pg1)
        self.assertEqual(len(rx), N_PKTS)

    def test_proto_is_honoured(self):
        """a UDP rule leaves TCP alone"""
        self.add_rule(
            100,
            mk_match(
                flags=MATCH_DST_PREFIX | MATCH_PROTO,
                dst_ip=self.pg1.remote_ip4,
                dst_prefix_len=32,
                proto=IP_PROTO_UDP,
            ),
            mk_action(self.DROP),
        )

        self.send_and_assert_no_replies(
            self.pg0, self.pkts4(self.pg1.remote_ip4, proto=UDP)
        )
        rx = self.send_and_expect(
            self.pg0, self.pkts4(self.pg1.remote_ip4, proto=TCP), self.pg1
        )
        self.assertEqual(len(rx), N_PKTS)

    def test_destination_port_range(self):
        """a port range drops inside it and forwards outside it"""
        self.add_rule(
            100,
            mk_match(
                flags=MATCH_DST_PREFIX | MATCH_PROTO | MATCH_DST_PORT,
                dst_ip=self.pg1.remote_ip4,
                dst_prefix_len=32,
                proto=IP_PROTO_UDP,
                dst_port_min=1000,
                dst_port_max=2000,
            ),
            mk_action(self.DROP),
        )

        self.send_and_assert_no_replies(
            self.pg0, self.pkts4(self.pg1.remote_ip4, dport=1500)
        )
        rx = self.send_and_expect(
            self.pg0, self.pkts4(self.pg1.remote_ip4, dport=2500), self.pg1
        )
        self.assertEqual(len(rx), N_PKTS)

    def test_ipv6_drop(self):
        """the same rule set serves IPv6"""
        self.add_rule(
            100,
            mk_match(
                af=1,
                flags=MATCH_DST_PREFIX | MATCH_IS_IP6,
                dst_ip=self.pg1.remote_ip6,
                dst_prefix_len=128,
            ),
            mk_action(self.DROP),
        )

        self.send_and_assert_no_replies(self.pg0, self.pkts6(self.pg1.remote_ip6))

    def test_rule_dump_round_trip(self):
        """what the dump returns is what was installed"""
        self.add_rule(
            42,
            mk_match(
                flags=MATCH_DST_PREFIX | MATCH_PROTO,
                dst_ip="198.51.100.0",
                dst_prefix_len=24,
                proto=IP_PROTO_TCP,
            ),
            mk_action(self.DROP),
        )

        rules = self.dump()
        self.assertEqual(len(rules), 1)
        r = rules[0]
        self.assertEqual(r.order, 42)
        self.assertEqual(r.match.proto, IP_PROTO_TCP)
        self.assertEqual(r.match.dst_prefix_len, 24)
        self.assertEqual(str(r.match.dst_addr), "198.51.100.0")
        self.assertEqual(r.action.type, self.DROP)

    def test_rule_del_stops_dropping(self):
        """deleting the rule restores forwarding"""
        self.add_rule(
            100,
            mk_match(
                flags=MATCH_DST_PREFIX,
                dst_ip=self.pg1.remote_ip4,
                dst_prefix_len=32,
            ),
            mk_action(self.DROP),
        )
        self.send_and_assert_no_replies(self.pg0, self.pkts4(self.pg1.remote_ip4))

        rules = self.dump()
        self.assertEqual(len(rules), 1)
        self.vapi.fastacl_rule_del(rule_index=rules[0].rule_index)
        self.assertEqual(len(self.dump()), 0)

        rx = self.send_and_expect(self.pg0, self.pkts4(self.pg1.remote_ip4), self.pg1)
        self.assertEqual(len(rx), N_PKTS)

    def test_counters_follow_the_drops(self):
        """per-rule and aggregate counters agree with what was dropped"""
        self.vapi.fastacl_counters_clear()
        self.add_rule(
            100,
            mk_match(
                flags=MATCH_DST_PREFIX,
                dst_ip=self.pg1.remote_ip4,
                dst_prefix_len=32,
            ),
            mk_action(self.DROP),
        )

        self.send_and_assert_no_replies(self.pg0, self.pkts4(self.pg1.remote_ip4))

        rules = self.dump()
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0].packet_count, N_PKTS)

        agg = self.vapi.fastacl_counters_get()
        self.assertEqual(agg.total_dropped, N_PKTS)
        self.assertEqual(agg.n_hit_rules, 1)

    def test_batch_add_installs_every_rule(self):
        """the batch message is all-or-nothing and installs what it took"""
        rules = [
            {
                "order": 100 + i,
                "match": mk_match(
                    flags=MATCH_DST_PREFIX,
                    dst_ip="203.0.113.%d" % i,
                    dst_prefix_len=32,
                ),
                "action": mk_action(self.DROP),
            }
            for i in range(8)
        ]

        rv = self.vapi.fastacl_rule_add_batch(count=len(rules), rules=rules)
        self.assertEqual(rv.n_added, len(rules))
        self.assertEqual(len(self.dump()), len(rules))

    def test_del_all_clears_the_table(self):
        """del_all empties the table and stops filtering"""
        for i in range(4):
            self.add_rule(
                100 + i,
                mk_match(
                    flags=MATCH_DST_PREFIX,
                    dst_ip="203.0.113.%d" % i,
                    dst_prefix_len=32,
                ),
                mk_action(self.DROP),
            )
        self.assertEqual(len(self.dump()), 4)

        self.vapi.fastacl_rule_del_all()
        self.assertEqual(len(self.dump()), 0)

        rx = self.send_and_expect(self.pg0, self.pkts4(self.pg1.remote_ip4), self.pg1)
        self.assertEqual(len(rx), N_PKTS)

    def test_isf_matches_only_later_fragments(self):
        """IsF matches fragments other than the first (RFC 8955)"""
        self.add_rule(
            100,
            mk_match(
                flags=MATCH_DST_PREFIX | MATCH_FRAGMENT,
                dst_ip=self.pg1.remote_ip4,
                dst_prefix_len=32,
                fragment_flags=FRAG_ISF,
                fragment_mask=FRAG_ISF,
            ),
            mk_action(self.DROP),
        )

        first = [
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, flags="MF", frag=0)
            / UDP(sport=1234, dport=4444)
            / Raw(b"\xa5" * 64)
            for _ in range(N_PKTS)
        ]
        later = [
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, proto=17, frag=2)
            / Raw(b"\xa5" * 64)
            for _ in range(N_PKTS)
        ]
        rx = self.send_and_expect(self.pg0, first, self.pg1)
        self.assertEqual(len(rx), N_PKTS)
        self.send_and_assert_no_replies(self.pg0, later)

    def test_packet_length_spans_buffer_chain(self):
        """packet length is matched on the whole packet, not the first buffer"""
        self.add_rule(
            100,
            mk_match(
                flags=MATCH_DST_PREFIX | MATCH_PKT_LEN,
                dst_ip=self.pg1.remote_ip4,
                dst_prefix_len=32,
                pkt_len_min=5000,
                pkt_len_max=6000,
            ),
            mk_action(self.DROP),
        )
        self.add_rule(
            200,
            mk_match(
                af=1,
                flags=MATCH_DST_PREFIX | MATCH_PKT_LEN | MATCH_IS_IP6,
                dst_ip=self.pg1.remote_ip6,
                dst_prefix_len=128,
                pkt_len_min=5000,
                pkt_len_max=6000,
            ),
            mk_action(self.DROP),
        )

        def p4(size):
            return [
                Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
                / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4)
                / UDP(sport=1234, dport=4444)
                / Raw(b"\xa5" * (size - 28))
                for _ in range(N_PKTS)
            ]

        def p6(size):
            return [
                Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
                / IPv6(src=self.pg0.remote_ip6, dst=self.pg1.remote_ip6)
                / UDP(sport=1234, dport=4444)
                / Raw(b"\xa5" * (size - 48))
                for _ in range(N_PKTS)
            ]

        rx = self.send_and_expect(self.pg0, p4(4000), self.pg1)
        self.assertEqual(len(rx), N_PKTS)
        self.send_and_assert_no_replies(self.pg0, p4(5028))
        rx = self.send_and_expect(self.pg0, p6(4000), self.pg1)
        self.assertEqual(len(rx), N_PKTS)
        self.send_and_assert_no_replies(self.pg0, p6(5028))

    def test_later_ipv6_fragment_keeps_its_protocol(self):
        """a non-first IPv6 fragment matches the protocol its header names"""
        self.add_rule(
            100,
            mk_match(
                af=1,
                flags=MATCH_DST_PREFIX | MATCH_PROTO | MATCH_IS_IP6,
                dst_ip=self.pg1.remote_ip6,
                dst_prefix_len=128,
                proto=IP_PROTO_UDP,
            ),
            mk_action(self.DROP),
        )

        def later(nh):
            return [
                Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
                / IPv6(src=self.pg0.remote_ip6, dst=self.pg1.remote_ip6)
                / IPv6ExtHdrFragment(offset=1, m=0, id=0x5678, nh=nh)
                / Raw(b"\xa5" * 64)
                for _ in range(N_PKTS)
            ]

        rx = self.send_and_expect(self.pg0, later(IP_PROTO_TCP), self.pg1)
        self.assertEqual(len(rx), N_PKTS)
        self.send_and_assert_no_replies(self.pg0, later(IP_PROTO_UDP))

    def test_rejected_candidate_falls_through(self):
        """a rule whose length does not match yields to the next rule"""
        self.add_rule(
            100,
            mk_match(
                flags=MATCH_DST_PREFIX | MATCH_PKT_LEN,
                dst_ip=self.pg1.remote_ip4,
                dst_prefix_len=32,
                pkt_len_min=1000,
                pkt_len_max=1500,
            ),
            mk_action(self.PERMIT),
        )
        self.add_rule(
            200,
            mk_match(
                flags=MATCH_DST_PREFIX,
                dst_ip=self.pg1.remote_ip4,
                dst_prefix_len=32,
            ),
            mk_action(self.DROP),
        )

        self.send_and_assert_no_replies(self.pg0, self.pkts4(self.pg1.remote_ip4))
        long = [
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4)
            / UDP(sport=1234, dport=4444)
            / Raw(b"\xa5" * 1100)
            for _ in range(N_PKTS)
        ]
        rx = self.send_and_expect(self.pg0, long, self.pg1)
        self.assertEqual(len(rx), N_PKTS)

    def test_later_fragment_skips_port_rule(self):
        """a port range that covers port 0 never matches a later fragment"""
        self.add_rule(
            100,
            mk_match(
                flags=MATCH_DST_PREFIX | MATCH_PROTO | MATCH_DST_PORT,
                dst_ip=self.pg1.remote_ip4,
                dst_prefix_len=32,
                proto=IP_PROTO_UDP,
                dst_port_min=0,
                dst_port_max=1024,
            ),
            mk_action(self.DROP),
        )

        later = [
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, proto=17, frag=2)
            / Raw(b"\xa5" * 64)
            for _ in range(N_PKTS)
        ]
        rx = self.send_and_expect(self.pg0, later, self.pg1)
        self.assertEqual(len(rx), N_PKTS)
        self.send_and_assert_no_replies(
            self.pg0, self.pkts4(self.pg1.remote_ip4, dport=53)
        )

    def test_tuple_merge_shares_tuples(self):
        """nearby prefixes share one relaxed tuple only under TupleMerge"""
        for order, prefix in enumerate(
            ("10.40.0.0/24", "10.41.0.0/23", "10.42.0.0/22", "10.43.0.0/21")
        ):
            self.drop4(10 * (order + 1), prefix)
        count, _, _ = self.tuples()
        self.assertEqual(count, 1 if self.tuple_merge else 4)
        self.assertIn(
            "tuple-merge: " + ("on" if self.tuple_merge else "off"),
            self.vapi.cli("show fastacl tuples"),
        )

    def test_relaxed_tuple_does_not_widen_rule(self):
        """a /22 in a relaxed /20 tuple matches only its own /22"""
        self.route_10_8()
        self.drop4(10, "10.80.0.0/20")
        self.drop4(20, "10.81.0.0/22")
        self.assert_dropped("10.81.1.1")
        self.assert_forwarded("10.81.8.1")

    def test_precedence_across_merged_tuples(self):
        """the lowest order wins whichever tuple holds the rule"""
        self.route_10_8()
        self.drop4(30, "10.50.1.0/24")
        self.drop4(20, "10.50.0.0/22", self.PERMIT)
        self.drop4(10, "10.50.1.0/26")
        self.assert_dropped("10.50.1.1")
        self.assert_forwarded("10.50.1.200")
        self.assert_forwarded("10.50.3.1")

    def test_chain_split(self):
        """a chain past 16 rules moves into a tighter tuple; verdicts hold"""
        self.route_10_8()
        self.drop4(5, "10.61.0.0/24")
        for k in range(20):
            self.drop4(100 + k, "10.60.0.%d/29" % (8 * k))
        count, dplens, deepest = self.tuples()
        self.assertEqual(count, 2)
        self.assertLessEqual(deepest, 16)
        self.assertEqual(dplens, {20, 27} if self.tuple_merge else {24, 29})
        self.assert_dropped("10.60.0.1")
        self.assert_dropped("10.60.0.153")
        self.assert_forwarded("10.60.0.200")

        for r in self.dump():
            if r.order >= 100:
                self.vapi.fastacl_rule_del(rule_index=r.rule_index)
        self.assertEqual(self.tuples()[0], 1)
        self.assert_forwarded("10.60.0.1")

    def test_recreated_interface_can_be_armed(self):
        """a deleted interface does not leave its index marked as armed"""
        sw = self.vapi.create_loopback().sw_if_index
        name = self.vapi.sw_interface_dump(sw_if_index=sw)[0].interface_name
        self.vapi.fastacl_interface_enable_disable(sw_if_index=sw, enable_disable=True)
        self.assertIn(
            "fastacl-filter", self.vapi.cli("show interface features " + name)
        )

        self.vapi.delete_loopback(sw_if_index=sw)
        again = self.vapi.create_loopback().sw_if_index
        self.assertEqual(again, sw)
        name = self.vapi.sw_interface_dump(sw_if_index=again)[0].interface_name

        self.vapi.fastacl_interface_enable_disable(
            sw_if_index=again, enable_disable=True
        )
        self.assertIn(
            "fastacl-filter", self.vapi.cli("show interface features " + name)
        )
        self.vapi.fastacl_interface_enable_disable(
            sw_if_index=again, enable_disable=False
        )
        self.vapi.delete_loopback(sw_if_index=again)


@unittest.skipIf("fastacl" in config.excluded_plugins, "Exclude FastACL plugin tests")
class TestFastACLPlainTSS(TestFastACL):
    """FastACL FlowSpec Filter Test Case, plain Tuple Space Search"""

    tuple_merge = False
    extra_vpp_config = ["fastacl", "{", "tuple-merge", "off", "}"]


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
