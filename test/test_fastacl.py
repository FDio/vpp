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
from scapy.layers.inet6 import IPv6

from vpp_papi import VppEnum
from config import config

N_PKTS = 17

# fastacl_match.flags is an opaque u32 on the wire; these are its bits.
MATCH_DST_PREFIX = 1 << 0
MATCH_SRC_PREFIX = 1 << 1
MATCH_PROTO = 1 << 2
MATCH_DST_PORT = 1 << 3
MATCH_IS_IP6 = 1 << 15

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


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
