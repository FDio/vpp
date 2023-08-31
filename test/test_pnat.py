#!/usr/bin/env python3
"""Policy 1:1 NAT functional tests"""

import unittest
from scapy.layers.inet import Ether, IP, UDP, ICMP
from framework import VppTestCase
from asfframework import VppTestRunner
from vpp_papi import VppEnum


class TestPNAT(VppTestCase):
    """PNAT Test Case"""

    maxDiff = None

    @classmethod
    def setUpClass(cls):
        super(TestPNAT, cls).setUpClass()
        cls.create_pg_interfaces(range(2))
        cls.interfaces = list(cls.pg_interfaces)

    @classmethod
    def tearDownClass(cls):
        super(TestPNAT, cls).tearDownClass()

    def setUp(self):
        super(TestPNAT, self).setUp()
        for i in self.interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    def tearDown(self):
        super(TestPNAT, self).tearDown()
        if not self.vpp_dead:
            for i in self.pg_interfaces:
                i.unconfig_ip4()
                i.admin_down()

    def validate(self, rx, expected):
        self.assertEqual(rx, expected.__class__(expected))

    def validate_bytes(self, rx, expected):
        self.assertEqual(rx, expected)

    def ping_check(self):
        """Verify non matching traffic works."""
        p_ether = Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)

        icmpecho = IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) / ICMP()
        reply = IP(src=self.pg0.local_ip4, dst=self.pg0.remote_ip4) / ICMP(
            type="echo-reply"
        )
        rx = self.send_and_expect(self.pg0, p_ether / icmpecho * 1, self.pg0)
        for p in rx:
            reply[IP].id = p[IP].id
            self.validate(p[1], reply)

    def test_pnat(self):
        """PNAT test"""

        PNAT_IP4_INPUT = VppEnum.vl_api_pnat_attachment_point_t.PNAT_IP4_INPUT
        PNAT_IP4_OUTPUT = VppEnum.vl_api_pnat_attachment_point_t.PNAT_IP4_OUTPUT

        tests = [
            {
                "input": PNAT_IP4_INPUT,
                "sw_if_index": self.pg0.sw_if_index,
                "match": {
                    "mask": 0xA,
                    "dst": "10.10.10.10",
                    "proto": 17,
                    "dport": 6871,
                },
                "rewrite": {"mask": 0x2, "dst": self.pg1.remote_ip4},
                "send": (
                    IP(src=self.pg0.remote_ip4, dst="10.10.10.10") / UDP(dport=6871)
                ),
                "reply": (
                    IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4)
                    / UDP(dport=6871)
                ),
            },
            {
                "input": PNAT_IP4_OUTPUT,
                "sw_if_index": self.pg1.sw_if_index,
                "match": {
                    "mask": 0x9,
                    "src": self.pg0.remote_ip4,
                    "proto": 17,
                    "dport": 6871,
                },
                "rewrite": {"mask": 0x1, "src": "11.11.11.11"},
                "send": (
                    IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4)
                    / UDP(dport=6871)
                ),
                "reply": (
                    IP(src="11.11.11.11", dst=self.pg1.remote_ip4) / UDP(dport=6871)
                ),
            },
            {
                "input": PNAT_IP4_INPUT,
                "sw_if_index": self.pg0.sw_if_index,
                "match": {
                    "mask": 0xA,
                    "dst": "10.10.10.10",
                    "proto": 17,
                    "dport": 6871,
                },
                "rewrite": {"mask": 0xA, "dst": self.pg1.remote_ip4, "dport": 5555},
                "send": (
                    IP(src=self.pg0.remote_ip4, dst="10.10.10.10")
                    / UDP(sport=65530, dport=6871)
                ),
                "reply": (
                    IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4)
                    / UDP(sport=65530, dport=5555)
                ),
            },
            {
                "input": PNAT_IP4_INPUT,
                "sw_if_index": self.pg0.sw_if_index,
                "match": {
                    "mask": 0xA,
                    "dst": self.pg1.remote_ip4,
                    "proto": 17,
                    "dport": 6871,
                },
                "rewrite": {"mask": 0x8, "dport": 5555},
                "send": (
                    IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4)
                    / UDP(dport=6871, chksum=0)
                ),
                "reply": (
                    IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4)
                    / UDP(dport=5555, chksum=0)
                ),
            },
            {
                "input": PNAT_IP4_INPUT,
                "sw_if_index": self.pg0.sw_if_index,
                "match": {"mask": 0x2, "dst": self.pg1.remote_ip4, "proto": 1},
                "rewrite": {"mask": 0x1, "src": "8.8.8.8"},
                "send": (IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) / ICMP()),
                "reply": IP(src="8.8.8.8", dst=self.pg1.remote_ip4) / ICMP(),
            },
        ]

        p_ether = Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
        for t in tests:
            rv = self.vapi.pnat_binding_add(match=t["match"], rewrite=t["rewrite"])
            self.vapi.pnat_binding_attach(
                sw_if_index=t["sw_if_index"],
                attachment=t["input"],
                binding_index=rv.binding_index,
            )

            reply = t["reply"]
            reply[IP].ttl -= 1
            rx = self.send_and_expect(self.pg0, p_ether / t["send"] * 1, self.pg1)
            for p in rx:
                # p.show2()
                self.validate(p[1], reply)

            self.ping_check()

            self.vapi.pnat_binding_detach(
                sw_if_index=t["sw_if_index"],
                attachment=t["input"],
                binding_index=rv.binding_index,
            )
            self.vapi.pnat_binding_del(binding_index=rv.binding_index)

    def test_pnat_show(self):
        """PNAT show tests"""

        PNAT_IP4_INPUT = VppEnum.vl_api_pnat_attachment_point_t.PNAT_IP4_INPUT
        PNAT_IP4_OUTPUT = VppEnum.vl_api_pnat_attachment_point_t.PNAT_IP4_OUTPUT

        tests = [
            {
                "input": PNAT_IP4_INPUT,
                "sw_if_index": self.pg0.sw_if_index,
                "match": {
                    "mask": 0xA,
                    "dst": "10.10.10.10",
                    "proto": 17,
                    "dport": 6871,
                },
                "rewrite": {"mask": 0x2, "dst": self.pg1.remote_ip4},
                "send": (
                    IP(src=self.pg0.remote_ip4, dst="10.10.10.10") / UDP(dport=6871)
                ),
                "reply": (
                    IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4)
                    / UDP(dport=6871)
                ),
            },
            {
                "input": PNAT_IP4_OUTPUT,
                "sw_if_index": self.pg1.sw_if_index,
                "match": {
                    "mask": 0x9,
                    "src": self.pg0.remote_ip4,
                    "proto": 17,
                    "dport": 6871,
                },
                "rewrite": {"mask": 0x1, "src": "11.11.11.11"},
                "send": (
                    IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4)
                    / UDP(dport=6871)
                ),
                "reply": (
                    IP(src="11.11.11.11", dst=self.pg1.remote_ip4) / UDP(dport=6871)
                ),
            },
        ]
        binding_index = []
        for t in tests:
            rv = self.vapi.pnat_binding_add(match=t["match"], rewrite=t["rewrite"])
            binding_index.append(rv.binding_index)
            self.vapi.pnat_binding_attach(
                sw_if_index=t["sw_if_index"],
                attachment=t["input"],
                binding_index=rv.binding_index,
            )

        rv, l = self.vapi.pnat_bindings_get()
        self.assertEqual(len(l), len(tests))

        rv, l = self.vapi.pnat_interfaces_get()
        self.assertEqual(len(l), 2)

        self.logger.info(self.vapi.cli("show pnat translations"))
        self.logger.info(self.vapi.cli("show pnat interfaces"))

        for i, t in enumerate(tests):
            self.vapi.pnat_binding_detach(
                sw_if_index=t["sw_if_index"],
                attachment=t["input"],
                binding_index=binding_index[i],
            )
            self.vapi.pnat_binding_del(binding_index=binding_index[i])

    def test_pnat_wildcard_proto(self):
        """
        PNAT test wildcard IP protocol, PNAT_PROTO for mask should be set by
        handler
        """

        PNAT_IP4_INPUT = VppEnum.vl_api_pnat_attachment_point_t.PNAT_IP4_INPUT
        PNAT_IP4_OUTPUT = VppEnum.vl_api_pnat_attachment_point_t.PNAT_IP4_OUTPUT

        tests = [
            {
                "input": PNAT_IP4_INPUT,
                "sw_if_index": self.pg0.sw_if_index,
                "match": {"mask": 0x2, "dst": "10.10.10.10"},
                "rewrite": {"mask": 0x2, "dst": self.pg1.remote_ip4},
                "send": (IP(src=self.pg0.remote_ip4, dst="10.10.10.10")),
                "reply": (IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4)),
            },
            {
                "input": PNAT_IP4_OUTPUT,
                "sw_if_index": self.pg1.sw_if_index,
                "match": {"mask": 0x1, "src": self.pg0.remote_ip4},
                "rewrite": {"mask": 0x1, "src": "11.11.11.11"},
                "send": (IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4)),
                "reply": (IP(src="11.11.11.11", dst=self.pg1.remote_ip4)),
            },
        ]

        p_ether = Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
        for t in tests:
            rv = self.vapi.pnat_binding_add(match=t["match"], rewrite=t["rewrite"])
            self.vapi.pnat_binding_attach(
                sw_if_index=t["sw_if_index"],
                attachment=t["input"],
                binding_index=rv.binding_index,
            )

            reply = t["reply"]
            reply[IP].ttl -= 1
            rx = self.send_and_expect(self.pg0, p_ether / t["send"] * 1, self.pg1)
            for p in rx:
                self.validate(p[1], reply)

            self.ping_check()

            self.vapi.pnat_binding_detach(
                sw_if_index=t["sw_if_index"],
                attachment=t["input"],
                binding_index=rv.binding_index,
            )
            self.vapi.pnat_binding_del(binding_index=rv.binding_index)

    def test_pnat_wildcard_proto_v2(self):
        """PNAT test wildcard IP protocol using pnat_binding_add_v2"""

        PNAT_IP4_INPUT = VppEnum.vl_api_pnat_attachment_point_t.PNAT_IP4_INPUT
        PNAT_IP4_OUTPUT = VppEnum.vl_api_pnat_attachment_point_t.PNAT_IP4_OUTPUT

        tests = [
            {
                "input": PNAT_IP4_INPUT,
                "sw_if_index": self.pg0.sw_if_index,
                "match": {"mask": 0x42, "dst": "10.10.10.10"},
                "rewrite": {"mask": 0x42, "dst": self.pg1.remote_ip4},
                "send": (IP(src=self.pg0.remote_ip4, dst="10.10.10.10")),
                "reply": (IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4)),
            },
            {
                "input": PNAT_IP4_OUTPUT,
                "sw_if_index": self.pg1.sw_if_index,
                "match": {"mask": 0x41, "src": self.pg0.remote_ip4},
                "rewrite": {"mask": 0x41, "src": "11.11.11.11"},
                "send": (IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4)),
                "reply": (IP(src="11.11.11.11", dst=self.pg1.remote_ip4)),
            },
        ]

        p_ether = Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
        for t in tests:
            rv = self.vapi.pnat_binding_add_v2(match=t["match"], rewrite=t["rewrite"])
            self.vapi.pnat_binding_attach(
                sw_if_index=t["sw_if_index"],
                attachment=t["input"],
                binding_index=rv.binding_index,
            )

            reply = t["reply"]
            reply[IP].ttl -= 1
            rx = self.send_and_expect(self.pg0, p_ether / t["send"] * 1, self.pg1)
            for p in rx:
                self.validate(p[1], reply)

            self.ping_check()

            self.vapi.pnat_binding_detach(
                sw_if_index=t["sw_if_index"],
                attachment=t["input"],
                binding_index=rv.binding_index,
            )
            self.vapi.pnat_binding_del(binding_index=rv.binding_index)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
