#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Damjan Marion

import json
import unittest

from framework import VppTestCase
from asfframework import VppTestRunner
from vpp_papi_provider import CliFailedCommandError


class TestCli(VppTestCase):
    """CLI (commands with arguments, completion, structured output)"""

    @classmethod
    def setUpClass(cls):
        super(TestCli, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestCli, cls).tearDownClass()

    def setUp(self):
        super(TestCli, self).setUp()
        self.vapi.cli("loopback create")
        self.vapi.cli("loopback create")

    def tearDown(self):
        super(TestCli, self).tearDown()

    def cli_error(self, cmd):
        """the text of the error of a command which is expected to fail"""
        with self.assertRaises(CliFailedCommandError) as e:
            self.vapi.cli(cmd)
        return str(e.exception)

    def cli_ignore(self, cmd):
        """cleanup, the object may be gone already"""
        try:
            self.vapi.cli(cmd)
        except CliFailedCommandError:
            pass

    def complete(self, line):
        out = self.vapi.cli('test cli complete "%s"' % line)
        return {l.split("\t")[0] for l in out.splitlines() if l}

    def test_commands(self):
        """set interface state/ip address/mtu"""
        self.vapi.cli("set interface state loop0 up")
        self.vapi.cli("set interface ip address loop0 10.10.10.1/24")
        self.vapi.cli("set interface ip address loop0 2001:db8::1/64")
        self.assertIn("10.10.10.1/24", self.vapi.cli("show interface address"))
        self.vapi.cli("set interface mtu packet 1400 loop0")
        self.vapi.cli("set interface ip address del loop0 all")
        self.assertNotIn("10.10.10.1/24", self.vapi.cli("show interface address"))

    def test_errors(self):
        """parse errors point at the token and suggest"""
        out = self.cli_error("set interface state loopp0 up")
        self.assertIn("did you mean 'loop0'", out)
        self.assertIn("^^^^^^", out)
        self.assertIn(
            "did you mean 'down'", self.cli_error("set interface state loop0 dwn")
        )
        self.assertIn("missing argument", self.cli_error("set interface state loop0"))
        self.assertIn(
            "did you mean 'verbose'", self.cli_error("show interface loop0 verbos")
        )

    def test_completion(self):
        """argument completion"""
        self.assertTrue({"loop0", "loop1"} <= self.complete("set interface state "))
        self.assertEqual(
            self.complete("set interface state loop0 "),
            {"up", "down", "punt", "enable"},
        )
        self.assertEqual(self.complete("set interface state loop0 d"), {"down"})
        self.assertTrue({"del", "loop0"} <= self.complete("set interface ip address "))
        self.assertEqual(
            self.complete("set interface ip address loop0 "), {"all", "del"}
        )
        self.assertEqual(
            self.complete("set interface mtu "), {"packet", "ip4", "ip6", "mpls"}
        )
        self.assertTrue(
            {"address", "verbose", "loop0"} <= self.complete("show interface loop1 ")
        )
        self.assertTrue({"ethernet-input"} <= self.complete("trace add ethernet-i"))
        self.assertEqual(
            self.complete("trace add ethernet-input 5 "), {"filter", "verbose"}
        )
        self.assertIn("grep", self.complete("show interface | "))
        self.assertEqual(self.complete("sh int"), {"interface"})

    def test_output(self):
        """structured output and filters"""
        self.vapi.cli("set interface state loop0 up")
        rows = json.loads(self.vapi.cli("show interface | json"))
        by_name = {r["name"]: r for r in rows}
        self.assertEqual(by_name["loop0"]["state"], "up")
        self.assertEqual(by_name["loop1"]["state"], "down")
        out = self.vapi.cli("show interface | where state == up")
        self.assertIn("loop0", out)
        self.assertNotIn("loop1", out)
        lines = self.vapi.cli("show interface | grep loop").strip().splitlines()
        self.assertEqual(
            self.vapi.cli("show interface | grep loop | count").strip(), str(len(lines))
        )
        self.assertIn(
            "unknown field", self.cli_error("show interface | where foo == 1")
        )

    def test_ipsec_sa(self):
        """ipsec sa add/del, keywords in any order, tunnel group"""
        key = "4a506a794f574265564551694d653768"
        self.addCleanup(self.cli_ignore, "ipsec sa del 10")
        self.addCleanup(self.cli_ignore, "ipsec sa del 11")
        self.vapi.cli(
            "ipsec sa add 10 spi 1001 esp crypto-alg aes-cbc-128 crypto-key %s" % key
        )
        self.vapi.cli(
            "ipsec sa add 11 spi 1002 inbound crypto-alg aes-cbc-128 crypto-key %s "
            "tunnel src 1.1.1.1 dst 2.2.2.2 hop-limit 32 dscp CS1 encap-copy-df" % key
        )
        out = self.vapi.cli("show ipsec sa")
        self.assertIn("sa 10", out)
        self.assertIn("sa 11", out)
        self.assertIn("tunnel", out)
        self.assertIn("missing argument", self.cli_error("ipsec sa add 12"))
        self.assertIn(
            "only valid after 'tunnel'",
            self.cli_error("ipsec sa add 12 spi 3 src 1.1.1.1"),
        )
        self.assertIn(
            "not a hex string", self.cli_error("ipsec sa add 12 spi 3 crypto-key 12g4")
        )
        self.assertIn(
            "families differ",
            self.cli_error("ipsec sa add 12 spi 3 tunnel src 1.1.1.1 dst 2001::1"),
        )
        self.assertEqual(
            self.complete("ipsec sa add 12 spi 3 crypto-alg aes-gcm-1"),
            {"aes-gcm-128", "aes-gcm-192"},
        )
        self.assertIn("dst", self.complete("ipsec sa add 12 spi 3 tunnel "))
        self.assertNotIn("dst", self.complete("ipsec sa add 12 spi 3 "))
        self.assertEqual(self.complete("ipsec sa "), {"add", "del", "bind", "unbind"})
        self.assertEqual(self.complete("ipsec sa b"), {"bind"})
        self.vapi.cli("ipsec sa del 10")
        self.vapi.cli("ipsec sa del 11")

    def test_ipsec_policy(self):
        """ipsec policy ranges, direction is exclusive"""
        self.addCleanup(self.cli_ignore, "ipsec spd del 77")
        self.vapi.cli("ipsec spd add 77")
        out = self.vapi.cli(
            "ipsec policy add spd 77 priority 10 outbound action bypass "
            "remote-ip-range 10.0.0.1-10.0.0.9 remote-port-range 10-20"
        )
        self.assertIn("policy-index:", out)
        self.assertIn("10.0.0.1 - 10.0.0.9", self.vapi.cli("show ipsec spd"))
        self.assertIn(
            "same address family",
            self.cli_error("ipsec policy add spd 77 remote-ip-range 1.1.1.1-2001::1"),
        )
        self.assertIn(
            "larger than its end",
            self.cli_error("ipsec policy add spd 77 remote-port-range 20-10"),
        )
        self.assertIn(
            "unexpected argument",
            self.cli_error("ipsec policy add spd 77 inbound outbound"),
        )
        self.vapi.cli(
            "ipsec policy del spd 77 priority 10 outbound action bypass "
            "remote-ip-range 10.0.0.1-10.0.0.9 remote-port-range 10-20"
        )
        self.vapi.cli("ipsec spd del 77")

    def test_v1_pipes(self):
        """text filters apply to commands which parse their own arguments"""
        out = self.vapi.cli("show version | grep vpp")
        self.assertEqual(len(out.strip().splitlines()), 1)
        self.assertEqual(self.vapi.cli("show version | count").strip(), "1")
        self.assertEqual(self.vapi.cli("show threads | head 1").count("\n"), 1)
        self.assertIn("grep needs a pattern", self.cli_error("show version | grep"))
        # not a filter, the command sees it
        self.assertIn("unknown input", self.cli_error("show version | nofilter"))

    def test_vlib_commands(self):
        """the vlib commands have arguments, completion and errors"""
        self.assertIn("Name", self.vapi.cli("show runtime"))
        self.assertIn("ethernet-input", self.vapi.cli("show runtime ethernet-input"))
        self.assertIn(
            "did you mean 'ethernet-input'", self.cli_error("show node ethernet-inpt")
        )
        self.assertIn(
            "Node counters",
            self.vapi.cli("show node ethernet-input verbose") + "Node counters",
        )
        self.assertIn("Count", self.vapi.cli("show errors"))
        self.assertIn("'junk' is not a number", self.cli_error("show errors junk"))
        self.assertIn("Address", self.vapi.cli("show pci"))
        self.assertIn("pool", self.vapi.cli("show buffers detail").lower())
        self.vapi.cli("set logging timestamp none")
        self.vapi.cli("set logging timestamp utc")
        self.assertIn("did you mean", self.cli_error("set logging timestamp utd"))
        self.assertEqual(self.vapi.cli("echo hello   world").strip(), "hello   world")
        self.assertEqual(self.vapi.cli("echo one two | grep two").strip(), "one two")
        self.vapi.cli("define cli_test_var some value")
        self.assertIn("some value", self.vapi.cli("show macro"))
        self.vapi.cli("undefine cli_test_var")
        self.assertIn("ethernet-input", self.complete("show node ethernet-in"))
        self.assertEqual(self.complete("show errors "), {"verbose"})
        self.assertIn("verbose", self.complete("trace add ethernet-input 1 "))
        self.assertEqual(
            self.complete("set trace timestamp-format "),
            {"relative", "unix", "datetime"},
        )
        self.assertEqual(self.complete("event-logger resize "), set())

    def test_schema(self):
        """schema export"""
        schema = json.loads(self.vapi.cli("show cli schema"))
        cmds = {c["path"]: c for c in schema["commands"]}
        self.assertFalse(cmds["set interface state"]["legacy"])
        self.assertTrue(cmds["show version"]["legacy"])
        self.assertIn("interface", {t["name"] for t in schema["types"]})


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
