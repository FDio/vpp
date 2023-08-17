#!/usr/bin/env python3

import unittest
import ipaddress
from framework import VppTestCase, VppTestRunner

from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.layers.l2 import Ether
from scapy.packet import Raw


class TestNPT66(VppTestCase):
    """NPTv6 Test Case"""

    def setUp(self):
        super(TestNPT66, self).setUp()

        # create 2 pg interfaces
        self.create_pg_interfaces(range(2))

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip6()
            i.resolve_ndp()

    def tearDown(self):
        for i in self.pg_interfaces:
            i.unconfig_ip6()
            i.admin_down()
        super(TestNPT66, self).tearDown()

    def send_and_verify(self, in2out, internal, external):
        if in2out:
            sendif = self.pg0
            recvif = self.pg1
            local_mac = self.pg0.local_mac
            remote_mac = self.pg0.remote_mac
            src = ipaddress.ip_interface(internal).ip + 1
            dst = self.pg1.remote_ip6
        else:
            sendif = self.pg1
            recvif = self.pg0
            local_mac = self.pg1.local_mac
            remote_mac = self.pg1.remote_mac
            src = self.pg1.remote_ip6
            dst = ipaddress.ip_interface(external).ip + 1

        p = (
            Ether(dst=local_mac, src=remote_mac)
            / IPv6(src=src, dst=dst)
            / ICMPv6EchoRequest()
        )
        rxs = self.send_and_expect(sendif, p, recvif)
        for rx in rxs:
            rx.show2()
            original_cksum = rx[ICMPv6EchoRequest].cksum
            del rx[ICMPv6EchoRequest].cksum
            rx = rx.__class__(bytes(rx))
            self.assertEqual(original_cksum, rx[ICMPv6EchoRequest].cksum)

    def do_test(self, internal, external):
        self.vapi.npt66_binding_add_del(
            sw_if_index=self.pg1.sw_if_index,
            internal=internal,
            external=external,
            is_add=True,
        )
        self.vapi.cli(f"ip route add {internal} via {self.pg0.remote_ip6}")

        self.send_and_verify(True, internal, external)
        self.send_and_verify(False, internal, external)

        self.vapi.npt66_binding_add_del(
            sw_if_index=self.pg1.sw_if_index,
            internal=internal,
            external=external,
            is_add=False,
        )

    def test_npt66_simple(self):
        """Send and receive a packet through NPT66"""

        self.do_test("fc00:1::/48", "2001:db8:1::/48")
        self.do_test("fc00:1234::/32", "2001:db8:1::/32")
        self.do_test("fc00:1234::/63", "2001:db8:1::/56")


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
