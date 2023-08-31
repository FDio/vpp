#!/usr/bin/env python3

import unittest
import ipaddress
from framework import VppTestCase
from asfframework import VppTestRunner

from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.layers.l2 import Ether


class TestNPT66(VppTestCase):
    """NPTv6 Test Case"""

    extra_vpp_plugin_config = [
        "plugin npt66_plugin.so {enable}",
    ]

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

    def send_and_verify(self, internal):
        sendif = self.pg0
        recvif = self.pg1
        local_mac = self.pg0.local_mac
        remote_mac = self.pg0.remote_mac
        src = ipaddress.ip_interface(internal).ip + 1
        dst = self.pg1.remote_ip6

        p = (
            Ether(dst=local_mac, src=remote_mac)
            / IPv6(src=src, dst=dst)
            / ICMPv6EchoRequest()
            / Raw(b"Request")
        )
        rxs = self.send_and_expect(sendif, p, recvif)
        for rx in rxs:
            original_cksum = rx[ICMPv6EchoRequest].cksum
            del rx[ICMPv6EchoRequest].cksum
            rx = rx.__class__(bytes(rx))
            self.assertEqual(original_cksum, rx[ICMPv6EchoRequest].cksum)

            # Generate a replies
            reply = (
                Ether(dst=rx[Ether].src, src=local_mac)
                / IPv6(src=rx[IPv6].dst, dst=rx[IPv6].src)
                / ICMPv6EchoRequest()
                / Raw(b"Reply")
            )

            replies = self.send_and_expect(recvif, reply, sendif)
            for r in replies:
                self.assertEqual(str(p[IPv6].src), r[IPv6].dst)
                original_cksum = r[ICMPv6EchoRequest].cksum
                del r[ICMPv6EchoRequest].cksum
                r = r.__class__(bytes(r))
                self.assertEqual(original_cksum, r[ICMPv6EchoRequest].cksum)

    def do_test(self, internal, external):
        self.vapi.npt66_binding_add_del(
            sw_if_index=self.pg1.sw_if_index,
            internal=internal,
            external=external,
            is_add=True,
        )
        ## TODO use route api
        self.vapi.cli(f"ip route add {internal} via {self.pg0.remote_ip6}")

        self.send_and_verify(internal)

        self.vapi.npt66_binding_add_del(
            sw_if_index=self.pg1.sw_if_index,
            internal=internal,
            external=external,
            is_add=False,
        )

    def test_npt66_simple(self):
        """Send and receive a packet through NPT66"""

        self.do_test("fd00:0000:0000::/48", "2001:4650:c3ed::/48")
        self.do_test("fc00:1::/48", "2001:db8:1::/48")
        self.do_test("fc00:1234::/32", "2001:db8:1::/32")
        self.do_test("fc00:1234::/63", "2001:db8:1::/56")


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
