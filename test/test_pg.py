#!/usr/bin/env python3

import unittest

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6

from framework import VppTestCase
from asfframework import VppTestRunner


class TestPgTun(VppTestCase):
    """PG Test Case"""

    def setUp(self):
        super(TestPgTun, self).setUp()

        # create 3 pg interfaces - one each ethernet, ip4-tun, ip6-tun.
        self.create_pg_interfaces(range(0, 1))
        self.pg_interfaces += self.create_pg_ip4_interfaces(range(1, 2))
        self.pg_interfaces += self.create_pg_ip6_interfaces(range(2, 3))

        for i in self.pg_interfaces:
            i.admin_up()

        for i in [self.pg0, self.pg1]:
            i.config_ip4()

        for i in [self.pg0, self.pg2]:
            i.config_ip6()

        self.pg0.resolve_arp()
        self.pg0.resolve_ndp()

    def tearDown(self):
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.admin_down()
        super(TestPgTun, self).tearDown()

    def test_pg_tun(self):
        """IP[46] Tunnel Mode PG"""

        #
        # test that we can send and receive IP encap'd packets on the
        # tun interfaces
        #
        N_PKTS = 31

        # v4 tun to ethernet
        p = (
            IP(src=self.pg1.remote_ip4, dst=self.pg0.remote_ip4)
            / UDP(sport=1234, dport=1234)
            / Raw("0" * 48)
        )

        rxs = self.send_and_expect(self.pg1, p * N_PKTS, self.pg0)
        for rx in rxs:
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[IP].dst, self.pg0.remote_ip4)

        # v6 tun to ethernet
        p = (
            IPv6(src=self.pg2.remote_ip6, dst=self.pg0.remote_ip6)
            / UDP(sport=1234, dport=1234)
            / Raw("0" * 48)
        )

        rxs = self.send_and_expect(self.pg2, p * N_PKTS, self.pg0)
        for rx in rxs:
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[IPv6].dst, self.pg0.remote_ip6)

        # eth to v4 tun
        p = (
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4)
            / UDP(sport=1234, dport=1234)
            / Raw("0" * 48)
        )

        rxs = self.send_and_expect(self.pg0, p * N_PKTS, self.pg1)
        for rx in rxs:
            rx = IP(rx)
            self.assertFalse(rx.haslayer(Ether))
            self.assertEqual(rx[IP].dst, self.pg1.remote_ip4)

        # eth to v6 tun
        p = (
            Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac)
            / IPv6(src=self.pg0.remote_ip6, dst=self.pg2.remote_ip6)
            / UDP(sport=1234, dport=1234)
            / Raw("0" * 48)
        )

        rxs = self.send_and_expect(self.pg0, p * N_PKTS, self.pg2)
        for rx in rxs:
            rx = IPv6(rx)
            self.assertFalse(rx.haslayer(Ether))
            self.assertEqual(rx[IPv6].dst, self.pg2.remote_ip6)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
