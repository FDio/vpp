#!/usr/bin/env python3

import unittest

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.inet6 import IPv6

from framework import VppTestCase
from asfframework import VppTestRunner


class TestPg(VppTestCase):
    """PG Test Case"""

    def __init__(self, *args):
        VppTestCase.__init__(self, *args)

    @classmethod
    def setUpClass(self):
        super(TestPg, self).setUpClass()

    @classmethod
    def tearDownClass(self):
        super(TestPg, self).tearDownClass()

    def setUp(self):
        super(TestPg, self).setUp()
        # create pg interfaces

        # ethernet
        self.create_pg_interfaces(range(0, 1))
        # ip4-tun
        self.pg_interfaces += self.create_pg_ip4_interfaces(range(1, 2))
        # ip6-tun
        self.pg_interfaces += self.create_pg_ip6_interfaces(range(2, 3))
        # ethernet with checksum offload
        self.pg_interfaces += self.create_pg_interfaces(range(3, 4), 1)
        # ethernet with gso offload
        self.pg_interfaces += self.create_pg_interfaces(range(4, 5), 0, 1, 1458)

        for i in self.pg_interfaces:
            i.admin_up()

        for i in [self.pg0, self.pg1, self.pg3, self.pg4]:
            i.config_ip4()

        for i in [self.pg0, self.pg2]:
            i.config_ip6()

        self.pg0.resolve_arp()
        self.pg3.resolve_arp()
        self.pg4.resolve_arp()
        self.pg0.resolve_ndp()

    def tearDown(self):
        super(TestPg, self).tearDown()
        for i in [self.pg0, self.pg1, self.pg3, self.pg4]:
            i.unconfig_ip4()
        for i in [self.pg0, self.pg2]:
            i.unconfig_ip6()
        for i in self.pg_interfaces:
            i.admin_down()

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
            rx = IP(bytes(rx))
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
            rx = IPv6(bytes(rx))
            self.assertFalse(rx.haslayer(Ether))
            self.assertEqual(rx[IPv6].dst, self.pg2.remote_ip6)

    def test_pg_offload(self):
        """PG Interface Offload"""

        N_PKTS = 31

        p03 = (
            Ether(dst=self.pg3.local_mac, src=self.pg3.remote_mac)
            / IP(src=self.pg3.remote_ip4, dst=self.pg0.remote_ip4)
            / UDP(sport=1234, dport=1234, chksum=0)
            / Raw("0" * 48)
        )

        rxs = self.send_and_expect(self.pg3, p03 * N_PKTS, self.pg0)
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assert_ip_checksum_valid(rx)
            self.assert_udp_checksum_valid(rx, ignore_zero_checksum=False)
            self.assertEqual(rx[IP].dst, self.pg0.remote_ip4)

        p04 = (
            Ether(dst=self.pg4.local_mac, src=self.pg4.remote_mac)
            / IP(src=self.pg4.remote_ip4, dst=self.pg3.remote_ip4, flags="DF")
            / TCP(sport=1234, dport=1234)
            / Raw(b"\xa5" * 65200)
        )

        rxs = self.send_and_expect(self.pg4, p04 * N_PKTS, self.pg3)
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg3.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg3.remote_mac)
            self.assertEqual(rx[IP].dst, self.pg3.remote_ip4)

        r = self.vapi.cli_return_response("show errors")
        self.assertTrue(r.retval == 0)
        self.assertTrue(hasattr(r, "reply"))
        rv = r.reply
        outcome = rv.find(
            "31               pg3-tx              gso disabled on itf  -- gso packet    error"
        )
        self.assertNotEqual(outcome, -1)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
