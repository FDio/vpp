#!/usr/bin/env python3

import unittest

from framework import VppTestCase, VppTestRunner

from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Raw


class TestTMC(VppTestCase):
    """ TCP MSS Clamping Test Case """

    def setUp(self):
        super().setUp()

        # create 2 pg interfaces
        self.create_pg_interfaces(range(2))

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()
            i.config_ip6()
            i.resolve_ndp()

    def tearDown(self):
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            # Why is this needed? Tests fail when uncommented
            # i.ip6_disable()
            i.admin_down()
        super().tearDown()

    def test_tcp_mss_clamping(self):
        """ IP4/IP6 TCP MSS Clamping """

        #
        # v4 and v6 TCP packet with the MSS option at 0x400.
        # from a host on pg0 to a host on pg1
        #
        ps = [(Ether(dst=self.pg0.local_mac,
                     src=self.pg0.remote_mac) /
               IP(src=self.pg0.remote_ip4,
                  dst=self.pg1.remote_ip4) /
               TCP(sport=1234, dport=1234,
                   flags="S",
                   options=[('MSS', (0x0400)), ('EOL', None)]) /
               Raw('\xa5' * 100)),
              (Ether(dst=self.pg0.local_mac,
                     src=self.pg0.remote_mac) /
               IPv6(src=self.pg0.remote_ip6,
                    dst=self.pg1.remote_ip6) /
               TCP(sport=1234, dport=1234,
                   flags="S",
                   options=[('MSS', (0x0400)), ('EOL', None)]) /
               Raw('\xa5' * 100))]

        #
        # enable the TCP MSS clamping feature to lower the MSS to 0x300
        # and send the syn packets
        #
        self.vapi.tmc_enable_disable(sw_if_index=self.pg1.sw_if_index,
                                     mss=0x300)

        for p in ps:
            rxs = self.send_and_expect(self.pg0, p * 65, self.pg1)

            #
            # check that the MSS size has been changed to the value
            # configured and the IP and TCP checksums are correct
            #
            for rx in rxs:
                tcp = rx[TCP]
                tcp_csum = tcp.chksum
                del tcp.chksum
                ip_csum = 0
                if (rx.haslayer(IP)):
                    ip_csum = rx[IP].chksum
                    del rx[IP].chksum

                opt = tcp.options
                self.assertEqual(opt[0][0], 'MSS')
                self.assertEqual(opt[0][1], 0x300)
                # recalculate checksums
                rx = rx.__class__(bytes(rx))

                tcp = rx[TCP]
                self.assertEqual(tcp_csum, tcp.chksum)
                if (rx.haslayer(IP)):
                    self.assertEqual(ip_csum, rx[IP].chksum)

        #
        # check the stats
        #
        err = self.statistics.get_counter(
            '/err/tcp-mss-clamping-ip4/clamped')[0]
        self.assertEqual(err, 65)
        err = self.statistics.get_counter(
            '/err/tcp-mss-clamping-ip6/clamped')[0]
        self.assertEqual(err, 65)

        #
        # disable the feature. send the packets again and ensure
        # they are unchanged
        #
        self.vapi.tmc_enable_disable(sw_if_index=self.pg1.sw_if_index, mss=0,
                                     is_enable=0)

        for p in ps:
            rxs = self.send_and_expect(self.pg0, p * 65, self.pg1)

            for rx in rxs:
                tcp = rx[TCP]
                opt = tcp.options
                self.assertEqual(opt[0][0], 'MSS')
                self.assertEqual(opt[0][1], 0x400)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
