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
        super(TestTMC, self).setUp()

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
            i.admin_down()
        super(TestTMC, self).tearDown()

    def send_and_verify_pkts(self, src_pg, dst_pg, mss, expected_mss):
        #
        # v4 and v6 TCP packet with the requested MSS option.
        # from a host on src_pg to a host on dst_pg.
        #
        ps = [(Ether(dst=src_pg.local_mac,
                     src=src_pg.remote_mac) /
               IP(src=src_pg.remote_ip4,
                  dst=dst_pg.remote_ip4) /
               TCP(sport=1234, dport=1234,
                   flags="S",
                   options=[('MSS', (mss)), ('EOL', None)]) /
               Raw('\xa5' * 100)),
              (Ether(dst=src_pg.local_mac,
                     src=src_pg.remote_mac) /
               IPv6(src=src_pg.remote_ip6,
                    dst=dst_pg.remote_ip6) /
               TCP(sport=1234, dport=1234,
                   flags="S",
                   options=[('MSS', (mss)), ('EOL', None)]) /
               Raw('\xa5' * 100))]

        for p in ps:
            rxs = self.send_and_expect(src_pg, p * 65, dst_pg)

            #
            # check that the MSS size equals the expected value
            # and the IP and TCP checksums are correct
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
                self.assertEqual(opt[0][1], expected_mss)
                # recalculate checksums
                rx = rx.__class__(bytes(rx))
                tcp = rx[TCP]
                self.assertEqual(tcp_csum, tcp.chksum)
                if (rx.haslayer(IP)):
                    self.assertEqual(ip_csum, rx[IP].chksum)

    def test_tcp_mss_clamping_tx(self):
        """ IP4/IP6 TCP MSS Clamping TX """

        #
        # enable the TCP MSS clamping feature to lower the MSS to 0x300.
        #
        self.vapi.tmc_enable_disable(self.pg1.sw_if_index, 1424, enable=1)

	#
	# Verify that the feature is enabled.
	#
        reply = self.vapi.tmc_get_mss(self.pg1.sw_if_index)
        self.assertEqual(reply.retval, 0)
        self.assertEqual(reply.mss, 1424)

        # Send syn packets and verify that the MSS value is lowered.
        self.send_and_verify_pkts(self.pg0, self.pg1, 1460, 1424)

        #
        # check the stats
        #
        stats = self.statistics.get_counter(
            '/err/tcp-mss-clamping-ip4-out/clamped')
        self.assertEqual(stats[0], 65)
        stats = self.statistics.get_counter(
            '/err/tcp-mss-clamping-ip6-out/clamped')
        self.assertEqual(stats[0], 65)

        #
        # Send syn packets with small enough MSS values and verify they are
        # unchanged.
        #
        self.send_and_verify_pkts(self.pg0, self.pg1, 1400, 1400)

        #
        # disable the feature
        #
        self.vapi.tmc_enable_disable(self.pg1.sw_if_index, 0, enable=0)

        #
        # Send the packets again and ensure they are unchanged.
        #
        self.send_and_verify_pkts(self.pg0, self.pg1, 1460, 1460)

    def test_tcp_mss_clamping_rx(self):
        """ IP4/IP6 TCP MSS Clamping RX """

        #
        # enable the TCP MSS clamping feature to lower the MSS to 0x300.
        #
        self.vapi.tmc_enable_disable(self.pg1.sw_if_index, 1424, enable=1)

	#
	# Verify that the feature is enabled.
	#
        reply = self.vapi.tmc_get_mss(self.pg1.sw_if_index)
        self.assertEqual(reply.retval, 0)
        self.assertEqual(reply.mss, 1424)

        # Send syn packets and verify that the MSS value is lowered.
        self.send_and_verify_pkts(self.pg1, self.pg0, 1460, 1424)

        #
        # check the stats
        #
        stats = self.statistics.get_counter(
            '/err/tcp-mss-clamping-ip4-in/clamped')
        self.assertEqual(stats[0], 65)
        stats = self.statistics.get_counter(
            '/err/tcp-mss-clamping-ip6-in/clamped')
        self.assertEqual(stats[0], 65)

        #
        # Send syn packets with small enough MSS values and verify they are
        # unchanged.
        #
        self.send_and_verify_pkts(self.pg1, self.pg0, 1400, 1400)

        #
        # disable the feature
        #
        self.vapi.tmc_enable_disable(self.pg1.sw_if_index, 0, enable=0)

        #
        # Send the packets again and ensure they are unchanged.
        #
        self.send_and_verify_pkts(self.pg1, self.pg0, 1460, 1460)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
