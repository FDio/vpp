#!/usr/bin/env python3
"""GRO functional tests"""

#
# Add tests for:
# - GRO
# - Verify that sending 1500 Bytes frame without GRO enabled correctly
# - Verify that sending 1500 Bytes frame with GRO enabled correctly
#
import unittest

from scapy.packet import Raw
from scapy.layers.inet6 import IPv6, Ether, IP, UDP, ICMPv6PacketTooBig
from scapy.layers.inet6 import ipv6nh, IPerror6
from scapy.layers.inet import TCP, ICMP
from scapy.data import ETH_P_IP, ETH_P_IPV6, ETH_P_ARP

from framework import VppTestCase, VppTestRunner
from vpp_object import VppObject
from vpp_interface import VppInterface
from socket import AF_INET, AF_INET6, inet_pton


""" Test_gro is a subclass of VPPTestCase classes.
    GRO tests.
"""


class TestGRO(VppTestCase):
    """ GRO Test Case """

    def __init__(self, *args):
        VppTestCase.__init__(self, *args)

    @classmethod
    def setUpClass(self):
        super(TestGRO, self).setUpClass()
        res = self.create_pg_interfaces(range(2))
        res_gro = self.create_pg_interfaces(range(2, 3), 1, 1460, 1)
        self.create_pg_interfaces(range(3, 4), 1, 8940, 1)
        self.pg_interfaces.append(res[0])
        self.pg_interfaces.append(res[1])
        self.pg_interfaces.append(res_gro[0])

    @classmethod
    def tearDownClass(self):
        super(TestGRO, self).tearDownClass()

    def setUp(self):
        super(TestGRO, self).setUp()
        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.config_ip6()
            i.disable_ipv6_ra()
            i.resolve_arp()
            i.resolve_ndp()

    def tearDown(self):
        super(TestGRO, self).tearDown()
        if not self.vpp_dead:
            for i in self.pg_interfaces:
                i.unconfig_ip4()
                i.unconfig_ip6()
                i.admin_down()

    def test_gro(self):
        """ GRO test """

        n_packets = 124
        #
        # Send 1500 bytes frame with gro disabled
        #
        p4 = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
              IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4,
                 flags='DF') /
              TCP(sport=1234, dport=1234) /
              Raw(b'\xa5' * 1460))

        rxs = self.send_and_expect(self.pg0, n_packets * p4, self.pg1)
        i = 0
        for rx in rxs:
            i += 1
            self.assertEqual(rx[Ether].src, self.pg1.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg1.remote_mac)
            self.assertEqual(rx[IP].src, self.pg0.remote_ip4)
            self.assertEqual(rx[IP].dst, self.pg1.remote_ip4)
            self.assertEqual(rx[TCP].sport, 1234)
            self.assertEqual(rx[TCP].dport, 1234)
        self.assertEqual(i, n_packets)

        #
        # Send 1500 bytes frame with gro enabled on
        # output interfaces support GRO
        #
        p = []
        s = 0
        for n in range(0, n_packets):
            p.append((Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
                      IP(src=self.pg0.remote_ip4, dst=self.pg2.remote_ip4,
                         flags='DF') /
                      TCP(sport=1234, dport=1234, seq=s, ack=n, flags='A') /
                      Raw(b'\xa5' * 1460)))
            s += 1460

        rxs = self.send_and_expect(self.pg0, p, self.pg2, n_rx=2)

        i = 0
        for rx in rxs:
            i += 1
            self.assertEqual(rx[Ether].src, self.pg2.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg2.remote_mac)
            self.assertEqual(rx[IP].src, self.pg0.remote_ip4)
            self.assertEqual(rx[IP].dst, self.pg2.remote_ip4)
            self.assertEqual(rx[IP].len, 64280)  # 1460 * 44 + 40 < 65536
            self.assertEqual(rx[TCP].sport, 1234)
            self.assertEqual(rx[TCP].dport, 1234)
            self.assertEqual(rx[TCP].ack, (44*i - 1))

        p4_temp = (Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac) /
                   IP(src=self.pg2.remote_ip4, dst=self.pg0.remote_ip4,
                      flags='DF') /
                   TCP(sport=1234, dport=1234, flags='F'))

        for n in range(1, 99):
            rxs = self.send_and_expect(self.pg2, [p4_temp], self.pg0, n_rx=1)
            self.assertEqual(rxs[0][Ether].src, self.pg0.local_mac)
            self.assertEqual(rxs[0][Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rxs[0][IP].src, self.pg2.remote_ip4)
            self.assertEqual(rxs[0][IP].dst, self.pg0.remote_ip4)
            self.assertEqual(rxs[0][IP].len, 40)
            self.assertEqual(rxs[0][TCP].sport, 1234)
            self.assertEqual(rxs[0][TCP].dport, 1234)

        self.pg_send(self.pg2, [p4_temp])
        rx_coalesce = self.pg2.get_capture(1, timeout=1)
        rxs = self.pg0.get_capture(1, timeout=1)

        rx0 = rx_coalesce[0]
        self.assertEqual(rx0[Ether].src, self.pg2.local_mac)
        self.assertEqual(rx0[Ether].dst, self.pg2.remote_mac)
        self.assertEqual(rx0[IP].src, self.pg0.remote_ip4)
        self.assertEqual(rx0[IP].dst, self.pg2.remote_ip4)
        self.assertEqual(rx0[IP].len, 52600)  # 1460 * 36 + 40
        self.assertEqual(rx0[TCP].sport, 1234)
        self.assertEqual(rx0[TCP].dport, 1234)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[IP].src, self.pg2.remote_ip4)
            self.assertEqual(rx[IP].dst, self.pg0.remote_ip4)
            self.assertEqual(rx[IP].len, 40)
            self.assertEqual(rx[TCP].sport, 1234)
            self.assertEqual(rx[TCP].dport, 1234)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
