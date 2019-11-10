#!/usr/bin/env python3
"""GSO functional tests"""

#
# Add tests for:
# - GSO
# - Verify that sending Jumbo frame without GSO enabled correctly
# - Verify that sending Jumbo frame with GSO enabled correctly
# - Verify that sending Jumbo frame with GSO enabled only on ingress interface
#
import unittest
from socket import AF_INET, AF_INET6, inet_pton

from scapy.data import ETH_P_ARP, ETH_P_IP, ETH_P_IPV6
from scapy.layers.inet import ICMP, TCP
from scapy.layers.inet6 import (
    IP,
    UDP,
    Ether,
    ICMPv6PacketTooBig,
    IPv6,
)
from scapy.layers.vxlan import VXLAN
from scapy.packet import Raw

from framework import VppTestCase, VppTestRunner
from util import reassemble4
from vpp_interface import VppInterface
from vpp_ip import DpoProto
from vpp_ip_route import (
    FibPathProto,
    VppIpRoute,
    VppRoutePath,
)
from vpp_object import VppObject


""" Test_gso is a subclass of VPPTestCase classes.
    GSO tests.
"""


class TestGSO(VppTestCase):
    """ GSO Test Case """

    def __init__(self, *args):
        VppTestCase.__init__(self, *args)

    @classmethod
    def setUpClass(self):
        super(TestGSO, self).setUpClass()

    @classmethod
    def tearDownClass(self):
        super(TestGSO, self).tearDownClass()

    def setUp(self):
        super(TestGSO, self).setUp()

    def tearDown(self):
        super(TestGSO, self).tearDown()
        if not self.vpp_dead:
            for i in self.pg_interfaces:
                i.unconfig_ip4()
                i.unconfig_ip6()
                i.admin_down()

    def test_gso(self):
        """ GSO test """
        #
        # Send jumbo frame with gso disabled and DF bit is set
        #
        self.create_pg_interfaces(range(2))
        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.config_ip6()
            i.disable_ipv6_ra()
            i.resolve_arp()
            i.resolve_ndp()

        p4 = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
              IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4,
                 flags='DF') /
              TCP(sport=1234, dport=1234) /
              Raw(b'\xa5' * 65200))

        rxs = self.send_and_expect(self.pg0, [p4], self.pg0)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[IP].src, self.pg0.local_ip4)
            self.assertEqual(rx[IP].dst, self.pg0.remote_ip4)
            self.assertEqual(rx[ICMP].type, 3)  # "dest-unreach"
            self.assertEqual(rx[ICMP].code, 4)  # "fragmentation-needed"

        #
        # Send jumbo frame with gso enabled and DF bit is set
        # input and output interfaces support GSO
        #
        self.create_pg_interfaces(range(2, 4), 1, 1460)
        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.config_ip6()
            i.disable_ipv6_ra()
            i.resolve_arp()
            i.resolve_ndp()

        p41 = (Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac) /
               IP(src=self.pg2.remote_ip4, dst=self.pg3.remote_ip4,
                  flags='DF') /
               TCP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 65200))

        rxs = self.send_and_expect(self.pg2, [p41], self.pg3)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg3.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg3.remote_mac)
            self.assertEqual(rx[IP].src, self.pg2.remote_ip4)
            self.assertEqual(rx[IP].dst, self.pg3.remote_ip4)
            self.assertEqual(rx[IP].len, 65240)  # 65200 + 20 (IP) + 20 (TCP)
            self.assertEqual(rx[TCP].sport, 1234)
            self.assertEqual(rx[TCP].dport, 1234)

        #
        # Send jumbo frame with gso enabled only on input interface
        # and DF bit is set. GSO packet will be chunked into gso_size
        # data payload
        #
        self.create_pg_interfaces(range(4, 5))
        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.config_ip6()
            i.disable_ipv6_ra()
            i.resolve_arp()
            i.resolve_ndp()

        self.vapi.feature_gso_enable_disable(self.pg4.sw_if_index)
        p42 = (Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac) /
               IP(src=self.pg2.remote_ip4, dst=self.pg4.remote_ip4,
                  flags='DF') /
               TCP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 65200))

        rxs = self.send_and_expect(self.pg2, [p42], self.pg4, 45)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg4.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg4.remote_mac)
            self.assertEqual(rx[IP].src, self.pg2.remote_ip4)
            self.assertEqual(rx[IP].dst, self.pg4.remote_ip4)
            self.assertEqual(rx[TCP].sport, 1234)
            self.assertEqual(rx[TCP].dport, 1234)

        size = rxs[44][TCP].seq + rxs[44][IP].len - 20 - 20
        self.assertEqual(size, 65200)

        #
        # Send jumbo frame with gso enabled only on input interface
        # and DF bit is unset. GSO packet will be fragmented.
        #
        self.vapi.sw_interface_set_mtu(self.pg1.sw_if_index, [576, 0, 0, 0])

        p43 = (Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac) /
               IP(src=self.pg2.remote_ip4, dst=self.pg1.remote_ip4) /
               TCP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 65200))

        rxs = self.send_and_expect(self.pg2, [p43], self.pg1, 119)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg1.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg1.remote_mac)
            self.assertEqual(rx[IP].src, self.pg2.remote_ip4)
            self.assertEqual(rx[IP].dst, self.pg1.remote_ip4)
            size += rx[IP].len - 20
        size -= 20  # TCP header
        self.assertEqual(size, 65200)

        #
        # Send jumbo frame with gso enabled only on input interface with 9K MTU
        # and DF bit is unset. GSO packet will be fragmented. GSO size will be
        # 8960.
        #
        self.vapi.sw_interface_set_mtu(self.pg1.sw_if_index, [9000, 0, 0, 0])
        self.create_pg_interfaces(range(5, 6), 1, 8960)
        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.config_ip6()
            i.disable_ipv6_ra()
            i.resolve_arp()
            i.resolve_ndp()

        self.vapi.sw_interface_set_mtu(self.pg5.sw_if_index, [9000, 0, 0, 0])
        self.vapi.feature_gso_enable_disable(self.pg1.sw_if_index)
        p44 = (Ether(src=self.pg5.remote_mac, dst=self.pg5.local_mac) /
               IP(src=self.pg5.remote_ip4, dst=self.pg1.remote_ip4) /
               TCP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 65200))

        self.pg1.enable_capture()
        rxs = self.send_and_expect(self.pg5, [p44], self.pg1, 33)
        size = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg1.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg1.remote_mac)
            self.assertEqual(rx[IP].src, self.pg5.remote_ip4)
            self.assertEqual(rx[IP].dst, self.pg1.remote_ip4)
        size = rxs[32][TCP].seq + rxs[32][IP].len - 20 - 20
        self.assertEqual(size, 65200)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
