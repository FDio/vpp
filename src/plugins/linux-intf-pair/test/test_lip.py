#!/usr/bin/env python

from socket import inet_pton, inet_ntop, AF_INET, AF_INET6
import unittest

from framework import VppTestCase, VppTestRunner
from vpp_neighbor import find_nbr

from scapy.packet import Raw
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6

from vpp_object import VppObject

NUM_PKTS = 67


def find_lip(test, host_sw_if_index):
    lips = test.vapi.lip_dump()
    for lip in lips:
        if host_sw_if_index == lip.pair.host_sw_if_index:
            return True
    return False


class VppLip(VppObject):

    def __init__(self, test, host_itf, phy_itf):
        self._test = test
        self.host_itf = host_itf
        self.phy_itf = phy_itf

    def add_vpp_config(self):
        self._test.vapi.lip_add_del(
            is_add=1,
            pair={'host_sw_if_index': self.host_itf.sw_if_index,
                  'phy_sw_if_index': self.phy_itf.sw_if_index})
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.lip_add_del(
            is_add=0,
            pair={'host_sw_if_index': self.host_itf.sw_if_index,
                  'phy_sw_if_index': self.phy_itf.sw_if_index})

    def query_vpp_config(self):
        return find_lip(self._test, self.host_itf.sw_if_index)

    def object_id(self):
        return ("lip-policy-%d" % self.host_itf.sw_if_index)


class TestLip(VppTestCase):
    """ Linux Interface Pair Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestLip, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestLip, cls).tearDownClass()

    def setUp(self):
        super(TestLip, self).setUp()

        self.create_pg_interfaces(range(4))

        for i in self.pg_interfaces[:2]:
            i.admin_up()
        for i in self.pg_interfaces[2:]:
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
        super(TestLip, self).tearDown()

    def test_lip(self):
        """ Linux Interface Pairing """

        #
        # Generate some hosts on pg2
        #
        self.pg2.generate_remote_hosts(3)

        pair1 = VppLip(self, self.pg0, self.pg2)
        pair1.add_vpp_config()

        pair2 = VppLip(self, self.pg1, self.pg3)
        pair2.add_vpp_config()

        self.logger.info(self.vapi.cli("sh lip"))
        self.logger.info(self.vapi.cli("sh ip punt redirect"))

        #
        # packets from the host are L2 x-connected to the phy
        #
        p1_h2p = (Ether(src=self.pg0.remote_mac,
                        dst=self.pg2.remote_mac) /
                  IP(src="1.1.1.1", dst="1.1.1.2") /
                  TCP(sport=1234, dport=1234) /
                  Raw('\xa5' * 100))
        p2_h2p = (Ether(src=self.pg1.remote_mac,
                        dst=self.pg3.remote_mac) /
                  IP(src="1.1.1.1", dst="1.1.1.2") /
                  TCP(sport=1234, dport=1234) /
                  Raw('\xa5' * 100))

        rxs = self.send_and_expect(self.pg0, p1_h2p*NUM_PKTS, self.pg2)

        for rx in rxs:
            self.assertEqual(rx[Ether].dst, self.pg2.remote_mac)
            self.assertEqual(rx[Ether].src, self.pg0.remote_mac)

        rxs = self.send_and_expect(self.pg1, p2_h2p*NUM_PKTS, self.pg3)

        for rx in rxs:
            self.assertEqual(rx[Ether].dst, self.pg3.remote_mac)
            self.assertEqual(rx[Ether].src, self.pg1.remote_mac)

        #
        # Packets from phy are punted to the host with the original
        # L2 header preserved
        #
        p1_p2h = (Ether(src=self.pg2.remote_mac,
                        dst=self.pg2.local_mac) /
                  IP(src=self.pg2.remote_ip4, dst=self.pg2.local_ip4) /
                  TCP(sport=1234, dport=1234) /
                  Raw('\xa5' * 100))
        p2_p2h = (Ether(src=self.pg3.remote_mac,
                        dst=self.pg3.local_mac) /
                  IP(src=self.pg3.remote_ip4, dst=self.pg3.local_ip4) /
                  TCP(sport=1234, dport=1234) /
                  Raw('\xa5' * 100))

        rxs = self.send_and_expect(self.pg2, p1_p2h*NUM_PKTS, self.pg0)
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg2.remote_mac)
            self.assertEqual(rx[Ether].dst, self.pg2.local_mac)

        rxs = self.send_and_expect(self.pg3, p2_p2h*NUM_PKTS, self.pg1)
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg3.remote_mac)
            self.assertEqual(rx[Ether].dst, self.pg3.local_mac)

        #
        # VPP learns from ARP responses on the phy and
        # they are sent to the host
        #
        p_arp_resp = (Ether(dst=self.pg2.local_mac,
                            src=self.pg2._remote_hosts[1].mac) /
                      ARP(op="is-at",
                          hwdst=self.pg2.local_mac,
                          hwsrc=self.pg2._remote_hosts[1].mac,
                          pdst=self.pg2.local_ip4,
                          psrc=self.pg2._remote_hosts[1].ip4))

        rxs = self.send_and_expect(self.pg2, [p_arp_resp], self.pg0)
        self.assertEqual(len(rxs), 1)
        self.assertEqual(rxs[0][Ether].dst, self.pg2.local_mac)
        self.assertEqual(rxs[0][Ether].src, self.pg2._remote_hosts[1].mac)
        self.assertTrue(rxs[0][ARP])

        self.assertTrue(find_nbr(self, self.pg2.sw_if_index,
                                 self.pg2._remote_hosts[1].ip4))

        #
        # VPP responds to ARP requests and does not send these to the host
        #
        p_arp_req = (Ether(dst="ff:ff:ff:ff:ff:ff",
                           src=self.pg2._remote_hosts[2].mac) /
                     ARP(op="who-has",
                         hwsrc=self.pg2._remote_hosts[2].mac,
                         pdst=self.pg2.local_ip4,
                         psrc=self.pg2._remote_hosts[2].ip4))

        rxs = self.send_and_expect_only(self.pg2, [p_arp_req], self.pg2)

        #
        # packets destined to the all ones address are punted to the host
        #
        p1_all_ones = (Ether(src=self.pg2.remote_mac,
                             dst="ff:ff:ff:ff:ff:ff") /
                       IP(src=self.pg2.remote_ip4,
                          dst="255.255.255.255") /
                       UDP(sport=1234, dport=1234) /
                       Raw('\xa5' * 100))
        rxs = self.send_and_expect(self.pg2, [p1_all_ones], self.pg0)

        #
        # delete one of the pairs, check state has gone
        #
        pair1.remove_vpp_config()

        self.send_and_assert_no_replies(self.pg2, p1_p2h*NUM_PKTS)
        self.send_and_assert_no_replies(self.pg0, p1_h2p*NUM_PKTS)

        #
        # remove the IP address on the phy
        #
        self.pg3.unconfig_ip4()

        # packets sent are now not recieved on the host
        self.send_and_assert_no_replies(self.pg3, p2_p2h*NUM_PKTS)

        # unless it's a DHCP packet
        p2_p2h = (Ether(src=self.pg3.remote_mac,
                        dst=self.pg3.local_mac) /
                  IP(src=self.pg3.remote_ip4, dst=self.pg3.local_ip4) /
                  UDP(sport=67, dport=68) /
                  Raw('\xa5' * 100))
        rxs = self.send_and_expect(self.pg3, p2_p2h*NUM_PKTS, self.pg1)
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg3.remote_mac)
            self.assertEqual(rx[Ether].dst, self.pg3.local_mac)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
