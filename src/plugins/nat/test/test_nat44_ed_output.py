#!/usr/bin/env python3
"""NAT44 ED output-feature tests"""

import unittest
from scapy.layers.inet import ICMP, Ether, IP
from framework import VppTestCase, VppTestRunner


class TestNAT44EDOutput(VppTestCase):
    """ NAT44 ED output feature Test Case """
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.create_pg_interfaces(range(2))
        cls.interfaces = list(cls.pg_interfaces)

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        for i in self.interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()
        self.vapi.nat44_ed_plugin_enable_disable(sessions=1024, enable=1)

    def tearDown(self):
        super().tearDown()
        if not self.vpp_dead:
            for i in self.pg_interfaces:
                i.unconfig_ip4()
                i.admin_down()
            self.vapi.nat44_ed_plugin_enable_disable(enable=0)

    def test_output_feature(self):
        '''Output feature with interface address'''

        # test also IDs below 1024 range, which would normally trigger
        # an undesired translation in i2o direction
        icmp_ids = [60, 600, 6000, 60000]

        # verify ping without NAT works
        pkts = [Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
                IP(src=self.pg1.remote_ip4, dst=self.pg1.local_ip4) /
                ICMP(id=id)
                for id in icmp_ids]

        rx = self.send_and_expect(self.pg1, pkts, self.pg1)

        # Configure NAT
        self.vapi.nat44_add_del_interface_addr(
            sw_if_index=self.pg1.sw_if_index, is_add=1)
        self.vapi.nat44_interface_add_del_output_feature(
            sw_if_index=self.pg1.sw_if_index, is_add=1)

        rx = self.send_and_expect(self.pg1, pkts, self.pg1)
        for (recvd, sent) in zip(rx, pkts):
            self.assertEqual(recvd[ICMP].id, sent[ICMP].id)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
