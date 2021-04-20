#!/usr/bin/env python3
"""NAT44 ED output-feature tests"""

import unittest
from scapy.layers.inet import ICMP, Ether, IP, UDP
from framework import VppTestCase, VppTestRunner
from vpp_ip import DpoProto
from vpp_ip_route import VppIpRoute, VppRoutePath, FibPathProto
from socket import AF_INET, inet_pton
from util import reassemble4
from vpp_papi import VppEnum

def payload(length):
    '''Return payload'''
    return 'x' * length

class TestNAT44EDOutput(VppTestCase):
    """ NAT44 ED output feature Test Case """
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        super(TestNAT44EDOutput, cls).setUpClass()
        cls.create_pg_interfaces(range(2))
        cls.interfaces = list(cls.pg_interfaces)

    @classmethod
    def tearDownClass(cls):
        super(TestNAT44EDOutput, cls).tearDownClass()

    def setUp(self):
        super(TestNAT44EDOutput, self).setUp()
        for i in self.interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    def tearDown(self):
        super(TestNAT44EDOutput, self).tearDown()
        if not self.vpp_dead:
            for i in self.pg_interfaces:
                i.unconfig_ip4()
                i.admin_down()

    def validate(self, rx, expected):
        self.assertEqual(rx, expected.__class__(expected))

    def validate_bytes(self, rx, expected):
        self.assertEqual(rx, expected)

    def test_output_feature(self):
        '''Output feature with interface address'''

        # Verify ping without NAT works
        p_ether = Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
        p_ip4 = IP(src=self.pg1.remote_ip4, dst=self.pg1.local_ip4)
        p4 = p_ether / p_ip4 / ICMP(id=80)

        rx = self.send_and_expect(self.pg1, p4*1, self.pg1)
        self.assertEqual(len(rx), 1)
        print('RX:', rx[0].show2())

        # Configure NAT
        self.vapi.nat44_ed_plugin_enable_disable(
            sessions=1024, enable=1)
        self.vapi.nat44_add_del_interface_addr(
            sw_if_index=self.pg1.sw_if_index, is_add=1)
        self.vapi.nat44_interface_add_del_output_feature(
            sw_if_index=self.pg1.sw_if_index, is_add=1)

        # NAT with id < 1024 doesn't work I guess
        rx = self.send_and_expect(self.pg1, p4*1, self.pg1)
        self.assertEqual(len(rx), 1)
        self.assertEqual(rx[0][ICMP].id, p4[ICMP].id)
        print('RX:', rx[0].show2())
        print('SESSIONS', self.vapi.cli("show nat44 sessions"))

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
