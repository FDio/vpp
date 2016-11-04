#!/usr/bin/env python

import unittest
import random

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from logging import *

from framework import VppTestCase, VppTestRunner
from util import TestHost


class TestIpIrb(VppTestCase):
    """ IRB Test Case """


    @classmethod
    def setUpClass(cls):
        super(TestIpIrb, cls).setUpClass()

        cls.bd_id = 10

        # create 3 pg interfaces, 1 loopback interface
        cls.create_pg_interfaces(range(3))
        cls.create_loopback_interfaces(range(1))

        cls.interfaces = list(cls.pg_interfaces)
        cls.interfaces.extend(cls.lo_interfaces)

        for i in cls.interfaces:
            i.admin_up()

        # Create BD with MAC learning enabled and put interfaces to this BD
        cls.vapi.sw_interface_set_l2_bridge(cls.loop0.sw_if_index, bd_id=cls.bd_id, bvi=1)
        cls.vapi.sw_interface_set_l2_bridge(cls.pg0.sw_if_index, bd_id=cls.bd_id)
        cls.vapi.sw_interface_set_l2_bridge(cls.pg1.sw_if_index, bd_id=cls.bd_id)

        cls.loop0.config_ip4()
        cls.pg2.config_ip4()

    def setUp(self):
        super(TestIpIrb, self).setUp()

    def tearDown(self):
        super(TestIpIrb, self).tearDown()
        if not self.vpp_dead:
            info(self.vapi.cli("show l2patch"))
            info(self.vapi.cli("show l2fib verbose"))
            info(self.vapi.cli("show bridge-domain %s detail" % self.bd_id))
            info(self.vapi.cli("show ip arp"))
        # if not self.vpp_dead:

    @unittest.skip('Not finished yet')
    def test_ip4_irb_1(self):
        """ IPv4 IRB test

        Test scenario:
            l2 traffic from pg0 ends in pg1. vice versa
        """
        pass

    @unittest.skip('Not finished yet')
    def test_ip4_irb_2(self):
        """ IPv4 IRB test

        Test scenario:
            ip traffic from pg2 interface must ends in both pg0 and pg1 if arp entry present in loop0 interface
        """
        pass

    @unittest.skip('Not finished yet')
    def test_ip4_irb_3(self):
        """ IPv4 IRB test

        Test scenario:
            ip traffic from pg0 and pg1 ends on pg2
        """
        pass

    @unittest.skip('Not finished yet')
    def test_ip4_irb_4(self):
        """ IPv4 IRB test

        Test scenario:
            mac learned on pg0 and pg1, ip traffic ends only pg0 or pg1.
        """
        pass


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
