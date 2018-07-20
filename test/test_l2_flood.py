#!/usr/bin/env python

import unittest
import socket

from framework import VppTestCase, VppTestRunner
from vpp_ip_route import VppIpRoute, VppRoutePath

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP


class TestL2Flood(VppTestCase):
    """ L2-flood """

    def setUp(self):
        super(TestL2Flood, self).setUp()

        # 12 l2 interface and one l3
        self.create_pg_interfaces(range(13))
        self.create_loopback_interfaces(1)

        for i in self.pg_interfaces:
            i.admin_up()
        for i in self.lo_interfaces:
            i.admin_up()

        self.pg12.config_ip4()
        self.pg12.resolve_arp()
        self.loop0.config_ip4()

    def tearDown(self):
        self.pg12.unconfig_ip4()
        self.loop0.unconfig_ip4()

        for i in self.pg_interfaces:
            i.admin_down()
        for i in self.lo_interfaces:
            i.admin_down()
        super(TestL2Flood, self).tearDown()

    def test_flood(self):
        """ L2 Flood Tests """

        #
        # Create a single bridge Domain
        #
        self.vapi.bridge_domain_add_del(1)

        #
        # add each interface to the BD. 3 interfaces per split horizon group
        #
        for i in self.pg_interfaces[0:4]:
            self.vapi.sw_interface_set_l2_bridge(i.sw_if_index, 1, 0)
        for i in self.pg_interfaces[4:8]:
            self.vapi.sw_interface_set_l2_bridge(i.sw_if_index, 1, 1)
        for i in self.pg_interfaces[8:12]:
            self.vapi.sw_interface_set_l2_bridge(i.sw_if_index, 1, 2)
        for i in self.lo_interfaces:
            self.vapi.sw_interface_set_l2_bridge(i.sw_if_index, 1, 2, bvi=1)

        p = (Ether(dst="ff:ff:ff:ff:ff:ff",
                   src="00:00:de:ad:be:ef") /
             IP(src="10.10.10.10", dst="1.1.1.1") /
             UDP(sport=1234, dport=1234) /
             Raw('\xa5' * 100))

        #
        # input on pg0 expect copies on pg1->11
        # this is in SHG=0 so its flooded to all, expect the pg0 since that's
        # the ingress link
        #
        self.pg0.add_stream(p*65)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        for i in self.pg_interfaces[1:12]:
            rx0 = i.get_capture(65, timeout=1)

        self.logger.error(self.vapi.cli("sh trace"))

        #
        # input on pg4 (SHG=1) expect copies on pg0->3 (SHG=0)
        # and pg8->11 (SHG=2)
        #
        self.pg4.add_stream(p*65)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        for i in self.pg_interfaces[:4]:
            rx0 = i.get_capture(65, timeout=1)
        for i in self.pg_interfaces[8:12]:
            rx0 = i.get_capture(65, timeout=1)
        for i in self.pg_interfaces[4:8]:
            i.assert_nothing_captured(remark="Different SH group")

        #
        # An IP route so the packet that hits the BVI is sent out of pg12
        #
        ip_route = VppIpRoute(self, "1.1.1.1", 32,
                              [VppRoutePath(self.pg12.remote_ip4,
                                            self.pg12.sw_if_index)])
        ip_route.add_vpp_config()

        self.logger.info(self.vapi.cli("sh bridge 1 detail"))

        #
        # input on pg0 expect copies on pg1->12
        # this is in SHG=0 so its flooded to all, expect the pg0 since that's
        # the ingress link
        #
        self.pg0.add_stream(p*65)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        for i in self.pg_interfaces[1:]:
            rx0 = i.get_capture(65, timeout=1)

        #
        # input on pg4 (SHG=1) expect copies on pg0->3 (SHG=0)
        # and pg8->12 (SHG=2)
        #
        self.pg4.add_stream(p*65)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        for i in self.pg_interfaces[:4]:
            rx0 = i.get_capture(65, timeout=1)
        for i in self.pg_interfaces[8:13]:
            rx0 = i.get_capture(65, timeout=1)
        for i in self.pg_interfaces[4:8]:
            i.assert_nothing_captured(remark="Different SH group")

        #
        # cleanup
        #
        for i in self.pg_interfaces[:12]:
            self.vapi.sw_interface_set_l2_bridge(i.sw_if_index, 1, enable=0)
        for i in self.lo_interfaces:
            self.vapi.sw_interface_set_l2_bridge(i.sw_if_index, 1, 2,
                                                 bvi=1, enable=0)

        self.vapi.bridge_domain_add_del(1, is_add=0)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
