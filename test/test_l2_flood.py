#!/usr/bin/env python3

import unittest
import socket

from framework import VppTestCase, VppTestRunner
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_l2 import L2_PORT_TYPE, BRIDGE_FLAGS

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP

NUM_PKTS = 67


class TestL2Flood(VppTestCase):
    """ L2-flood """

    @classmethod
    def setUpClass(cls):
        super(TestL2Flood, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestL2Flood, cls).tearDownClass()

    def setUp(self):
        super(TestL2Flood, self).setUp()

        # 12 l2 interface and one l3
        self.create_pg_interfaces(range(13))
        self.create_bvi_interfaces(1)

        for i in self.pg_interfaces:
            i.admin_up()
        for i in self.bvi_interfaces:
            i.admin_up()

        self.pg12.config_ip4()
        self.pg12.resolve_arp()
        self.bvi0.config_ip4()

    def tearDown(self):
        self.pg12.unconfig_ip4()
        self.bvi0.unconfig_ip4()

        for i in self.pg_interfaces:
            i.admin_down()
        for i in self.bvi_interfaces:
            i.admin_down()
        super(TestL2Flood, self).tearDown()

    def test_flood(self):
        """ L2 Flood Tests """

        #
        # Create a single bridge Domain
        #
        self.vapi.bridge_domain_add_del(bd_id=1)

        #
        # add each interface to the BD. 3 interfaces per split horizon group
        #
        for i in self.pg_interfaces[0:4]:
            self.vapi.sw_interface_set_l2_bridge(rx_sw_if_index=i.sw_if_index,
                                                 bd_id=1, shg=0)
        for i in self.pg_interfaces[4:8]:
            self.vapi.sw_interface_set_l2_bridge(rx_sw_if_index=i.sw_if_index,
                                                 bd_id=1, shg=1)
        for i in self.pg_interfaces[8:12]:
            self.vapi.sw_interface_set_l2_bridge(rx_sw_if_index=i.sw_if_index,
                                                 bd_id=1, shg=2)
        for i in self.bvi_interfaces:
            self.vapi.sw_interface_set_l2_bridge(rx_sw_if_index=i.sw_if_index,
                                                 bd_id=1, shg=2,
                                                 port_type=L2_PORT_TYPE.BVI)

        p = (Ether(dst="ff:ff:ff:ff:ff:ff",
                   src="00:00:de:ad:be:ef") /
             IP(src="10.10.10.10", dst="1.1.1.1") /
             UDP(sport=1234, dport=1234) /
             Raw(b'\xa5' * 100))

        #
        # input on pg0 expect copies on pg1->11
        # this is in SHG=0 so its flooded to all, expect the pg0 since that's
        # the ingress link
        #
        self.pg0.add_stream(p*NUM_PKTS)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        for i in self.pg_interfaces[1:12]:
            rx0 = i.get_capture(NUM_PKTS, timeout=1)

        #
        # input on pg4 (SHG=1) expect copies on pg0->3 (SHG=0)
        # and pg8->11 (SHG=2)
        #
        self.pg4.add_stream(p*NUM_PKTS)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        for i in self.pg_interfaces[:4]:
            rx0 = i.get_capture(NUM_PKTS, timeout=1)
        for i in self.pg_interfaces[8:12]:
            rx0 = i.get_capture(NUM_PKTS, timeout=1)
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
        self.pg0.add_stream(p*NUM_PKTS)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        for i in self.pg_interfaces[1:]:
            rx0 = i.get_capture(NUM_PKTS, timeout=1)

        #
        # input on pg4 (SHG=1) expect copies on pg0->3 (SHG=0)
        # and pg8->12 (SHG=2)
        #
        self.pg4.add_stream(p*NUM_PKTS)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        for i in self.pg_interfaces[:4]:
            rx0 = i.get_capture(NUM_PKTS, timeout=1)
        for i in self.pg_interfaces[8:13]:
            rx0 = i.get_capture(NUM_PKTS, timeout=1)
        for i in self.pg_interfaces[4:8]:
            i.assert_nothing_captured(remark="Different SH group")

        #
        # cleanup
        #
        for i in self.pg_interfaces[:12]:
            self.vapi.sw_interface_set_l2_bridge(rx_sw_if_index=i.sw_if_index,
                                                 bd_id=1, enable=0)
        for i in self.bvi_interfaces:
            self.vapi.sw_interface_set_l2_bridge(rx_sw_if_index=i.sw_if_index,
                                                 bd_id=1, shg=2,
                                                 port_type=L2_PORT_TYPE.BVI,
                                                 enable=0)

        self.vapi.bridge_domain_add_del(bd_id=1, is_add=0)

    def test_flood_one(self):
        """ L2 no-Flood Test """

        #
        # Create a single bridge Domain
        #
        self.vapi.bridge_domain_add_del(bd_id=1)

        #
        # add 2 interfaces to the BD. this means a flood goes to only
        # one member
        #
        for i in self.pg_interfaces[:2]:
            self.vapi.sw_interface_set_l2_bridge(rx_sw_if_index=i.sw_if_index,
                                                 bd_id=1, shg=0)

        p = (Ether(dst="ff:ff:ff:ff:ff:ff",
                   src="00:00:de:ad:be:ef") /
             IP(src="10.10.10.10", dst="1.1.1.1") /
             UDP(sport=1234, dport=1234) /
             Raw(b'\xa5' * 100))

        #
        # input on pg0 expect copies on pg1
        #
        self.send_and_expect(self.pg0, p*NUM_PKTS, self.pg1)

        #
        # cleanup
        #
        for i in self.pg_interfaces[:2]:
            self.vapi.sw_interface_set_l2_bridge(rx_sw_if_index=i.sw_if_index,
                                                 bd_id=1, enable=0)
        self.vapi.bridge_domain_add_del(bd_id=1, is_add=0)

    def test_uu_fwd(self):
        """ UU Flood """

        #
        # Create a single bridge Domain
        #
        self.vapi.bridge_domain_add_del(bd_id=1, uu_flood=1)

        #
        # add each interface to the BD. 3 interfaces per split horizon group
        #
        for i in self.pg_interfaces[0:4]:
            self.vapi.sw_interface_set_l2_bridge(rx_sw_if_index=i.sw_if_index,
                                                 bd_id=1, shg=0)

        #
        # an unknown unicast and broadcast packets
        #
        p_uu = (Ether(dst="00:00:00:c1:5c:00",
                      src="00:00:de:ad:be:ef") /
                IP(src="10.10.10.10", dst="1.1.1.1") /
                UDP(sport=1234, dport=1234) /
                Raw(b'\xa5' * 100))
        p_bm = (Ether(dst="ff:ff:ff:ff:ff:ff",
                      src="00:00:de:ad:be:ef") /
                IP(src="10.10.10.10", dst="1.1.1.1") /
                UDP(sport=1234, dport=1234) /
                Raw(b'\xa5' * 100))

        #
        # input on pg0, expected copies on pg1->4
        #
        self.pg0.add_stream(p_uu*NUM_PKTS)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        for i in self.pg_interfaces[1:4]:
            rx0 = i.get_capture(NUM_PKTS, timeout=1)

        self.pg0.add_stream(p_bm*NUM_PKTS)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        for i in self.pg_interfaces[1:4]:
            rx0 = i.get_capture(NUM_PKTS, timeout=1)

        #
        # use pg8 as the uu-fwd interface
        #
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.pg8.sw_if_index, bd_id=1, shg=0,
            port_type=L2_PORT_TYPE.UU_FWD)

        #
        # expect the UU packet on the uu-fwd interface and not be flooded
        #
        self.pg0.add_stream(p_uu*NUM_PKTS)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx0 = self.pg8.get_capture(NUM_PKTS, timeout=1)

        for i in self.pg_interfaces[0:4]:
            i.assert_nothing_captured(remark="UU not flooded")

        self.pg0.add_stream(p_bm*NUM_PKTS)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        for i in self.pg_interfaces[1:4]:
            rx0 = i.get_capture(NUM_PKTS, timeout=1)

        #
        # remove the uu-fwd interface and expect UU to be flooded again
        #
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.pg8.sw_if_index, bd_id=1, shg=0,
            port_type=L2_PORT_TYPE.UU_FWD, enable=0)

        self.pg0.add_stream(p_uu*NUM_PKTS)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        for i in self.pg_interfaces[1:4]:
            rx0 = i.get_capture(NUM_PKTS, timeout=1)

        #
        # change the BD config to not support UU-flood
        #
        self.vapi.bridge_flags(bd_id=1, is_set=0, flags=BRIDGE_FLAGS.UU_FLOOD)

        self.send_and_assert_no_replies(self.pg0, p_uu)

        #
        # re-add the uu-fwd interface
        #
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.pg8.sw_if_index, bd_id=1, shg=0,
            port_type=L2_PORT_TYPE.UU_FWD)
        self.logger.info(self.vapi.cli("sh bridge 1 detail"))

        self.pg0.add_stream(p_uu*NUM_PKTS)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx0 = self.pg8.get_capture(NUM_PKTS, timeout=1)

        for i in self.pg_interfaces[0:4]:
            i.assert_nothing_captured(remark="UU not flooded")

        #
        # remove the uu-fwd interface
        #
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.pg8.sw_if_index, bd_id=1, shg=0,
            port_type=L2_PORT_TYPE.UU_FWD, enable=0)
        self.send_and_assert_no_replies(self.pg0, p_uu)

        #
        # cleanup
        #
        for i in self.pg_interfaces[:4]:
            self.vapi.sw_interface_set_l2_bridge(rx_sw_if_index=i.sw_if_index,
                                                 bd_id=1, enable=0)

        self.vapi.bridge_domain_add_del(bd_id=1, is_add=0)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
