#!/usr/bin/env python

import unittest
import socket
import struct

from framework import VppTestCase, VppTestRunner
from vpp_object import VppObject
from vpp_papi_provider import QOS_SOURCE
from vpp_ip_route import VppIpRoute, VppRoutePath, VppMplsRoute
from vpp_sub_interface import VppSubInterface, VppDot1QSubint

from scapy.packet import Raw
from scapy.layers.l2 import Ether, Dot1Q
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.contrib.mpls import MPLS


class TestQOS(VppTestCase):
    """ QOS Test Case """

    def setUp(self):
        super(TestQOS, self).setUp()

        self.create_pg_interfaces(range(5))

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

        super(TestQOS, self).tearDown()

    def test_qos_ip(self):
        """ QoS Mark IP """

        #
        # for table 1 map the n=0xff possible values of input QoS mark,
        # n to 1-n
        #
        output = [chr(0)] * 256
        for i in range(0, 255):
            output[i] = chr(255 - i)
        os = ''.join(output)
        rows = [{'outputs': os},
                {'outputs': os},
                {'outputs': os},
                {'outputs': os}]

        self.vapi.qos_egress_map_update(1, rows)

        #
        # For table 2 (and up) use the value n for everything
        #
        output = [chr(2)] * 256
        os = ''.join(output)
        rows = [{'outputs': os},
                {'outputs': os},
                {'outputs': os},
                {'outputs': os}]

        self.vapi.qos_egress_map_update(2, rows)

        output = [chr(3)] * 256
        os = ''.join(output)
        rows = [{'outputs': os},
                {'outputs': os},
                {'outputs': os},
                {'outputs': os}]

        self.vapi.qos_egress_map_update(3, rows)

        output = [chr(4)] * 256
        os = ''.join(output)
        rows = [{'outputs': os},
                {'outputs': os},
                {'outputs': os},
                {'outputs': os}]
        self.vapi.qos_egress_map_update(4, rows)
        self.vapi.qos_egress_map_update(5, rows)
        self.vapi.qos_egress_map_update(6, rows)
        self.vapi.qos_egress_map_update(7, rows)

        self.logger.info(self.vapi.cli("sh qos eg map"))

        #
        # Bind interface pgN to table n
        #
        self.vapi.qos_mark_enable_disable(self.pg1.sw_if_index,
                                          QOS_SOURCE.IP,
                                          1,
                                          1)
        self.vapi.qos_mark_enable_disable(self.pg2.sw_if_index,
                                          QOS_SOURCE.IP,
                                          2,
                                          1)
        self.vapi.qos_mark_enable_disable(self.pg3.sw_if_index,
                                          QOS_SOURCE.IP,
                                          3,
                                          1)
        self.vapi.qos_mark_enable_disable(self.pg4.sw_if_index,
                                          QOS_SOURCE.IP,
                                          4,
                                          1)

        #
        # packets ingress on Pg0
        #
        p_v4 = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
                IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, tos=1) /
                UDP(sport=1234, dport=1234) /
                Raw(chr(100) * 65))
        p_v6 = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
                IPv6(src=self.pg0.remote_ip6, dst=self.pg1.remote_ip6,
                     tc=1) /
                UDP(sport=1234, dport=1234) /
                Raw(chr(100) * 65))

        #
        # Since we have not yet enabled the recording of the input QoS
        # from the input iP header, the egress packet's ToS will be unchanged
        #
        rx = self.send_and_expect(self.pg0, p_v4 * 65, self.pg1)
        for p in rx:
            self.assertEqual(p[IP].tos, 1)
        rx = self.send_and_expect(self.pg0, p_v6 * 65, self.pg1)
        for p in rx:
            self.assertEqual(p[IPv6].tc, 1)

        #
        # Enable QoS recrding on IP input for pg0
        #
        self.vapi.qos_record_enable_disable(self.pg0.sw_if_index,
                                            QOS_SOURCE.IP,
                                            1)

        #
        # send the same packets, this time expect the input TOS of 1
        # to be mapped to pg1's egress value of 254
        #
        rx = self.send_and_expect(self.pg0, p_v4 * 65, self.pg1)
        for p in rx:
            self.assertEqual(p[IP].tos, 254)
        rx = self.send_and_expect(self.pg0, p_v6 * 65, self.pg1)
        for p in rx:
            self.assertEqual(p[IPv6].tc, 254)

        #
        # different input ToS to test the mapping
        #
        p_v4[IP].tos = 127
        rx = self.send_and_expect(self.pg0, p_v4 * 65, self.pg1)
        for p in rx:
            self.assertEqual(p[IP].tos, 128)
        p_v6[IPv6].tc = 127
        rx = self.send_and_expect(self.pg0, p_v6 * 65, self.pg1)
        for p in rx:
            self.assertEqual(p[IPv6].tc, 128)

        p_v4[IP].tos = 254
        rx = self.send_and_expect(self.pg0, p_v4 * 65, self.pg1)
        for p in rx:
            self.assertEqual(p[IP].tos, 1)
        p_v6[IPv6].tc = 254
        rx = self.send_and_expect(self.pg0, p_v6 * 65, self.pg1)
        for p in rx:
            self.assertEqual(p[IPv6].tc, 1)

        #
        # send packets out the other interfaces to test the maps are
        # correctly applied
        #
        p_v4[IP].dst = self.pg2.remote_ip4
        rx = self.send_and_expect(self.pg0, p_v4 * 65, self.pg2)
        for p in rx:
            self.assertEqual(p[IP].tos, 2)

        p_v4[IP].dst = self.pg3.remote_ip4
        rx = self.send_and_expect(self.pg0, p_v4 * 65, self.pg3)
        for p in rx:
            self.assertEqual(p[IP].tos, 3)

        p_v6[IPv6].dst = self.pg3.remote_ip6
        rx = self.send_and_expect(self.pg0, p_v6 * 65, self.pg3)
        for p in rx:
            self.assertEqual(p[IPv6].tc, 3)

        #
        # remove the map on pg2 and pg3, now expect an unchanged IP tos
        #
        self.vapi.qos_mark_enable_disable(self.pg2.sw_if_index,
                                          QOS_SOURCE.IP,
                                          2,
                                          0)
        self.vapi.qos_mark_enable_disable(self.pg3.sw_if_index,
                                          QOS_SOURCE.IP,
                                          3,
                                          0)
        self.logger.info(self.vapi.cli("sh int feat pg2"))

        p_v4[IP].dst = self.pg2.remote_ip4
        rx = self.send_and_expect(self.pg0, p_v4 * 65, self.pg2)
        for p in rx:
            self.assertEqual(p[IP].tos, 254)

        p_v4[IP].dst = self.pg3.remote_ip4
        rx = self.send_and_expect(self.pg0, p_v4 * 65, self.pg3)
        for p in rx:
            self.assertEqual(p[IP].tos, 254)

        #
        # still mapping out of pg1
        #
        p_v4[IP].dst = self.pg1.remote_ip4
        rx = self.send_and_expect(self.pg0, p_v4 * 65, self.pg1)
        for p in rx:
            self.assertEqual(p[IP].tos, 1)

        #
        # disable the input recording on pg0
        #
        self.vapi.qos_record_enable_disable(self.pg0.sw_if_index,
                                            QOS_SOURCE.IP,
                                            0)

        #
        # back to an unchanged TOS value
        #
        rx = self.send_and_expect(self.pg0, p_v4 * 65, self.pg1)
        for p in rx:
            self.assertEqual(p[IP].tos, 254)

        #
        # disable the egress map on pg1 and pg4
        #
        self.vapi.qos_mark_enable_disable(self.pg1.sw_if_index,
                                          QOS_SOURCE.IP,
                                          1,
                                          0)
        self.vapi.qos_mark_enable_disable(self.pg4.sw_if_index,
                                          QOS_SOURCE.IP,
                                          4,
                                          0)

        #
        # unchanged Tos on pg1
        #
        rx = self.send_and_expect(self.pg0, p_v4 * 65, self.pg1)
        for p in rx:
            self.assertEqual(p[IP].tos, 254)

        #
        # clean-up the masp
        #
        self.vapi.qos_egress_map_delete(1)
        self.vapi.qos_egress_map_delete(4)
        self.vapi.qos_egress_map_delete(2)
        self.vapi.qos_egress_map_delete(3)
        self.vapi.qos_egress_map_delete(5)
        self.vapi.qos_egress_map_delete(6)
        self.vapi.qos_egress_map_delete(7)

    def test_qos_mpls(self):
        """ QoS Mark MPLS """

        #
        # 255 QoS for all input values
        #
        output = [chr(255)] * 256
        os = ''.join(output)
        rows = [{'outputs': os},
                {'outputs': os},
                {'outputs': os},
                {'outputs': os}]

        self.vapi.qos_egress_map_update(1, rows)

        #
        # a route with 1 MPLS label
        #
        route_10_0_0_1 = VppIpRoute(self, "10.0.0.1", 32,
                                    [VppRoutePath(self.pg1.remote_ip4,
                                                  self.pg1.sw_if_index,
                                                  labels=[32])])
        route_10_0_0_1.add_vpp_config()

        #
        # a route with 3 MPLS labels
        #
        route_10_0_0_3 = VppIpRoute(self, "10.0.0.3", 32,
                                    [VppRoutePath(self.pg1.remote_ip4,
                                                  self.pg1.sw_if_index,
                                                  labels=[63, 33, 34])])
        route_10_0_0_3.add_vpp_config()

        #
        # enable IP QoS recording on the input Pg0 and MPLS egress marking
        # on Pg1
        #
        self.vapi.qos_record_enable_disable(self.pg0.sw_if_index,
                                            QOS_SOURCE.IP,
                                            1)
        self.vapi.qos_mark_enable_disable(self.pg1.sw_if_index,
                                          QOS_SOURCE.MPLS,
                                          1,
                                          1)

        #
        # packet that will get one label added and 3 labels added resp.
        #
        p_1 = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
               IP(src=self.pg0.remote_ip4, dst="10.0.0.1", tos=1) /
               UDP(sport=1234, dport=1234) /
               Raw(chr(100) * 65))
        p_3 = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
               IP(src=self.pg0.remote_ip4, dst="10.0.0.3", tos=1) /
               UDP(sport=1234, dport=1234) /
               Raw(chr(100) * 65))

        rx = self.send_and_expect(self.pg0, p_1 * 65, self.pg1)

        #
        # only 3 bits of ToS value in MPLS make sure tos is correct
        # and the label and EOS bit have not been corrupted
        #
        for p in rx:
            self.assertEqual(p[MPLS].cos, 7)
            self.assertEqual(p[MPLS].label, 32)
            self.assertEqual(p[MPLS].s, 1)
        rx = self.send_and_expect(self.pg0, p_3 * 65, self.pg1)
        for p in rx:
            self.assertEqual(p[MPLS].cos, 7)
            self.assertEqual(p[MPLS].label, 63)
            self.assertEqual(p[MPLS].s, 0)
            h = p[MPLS].payload
            self.assertEqual(h[MPLS].cos, 7)
            self.assertEqual(h[MPLS].label, 33)
            self.assertEqual(h[MPLS].s, 0)
            h = h[MPLS].payload
            self.assertEqual(h[MPLS].cos, 7)
            self.assertEqual(h[MPLS].label, 34)
            self.assertEqual(h[MPLS].s, 1)

        #
        # cleanup
        #
        self.vapi.qos_record_enable_disable(self.pg0.sw_if_index,
                                            QOS_SOURCE.IP,
                                            0)
        self.vapi.qos_mark_enable_disable(self.pg1.sw_if_index,
                                          QOS_SOURCE.MPLS,
                                          1,
                                          0)
        self.vapi.qos_egress_map_delete(1)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
