#!/usr/bin/env python

import unittest

from framework import VppTestCase, VppTestRunner
from vpp_papi_provider import QOS_SOURCE
from vpp_sub_interface import VppDot1QSubint
from vpp_ip import DPO_PROTO
from vpp_ip_route import VppIpRoute, VppRoutePath, VppMplsRoute, \
    VppMplsLabel, VppMplsTable

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

        tbl = VppMplsTable(self, 0)
        tbl.add_vpp_config()

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()
            i.config_ip6()
            i.resolve_ndp()
            i.enable_mpls()

    def tearDown(self):
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.disable_mpls()

        super(TestQOS, self).tearDown()

    def test_qos_ip(self):
        """ QoS Mark/Record IP """

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
        """ QoS Mark/Record MPLS """

        #
        # 255 QoS for all input values
        #
        from_ext = 7
        from_ip = 6
        from_mpls = 5
        from_vlan = 4
        output = [chr(from_ext)] * 256
        os1 = ''.join(output)
        output = [chr(from_vlan)] * 256
        os2 = ''.join(output)
        output = [chr(from_mpls)] * 256
        os3 = ''.join(output)
        output = [chr(from_ip)] * 256
        os4 = ''.join(output)
        rows = [{'outputs': os1},
                {'outputs': os2},
                {'outputs': os3},
                {'outputs': os4}]

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
            self.assertEqual(p[MPLS].cos, from_ip)
            self.assertEqual(p[MPLS].label, 32)
            self.assertEqual(p[MPLS].s, 1)
        rx = self.send_and_expect(self.pg0, p_3 * 65, self.pg1)
        for p in rx:
            self.assertEqual(p[MPLS].cos, from_ip)
            self.assertEqual(p[MPLS].label, 63)
            self.assertEqual(p[MPLS].s, 0)
            h = p[MPLS].payload
            self.assertEqual(h[MPLS].cos, from_ip)
            self.assertEqual(h[MPLS].label, 33)
            self.assertEqual(h[MPLS].s, 0)
            h = h[MPLS].payload
            self.assertEqual(h[MPLS].cos, from_ip)
            self.assertEqual(h[MPLS].label, 34)
            self.assertEqual(h[MPLS].s, 1)

        #
        # enable MPLS QoS recording on the input Pg0 and IP egress marking
        # on Pg1
        #
        self.vapi.qos_record_enable_disable(self.pg0.sw_if_index,
                                            QOS_SOURCE.MPLS,
                                            1)
        self.vapi.qos_mark_enable_disable(self.pg1.sw_if_index,
                                          QOS_SOURCE.IP,
                                          1,
                                          1)

        #
        # MPLS x-connect - COS according to pg1 map
        #
        route_32_eos = VppMplsRoute(self, 32, 1,
                                    [VppRoutePath(self.pg1.remote_ip4,
                                                  self.pg1.sw_if_index,
                                                  labels=[VppMplsLabel(33)])])
        route_32_eos.add_vpp_config()

        p_m1 = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
                MPLS(label=32, cos=3, ttl=2) /
                IP(src=self.pg0.remote_ip4, dst="10.0.0.1", tos=1) /
                UDP(sport=1234, dport=1234) /
                Raw(chr(100) * 65))

        rx = self.send_and_expect(self.pg0, p_m1 * 65, self.pg1)
        for p in rx:
            self.assertEqual(p[MPLS].cos, from_mpls)
            self.assertEqual(p[MPLS].label, 33)
            self.assertEqual(p[MPLS].s, 1)

        #
        # MPLS deag - COS is copied from MPLS to IP
        #
        route_33_eos = VppMplsRoute(self, 33, 1,
                                    [VppRoutePath("0.0.0.0",
                                                  0xffffffff,
                                                  nh_table_id=0)])
        route_33_eos.add_vpp_config()

        route_10_0_0_4 = VppIpRoute(self, "10.0.0.4", 32,
                                    [VppRoutePath(self.pg1.remote_ip4,
                                                  self.pg1.sw_if_index)])
        route_10_0_0_4.add_vpp_config()

        p_m2 = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
                MPLS(label=33, ttl=2, cos=3) /
                IP(src=self.pg0.remote_ip4, dst="10.0.0.4", tos=1) /
                UDP(sport=1234, dport=1234) /
                Raw(chr(100) * 65))

        rx = self.send_and_expect(self.pg0, p_m2 * 65, self.pg1)

        for p in rx:
            self.assertEqual(p[IP].tos, from_mpls)

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
        self.vapi.qos_record_enable_disable(self.pg0.sw_if_index,
                                            QOS_SOURCE.MPLS,
                                            0)
        self.vapi.qos_mark_enable_disable(self.pg1.sw_if_index,
                                          QOS_SOURCE.IP,
                                          1,
                                          0)
        self.vapi.qos_egress_map_delete(1)

    def test_qos_vlan(self):
        """QoS mark/record VLAN """

        #
        # QoS for all input values
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

        sub_if = VppDot1QSubint(self, self.pg0, 11)

        sub_if.admin_up()
        sub_if.config_ip4()
        sub_if.resolve_arp()
        sub_if.config_ip6()
        sub_if.resolve_ndp()

        #
        # enable VLAN QoS recording/marking on the input Pg0 subinterface and
        #
        self.vapi.qos_record_enable_disable(sub_if.sw_if_index,
                                            QOS_SOURCE.VLAN,
                                            1)
        self.vapi.qos_mark_enable_disable(sub_if.sw_if_index,
                                          QOS_SOURCE.VLAN,
                                          1,
                                          1)

        #
        # IP marking/recording on pg1
        #
        self.vapi.qos_record_enable_disable(self.pg1.sw_if_index,
                                            QOS_SOURCE.IP,
                                            1)
        self.vapi.qos_mark_enable_disable(self.pg1.sw_if_index,
                                          QOS_SOURCE.IP,
                                          1,
                                          1)

        #
        # a routes to/from sub-interface
        #
        route_10_0_0_1 = VppIpRoute(self, "10.0.0.1", 32,
                                    [VppRoutePath(sub_if.remote_ip4,
                                                  sub_if.sw_if_index)])
        route_10_0_0_1.add_vpp_config()
        route_10_0_0_2 = VppIpRoute(self, "10.0.0.2", 32,
                                    [VppRoutePath(self.pg1.remote_ip4,
                                                  self.pg1.sw_if_index)])
        route_10_0_0_2.add_vpp_config()
        route_2001_1 = VppIpRoute(self, "2001::1", 128,
                                  [VppRoutePath(sub_if.remote_ip6,
                                                sub_if.sw_if_index,
                                                proto=DPO_PROTO.IP6)],
                                  is_ip6=1)
        route_2001_1.add_vpp_config()
        route_2001_2 = VppIpRoute(self, "2001::2", 128,
                                  [VppRoutePath(self.pg1.remote_ip6,
                                                self.pg1.sw_if_index,
                                                proto=DPO_PROTO.IP6)],
                                  is_ip6=1)
        route_2001_2.add_vpp_config()

        p_v1 = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
                Dot1Q(vlan=11, prio=1) /
                IP(src="1.1.1.1", dst="10.0.0.2", tos=1) /
                UDP(sport=1234, dport=1234) /
                Raw(chr(100) * 65))

        p_v2 = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
                IP(src="1.1.1.1", dst="10.0.0.1", tos=1) /
                UDP(sport=1234, dport=1234) /
                Raw(chr(100) * 65))

        rx = self.send_and_expect(self.pg1, p_v2 * 65, self.pg0)

        for p in rx:
            self.assertEqual(p[Dot1Q].prio, 6)

        rx = self.send_and_expect(self.pg0, p_v1 * 65, self.pg1)

        for p in rx:
            self.assertEqual(p[IP].tos, 254)

        p_v1 = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
                Dot1Q(vlan=11, prio=2) /
                IPv6(src="2001::1", dst="2001::2", tc=1) /
                UDP(sport=1234, dport=1234) /
                Raw(chr(100) * 65))

        p_v2 = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
                IPv6(src="3001::1", dst="2001::1", tc=1) /
                UDP(sport=1234, dport=1234) /
                Raw(chr(100) * 65))

        rx = self.send_and_expect(self.pg1, p_v2 * 65, self.pg0)

        for p in rx:
            self.assertEqual(p[Dot1Q].prio, 6)

        rx = self.send_and_expect(self.pg0, p_v1 * 65, self.pg1)

        for p in rx:
            self.assertEqual(p[IPv6].tc, 253)

        #
        # cleanup
        #
        sub_if.unconfig_ip4()
        sub_if.unconfig_ip6()

        self.vapi.qos_record_enable_disable(sub_if.sw_if_index,
                                            QOS_SOURCE.VLAN,
                                            0)
        self.vapi.qos_mark_enable_disable(sub_if.sw_if_index,
                                          QOS_SOURCE.VLAN,
                                          1,
                                          0)
        self.vapi.qos_record_enable_disable(self.pg1.sw_if_index,
                                            QOS_SOURCE.IP,
                                            0)
        self.vapi.qos_mark_enable_disable(self.pg1.sw_if_index,
                                          QOS_SOURCE.IP,
                                          1,
                                          0)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
