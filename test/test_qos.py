#!/usr/bin/env python3
# Copyright (c) 2021 Cisco and/or its affiliates.
#
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#
# Licensed under the Apache License 2.0 or
# GNU General Public License v2.0 or later;  you may not use this file
# except in compliance with one of these Licenses. You
# may obtain a copy of the Licenses at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#     https://www.gnu.org/licenses/old-licenses/gpl-2.0-standalone.html
#
# Note: If this file is linked with Scapy, which is GPLv2+, your use of it
# must be under GPLv2+.  If at any point in the future it is no longer linked
# with Scapy (or other GPLv2+ licensed software), you are free to choose
# Apache 2.
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import unittest

from framework import VppTestCase, VppTestRunner
from vpp_sub_interface import VppDot1QSubint
from vpp_ip import DpoProto
from vpp_ip_route import VppIpRoute, VppRoutePath, VppMplsRoute, \
    VppMplsLabel, VppMplsTable, FibPathProto

import scapy.compat
from scapy.packet import Raw
from scapy.layers.l2 import Ether, Dot1Q
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.contrib.mpls import MPLS
from vpp_papi import VppEnum
from vpp_qos import VppQosRecord, VppQosEgressMap, VppQosMark, VppQosStore

NUM_PKTS = 67


class TestQOS(VppTestCase):
    """ QOS Test Case """

    # Note: Since the enums aren't created dynamically until after
    #       the papi client attaches to VPP, we put it in a property to
    #       ensure it is the value at runtime, not at module load time.
    @property
    def QOS_SOURCE(self):
        return VppEnum.vl_api_qos_source_t

    @classmethod
    def setUpClass(cls):
        super(TestQOS, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestQOS, cls).tearDownClass()

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
        """ QoS Mark/Record/Store IP """

        #
        # for table 1 map the n=0xff possible values of input QoS mark,
        # n to 1-n
        #
        output = [scapy.compat.chb(0)] * 256
        for i in range(0, 255):
            output[i] = scapy.compat.chb(255 - i)
        os = b''.join(output)
        rows = [{'outputs': os},
                {'outputs': os},
                {'outputs': os},
                {'outputs': os}]

        qem1 = VppQosEgressMap(self, 1, rows).add_vpp_config()

        #
        # For table 2 (and up) use the value n for everything
        #
        output = [scapy.compat.chb(2)] * 256
        os = b''.join(output)
        rows = [{'outputs': os},
                {'outputs': os},
                {'outputs': os},
                {'outputs': os}]

        qem2 = VppQosEgressMap(self, 2, rows).add_vpp_config()

        output = [scapy.compat.chb(3)] * 256
        os = b''.join(output)
        rows = [{'outputs': os},
                {'outputs': os},
                {'outputs': os},
                {'outputs': os}]

        qem3 = VppQosEgressMap(self, 3, rows).add_vpp_config()

        output = [scapy.compat.chb(4)] * 256
        os = b''.join(output)
        rows = [{'outputs': os},
                {'outputs': os},
                {'outputs': os},
                {'outputs': os}]

        qem4 = VppQosEgressMap(self, 4, rows).add_vpp_config()
        qem5 = VppQosEgressMap(self, 5, rows).add_vpp_config()
        qem6 = VppQosEgressMap(self, 6, rows).add_vpp_config()
        qem7 = VppQosEgressMap(self, 7, rows).add_vpp_config()

        self.assertTrue(qem7.query_vpp_config())
        self.logger.info(self.vapi.cli("sh qos eg map"))

        #
        # Bind interface pgN to table n
        #
        qm1 = VppQosMark(self, self.pg1, qem1,
                         self.QOS_SOURCE.QOS_API_SOURCE_IP).add_vpp_config()
        qm2 = VppQosMark(self, self.pg2, qem2,
                         self.QOS_SOURCE.QOS_API_SOURCE_IP).add_vpp_config()
        qm3 = VppQosMark(self, self.pg3, qem3,
                         self.QOS_SOURCE.QOS_API_SOURCE_IP).add_vpp_config()
        qm4 = VppQosMark(self, self.pg4, qem4,
                         self.QOS_SOURCE.QOS_API_SOURCE_IP).add_vpp_config()
        self.assertTrue(qm3.query_vpp_config())

        self.logger.info(self.vapi.cli("sh qos mark"))

        #
        # packets ingress on Pg0
        #
        p_v4 = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
                IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, tos=1) /
                UDP(sport=1234, dport=1234) /
                Raw(scapy.compat.chb(100) * NUM_PKTS))
        p_v6 = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
                IPv6(src=self.pg0.remote_ip6, dst=self.pg1.remote_ip6,
                     tc=1) /
                UDP(sport=1234, dport=1234) /
                Raw(scapy.compat.chb(100) * NUM_PKTS))

        #
        # Since we have not yet enabled the recording of the input QoS
        # from the input iP header, the egress packet's ToS will be unchanged
        #
        rx = self.send_and_expect(self.pg0, p_v4 * NUM_PKTS, self.pg1)
        for p in rx:
            self.assertEqual(p[IP].tos, 1)
        rx = self.send_and_expect(self.pg0, p_v6 * NUM_PKTS, self.pg1)
        for p in rx:
            self.assertEqual(p[IPv6].tc, 1)

        #
        # Enable QoS recording on IP input for pg0
        #
        qr1 = VppQosRecord(self, self.pg0,
                           self.QOS_SOURCE.QOS_API_SOURCE_IP)
        qr1.add_vpp_config()
        self.logger.info(self.vapi.cli("sh qos record"))

        #
        # send the same packets, this time expect the input TOS of 1
        # to be mapped to pg1's egress value of 254
        #
        rx = self.send_and_expect(self.pg0, p_v4 * NUM_PKTS, self.pg1)
        for p in rx:
            self.assertEqual(p[IP].tos, 254)
        rx = self.send_and_expect(self.pg0, p_v6 * NUM_PKTS, self.pg1)
        for p in rx:
            self.assertEqual(p[IPv6].tc, 254)

        #
        # different input ToS to test the mapping
        #
        p_v4[IP].tos = 127
        rx = self.send_and_expect(self.pg0, p_v4 * NUM_PKTS, self.pg1)
        for p in rx:
            self.assertEqual(p[IP].tos, 128)
        p_v6[IPv6].tc = 127
        rx = self.send_and_expect(self.pg0, p_v6 * NUM_PKTS, self.pg1)
        for p in rx:
            self.assertEqual(p[IPv6].tc, 128)

        p_v4[IP].tos = 254
        rx = self.send_and_expect(self.pg0, p_v4 * NUM_PKTS, self.pg1)
        for p in rx:
            self.assertEqual(p[IP].tos, 1)
        p_v6[IPv6].tc = 254
        rx = self.send_and_expect(self.pg0, p_v6 * NUM_PKTS, self.pg1)
        for p in rx:
            self.assertEqual(p[IPv6].tc, 1)

        #
        # send packets out the other interfaces to test the maps are
        # correctly applied
        #
        p_v4[IP].dst = self.pg2.remote_ip4
        rx = self.send_and_expect(self.pg0, p_v4 * NUM_PKTS, self.pg2)
        for p in rx:
            self.assertEqual(p[IP].tos, 2)

        p_v4[IP].dst = self.pg3.remote_ip4
        rx = self.send_and_expect(self.pg0, p_v4 * NUM_PKTS, self.pg3)
        for p in rx:
            self.assertEqual(p[IP].tos, 3)

        p_v6[IPv6].dst = self.pg3.remote_ip6
        rx = self.send_and_expect(self.pg0, p_v6 * NUM_PKTS, self.pg3)
        for p in rx:
            self.assertEqual(p[IPv6].tc, 3)

        #
        # remove the map on pg2 and pg3, now expect an unchanged IP tos
        #
        qm2.remove_vpp_config()
        qm3.remove_vpp_config()
        self.logger.info(self.vapi.cli("sh qos mark"))

        self.assertFalse(qm3.query_vpp_config())
        self.logger.info(self.vapi.cli("sh int feat pg2"))

        p_v4[IP].dst = self.pg2.remote_ip4
        rx = self.send_and_expect(self.pg0, p_v4 * NUM_PKTS, self.pg2)
        for p in rx:
            self.assertEqual(p[IP].tos, 254)

        p_v4[IP].dst = self.pg3.remote_ip4
        rx = self.send_and_expect(self.pg0, p_v4 * NUM_PKTS, self.pg3)
        for p in rx:
            self.assertEqual(p[IP].tos, 254)

        #
        # still mapping out of pg1
        #
        p_v4[IP].dst = self.pg1.remote_ip4
        rx = self.send_and_expect(self.pg0, p_v4 * NUM_PKTS, self.pg1)
        for p in rx:
            self.assertEqual(p[IP].tos, 1)

        #
        # disable the input recording on pg0
        #
        self.assertTrue(qr1.query_vpp_config())
        qr1.remove_vpp_config()

        #
        # back to an unchanged TOS value
        #
        rx = self.send_and_expect(self.pg0, p_v4 * NUM_PKTS, self.pg1)
        for p in rx:
            self.assertEqual(p[IP].tos, 254)

        #
        # enable QoS stroe instead of record
        #
        qst1 = VppQosStore(self, self.pg0,
                           self.QOS_SOURCE.QOS_API_SOURCE_IP,
                           5).add_vpp_config()
        self.logger.info(self.vapi.cli("sh qos store"))

        p_v4[IP].dst = self.pg1.remote_ip4
        rx = self.send_and_expect(self.pg0, p_v4 * NUM_PKTS, self.pg1)
        for p in rx:
            self.assertEqual(p[IP].tos, 250)

        #
        # disable the input storing on pg0
        #
        self.assertTrue(qst1.query_vpp_config())
        qst1.remove_vpp_config()

        #
        # back to an unchanged TOS value
        #
        rx = self.send_and_expect(self.pg0, p_v4 * NUM_PKTS, self.pg1)
        for p in rx:
            self.assertEqual(p[IP].tos, 254)

        #
        # disable the egress map on pg1 and pg4
        #
        qm1.remove_vpp_config()
        qm4.remove_vpp_config()

        #
        # unchanged Tos on pg1
        #
        rx = self.send_and_expect(self.pg0, p_v4 * NUM_PKTS, self.pg1)
        for p in rx:
            self.assertEqual(p[IP].tos, 254)

    def test_qos_mpls(self):
        """ QoS Mark/Record MPLS """

        #
        # 255 QoS for all input values
        #
        from_ext = 7
        from_ip = 6
        from_mpls = 5
        from_vlan = 4
        output = [scapy.compat.chb(from_ext)] * 256
        os1 = b''.join(output)
        output = [scapy.compat.chb(from_vlan)] * 256
        os2 = b''.join(output)
        output = [scapy.compat.chb(from_mpls)] * 256
        os3 = b''.join(output)
        output = [scapy.compat.chb(from_ip)] * 256
        os4 = b''.join(output)
        rows = [{'outputs': os1},
                {'outputs': os2},
                {'outputs': os3},
                {'outputs': os4}]

        qem1 = VppQosEgressMap(self, 1, rows).add_vpp_config()

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
        qr1 = VppQosRecord(self, self.pg0,
                           self.QOS_SOURCE.QOS_API_SOURCE_IP).add_vpp_config()
        qm1 = VppQosMark(self, self.pg1, qem1,
                         self.QOS_SOURCE.QOS_API_SOURCE_MPLS).add_vpp_config()

        #
        # packet that will get one label added and 3 labels added resp.
        #
        p_1 = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
               IP(src=self.pg0.remote_ip4, dst="10.0.0.1", tos=1) /
               UDP(sport=1234, dport=1234) /
               Raw(scapy.compat.chb(100) * NUM_PKTS))
        p_3 = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
               IP(src=self.pg0.remote_ip4, dst="10.0.0.3", tos=1) /
               UDP(sport=1234, dport=1234) /
               Raw(scapy.compat.chb(100) * NUM_PKTS))

        rx = self.send_and_expect(self.pg0, p_1 * NUM_PKTS, self.pg1)

        #
        # only 3 bits of ToS value in MPLS make sure tos is correct
        # and the label and EOS bit have not been corrupted
        #
        for p in rx:
            self.assertEqual(p[MPLS].cos, from_ip)
            self.assertEqual(p[MPLS].label, 32)
            self.assertEqual(p[MPLS].s, 1)
        rx = self.send_and_expect(self.pg0, p_3 * NUM_PKTS, self.pg1)
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
        qr2 = VppQosRecord(
            self, self.pg0,
            self.QOS_SOURCE.QOS_API_SOURCE_MPLS).add_vpp_config()
        qm2 = VppQosMark(
            self, self.pg1, qem1,
            self.QOS_SOURCE.QOS_API_SOURCE_IP).add_vpp_config()

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
                Raw(scapy.compat.chb(100) * NUM_PKTS))

        rx = self.send_and_expect(self.pg0, p_m1 * NUM_PKTS, self.pg1)
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
                Raw(scapy.compat.chb(100) * NUM_PKTS))

        rx = self.send_and_expect(self.pg0, p_m2 * NUM_PKTS, self.pg1)

        for p in rx:
            self.assertEqual(p[IP].tos, from_mpls)

    def test_qos_vlan(self):
        """QoS mark/record VLAN """

        #
        # QoS for all input values
        #
        output = [scapy.compat.chb(0)] * 256
        for i in range(0, 255):
            output[i] = scapy.compat.chb(255 - i)
        os = b''.join(output)
        rows = [{'outputs': os},
                {'outputs': os},
                {'outputs': os},
                {'outputs': os}]

        qem1 = VppQosEgressMap(self, 1, rows).add_vpp_config()

        sub_if = VppDot1QSubint(self, self.pg0, 11)

        sub_if.admin_up()
        sub_if.config_ip4()
        sub_if.resolve_arp()
        sub_if.config_ip6()
        sub_if.resolve_ndp()

        #
        # enable VLAN QoS recording/marking on the input Pg0 subinterface and
        #
        qr_v = VppQosRecord(
            self, sub_if,
            self.QOS_SOURCE.QOS_API_SOURCE_VLAN).add_vpp_config()
        qm_v = VppQosMark(
            self, sub_if, qem1,
            self.QOS_SOURCE.QOS_API_SOURCE_VLAN).add_vpp_config()

        #
        # IP marking/recording on pg1
        #
        qr_ip = VppQosRecord(
            self, self.pg1,
            self.QOS_SOURCE.QOS_API_SOURCE_IP).add_vpp_config()
        qm_ip = VppQosMark(
            self, self.pg1, qem1,
            self.QOS_SOURCE.QOS_API_SOURCE_IP).add_vpp_config()

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
                                                sub_if.sw_if_index)])
        route_2001_1.add_vpp_config()
        route_2001_2 = VppIpRoute(self, "2001::2", 128,
                                  [VppRoutePath(self.pg1.remote_ip6,
                                                self.pg1.sw_if_index)])
        route_2001_2.add_vpp_config()

        p_v1 = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
                Dot1Q(vlan=11, prio=1) /
                IP(src="1.1.1.1", dst="10.0.0.2", tos=1) /
                UDP(sport=1234, dport=1234) /
                Raw(scapy.compat.chb(100) * NUM_PKTS))

        p_v2 = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
                IP(src="1.1.1.1", dst="10.0.0.1", tos=1) /
                UDP(sport=1234, dport=1234) /
                Raw(scapy.compat.chb(100) * NUM_PKTS))

        p_v3 = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
                Dot1Q(vlan=11, prio=1, id=1) /
                IP(src="1.1.1.1", dst="10.0.0.2", tos=2) /
                UDP(sport=1234, dport=1234) /
                Raw(scapy.compat.chb(100) * NUM_PKTS))

        rx = self.send_and_expect(self.pg1, p_v2 * NUM_PKTS, self.pg0)

        for p in rx:
            self.assertEqual(p[Dot1Q].prio, 7)
            self.assertEqual(p[Dot1Q].id, 0)

        rx = self.send_and_expect(self.pg0, p_v3 * NUM_PKTS, self.pg1)

        for p in rx:
            self.assertEqual(p[IP].tos, 252)

        rx = self.send_and_expect(self.pg0, p_v1 * NUM_PKTS, self.pg1)

        for p in rx:
            self.assertEqual(p[IP].tos, 253)

        p_v1 = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
                Dot1Q(vlan=11, prio=2) /
                IPv6(src="2001::1", dst="2001::2", tc=1) /
                UDP(sport=1234, dport=1234) /
                Raw(scapy.compat.chb(100) * NUM_PKTS))

        p_v2 = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) /
                IPv6(src="3001::1", dst="2001::1", tc=1) /
                UDP(sport=1234, dport=1234) /
                Raw(scapy.compat.chb(100) * NUM_PKTS))

        rx = self.send_and_expect(self.pg1, p_v2 * NUM_PKTS, self.pg0)

        for p in rx:
            self.assertEqual(p[Dot1Q].prio, 7)
            self.assertEqual(p[Dot1Q].id, 0)

        rx = self.send_and_expect(self.pg0, p_v1 * NUM_PKTS, self.pg1)

        for p in rx:
            self.assertEqual(p[IPv6].tc, 251)

        #
        # cleanup
        #
        sub_if.unconfig_ip4()
        sub_if.unconfig_ip6()


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
