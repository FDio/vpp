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
from vpp_ip_route import VppIpRoute, VppRoutePath, FibPathType
from vpp_l2 import L2_PORT_TYPE
from vpp_sub_interface import L2_VTR_OP, VppDot1QSubint
from vpp_acl import AclRule, VppAcl, VppAclInterface

from scapy.packet import Raw
from scapy.layers.l2 import Ether, Dot1Q
from scapy.layers.inet import IP, UDP
from socket import AF_INET, inet_pton
from ipaddress import IPv4Network

NUM_PKTS = 67


class TestDVR(VppTestCase):
    """ Distributed Virtual Router """

    @classmethod
    def setUpClass(cls):
        super(TestDVR, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestDVR, cls).tearDownClass()

    def setUp(self):
        super(TestDVR, self).setUp()

        self.create_pg_interfaces(range(4))
        self.create_loopback_interfaces(1)

        for i in self.pg_interfaces:
            i.admin_up()

        self.loop0.config_ip4()

    def tearDown(self):
        for i in self.pg_interfaces:
            i.admin_down()
        self.loop0.unconfig_ip4()

        super(TestDVR, self).tearDown()

    def assert_same_mac_addr(self, tx, rx):
        t_eth = tx[Ether]
        for p in rx:
            r_eth = p[Ether]
            self.assertEqual(t_eth.src, r_eth.src)
            self.assertEqual(t_eth.dst, r_eth.dst)

    def assert_has_vlan_tag(self, tag, rx):
        for p in rx:
            r_1q = p[Dot1Q]
            self.assertEqual(tag, r_1q.vlan)

    def assert_has_no_tag(self, rx):
        for p in rx:
            self.assertFalse(p.haslayer(Dot1Q))

    def test_dvr(self):
        """ Distributed Virtual Router """

        #
        # A packet destined to an IP address that is L2 bridged via
        # a non-tag interface
        #
        ip_non_tag_bridged = "10.10.10.10"
        ip_tag_bridged = "10.10.10.11"
        any_src_addr = "1.1.1.1"

        pkt_no_tag = (Ether(src=self.pg0.remote_mac,
                            dst=self.loop0.local_mac) /
                      IP(src=any_src_addr,
                         dst=ip_non_tag_bridged) /
                      UDP(sport=1234, dport=1234) /
                      Raw(b'\xa5' * 100))
        pkt_tag = (Ether(src=self.pg0.remote_mac,
                         dst=self.loop0.local_mac) /
                   IP(src=any_src_addr,
                      dst=ip_tag_bridged) /
                   UDP(sport=1234, dport=1234) /
                   Raw(b'\xa5' * 100))

        #
        # Two sub-interfaces so we can test VLAN tag push/pop
        #
        sub_if_on_pg2 = VppDot1QSubint(self, self.pg2, 92)
        sub_if_on_pg3 = VppDot1QSubint(self, self.pg3, 93)
        sub_if_on_pg2.admin_up()
        sub_if_on_pg3.admin_up()

        #
        # Put all the interfaces into a new bridge domain
        #
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.pg0.sw_if_index, bd_id=1)
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.pg1.sw_if_index, bd_id=1)
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=sub_if_on_pg2.sw_if_index, bd_id=1)
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=sub_if_on_pg3.sw_if_index, bd_id=1)
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.loop0.sw_if_index, bd_id=1,
            port_type=L2_PORT_TYPE.BVI)

        self.vapi.l2_interface_vlan_tag_rewrite(
            sw_if_index=sub_if_on_pg2.sw_if_index, vtr_op=L2_VTR_OP.L2_POP_1,
            push_dot1q=92)
        self.vapi.l2_interface_vlan_tag_rewrite(
            sw_if_index=sub_if_on_pg3.sw_if_index, vtr_op=L2_VTR_OP.L2_POP_1,
            push_dot1q=93)

        #
        # Add routes to bridge the traffic via a tagged an nontagged interface
        #
        route_no_tag = VppIpRoute(
            self, ip_non_tag_bridged, 32,
            [VppRoutePath("0.0.0.0",
                          self.pg1.sw_if_index,
                          type=FibPathType.FIB_PATH_TYPE_DVR)])
        route_no_tag.add_vpp_config()

        #
        # Inject the packet that arrives and leaves on a non-tagged interface
        # Since it's 'bridged' expect that the MAC headed is unchanged.
        #
        rx = self.send_and_expect(self.pg0, pkt_no_tag * NUM_PKTS, self.pg1)
        self.assert_same_mac_addr(pkt_no_tag, rx)
        self.assert_has_no_tag(rx)

        #
        # Add routes to bridge the traffic via a tagged interface
        #
        route_with_tag = VppIpRoute(
            self, ip_tag_bridged, 32,
            [VppRoutePath("0.0.0.0",
                          sub_if_on_pg3.sw_if_index,
                          type=FibPathType.FIB_PATH_TYPE_DVR)])
        route_with_tag.add_vpp_config()

        #
        # Inject the packet that arrives non-tag and leaves on a tagged
        # interface
        #
        rx = self.send_and_expect(self.pg0, pkt_tag * NUM_PKTS, self.pg3)
        self.assert_same_mac_addr(pkt_tag, rx)
        self.assert_has_vlan_tag(93, rx)

        #
        # Tag to tag
        #
        pkt_tag_to_tag = (Ether(src=self.pg2.remote_mac,
                                dst=self.loop0.local_mac) /
                          Dot1Q(vlan=92) /
                          IP(src=any_src_addr,
                             dst=ip_tag_bridged) /
                          UDP(sport=1234, dport=1234) /
                          Raw(b'\xa5' * 100))

        rx = self.send_and_expect(self.pg2,
                                  pkt_tag_to_tag * NUM_PKTS,
                                  self.pg3)
        self.assert_same_mac_addr(pkt_tag_to_tag, rx)
        self.assert_has_vlan_tag(93, rx)

        #
        # Tag to non-Tag
        #
        pkt_tag_to_non_tag = (Ether(src=self.pg2.remote_mac,
                                    dst=self.loop0.local_mac) /
                              Dot1Q(vlan=92) /
                              IP(src=any_src_addr,
                                 dst=ip_non_tag_bridged) /
                              UDP(sport=1234, dport=1234) /
                              Raw(b'\xa5' * 100))

        rx = self.send_and_expect(self.pg2,
                                  pkt_tag_to_non_tag * NUM_PKTS,
                                  self.pg1)
        self.assert_same_mac_addr(pkt_tag_to_tag, rx)
        self.assert_has_no_tag(rx)

        #
        # Add an output L3 ACL that will block the traffic
        #
        rule_1 = AclRule(is_permit=0, proto=17, ports=1234,
                         src_prefix=IPv4Network((any_src_addr, 32)),
                         dst_prefix=IPv4Network((ip_non_tag_bridged, 32)))
        acl = VppAcl(self, rules=[rule_1])
        acl.add_vpp_config()

        #
        # Apply the ACL on the output interface
        #
        acl_if1 = VppAclInterface(self, sw_if_index=self.pg1.sw_if_index,
                                  n_input=0, acls=[acl])
        acl_if1.add_vpp_config()

        #
        # Send packet's that should match the ACL and be dropped
        #
        rx = self.send_and_assert_no_replies(self.pg2,
                                             pkt_tag_to_non_tag * NUM_PKTS)

        #
        # cleanup
        #
        acl_if1.remove_vpp_config()
        acl.remove_vpp_config()

        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.pg0.sw_if_index, bd_id=1, enable=0)
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.pg1.sw_if_index, bd_id=1, enable=0)
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=sub_if_on_pg2.sw_if_index, bd_id=1, enable=0)
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=sub_if_on_pg3.sw_if_index, bd_id=1, enable=0)
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.loop0.sw_if_index, bd_id=1,
            port_type=L2_PORT_TYPE.BVI, enable=0)

        #
        # Do a FIB dump to make sure the paths are correctly reported as DVR
        #
        routes = self.vapi.ip_route_dump(0)

        for r in routes:
            if (ip_tag_bridged == str(r.route.prefix.network_address)):
                self.assertEqual(r.route.paths[0].sw_if_index,
                                 sub_if_on_pg3.sw_if_index)
                self.assertEqual(r.route.paths[0].type,
                                 FibPathType.FIB_PATH_TYPE_DVR)
            if (ip_non_tag_bridged == str(r.route.prefix.network_address)):
                self.assertEqual(r.route.paths[0].sw_if_index,
                                 self.pg1.sw_if_index)
                self.assertEqual(r.route.paths[0].type,
                                 FibPathType.FIB_PATH_TYPE_DVR)

        #
        # the explicit route delete is require so it happens before
        # the sbu-interface delete. subinterface delete is required
        # because that object type does not use the object registry
        #
        route_no_tag.remove_vpp_config()
        route_with_tag.remove_vpp_config()
        sub_if_on_pg3.remove_vpp_config()
        sub_if_on_pg2.remove_vpp_config()


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
