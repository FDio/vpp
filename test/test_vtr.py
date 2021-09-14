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
import random

from scapy.packet import Raw
from scapy.layers.l2 import Ether, Dot1Q
from scapy.layers.inet import IP, UDP

from util import Host
from framework import VppTestCase, VppTestRunner
from vpp_sub_interface import L2_VTR_OP, VppDot1QSubint, VppDot1ADSubint
from collections import namedtuple

Tag = namedtuple('Tag', ['dot1', 'vlan'])
DOT1AD = 0x88A8
DOT1Q = 0x8100


class TestVtr(VppTestCase):
    """ VTR Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestVtr, cls).setUpClass()

        # Test variables
        cls.bd_id = 1
        cls.mac_entries_count = 5
        cls.Atag = 100
        cls.Btag = 200
        cls.dot1ad_sub_id = 20

        try:
            ifs = range(3)
            cls.create_pg_interfaces(ifs)

            cls.sub_interfaces = [
                VppDot1ADSubint(cls, cls.pg1, cls.dot1ad_sub_id,
                                cls.Btag, cls.Atag),
                VppDot1QSubint(cls, cls.pg2, cls.Btag)]

            interfaces = list(cls.pg_interfaces)
            interfaces.extend(cls.sub_interfaces)

            # Create BD with MAC learning enabled and put interfaces and
            #  sub-interfaces to this BD
            for pg_if in cls.pg_interfaces:
                sw_if_index = pg_if.sub_if.sw_if_index \
                    if hasattr(pg_if, 'sub_if') else pg_if.sw_if_index
                cls.vapi.sw_interface_set_l2_bridge(rx_sw_if_index=sw_if_index,
                                                    bd_id=cls.bd_id)

            # setup all interfaces
            for i in interfaces:
                i.admin_up()

            # mapping between packet-generator index and lists of test hosts
            cls.hosts_by_pg_idx = dict()

            # create test host entries and inject packets to learn MAC entries
            # in the bridge-domain
            cls.create_hosts_and_learn(cls.mac_entries_count)
            cls.logger.info(cls.vapi.ppcli("show l2fib"))

        except Exception:
            super(TestVtr, cls).tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        super(TestVtr, cls).tearDownClass()

    def setUp(self):
        """
        Clear trace and packet infos before running each test.
        """
        super(TestVtr, self).setUp()
        self.reset_packet_infos()

    def tearDown(self):
        """
        Show various debug prints after each test.
        """
        super(TestVtr, self).tearDown()

    def show_commands_at_teardown(self):
        self.logger.info(self.vapi.ppcli("show l2fib verbose"))
        self.logger.info(self.vapi.ppcli("show bridge-domain %s detail" %
                                         self.bd_id))

    @classmethod
    def create_hosts_and_learn(cls, count):
        for pg_if in cls.pg_interfaces:
            cls.hosts_by_pg_idx[pg_if.sw_if_index] = []
            hosts = cls.hosts_by_pg_idx[pg_if.sw_if_index]
            packets = []
            for j in range(1, count + 1):
                host = Host(
                    "00:00:00:ff:%02x:%02x" % (pg_if.sw_if_index, j),
                    "172.17.1%02x.%u" % (pg_if.sw_if_index, j))
                packet = (Ether(dst="ff:ff:ff:ff:ff:ff", src=host.mac))
                hosts.append(host)
                if hasattr(pg_if, 'sub_if'):
                    packet = pg_if.sub_if.add_dot1_layer(packet)
                packets.append(packet)
            pg_if.add_stream(packets)
        cls.logger.info("Sending broadcast eth frames for MAC learning")
        cls.pg_enable_capture(cls.pg_interfaces)
        cls.pg_start()

    def create_packet(self, src_if, dst_if, do_dot1=True):
        packet_sizes = [64, 512, 1518, 9018]
        dst_host = random.choice(self.hosts_by_pg_idx[dst_if.sw_if_index])
        src_host = random.choice(self.hosts_by_pg_idx[src_if.sw_if_index])
        pkt_info = self.create_packet_info(src_if, dst_if)
        payload = self.info_to_payload(pkt_info)
        p = (Ether(dst=dst_host.mac, src=src_host.mac) /
             IP(src=src_host.ip4, dst=dst_host.ip4) /
             UDP(sport=1234, dport=1234) /
             Raw(payload))
        pkt_info.data = p.copy()
        if do_dot1 and hasattr(src_if, 'sub_if'):
            p = src_if.sub_if.add_dot1_layer(p)
        size = random.choice(packet_sizes)
        self.extend_packet(p, size)
        return p

    def _add_tag(self, packet, vlan, tag_type):
        payload = packet.payload
        inner_type = packet.type
        packet.remove_payload()
        packet.add_payload(Dot1Q(vlan=vlan) / payload)
        packet.payload.type = inner_type
        packet.payload.vlan = vlan
        packet.type = tag_type
        return packet

    def _remove_tag(self, packet, vlan=None, tag_type=None):
        if tag_type:
            self.assertEqual(packet.type, tag_type)

        payload = packet.payload
        if vlan:
            self.assertEqual(payload.vlan, vlan)
        inner_type = payload.type
        payload = payload.payload
        packet.remove_payload()
        packet.add_payload(payload)
        packet.type = inner_type

    def add_tags(self, packet, tags):
        for t in reversed(tags):
            self._add_tag(packet, t.vlan, t.dot1)

    def remove_tags(self, packet, tags):
        for t in tags:
            self._remove_tag(packet, t.vlan, t.dot1)

    def vtr_test(self, swif, tags):
        p = self.create_packet(swif, self.pg0)
        swif.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = self.pg0.get_capture(1)

        if tags:
            self.remove_tags(rx[0], tags)
        self.assertTrue(Dot1Q not in rx[0])

        if not tags:
            return

        i = VppDot1QSubint(self, self.pg0, tags[0].vlan)
        self.vapi.sw_interface_set_l2_bridge(rx_sw_if_index=i.sw_if_index,
                                             bd_id=self.bd_id, enable=1)
        i.admin_up()

        p = self.create_packet(self.pg0, swif, do_dot1=False)
        self.add_tags(p, tags)
        self.pg0.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = swif.get_capture(1)
        swif.sub_if.remove_dot1_layer(rx[0])
        self.assertTrue(Dot1Q not in rx[0])

        self.vapi.sw_interface_set_l2_bridge(rx_sw_if_index=i.sw_if_index,
                                             bd_id=self.bd_id, enable=0)
        i.remove_vpp_config()

    def test_1ad_vtr_pop_1(self):
        """ 1AD VTR pop 1 test
        """
        self.pg1.sub_if.set_vtr(L2_VTR_OP.L2_POP_1)
        self.vtr_test(self.pg1, [Tag(dot1=DOT1Q, vlan=100)])

    def test_1ad_vtr_pop_2(self):
        """ 1AD VTR pop 2 test
        """
        self.pg1.sub_if.set_vtr(L2_VTR_OP.L2_POP_2)
        self.vtr_test(self.pg1, [])

    def test_1ad_vtr_push_1ad(self):
        """ 1AD VTR push 1 1AD test
        """
        self.pg1.sub_if.set_vtr(L2_VTR_OP.L2_PUSH_1, tag=300)
        self.vtr_test(self.pg1, [Tag(dot1=DOT1AD, vlan=300),
                                 Tag(dot1=DOT1AD, vlan=200),
                                 Tag(dot1=DOT1Q, vlan=100)])

    def test_1ad_vtr_push_2ad(self):
        """ 1AD VTR push 2 1AD test
        """
        self.pg1.sub_if.set_vtr(L2_VTR_OP.L2_PUSH_2, outer=400, inner=300)
        self.vtr_test(self.pg1, [Tag(dot1=DOT1AD, vlan=400),
                                 Tag(dot1=DOT1Q, vlan=300),
                                 Tag(dot1=DOT1AD, vlan=200),
                                 Tag(dot1=DOT1Q, vlan=100)])

    def test_1ad_vtr_push_1q(self):
        """ 1AD VTR push 1 1Q test
        """
        self.pg1.sub_if.set_vtr(L2_VTR_OP.L2_PUSH_1, tag=300, push1q=1)
        self.vtr_test(self.pg1, [Tag(dot1=DOT1Q, vlan=300),
                                 Tag(dot1=DOT1AD, vlan=200),
                                 Tag(dot1=DOT1Q, vlan=100)])

    def test_1ad_vtr_push_2q(self):
        """ 1AD VTR push 2 1Q test
        """
        self.pg1.sub_if.set_vtr(L2_VTR_OP.L2_PUSH_2,
                                outer=400, inner=300, push1q=1)
        self.vtr_test(self.pg1, [Tag(dot1=DOT1Q, vlan=400),
                                 Tag(dot1=DOT1Q, vlan=300),
                                 Tag(dot1=DOT1AD, vlan=200),
                                 Tag(dot1=DOT1Q, vlan=100)])

    def test_1ad_vtr_translate_1_1ad(self):
        """ 1AD VTR translate 1 -> 1 1AD test
        """
        self.pg1.sub_if.set_vtr(L2_VTR_OP.L2_TRANSLATE_1_1, tag=300)
        self.vtr_test(self.pg1, [Tag(dot1=DOT1AD, vlan=300),
                                 Tag(dot1=DOT1Q, vlan=100)])

    def test_1ad_vtr_translate_1_2ad(self):
        """ 1AD VTR translate 1 -> 2 1AD test
        """
        self.pg1.sub_if.set_vtr(
            L2_VTR_OP.L2_TRANSLATE_1_2, inner=300, outer=400)
        self.vtr_test(self.pg1, [Tag(dot1=DOT1AD, vlan=400),
                                 Tag(dot1=DOT1Q, vlan=300),
                                 Tag(dot1=DOT1Q, vlan=100)])

    def test_1ad_vtr_translate_2_1ad(self):
        """ 1AD VTR translate 2 -> 1 1AD test
        """
        self.pg1.sub_if.set_vtr(L2_VTR_OP.L2_TRANSLATE_2_1, tag=300)
        self.vtr_test(self.pg1, [Tag(dot1=DOT1AD, vlan=300)])

    def test_1ad_vtr_translate_2_2ad(self):
        """ 1AD VTR translate 2 -> 2 1AD test
        """
        self.pg1.sub_if.set_vtr(
            L2_VTR_OP.L2_TRANSLATE_2_2, inner=300, outer=400)
        self.vtr_test(self.pg1, [Tag(dot1=DOT1AD, vlan=400),
                                 Tag(dot1=DOT1Q, vlan=300)])

    def test_1ad_vtr_translate_1_1q(self):
        """ 1AD VTR translate 1 -> 1 1Q test
        """
        self.pg1.sub_if.set_vtr(L2_VTR_OP.L2_TRANSLATE_1_1, tag=300, push1q=1)
        self.vtr_test(self.pg1, [Tag(dot1=DOT1Q, vlan=300),
                                 Tag(dot1=DOT1Q, vlan=100)])

    def test_1ad_vtr_translate_1_2q(self):
        """ 1AD VTR translate 1 -> 2 1Q test
        """
        self.pg1.sub_if.set_vtr(
            L2_VTR_OP.L2_TRANSLATE_1_2, inner=300, outer=400, push1q=1)
        self.vtr_test(self.pg1, [Tag(dot1=DOT1Q, vlan=400),
                                 Tag(dot1=DOT1Q, vlan=300),
                                 Tag(dot1=DOT1Q, vlan=100)])

    def test_1ad_vtr_translate_2_1q(self):
        """ 1AD VTR translate 2 -> 1 1Q test
        """
        self.pg1.sub_if.set_vtr(L2_VTR_OP.L2_TRANSLATE_2_1, tag=300, push1q=1)
        self.vtr_test(self.pg1, [Tag(dot1=DOT1Q, vlan=300)])

    def test_1ad_vtr_translate_2_2q(self):
        """ 1AD VTR translate 2 -> 2 1Q test
        """
        self.pg1.sub_if.set_vtr(
            L2_VTR_OP.L2_TRANSLATE_2_2, inner=300, outer=400, push1q=1)
        self.vtr_test(self.pg1, [Tag(dot1=DOT1Q, vlan=400),
                                 Tag(dot1=DOT1Q, vlan=300)])

    def test_1q_vtr_pop_1(self):
        """ 1Q VTR pop 1 test
        """
        self.pg2.sub_if.set_vtr(L2_VTR_OP.L2_POP_1)
        self.vtr_test(self.pg2, [])

    def test_1q_vtr_push_1(self):
        """ 1Q VTR push 1 test
        """
        self.pg2.sub_if.set_vtr(L2_VTR_OP.L2_PUSH_1, tag=300)
        self.vtr_test(self.pg2, [Tag(dot1=DOT1AD, vlan=300),
                                 Tag(dot1=DOT1Q, vlan=200)])

    def test_1q_vtr_push_2(self):
        """ 1Q VTR push 2 test
        """
        self.pg2.sub_if.set_vtr(L2_VTR_OP.L2_PUSH_2, outer=400, inner=300)
        self.vtr_test(self.pg2, [Tag(dot1=DOT1AD, vlan=400),
                                 Tag(dot1=DOT1Q, vlan=300),
                                 Tag(dot1=DOT1Q, vlan=200)])

    def test_1q_vtr_translate_1_1(self):
        """ 1Q VTR translate 1 -> 1 test
        """
        self.pg2.sub_if.set_vtr(L2_VTR_OP.L2_TRANSLATE_1_1, tag=300)
        self.vtr_test(self.pg2, [Tag(dot1=DOT1AD, vlan=300)])

    def test_1q_vtr_translate_1_2(self):
        """ 1Q VTR translate 1 -> 2 test
        """
        self.pg2.sub_if.set_vtr(
            L2_VTR_OP.L2_TRANSLATE_1_2, inner=300, outer=400)
        self.vtr_test(self.pg2, [Tag(dot1=DOT1AD, vlan=400),
                                 Tag(dot1=DOT1Q, vlan=300)])

    def test_if_vtr_disable(self):
        """ Disable VTR on non-sub-interfaces
        """
        # First set the VTR fields to junk
        self.vapi.l2_interface_vlan_tag_rewrite(
            sw_if_index=self.pg0.sw_if_index, vtr_op=L2_VTR_OP.L2_PUSH_2,
            push_dot1q=1, tag1=19, tag2=630)

        if_state = self.vapi.sw_interface_dump(
            sw_if_index=self.pg0.sw_if_index)
        self.assertEqual(if_state[0].sw_if_index, self.pg0.sw_if_index)
        self.assertNotEqual(if_state[0].vtr_op, L2_VTR_OP.L2_DISABLED)

        # Then ensure that a request to disable VTR is honored.
        self.vapi.l2_interface_vlan_tag_rewrite(
            sw_if_index=self.pg0.sw_if_index, vtr_op=L2_VTR_OP.L2_DISABLED)

        if_state = self.vapi.sw_interface_dump(
            sw_if_index=self.pg0.sw_if_index)
        self.assertEqual(if_state[0].sw_if_index, self.pg0.sw_if_index)
        self.assertEqual(if_state[0].vtr_op, L2_VTR_OP.L2_DISABLED)

    def test_if_vtr_push_1q(self):
        """ 1Q VTR push 1 on non-sub-interfaces
        """
        self.vapi.l2_interface_vlan_tag_rewrite(
            sw_if_index=self.pg0.sw_if_index, vtr_op=L2_VTR_OP.L2_PUSH_1,
            push_dot1q=1, tag1=150)

        if_state = self.vapi.sw_interface_dump(
            sw_if_index=self.pg0.sw_if_index)
        self.assertEqual(if_state[0].sw_if_index, self.pg0.sw_if_index)
        self.assertEqual(if_state[0].vtr_op, L2_VTR_OP.L2_PUSH_1)
        self.assertEqual(if_state[0].vtr_tag1, 150)
        self.assertNotEqual(if_state[0].vtr_push_dot1q, 0)

    def test_if_vtr_push_2ad(self):
        """ 1AD VTR push 2 on non-sub-interfaces
        """
        self.vapi.l2_interface_vlan_tag_rewrite(
            sw_if_index=self.pg0.sw_if_index, vtr_op=L2_VTR_OP.L2_PUSH_2,
            push_dot1q=0, tag1=450, tag2=350)

        if_state = self.vapi.sw_interface_dump(
            sw_if_index=self.pg0.sw_if_index)
        self.assertEqual(if_state[0].sw_if_index, self.pg0.sw_if_index)
        self.assertEqual(if_state[0].vtr_op, L2_VTR_OP.L2_PUSH_2)
        self.assertEqual(if_state[0].vtr_tag1, 450)         # outer
        self.assertEqual(if_state[0].vtr_tag2, 350)         # inner
        self.assertEqual(if_state[0].vtr_push_dot1q, 0)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
