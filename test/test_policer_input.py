#!/usr/bin/env python3
# Copyright (c) 2021 Graphiant, Inc.
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
import scapy.compat
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from framework import VppTestCase, VppTestRunner
from vpp_papi import VppEnum
from vpp_policer import VppPolicer, PolicerAction

NUM_PKTS = 67


class TestPolicerInput(VppTestCase):
    """ Policer on an input interface """
    vpp_worker_count = 2

    def setUp(self):
        super(TestPolicerInput, self).setUp()

        self.create_pg_interfaces(range(2))
        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

        self.pkt = (Ether(src=self.pg0.remote_mac,
                          dst=self.pg0.local_mac) /
                    IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4) /
                    UDP(sport=1234, dport=1234) /
                    Raw(b'\xa5' * 100))

    def tearDown(self):
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.admin_down()
        super(TestPolicerInput, self).tearDown()

    def test_policer_input(self):
        """ Input Policing """
        pkts = self.pkt * NUM_PKTS

        action_tx = PolicerAction(
            VppEnum.vl_api_sse2_qos_action_type_t.SSE2_QOS_ACTION_API_TRANSMIT,
            0)
        policer = VppPolicer(self, "pol1", 80, 0, 1000, 0,
                             conform_action=action_tx,
                             exceed_action=action_tx,
                             violate_action=action_tx)
        policer.add_vpp_config()

        # Start policing on pg0
        policer.apply_vpp_config(self.pg0.sw_if_index, True)

        rx = self.send_and_expect(self.pg0, pkts, self.pg1, worker=0)
        stats = policer.get_stats()

        # Single rate, 2 colour policer - expect conform, violate but no exceed
        self.assertGreater(stats['conform_packets'], 0)
        self.assertEqual(stats['exceed_packets'], 0)
        self.assertGreater(stats['violate_packets'], 0)

        # Stop policing on pg0
        policer.apply_vpp_config(self.pg0.sw_if_index, False)

        rx = self.send_and_expect(self.pg0, pkts, self.pg1, worker=0)

        statsnew = policer.get_stats()

        # No new packets counted
        self.assertEqual(stats, statsnew)

        policer.remove_vpp_config()

    def test_policer_handoff(self):
        """ Worker thread handoff """
        pkts = self.pkt * NUM_PKTS

        action_tx = PolicerAction(
            VppEnum.vl_api_sse2_qos_action_type_t.SSE2_QOS_ACTION_API_TRANSMIT,
            0)
        policer = VppPolicer(self, "pol2", 80, 0, 1000, 0,
                             conform_action=action_tx,
                             exceed_action=action_tx,
                             violate_action=action_tx)
        policer.add_vpp_config()

        # Bind the policer to worker 1
        policer.bind_vpp_config(1, True)

        # Start policing on pg0
        policer.apply_vpp_config(self.pg0.sw_if_index, True)

        for worker in [0, 1]:
            self.send_and_expect(self.pg0, pkts, self.pg1, worker=worker)
            self.logger.debug(self.vapi.cli("show trace max 100"))

        stats = policer.get_stats()
        stats0 = policer.get_stats(worker=0)
        stats1 = policer.get_stats(worker=1)

        # Worker 1, should have done all the policing
        self.assertEqual(stats, stats1)

        # Worker 0, should have handed everything off
        self.assertEqual(stats0['conform_packets'], 0)
        self.assertEqual(stats0['exceed_packets'], 0)
        self.assertEqual(stats0['violate_packets'], 0)

        # Unbind the policer from worker 1 and repeat
        policer.bind_vpp_config(1, False)
        for worker in [0, 1]:
            self.send_and_expect(self.pg0, pkts, self.pg1, worker=worker)
            self.logger.debug(self.vapi.cli("show trace max 100"))

        # The policer should auto-bind to worker 0 when packets arrive
        stats = policer.get_stats()

        # The 2 workers should now have policed the same amount
        stats = policer.get_stats()
        stats0 = policer.get_stats(worker=0)
        stats1 = policer.get_stats(worker=1)

        self.assertGreater(stats0['conform_packets'], 0)
        self.assertEqual(stats0['exceed_packets'], 0)
        self.assertGreater(stats0['violate_packets'], 0)

        self.assertGreater(stats1['conform_packets'], 0)
        self.assertEqual(stats1['exceed_packets'], 0)
        self.assertGreater(stats1['violate_packets'], 0)

        self.assertEqual(stats0['conform_packets'] + stats1['conform_packets'],
                         stats['conform_packets'])

        self.assertEqual(stats0['violate_packets'] + stats1['violate_packets'],
                         stats['violate_packets'])

        # Stop policing on pg0
        policer.apply_vpp_config(self.pg0.sw_if_index, False)

        policer.remove_vpp_config()

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
