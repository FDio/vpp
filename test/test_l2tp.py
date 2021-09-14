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

from scapy.layers.l2 import Ether
from scapy.layers.inet6 import IPv6

from framework import tag_fixme_vpp_workers
from framework import VppTestCase


@tag_fixme_vpp_workers
class TestL2tp(VppTestCase):
    """ L2TP Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestL2tp, cls).setUpClass()

        cls.create_pg_interfaces(range(1))
        cls.pg0.admin_up()
        cls.pg0.config_ip6()

    def test_l2tp_decap_local(self):
        """ L2TP don't accept packets unless configured """

        pkt = (Ether(dst=self.pg0.local_mac, src=self.pg0.remote_mac) /
               IPv6(src=self.pg0.remote_ip6, dst=self.pg0.local_ip6, nh=115))

        self.pg0.add_stream(pkt)
        self.pg_start()

        # l2tp should not accept packets
        err = self.statistics.get_counter(
            '/err/l2tp-decap-local/l2tpv3 session not found')[0]
        self.assertEqual(err, 0)
        err_count = err

        self.vapi.l2tpv3_create_tunnel(client_address=self.pg0.local_ip6,
                                       our_address=self.pg0.remote_ip6)

        self.pg0.add_stream(pkt)
        self.pg_start()

        # l2tp accepts packets
        err = self.statistics.get_counter(
            '/err/l2tp-decap-local/l2tpv3 session not found')[0]
        self.assertEqual(err, 1)
        err_count = err
