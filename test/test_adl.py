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

from framework import VppTestCase, VppTestRunner, running_gcov_tests
from vpp_ip_route import VppIpTable, VppIpRoute, VppRoutePath


class TestAdl(VppTestCase):
    """ Allow/Deny Plugin Unit Test Cases """

    @classmethod
    def setUpClass(cls):
        super(TestAdl, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestAdl, cls).tearDownClass()

    def setUp(self):
        super(TestAdl, self).setUp()

    def tearDown(self):
        super(TestAdl, self).tearDown()

    def test_adl1_unittest(self):
        """ Plugin API Test """
        cmds = ["loop create\n",
                "set int ip address loop0 192.168.1.1/24\n",
                "set int ip6 table loop0 0\n",
                "set int ip address loop0 2001:db01::1/64\n",
                "set int state loop0 up\n",
                "packet-generator new {\n"
                " name ip4\n"
                " limit 100\n"
                " rate 0\n"
                " size 128-128\n"
                " interface loop0\n"
                " node adl-input\n"
                " data { IP4: 1.2.40 -> 3cfd.fed0.b6c8\n"
                "        UDP: 192.168.1.2-192.168.1.10 -> 192.168.2.1\n"
                "        UDP: 1234 -> 2345\n"
                "        incrementing 114\n"
                "       }\n"
                " }\n",
                "packet-generator new {\n"
                " name ip6-allow\n"
                " limit 50\n"
                " rate 0\n"
                " size 128-128\n"
                " interface loop0\n"
                " node adl-input\n"
                " data { IP6: 1.2.40 -> 3cfd.fed0.b6c8\n"
                "        UDP: 2001:db01::2 -> 2001:db01::1\n"
                "        UDP: 1234 -> 2345\n"
                "        incrementing 80\n"
                "      }\n"
                " }\n",
                "packet-generator new {\n"
                " name ip6-drop\n"
                " limit 50\n"
                " rate 0\n"
                " size 128-128\n"
                " interface loop0\n"
                " node adl-input\n"
                " data { IP6: 1.2.40 -> 3cfd.fed0.b6c8\n"
                "        UDP: 2001:db01::3 -> 2001:db01::1\n"
                "        UDP: 1234 -> 2345\n"
                "        incrementing 80\n"
                "      }\n"
                " }\n",
                "ip table 1\n",
                "ip route add 192.168.2.1/32 via drop\n",
                "ip route add table 1 192.168.1.2/32 via local\n",
                "ip6 table 1\n",
                "ip route add 2001:db01::1/128 via drop\n",
                "ip route add table 1 2001:db01::2/128 via local\n",
                "bin adl_interface_enable_disable loop0\n",
                "bin adl_allowlist_enable_disable loop0 fib-id 1 ip4 ip6\n",
                "pa en\n"]

        for cmd in cmds:
            r = self.vapi.cli_return_response(cmd)
            if r.retval != 0:
                if hasattr(r, 'reply'):
                    self.logger.info(cmd + " FAIL reply " + r.reply)
                else:
                    self.logger.info(cmd + " FAIL retval " + str(r.retval))

        total_pkts = self.statistics.get_err_counter(
            "/err/adl-input/Allow/Deny packets processed")

        self.assertEqual(total_pkts, 200)

        ip4_allow = self.statistics.get_err_counter(
            "/err/ip4-adl-allowlist/ip4 allowlist allowed")
        self.assertEqual(ip4_allow, 12)
        ip6_allow = self.statistics.get_err_counter(
            "/err/ip6-adl-allowlist/ip6 allowlist allowed")
        self.assertEqual(ip6_allow, 50)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
