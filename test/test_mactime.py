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


class TestMactime(VppTestCase):
    """ Mactime Unit Test Cases """

    @classmethod
    def setUpClass(cls):
        super(TestMactime, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestMactime, cls).tearDownClass()

    def setUp(self):
        super(TestMactime, self).setUp()

    def tearDown(self):
        super(TestMactime, self).tearDown()

    def test_mactime_range_unittest(self):
        """ Time Range Test """
        error = self.vapi.cli("test time-range")

        if error:
            self.logger.critical(error)
        self.assertNotIn('FAILED', error)

    @unittest.skipUnless(running_gcov_tests, "part of code coverage tests")
    def test_mactime_unittest(self):
        """ Mactime Plugin Code Coverage Test """
        cmds = ["loopback create",
                "mactime enable-disable disable",
                "mactime enable-disable loop0",
                "mactime enable-disable loop0 disable",
                "mactime enable-disable sw_if_index 9999",
                "bin mactime_enable_disable loop0",
                "bin mactime_enable_disable loop0 disable",
                "bin mactime_enable_disable sw_if_index 1",
                "set interface state loop0 up",
                "clear mactime",
                "set ip neighbor loop0 192.168.1.1 00:d0:2d:5e:86:85",
                "bin mactime_add_del_range name sallow "
                "mac 00:d0:2d:5e:86:85 allow-static del",
                "bin mactime_add_del_range name sallow "
                "mac 00:d0:2d:5e:86:85 allow-static",
                "bin mactime_add_del_range name sallow "
                "mac 00:d0:2d:5e:86:85 allow-static del",
                "bin mactime_add_del_range name sallow "
                "mac 00:d0:2d:5e:86:85 allow-static",
                "bin mactime_add_del_range name sblock "
                "mac 01:00:5e:7f:ff:fa drop-static",
                "bin mactime_add_del_range name ddrop "
                "mac c8:bc:c8:5a:ba:f3 drop-range Sun - Sat "
                "00:00 - 23:59",
                "bin mactime_add_del_range name dallow "
                "mac c8:bc:c8:5a:ba:f4 allow-range Sun - Sat "
                "00:00 - 23:59",
                "bin mactime_add_del_range name multi "
                "mac c8:bc:c8:f0:f0:f0 allow-range Sun - Mon "
                "00:00 - 23:59 Tue - Sat 00:00 - 23:59",
                "bin mactime_add_del_range bogus",
                "bin mactime_add_del_range mac 01:00:5e:7f:f0:f0 allow-static",
                "bin mactime_add_del_range "
                "name tooloooooooooooooooooooooooooooooooooooooooooooooooo"
                "nnnnnnnnnnnnnnnnnnnnnnnnnnnng mac 00:00:de:ad:be:ef "
                "allow-static",
                "packet-generator new {\n"
                " name allow\n"
                " limit 15\n"
                " size 128-128\n"
                " interface loop0\n"
                " node ethernet-input\n"
                " data {\n"
                "   IP6: 00:d0:2d:5e:86:85 -> 00:0d:ea:d0:00:00\n"
                "   ICMP: db00::1 -> db00::2\n"
                "   incrementing 30\n"
                "   }\n",
                "}\n",
                "packet-generator new {\n"
                " name deny\n"
                " limit 15\n"
                " size 128-128\n"
                " interface loop0\n"
                " node ethernet-input\n"
                " data {\n"
                "   IP6: 01:00:5e:7f:ff:fa -> 00:0d:ea:d0:00:00\n"
                "   ICMP: db00::1 -> db00::2\n"
                "   incrementing 30\n"
                "   }\n",
                "}\n",
                "packet-generator new {\n"
                " name ddrop\n"
                " limit 15\n"
                " size 128-128\n"
                " interface loop0\n"
                " node ethernet-input\n"
                " data {\n"
                "   IP6: c8:bc:c8:5a:ba:f3 -> 00:0d:ea:d0:00:00\n"
                "   ICMP: db00::1 -> db00::2\n"
                "   incrementing 30\n"
                "   }\n",
                "}\n",
                "packet-generator new {\n"
                " name dallow\n"
                " limit 15\n"
                " size 128-128\n"
                " interface loop0\n"
                " node ethernet-input\n"
                " data {\n"
                "   IP6: c8:bc:c8:5a:ba:f4 -> 00:0d:ea:d0:00:00\n"
                "   ICMP: db00::1 -> db00::2\n"
                "   incrementing 30\n"
                "   }\n"
                "}\n"
                "packet-generator new {\n"
                " name makeentry\n"
                " limit 15\n"
                " size 128-128\n"
                " interface loop0\n"
                " node ethernet-input\n"
                " data {\n"
                "   IP6: c8:bc:c8:5a:b0:0b -> 00:0d:ea:d0:00:00\n"
                "   ICMP: db00::1 -> db00::2\n"
                "   incrementing 30\n"
                "   }\n"
                "}\n"
                "packet-generator new {\n"
                " name tx\n"
                " limit 15\n"
                " size 128-128\n"
                " interface local0\n"
                " tx-interface loop0\n"
                " node loop0-output\n"
                " data {\n"
                "   hex 0x01005e7ffffa000dead000000800"
                "0102030405060708090a0b0c0d0e0f0102030405\n"
                "   }\n"
                "}\n"
                "trace add pg-input 2",
                "pa en",
                "show mactime verbose 2",
                "show trace",
                "show error"]

        for cmd in cmds:
            r = self.vapi.cli_return_response(cmd)
            if r.retval != 0:
                if hasattr(r, 'reply'):
                    self.logger.info(cmd + " FAIL reply " + r.reply)
                else:
                    self.logger.info(cmd + " FAIL retval " + str(r.retval))

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
