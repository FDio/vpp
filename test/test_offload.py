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


class TestOffload(VppTestCase):
    """ Offload Unit Test Cases """

    @classmethod
    def setUpClass(cls):
        super(TestOffload, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestOffload, cls).tearDownClass()

    def setUp(self):
        super(TestOffload, self).setUp()

    def tearDown(self):
        super(TestOffload, self).tearDown()

    def test_offload_unittest(self):
        """ Checksum Offload Test """
        cmds = ["loop create",
                "set int ip address loop0 11.22.33.1/24",
                "set int state loop0 up",
                "loop create",
                "set int ip address loop1 11.22.34.1/24",
                "set int state loop1 up",
                "set ip neighbor loop1 11.22.34.44 03:00:11:22:34:44",
                "packet-generator new {\n"
                "  name s0\n"
                "  limit 100\n"
                "  size 128-128\n"
                "  interface loop0\n"
                "  tx-interface loop1\n"
                "  node loop1-output\n"
                "  buffer-flags ip4 offload\n"
                "  buffer-offload-flags offload-ip-cksum offload-udp-cksum\n"
                "  data {\n"
                "    IP4: 1.2.3 -> dead.0000.0001\n"
                "    UDP: 11.22.33.44 -> 11.22.34.44\n"
                "      ttl 2 checksum 13\n"
                "    UDP: 1234 -> 2345\n"
                "      checksum 11\n"
                "    incrementing 114\n"
                "  }\n"
                "}",
                "trace add pg-input 1",
                "pa en",
                "show error"]

        for cmd in cmds:
            r = self.vapi.cli_return_response(cmd)
            if r.retval != 0:
                if hasattr(r, 'reply'):
                    self.logger.info(cmd + " FAIL reply " + r.reply)
                else:
                    self.logger.info(cmd + " FAIL retval " + str(r.retval))

        r = self.vapi.cli_return_response("show trace")
        self.assertTrue(r.retval == 0)
        self.assertTrue(hasattr(r, 'reply'))
        rv = r.reply
        look_here = rv.find('ethernet-input')
        self.assertFalse(look_here == -1)
        bad_checksum_index = rv[look_here:].find('should be')
        self.assertTrue(bad_checksum_index == -1)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
