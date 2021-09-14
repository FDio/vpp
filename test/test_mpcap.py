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

from framework import VppTestCase, VppTestRunner, running_extended_tests
from vpp_ip_route import VppIpTable, VppIpRoute, VppRoutePath
import os


class TestMpcap(VppTestCase):
    """ Mpcap Unit Test Cases """

    @classmethod
    def setUpClass(cls):
        super(TestMpcap, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestMpcap, cls).tearDownClass()

    def setUp(self):
        super(TestMpcap, self).setUp()

    def tearDown(self):
        super(TestMpcap, self).tearDown()

    def test_mpcap_unittest(self):
        """ Mapped pcap file test """
        cmds = ["packet-generator new {\n"
                " name mpcap\n"
                " limit 15\n"
                " size 128-128\n"
                " interface local0\n"
                " node mpcap-unittest\n"
                " data {\n"
                "   IP6: 00:d0:2d:5e:86:85 -> 00:0d:ea:d0:00:00\n"
                "   ICMP: db00::1 -> db00::2\n"
                "   incrementing 30\n"
                "   }\n",
                "trace add pg-input 15",
                "pa en",
                "show trace",
                "show error"]

        for cmd in cmds:
            self.logger.info(self.vapi.cli(cmd))

        size = os.path.getsize("/tmp/mpcap_unittest.pcap")
        os.remove("/tmp/mpcap_unittest.pcap")
        if size != 2184:
            self.logger.critical("BUG: file size %d not 2184" % size)
            self.assertNotIn('WrongMPCAPFileSize', 'WrongMPCAPFileSize')

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
