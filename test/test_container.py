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
""" Container integration tests """

import unittest
from framework import VppTestCase, VppTestRunner, running_extended_tests
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.layers.inet import IP, UDP, TCP
from scapy.packet import Packet
from socket import inet_pton, AF_INET, AF_INET6
from scapy.layers.inet6 import IPv6, ICMPv6Unknown, ICMPv6EchoRequest
from scapy.layers.inet6 import ICMPv6EchoReply, IPv6ExtHdrRouting
from scapy.layers.inet6 import IPv6ExtHdrFragment
from pprint import pprint
from random import randint
from util import L4_Conn


class Conn(L4_Conn):
    # for now same as L4_Conn
    pass


@unittest.skipUnless(running_extended_tests, "part of extended tests")
class ContainerIntegrationTestCase(VppTestCase):
    """ Container integration extended testcases """

    @classmethod
    def setUpClass(cls):
        super(ContainerIntegrationTestCase, cls).setUpClass()
        # create pg0 and pg1
        cls.create_pg_interfaces(range(2))
        for i in cls.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.config_ip6()
            i.resolve_arp()
            i.resolve_ndp()

    @classmethod
    def tearDownClass(cls):
        super(ContainerIntegrationTestCase, cls).tearDownClass()

    def tearDown(self):
        """Run standard test teardown and log various show commands
        """
        super(ContainerIntegrationTestCase, self).tearDown()

    def show_commands_at_teardown(self):
        self.logger.info(self.vapi.cli("show ip neighbors"))

    def run_basic_conn_test(self, af, acl_side):
        """ Basic connectivity test """
        conn1 = Conn(self, self.pg0, self.pg1, af, UDP, 42001, 4242)
        conn1.send_through(0)
        # the return packets should pass
        conn1.send_through(1)

    def run_negative_conn_test(self, af, acl_side):
        """ Packets with local spoofed address """
        conn1 = Conn(self, self.pg0, self.pg1, af, UDP, 42001, 4242)
        try:
            p2 = conn1.send_through(0).command()
        except:
            # If we asserted while waiting, it's good.
            # the conn should have timed out.
            p2 = None
        self.assert_equal(p2, None, ": packet should have been dropped")

    def test_0010_basic_conn_test(self):
        """ IPv4 basic connectivity test """
        self.run_basic_conn_test(AF_INET, 0)

    def test_0011_basic_conn_test(self):
        """ IPv6 basic connectivity test """
        self.run_basic_conn_test(AF_INET6, 0)

    def test_0050_loopback_prepare_test(self):
        """ Create loopbacks overlapping with remote addresses """
        self.create_loopback_interfaces(2)
        for i in range(2):
            intf = self.lo_interfaces[i]
            intf.admin_up()
            intf.local_ip4 = self.pg_interfaces[i].remote_ip4
            intf.local_ip4_prefix_len = 32
            intf.config_ip4()
            intf.local_ip6 = self.pg_interfaces[i].remote_ip6
            intf.local_ip6_prefix_len = 128
            intf.config_ip6()

    def test_0110_basic_conn_test(self):
        """ IPv4 local-spoof connectivity test """
        self.run_negative_conn_test(AF_INET, 0)

    def test_0111_basic_conn_test(self):
        """ IPv6 local-spoof connectivity test """
        self.run_negative_conn_test(AF_INET, 1)

    def test_0200_basic_conn_test(self):
        """ Configure container commands """
        for i in range(2):
            for addr in [self.pg_interfaces[i].remote_ip4,
                         self.pg_interfaces[i].remote_ip6]:
                self.vapi.ppcli("ip container " + addr + " " +
                                self.pg_interfaces[i].name)
                self.vapi.ppcli("stn rule address " + addr +
                                " interface " + self.pg_interfaces[i].name)

    def test_0210_basic_conn_test(self):
        """ IPv4 test after configuring container """
        self.run_basic_conn_test(AF_INET, 0)

    def test_0211_basic_conn_test(self):
        """ IPv6 test after configuring container """
        self.run_basic_conn_test(AF_INET, 1)

    def test_0300_unconfigure_commands(self):
        """ Unconfigure container commands """
        for i in range(2):
            for addr in [self.pg_interfaces[i].remote_ip4,
                         self.pg_interfaces[i].remote_ip6]:
                self.vapi.ppcli("ip container " + addr + " " +
                                self.pg_interfaces[i].name +
                                " del")
                self.vapi.ppcli("stn rule address " + addr +
                                " interface " + self.pg_interfaces[i].name +
                                " del")

    def test_0410_spoof_test(self):
        """ IPv4 local-spoof after unconfig test """
        self.run_negative_conn_test(AF_INET, 0)

    def test_0411_spoof_test(self):
        """ IPv6 local-spoof after unconfig test """
        self.run_negative_conn_test(AF_INET, 1)
