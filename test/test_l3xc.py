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

from socket import inet_pton, inet_ntop, AF_INET, AF_INET6
import unittest

from framework import VppTestCase, VppTestRunner
from vpp_ip import DpoProto
from vpp_ip_route import VppIpRoute, VppRoutePath, VppMplsLabel, VppIpTable

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6

from vpp_object import VppObject

NUM_PKTS = 67


def find_l3xc(test, sw_if_index, dump_sw_if_index=None):
    if not dump_sw_if_index:
        dump_sw_if_index = sw_if_index
    xcs = test.vapi.l3xc_dump(dump_sw_if_index)
    for xc in xcs:
        if sw_if_index == xc.l3xc.sw_if_index:
            return True
    return False


class VppL3xc(VppObject):

    def __init__(self,  test, intf, paths, is_ip6=False):
        self._test = test
        self.intf = intf
        self.is_ip6 = is_ip6
        self.paths = paths
        self.encoded_paths = []
        for path in self.paths:
            self.encoded_paths.append(path.encode())

    def add_vpp_config(self):
        self._test.vapi.l3xc_update(
            l3xc={
                'is_ip6': self.is_ip6,
                'sw_if_index': self.intf.sw_if_index,
                'n_paths': len(self.paths),
                'paths': self.encoded_paths
            })
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.l3xc_del(
            is_ip6=self.is_ip6,
            sw_if_index=self.intf.sw_if_index)

    def query_vpp_config(self):
        return find_l3xc(self._test, self.intf.sw_if_index)

    def object_id(self):
        return ("l3xc-%d" % self.intf.sw_if_index)


class TestL3xc(VppTestCase):
    """ L3XC Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestL3xc, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestL3xc, cls).tearDownClass()

    def setUp(self):
        super(TestL3xc, self).setUp()

        self.create_pg_interfaces(range(6))

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()
            i.config_ip6()
            i.resolve_ndp()

    def tearDown(self):
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.admin_down()
        super(TestL3xc, self).tearDown()

    def send_and_expect_load_balancing(self, input, pkts, outputs):
        self.pg_send(input, pkts)
        rxs = []
        for oo in outputs:
            rx = oo._get_capture(1)
            self.assertNotEqual(0, len(rx))
            for r in rx:
                rxs.append(r)
        return rxs

    def test_l3xc4(self):
        """ IPv4 X-Connect """

        #
        # x-connect pg0 to pg1 and pg2 to pg3->5
        #
        l3xc_1 = VppL3xc(self, self.pg0,
                         [VppRoutePath(self.pg1.remote_ip4,
                                       self.pg1.sw_if_index)])
        l3xc_1.add_vpp_config()
        l3xc_2 = VppL3xc(self, self.pg2,
                         [VppRoutePath(self.pg3.remote_ip4,
                                       self.pg3.sw_if_index),
                          VppRoutePath(self.pg4.remote_ip4,
                                       self.pg4.sw_if_index),
                          VppRoutePath(self.pg5.remote_ip4,
                                       self.pg5.sw_if_index)])
        l3xc_2.add_vpp_config()

        self.assertTrue(find_l3xc(self, self.pg2.sw_if_index, 0xffffffff))

        self.logger.info(self.vapi.cli("sh l3xc"))

        #
        # fire in packets. If it's forwarded then the L3XC was successful,
        # since default routing will drop it
        #
        p_1 = (Ether(src=self.pg0.remote_mac,
                     dst=self.pg0.local_mac) /
               IP(src="1.1.1.1", dst="1.1.1.2") /
               UDP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 100))
        # self.send_and_expect(self.pg0, p_1*NUM_PKTS, self.pg1)

        p_2 = []
        for ii in range(NUM_PKTS):
            p_2.append(Ether(src=self.pg0.remote_mac,
                             dst=self.pg0.local_mac) /
                       IP(src="1.1.1.1", dst="1.1.1.2") /
                       UDP(sport=1000 + ii, dport=1234) /
                       Raw(b'\xa5' * 100))
        self.send_and_expect_load_balancing(self.pg2, p_2,
                                            [self.pg3, self.pg4, self.pg5])

        l3xc_2.remove_vpp_config()
        self.send_and_assert_no_replies(self.pg2, p_2)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
