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
"""CRUD tests of APIs (Create, Read, Update, Delete) HLD:

- interface up/down/add/delete - interface type:
    - pg (TBD)
    - loopback
    - vhostuser (TBD)
    - af_packet (TBD)
    - netmap (TBD)
    - tuntap (root privileges needed)
    - vxlan (TBD)
"""

import unittest

from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether

from framework import VppTestCase, VppTestRunner


class TestLoopbackInterfaceCRUD(VppTestCase):
    """CRUD Loopback

    """

    @classmethod
    def setUpClass(cls):
        super(TestLoopbackInterfaceCRUD, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(1))
            for i in cls.pg_interfaces:
                i.config_ip4().resolve_arp()
        except:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        super(TestLoopbackInterfaceCRUD, cls).tearDownClass()

    @staticmethod
    def create_icmp_stream(src_if, dst_ifs):
        """

        :param VppInterface src_if: Packets are send to this interface,
            using this interfaces remote host.
        :param list dst_ifs: IPv4 ICMP requests are send to interfaces
            addresses.
        :return: List of generated packets.
        """
        pkts = []
        for i in dst_ifs:
            p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                 IP(src=src_if.remote_ip4, dst=i.local_ip4) /
                 ICMP(id=i.sw_if_index, type='echo-request'))
            pkts.append(p)
        return pkts

    def verify_icmp(self, capture, request_src_if, dst_ifs):
        """

        :param capture: Capture to verify.
        :param VppInterface request_src_if: Interface where was send packets.
        :param list dst_ifs: Interfaces where was generated IPv4 ICMP requests.
        """
        rcvd_icmp_pkts = []
        for pkt in capture:
            try:
                ip = pkt[IP]
                icmp = pkt[ICMP]
            except IndexError:
                pass
            else:
                info = (ip.src, ip.dst, icmp.type, icmp.id)
                rcvd_icmp_pkts.append(info)

        for i in dst_ifs:
            # 0 - icmp echo response
            info = (i.local_ip4, request_src_if.remote_ip4, 0, i.sw_if_index)
            self.assertIn(info, rcvd_icmp_pkts)

    def test_crud(self):
        # create
        loopbacks = self.create_loopback_interfaces(20)
        for i in loopbacks:
            i.local_ip4_prefix_len = 32
            i.config_ip4().admin_up()

        # read (check sw if dump, ip4 fib, ip6 fib)
        if_dump = self.vapi.sw_interface_dump(name_filter_valid=True,
                                              name_filter='loop')
        fib4_dump = self.vapi.ip_route_dump(0)
        for i in loopbacks:
            self.assertTrue(i.is_interface_config_in_dump(if_dump))
            self.assertTrue(i.is_ip4_entry_in_fib_dump(fib4_dump))

        if_dump = self.vapi.sw_interface_dump(name_filter_valid=True,
                                              name_filter='loopXYZ')
        self.assertEqual(len(if_dump), 0)

        # check ping
        stream = self.create_icmp_stream(self.pg0, loopbacks)
        self.pg0.add_stream(stream)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        capture = self.pg0.get_capture(expected_count=len(stream))

        self.verify_icmp(capture, self.pg0, loopbacks)

        # delete
        for i in loopbacks:
            i.remove_vpp_config()

        # read (check not in sw if dump, ip4 fib, ip6 fib)
        if_dump = self.vapi.sw_interface_dump()
        fib4_dump = self.vapi.ip_route_dump(0)
        for i in loopbacks:
            self.assertFalse(i.is_interface_config_in_dump(if_dump))
            self.assertFalse(i.is_ip4_entry_in_fib_dump(fib4_dump))

        #  check not ping
        stream = self.create_icmp_stream(self.pg0, loopbacks)
        self.pg0.add_stream(stream)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg0.assert_nothing_captured()

    def test_down(self):
        # create
        loopbacks = self.create_loopback_interfaces(20)
        for i in loopbacks:
            i.local_ip4_prefix_len = 32
            i.config_ip4().admin_up()

        # disable
        for i in loopbacks:
            i.admin_down().unconfig_ip4()

        # read (check not in sw if dump, ip4 fib, ip6 fib)
        if_dump = self.vapi.sw_interface_dump()
        fib4_dump = self.vapi.ip_route_dump(0)
        for i in loopbacks:
            self.assertTrue(i.is_interface_config_in_dump(if_dump))
            self.assertFalse(i.is_ip4_entry_in_fib_dump(fib4_dump))

        #  check not ping
        stream = self.create_icmp_stream(self.pg0, loopbacks)
        self.pg0.add_stream(stream)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg0.assert_nothing_captured()


class TestInterfaceDumpApiLocalOnly(VppTestCase):
    """test_interface_crud.TestInterfaceDumpApiLocalOnly"""

    def test_sw_if_index_0(self):
        rv = self.vapi.sw_interface_dump(sw_if_index=0)
        self.assertEqual(rv[0].sw_if_index, 0)

    def test_sw_if_index_twiddle0(self):
        rv = self.vapi.sw_interface_dump(sw_if_index=0xffffffff)
        self.assertEqual(rv[0].sw_if_index, 0)

    def test_sw_if_index_1_not_existing(self):
        rv = self.vapi.sw_interface_dump(sw_if_index=1)
        self.assertEqual(len(rv), 0, 'expected no records.')


class TestInterfaceDumpApi(VppTestCase):
    """test_interface_crud.TestInterfaceDumpApi"""

    def test_sw_if_index_1(self):
        self.vapi.create_loopback_instance(is_specified=1,
                                           user_instance=10)
        self.vapi.create_loopback_instance(is_specified=1,
                                           user_instance=5)

        # Can I get back the specified record?
        rv = self.vapi.sw_interface_dump(sw_if_index=1)
        self.assertEqual(rv[0].sw_if_index, 1, rv)

        # verify 3 interfaces
        rv = self.vapi.sw_interface_dump(sw_if_index=0xffffffff)
        self.assertEqual(len(rv), 3, 'Expected 3 interfaces.')


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
