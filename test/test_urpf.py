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

from framework import VppTestCase, VppTestRunner

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, ICMP
from scapy.layers.inet6 import IPv6

from vpp_papi import VppEnum

N_PKTS = 63


class TestURPF(VppTestCase):
    """ Unicast Reverse Path Forwarding Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestURPF, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestURPF, cls).tearDownClass()

    def setUp(self):
        super(TestURPF, self).setUp()

        # create 4 pg interfaces so there are a few addresses
        # in the FIB
        self.create_pg_interfaces(range(4))

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
        super(TestURPF, self).tearDown()

    def test_urpf4(self):
        """ uRPF IP4 """

        e = VppEnum
        p_spoof_loose = (Ether(dst=self.pg0.local_mac,
                               src=self.pg0.remote_mac) /
                         IP(src="3.3.3.3", dst=self.pg1.remote_ip4) /
                         UDP(sport=1234, dport=1234) /
                         Raw(b'\xa5' * 100)) * N_PKTS
        p_spoof_strict = (Ether(dst=self.pg0.local_mac,
                                src=self.pg0.remote_mac) /
                          IP(src=self.pg2.remote_ip4,
                             dst=self.pg1.remote_ip4) /
                          UDP(sport=1234, dport=1234) /
                          Raw(b'\xa5' * 100)) * N_PKTS
        p_good = (Ether(dst=self.pg0.local_mac,
                        src=self.pg0.remote_mac) /
                  IP(src=self.pg0.remote_ip4,
                     dst=self.pg1.remote_ip4) /
                  UDP(sport=1234, dport=1234) /
                  Raw(b'\xa5' * 100)) * N_PKTS

        #
        # before adding the uRPF, ensure all packets are forwarded
        #
        self.send_and_expect(self.pg0, p_good, self.pg1)
        self.send_and_expect(self.pg0, p_spoof_strict, self.pg1)
        self.send_and_expect(self.pg0, p_spoof_loose, self.pg1)

        #
        # apply loose uRPF check on pg0 rx
        #
        self.vapi.urpf_update(is_input=True,
                              mode=e.vl_api_urpf_mode_t.URPF_API_MODE_LOOSE,
                              af=e.vl_api_address_family_t.ADDRESS_IP4,
                              sw_if_index=self.pg0.sw_if_index)

        # good packets still pass
        self.send_and_expect(self.pg0, p_good, self.pg1)
        # packets from address for which there is a route are forwarded
        self.send_and_expect(self.pg0, p_spoof_strict, self.pg1)
        # packets from address to which there is no route are dropped
        self.send_and_assert_no_replies(self.pg0, p_spoof_loose)

        self.assert_error_counter_equal("/err/ip4-rx-urpf-loose/uRPF Drop",
                                        N_PKTS)

        #
        # crank it up to strict mode
        #
        self.vapi.urpf_update(is_input=True,
                              mode=e.vl_api_urpf_mode_t.URPF_API_MODE_STRICT,
                              af=e.vl_api_address_family_t.ADDRESS_IP4,
                              sw_if_index=self.pg0.sw_if_index)

        # good packets still pass
        self.send_and_expect(self.pg0, p_good, self.pg1)
        # packets that would not be routed back thru pg0 are dropped
        self.send_and_assert_no_replies(self.pg0, p_spoof_strict)
        self.send_and_assert_no_replies(self.pg0, p_spoof_loose)

        self.assert_error_counter_equal("/err/ip4-rx-urpf-strict/uRPF Drop",
                                        2 * N_PKTS)

        #
        # disable uRPF, all traffic should pass
        #
        self.vapi.urpf_update(is_input=True,
                              mode=e.vl_api_urpf_mode_t.URPF_API_MODE_OFF,
                              af=e.vl_api_address_family_t.ADDRESS_IP4,
                              sw_if_index=self.pg0.sw_if_index)

        self.send_and_expect(self.pg0, p_good, self.pg1)
        self.send_and_expect(self.pg0, p_spoof_strict, self.pg1)
        self.send_and_expect(self.pg0, p_spoof_loose, self.pg1)

        #
        # Now apply in the TX direction
        #  for loose it is the same deal, they should not be forwarded
        #  if there's no route
        #  for strict they should not be forwarded if they would be
        #  forwarded thru that interface.
        #
        self.vapi.urpf_update(is_input=False,
                              mode=e.vl_api_urpf_mode_t.URPF_API_MODE_LOOSE,
                              af=e.vl_api_address_family_t.ADDRESS_IP4,
                              sw_if_index=self.pg1.sw_if_index)

        self.send_and_expect(self.pg0, p_good, self.pg1)
        self.send_and_expect(self.pg0, p_spoof_strict, self.pg1)
        self.send_and_assert_no_replies(self.pg0, p_spoof_loose)

        self.assert_error_counter_equal("/err/ip4-tx-urpf-loose/uRPF Drop",
                                        N_PKTS)

        self.vapi.urpf_update(is_input=False,
                              mode=e.vl_api_urpf_mode_t.URPF_API_MODE_STRICT,
                              af=e.vl_api_address_family_t.ADDRESS_IP4,
                              sw_if_index=self.pg1.sw_if_index)

        self.send_and_expect(self.pg0, p_good, self.pg1)
        # the strict packet, from a peer is allowed, since it does
        # not forward via pg1
        self.send_and_expect(self.pg0, p_spoof_strict, self.pg1)
        self.send_and_assert_no_replies(self.pg0, p_spoof_loose)

        self.assert_error_counter_equal("/err/ip4-tx-urpf-strict/uRPF Drop",
                                        N_PKTS)

        # change the strict packet so that it would forward through pg1
        p_spoof_strict = (Ether(dst=self.pg0.local_mac,
                                src=self.pg0.remote_mac) /
                          IP(src=self.pg1.remote_ip4,
                             dst=self.pg1.remote_ip4) /
                          UDP(sport=1234, dport=1234) /
                          Raw(b'\xa5' * 100)) * N_PKTS

        self.send_and_assert_no_replies(self.pg0, p_spoof_strict)
        self.assert_error_counter_equal("/err/ip4-tx-urpf-strict/uRPF Drop",
                                        2 * N_PKTS)

        # cleanup
        self.vapi.urpf_update(is_input=False,
                              mode=e.vl_api_urpf_mode_t.URPF_API_MODE_OFF,
                              af=e.vl_api_address_family_t.ADDRESS_IP4,
                              sw_if_index=self.pg1.sw_if_index)

    def test_urpf6(self):
        """ uRPF IP6 """

        e = VppEnum
        p_spoof_loose = (Ether(dst=self.pg0.local_mac,
                               src=self.pg0.remote_mac) /
                         IPv6(src="3::3", dst=self.pg1.remote_ip6) /
                         UDP(sport=1236, dport=1236) /
                         Raw(b'\xa5' * 100)) * N_PKTS
        p_spoof_strict = (Ether(dst=self.pg0.local_mac,
                                src=self.pg0.remote_mac) /
                          IPv6(src=self.pg2.remote_ip6,
                               dst=self.pg1.remote_ip6) /
                          UDP(sport=1236, dport=1236) /
                          Raw(b'\xa5' * 100)) * N_PKTS
        p_good = (Ether(dst=self.pg0.local_mac,
                        src=self.pg0.remote_mac) /
                  IPv6(src=self.pg0.remote_ip6,
                       dst=self.pg1.remote_ip6) /
                  UDP(sport=1236, dport=1236) /
                  Raw(b'\xa5' * 100)) * N_PKTS

        #
        # before adding the uRPF, ensure all packets are forwarded
        #
        self.send_and_expect(self.pg0, p_good, self.pg1)
        self.send_and_expect(self.pg0, p_spoof_strict, self.pg1)
        self.send_and_expect(self.pg0, p_spoof_loose, self.pg1)

        #
        # apply loose uRPF check on pg0 rx
        #
        self.vapi.urpf_update(is_input=True,
                              mode=e.vl_api_urpf_mode_t.URPF_API_MODE_LOOSE,
                              af=e.vl_api_address_family_t.ADDRESS_IP6,
                              sw_if_index=self.pg0.sw_if_index)

        # good packets still pass
        self.send_and_expect(self.pg0, p_good, self.pg1)
        # packets from address for which there is a route are forwarded
        self.send_and_expect(self.pg0, p_spoof_strict, self.pg1)
        # packets from address to which there is no route are dropped
        self.send_and_assert_no_replies(self.pg0, p_spoof_loose)

        self.assert_error_counter_equal("/err/ip6-rx-urpf-loose/uRPF Drop",
                                        N_PKTS)

        #
        # crank it up to strict mode
        #
        self.vapi.urpf_update(is_input=True,
                              mode=e.vl_api_urpf_mode_t.URPF_API_MODE_STRICT,
                              af=e.vl_api_address_family_t.ADDRESS_IP6,
                              sw_if_index=self.pg0.sw_if_index)

        # good packets still pass
        self.send_and_expect(self.pg0, p_good, self.pg1)
        # packets that would not be routed back thru pg0 are dropped
        self.send_and_assert_no_replies(self.pg0, p_spoof_strict)
        self.send_and_assert_no_replies(self.pg0, p_spoof_loose)

        self.assert_error_counter_equal("/err/ip6-rx-urpf-strict/uRPF Drop",
                                        2 * N_PKTS)

        #
        # disable uRPF, all traffic should pass
        #
        self.vapi.urpf_update(is_input=True,
                              mode=e.vl_api_urpf_mode_t.URPF_API_MODE_OFF,
                              af=e.vl_api_address_family_t.ADDRESS_IP6,
                              sw_if_index=self.pg0.sw_if_index)

        self.send_and_expect(self.pg0, p_good, self.pg1)
        self.send_and_expect(self.pg0, p_spoof_strict, self.pg1)
        self.send_and_expect(self.pg0, p_spoof_loose, self.pg1)

        #
        # Now apply in the TX direction
        #  for loose it is the same deal, they should not be forwarded
        #  if there's no route
        #  for strict they should not be forwarded if they would be
        #  forwarded thru that interface.
        #
        self.vapi.urpf_update(is_input=False,
                              mode=e.vl_api_urpf_mode_t.URPF_API_MODE_LOOSE,
                              af=e.vl_api_address_family_t.ADDRESS_IP6,
                              sw_if_index=self.pg1.sw_if_index)

        self.send_and_expect(self.pg0, p_good, self.pg1)
        self.send_and_expect(self.pg0, p_spoof_strict, self.pg1)
        self.send_and_assert_no_replies(self.pg0, p_spoof_loose)

        self.assert_error_counter_equal("/err/ip6-tx-urpf-loose/uRPF Drop",
                                        N_PKTS)

        self.vapi.urpf_update(is_input=False,
                              mode=e.vl_api_urpf_mode_t.URPF_API_MODE_STRICT,
                              af=e.vl_api_address_family_t.ADDRESS_IP6,
                              sw_if_index=self.pg1.sw_if_index)

        self.send_and_expect(self.pg0, p_good, self.pg1)
        # the strict packet, from a peer is allowed, since it does
        # not forward via pg1
        self.send_and_expect(self.pg0, p_spoof_strict, self.pg1)
        self.send_and_assert_no_replies(self.pg0, p_spoof_loose)

        self.assert_error_counter_equal("/err/ip6-tx-urpf-strict/uRPF Drop",
                                        N_PKTS)

        # change the strict packet so that it would forward through pg1
        p_spoof_strict = (Ether(dst=self.pg0.local_mac,
                                src=self.pg0.remote_mac) /
                          IPv6(src=self.pg1.remote_ip6,
                               dst=self.pg1.remote_ip6) /
                          UDP(sport=1236, dport=1236) /
                          Raw(b'\xa5' * 100)) * N_PKTS

        self.send_and_assert_no_replies(self.pg0, p_spoof_strict)
        self.assert_error_counter_equal("/err/ip6-tx-urpf-strict/uRPF Drop",
                                        2 * N_PKTS)

        # cleanup
        self.vapi.urpf_update(is_input=False,
                              mode=e.vl_api_urpf_mode_t.URPF_API_MODE_OFF,
                              af=e.vl_api_address_family_t.ADDRESS_IP6,
                              sw_if_index=self.pg1.sw_if_index)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
