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

from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Raw


class TestMSSClamp(VppTestCase):
    """ TCP MSS Clamping Test Case """

    def setUp(self):
        super(TestMSSClamp, self).setUp()

        # create 2 pg interfaces
        self.create_pg_interfaces(range(2))

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
        super(TestMSSClamp, self).tearDown()

    def verify_pkt(self, rx, expected_mss):
        # check that the MSS size equals the expected value
        # and the IP and TCP checksums are correct
        tcp = rx[TCP]
        tcp_csum = tcp.chksum
        del tcp.chksum
        ip_csum = 0
        if (rx.haslayer(IP)):
            ip_csum = rx[IP].chksum
            del rx[IP].chksum

        opt = tcp.options
        self.assertEqual(opt[0][0], 'MSS')
        self.assertEqual(opt[0][1], expected_mss)
        # recalculate checksums
        rx = rx.__class__(bytes(rx))
        tcp = rx[TCP]
        self.assertEqual(tcp_csum, tcp.chksum)
        if (rx.haslayer(IP)):
            self.assertEqual(ip_csum, rx[IP].chksum)

    def send_and_verify_ip4(self, src_pg, dst_pg, mss, expected_mss):
        # IPv4 TCP packet with the requested MSS option.
        # from a host on src_pg to a host on dst_pg.
        p = (Ether(dst=src_pg.local_mac,
                   src=src_pg.remote_mac) /
             IP(src=src_pg.remote_ip4,
                dst=dst_pg.remote_ip4) /
             TCP(sport=1234, dport=1234,
                 flags="S",
                 options=[('MSS', (mss)), ('EOL', None)]) /
             Raw('\xa5' * 100))

        rxs = self.send_and_expect(src_pg, p * 65, dst_pg)

        for rx in rxs:
            self.verify_pkt(rx, expected_mss)

    def send_and_verify_ip6(self, src_pg, dst_pg, mss, expected_mss):
        #
        # IPv6 TCP packet with the requested MSS option.
        # from a host on src_pg to a host on dst_pg.
        #
        p = (Ether(dst=src_pg.local_mac,
                   src=src_pg.remote_mac) /
             IPv6(src=src_pg.remote_ip6,
                  dst=dst_pg.remote_ip6) /
             TCP(sport=1234, dport=1234,
                 flags="S",
                 options=[('MSS', (mss)), ('EOL', None)]) /
             Raw('\xa5' * 100))

        rxs = self.send_and_expect(src_pg, p * 65, dst_pg)

        for rx in rxs:
            self.verify_pkt(rx, expected_mss)

    def test_tcp_mss_clamping_ip4_tx(self):
        """ IP4 TCP MSS Clamping TX """

        # enable the TCP MSS clamping feature to lower the MSS to 1424.
        self.vapi.mss_clamp_enable_disable(self.pg1.sw_if_index,
                                           ipv4_mss=1424, ipv6_mss=0,
                                           ipv4_direction=3, ipv6_direction=0)

        # Verify that the feature is enabled.
        rv, reply = self.vapi.mss_clamp_get(sw_if_index=self.pg1.sw_if_index)
        self.assertEqual(reply[0].ipv4_mss, 1424)
        self.assertEqual(reply[0].ipv4_direction, 3)

        # Send syn packets and verify that the MSS value is lowered.
        self.send_and_verify_ip4(self.pg0, self.pg1, 1460, 1424)

        # check the stats
        stats = self.statistics.get_counter(
            '/err/tcp-mss-clamping-ip4-out/clamped')
        self.assertEqual(sum(stats), 65)

        # Send syn packets with small enough MSS values and verify they are
        # unchanged.
        self.send_and_verify_ip4(self.pg0, self.pg1, 1400, 1400)

        # enable the the feature only in TX direction
        # and change the max MSS value
        self.vapi.mss_clamp_enable_disable(self.pg1.sw_if_index,
                                           ipv4_mss=1420, ipv6_mss=0,
                                           ipv4_direction=2, ipv6_direction=0)

        # Send syn packets and verify that the MSS value is lowered.
        self.send_and_verify_ip4(self.pg0, self.pg1, 1460, 1420)

        # enable the the feature only in RX direction
        self.vapi.mss_clamp_enable_disable(self.pg1.sw_if_index,
                                           ipv4_mss=1424, ipv6_mss=0,
                                           ipv4_direction=1, ipv6_direction=0)

        # Send the packets again and ensure they are unchanged.
        self.send_and_verify_ip4(self.pg0, self.pg1, 1460, 1460)

        # disable the feature
        self.vapi.mss_clamp_enable_disable(self.pg1.sw_if_index,
                                           ipv4_mss=0, ipv6_mss=0,
                                           ipv4_direction=0, ipv6_direction=0)

        # Send the packets again and ensure they are unchanged.
        self.send_and_verify_ip4(self.pg0, self.pg1, 1460, 1460)

    def test_tcp_mss_clamping_ip4_rx(self):
        """ IP4 TCP MSS Clamping RX """

        # enable the TCP MSS clamping feature to lower the MSS to 1424.
        self.vapi.mss_clamp_enable_disable(self.pg1.sw_if_index,
                                           ipv4_mss=1424, ipv6_mss=0,
                                           ipv4_direction=3, ipv6_direction=0)

        # Verify that the feature is enabled.
        rv, reply = self.vapi.mss_clamp_get(sw_if_index=self.pg1.sw_if_index)
        self.assertEqual(reply[0].ipv4_mss, 1424)
        self.assertEqual(reply[0].ipv4_direction, 3)

        # Send syn packets and verify that the MSS value is lowered.
        self.send_and_verify_ip4(self.pg1, self.pg0, 1460, 1424)

        # check the stats
        stats = self.statistics.get_counter(
            '/err/tcp-mss-clamping-ip4-in/clamped')
        self.assertEqual(sum(stats), 65)

        # Send syn packets with small enough MSS values and verify they are
        # unchanged.
        self.send_and_verify_ip4(self.pg1, self.pg0, 1400, 1400)

        # enable the the feature only in RX direction
        # and change the max MSS value
        self.vapi.mss_clamp_enable_disable(self.pg1.sw_if_index,
                                           ipv4_mss=1420, ipv6_mss=0,
                                           ipv4_direction=1, ipv6_direction=0)

        # Send syn packets and verify that the MSS value is lowered.
        self.send_and_verify_ip4(self.pg1, self.pg0, 1460, 1420)

        # enable the the feature only in TX direction
        self.vapi.mss_clamp_enable_disable(self.pg1.sw_if_index,
                                           ipv4_mss=1424, ipv6_mss=0,
                                           ipv4_direction=2, ipv6_direction=0)

        # Send the packets again and ensure they are unchanged.
        self.send_and_verify_ip4(self.pg1, self.pg0, 1460, 1460)

        # disable the feature
        self.vapi.mss_clamp_enable_disable(self.pg1.sw_if_index,
                                           ipv4_mss=0, ipv6_mss=0,
                                           ipv4_direction=0, ipv6_direction=0)

        # Send the packets again and ensure they are unchanged.
        self.send_and_verify_ip4(self.pg1, self.pg0, 1460, 1460)

    def test_tcp_mss_clamping_ip6_tx(self):
        """ IP6 TCP MSS Clamping TX """

        # enable the TCP MSS clamping feature to lower the MSS to 1424.
        self.vapi.mss_clamp_enable_disable(self.pg1.sw_if_index,
                                           ipv4_mss=0, ipv6_mss=1424,
                                           ipv4_direction=0, ipv6_direction=3)

        # Verify that the feature is enabled.
        rv, reply = self.vapi.mss_clamp_get(sw_if_index=self.pg1.sw_if_index)
        self.assertEqual(reply[0].ipv6_mss, 1424)
        self.assertEqual(reply[0].ipv6_direction, 3)

        # Send syn packets and verify that the MSS value is lowered.
        self.send_and_verify_ip6(self.pg0, self.pg1, 1460, 1424)

        # check the stats
        stats = self.statistics.get_counter(
            '/err/tcp-mss-clamping-ip6-out/clamped')
        self.assertEqual(sum(stats), 65)

        # Send syn packets with small enough MSS values and verify they are
        # unchanged.
        self.send_and_verify_ip6(self.pg0, self.pg1, 1400, 1400)

        # enable the the feature only in TX direction
        # and change the max MSS value
        self.vapi.mss_clamp_enable_disable(self.pg1.sw_if_index,
                                           ipv4_mss=0, ipv6_mss=1420,
                                           ipv4_direction=0, ipv6_direction=2)

        # Send syn packets and verify that the MSS value is lowered.
        self.send_and_verify_ip6(self.pg0, self.pg1, 1460, 1420)

        # enable the the feature only in RX direction
        self.vapi.mss_clamp_enable_disable(self.pg1.sw_if_index,
                                           ipv4_mss=0, ipv6_mss=1424,
                                           ipv4_direction=0, ipv6_direction=1)

        # Send the packets again and ensure they are unchanged.
        self.send_and_verify_ip6(self.pg0, self.pg1, 1460, 1460)

        # disable the feature
        self.vapi.mss_clamp_enable_disable(self.pg1.sw_if_index,
                                           ipv4_mss=0, ipv6_mss=0,
                                           ipv4_direction=0, ipv6_direction=0)

        # Send the packets again and ensure they are unchanged.
        self.send_and_verify_ip6(self.pg0, self.pg1, 1460, 1460)

    def test_tcp_mss_clamping_ip6_rx(self):
        """ IP6 TCP MSS Clamping RX """

        # enable the TCP MSS clamping feature to lower the MSS to 1424.
        self.vapi.mss_clamp_enable_disable(self.pg1.sw_if_index,
                                           ipv4_mss=0, ipv6_mss=1424,
                                           ipv4_direction=0, ipv6_direction=3)

        # Verify that the feature is enabled.
        rv, reply = self.vapi.mss_clamp_get(sw_if_index=self.pg1.sw_if_index)
        self.assertEqual(reply[0].ipv6_mss, 1424)
        self.assertEqual(reply[0].ipv6_direction, 3)

        # Send syn packets and verify that the MSS value is lowered.
        self.send_and_verify_ip6(self.pg1, self.pg0, 1460, 1424)

        # check the stats
        stats = self.statistics.get_counter(
            '/err/tcp-mss-clamping-ip6-in/clamped')
        self.assertEqual(sum(stats), 65)

        # Send syn packets with small enough MSS values and verify they are
        # unchanged.
        self.send_and_verify_ip6(self.pg1, self.pg0, 1400, 1400)

        # enable the the feature only in RX direction
        # and change the max MSS value
        self.vapi.mss_clamp_enable_disable(self.pg1.sw_if_index,
                                           ipv4_mss=0, ipv6_mss=1420,
                                           ipv4_direction=0, ipv6_direction=1)

        # Send syn packets and verify that the MSS value is lowered.
        self.send_and_verify_ip6(self.pg1, self.pg0, 1460, 1420)

        # enable the the feature only in TX direction
        self.vapi.mss_clamp_enable_disable(self.pg1.sw_if_index,
                                           ipv4_mss=0, ipv6_mss=1424,
                                           ipv4_direction=0, ipv6_direction=2)

        # Send the packets again and ensure they are unchanged.
        self.send_and_verify_ip6(self.pg1, self.pg0, 1460, 1460)

        # disable the feature
        self.vapi.mss_clamp_enable_disable(self.pg1.sw_if_index,
                                           ipv4_mss=0, ipv6_mss=0,
                                           ipv4_direction=0, ipv6_direction=0)

        # Send the packets again and ensure they are unchanged.
        self.send_and_verify_ip6(self.pg1, self.pg0, 1460, 1460)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
