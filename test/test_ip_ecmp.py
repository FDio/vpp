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
import random
import socket
from ipaddress import IPv4Address, IPv6Address, AddressValueError

from framework import VppTestCase, VppTestRunner
from util import ppp

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from vpp_ip_route import VppIpRoute, VppRoutePath

try:
    text_type = unicode
except NameError:
    text_type = str

#
# The number of packets to sent.
#
N_PKTS_IN_STREAM = 300


class TestECMP(VppTestCase):
    """ Equal-cost multi-path routing Test Case """

    @classmethod
    def setUpClass(cls):
        """
        Perform standard class setup (defined by class method setUpClass in
        class VppTestCase) before running the test case, set test case related
        variables and configure VPP.
        """
        super(TestECMP, cls).setUpClass()

        # create 4 pg interfaces
        cls.create_pg_interfaces(range(4))

        # packet sizes to test
        cls.pg_if_packet_sizes = [64, 1500, 9018]

        # setup interfaces
        for i in cls.pg_interfaces:
            i.admin_up()
            i.generate_remote_hosts(5)
            i.config_ip4()
            i.resolve_arp()
            i.configure_ipv4_neighbors()
            i.config_ip6()
            i.resolve_ndp()
            i.configure_ipv6_neighbors()

    @classmethod
    def tearDownClass(cls):
        if not cls.vpp_dead:
            for i in cls.pg_interfaces:
                i.unconfig_ip4()
                i.unconfig_ip6()
                i.admin_down()

        super(TestECMP, cls).tearDownClass()

    def setUp(self):
        super(TestECMP, self).setUp()
        self.reset_packet_infos()

    def tearDown(self):
        """
        Show various debug prints after each test.
        """
        super(TestECMP, self).tearDown()

    def show_commands_at_teardown(self):
        self.logger.info(self.vapi.ppcli("show ip4 neighbors"))
        self.logger.info(self.vapi.ppcli("show ip6 neighbors"))

    def get_ip_address(self, ip_addr_start, ip_prefix_len):
        """

        :param str ip_addr_start: Starting IPv4 or IPv6 address.
        :param int ip_prefix_len: IP address prefix length.
        :return: Random IPv4 or IPv6 address from required range.
        """
        try:
            ip_addr = IPv4Address(text_type(ip_addr_start))
            ip_max_len = 32
        except (AttributeError, AddressValueError):
            ip_addr = IPv6Address(text_type(ip_addr_start))
            ip_max_len = 128

        return str(ip_addr +
                   random.randint(0, 2 ** (ip_max_len - ip_prefix_len) - 2))

    def create_stream(self, src_if, src_ip_start, dst_ip_start,
                      ip_prefix_len, packet_sizes, ip_l=IP):
        """Create input packet stream for defined interfaces.

        :param VppInterface src_if: Source Interface for packet stream.
        :param str src_ip_start: Starting source IPv4 or IPv6 address.
        :param str dst_ip_start: Starting destination IPv4 or IPv6 address.
        :param int ip_prefix_len: IP address prefix length.
        :param list packet_sizes: packet size to test.
        :param Scapy ip_l: Required IP layer - IP or IPv6. (Default is IP.)
        """
        pkts = []
        for i in range(0, N_PKTS_IN_STREAM):
            info = self.create_packet_info(src_if, src_if)
            payload = self.info_to_payload(info)
            src_ip = self.get_ip_address(src_ip_start, ip_prefix_len)
            dst_ip = self.get_ip_address(dst_ip_start, ip_prefix_len)
            p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                 ip_l(src=src_ip, dst=dst_ip) /
                 UDP(sport=1234, dport=1234) /
                 Raw(payload))
            info.data = p.copy()
            size = random.choice(packet_sizes)
            self.extend_packet(p, size)
            pkts.append(p)
        return pkts

    def verify_capture(self, rx_if, capture, ip_l=IP):
        """Verify captured input packet stream for defined interface.

        :param VppInterface rx_if: Interface to verify captured packet stream.
        :param list capture: Captured packet stream.
        :param Scapy ip_l: Required IP layer - IP or IPv6. (Default is IP.)
        """
        self.logger.info("Verifying capture on interface %s" % rx_if.name)

        count = 0
        host_counters = {}
        for host_mac in rx_if._hosts_by_mac:
            host_counters[host_mac] = 0

        for packet in capture:
            try:
                ip_received = packet[ip_l]
                payload_info = self.payload_to_info(packet[Raw])
                packet_index = payload_info.index
                ip_sent = self._packet_infos[packet_index].data[ip_l]
                self.logger.debug("Got packet on port %s: src=%u (id=%u)" %
                                  (rx_if.name, payload_info.src, packet_index))
                # Check standard fields
                self.assertIn(packet.dst, rx_if._hosts_by_mac,
                              "Destination MAC address %s shouldn't be routed "
                              "via interface %s" % (packet.dst, rx_if.name))
                self.assertEqual(packet.src, rx_if.local_mac)
                self.assertEqual(ip_received.src, ip_sent.src)
                self.assertEqual(ip_received.dst, ip_sent.dst)
                host_counters[packet.dst] += 1
                self._packet_infos.pop(packet_index)

            except:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise

        # We expect packet routed via all host of pg interface
        for host_mac in host_counters:
            nr = host_counters[host_mac]
            self.assertNotEqual(
                nr, 0, "No packet routed via host %s" % host_mac)
            self.logger.info("%u packets routed via host %s of %s interface" %
                             (nr, host_mac, rx_if.name))
            count += nr
        self.logger.info("Total amount of %u packets routed via %s interface" %
                         (count, rx_if.name))

        return count

    def create_ip_routes(self, dst_ip_net, dst_prefix_len, is_ipv6=0):
        """
        Create IP routes for defined destination IP network.

        :param str dst_ip_net: Destination IP network.
        :param int dst_prefix_len: IP address prefix length.
        :param int is_ipv6: 0 if an ip4 route, else ip6
        """

        paths = []
        for pg_if in self.pg_interfaces[1:]:
            for nh_host in pg_if.remote_hosts:
                nh_host_ip = nh_host.ip4 if is_ipv6 == 0 else nh_host.ip6
                paths.append(VppRoutePath(nh_host_ip,
                                          pg_if.sw_if_index))

        rip = VppIpRoute(self, dst_ip_net, dst_prefix_len, paths)
        rip.add_vpp_config()
        self.logger.info("Route via %s on %s created" %
                         (nh_host_ip, pg_if.name))

        self.logger.debug(self.vapi.ppcli("show ip fib"))
        self.logger.debug(self.vapi.ppcli("show ip6 fib"))

    def test_ip_ecmp(self):
        """ IP equal-cost multi-path routing test """

        src_ip_net = '16.0.0.1'
        dst_ip_net = '32.0.0.1'
        ip_prefix_len = 24

        self.create_ip_routes(dst_ip_net, ip_prefix_len)

        pkts = self.create_stream(self.pg0, src_ip_net, dst_ip_net,
                                  ip_prefix_len, self.pg_if_packet_sizes)
        self.pg0.add_stream(pkts)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # We expect packets on pg1, pg2 and pg3, but not on pg0
        rx_count = 0
        for pg_if in self.pg_interfaces[1:]:
            capture = pg_if._get_capture(timeout=1)
            self.assertNotEqual(
                len(capture), 0, msg="No packets captured on %s" % pg_if.name)
            rx_count += self.verify_capture(pg_if, capture)
        self.pg0.assert_nothing_captured(remark="IP packets forwarded on pg0")

        # Check that all packets were forwarded via pg1, pg2 and pg3
        self.assertEqual(rx_count, len(pkts))

    def test_ip6_ecmp(self):
        """ IPv6 equal-cost multi-path routing test """

        src_ip_net = '3ffe:51::1'
        dst_ip_net = '3ffe:71::1'
        ip_prefix_len = 64

        self.create_ip_routes(dst_ip_net, ip_prefix_len, is_ipv6=1)

        pkts = self.create_stream(
            self.pg0, src_ip_net, dst_ip_net,
            ip_prefix_len, self.pg_if_packet_sizes, ip_l=IPv6)
        self.pg0.add_stream(pkts)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # We expect packets on pg1, pg2 and pg3, but not on pg0
        rx_count = 0
        for pg_if in self.pg_interfaces[1:]:
            capture = pg_if._get_capture(timeout=1)
            self.assertNotEqual(
                len(capture), 0, msg="No packets captured on %s" % pg_if.name)
            rx_count += self.verify_capture(pg_if, capture, ip_l=IPv6)
        self.pg0.assert_nothing_captured(remark="IP packets forwarded on pg0")

        # Check that all packets were forwarded via pg1, pg2 and pg3
        self.assertEqual(rx_count, len(pkts))


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
