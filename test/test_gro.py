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
"""GRO functional tests"""

#
# Add tests for:
# - GRO
# - Verify that sending 1500 Bytes frame without GRO enabled correctly
# - Verify that sending 1500 Bytes frame with GRO enabled correctly
#
import unittest

from scapy.packet import Raw
from scapy.layers.inet6 import IPv6, Ether, IP, UDP, ICMPv6PacketTooBig
from scapy.layers.inet6 import ipv6nh, IPerror6
from scapy.layers.inet import TCP, ICMP
from scapy.data import ETH_P_IP, ETH_P_IPV6, ETH_P_ARP

from framework import VppTestCase, VppTestRunner
from vpp_object import VppObject
from vpp_interface import VppInterface


""" Test_gro is a subclass of VPPTestCase classes.
    GRO tests.
"""


class TestGRO(VppTestCase):
    """ GRO Test Case """

    @classmethod
    def setUpClass(self):
        super(TestGRO, self).setUpClass()
        res = self.create_pg_interfaces(range(2))
        res_gro = self.create_pg_interfaces(range(2, 3), 1, 1460)
        self.create_pg_interfaces(range(3, 4), 1, 8940)
        self.pg_interfaces.append(res[0])
        self.pg_interfaces.append(res[1])
        self.pg_interfaces.append(res_gro[0])
        self.pg2.coalesce_enable()
        self.pg3.coalesce_enable()

    @classmethod
    def tearDownClass(self):
        super(TestGRO, self).tearDownClass()

    def setUp(self):
        super(TestGRO, self).setUp()
        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.config_ip6()
            i.disable_ipv6_ra()
            i.resolve_arp()
            i.resolve_ndp()

    def tearDown(self):
        super(TestGRO, self).tearDown()
        if not self.vpp_dead:
            for i in self.pg_interfaces:
                i.unconfig_ip4()
                i.unconfig_ip6()
                i.admin_down()

    def test_gro(self):
        """ GRO test """

        n_packets = 124
        #
        # Send 1500 bytes frame with gro disabled
        #
        p4 = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
              IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4,
                 flags='DF') /
              TCP(sport=1234, dport=4321) /
              Raw(b'\xa5' * 1460))

        rxs = self.send_and_expect(self.pg0, n_packets * p4, self.pg1)
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg1.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg1.remote_mac)
            self.assertEqual(rx[IP].src, self.pg0.remote_ip4)
            self.assertEqual(rx[IP].dst, self.pg1.remote_ip4)
            self.assertEqual(rx[TCP].sport, 1234)
            self.assertEqual(rx[TCP].dport, 4321)

        #
        # Send 1500 bytes frame with gro enabled on
        # output interfaces support GRO
        #
        p = []
        s = 0
        for n in range(0, n_packets):
            p.append((Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
                      IP(src=self.pg0.remote_ip4, dst=self.pg2.remote_ip4,
                         flags='DF') /
                      TCP(sport=1234, dport=4321, seq=s, ack=n, flags='A') /
                      Raw(b'\xa5' * 1460)))
            s += 1460

        rxs = self.send_and_expect(self.pg0, p, self.pg2, n_rx=2)

        i = 0
        for rx in rxs:
            i += 1
            self.assertEqual(rx[Ether].src, self.pg2.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg2.remote_mac)
            self.assertEqual(rx[IP].src, self.pg0.remote_ip4)
            self.assertEqual(rx[IP].dst, self.pg2.remote_ip4)
            self.assertEqual(rx[IP].len, 64280)  # 1460 * 44 + 40 < 65536
            self.assertEqual(rx[TCP].sport, 1234)
            self.assertEqual(rx[TCP].dport, 4321)
            self.assertEqual(rx[TCP].ack, (44*i - 1))

        p4_temp = (Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac) /
                   IP(src=self.pg2.remote_ip4, dst=self.pg0.remote_ip4,
                      flags='DF') /
                   TCP(sport=1234, dport=4321, flags='F'))

        rxs = self.send_and_expect(self.pg2, 100*[p4_temp], self.pg0, n_rx=100)
        rx_coalesce = self.pg2.get_capture(1, timeout=1)

        rx0 = rx_coalesce[0]
        self.assertEqual(rx0[Ether].src, self.pg2.local_mac)
        self.assertEqual(rx0[Ether].dst, self.pg2.remote_mac)
        self.assertEqual(rx0[IP].src, self.pg0.remote_ip4)
        self.assertEqual(rx0[IP].dst, self.pg2.remote_ip4)
        self.assertEqual(rx0[IP].len, 52600)  # 1460 * 36 + 40
        self.assertEqual(rx0[TCP].sport, 1234)
        self.assertEqual(rx0[TCP].dport, 4321)

        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[IP].src, self.pg2.remote_ip4)
            self.assertEqual(rx[IP].dst, self.pg0.remote_ip4)
            self.assertEqual(rx[IP].len, 40)
            self.assertEqual(rx[TCP].sport, 1234)
            self.assertEqual(rx[TCP].dport, 4321)

        #
        # Same test with IPv6
        #
        p = []
        s = 0
        for n in range(0, 88):
            p.append((Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
                      IPv6(src=self.pg0.remote_ip6, dst=self.pg2.remote_ip6) /
                      TCP(sport=1234, dport=4321, seq=s, ack=n, flags='A') /
                      Raw(b'\xa5' * 1460)))
            s += 1460
        p[-1][TCP].flags = 'AP'  # push to flush second packet

        rxs = self.send_and_expect(self.pg0, p, self.pg2, n_rx=2)

        i = 0
        for rx in rxs:
            i += 1
            self.assertEqual(rx[Ether].src, self.pg2.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg2.remote_mac)
            self.assertEqual(rx[IPv6].src, self.pg0.remote_ip6)
            self.assertEqual(rx[IPv6].dst, self.pg2.remote_ip6)
            self.assertEqual(rx[IPv6].plen, 64260)  # 1460 * 44 + 20 < 65536
            self.assertEqual(rx[TCP].sport, 1234)
            self.assertEqual(rx[TCP].dport, 4321)
            self.assertEqual(rx[TCP].ack, (44*i - 1))

        #
        # Send a series of 1500 bytes packets each followed by a packet with a
        # PSH flag. Verify that GRO stops everytime a PSH flag is encountered
        #
        p = []
        s = 0
        for n in range(0, n_packets):
            p.append((Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
                      IP(src=self.pg0.remote_ip4, dst=self.pg2.remote_ip4,
                         flags='DF') /
                      TCP(sport=1234, dport=4321, seq=s, ack=2*n, flags='A') /
                      Raw(b'\xa5' * 1460)))
            s += 1460
            p.append((Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
                      IP(src=self.pg0.remote_ip4, dst=self.pg2.remote_ip4,
                         flags='DF') /
                      TCP(sport=1234, dport=4321, seq=s, ack=2*n+1,
                          flags='AP') /
                      Raw(b'\xa5' * 1340)))
            s += 1340

        rxs = self.send_and_expect(self.pg0, p, self.pg2, n_rx=n_packets)

        i = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg2.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg2.remote_mac)
            self.assertEqual(rx[IP].src, self.pg0.remote_ip4)
            self.assertEqual(rx[IP].dst, self.pg2.remote_ip4)
            self.assertEqual(rx[IP].len, 40 + 1460 + 1340)
            self.assertEqual(rx[TCP].sport, 1234)
            self.assertEqual(rx[TCP].dport, 4321)
            self.assertEqual(rx[TCP].ack, (2*i + 1))
            i += 1

        #
        # Send a series of 1500 bytes packets each followed by a short packet
        # with padding. Verify that GRO removes the padding and stops on short
        # packets
        #
        p = []
        s = 0
        for n in range(0, n_packets):
            i = self.pg0
            p.append((Ether(src=i.remote_mac, dst=i.local_mac) /
                      IP(src=i.remote_ip4, dst=self.pg2.remote_ip4,
                         flags='DF') /
                      TCP(sport=1234, dport=4321, seq=s, ack=2*n, flags='A') /
                      Raw(b'\xa5' * 1459)))
            s += 1459
            p2 = (Ether(src=i.remote_mac, dst=i.local_mac) /
                  IP(src=i.remote_ip4, dst=self.pg2.remote_ip4,
                     flags='DF', len=41) /
                  TCP(sport=1234, dport=4321, seq=s, ack=2*n+1, flags='A') /
                  Raw(b'\xa5'))
            # first compute csum of pkt w/o padding to work around scapy bug
            p2 = Ether(bytes(p2))
            p.append(p2 / Raw(b'\xa5' * 5))  # 1 byte data + 5 bytes padding
            s += 1

        rxs = self.send_and_expect(self.pg0, p, self.pg2, n_rx=n_packets)

        i = 0
        for rx in rxs:
            self.assertEqual(rx[Ether].src, self.pg2.local_mac)
            self.assertEqual(rx[Ether].dst, self.pg2.remote_mac)
            self.assertEqual(rx[IP].src, self.pg0.remote_ip4)
            self.assertEqual(rx[IP].dst, self.pg2.remote_ip4)
            self.assertEqual(rx[IP].len, 40 + 1459 + 1)
            self.assertEqual(rx[TCP].sport, 1234)
            self.assertEqual(rx[TCP].dport, 4321)
            self.assertEqual(rx[TCP].ack, (2*i + 1))
            i += 1


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
