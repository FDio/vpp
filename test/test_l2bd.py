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

from scapy.packet import Raw
from scapy.layers.l2 import Ether, Dot1Q
from scapy.layers.inet import IP, UDP

from framework import VppTestCase, VppTestRunner
from util import Host, ppp
from vpp_sub_interface import VppDot1QSubint, VppDot1ADSubint


class TestL2bd(VppTestCase):
    """ L2BD Test Case """

    @classmethod
    def setUpClass(cls):
        """
        Perform standard class setup (defined by class method setUpClass in
        class VppTestCase) before running the test case, set test case related
        variables and configure VPP.

        :var int bd_id: Bridge domain ID.
        :var int mac_entries_count: Number of MAC entries for bridge-domain to
            learn.
        :var int dot1q_tag: VLAN tag for dot1q sub-interface.
        :var int dot1ad_sub_id: SubID of dot1ad sub-interface.
        :var int dot1ad_outer_tag: VLAN S-tag for dot1ad sub-interface.
        :var int dot1ad_inner_tag: VLAN C-tag for dot1ad sub-interface.
        :var int sl_pkts_per_burst: Number of packets in burst for single-loop
            test.
        :var int dl_pkts_per_burst: Number of packets in burst for dual-loop
            test.
        """
        super(TestL2bd, cls).setUpClass()

        # Test variables
        cls.bd_id = 1
        cls.mac_entries_count = 100
        # cls.dot1q_sub_id = 100
        cls.dot1q_tag = 100
        cls.dot1ad_sub_id = 20
        cls.dot1ad_outer_tag = 200
        cls.dot1ad_inner_tag = 300
        cls.sl_pkts_per_burst = 2
        cls.dl_pkts_per_burst = 257

        try:
            # create 3 pg interfaces
            cls.create_pg_interfaces(range(3))

            # create 2 sub-interfaces for pg1 and pg2
            cls.sub_interfaces = [
                VppDot1QSubint(cls, cls.pg1, cls.dot1q_tag),
                VppDot1ADSubint(cls, cls.pg2, cls.dot1ad_sub_id,
                                cls.dot1ad_outer_tag, cls.dot1ad_inner_tag)]

            # packet flows mapping pg0 -> pg1, pg2, etc.
            cls.flows = dict()
            cls.flows[cls.pg0] = [cls.pg1, cls.pg2]
            cls.flows[cls.pg1] = [cls.pg0, cls.pg2]
            cls.flows[cls.pg2] = [cls.pg0, cls.pg1]

            # packet sizes
            cls.pg_if_packet_sizes = [64, 512, 1518, 9018]
            cls.sub_if_packet_sizes = [64, 512, 1518 + 4, 9018 + 4]

            cls.interfaces = list(cls.pg_interfaces)
            cls.interfaces.extend(cls.sub_interfaces)

            # Create BD with MAC learning enabled and put interfaces and
            #  sub-interfaces to this BD
            for pg_if in cls.pg_interfaces:
                sw_if_index = pg_if.sub_if.sw_if_index \
                    if hasattr(pg_if, 'sub_if') else pg_if.sw_if_index
                cls.vapi.sw_interface_set_l2_bridge(rx_sw_if_index=sw_if_index,
                                                    bd_id=cls.bd_id)

            # setup all interfaces
            for i in cls.interfaces:
                i.admin_up()

            # mapping between packet-generator index and lists of test hosts
            cls.hosts_by_pg_idx = dict()

            # create test host entries and inject packets to learn MAC entries
            # in the bridge-domain
            cls.create_hosts_and_learn(cls.mac_entries_count)
            cls.logger.info(cls.vapi.ppcli("show l2fib"))

        except Exception:
            super(TestL2bd, cls).tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        super(TestL2bd, cls).tearDownClass()

    def setUp(self):
        """
        Clear trace and packet infos before running each test.
        """
        super(TestL2bd, self).setUp()
        self.reset_packet_infos()

    def tearDown(self):
        """
        Show various debug prints after each test.
        """
        super(TestL2bd, self).tearDown()
        if not self.vpp_dead:
            self.logger.info(self.vapi.ppcli("show l2fib verbose"))
            self.logger.info(self.vapi.ppcli("show bridge-domain %s detail" %
                                             self.bd_id))

    @classmethod
    def create_hosts_and_learn(cls, count):
        """
        Create required number of host MAC addresses and distribute them among
        interfaces. Create host IPv4 address for every host MAC address. Create
        L2 MAC packet stream with host MAC addresses per interface to let
        the bridge domain learn these MAC addresses.

        :param count: Integer number of hosts to create MAC/IPv4 addresses for.
        """
        n_int = len(cls.pg_interfaces)
        macs_per_if = count // n_int
        i = -1
        for pg_if in cls.pg_interfaces:
            i += 1
            start_nr = macs_per_if * i
            end_nr = count if i == (n_int - 1) else macs_per_if * (i + 1)
            cls.hosts_by_pg_idx[pg_if.sw_if_index] = []
            hosts = cls.hosts_by_pg_idx[pg_if.sw_if_index]
            packets = []
            for j in range(start_nr, end_nr):
                host = Host(
                    "00:00:00:ff:%02x:%02x" % (pg_if.sw_if_index, j),
                    "172.17.1%02x.%u" % (pg_if.sw_if_index, j))
                packet = (Ether(dst="ff:ff:ff:ff:ff:ff", src=host.mac))
                hosts.append(host)
                if hasattr(pg_if, 'sub_if'):
                    packet = pg_if.sub_if.add_dot1_layer(packet)
                packets.append(packet)
            pg_if.add_stream(packets)
        cls.logger.info("Sending broadcast eth frames for MAC learning")
        cls.pg_start()

    def create_stream(self, src_if, packet_sizes, packets_per_burst):
        """
        Create input packet stream for defined interface.

        :param object src_if: Interface to create packet stream for.
        :param list packet_sizes: List of required packet sizes.
        :param int packets_per_burst: Number of packets in burst.
        :return: Stream of packets.
        """
        pkts = []
        for i in range(0, packets_per_burst):
            dst_if = self.flows[src_if][i % 2]
            dst_host = random.choice(self.hosts_by_pg_idx[dst_if.sw_if_index])
            src_host = random.choice(self.hosts_by_pg_idx[src_if.sw_if_index])
            pkt_info = self.create_packet_info(src_if, dst_if)
            payload = self.info_to_payload(pkt_info)
            p = (Ether(dst=dst_host.mac, src=src_host.mac) /
                 IP(src=src_host.ip4, dst=dst_host.ip4) /
                 UDP(sport=1234, dport=1234) /
                 Raw(payload))
            pkt_info.data = p.copy()
            if hasattr(src_if, 'sub_if'):
                p = src_if.sub_if.add_dot1_layer(p)
            size = random.choice(packet_sizes)
            self.extend_packet(p, size)
            pkts.append(p)
        return pkts

    def verify_capture(self, pg_if, capture):
        """
        Verify captured input packet stream for defined interface.

        :param object pg_if: Interface to verify captured packet stream for.
        :param list capture: Captured packet stream.
        """
        last_info = dict()
        for i in self.pg_interfaces:
            last_info[i.sw_if_index] = None
        dst_sw_if_index = pg_if.sw_if_index
        for packet in capture:
            payload_info = self.payload_to_info(packet[Raw])
            src_sw_if_index = payload_info.src
            src_if = None
            for ifc in self.pg_interfaces:
                if ifc != pg_if:
                    if ifc.sw_if_index == src_sw_if_index:
                        src_if = ifc
                        break
            if hasattr(src_if, 'sub_if'):
                # Check VLAN tags and Ethernet header
                packet = src_if.sub_if.remove_dot1_layer(packet)
            self.assertTrue(Dot1Q not in packet)
            try:
                ip = packet[IP]
                udp = packet[UDP]
                packet_index = payload_info.index
                self.assertEqual(payload_info.dst, dst_sw_if_index)
                self.logger.debug("Got packet on port %s: src=%u (id=%u)" %
                                  (pg_if.name, payload_info.src, packet_index))
                next_info = self.get_next_packet_info_for_interface2(
                    payload_info.src, dst_sw_if_index,
                    last_info[payload_info.src])
                last_info[payload_info.src] = next_info
                self.assertTrue(next_info is not None)
                self.assertEqual(packet_index, next_info.index)
                saved_packet = next_info.data
                # Check standard fields
                self.assertEqual(ip.src, saved_packet[IP].src)
                self.assertEqual(ip.dst, saved_packet[IP].dst)
                self.assertEqual(udp.sport, saved_packet[UDP].sport)
                self.assertEqual(udp.dport, saved_packet[UDP].dport)
            except:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise
        for i in self.pg_interfaces:
            remaining_packet = self.get_next_packet_info_for_interface2(
                i, dst_sw_if_index, last_info[i.sw_if_index])
            self.assertTrue(
                remaining_packet is None,
                "Port %u: Packet expected from source %u didn't arrive" %
                (dst_sw_if_index, i.sw_if_index))

    def run_l2bd_test(self, pkts_per_burst):
        """ L2BD MAC learning test """

        # Create incoming packet streams for packet-generator interfaces
        for i in self.pg_interfaces:
            packet_sizes = self.sub_if_packet_sizes if hasattr(i, 'sub_if') \
                else self.pg_if_packet_sizes
            pkts = self.create_stream(i, packet_sizes, pkts_per_burst)
            i.add_stream(pkts)

        # Enable packet capture and start packet sending
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Verify outgoing packet streams per packet-generator interface
        for i in self.pg_interfaces:
            capture = i.get_capture()
            self.logger.info("Verifying capture on interface %s" % i.name)
            self.verify_capture(i, capture)

    def test_l2bd_sl(self):
        """ L2BD MAC learning single-loop test

        Test scenario:
            1.config
                MAC learning enabled
                learn 100 MAC entries
                3 interfaces: untagged, dot1q, dot1ad (dot1q used instead of
                dot1ad in the first version)

            2.sending l2 eth pkts between 3 interface
                64B, 512B, 1518B, 9200B (ether_size)
                burst of 2 pkts per interface
        """

        self.run_l2bd_test(self.sl_pkts_per_burst)

    def test_l2bd_dl(self):
        """ L2BD MAC learning dual-loop test

         Test scenario:
            1.config
                MAC learning enabled
                learn 100 MAC entries
                3 interfaces: untagged, dot1q, dot1ad (dot1q used instead of
                dot1ad in the first version)

            2.sending l2 eth pkts between 3 interface
                64B, 512B, 1518B, 9200B (ether_size)
                burst of 257 pkts per interface
        """

        self.run_l2bd_test(self.dl_pkts_per_burst)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
