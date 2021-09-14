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
"""L2XC Multi-instance Test Case HLD:

**NOTES:**
    - higher number (more than 15) of pg-l2 interfaces causes problems => only
      14 pg-l2 interfaces and 10 cross-connects are tested
    - jumbo packets in configuration with 14 l2-pg interfaces leads to
      problems too

**config 1**
    - add 14 pg-l2 interfaces
    - add 10 cross-connects (two cross-connects per pair of l2-pg interfaces)

**test 1**
    - send L2 MAC frames between all pairs of pg-l2 interfaces

**verify 1**
    - all packets received correctly in case of cross-connected l2-pg
      interfaces
    - no packet received in case of not cross-connected l2-pg interfaces

**config 2**
    - delete 4 cross-connects

**test 2**
    - send L2 MAC frames between all pairs of pg-l2 interfaces

**verify 2**
    - all packets received correctly in case of cross-connected l2-pg
      interfaces
    - no packet received in case of not cross-connected l2-pg interfaces

**config 3**
    - add new 4 cross-connects

**test 3**
    - send L2 MAC frames between all pairs of pg-l2 interfaces

**verify 3**
    - all packets received correctly in case of cross-connected l2-pg
      interfaces
    - no packet received in case of not cross-connected l2-pg interfaces

**config 4**
    - delete 10 cross-connects

**test 4**
    - send L2 MAC frames between all pairs of pg-l2 interfaces

**verify 4**
    - no packet received on all of l2-pg interfaces (no cross-connect created)
"""

import unittest
import random

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP

from framework import VppTestCase, VppTestRunner
from util import Host, ppp


class TestL2xcMultiInst(VppTestCase):
    """ L2XC Multi-instance Test Case """

    @classmethod
    def setUpClass(cls):
        """
        Perform standard class setup (defined by class method setUpClass in
        class VppTestCase) before running the test case, set test case related
        variables and configure VPP.
        """
        super(TestL2xcMultiInst, cls).setUpClass()

        try:
            # Create pg interfaces
            cls.create_pg_interfaces(range(14))

            # Packet flows mapping pg0 -> pg1 etc.
            cls.flows = dict()
            for i in range(len(cls.pg_interfaces)):
                delta = 1 if i % 2 == 0 else -1
                cls.flows[cls.pg_interfaces[i]] =\
                    [cls.pg_interfaces[i + delta]]

            # Mapping between packet-generator index and lists of test hosts
            cls.hosts_by_pg_idx = dict()
            for pg_if in cls.pg_interfaces:
                cls.hosts_by_pg_idx[pg_if.sw_if_index] = []

            # Create test host entries
            cls.create_hosts(70)

            # Packet sizes - jumbo packet (9018 bytes) skipped
            cls.pg_if_packet_sizes = [64, 512, 1518]

            # Set up all interfaces
            for i in cls.pg_interfaces:
                i.admin_up()

            # Create list of x-connected pg_interfaces
            cls.pg_in_xc = list()

            # Create list of not x-connected pg_interfaces
            cls.pg_not_in_xc = list()
            for pg_if in cls.pg_interfaces:
                cls.pg_not_in_xc.append(pg_if)

        except Exception:
            super(TestL2xcMultiInst, cls).tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        super(TestL2xcMultiInst, cls).tearDownClass()

    def setUp(self):
        """
        Clear trace and packet infos before running each test.
        """
        super(TestL2xcMultiInst, self).setUp()
        self.reset_packet_infos()

    def tearDown(self):
        """
        Show various debug prints after each test.
        """
        super(TestL2xcMultiInst, self).tearDown()

    def show_commands_at_teardown(self):
        self.logger.info(self.vapi.ppcli("show l2patch"))

    @classmethod
    def create_hosts(cls, count):
        """
        Create required number of host MAC addresses and distribute them among
        interfaces. Create host IPv4 address for every host MAC address.

        :param int count: Number of hosts to create MAC/IPv4 addresses for.
        """
        n_int = len(cls.pg_interfaces)
        macs_per_if = count // n_int
        i = -1
        for pg_if in cls.pg_interfaces:
            i += 1
            start_nr = macs_per_if * i
            end_nr = count if i == (n_int - 1) else macs_per_if * (i + 1)
            hosts = cls.hosts_by_pg_idx[pg_if.sw_if_index]
            for j in range(start_nr, end_nr):
                host = Host(
                    "00:00:00:ff:%02x:%02x" % (pg_if.sw_if_index, j),
                    "172.17.1%02u.%u" % (pg_if.sw_if_index, j))
                hosts.append(host)

    def create_xconnects(self, count, start=0):
        """
        Create required number of cross-connects (always two cross-connects per
        pair of packet-generator interfaces).

        :param int count: Number of cross-connects to be created.
        :param int start: Starting index of packet-generator interfaces. \
        (Default value = 0)
        """
        for i in range(count):
            rx_if = self.pg_interfaces[i + start]
            delta = 1 if i % 2 == 0 else -1
            tx_if = self.pg_interfaces[i + start + delta]
            self.vapi.sw_interface_set_l2_xconnect(rx_if.sw_if_index,
                                                   tx_if.sw_if_index, 1)
            self.logger.info("Cross-connect from %s to %s created"
                             % (tx_if.name, rx_if.name))
            if self.pg_in_xc.count(rx_if) == 0:
                self.pg_in_xc.append(rx_if)
            if self.pg_not_in_xc.count(rx_if) == 1:
                self.pg_not_in_xc.remove(rx_if)

    def delete_xconnects(self, count, start=0):
        """
        Delete required number of cross-connects (always two cross-connects per
        pair of packet-generator interfaces).

        :param int count: Number of cross-connects to be deleted.
        :param int start: Starting index of packet-generator interfaces. \
        (Default value = 0)
        """
        for i in range(count):
            rx_if = self.pg_interfaces[i + start]
            delta = 1 if i % 2 == 0 else -1
            tx_if = self.pg_interfaces[i + start + delta]
            self.vapi.sw_interface_set_l2_xconnect(rx_if.sw_if_index,
                                                   tx_if.sw_if_index, 0)
            self.logger.info("Cross-connect from %s to %s deleted"
                             % (tx_if.name, rx_if.name))
            if self.pg_not_in_xc.count(rx_if) == 0:
                self.pg_not_in_xc.append(rx_if)
            if self.pg_in_xc.count(rx_if) == 1:
                self.pg_in_xc.remove(rx_if)

    def create_stream(self, src_if, packet_sizes):
        """
        Create input packet stream for defined interface using hosts list.

        :param object src_if: Interface to create packet stream for.
        :param list packet_sizes: List of required packet sizes.
        :return: Stream of packets.
        """
        pkts = []
        src_hosts = self.hosts_by_pg_idx[src_if.sw_if_index]
        for dst_if in self.flows[src_if]:
            dst_hosts = self.hosts_by_pg_idx[dst_if.sw_if_index]
            n_int = len(dst_hosts)
            for i in range(0, n_int):
                dst_host = dst_hosts[i]
                src_host = random.choice(src_hosts)
                pkt_info = self.create_packet_info(src_if, dst_if)
                payload = self.info_to_payload(pkt_info)
                p = (Ether(dst=dst_host.mac, src=src_host.mac) /
                     IP(src=src_host.ip4, dst=dst_host.ip4) /
                     UDP(sport=1234, dport=1234) /
                     Raw(payload))
                pkt_info.data = p.copy()
                size = random.choice(packet_sizes)
                self.extend_packet(p, size)
                pkts.append(p)
        self.logger.debug("Input stream created for port %s. Length: %u pkt(s)"
                          % (src_if.name, len(pkts)))
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

    def run_verify_test(self):
        """
        Create packet streams for all configured l2-pg interfaces, send all \
        prepared packet streams and verify that:
            - all packets received correctly on all pg-l2 interfaces assigned
              to cross-connects
            - no packet received on all pg-l2 interfaces not assigned to
              cross-connects

        :raise RuntimeError: if no packet captured on l2-pg interface assigned
                             to the cross-connect or if any packet is captured
                             on l2-pg interface not assigned to the
                             cross-connect.
        """
        # Test
        # Create incoming packet streams for packet-generator interfaces
        for pg_if in self.pg_interfaces:
            pkts = self.create_stream(pg_if, self.pg_if_packet_sizes)
            pg_if.add_stream(pkts)

        # Enable packet capture and start packet sending
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Verify
        # Verify outgoing packet streams per packet-generator interface
        for pg_if in self.pg_interfaces:
            if pg_if in self.pg_in_xc:
                capture = pg_if.get_capture(
                    remark="interface is a cross-connect sink")
                self.verify_capture(pg_if, capture)
            elif pg_if in self.pg_not_in_xc:
                pg_if.assert_nothing_captured(
                    remark="interface is not a cross-connect sink")
            else:
                raise Exception("Unexpected interface: %s" % pg_if.name)

    def test_l2xc_inst_01(self):
        """ L2XC Multi-instance test 1 - create 10 cross-connects
        """
        # Config 1
        # Create 10 cross-connects
        self.create_xconnects(10)

        # Test 1
        self.run_verify_test()

    def test_l2xc_inst_02(self):
        """ L2XC Multi-instance test 2 - delete 4 cross-connects
        """
        # Config 2
        # Delete 4 cross-connects
        self.delete_xconnects(4)

        # Test 2
        self.run_verify_test()

    def test_l2xc_inst_03(self):
        """ L2BD Multi-instance 3 - add new 4 cross-connects
        """
        # Config 3
        # Add new 4 cross-connects
        self.create_xconnects(4, start=10)

        # Test 3
        self.run_verify_test()

    def test_l2xc_inst_04(self):
        """ L2XC Multi-instance test 4 - delete 10 cross-connects
        """
        # Config 4
        # Delete 10 cross-connects
        self.delete_xconnects(10, start=4)

        # Test 4
        self.run_verify_test()


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
