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
"""L2BD Multi-instance Test Case HLD:

**NOTES:**
    - higher number of pg-l2 interfaces causes problems => only 15 pg-l2 \
    interfaces in 5 bridge domains are tested
    - jumbo packets in configuration with 14 l2-pg interfaces leads to \
    problems too

**config 1**
    - add 15 pg-l2 interfaces
    - configure one host per pg-l2 interface
    - configure 5 bridge domains (BD)
    - add 3 pg-l2 interfaces per BD

**test 1**
    - send L2 MAC frames between all pg-l2 interfaces of all BDs

**verify 1**
    - check BD data by parsing output of bridge_domain_dump API command
    - all packets received correctly

**config 2**
    - update data of 5 BD
        - disable learning, forwarding, flooding and uu_flooding for BD1
        - disable forwarding for BD2
        - disable flooding for BD3
        - disable uu_flooding for BD4
        - disable learning for BD5

**verify 2**
    - check BD data by parsing output of bridge_domain_dump API command

**config 3**
    - delete 2 BDs

**test 3**
    - send L2 MAC frames between all pg-l2 interfaces of all BDs
    - send L2 MAC frames between all pg-l2 interfaces formerly assigned to \
    deleted BDs

**verify 3**
    - check BD data by parsing output of bridge_domain_dump API command
    - all packets received correctly on all 3 pg-l2 interfaces assigned to BDs
    - no packet received on all 3 pg-l2 interfaces of all deleted BDs

**config 4**
    - add 2 BDs
    - add 3 pg-l2 interfaces per BD

**test 4**
    - send L2 MAC frames between all pg-l2 interfaces of all BDs

**verify 4**
    - check BD data by parsing output of bridge_domain_dump API command
    - all packets received correctly

**config 5**
    - delete 5 BDs

**verify 5**
    - check BD data by parsing output of bridge_domain_dump API command
"""

import unittest
import random

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP

from framework import VppTestCase, VppTestRunner, running_extended_tests
from util import Host, ppp


class TestL2bdMultiInst(VppTestCase):
    """ L2BD Multi-instance Test Case """

    @classmethod
    def setUpClass(cls):
        """
        Perform standard class setup (defined by class method setUpClass in
        class VppTestCase) before running the test case, set test case related
        variables and configure VPP.
        """
        super(TestL2bdMultiInst, cls).setUpClass()

        try:
            # Create pg interfaces
            n_bd = 5
            cls.ifs_per_bd = ifs_per_bd = 3
            n_ifs = n_bd * ifs_per_bd
            cls.create_pg_interfaces(range(n_ifs))

            # Packet flows mapping pg0 -> pg1, pg2 etc.
            cls.flows = dict()
            for b in range(n_bd):
                bd_ifs = cls.bd_if_range(b + 1)
                for j in bd_ifs:
                    cls.flows[cls.pg_interfaces[j]] = [
                        cls.pg_interfaces[x] for x in bd_ifs if x != j]
                    assert(
                        len(cls.flows[cls.pg_interfaces[j]]) == ifs_per_bd - 1)

            # Mapping between packet-generator index and lists of test hosts
            cls.hosts_by_pg_idx = dict()

            # Create test host entries
            cls.create_hosts(5)

            # Packet sizes - jumbo packet (9018 bytes) skipped
            cls.pg_if_packet_sizes = [64, 512, 1518]

            # Set up all interfaces
            for i in cls.pg_interfaces:
                i.admin_up()

        except Exception:
            super(TestL2bdMultiInst, cls).tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        super(TestL2bdMultiInst, cls).tearDownClass()

    def setUp(self):
        """
        Clear trace and packet infos before running each test.
        """
        self.reset_packet_infos()
        super(TestL2bdMultiInst, self).setUp()
        # Create list of BDs
        self.bd_list = []

        # Create list of deleted BDs
        self.bd_deleted_list = []

        # Create list of pg_interfaces in BDs
        self.pg_in_bd = []

    def tearDown(self):
        """
        Show various debug prints after each test.
        """
        super(TestL2bdMultiInst, self).tearDown()
        if not self.vpp_dead:
            self.logger.info(self.vapi.ppcli("show l2fib verbose"))
            self.logger.info(self.vapi.ppcli("show bridge-domain"))

    @classmethod
    def create_hosts(cls, hosts_per_if):
        """
        Create required number of host MAC addresses and distribute them
        among interfaces. Create host IPv4 address for every host MAC
        address.

        :param int hosts_per_if: Number of hosts per if to create MAC/IPv4
                                 addresses for.
        """
        c = hosts_per_if
        assert(not cls.hosts_by_pg_idx)
        for i in range(len(cls.pg_interfaces)):
            pg_idx = cls.pg_interfaces[i].sw_if_index
            cls.hosts_by_pg_idx[pg_idx] = [Host(
                "00:00:00:ff:%02x:%02x" % (pg_idx, j + 1),
                "172.17.1%02u.%u" % (pg_idx, j + 1)) for j in range(c)]

    @classmethod
    def bd_if_range(cls, b):
        n = cls.ifs_per_bd
        start = (b - 1) * n
        return range(start, start + n)

    def create_bd_and_mac_learn(self, count, start=1):
        """
        Create required number of bridge domains with MAC learning enabled,
        put 3 l2-pg interfaces to every bridge domain and send MAC learning
        packets.

        :param int count: Number of bridge domains to be created.
        :param int start: Starting number of the bridge domain ID.
            (Default value = 1)
        """
        for b in range(start, start + count):
            self.vapi.bridge_domain_add_del(bd_id=b)
            self.logger.info("Bridge domain ID %d created" % b)
            if self.bd_list.count(b) == 0:
                self.bd_list.append(b)
            if self.bd_deleted_list.count(b) == 1:
                self.bd_deleted_list.remove(b)
            for j in self.bd_if_range(b):
                pg_if = self.pg_interfaces[j]
                self.vapi.sw_interface_set_l2_bridge(
                    rx_sw_if_index=pg_if.sw_if_index, bd_id=b)
                self.logger.info("pg-interface %s added to bridge domain ID %d"
                                 % (pg_if.name, b))
                self.pg_in_bd.append(pg_if)
                hosts = self.hosts_by_pg_idx[pg_if.sw_if_index]
                packets = [Ether(dst="ff:ff:ff:ff:ff:ff", src=host.mac)
                           for host in hosts]
                pg_if.add_stream(packets)
        self.logger.info("Sending broadcast eth frames for MAC learning")
        self.pg_start()
        self.logger.info(self.vapi.ppcli("show bridge-domain"))
        self.logger.info(self.vapi.ppcli("show l2fib"))

    def delete_bd(self, count, start=1):
        """
        Delete required number of bridge domains.

        :param int count: Number of bridge domains to be created.
        :param int start: Starting number of the bridge domain ID.
            (Default value = 1)
        """
        for b in range(start, start + count):
            for j in self.bd_if_range(b):
                pg_if = self.pg_interfaces[j]
                self.vapi.sw_interface_set_l2_bridge(
                    rx_sw_if_index=pg_if.sw_if_index, bd_id=b, enable=0)
                self.pg_in_bd.remove(pg_if)
            self.vapi.bridge_domain_add_del(bd_id=b, is_add=0)
            self.bd_list.remove(b)
            self.bd_deleted_list.append(b)
            self.logger.info("Bridge domain ID %d deleted" % b)

    def create_stream(self, src_if):
        """
        Create input packet stream for defined interface using hosts list.

        :param object src_if: Interface to create packet stream for.
        :param list packet_sizes: List of required packet sizes.
        :return: Stream of packets.
        """
        packet_sizes = self.pg_if_packet_sizes
        pkts = []
        src_hosts = self.hosts_by_pg_idx[src_if.sw_if_index]
        for dst_if in self.flows[src_if]:
            dst_hosts = self.hosts_by_pg_idx[dst_if.sw_if_index]
            for dst_host in dst_hosts:
                pkt_info = self.create_packet_info(src_if, dst_if)
                payload = self.info_to_payload(pkt_info)
                src_host = random.choice(src_hosts)
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

    def verify_capture(self, dst_if):
        """
        Verify captured input packet stream for defined interface.

        :param object dst_if: Interface to verify captured packet stream for.
        """
        last_info = dict()
        for i in self.flows[dst_if]:
            last_info[i.sw_if_index] = None
        dst = dst_if.sw_if_index
        for packet in dst_if.get_capture():
            try:
                ip = packet[IP]
                udp = packet[UDP]
                info = self.payload_to_info(packet[Raw])
                self.assertEqual(info.dst, dst)
                self.logger.debug("Got packet on port %s: src=%u (id=%u)" %
                                  (dst_if.name, info.src, info.index))
                last_info[info.src] = self.get_next_packet_info_for_interface2(
                    info.src, dst, last_info[info.src])
                pkt_info = last_info[info.src]
                self.assertTrue(pkt_info is not None)
                self.assertEqual(info.index, pkt_info.index)
                # Check standard fields against saved data in pkt
                saved = pkt_info.data
                self.assertEqual(ip.src, saved[IP].src)
                self.assertEqual(ip.dst, saved[IP].dst)
                self.assertEqual(udp.sport, saved[UDP].sport)
                self.assertEqual(udp.dport, saved[UDP].dport)
            except:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise
        s = ""
        remaining = 0
        for src in self.flows[dst_if]:
            remaining_packet = self.get_next_packet_info_for_interface2(
                src.sw_if_index, dst, last_info[src.sw_if_index])
            if remaining_packet is None:
                s += "Port %u: Packet expected from source %u didn't arrive\n"\
                     % (dst, src.sw_if_index)
                remaining += 1
            self.assertNotEqual(0, remaining, s)

    def set_bd_flags(self, bd_id, **args):
        """
        Enable/disable defined feature(s) of the bridge domain.

        :param int bd_id: Bridge domain ID.
        :param list args: List of feature/status pairs. Allowed features: \
        learn, forward, flood, uu_flood and arp_term. Status False means \
        disable, status True means enable the feature.
        :raise: ValueError in case of unknown feature in the input.
        """
        for flag in args:
            if flag == "learn":
                feature_bitmap = 1 << 0
            elif flag == "forward":
                feature_bitmap = 1 << 1
            elif flag == "flood":
                feature_bitmap = 1 << 2
            elif flag == "uu_flood":
                feature_bitmap = 1 << 3
            elif flag == "arp_term":
                feature_bitmap = 1 << 4
            else:
                raise ValueError("Unknown feature used: %s" % flag)
            is_set = 1 if args[flag] else 0
            self.vapi.bridge_flags(bd_id=bd_id, is_set=is_set,
                                   flags=feature_bitmap)
        self.logger.info("Bridge domain ID %d updated" % bd_id)

    def verify_bd(self, bd_id, **args):
        """
        Check if the bridge domain is configured and verify expected status
        of listed features.

        :param int bd_id: Bridge domain ID.
        :param list args: List of feature/status pairs. Allowed features: \
        learn, forward, flood, uu_flood and arp_term. Status False means \
        disable, status True means enable the feature.
        :return: 1 if bridge domain is configured, otherwise return 0.
        :raise: ValueError in case of unknown feature in the input.
        """
        bd_dump = self.vapi.bridge_domain_dump(bd_id)
        if len(bd_dump) == 0:
            self.logger.info("Bridge domain ID %d is not configured" % bd_id)
            return 0
        else:
            bd_dump = bd_dump[0]
            if len(args) > 0:
                for flag in args:
                    expected_status = 1 if args[flag] else 0
                    if flag == "learn":
                        flag_status = bd_dump[6]
                    elif flag == "forward":
                        flag_status = bd_dump[5]
                    elif flag == "flood":
                        flag_status = bd_dump[3]
                    elif flag == "uu_flood":
                        flag_status = bd_dump[4]
                    elif flag == "arp_term":
                        flag_status = bd_dump[7]
                    else:
                        raise ValueError("Unknown feature used: %s" % flag)
                    self.assertEqual(expected_status, flag_status)
            return 1

    def run_verify_test(self):
        """
        Create packet streams for all configured l2-pg interfaces, send all \
        prepared packet streams and verify that:
            - all packets received correctly on all pg-l2 interfaces assigned
              to bridge domains
            - no packet received on all pg-l2 interfaces not assigned to
              bridge domains

        :raise RuntimeError: if no packet captured on l2-pg interface assigned
                             to the bridge domain or if any packet is captured
                             on l2-pg interface not assigned to the bridge
                             domain.
        """
        # Test
        # Create incoming packet streams for packet-generator interfaces
        # for pg_if in self.pg_interfaces:
        assert(len(self._packet_count_for_dst_if_idx) == 0)
        for pg_if in self.pg_in_bd:
            pkts = self.create_stream(pg_if)
            pg_if.add_stream(pkts)

        # Enable packet capture and start packet sending
        self.pg_enable_capture(self.pg_in_bd)
        self.pg_start()

        # Verify
        # Verify outgoing packet streams per packet-generator interface
        for pg_if in self.pg_in_bd:
            self.verify_capture(pg_if)

    def test_l2bd_inst_01(self):
        """ L2BD Multi-instance test 1 - create 5 BDs
        """
        # Config 1
        # Create 5 BDs, put interfaces to these BDs and send MAC learning
        # packets
        self.create_bd_and_mac_learn(5)

        # Verify 1
        for bd_id in self.bd_list:
            self.assertEqual(self.verify_bd(bd_id), 1)

        # Test 1
        # self.vapi.cli("clear trace")
        self.run_verify_test()
        self.delete_bd(5)

    def test_l2bd_inst_02(self):
        """ L2BD Multi-instance test 2 - update data of 5 BDs
        """
        # Config 2
        # Update data of 5 BDs (disable learn, forward, flood, uu-flood)
        self.create_bd_and_mac_learn(5)
        self.set_bd_flags(self.bd_list[0], learn=False, forward=False,
                          flood=False, uu_flood=False)
        self.set_bd_flags(self.bd_list[1], forward=False)
        self.set_bd_flags(self.bd_list[2], flood=False)
        self.set_bd_flags(self.bd_list[3], uu_flood=False)
        self.set_bd_flags(self.bd_list[4], learn=False)

        # Verify 2
        # Skipping check of uu_flood as it is not returned by
        # bridge_domain_dump api command
        self.verify_bd(self.bd_list[0], learn=False, forward=False,
                       flood=False, uu_flood=False)
        self.verify_bd(self.bd_list[1], learn=True, forward=False,
                       flood=True, uu_flood=True)
        self.verify_bd(self.bd_list[2], learn=True, forward=True,
                       flood=False, uu_flood=True)
        self.verify_bd(self.bd_list[3], learn=True, forward=True,
                       flood=True, uu_flood=False)
        self.verify_bd(self.bd_list[4], learn=False, forward=True,
                       flood=True, uu_flood=True)
        self.delete_bd(5)

    def test_l2bd_inst_03(self):
        """ L2BD Multi-instance test 3 - delete 2 BDs
        """
        # Config 3
        # Delete 2 BDs
        self.create_bd_and_mac_learn(5)
        self.delete_bd(2)

        # Verify 3
        for bd_id in self.bd_deleted_list:
            self.assertEqual(self.verify_bd(bd_id), 0)
        for bd_id in self.bd_list:
            self.assertEqual(self.verify_bd(bd_id), 1)

        # Test 3
        self.run_verify_test()
        self.delete_bd(3, 3)

    def test_l2bd_inst_04(self):
        """ L2BD Multi-instance test 4 - add 2 BDs
        """
        # Config 4
        # Create 5 BDs, put interfaces to these BDs and send MAC learning
        # packets
        self.create_bd_and_mac_learn(2)

        # Verify 4
        for bd_id in self.bd_list:
            self.assertEqual(self.verify_bd(bd_id), 1)

        # Test 4
        # self.vapi.cli("clear trace")
        self.run_verify_test()
        self.delete_bd(2)

    def test_l2bd_inst_05(self):
        """ L2BD Multi-instance test 5 - delete 5 BDs
        """
        # Config 5
        # Delete 5 BDs
        self.create_bd_and_mac_learn(5)
        self.delete_bd(5)

        # Verify 5
        for bd_id in self.bd_deleted_list:
            self.assertEqual(self.verify_bd(bd_id), 0)
        for bd_id in self.bd_list:
            self.assertEqual(self.verify_bd(bd_id), 1)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
