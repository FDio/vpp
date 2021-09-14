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
"""IP4 VRF Multi-instance Test Case HLD:

**NOTES:**
    - higher number of pg-ip4 interfaces causes problems => only 15 pg-ip4 \
      interfaces in 5 VRFs are tested
    - jumbo packets in configuration with 15 pg-ip4 interfaces leads to \
      problems too

**config 1**
    - add 15 pg-ip4 interfaces
    - configure 5 hosts per pg-ip4 interface
    - configure 4 VRFs
    - add 3 pg-ip4 interfaces per VRF

**test 1**
    - send IP4 packets between all pg-ip4 interfaces in all VRF groups

**verify 1**
    - check VRF data by parsing output of ip_fib_dump API command
    - all packets received correctly in case of pg-ip4 interfaces in the
      same VRF
    - no packet received in case of pg-ip4 interfaces not in VRF
    - no packet received in case of pg-ip4 interfaces in different VRFs

**config 2**
    - reset 2 VRFs

**test 2**
    - send IP4 packets between all pg-ip4 interfaces in all VRF groups

**verify 2**
    - all packets received correctly in case of pg-ip4 interfaces in the
      same VRF
    - no packet received in case of pg-ip4 interfaces not in VRF
    - no packet received in case of pg-ip4 interfaces in different VRFs

**config 3**
    - add 1 of reset VRFs and 1 new VRF

**test 3**
    - send IP4 packets between all pg-ip4 interfaces in all VRF groups

**verify 3**
    - check VRF data by parsing output of ip_fib_dump API command
    - all packets received correctly in case of pg-ip4 interfaces in the
      same VRF
    - no packet received in case of pg-ip4 interfaces not in VRF
    - no packet received in case of pg-ip4 interfaces in different VRFs

**config 4**
    - reset all created VRFs

**test 4**
    - send IP4 packets between all pg-ip4 interfaces in all VRF groups

**verify 4**
    - check VRF data by parsing output of ip_fib_dump API command
    - all packets received correctly in case of pg-ip4 interfaces in the
      same VRF
    - no packet received in case of pg-ip4 interfaces not in VRF
    - no packet received in case of pg-ip4 interfaces in different VRFs
"""

import unittest
import random
import socket

import scapy.compat
from scapy.packet import Raw
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, UDP

from framework import VppTestCase, VppTestRunner
from util import ppp
from vrf import VRFState


def is_ipv4_misc(p):
    """ Is packet one of uninteresting IPv4 broadcasts? """
    if p.haslayer(ARP):
        return True
    return False


class TestIp4VrfMultiInst(VppTestCase):
    """ IP4 VRF  Multi-instance Test Case """

    @classmethod
    def setUpClass(cls):
        """
        Perform standard class setup (defined by class method setUpClass in
        class VppTestCase) before running the test case, set test case related
        variables and configure VPP.
        """
        super(TestIp4VrfMultiInst, cls).setUpClass()

        # Test variables
        cls.hosts_per_pg = 5
        cls.nr_of_vrfs = 5
        cls.pg_ifs_per_vrf = 3

        try:
            # Create pg interfaces
            cls.create_pg_interfaces(
                range(cls.nr_of_vrfs * cls.pg_ifs_per_vrf))

            # Packet flows mapping pg0 -> pg1, pg2 etc.
            cls.flows = dict()
            for i in range(len(cls.pg_interfaces)):
                multiplicand = i // cls.pg_ifs_per_vrf
                pg_list = [
                    cls.pg_interfaces[multiplicand * cls.pg_ifs_per_vrf + j]
                    for j in range(cls.pg_ifs_per_vrf)
                    if (multiplicand * cls.pg_ifs_per_vrf + j) != i]
                cls.flows[cls.pg_interfaces[i]] = pg_list

            # Packet sizes - jumbo packet (9018 bytes) skipped
            cls.pg_if_packet_sizes = [64, 512, 1518]

            # Set up all interfaces
            for pg_if in cls.pg_interfaces:
                pg_if.admin_up()
                pg_if.generate_remote_hosts(cls.hosts_per_pg)

            # Create list of VRFs
            cls.vrf_list = list()

            # Create list of reset VRFs
            cls.vrf_reset_list = list()

            # Create list of pg_interfaces in VRFs
            cls.pg_in_vrf = list()

            # Create list of pg_interfaces not in VRFs
            cls.pg_not_in_vrf = [pg_if for pg_if in cls.pg_interfaces]

            # Create mapping of pg_interfaces to VRF IDs
            cls.pg_if_sets = dict()
            for i in range(cls.nr_of_vrfs):
                set_id = i + 1
                pg_list = [
                    cls.pg_interfaces[i * cls.pg_ifs_per_vrf + j]
                    for j in range(cls.pg_ifs_per_vrf)]
                cls.pg_if_sets[set_id] = pg_list

        except Exception:
            super(TestIp4VrfMultiInst, cls).tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        super(TestIp4VrfMultiInst, cls).tearDownClass()

    def setUp(self):
        """
        Clear trace and packet infos before running each test.
        """
        super(TestIp4VrfMultiInst, self).setUp()
        self.reset_packet_infos()

    def tearDown(self):
        """
        Show various debug prints after each test.
        """
        super(TestIp4VrfMultiInst, self).tearDown()

    def show_commands_at_teardown(self):
        self.logger.info(self.vapi.ppcli("show ip fib"))
        self.logger.info(self.vapi.ppcli("show ip4 neighbors"))

    def _assign_interfaces(self, vrf_id, if_set_id):
        for i in range(self.pg_ifs_per_vrf):
            pg_if = self.pg_if_sets[if_set_id][i]
            pg_if.set_table_ip4(vrf_id)
            self.logger.info("pg-interface %s added to IPv4 VRF ID %d"
                             % (pg_if.name, vrf_id))
            if pg_if not in self.pg_in_vrf:
                self.pg_in_vrf.append(pg_if)
            if pg_if in self.pg_not_in_vrf:
                self.pg_not_in_vrf.remove(pg_if)
            pg_if.config_ip4()
            pg_if.configure_ipv4_neighbors()

    def create_vrf_and_assign_interfaces(self, count, start=1):
        """
        Create required number of FIB tables / VRFs, put 3 pg-ip4 interfaces
        to every FIB table / VRF.

        :param int count: Number of FIB tables / VRFs to be created.
        :param int start: Starting number of the FIB table / VRF ID. \
        (Default value = 1)
        """

        for i in range(count):
            vrf_id = i + start
            self.vapi.ip_table_add_del(is_add=1, table={'table_id': vrf_id})
            self.logger.info("IPv4 VRF ID %d created" % vrf_id)
            if vrf_id not in self.vrf_list:
                self.vrf_list.append(vrf_id)
            if vrf_id in self.vrf_reset_list:
                self.vrf_reset_list.remove(vrf_id)
            self._assign_interfaces(vrf_id, vrf_id)
        self.logger.debug(self.vapi.ppcli("show ip fib"))
        self.logger.debug(self.vapi.ppcli("show ip4 neighbors"))

    def create_vrf_by_id_and_assign_interfaces(self, set_id,
                                               vrf_id=0xffffffff):
        """
        Create a FIB table / VRF by vrf_id, put 3 pg-ip4 interfaces
        to FIB table / VRF.

        :param int vrf_id: Required table ID / VRF ID. \
        (Default value = 0xffffffff, ID will be selected automatically)
        """
        ret = self.vapi.ip_table_allocate(table={'table_id': vrf_id})
        vrf_id = ret.table.table_id
        self.logger.info("IPv4 VRF ID %d created" % vrf_id)
        if vrf_id not in self.vrf_list:
            self.vrf_list.append(vrf_id)
        if vrf_id in self.vrf_reset_list:
            self.vrf_reset_list.remove(vrf_id)
        self._assign_interfaces(vrf_id, set_id)
        self.logger.debug(self.vapi.ppcli("show ip fib"))
        self.logger.debug(self.vapi.ppcli("show ip4 neighbors"))

        return vrf_id

    def reset_vrf_and_remove_from_vrf_list(self, vrf_id, if_set_id=None):
        """
        Reset required FIB table / VRF and remove it from VRF list.

        :param int vrf_id: The FIB table / VRF ID to be reset.
        """
        if if_set_id is None:
            if_set_id = vrf_id
        self.vapi.ip_table_flush(table={'table_id': vrf_id})
        if vrf_id in self.vrf_list:
            self.vrf_list.remove(vrf_id)
        if vrf_id not in self.vrf_reset_list:
            self.vrf_reset_list.append(vrf_id)
        for j in range(self.pg_ifs_per_vrf):
            pg_if = self.pg_if_sets[if_set_id][j]
            pg_if.unconfig_ip4()
            if pg_if in self.pg_in_vrf:
                self.pg_in_vrf.remove(pg_if)
            if pg_if not in self.pg_not_in_vrf:
                self.pg_not_in_vrf.append(pg_if)
        self.logger.info("IPv4 VRF ID %d reset finished" % vrf_id)
        self.logger.debug(self.vapi.ppcli("show ip fib"))
        self.logger.debug(self.vapi.ppcli("show ip neighbors"))
        self.vapi.ip_table_add_del(is_add=0, table={'table_id': vrf_id})

    def create_stream(self, src_if, packet_sizes):
        """
        Create input packet stream for defined interface using hosts list.

        :param object src_if: Interface to create packet stream for.
        :param list packet_sizes: List of required packet sizes.
        :return: Stream of packets.
        """
        pkts = []
        src_hosts = src_if.remote_hosts
        for dst_if in self.flows[src_if]:
            for dst_host in dst_if.remote_hosts:
                src_host = random.choice(src_hosts)
                pkt_info = self.create_packet_info(src_if, dst_if)
                payload = self.info_to_payload(pkt_info)
                p = (Ether(dst=src_if.local_mac, src=src_host.mac) /
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

    def create_stream_crosswise_vrf(self, src_if, vrf_id, packet_sizes):
        """
        Create input packet stream for negative test for leaking across
        different VRFs for defined interface using hosts list.

        :param object src_if: Interface to create packet stream for.
        :param int vrf_id: The FIB table / VRF ID where src_if is assigned.
        :param list packet_sizes: List of required packet sizes.
        :return: Stream of packets.
        """
        pkts = []
        src_hosts = src_if.remote_hosts
        vrf_lst = list(self.vrf_list)
        vrf_lst.remove(vrf_id)
        for vrf in vrf_lst:
            for dst_if in self.pg_if_sets[vrf]:
                for dst_host in dst_if.remote_hosts:
                    src_host = random.choice(src_hosts)
                    pkt_info = self.create_packet_info(src_if, dst_if)
                    payload = self.info_to_payload(pkt_info)
                    p = (Ether(dst=src_if.local_mac, src=src_host.mac) /
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
            try:
                ip = packet[IP]
                udp = packet[UDP]
                payload_info = self.payload_to_info(packet[Raw])
                packet_index = payload_info.index
                self.assertEqual(payload_info.dst, dst_sw_if_index)
                self.logger.debug("Got packet on port %s: src=%u (id=%u)" %
                                  (pg_if.name, payload_info.src, packet_index))
                next_info = self.get_next_packet_info_for_interface2(
                    payload_info.src, dst_sw_if_index,
                    last_info[payload_info.src])
                last_info[payload_info.src] = next_info
                self.assertIsNotNone(next_info)
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
            self.assertIsNone(
                remaining_packet,
                "Port %u: Packet expected from source %u didn't arrive" %
                (dst_sw_if_index, i.sw_if_index))

    def verify_vrf(self, vrf_id, if_set_id=None):
        """
        Check if the FIB table / VRF ID is configured.

        :param int vrf_id: The FIB table / VRF ID to be verified.
        :return: 1 if the FIB table / VRF ID is configured, otherwise return 0.
        """
        if if_set_id is None:
            if_set_id = vrf_id
        ip_fib_dump = self.vapi.ip_route_dump(vrf_id)
        vrf_exist = len(ip_fib_dump)
        vrf_count = 0
        for ip_fib_details in ip_fib_dump:
            addr = ip_fib_details.route.prefix.network_address
            found = False
            for pg_if in self.pg_if_sets[if_set_id]:
                if found:
                    break
                for host in pg_if.remote_hosts:
                    if str(addr) == host.ip4:
                        vrf_count += 1
                        found = True
                        break
        if not vrf_exist and vrf_count == 0:
            self.logger.info("IPv4 VRF ID %d is not configured" % vrf_id)
            return VRFState.not_configured
        elif vrf_exist and vrf_count == 0:
            self.logger.info("IPv4 VRF ID %d has been reset" % vrf_id)
            return VRFState.reset
        else:
            self.logger.info("IPv4 VRF ID %d is configured" % vrf_id)
            return VRFState.configured

    def run_verify_test(self):
        """
        Create packet streams for all configured pg interfaces, send all \
        prepared packet streams and verify that:
            - all packets received correctly on all pg-ip4 interfaces assigned
              to VRFs
            - no packet received on all pg-ip4 interfaces not assigned to VRFs

        :raise RuntimeError: If no packet captured on pg-ip4 interface assigned
            to VRF or if any packet is captured on pg-ip4 interface not
            assigned to VRF.
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
            if pg_if in self.pg_in_vrf:
                capture = pg_if.get_capture(remark="interface is in VRF")
                self.verify_capture(pg_if, capture)
            elif pg_if in self.pg_not_in_vrf:
                pg_if.assert_nothing_captured(remark="interface is not in VRF",
                                              filter_out_fn=is_ipv4_misc)
                self.logger.debug("No capture for interface %s" % pg_if.name)
            else:
                raise Exception("Unknown interface: %s" % pg_if.name)

    def run_crosswise_vrf_test(self):
        """
        Create packet streams for every pg-ip4 interface in VRF towards all
        pg-ip4 interfaces in other VRFs, send all prepared packet streams and
        verify that:

        - no packet received on all configured pg-ip4 interfaces

        :raise RuntimeError: If any packet is captured on any pg-ip4 interface.
        """
        # Test
        # Create incoming packet streams for packet-generator interfaces
        for vrf_id in self.vrf_list:
            for pg_if in self.pg_if_sets[vrf_id]:
                pkts = self.create_stream_crosswise_vrf(
                    pg_if, vrf_id, self.pg_if_packet_sizes)
                pg_if.add_stream(pkts)

        # Enable packet capture and start packet sending
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Verify
        # Verify outgoing packet streams per packet-generator interface
        for pg_if in self.pg_interfaces:
            pg_if.assert_nothing_captured(remark="interface is in other VRF",
                                          filter_out_fn=is_ipv4_misc)
            self.logger.debug("No capture for interface %s" % pg_if.name)

    def test_ip4_vrf_01(self):
        """ IP4 VRF  Multi-instance test 1 - create 4 VRFs
        """
        # Config 1
        # Create 4 VRFs
        self.create_vrf_and_assign_interfaces(4)

        # Verify 1
        for vrf_id in self.vrf_list:
            self.assert_equal(self.verify_vrf(vrf_id),
                              VRFState.configured, VRFState)

        # Test 1
        self.run_verify_test()
        self.run_crosswise_vrf_test()

    def test_ip4_vrf_02(self):
        """ IP4 VRF  Multi-instance test 2 - reset 2 VRFs
        """
        # Config 2
        # Reset 2 VRFs
        self.reset_vrf_and_remove_from_vrf_list(1)
        self.reset_vrf_and_remove_from_vrf_list(2)

        # Verify 2
        for vrf_id in self.vrf_reset_list:
            self.assert_equal(self.verify_vrf(vrf_id),
                              VRFState.reset, VRFState)
        for vrf_id in self.vrf_list:
            self.assert_equal(self.verify_vrf(vrf_id),
                              VRFState.configured, VRFState)

        # Test 2
        self.run_verify_test()
        self.run_crosswise_vrf_test()

    def test_ip4_vrf_03(self):
        """ IP4 VRF  Multi-instance 3 - add 2 VRFs
        """
        # Config 3
        # Add 1 of reset VRFs and 1 new VRF
        self.create_vrf_and_assign_interfaces(1)
        self.create_vrf_and_assign_interfaces(1, start=5)

        # Verify 3
        for vrf_id in self.vrf_reset_list:
            self.assert_equal(self.verify_vrf(vrf_id),
                              VRFState.reset, VRFState)
        for vrf_id in self.vrf_list:
            self.assert_equal(self.verify_vrf(vrf_id),
                              VRFState.configured, VRFState)

        # Test 3
        self.run_verify_test()
        self.run_crosswise_vrf_test()

    def test_ip4_vrf_04(self):
        """ IP4 VRF  Multi-instance test 4 - reset 4 VRFs
        """
        # Config 4
        # Reset all VRFs (i.e. no VRF except VRF=0 configured)
        for i in range(len(self.vrf_list)):
            self.reset_vrf_and_remove_from_vrf_list(self.vrf_list[0])

        # Verify 4
        for vrf_id in self.vrf_reset_list:
            self.assert_equal(self.verify_vrf(vrf_id),
                              VRFState.reset, VRFState)
        vrf_list_length = len(self.vrf_list)
        self.assertEqual(
            vrf_list_length, 0,
            "List of configured VRFs is not empty: %s != 0" % vrf_list_length)

        # Test 4
        self.run_verify_test()
        self.run_crosswise_vrf_test()

    def test_ip4_vrf_05(self):
        """ IP4 VRF  Multi-instance test 5 - id allocation
        """
        # Config 5
        # Create several VRFs
        # Set vrf_id manually first
        self.create_vrf_by_id_and_assign_interfaces(1, 1)
        # Set vrf_id automatically a few times
        auto_vrf_id = [
            self.create_vrf_by_id_and_assign_interfaces(i) for i in range(2, 5)
        ]

        # Verify 5
        self.assert_equal(self.verify_vrf(1, 1), VRFState.configured, VRFState)
        for i, vrf in enumerate(auto_vrf_id):
            self.assert_equal(self.verify_vrf(vrf, i+2),
                              VRFState.configured, VRFState)

        # Test 5
        self.run_verify_test()

        # Config 5.1
        # Reset VRFs
        self.reset_vrf_and_remove_from_vrf_list(1)
        for i, vrf in enumerate(auto_vrf_id):
            self.reset_vrf_and_remove_from_vrf_list(vrf, i+2)

        # Verify 5.1
        self.assert_equal(self.verify_vrf(1, 1), VRFState.reset, VRFState)
        for i, vrf in enumerate(auto_vrf_id):
            self.assert_equal(self.verify_vrf(vrf, i+2),
                              VRFState.reset, VRFState)

        vrf_list_length = len(self.vrf_list)
        self.assertEqual(
            vrf_list_length, 0,
            "List of configured VRFs is not empty: %s != 0" % vrf_list_length)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
