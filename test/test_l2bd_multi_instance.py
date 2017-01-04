#!/usr/bin/env python
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

from framework import VppTestCase, VppTestRunner
from util import Host, ppp


@unittest.skip("Crashes VPP")
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
            cls.create_pg_interfaces(range(15))

            # Packet flows mapping pg0 -> pg1, pg2 etc.
            cls.flows = dict()
            for i in range(0, len(cls.pg_interfaces), 3):
                cls.flows[cls.pg_interfaces[i]] = [cls.pg_interfaces[i + 1],
                                                   cls.pg_interfaces[i + 2]]
                cls.flows[cls.pg_interfaces[i + 1]] = \
                    [cls.pg_interfaces[i], cls.pg_interfaces[i + 2]]
                cls.flows[cls.pg_interfaces[i + 2]] = \
                    [cls.pg_interfaces[i], cls.pg_interfaces[i + 1]]

            # Mapping between packet-generator index and lists of test hosts
            cls.hosts_by_pg_idx = dict()
            for pg_if in cls.pg_interfaces:
                cls.hosts_by_pg_idx[pg_if.sw_if_index] = []

            # Create test host entries
            cls.create_hosts(75)

            # Packet sizes - jumbo packet (9018 bytes) skipped
            cls.pg_if_packet_sizes = [64, 512, 1518]

            # Set up all interfaces
            for i in cls.pg_interfaces:
                i.admin_up()

            # Create list of BDs
            cls.bd_list = list()

            # Create list of deleted BDs
            cls.bd_deleted_list = list()

            # Create list of pg_interfaces in BDs
            cls.pg_in_bd = list()

            # Create list of pg_interfaces not in BDs
            cls.pg_not_in_bd = list()
            for pg_if in cls.pg_interfaces:
                cls.pg_not_in_bd.append(pg_if)

        except Exception:
            super(TestL2bdMultiInst, cls).tearDownClass()
            raise

    def setUp(self):
        """
        Clear trace and packet infos before running each test.
        """
        super(TestL2bdMultiInst, self).setUp()

    def tearDown(self):
        """
        Show various debug prints after each test.
        """
        super(TestL2bdMultiInst, self).tearDown()
        if not self.vpp_dead:
            self.logger.info(self.vapi.ppcli("show l2fib verbose"))
            self.logger.info(self.vapi.ppcli("show bridge-domain"))

    @classmethod
    def create_hosts(cls, count):
        """
        Create required number of host MAC addresses and distribute them among
        interfaces. Create host IPv4 address for every host MAC address.

        :param int count: Number of hosts to create MAC/IPv4 addresses for.
        """
        n_int = len(cls.pg_interfaces)
        macs_per_if = count / n_int
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

    def create_bd_and_mac_learn(self, count, start=1):
        """
        Create required number of bridge domains with MAC learning enabled,
        put 3 l2-pg interfaces to every bridge domain and send MAC learning
        packets.

        :param int count: Number of bridge domains to be created.
        :param int start: Starting number of the bridge domain ID.
            (Default value = 1)
        """
        for i in range(count):
            bd_id = i + start
            self.vapi.bridge_domain_add_del(bd_id=bd_id)
            self.logger.info("Bridge domain ID %d created" % bd_id)
            if self.bd_list.count(bd_id) == 0:
                self.bd_list.append(bd_id)
            if self.bd_deleted_list.count(bd_id) == 1:
                self.bd_deleted_list.remove(bd_id)
            for j in range(3):
                pg_if = self.pg_interfaces[(i + start - 1) * 3 + j]
                self.vapi.sw_interface_set_l2_bridge(pg_if.sw_if_index,
                                                     bd_id=bd_id)
                self.logger.info("pg-interface %s added to bridge domain ID %d"
                                 % (pg_if.name, bd_id))
                self.pg_in_bd.append(pg_if)
                self.pg_not_in_bd.remove(pg_if)
                packets = []
                for host in self.hosts_by_pg_idx[pg_if.sw_if_index]:
                    packet = (Ether(dst="ff:ff:ff:ff:ff:ff", src=host.mac))
                    packets.append(packet)
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
        for i in range(count):
            bd_id = i + start
            self.vapi.bridge_domain_add_del(bd_id=bd_id, is_add=0)
            if self.bd_list.count(bd_id) == 1:
                self.bd_list.remove(bd_id)
            if self.bd_deleted_list.count(bd_id) == 0:
                self.bd_deleted_list.append(bd_id)
            for j in range(3):
                pg_if = self.pg_interfaces[(i + start - 1) * 3 + j]
                self.pg_in_bd.remove(pg_if)
                self.pg_not_in_bd.append(pg_if)
            self.logger.info("Bridge domain ID %d deleted" % bd_id)

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
            payload_info = self.payload_to_info(str(packet[Raw]))
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
            self.vapi.bridge_flags(bd_id, is_set, feature_bitmap)
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
        for pg_if in self.pg_interfaces:
            pkts = self.create_stream(pg_if, self.pg_if_packet_sizes)
            pg_if.add_stream(pkts)

        # Enable packet capture and start packet sending
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Verify
        # Verify outgoing packet streams per packet-generator interface
        for pg_if in self.pg_interfaces:
            capture = pg_if.get_capture()
            if pg_if in self.pg_in_bd:
                self.verify_capture(pg_if, capture)
            elif pg_if not in self.pg_not_in_bd:
                self.logger.error("Unknown interface: %s" % pg_if.name)

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

    def test_l2bd_inst_02(self):
        """ L2BD Multi-instance test 2 - update data of 5 BDs
        """
        # Config 2
        # Update data of 5 BDs (disable learn, forward, flood, uu-flood)
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

    def test_l2bd_inst_03(self):
        """ L2BD Multi-instance 3 - delete 2 BDs
        """
        # Config 3
        # Delete 2 BDs
        self.delete_bd(2)

        # Verify 3
        for bd_id in self.bd_deleted_list:
            self.assertEqual(self.verify_bd(bd_id), 0)
        for bd_id in self.bd_list:
            self.assertEqual(self.verify_bd(bd_id), 1)

        # Test 3
        self.run_verify_test()

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

    def test_l2bd_inst_05(self):
        """ L2BD Multi-instance 5 - delete 5 BDs
        """
        # Config 5
        # Delete 5 BDs
        self.delete_bd(5)

        # Verify 5
        for bd_id in self.bd_deleted_list:
            self.assertEqual(self.verify_bd(bd_id), 0)
        for bd_id in self.bd_list:
            self.assertEqual(self.verify_bd(bd_id), 1)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
