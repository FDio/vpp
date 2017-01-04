#!/usr/bin/env python
"""L2 FIB Test Case HLD:

**config 1**
    - add 4 pg-l2 interfaces
    - configure them into l2bd
    - configure 100 MAC entries in L2 fib - 25 MACs per interface
    - L2 MAC learning and unknown unicast flooding disabled in l2bd
    - configure 100 MAC entries in L2 fib - 25 MACs per interface

**test 1**
    - send L2 MAC frames between all 4 pg-l2 interfaces for all of 100 MAC \
    entries in the FIB

**verify 1**
    - all packets received correctly

**config 2**
    - delete 12 MAC entries - 3 MACs per interface

**test 2a**
    - send L2 MAC frames between all 4 pg-l2 interfaces for non-deleted MAC \
    entries

**verify 2a**
    - all packets received correctly

**test 2b**
    - send L2 MAC frames between all 4 pg-l2 interfaces for all of 12 deleted \
    MAC entries

**verify 2b**
    - no packet received on all 4 pg-l2 interfaces

**config 3**
    - configure new 100 MAC entries in L2 fib - 25 MACs per interface

**test 3**
    - send L2 MAC frames between all 4 pg-l2 interfaces for all of 188 MAC \
    entries in the FIB

**verify 3**
    - all packets received correctly

**config 4**
    - delete 160 MAC entries, 40 MACs per interface

**test 4a**
    - send L2 MAC frames between all 4 pg-l2 interfaces for all of 28 \
    non-deleted MAC entries

**verify 4a**
    - all packets received correctly

**test 4b**
    - try send L2 MAC frames between all 4 pg-l2 interfaces for all of 172 \
    deleted MAC entries

**verify 4b**
    - no packet received on all 4 pg-l2 interfaces
"""

import unittest
import random

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP

from framework import VppTestCase, VppTestRunner
from util import Host, ppp


class TestL2fib(VppTestCase):
    """ L2 FIB Test Case """

    @classmethod
    def setUpClass(cls):
        """
        Perform standard class setup (defined by class method setUpClass in
        class VppTestCase) before running the test case, set test case related
        variables and configure VPP.

        :var int bd_id: Bridge domain ID.
        :var int mac_entries_count: Number of MAC entries for bridge-domain.
        """
        super(TestL2fib, cls).setUpClass()

        # Test variables
        cls.bd_id = 1
        cls.mac_entries_count = 200

        try:
            # Create 4 pg interfaces
            cls.create_pg_interfaces(range(4))

            # Packet flows mapping pg0 -> pg1, pg2, pg3 etc.
            cls.flows = dict()
            cls.flows[cls.pg0] = [cls.pg1, cls.pg2, cls.pg3]
            cls.flows[cls.pg1] = [cls.pg0, cls.pg2, cls.pg3]
            cls.flows[cls.pg2] = [cls.pg0, cls.pg1, cls.pg3]
            cls.flows[cls.pg3] = [cls.pg0, cls.pg1, cls.pg2]

            # Packet sizes
            cls.pg_if_packet_sizes = [64, 512, 1518, 9018]

            # Create BD with MAC learning and unknown unicast flooding disabled
            # and put interfaces to this BD
            cls.vapi.bridge_domain_add_del(
                bd_id=cls.bd_id, uu_flood=0, learn=0)
            for pg_if in cls.pg_interfaces:
                cls.vapi.sw_interface_set_l2_bridge(pg_if.sw_if_index,
                                                    bd_id=cls.bd_id)

            # Set up all interfaces
            for i in cls.pg_interfaces:
                i.admin_up()

            # Mapping between packet-generator index and lists of test hosts
            cls.hosts_by_pg_idx = dict()
            for pg_if in cls.pg_interfaces:
                cls.hosts_by_pg_idx[pg_if.sw_if_index] = []

            # Create list of deleted hosts
            cls.deleted_hosts_by_pg_idx = dict()
            for pg_if in cls.pg_interfaces:
                cls.deleted_hosts_by_pg_idx[pg_if.sw_if_index] = []

        except Exception:
            super(TestL2fib, cls).tearDownClass()
            raise

    def setUp(self):
        super(TestL2fib, self).setUp()
        self.reset_packet_infos()

    def tearDown(self):
        """
        Show various debug prints after each test.
        """
        super(TestL2fib, self).tearDown()
        if not self.vpp_dead:
            self.logger.info(self.vapi.ppcli("show l2fib verbose"))
            self.logger.info(self.vapi.ppcli("show bridge-domain %s detail"
                                             % self.bd_id))

    def create_hosts(self, count, start=0):
        """
        Create required number of host MAC addresses and distribute them among
        interfaces. Create host IPv4 address for every host MAC address.

        :param int count: Number of hosts to create MAC/IPv4 addresses for.
        :param int start: Number to start numbering from.
        """
        n_int = len(self.pg_interfaces)
        macs_per_if = count / n_int
        i = -1
        for pg_if in self.pg_interfaces:
            i += 1
            start_nr = macs_per_if * i + start
            end_nr = count + start if i == (n_int - 1) \
                else macs_per_if * (i + 1) + start
            hosts = self.hosts_by_pg_idx[pg_if.sw_if_index]
            for j in range(start_nr, end_nr):
                host = Host(
                    "00:00:00:ff:%02x:%02x" % (pg_if.sw_if_index, j),
                    "172.17.1%02x.%u" % (pg_if.sw_if_index, j))
                hosts.append(host)

    def config_l2_fib_entries(self, count, start=0):
        """
        Create required number of L2 FIB entries.

        :param int count: Number of L2 FIB entries to be created.
        :param int start: Starting index of the host list. (Default value = 0)
        """
        n_int = len(self.pg_interfaces)
        percent = 0
        counter = 0.0
        for pg_if in self.pg_interfaces:
            end_nr = start + count / n_int
            for j in range(start, end_nr):
                host = self.hosts_by_pg_idx[pg_if.sw_if_index][j]
                self.vapi.l2fib_add_del(
                    host.mac, self.bd_id, pg_if.sw_if_index, static_mac=1)
                counter += 1
                percentage = counter / count * 100
                if percentage > percent:
                    self.logger.info("Configure %d L2 FIB entries .. %d%% done"
                                     % (count, percentage))
                    percent += 1
        self.logger.info(self.vapi.ppcli("show l2fib"))

    def delete_l2_fib_entry(self, count):
        """
        Delete required number of L2 FIB entries.

        :param int count: Number of L2 FIB entries to be created.
        """
        n_int = len(self.pg_interfaces)
        percent = 0
        counter = 0.0
        for pg_if in self.pg_interfaces:
            for j in range(count / n_int):
                host = self.hosts_by_pg_idx[pg_if.sw_if_index][0]
                self.vapi.l2fib_add_del(
                    host.mac, self.bd_id, pg_if.sw_if_index, is_add=0)
                self.deleted_hosts_by_pg_idx[pg_if.sw_if_index].append(host)
                del self.hosts_by_pg_idx[pg_if.sw_if_index][0]
                counter += 1
                percentage = counter / count * 100
                if percentage > percent:
                    self.logger.info("Delete %d L2 FIB entries .. %d%% done"
                                     % (count, percentage))
                    percent += 1
        self.logger.info(self.vapi.ppcli("show l2fib"))

    def create_stream(self, src_if, packet_sizes, deleted=False):
        """
        Create input packet stream for defined interface using hosts or
        deleted_hosts list.

        :param object src_if: Interface to create packet stream for.
        :param list packet_sizes: List of required packet sizes.
        :param boolean deleted: Set to True if deleted_hosts list required.
        :return: Stream of packets.
        """
        pkts = []
        src_hosts = self.hosts_by_pg_idx[src_if.sw_if_index]
        for dst_if in self.flows[src_if]:
            dst_hosts = self.deleted_hosts_by_pg_idx[dst_if.sw_if_index]\
                if deleted else self.hosts_by_pg_idx[dst_if.sw_if_index]
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

    def run_verify_test(self):
        # Test
        # Create incoming packet streams for packet-generator interfaces
        for i in self.pg_interfaces:
            pkts = self.create_stream(i, self.pg_if_packet_sizes)
            i.add_stream(pkts)

        # Enable packet capture and start packet sending
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Verify
        # Verify outgoing packet streams per packet-generator interface
        for i in self.pg_interfaces:
            capture = i.get_capture()
            self.logger.info("Verifying capture on interface %s" % i.name)
            self.verify_capture(i, capture)

    def run_verify_negat_test(self):
        # Test
        # Create incoming packet streams for packet-generator interfaces for
        # deleted MAC addresses
        self.reset_packet_infos()
        for i in self.pg_interfaces:
            pkts = self.create_stream(i, self.pg_if_packet_sizes, deleted=True)
            i.add_stream(pkts)

        # Enable packet capture and start packet sending
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        # Verify
        # Verify outgoing packet streams per packet-generator interface
        for i in self.pg_interfaces:
            i.assert_nothing_captured(remark="outgoing interface")

    def test_l2_fib_01(self):
        """ L2 FIB test 1 - program 100 MAC addresses
        """
        # Config 1
        # Create test host entries
        self.create_hosts(100)

        # Add first 100 MAC entries to L2 FIB
        self.config_l2_fib_entries(100)

        # Test 1
        self.run_verify_test()

    def test_l2_fib_02(self):
        """ L2 FIB test 2 - delete 12 MAC entries
        """
        # Config 2
        # Delete 12 MAC entries (3 per interface) from L2 FIB
        self.delete_l2_fib_entry(12)

        # Test 2a
        self.run_verify_test()

        # Verify 2a
        self.run_verify_negat_test()

    def test_l2_fib_03(self):
        """ L2 FIB test 3 - program new 100 MAC addresses
        """
        # Config 3
        # Create new test host entries
        self.create_hosts(100, start=100)

        # Add new 100 MAC entries to L2 FIB
        self.config_l2_fib_entries(100, start=22)

        # Test 3
        self.run_verify_test()

    def test_l2_fib_04(self):
        """ L2 FIB test 4 - delete 160 MAC entries
        """
        # Config 4
        # Delete 160 MAC entries (40 per interface) from L2 FIB
        self.delete_l2_fib_entry(160)

        # Test 4a
        self.run_verify_negat_test()


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
