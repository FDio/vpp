#!/usr/bin/env python
"""IP4 VRF Multi-instance Test Case HLD:

**NOTES:**
    - higher number of pg-ip4 interfaces causes problems => only 15 pg-ip4 \
    interfaces in 5 VRFs are tested
    - jumbo packets in configuration with 15 pg-ip4 interfaces leads to \
    problems too
    - Reset of FIB table / VRF does not remove routes from IP FIB (see Jira \
    ticket https://jira.fd.io/browse/VPP-560) so checks of reset VRF tables \
    are skipped in tests 2, 3 and 4

**config 1**
    - add 15 pg-ip4 interfaces
    - configure 5 hosts per pg-ip4 interface
    - configure 4 VRFs
    - add 3 pg-ip4 interfaces per VRF

**test 1**
    - send IP4 packets between all pg-ip4 interfaces in all VRF groups

**verify 1**
    - check VRF data by parsing output of ip_fib_dump API command
    - all packets received correctly in case of pg-ip4 interfaces in VRF
    - no packet received in case of pg-ip4 interfaces not in VRF

**config 2**
    - delete 2 VRFs

**test 2**
    - send IP4 packets between all pg-ip4 interfaces in all VRF groups

**verify 2**
    - check VRF data by parsing output of ip_fib_dump API command
    - all packets received correctly in case of pg-ip4 interfaces in VRF
    - no packet received in case of pg-ip4 interfaces not in VRF

**config 3**
    - add 1 of deleted VRFs and 1 new VRF

**test 3**
    - send IP4 packets between all pg-ip4 interfaces in all VRF groups

**verify 3**
    - check VRF data by parsing output of ip_fib_dump API command
    - all packets received correctly in case of pg-ip4 interfaces in VRF
    - no packet received in case of pg-ip4 interfaces not in VRF

**config 4**
    - delete all VRFs (i.e. no VRF except VRF=0 created)

**test 4**
    - send IP4 packets between all pg-ip4 interfaces in all VRF groups

**verify 4**
    - check VRF data by parsing output of ip_fib_dump API command
    - all packets received correctly in case of pg-ip4 interfaces in VRF
    - no packet received in case of pg-ip4 interfaces not in VRF
"""

import unittest
import random

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, ARP

from framework import VppTestCase, VppTestRunner
from util import ppp


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
                multiplicand = i / cls.pg_ifs_per_vrf
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

            # Create list of deleted VRFs
            cls.vrf_deleted_list = list()

            # Create list of pg_interfaces in VRFs
            cls.pg_in_vrf = list()

            # Create list of pg_interfaces not in BDs
            cls.pg_not_in_vrf = [pg_if for pg_if in cls.pg_interfaces]

            # Create mapping of pg_interfaces to VRF IDs
            cls.pg_if_by_vrf_id = dict()
            for i in range(cls.nr_of_vrfs):
                vrf_id = i + 1
                pg_list = [
                    cls.pg_interfaces[i * cls.pg_ifs_per_vrf + j]
                    for j in range(cls.pg_ifs_per_vrf)]
                cls.pg_if_by_vrf_id[vrf_id] = pg_list

        except Exception:
            super(TestIp4VrfMultiInst, cls).tearDownClass()
            raise

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
        if not self.vpp_dead:
            self.logger.info(self.vapi.ppcli("show ip fib"))
            self.logger.info(self.vapi.ppcli("show ip arp"))

    def create_vrf_and_assign_interfaces(self, count, start=1):
        """
        Create required number of FIB tables / VRFs, put 3 l2-pg interfaces
        to every FIB table / VRF.

        :param int count: Number of FIB tables / VRFs to be created.
        :param int start: Starting number of the FIB table / VRF ID. \
        (Default value = 1)
        """

        for i in range(count):
            vrf_id = i + start
            pg_if = self.pg_if_by_vrf_id[vrf_id][0]
            dest_addr = pg_if.remote_hosts[0].ip4n
            dest_addr_len = 24
            self.vapi.ip_table_add_del(vrf_id, is_add=1)
            self.vapi.ip_add_del_route(
                dest_addr, dest_addr_len, pg_if.local_ip4n,
                table_id=vrf_id, is_multipath=1)
            self.logger.info("IPv4 VRF ID %d created" % vrf_id)
            if vrf_id not in self.vrf_list:
                self.vrf_list.append(vrf_id)
            if vrf_id in self.vrf_deleted_list:
                self.vrf_deleted_list.remove(vrf_id)
            for j in range(self.pg_ifs_per_vrf):
                pg_if = self.pg_if_by_vrf_id[vrf_id][j]
                pg_if.set_table_ip4(vrf_id)
                self.logger.info("pg-interface %s added to IPv4 VRF ID %d"
                                 % (pg_if.name, vrf_id))
                if pg_if not in self.pg_in_vrf:
                    self.pg_in_vrf.append(pg_if)
                if pg_if in self.pg_not_in_vrf:
                    self.pg_not_in_vrf.remove(pg_if)
                pg_if.config_ip4()
                pg_if.configure_ipv4_neighbors()
        self.logger.debug(self.vapi.ppcli("show ip fib"))
        self.logger.debug(self.vapi.ppcli("show ip arp"))

    def delete_vrf(self, vrf_id):
        """
        Delete required FIB table / VRF.

        :param int vrf_id: The FIB table / VRF ID to be deleted.
        """
        # self.vapi.reset_vrf(vrf_id, is_ipv6=0)
        self.vapi.reset_fib(vrf_id, is_ipv6=0)
        if vrf_id in self.vrf_list:
            self.vrf_list.remove(vrf_id)
        if vrf_id not in self.vrf_deleted_list:
            self.vrf_deleted_list.append(vrf_id)
        for j in range(self.pg_ifs_per_vrf):
            pg_if = self.pg_if_by_vrf_id[vrf_id][j]
            pg_if.unconfig_ip4()
            if pg_if in self.pg_in_vrf:
                self.pg_in_vrf.remove(pg_if)
            if pg_if not in self.pg_not_in_vrf:
                self.pg_not_in_vrf.append(pg_if)
        self.logger.info("IPv4 VRF ID %d reset" % vrf_id)
        self.logger.debug(self.vapi.ppcli("show ip fib"))
        self.logger.debug(self.vapi.ppcli("show ip arp"))
        self.vapi.ip_table_add_del(vrf_id, is_add=0)

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
                payload_info = self.payload_to_info(str(packet[Raw]))
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

    def verify_vrf(self, vrf_id):
        """
        Check if the FIB table / VRF ID is configured.

        :param int vrf_id: The FIB table / VRF ID to be verified.
        :return: 1 if the FIB table / VRF ID is configured, otherwise return 0.
        """
        ip_fib_dump = self.vapi.ip_fib_dump()
        vrf_count = 0
        for ip_fib_details in ip_fib_dump:
            if ip_fib_details[2] == vrf_id:
                vrf_count += 1
        if vrf_count == 0:
            self.logger.info("IPv4 VRF ID %d is not configured" % vrf_id)
            return 0
        else:
            self.logger.info("IPv4 VRF ID %d is configured" % vrf_id)
            return 1

    def run_verify_test(self):
        """
        Create packet streams for all configured l2-pg interfaces, send all \
        prepared packet streams and verify that:
            - all packets received correctly on all pg-l2 interfaces assigned
              to bridge domains
            - no packet received on all pg-l2 interfaces not assigned to bridge
              domains

        :raise RuntimeError: If no packet captured on l2-pg interface assigned
            to the bridge domain or if any packet is captured on l2-pg
            interface not assigned to the bridge domain.
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

    def test_ip4_vrf_01(self):
        """ IP4 VRF  Multi-instance test 1 - create 5 BDs
        """
        # Config 1
        # Create 4 VRFs
        self.create_vrf_and_assign_interfaces(4)

        # Verify 1
        for vrf_id in self.vrf_list:
            self.assertEqual(self.verify_vrf(vrf_id), 1)

        # Test 1
        self.run_verify_test()

    def test_ip4_vrf_02(self):
        """ IP4 VRF  Multi-instance test 2 - delete 2 VRFs
        """
        # Config 2
        # Delete 2 VRFs
        self.delete_vrf(1)
        self.delete_vrf(2)

        # Verify 2
        # for vrf_id in self.vrf_deleted_list:
        #     self.assertEqual(self.verify_vrf(vrf_id), 0)
        for vrf_id in self.vrf_list:
            self.assertEqual(self.verify_vrf(vrf_id), 1)

        # Test 2
        self.run_verify_test()

    def test_ip4_vrf_03(self):
        """ IP4 VRF  Multi-instance 3 - add 2 VRFs
        """
        # Config 3
        # Add 1 of deleted VRFs and 1 new VRF
        self.create_vrf_and_assign_interfaces(1)
        self.create_vrf_and_assign_interfaces(1, start=5)

        # Verify 3
        # for vrf_id in self.vrf_deleted_list:
        #     self.assertEqual(self.verify_vrf(vrf_id), 0)
        for vrf_id in self.vrf_list:
            self.assertEqual(self.verify_vrf(vrf_id), 1)

        # Test 3
        self.run_verify_test()

    def test_ip4_vrf_04(self):
        """ IP4 VRF  Multi-instance test 4 - delete 4 VRFs
        """
        # Config 4
        # Delete all VRFs (i.e. no VRF except VRF=0 created)
        for i in range(len(self.vrf_list)):
            self.delete_vrf(self.vrf_list[0])

        # Verify 4
        # for vrf_id in self.vrf_deleted_list:
        #     self.assertEqual(self.verify_vrf(vrf_id), 0)
        for vrf_id in self.vrf_list:
            self.assertEqual(self.verify_vrf(vrf_id), 1)

        # Test 4
        self.run_verify_test()


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
