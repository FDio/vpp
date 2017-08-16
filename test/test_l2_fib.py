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

from framework import VppTestCase, VppTestRunner, VppMultiWorkerScenario
from util import Host, ppp


@VppMultiWorkerScenario.skip("test doesn't pass with multiple workers")
class TestL2fib(VppTestCase):
    """ L2 FIB Test Case """

    @classmethod
    def bd_ifs(cls, bd_id):
        return range((bd_id - 1) * cls.n_ifs_per_bd, bd_id * cls.n_ifs_per_bd)

    @classmethod
    def setUpClass(cls):
        """
        Perform standard class setup (defined by class method setUpClass in
        class VppTestCase) before running the test case, set test case related
        variables and configure VPP.

        :var int bd_id: Bridge domain ID.
        """
        super(TestL2fib, cls).setUpClass()

        try:
            n_brs = cls.n_brs = range(1, 3)
            cls.n_ifs_per_bd = 4
            n_ifs = range(cls.n_ifs_per_bd * len(cls.n_brs))
            # Create 4 pg interfaces
            cls.create_pg_interfaces(n_ifs)

            cls.flows = dict()
            for bd_id in n_brs:
                # Packet flows mapping pg0 -> pg1, pg2, pg3 etc.
                ifs = cls.bd_ifs(bd_id)
                for j in ifs:
                    cls.flows[cls.pg_interfaces[j]] = [
                        cls.pg_interfaces[x] for x in ifs if x != j]

            # Packet sizes
            cls.pg_if_packet_sizes = [64, 512, 1518, 9018]

            for bd_id in n_brs:
                # Create BD with MAC learning and unknown unicast flooding
                # disabled and put interfaces to this BD
                cls.vapi.bridge_domain_add_del(
                    bd_id=bd_id, uu_flood=0, learn=0)
                ifs = [cls.pg_interfaces[i] for i in cls.bd_ifs(bd_id)]
                for pg_if in ifs:
                    cls.vapi.sw_interface_set_l2_bridge(pg_if.sw_if_index,
                                                        bd_id=bd_id)

            # Set up all interfaces
            for i in cls.pg_interfaces:
                i.admin_up()

            # Mapping between packet-generator index and lists of test hosts
            cls.hosts = dict()
            cls.learned_hosts = dict()
            cls.fib_hosts = dict()
            cls.deleted_hosts = dict()
            for pg_if in cls.pg_interfaces:
                swif = pg_if.sw_if_index
                cls.hosts[swif] = []
                cls.learned_hosts[swif] = []
                cls.fib_hosts[swif] = []
                cls.deleted_hosts[swif] = []

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
            for bd_id in self.n_brs:
                self.logger.info(self.vapi.ppcli("show bridge-domain %s detail"
                                                 % bd_id))

    def create_hosts(self, n_hosts_per_if, subnet):
        """
        Create required number of host MAC addresses and distribute them among
        interfaces. Create host IPv4 address for every host MAC address.

        :param int n_hosts_per_if: Number of per interface hosts to
        create MAC/IPv4 addresses for.
        """

        for pg_if in self.pg_interfaces:
            swif = pg_if.sw_if_index

            def mac(j): return "00:00:%02x:ff:%02x:%02x" % (subnet, swif, j)

            def ip(j): return "172.%02u.1%02x.%u" % (subnet, swif, j)

            def h(j): return Host(mac(j), ip(j))
            self.hosts[swif] = [h(j) for j in range(n_hosts_per_if)]

    def learn_hosts(self, bd_id, n_hosts_per_if):
        """
        Create L2 MAC packet stream with host MAC addresses per interface to
        let the bridge domain learn these MAC addresses.

        :param int bd_id: BD to teach
        :param int n_hosts_per_if: number of hosts
        """
        self.vapi.bridge_flags(bd_id, 1, 1)
        ifs = [self.pg_interfaces[i] for i in self.bd_ifs(bd_id)]
        for pg_if in ifs:
            swif = pg_if.sw_if_index
            hosts = self.hosts[swif]
            lhosts = self.learned_hosts[swif]
            packets = []
            for j in range(n_hosts_per_if):
                host = hosts.pop()
                lhosts.append(host)
                packet = (Ether(dst="ff:ff:ff:ff:ff:ff", src=host.mac))
                packets.append(packet)
            pg_if.add_stream(packets)
        self.logger.info("Sending broadcast eth frames for MAC learning")
        self.pg_start()

    def config_l2_fib_entries(self, bd_id, n_hosts_per_if):
        """
        Config required number of L2 FIB entries.

        :param int bd_id: BD's id
        :param int count: Number of L2 FIB entries to be created.
        :param int start: Starting index of the host list. (Default value = 0)
        """
        ifs = [self.pg_interfaces[i] for i in self.bd_ifs(bd_id)]
        for pg_if in ifs:
            swif = pg_if.sw_if_index
            hosts = self.hosts[swif]
            fhosts = self.fib_hosts[swif]
            for j in range(n_hosts_per_if):
                host = hosts.pop()
                self.vapi.l2fib_add_del(
                    host.mac, bd_id, swif, static_mac=1)
                fhosts.append(host)
        #        del hosts[0]
        self.logger.info("Configure %d L2 FIB entries .." %
                         len(self.pg_interfaces) * n_hosts_per_if)
        self.logger.info(self.vapi.ppcli("show l2fib"))

    def delete_l2_fib_entry(self, bd_id, n_hosts_per_if):
        """
        Delete required number of L2 FIB entries.

        :param int count: Number of L2 FIB entries to be created.
        """
        ifs = [self.pg_interfaces[i] for i in self.bd_ifs(bd_id)]
        for pg_if in ifs:
            swif = pg_if.sw_if_index
            hosts = self.fib_hosts[swif]
            dhosts = self.deleted_hosts[swif]
            for j in range(n_hosts_per_if):
                host = hosts.pop()
                self.vapi.l2fib_add_del(
                    host.mac, bd_id, swif, is_add=0)
                dhosts.append(host)
        self.logger.info(self.vapi.ppcli("show l2fib"))

    def flush_int(self, swif):
        """
        Flush swif L2 FIB entries.

        :param int swif: sw if index.
        """
        flushed = dict()
        self.vapi.l2fib_flush_int(swif)
        self.deleted_hosts[swif] = self.learned_hosts[swif] + \
            self.deleted_hosts[swif]
        flushed[swif] = self.learned_hosts[swif]
        self.learned_hosts[swif] = []
        self.logger.info(self.vapi.ppcli("show l2fib"))
        return flushed

    def flush_bd(self, bd_id):
        """
        Flush bd_id L2 FIB entries.

        :param int bd_id: Bridge Domain id.
        """
        self.vapi.l2fib_flush_bd(bd_id)
        flushed = dict()
        ifs = [self.pg_interfaces[i] for i in self.bd_ifs(bd_id)]
        for pg_if in ifs:
            swif = pg_if.sw_if_index
            self.deleted_hosts[swif] = self.learned_hosts[swif] + \
                self.deleted_hosts[swif]
            flushed[swif] = self.learned_hosts[swif]
            self.learned_hosts[swif] = []
        self.logger.info(self.vapi.ppcli("show l2fib"))
        return flushed

    def flush_all(self):
        """
        Flush All L2 FIB entries.
        """
        self.vapi.l2fib_flush_all()
        flushed = dict()
        for pg_if in self.pg_interfaces:
            swif = pg_if.sw_if_index
            self.deleted_hosts[swif] = self.learned_hosts[swif] + \
                self.deleted_hosts[swif]
            flushed[swif] = self.learned_hosts[swif]
            self.learned_hosts[swif] = []
        self.logger.info(self.vapi.ppcli("show l2fib"))
        return flushed

    def create_stream(self, src_if, packet_sizes, if_src_hosts=None,
                      if_dst_hosts=None):
        """
        Create input packet stream for defined interface using hosts or
        deleted_hosts list.

        :param object src_if: Interface to create packet stream for.
        :param list packet_sizes: List of required packet sizes.
        :param boolean deleted: Set to True if deleted_hosts list required.
        :return: Stream of packets.
        """
        if not if_src_hosts:
            if_src_hosts = self.fib_hosts
        if not if_dst_hosts:
            if_dst_hosts = self.fib_hosts
        src_hosts = if_src_hosts[src_if.sw_if_index]
        if not src_hosts:
            return []
        pkts = []
        for dst_if in self.flows[src_if]:
            dst_swif = dst_if.sw_if_index
            if dst_swif not in if_dst_hosts:
                continue
            dst_hosts = if_dst_hosts[dst_swif]
            for i in range(0, len(dst_hosts)):
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

    def run_verify_test(self, bd_id, dst_hosts=None):
        # Test
        # Create incoming packet streams for packet-generator interfaces
        if not dst_hosts:
            dst_hosts = self.fib_hosts
        self.reset_packet_infos()
        ifs = [self.pg_interfaces[i] for i in self.bd_ifs(bd_id)]
        for i in ifs:
            pkts = self.create_stream(
                i, self.pg_if_packet_sizes, if_dst_hosts=dst_hosts)
            i.add_stream(pkts)

        self.vapi.bridge_flags(bd_id, 0, 1)
        # Enable packet capture and start packet sending
        self.pg_enable_capture(ifs)
        self.pg_start()

        # Verify
        # Verify outgoing packet streams per packet-generator interface
        for i in ifs:
            if not dst_hosts[i.sw_if_index]:
                continue
            capture = i.get_capture()
            self.logger.info("Verifying capture on interface %s" % i.name)
            self.verify_capture(i, capture)

    def run_verify_negat_test(self, bd_id, dst_hosts=None):
        # Test
        # Create incoming packet streams for packet-generator interfaces for
        # deleted MAC addresses
        if not dst_hosts:
            dst_hosts = self.deleted_hosts
        self.reset_packet_infos()
        ifs = [self.pg_interfaces[i] for i in self.bd_ifs(bd_id)]
        for i in ifs:
            pkts = self.create_stream(
                i, self.pg_if_packet_sizes, if_dst_hosts=dst_hosts)
            if pkts:
                i.add_stream(pkts)

        self.vapi.bridge_flags(bd_id, 0, 1)
        # Enable packet capture and start packet sending
        self.pg_enable_capture(ifs)
        self.pg_start()

        # Verify
        # Verify outgoing packet streams per packet-generator interface
        timeout = 1
        for i in ifs:
            i.get_capture(0, timeout=timeout)
            i.assert_nothing_captured(remark="outgoing interface")
            timeout = 0.1

    def test_l2_fib_01(self):
        """ L2 FIB test 1 - program 100 MAC addresses
        """
        # Config 1
        # Create test host entries
        self.create_hosts(100, subnet=17)

        # Add first 100 MAC entries to L2 FIB
        self.config_l2_fib_entries(bd_id=1, n_hosts_per_if=100)

        # Test 1
        self.run_verify_test(bd_id=1)

    def test_l2_fib_02(self):
        """ L2 FIB test 2 - delete 12 MAC entries
        """
        # Config 2
        # Delete 12 MAC entries per interface from L2 FIB
        self.delete_l2_fib_entry(bd_id=1, n_hosts_per_if=12)

        # Test 2a
        self.run_verify_test(bd_id=1)

        # Verify 2a
        self.run_verify_negat_test(bd_id=1)

    def test_l2_fib_03(self):
        """ L2 FIB test 3 - program new 100 MAC addresses
        """
        # Config 3
        # Create new test host entries
        self.create_hosts(100, subnet=22)

        # Add new 100 MAC entries to L2 FIB
        self.config_l2_fib_entries(bd_id=1, n_hosts_per_if=100)

        # Test 3
        self.run_verify_test(bd_id=1)

    def test_l2_fib_04(self):
        """ L2 FIB test 4 - delete 160 MAC entries
        """
        # Config 4
        # Delete 160 MAC entries per interface from L2 FIB
        self.delete_l2_fib_entry(bd_id=1, n_hosts_per_if=160)

        # Test 4a
        self.run_verify_negat_test(bd_id=1)

    def test_l2_fib_05(self):
        """ L2 FIB test 5 - Program 10 new MAC entries, learn 10
        """
        self.create_hosts(20, subnet=35)

        self.learn_hosts(bd_id=1, n_hosts_per_if=10)
        self.learn_hosts(bd_id=2, n_hosts_per_if=10)
        self.config_l2_fib_entries(bd_id=1, n_hosts_per_if=10)
        self.config_l2_fib_entries(bd_id=2, n_hosts_per_if=10)
        self.run_verify_test(bd_id=1, dst_hosts=self.learned_hosts)
        self.run_verify_test(bd_id=2, dst_hosts=self.learned_hosts)

    def test_l2_fib_06(self):
        """ L2 FIB test 6 - flush first interface
        """
        self.create_hosts(20, subnet=36)

        self.learn_hosts(bd_id=1, n_hosts_per_if=10)
        self.learn_hosts(bd_id=2, n_hosts_per_if=10)
        self.config_l2_fib_entries(bd_id=1, n_hosts_per_if=10)
        self.config_l2_fib_entries(bd_id=2, n_hosts_per_if=10)
        flushed = self.flush_int(self.pg_interfaces[0].sw_if_index)
        self.run_verify_test(bd_id=1, dst_hosts=self.learned_hosts)
        self.run_verify_negat_test(bd_id=1, dst_hosts=flushed)

    def test_l2_fib_07(self):
        """ L2 FIB test 7 - flush bd_id
        """
        self.create_hosts(20, subnet=37)

        self.learn_hosts(bd_id=1, n_hosts_per_if=10)
        self.learn_hosts(bd_id=2, n_hosts_per_if=10)
        self.config_l2_fib_entries(bd_id=1, n_hosts_per_if=10)
        self.config_l2_fib_entries(bd_id=2, n_hosts_per_if=10)
        flushed = self.flush_bd(bd_id=1)
        self.run_verify_negat_test(bd_id=1, dst_hosts=flushed)
        self.run_verify_test(bd_id=2, dst_hosts=self.learned_hosts)

    def test_l2_fib_08(self):
        """ L2 FIB test 8 - flush all
        """
        self.create_hosts(20, subnet=38)

        self.learn_hosts(bd_id=1, n_hosts_per_if=10)
        self.learn_hosts(bd_id=2, n_hosts_per_if=10)
        self.config_l2_fib_entries(bd_id=1, n_hosts_per_if=10)
        self.config_l2_fib_entries(bd_id=2, n_hosts_per_if=10)
        flushed = self.flush_all()
        self.run_verify_negat_test(bd_id=1, dst_hosts=flushed)
        self.run_verify_negat_test(bd_id=2, dst_hosts=flushed)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
