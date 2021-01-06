#!/usr/bin/env python3
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
from vpp_papi import mac_pton, VppEnum


class TestL2fib(VppTestCase):
    """ L2 FIB Test Case """

    @classmethod
    def bd_ifs(cls, bd_id):
        return range((bd_id - 1) * cls.n_ifs_per_bd,
                     bd_id * cls.n_ifs_per_bd - 1)

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
            # Create pg interfaces
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
                cls.vapi.bridge_domain_add_del(bd_id=bd_id, uu_flood=0,
                                               learn=0)
                ifs = [cls.pg_interfaces[i] for i in cls.bd_ifs(bd_id)]
                for pg_if in ifs:
                    cls.vapi.sw_interface_set_l2_bridge(
                        rx_sw_if_index=pg_if.sw_if_index, bd_id=bd_id)

            # Set up all interfaces
            for i in cls.pg_interfaces:
                i.admin_up()
        except Exception:
            super(TestL2fib, cls).tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        super(TestL2fib, cls).tearDownClass()

    def setUp(self):
        super(TestL2fib, self).setUp()
        self.reset_packet_infos()

    def tearDown(self):
        """
        Show various debug prints after each test.
        """
        super(TestL2fib, self).tearDown()
        if not self.vpp_dead:
            for bd_id in self.n_brs:
                self.logger.info(self.vapi.ppcli("show bridge-domain %s detail"
                                                 % bd_id))

    def show_commands_at_teardown(self):
        self.logger.info(self.vapi.ppcli("show l2fib verbose"))

    def create_hosts(self, n_hosts_per_if, subnet):
        """
        Create required number of host MAC addresses and distribute them among
        interfaces. Create host IPv4 address for every host MAC address.

        :param int n_hosts_per_if: Number of per interface hosts to
        create MAC/IPv4 addresses for.
        """

        hosts = dict()
        for pg_if in self.pg_interfaces:
            swif = pg_if.sw_if_index

            def mac(j): return "00:00:%02x:ff:%02x:%02x" % (subnet, swif, j)

            def ip(j): return "172.%02u.1%02x.%u" % (subnet, swif, j)

            def h(j): return Host(mac(j), ip(j))
            hosts[swif] = [h(j) for j in range(n_hosts_per_if)]
        return hosts

    def split_hosts(self, hosts, n):
        splits = dict()
        for pg_if in self.pg_interfaces:
            swif = pg_if.sw_if_index
            splits[swif] = hosts[swif][:n]
            hosts[swif] = hosts[swif][n:]
        return splits

    def learn_hosts(self, bd_id, hosts):
        """
        Create and send per interface L2 MAC broadcast packet stream to
        let the bridge domain learn these MAC addresses.

        :param int bd_id: BD to teach
        :param dict hosts: dict of hosts per interface
        """
        self.vapi.bridge_flags(bd_id=bd_id, is_set=1, flags=1)
        ifs = [self.pg_interfaces[i] for i in self.bd_ifs(bd_id)]
        for pg_if in ifs:
            swif = pg_if.sw_if_index
            packets = [Ether(dst="ff:ff:ff:ff:ff:ff", src=host.mac)
                       for host in hosts[swif]]
            pg_if.add_stream(packets)
        self.logger.info("Sending broadcast eth frames for MAC learning")
        self.pg_start()

    def config_l2_fib_entries(self, bd_id, hosts):
        """
        Config required number of L2 FIB entries.

        :param int bd_id: BD's id
        :param int count: Number of L2 FIB entries to be created.
        :param int start: Starting index of the host list. (Default value = 0)
        """
        ifs = [self.pg_interfaces[i] for i in self.bd_ifs(bd_id)]
        for pg_if in ifs:
            swif = pg_if.sw_if_index
            for host in hosts[swif]:
                self.vapi.l2fib_add_del(
                    mac_pton(host.mac), bd_id, swif, static_mac=1)

    def delete_l2_fib_entry(self, bd_id, hosts):
        """
        Delete required number of L2 FIB entries.

        :param int count: Number of L2 FIB entries to be created.
        """
        ifs = [self.pg_interfaces[i] for i in self.bd_ifs(bd_id)]
        for pg_if in ifs:
            swif = pg_if.sw_if_index
            for host in hosts[swif]:
                self.vapi.l2fib_add_del(
                    mac_pton(host.mac), bd_id, swif, is_add=0)

    def flush_int(self, swif, learned_hosts):
        """
        Flush swif L2 FIB entries.

        :param int swif: sw if index.
        """
        flushed = dict()
        self.vapi.l2fib_flush_int(swif)
        flushed[swif] = learned_hosts[swif]
        learned_hosts[swif] = []
        return flushed

    def flush_bd(self, bd_id, learned_hosts):
        """
        Flush bd_id L2 FIB entries.

        :param int bd_id: Bridge Domain id.
        """
        self.vapi.l2fib_flush_bd(bd_id)
        flushed = dict()
        ifs = [self.pg_interfaces[i] for i in self.bd_ifs(bd_id)]
        for pg_if in ifs:
            swif = pg_if.sw_if_index
            flushed[swif] = learned_hosts[swif]
            learned_hosts[swif] = []
        return flushed

    def flush_all(self):
        """
        Flush All L2 FIB entries.
        """
        self.vapi.l2fib_flush_all()

    def create_stream(self, src_if, packet_sizes, if_src_hosts, if_dst_hosts):
        """
        Create input packet stream for defined interface using hosts or
        deleted_hosts list.

        :param object src_if: Interface to create packet stream for.
        :param list packet_sizes: List of required packet sizes.
        :param boolean deleted: Set to True if deleted_hosts list required.
        :return: Stream of packets.
        """
        src_hosts = if_src_hosts[src_if.sw_if_index]
        if not src_hosts:
            return []
        pkts = []
        for dst_if in self.flows[src_if]:
            dst_swif = dst_if.sw_if_index
            if dst_swif not in if_dst_hosts:
                continue
            dst_hosts = if_dst_hosts[dst_swif]
            for dst_host in dst_hosts:
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
            except BaseException:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise
        for i in self.pg_interfaces:
            remaining_packet = self.get_next_packet_info_for_interface2(
                i, dst_sw_if_index, last_info[i.sw_if_index])
            self.assertTrue(
                remaining_packet is None,
                "Port %u: Packet expected from source %u didn't arrive" %
                (dst_sw_if_index, i.sw_if_index))

    def run_verify_test(self, bd_id, src_hosts, dst_hosts):
        # Test
        # Create incoming packet streams for packet-generator interfaces
        self.reset_packet_infos()
        ifs = [self.pg_interfaces[i] for i in self.bd_ifs(bd_id)]
        for i in ifs:
            pkts = self.create_stream(
                i, self.pg_if_packet_sizes,
                if_src_hosts=src_hosts,
                if_dst_hosts=dst_hosts)
            if pkts:
                i.add_stream(pkts)

        self.vapi.bridge_flags(bd_id=bd_id, is_set=0, flags=1)
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

    def run_verify_negat_test(self, bd_id, src_hosts, dst_hosts):
        # Test
        # Create incoming packet streams for packet-generator interfaces for
        # deleted MAC addresses
        self.reset_packet_infos()
        ifs = [self.pg_interfaces[i] for i in self.bd_ifs(bd_id)]
        for i in ifs:
            pkts = self.create_stream(
                i, self.pg_if_packet_sizes,
                if_src_hosts=src_hosts,
                if_dst_hosts=dst_hosts)
            if pkts:
                i.add_stream(pkts)

        self.vapi.bridge_flags(bd_id=bd_id, is_set=0, flags=1)
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

    def test_l2_fib_program100(self):
        """ L2 FIB - program 100 MACs
        """
        bd_id = 1
        hosts = self.create_hosts(100, subnet=17)
        self.config_l2_fib_entries(bd_id, hosts)
        self.run_verify_test(bd_id, hosts, hosts)

    def test_l2_fib_program100_delete12(self):
        """ L2 FIB - program 100, delete 12 MACs
        """
        bd_id = 1
        hosts = self.create_hosts(100, subnet=17)
        self.config_l2_fib_entries(bd_id, hosts)
        del_hosts = self.split_hosts(hosts, 12)
        self.delete_l2_fib_entry(bd_id, del_hosts)

        self.run_verify_test(bd_id, hosts, hosts)
        self.run_verify_negat_test(bd_id, hosts, del_hosts)

    def test_l2_fib_program100_add100(self):
        """ L2 FIB - program 100, add 100 MACs
        """
        bd_id = 1
        hosts = self.create_hosts(100, subnet=17)
        self.config_l2_fib_entries(bd_id, hosts)
        hosts2 = self.create_hosts(100, subnet=22)
        self.config_l2_fib_entries(bd_id, hosts2)
        self.run_verify_test(bd_id, hosts, hosts2)

    def test_l2_fib_program10_learn10(self):
        """ L2 FIB - program 10 MACs, learn 10
        """
        hosts = self.create_hosts(20, subnet=35)
        lhosts = self.split_hosts(hosts, 10)

        bd1 = 1
        bd2 = 2
        self.learn_hosts(bd1, lhosts)
        self.learn_hosts(bd2, lhosts)
        self.config_l2_fib_entries(bd1, hosts)
        self.config_l2_fib_entries(bd2, hosts)
        self.run_verify_test(bd1, lhosts, hosts)
        self.run_verify_test(bd2, lhosts, hosts)

    def test_l2_fib_flush_int(self):
        """ L2 FIB - flush interface
        """
        hosts = self.create_hosts(20, subnet=36)
        lhosts = self.split_hosts(hosts, 10)

        bd1 = 1
        self.learn_hosts(bd1, lhosts)
        self.config_l2_fib_entries(bd1, hosts)
        self.run_verify_test(bd1, lhosts, hosts)
        flushed = self.flush_int(self.pg_interfaces[0].sw_if_index, lhosts)
        self.run_verify_test(bd1, hosts, lhosts)
        self.run_verify_negat_test(bd1, hosts, flushed)

    def test_l2_fib_flush_bd(self):
        """ L2 FIB - flush BD
        """
        hosts = self.create_hosts(20, subnet=37)
        lhosts = self.split_hosts(hosts, 10)

        bd1 = 1
        self.learn_hosts(bd1, lhosts)
        self.config_l2_fib_entries(bd1, hosts)
        self.run_verify_test(bd1, lhosts, hosts)
        flushed = self.flush_bd(bd1, lhosts)
        self.run_verify_negat_test(bd1, hosts, flushed)

    def test_l2_fib_flush_all(self):
        """ L2 FIB - flush all
        """
        hosts = self.create_hosts(20, subnet=38)
        lhosts = self.split_hosts(hosts, 10)

        bd1 = 1
        bd2 = 2
        self.learn_hosts(bd1, lhosts)
        self.learn_hosts(bd2, lhosts)
        self.config_l2_fib_entries(bd1, hosts)
        self.config_l2_fib_entries(bd2, hosts)
        self.run_verify_test(bd1, hosts, lhosts)
        self.run_verify_test(bd2, hosts, lhosts)

        self.flush_all()

        self.run_verify_negat_test(bd1, hosts, lhosts)
        self.run_verify_negat_test(bd2, hosts, lhosts)

    def test_l2_fib_mac_learn_evs(self):
        """ L2 FIB - mac learning events
        """
        bd1 = 1
        hosts = self.create_hosts(10, subnet=39)

        self.vapi.want_l2_macs_events()
        self.learn_hosts(bd1, hosts)

        self.sleep(1)
        self.logger.info(self.vapi.ppcli("show l2fib"))
        evs = self.vapi.collect_events()
        action = VppEnum.vl_api_mac_event_action_t.MAC_EVENT_ACTION_API_ADD
        learned_macs = {
            e.mac[i].mac_addr.packed for e in evs for i in range(e.n_macs)
            if e.mac[i].action == action}
        macs = {h.bin_mac for swif in self.bd_ifs(bd1)
                for h in hosts[self.pg_interfaces[swif].sw_if_index]}
        self.vapi.want_l2_macs_events(enable_disable=0)
        self.assertEqual(len(learned_macs ^ macs), 0)

    def test_l2_fib_mac_learn_evs2(self):
        """ L2 FIB - mac learning events using want_l2_macs_events2
        """
        bd1 = 1
        hosts = self.create_hosts(10, subnet=39)

        self.vapi.l2fib_set_scan_delay(scan_delay=10)
        self.vapi.want_l2_macs_events2()
        self.sleep(1)
        self.learn_hosts(bd1, hosts)

        self.sleep(1)
        self.logger.info(self.vapi.ppcli("show l2fib"))
        evs = self.vapi.collect_events()
        action = VppEnum.vl_api_mac_event_action_t.MAC_EVENT_ACTION_API_ADD
        learned_macs = {
            e.mac[i].mac_addr.packed for e in evs for i in range(e.n_macs)
            if e.mac[i].action == action}
        macs = {h.bin_mac for swif in self.bd_ifs(bd1)
                for h in hosts[self.pg_interfaces[swif].sw_if_index]}
        self.vapi.want_l2_macs_events2(enable_disable=0)
        self.assertEqual(len(learned_macs ^ macs), 0)

    def test_l2_fib_macs_learn_max(self):
        """ L2 FIB - mac learning max macs in event
        """
        bd1 = 1
        hosts = self.create_hosts(10, subnet=40)

        ev_macs = 1
        self.vapi.want_l2_macs_events(max_macs_in_event=ev_macs)
        self.learn_hosts(bd1, hosts)

        self.sleep(1)
        self.logger.info(self.vapi.ppcli("show l2fib"))
        evs = self.vapi.collect_events()
        self.vapi.want_l2_macs_events(enable_disable=0)

        self.assertGreater(len(evs), 0)
        action = VppEnum.vl_api_mac_event_action_t.MAC_EVENT_ACTION_API_ADD
        learned_macs = {
            e.mac[i].mac_addr.packed for e in evs for i in range(e.n_macs)
            if e.mac[i].action == action}
        macs = {h.bin_mac for swif in self.bd_ifs(bd1)
                for h in hosts[self.pg_interfaces[swif].sw_if_index]}

        for e in evs:
            self.assertLess(len(e), ev_macs * 10)
        self.assertEqual(len(learned_macs ^ macs), 0)

    def test_l2_fib_macs_learn_max2(self):
        """ L2 FIB - mac learning max macs in event using want_l2_macs_events2
        """
        bd1 = 1
        hosts = self.create_hosts(10, subnet=40)

        ev_macs = 1
        self.vapi.l2fib_set_scan_delay(scan_delay=10)
        self.vapi.want_l2_macs_events2(max_macs_in_event=ev_macs)
        self.sleep(1)
        self.learn_hosts(bd1, hosts)

        self.sleep(1)
        self.logger.info(self.vapi.ppcli("show l2fib"))
        evs = self.vapi.collect_events()
        self.vapi.want_l2_macs_events2(enable_disable=0)

        self.assertGreater(len(evs), 0)
        action = VppEnum.vl_api_mac_event_action_t.MAC_EVENT_ACTION_API_ADD
        learned_macs = {
            e.mac[i].mac_addr.packed for e in evs for i in range(e.n_macs)
            if e.mac[i].action == action}
        macs = {h.bin_mac for swif in self.bd_ifs(bd1)
                for h in hosts[self.pg_interfaces[swif].sw_if_index]}

        for e in evs:
            self.assertLess(len(e), ev_macs * 10)
        self.assertEqual(len(learned_macs ^ macs), 0)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
