#!/usr/bin/env python
from random import choice
import unittest

from framework import VppTestCase, VppTestRunner

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP

packet_count = 257


class TestCounters(VppTestCase):
    """ Counters Test Case """

    @classmethod
    def setUpClass(cls):
        cls.extra_vpp_cmdline_config = ["stats", "{", "interval", "1", "}"]
        super(TestCounters, cls).setUpClass()

        # create 2 pg interfaces
        cls.create_pg_interfaces((0, 1))

        # packet sizes
        cls.pg_if_packet_sizes = [64, 512, 1518, 9018]

        # bridge domain id
        cls.bd_id = 1

        # setup all interfaces
        for i in cls.pg_interfaces:
            # put into bridge domain
            cls.vapi.sw_interface_set_l2_bridge(i.sw_if_index, bd_id=cls.bd_id)

            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

        cls.vapi.collect_detailed_interface_stats()

    def create_stream(self, src_if, dst_if, packet_sizes):
        """Create input packet stream for defined interface.

        :param VppInterface src_if: Interface to create packet stream for.
        :param list packet_sizes: Required packet sizes.
        """
        kinds = ('unicast', 'broadcast', 'multicast')
        pkts = []
        pkt_stats_by_if_index = {}
        for i in range(0, packet_count):
            info = self.create_packet_info(src_if, dst_if)
            payload = self.info_to_payload(info)
            t = choice(kinds)
            if t == 'unicast':
                p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                     IP(src=src_if.remote_ip4, dst=dst_if.remote_ip4) /
                     UDP(sport=1234, dport=1234) /
                     Raw(payload))
            elif t == 'multicast':
                p = (Ether(dst="ff:00:00:00:00:01", src=src_if.remote_mac) /
                     IP(src=src_if.remote_ip4, dst=dst_if.remote_ip4) /
                     UDP(sport=1234, dport=1234) /
                     Raw(payload))
            else:  # broadcast
                p = (Ether(dst="ff:ff:ff:ff:ff:ff", src=src_if.remote_mac) /
                     IP(src=src_if.remote_ip4, dst='255.255.255.255') /
                     UDP(sport=1234, dport=1234) /
                     Raw(payload))
            info.data = p.copy()
            size = packet_sizes[(i // 2) % len(packet_sizes)]
            self.extend_packet(p, size)
            pkts.append(p)
            for sw_if_index in (src_if.sw_if_index, dst_if.sw_if_index):
                if sw_if_index not in pkt_stats_by_if_index:
                    pkt_stats_by_if_index[sw_if_index] = {
                        'rx_packets': 0, 'rx_bytes': 0,
                        'rx_unicast_packets': 0, 'rx_unicast_bytes': 0,
                        'rx_multicast_packets': 0, 'rx_multicast_bytes': 0,
                        'rx_broadcast_packets': 0, 'rx_broadcast_bytes': 0,
                        'tx_packets': 0, 'tx_bytes': 0,
                        'tx_unicast_packets': 0, 'tx_unicast_bytes': 0,
                        'tx_multicast_packets': 0, 'tx_multicast_bytes': 0,
                        'tx_broadcast_packets': 0, 'tx_broadcast_bytes': 0, }
            src_stats = pkt_stats_by_if_index[src_if.sw_if_index]
            src_stats['rx_packets'] += 1
            src_stats['rx_bytes'] += len(p)
            src_stats['rx_%s_packets' % t] += 1
            src_stats['rx_%s_bytes' % t] += len(p)
            dst_stats = pkt_stats_by_if_index[dst_if.sw_if_index]
            dst_stats['tx_packets'] += 1
            dst_stats['tx_bytes'] += len(p)
            dst_stats['tx_%s_packets' % t] += 1
            dst_stats['tx_%s_bytes' % t] += len(p)
        self.stream = pkts
        self.pkt_stats_by_if_index = pkt_stats_by_if_index

    @staticmethod
    def update_counters(counters_dict, counters):
        for c in counters.data:
            counters_dict[c.sw_if_index] = c

    def wait_for_counters(self, interfaces):
        cnt = len(interfaces)
        counters = {}
        while len(counters) < cnt:
            e = self.vapi.wait_for_event(
                1, "vnet_per_interface_combined_counters")
            self.update_counters(counters, e)
        return counters

    def compare_counter(self, interface, pre_counter, post_counter, pkt_stats):
        for key, value in pkt_stats.iteritems():
            self.assert_equal(getattr(post_counter, key),
                              getattr(pre_counter, key) + value,
                              "%s for interface %s" % (key, interface),
                              "\npre-counter: %s\npost-counter: %s\n"
                              "expect-diff: %s" %
                              (pre_counter, post_counter, pkt_stats))

    def compare_counters(self, interfaces, pre_counters, post_counters,
                         pkt_stats_by_if_index):
        for i in interfaces:
            pre_counter = None
            for _, c in pre_counters.iteritems():
                if i.sw_if_index == c.sw_if_index:
                    pre_counter = c
            self.assertIsNotNone(
                pre_counter, "Interface %s with index %s not present in "
                "pre_counters dictionary" % (i.name, i.sw_if_index))
            post_counter = None
            for _, c in post_counters.iteritems():
                if i.sw_if_index == c.sw_if_index:
                    post_counter = c
            self.assertIsNotNone(
                post_counter, "Interface %s with index %s not present in "
                "post_counters dictionary" % (i.name, i.sw_if_index))
            self.assertIn(i.sw_if_index, pkt_stats_by_if_index,
                          "Interface %s with index %s not present in packet "
                          "stats dictionary" % (i.name, i.sw_if_index))
            self.compare_counter(i.name, pre_counter, post_counter,
                                 pkt_stats_by_if_index[i.sw_if_index])

    def test_counters(self):
        """ Counters test """

        self.create_stream(self.pg0, self.pg1, self.pg_if_packet_sizes)
        self.pg0.add_stream(self.stream)

        self.vapi.want_per_interface_combined_stats(
            sw_ifs=[i.sw_if_index for i in self.pg_interfaces])

        self.vapi.collect_events()  # throw away currently stored events

        pre_counters = self.wait_for_counters(self.pg_interfaces)

        self.vapi.collect_events()

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        post_counters = self.wait_for_counters(self.pg_interfaces)

        self.compare_counters(self.pg_interfaces, pre_counters, post_counters,
                              self.pkt_stats_by_if_index)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
