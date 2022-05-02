#!/usr/bin/env python3

import unittest
import random

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP

from framework import VppTestCase, VppTestRunner
from util import Host, ppp


class TestL2LearnLimitEnable(VppTestCase):
    """L2 Global Learn limit Test Case"""

    @classmethod
    def setUpClass(self):
        super(TestL2LearnLimitEnable, self).setUpClass()
        self.create_pg_interfaces(range(3))

    @classmethod
    def tearDownClass(cls):
        super(TestL2LearnLimitEnable, cls).tearDownClass()

    def create_hosts(self, pg_if, n_hosts_per_if, subnet):
        """
        Create required number of host MAC addresses and distribute them among
        interfaces. Create host IPv4 address for every host MAC address.

        :param int n_hosts_per_if: Number of per interface hosts to
             create MAC/IPv4 addresses for.
        """

        hosts = dict()
        swif = pg_if.sw_if_index

        def mac(j):
            return "00:00:%02x:ff:%02x:%02x" % (subnet, swif, j)

        def ip(j):
            return "172.%02u.1%02x.%u" % (subnet, swif, j)

        def h(j):
            return Host(mac(j), ip(j))

        hosts[swif] = [h(j) for j in range(n_hosts_per_if)]

        return hosts

    def learn_hosts(self, pg_if, bd_id, hosts):
        """
        Create and send per interface L2 MAC broadcast packet stream to
        let the bridge domain learn these MAC addresses.

        :param int bd_id: BD to teach
        :param dict hosts: dict of hosts per interface
        """

        self.vapi.bridge_flags(bd_id=bd_id, is_set=1, flags=1)

        swif = pg_if.sw_if_index
        packets = [Ether(dst="ff:ff:ff:ff:ff:ff", src=host.mac) for host in hosts[swif]]
        pg_if.add_stream(packets)
        self.logger.info("Sending broadcast eth frames for MAC learning")
        self.pg_start()

    def test_l2bd_learnlimit01(self):
        """L2BD test with learn Limit"""
        self.vapi.want_l2_macs_events(enable_disable=1, learn_limit=10)
        hosts = self.create_hosts(self.pg_interfaces[0], 20, 1)
        fhosts = self.create_hosts(self.pg_interfaces[1], 1, 2)

        # inject 20 mac addresses on bd1
        self.learn_hosts(self.pg_interfaces[0], 1, hosts)

        # inject 1 mac address on bd2
        self.learn_hosts(self.pg_interfaces[1], 2, fhosts)

        lfs1 = self.vapi.l2_fib_table_dump(1)
        lfs2 = self.vapi.l2_fib_table_dump(2)

        # check that only 10 macs are learned.
        self.assertEqual(len(lfs1), 10)

        # check that bd2 was not able to learn
        self.assertEqual(len(lfs2), 0)

    def setUp(self):
        super(TestL2LearnLimitEnable, self).setUp()

        self.vapi.bridge_domain_add_del(bd_id=1)
        self.vapi.bridge_domain_add_del(bd_id=2)

        self.vapi.sw_interface_set_l2_bridge(self.pg_interfaces[0].sw_if_index, bd_id=1)
        self.vapi.sw_interface_set_l2_bridge(self.pg_interfaces[1].sw_if_index, bd_id=2)

    def tearDown(self):
        super(TestL2LearnLimitEnable, self).tearDown()
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.pg_interfaces[0].sw_if_index, bd_id=1, enable=0
        )
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=self.pg_interfaces[1].sw_if_index, bd_id=2, enable=0
        )
        self.vapi.bridge_domain_add_del(bd_id=1, is_add=0)
        self.vapi.bridge_domain_add_del(bd_id=2, is_add=0)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
