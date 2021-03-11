#!/usr/bin/env python3

import unittest
import psutil
from vpp_papi.vpp_stats import VPPStats

from framework import tag_fixme_vpp_workers
from framework import VppTestCase, VppTestRunner
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP


@tag_fixme_vpp_workers
class StatsClientTestCase(VppTestCase):
    """Test Stats Client"""

    @classmethod
    def setUpClass(cls):
        super(StatsClientTestCase, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(StatsClientTestCase, cls).tearDownClass()

    @classmethod
    def setUpConstants(cls):
        cls.extra_vpp_statseg_config = "per-node-counters on"
        cls.extra_vpp_statseg_config += "update-interval 0.1"
        super(StatsClientTestCase, cls).setUpConstants()

    def test_set_errors(self):
        """Test set errors"""
        self.assertEqual(self.statistics.set_errors(), {})
        self.assertEqual(self.statistics.get_counter('/err/ethernet-input/no'),
                         [0])

    def test_client_fd_leak(self):
        """Test file descriptor count - VPP-1486"""

        cls = self.__class__
        p = psutil.Process()
        initial_fds = p.num_fds()

        for _ in range(100):
            stats = VPPStats(socketname=cls.stats_sock)
            stats.disconnect()

        ending_fds = p.num_fds()
        self.assertEqual(initial_fds, ending_fds,
                         "initial client side file descriptor count: %s "
                         "is not equal to "
                         "ending client side file descriptor count: %s" % (
                             initial_fds, ending_fds))

    def test_symlink_add_del_interfaces(self):
        """Test symlinks when adding and deleting interfaces"""
        self.create_loopback_interfaces(1)
        self.create_pg_interfaces(range(1))
        self.loop0.remove_vpp_config()
        self.create_pg_interfaces(range(2))

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

        p = list()
        bytes_to_send = 0
        for i in range(5):
            packet = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
                      IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4))
            bytes_to_send += len(packet)
            p.append(packet)

        tx_before_sending = self.statistics.get_counter('/interfaces/pg1/tx$')
        rx_before_sending = self.statistics.get_counter('/interfaces/pg0/rx$')
        self.send_and_expect(self.pg0, p, self.pg1)
        tx = self.statistics.get_counter('/interfaces/pg1/tx$')
        rx = self.statistics.get_counter('/interfaces/pg0/rx$')

        # We wait for nodes to update.
        time.sleep(0.1)
        vectors = self.statistics.get_counter('/nodes/pg1-tx/vectors')

        self.assertEqual(tx[0]['bytes'] - tx_before_sending[0]['bytes'],
                         bytes_to_send)
        self.assertEqual(tx[0]['packets'] - tx_before_sending[0]['packets'],
                         5)
        self.assertEqual(rx[0]['bytes'] - rx_before_sending[0]['bytes'],
                         bytes_to_send)
        self.assertEqual(rx[0]['packets'] - rx_before_sending[0]['packets'],
                         5)
        self.assertEqual(vectors[0], rx[0]['packets'])

        for i in self.pg_interfaces:
            i.unconfig()
            i.admin_down()

    def test_index_consistency(self):
        """Test index consistency despite changes in the stats"""
        d = self.statistics.ls('/if/names')
        self.create_pg_interfaces(range(10))
        retries = 0
        while True:
            try:
                s = self.statistics.dump(d)
                k, v = s.popitem()
                self.assertEqual(len(v), 11)
                break
            except self.statistics.VPPStatsIOError:
                if retries > 10:
                    break
                retries += 1

    @unittest.skip("Manual only")
    def test_mem_leak(self):
        def loop():
            print('Running loop')
            for i in range(50):
                rv = self.vapi.papi.tap_create_v2(id=i, use_random_mac=1)
                self.assertEqual(rv.retval, 0)
                rv = self.vapi.papi.tap_delete_v2(sw_if_index=rv.sw_if_index)
                self.assertEqual(rv.retval, 0)

        before = self.statistics.get_counter('/mem/statseg/used')
        loop()
        self.vapi.cli("memory-trace on stats-segment")
        for j in range(100):
            loop()
        print(self.vapi.cli("show memory stats-segment verbose"))
        print('AFTER', before,
              self.statistics.get_counter('/mem/statseg/used'))

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
