#!/usr/bin/env python3

import unittest
import psutil
from vpp_papi.vpp_stats import VPPStats

from framework import VppTestCase
from asfframework import VppTestRunner
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP


class StatsClientTestCase(VppTestCase):
    """Test Stats Client"""

    @classmethod
    def setUpClass(cls):
        super(StatsClientTestCase, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(StatsClientTestCase, cls).tearDownClass()

    def setUp(self):
        super(StatsClientTestCase, self).setUp()
        self.create_pg_interfaces([])

    def tearDown(self):
        super(StatsClientTestCase, self).tearDown()
        for i in self.pg_interfaces:
            i.unconfig()
            i.admin_down()

    @classmethod
    def setUpConstants(cls):
        cls.extra_vpp_statseg_config = "per-node-counters on"
        cls.extra_vpp_statseg_config += "update-interval 0.05"
        super(StatsClientTestCase, cls).setUpConstants()

    def test_set_errors(self):
        """Test set errors"""
        self.assertEqual(self.statistics.set_errors(), {})
        self.assertEqual(
            self.statistics.get_counter("/err/ethernet-input/no error"),
            [0] * (1 + self.vpp_worker_count),
        )

    def test_client_fd_leak(self):
        """Test file descriptor count - VPP-1486"""

        cls = self.__class__
        p = psutil.Process()
        initial_fds = p.num_fds()

        for _ in range(100):
            stats = VPPStats(socketname=cls.get_stats_sock_path())
            stats.disconnect()

        ending_fds = p.num_fds()
        self.assertEqual(
            initial_fds,
            ending_fds,
            "initial client side file descriptor count: %s "
            "is not equal to "
            "ending client side file descriptor count: %s" % (initial_fds, ending_fds),
        )

    def test_symlink_values(self):
        """Test symlinks reported values"""
        self.create_pg_interfaces(range(2))

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

        p = list()
        for i in range(5):
            packet = Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) / IP(
                src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4
            )
            p.append(packet)

        self.send_and_expect(self.pg0, p, self.pg1)
        pg1_tx = self.statistics.get_counter("/interfaces/pg1/tx")
        if_tx = self.statistics.get_counter("/if/tx")

        self.assertEqual(pg1_tx[0]["bytes"], if_tx[0][self.pg1.sw_if_index]["bytes"])

    def test_symlink_add_del_interfaces(self):
        """Test symlinks when adding and deleting interfaces"""
        # We first create and delete interfaces
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
            packet = Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) / IP(
                src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4
            )
            bytes_to_send += len(packet)
            p.append(packet)

        tx_before_sending = self.statistics.get_counter("/interfaces/pg1/tx")
        rx_before_sending = self.statistics.get_counter("/interfaces/pg0/rx")
        self.send_and_expect(self.pg0, p, self.pg1)
        tx = self.statistics.get_counter("/interfaces/pg1/tx")
        rx = self.statistics.get_counter("/interfaces/pg0/rx")

        # We wait for nodes symlinks to update (interfaces created/deleted).
        self.virtual_sleep(1)
        vectors = self.statistics.get_counter("/nodes/pg1-tx/vectors")

        rx_bytes = 0
        rx_packets = 0
        tx_bytes = 0
        tx_packets = 0
        for i in range(1 + self.vpp_worker_count):
            rx_bytes += rx[i]["bytes"] - rx_before_sending[i]["bytes"]
            rx_packets += rx[i]["packets"] - rx_before_sending[i]["packets"]
            tx_bytes += tx[i]["bytes"] - tx_before_sending[i]["bytes"]
            tx_packets += tx[i]["packets"] - tx_before_sending[i]["packets"]
        self.assertEqual(tx_bytes, bytes_to_send)
        self.assertEqual(tx_packets, 5)
        self.assertEqual(rx_bytes, bytes_to_send)
        self.assertEqual(rx_packets, 5)
        self.assertEqual(vectors[0], rx[0]["packets"])

    def test_index_consistency(self):
        """Test index consistency despite changes in the stats"""
        d = self.statistics.ls(["/if/names"])
        self.create_loopback_interfaces(10)
        for i in range(10):
            try:
                s = self.statistics.dump(d)
                break
            except:
                pass
        k, v = s.popitem()
        self.assertEqual(len(v), 11)

        for i in self.lo_interfaces:
            i.remove_vpp_config()

    @unittest.skip("Manual only")
    def test_mem_leak(self):
        def loop():
            print("Running loop")
            for i in range(50):
                rv = self.vapi.papi.tap_create_v2(id=i, use_random_mac=1)
                self.assertEqual(rv.retval, 0)
                rv = self.vapi.papi.tap_delete_v2(sw_if_index=rv.sw_if_index)
                self.assertEqual(rv.retval, 0)

        before = self.statistics.get_counter("/mem/statseg/used")
        loop()
        self.vapi.cli("memory-trace on stats-segment")
        for j in range(100):
            loop()
        print(self.vapi.cli("show memory stats-segment verbose"))
        print("AFTER", before, self.statistics.get_counter("/mem/statseg/used"))


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
