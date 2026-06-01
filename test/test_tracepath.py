# SPDX-License-Identifier: Apache-2.0
import unittest
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from asfframework import VppTestRunner
from config import config
from framework import VppTestCase
from vpp_ip_route import FibPathType, VppIpRoute, VppRoutePath


class TestTracePath(VppTestCase):
    """Tracepath plugin tests"""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.create_pg_interfaces(range(2))
        for i in cls.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    @classmethod
    def tearDownClass(cls):
        for i in cls.pg_interfaces:
            i.admin_down()
        super().tearDownClass()

    def test_tracepath(self):
        """Test tracepath on main thread"""
        # Send forwarded t
        n_fwd, n_drop = 5, 7

        # Add drop route
        drop_route = VppIpRoute(
            self,
            "192.0.2.0",
            24,
            [VppRoutePath("0.0.0.0", 0xFFFFFFFF, type=FibPathType.FIB_PATH_TYPE_DROP)],
        )
        drop_route.add_vpp_config()

        # Send traffic, which will be either forwarded or dropped
        self.send_and_expect(
            self.pg0,
            list(
                (
                    Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
                    / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4)
                    / UDP(sport=1234, dport=5678)
                )
                * n_fwd
            )
            + list(
                (
                    Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
                    / IP(src=self.pg0.remote_ip4, dst="192.0.2.1")
                    / UDP(sport=1234, dport=5678)
                )
                * n_drop
            ),
            self.pg1,
            n_rx=n_fwd,
        )

        # CLI Output verification
        out = self.vapi.cli("show trace paths")
        self.assertEqual(out.count("Count:"), 2)
        self.assertIn(f"Count: {n_drop}", out)
        self.assertIn(f"Count: {n_fwd}", out)
        self.assertIn("ip4-drop -> error-drop -> drop", out)
        self.assertIn("ip4-rewrite -> pg1-output -> pg1-tx", out)

        # Paths sorted by count descending: index 0 = drop, index 1 = fwd.
        # Verify 'show trace path' shows only the traces belonging to that path.
        out = self.vapi.cli("show trace path 0")
        self.assertIn("ip4-drop", out)
        self.assertNotIn("ip4-rewrite", out)

        out = self.vapi.cli("show trace path 1")
        self.assertIn("ip4-rewrite", out)
        self.assertNotIn("ip4-drop", out)

        # API Output verification
        fwd_nodes = [
            "pg-input",
            "ethernet-input",
            "ip4-input",
            "ip4-lookup",
            "ip4-rewrite",
            "pg1-output",
            "pg1-tx",
        ]
        drop_nodes = [
            "pg-input",
            "ethernet-input",
            "ip4-input",
            "ip4-lookup",
            "ip4-drop",
            "error-drop",
            "drop",
        ]
        paths = self.vapi.tracepath_dump()

        # Two unique paths, sorted by packet count descending: drop first, fwd second
        self.assertEqual(len(paths), 2)
        drop_path = paths[0]
        fwd_path = paths[1]

        self.assertEqual(drop_path.n_pkts, n_drop)
        self.assertEqual(fwd_path.n_pkts, n_fwd)

        # Exact node count and sequence for each path
        self.assertEqual(drop_path.n_nodes, len(drop_nodes))
        self.assertEqual(fwd_path.n_nodes, len(fwd_nodes))

        drop_names = [n.name for n in drop_path.nodes]
        fwd_names = [n.name for n in fwd_path.nodes]
        self.assertEqual(drop_names, drop_nodes)
        self.assertEqual(fwd_names, fwd_nodes)

        # Seen on main thread only (thread_index 0 = bit 0)
        self.assertEqual(drop_path.thread_bitmap, 1)
        self.assertEqual(fwd_path.thread_bitmap, 1)

        # Cleanup
        drop_route.remove_vpp_config()


class TestTracePathMultiThread(VppTestCase):
    """Tracepath plugin multi-thread tests"""

    vpp_worker_count = 2

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.create_pg_interfaces(range(2))
        for i in cls.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    @classmethod
    def tearDownClass(cls):
        for i in cls.pg_interfaces:
            i.admin_down()
        super().tearDownClass()

    def test_tracepath_multi_thread(self):
        """Test that show trace paths aggregates paths across worker threads"""
        n_pkts = 5

        fwd_pkt = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4)
            / UDP(sport=1234, dport=5678)
        )
        drop_pkt = (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst="192.0.2.1")
            / UDP(sport=1234, dport=5678)
        )

        drop_route = VppIpRoute(
            self,
            "192.0.2.0",
            24,
            [VppRoutePath("0.0.0.0", 0xFFFFFFFF, type=FibPathType.FIB_PATH_TYPE_DROP)],
        )
        drop_route.add_vpp_config()

        # Send traffic & do not clear traces after first send_and_expect call
        # fwd path traffic (workers 0, 1)
        self.send_and_expect(self.pg0, [fwd_pkt] * n_pkts, self.pg1, worker=0)
        self.send_and_expect(
            self.pg0, [fwd_pkt] * n_pkts, self.pg1, worker=1, trace=False
        )

        # drop path traffic (worker 0)
        self.pg_send(self.pg0, [drop_pkt] * n_pkts, trace=False)

        # Verify CLI output
        out = self.vapi.cli("show trace paths")

        # Two unique paths: forwarding and drop
        self.assertEqual(out.count("Count:"), 2)

        # Fwd path seen on workers 0,1
        self.assertIn(f"Count: {n_pkts * 2}", out)
        fwd_line = next(l for l in out.splitlines() if f"Count: {n_pkts * 2}" in l)
        # check comma is present, which is used
        self.assertIn("Threads: [1, 2]", fwd_line)

        # Drop path seen on worker 0 only
        self.assertIn(f"Count: {n_pkts}", out)
        drop_line = next(l for l in out.splitlines() if f"Count: {n_pkts}" in l)
        # No comma, used to delimit between worker threads
        self.assertIn("Threads: [1]", drop_line)

        # Verify API Output
        fwd_nodes = [
            "pg-input",
            "ethernet-input",
            "ip4-input",
            "ip4-lookup",
            "ip4-rewrite",
            "pg1-output",
            "pg1-tx",
        ]
        drop_nodes = [
            "pg-input",
            "ethernet-input",
            "ip4-input",
            "ip4-lookup",
            "ip4-drop",
            "error-drop",
            "drop",
        ]

        paths = self.vapi.tracepath_dump()

        # Two unique paths, sorted by packet count descending:
        self.assertEqual(len(paths), 2)
        fwd_path = paths[0]
        drop_path = paths[1]

        self.assertEqual(fwd_path.n_pkts, n_pkts * 2)
        self.assertEqual(drop_path.n_pkts, n_pkts)

        # Exact node sequences
        self.assertEqual(fwd_path.n_nodes, len(fwd_nodes))
        self.assertEqual(drop_path.n_nodes, len(drop_nodes))
        fwd_names = [n.name for n in fwd_path.nodes]
        drop_names = [n.name for n in drop_path.nodes]
        self.assertEqual(fwd_names, fwd_nodes)
        self.assertEqual(drop_names, drop_nodes)

        # fwd seen on workers 0+1 (thread_index 1 and 2)
        self.assertEqual(fwd_path.thread_bitmap, 0b110)
        # drop seen on worker 0 only (thread_index 1)
        self.assertEqual(drop_path.thread_bitmap, 0b010)

        # Cleanup
        drop_route.remove_vpp_config()


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
