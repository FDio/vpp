#!/usr/bin/env python3
"""Delayed free (epoch based reclamation) tests"""

import re
import unittest

from framework import VppTestCase
from asfframework import VppTestRunner


class TestDelayedFreeMechanics(VppTestCase):
    """Delayed free vppinfra mechanics (no workers)"""

    @classmethod
    def setUpClass(cls):
        super(TestDelayedFreeMechanics, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestDelayedFreeMechanics, cls).tearDownClass()

    def test_mechanics(self):
        """marked vec/pool/hash route stale memory via delayed free"""
        rv = self.vapi.cli("test delayed-free")
        self.assertIn("delayed-free vec test OK", rv)
        self.assertIn("delayed-free vec-unmarked test OK", rv)
        self.assertIn("delayed-free pool test OK", rv)
        self.assertIn("delayed-free hash test OK", rv)


class TestDelayedFreeWorkers(VppTestCase):
    """Delayed free epoch engine (with workers)"""

    vpp_worker_count = 2

    @classmethod
    def setUpClass(cls):
        super(TestDelayedFreeWorkers, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestDelayedFreeWorkers, cls).tearDownClass()

    def show_delayed_free(self):
        out = self.vapi.cli("show delayed-free")
        stats = {}
        m = re.search(r"current epoch: (\d+)", out)
        stats["current_epoch"] = int(m.group(1))
        m = re.search(r"pending frees: (\d+)", out)
        stats["pending"] = int(m.group(1))
        m = re.search(r"total enqueued: (\d+), total freed: (\d+)", out)
        stats["enqueued"] = int(m.group(1))
        stats["freed"] = int(m.group(2))
        return stats

    def test_fib_churn(self):
        """ip table churn generates delayed frees which get reclaimed"""
        before = self.show_delayed_free()

        # each table create/delete cycle grows/frees mt-safe marked
        # fib pools and hashes
        for i in range(50):
            self.vapi.cli("ip table add 100")
            self.vapi.cli("ip route add 10.0.0.0/24 table 100 via drop")
            self.vapi.cli("ip route add 10.0.1.0/24 table 100 via drop")
            self.vapi.cli("ip route del 10.0.1.0/24 table 100 via drop")
            self.vapi.cli("ip route del 10.0.0.0/24 table 100 via drop")
            self.vapi.cli("ip table del 100")

        after = self.show_delayed_free()
        self.assertGreater(after["enqueued"], before["enqueued"])
        self.assertGreater(after["current_epoch"], before["current_epoch"])

        # workers poll, so every epoch should be acknowledged and all
        # parked memory freed shortly after the churn stops
        self.sleep(1, "waiting for workers to acknowledge epochs")
        final = self.show_delayed_free()
        self.assertEqual(final["pending"], 0)
        self.assertEqual(final["enqueued"], final["freed"])


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
