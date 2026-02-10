#!/usr/bin/env python3
# Copyright (c) 2021 Graphiant, Inc.

import unittest

from config import config
from asfframework import VppAsfTestCase, VppTestRunner
from vpp_policer import VppPolicer

# Default for the tests is 10s of "Green" packets at 8Mbps, ie. 10M bytes.
# The policer helper CLI "sends" 500 byte packets, so default is 20000.

TEST_RATE = 8000  # kbps
TEST_BURST = 10000  # ms

CIR_OK = 8500  # CIR in kbps, above test rate
CIR_LOW = 7000  # CIR in kbps, below test rate
EIR_OK = 9000  # EIR in kbps, above test rate
EIR_LOW = 7500  # EIR in kbps, below test rate

NUM_PKTS = 20000

CBURST = 100000  # Committed burst in bytes
EBURST = 200000  # Excess burst in bytes


@unittest.skipIf("policer" in config.excluded_plugins, "Exclude Policer plugin tests")
class TestPolicer(VppAsfTestCase):
    """Policer Test Case"""

    def run_policer_test(
        self, type, cir, cb, eir, eb, rate=8000, burst=10000, colour=0
    ):
        """
        Configure a Policer and push traffic through it.
        """
        types = {
            "1R2C": 0,
            "1R3C": 1,
            "2R3C": 3,
        }

        pol_type = types.get(type)
        policer = VppPolicer(
            self,
            "pol1",
            cir,
            eir,
            cb,
            eb,
            rate_type=0,
            type=pol_type,
            color_aware=colour,
        )
        policer.add_vpp_config()

        error = self.vapi.cli(
            f"test policing index {policer.policer_index} rate {rate} "
            f"burst {burst} colour {colour}"
        )

        stats = policer.get_stats()
        policer.remove_vpp_config()

        return stats

    def test_policer_1r2c(self):
        """Single rate, 2 colour policer"""
        stats = self.run_policer_test("1R2C", CIR_OK, CBURST, 0, 0)
        self.assertEqual(stats["conform_packets"], NUM_PKTS)

        stats = self.run_policer_test("1R2C", CIR_LOW, CBURST, 0, 0)
        self.assertLess(stats["conform_packets"], NUM_PKTS)
        self.assertEqual(stats["exceed_packets"], 0)
        self.assertGreater(stats["violate_packets"], 0)

        stats = self.run_policer_test("1R2C", CIR_LOW, CBURST, 0, 0, colour=2)
        self.assertEqual(stats["violate_packets"], NUM_PKTS)

    def test_policer_1r3c(self):
        """Single rate, 3 colour policer"""
        stats = self.run_policer_test("1R3C", CIR_OK, CBURST, 0, 0)
        self.assertEqual(stats["conform_packets"], NUM_PKTS)

        stats = self.run_policer_test("1R3C", CIR_LOW, CBURST, 0, EBURST)
        self.assertLess(stats["conform_packets"], NUM_PKTS)
        self.assertGreater(stats["exceed_packets"], 0)
        self.assertGreater(stats["violate_packets"], 0)

        stats = self.run_policer_test("1R3C", CIR_LOW, CBURST, 0, EBURST, colour=1)
        self.assertEqual(stats["conform_packets"], 0)
        self.assertGreater(stats["exceed_packets"], 0)
        self.assertGreater(stats["violate_packets"], 0)

        stats = self.run_policer_test("1R3C", CIR_LOW, CBURST, 0, EBURST, colour=2)
        self.assertEqual(stats["violate_packets"], NUM_PKTS)

    def test_policer_2r3c(self):
        """Dual rate, 3 colour policer"""
        stats = self.run_policer_test("2R3C", CIR_OK, CBURST, EIR_OK, EBURST)
        self.assertEqual(stats["conform_packets"], NUM_PKTS)

        stats = self.run_policer_test("2R3C", CIR_LOW, CBURST, EIR_OK, EBURST)
        self.assertLess(stats["conform_packets"], NUM_PKTS)
        self.assertGreater(stats["exceed_packets"], 0)
        self.assertEqual(stats["violate_packets"], 0)

        stats = self.run_policer_test("2R3C", CIR_LOW, CBURST, EIR_LOW, EBURST)
        self.assertLess(stats["conform_packets"], NUM_PKTS)
        self.assertGreater(stats["exceed_packets"], 0)
        self.assertGreater(stats["violate_packets"], 0)

        stats = self.run_policer_test("2R3C", CIR_LOW, CBURST, EIR_OK, EBURST, colour=1)
        self.assertEqual(stats["exceed_packets"], NUM_PKTS)

        stats = self.run_policer_test(
            "2R3C", CIR_LOW, CBURST, EIR_LOW, EBURST, colour=1
        )
        self.assertEqual(stats["conform_packets"], 0)
        self.assertGreater(stats["exceed_packets"], 0)
        self.assertGreater(stats["violate_packets"], 0)

        stats = self.run_policer_test("2R3C", CIR_LOW, CBURST, EIR_OK, EBURST, colour=2)
        self.assertEqual(stats["violate_packets"], NUM_PKTS)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
