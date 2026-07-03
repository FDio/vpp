#!/usr/bin/env python3
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Cisco and/or its affiliates.
#

import unittest

from asfframework import VppAsfTestCase, VppTestRunner, tag_fixme_vpp_workers


@tag_fixme_vpp_workers
class TestADJ(VppAsfTestCase):
    """ADJ Test Case"""

    @classmethod
    def setUpClass(cls):
        super(TestADJ, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestADJ, cls).tearDownClass()

    def run_adj_unit_test(self, name=None):
        cmd = "test adj" if name is None else "test adj %s" % name
        error = self.vapi.cli(cmd)

        if error:
            self.logger.critical(error)
        self.assertEqual("", error)

    def test_adj_bfd_positive(self):
        """ADJ BFD positive state transitions"""
        self.run_adj_unit_test("positive")

    def test_adj_bfd_duplicate_create(self):
        """ADJ BFD duplicate create handling"""
        self.run_adj_unit_test("duplicate-create")

    def test_adj_bfd_negative(self):
        """ADJ BFD ignored event cases"""
        self.run_adj_unit_test("negative")


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
