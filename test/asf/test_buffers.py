#!/usr/bin/env python3

from asfframework import VppAsfTestCase


class TestBuffers(VppAsfTestCase):
    """Buffer C Unit Tests"""

    @classmethod
    def setUpClass(cls):
        super(TestBuffers, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestBuffers, cls).tearDownClass()

    def setUp(self):
        super(TestBuffers, self).setUp()

    def tearDown(self):
        super(TestBuffers, self).tearDown()

    def test_linearize(self):
        """Chained Buffer Linearization"""
        error = self.vapi.cli("test chained-buffer-linearization")

        if error:
            self.logger.critical(error)
            self.assertNotIn("failed", error)


class TestBufferPoolPageBoundary(VppAsfTestCase):
    """Buffer Pool Page Boundary Tests"""

    extra_vpp_config = [
        "buffers",
        "{",
        "page-size",
        "4k",
        "buffers-per-numa",
        "128",
        "default",
        "data-size",
        "3072",
        "}",
    ]

    def test_4k_pages_large_buffers_are_not_underutilized(self):
        """4K pages with large buffers populate one buffer per page"""
        output = self.vapi.cli("show buffers")
        totals = []

        for line in output.splitlines():
            fields = line.split()
            if fields and fields[0].startswith("default-numa-"):
                totals.append(int(fields[5]))

        self.assertTrue(totals, "no default buffer pools found")
        for total in totals:
            self.assertGreaterEqual(total, 127)
