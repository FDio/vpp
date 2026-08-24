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

    def test_scalar_frame_enqueue(self):
        """Scalar Frame Enqueue Compatibility"""
        error = self.vapi.cli("test buffer scalar-frame-enqueue")

        if error:
            self.logger.critical(error)
            self.assertNotIn("failed", error)


def buffer_pool_config(layout):
    return [
        "buffers",
        "{",
        "layout",
        layout,
        "page-size",
        "4k",
        "buffers-per-numa",
        "128",
        "default",
        "data-size",
        "3072",
        "}",
    ]


def buffer_pool_totals(test):
    output = test.vapi.cli("show buffers")
    totals = []

    for line in output.splitlines():
        fields = line.split()
        if fields and fields[0].startswith("default-numa-"):
            totals.append(int(fields[5]))

    test.assertTrue(totals, "no default buffer pools found")
    return totals


class TestBufferPoolPackedLayout(VppAsfTestCase):
    """Packed Buffer Pool Layout Tests"""

    extra_vpp_config = buffer_pool_config("packed")

    def test_4k_pages_large_buffers_are_not_underutilized(self):
        """4K pages with large buffers populate one buffer per page"""
        for total in buffer_pool_totals(self):
            self.assertGreaterEqual(total, 127)


class TestBufferPoolNaturalLayout(VppAsfTestCase):
    """Natural Buffer Pool Layout Tests"""

    extra_vpp_config = buffer_pool_config("natural")

    def test_4k_pages_preserve_natural_alignment(self):
        """Natural layout skips globally aligned buffers spanning pages"""
        for total in buffer_pool_totals(self):
            self.assertGreater(total, 0)
            self.assertLess(total, 127)
