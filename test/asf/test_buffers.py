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
