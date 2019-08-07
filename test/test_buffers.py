#!/usr/bin/env python

from framework import VppTestCase
from framework import unittest


class TestBuffers(VppTestCase):
    """ Buffer C Unit Tests """

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
        """ Chained Buffer Linearization """
        error = self.vapi.cli("test chained-buffer-linearization")

        if error:
            self.logger.critical(error)
            self.assertNotIn('failed', error)
