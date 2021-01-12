#!/usr/bin/env python3

from framework import VppTestCase


class TestCounters(VppTestCase):
    """ Counters C Unit Tests """

    @classmethod
    def setUpClass(cls):
        super(TestCounters, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestCounters, cls).tearDownClass()

    def setUp(self):
        super(TestCounters, self).setUp()

    def tearDown(self):
        super(TestCounters, self).tearDown()

    def test_counter_simple_expand(self):
        """ Simple Counter Expand """
        error = self.vapi.cli("test counter simple expand")

        if error:
            self.logger.critical(error)
            self.assertNotIn('failed', error)

    def test_counter_combined_expand(self):
        """ Combined Counter Expand """
        error = self.vapi.cli("test counter combined expand")

        if error:
            self.logger.critical(error)
            self.assertNotIn('failed', error)
