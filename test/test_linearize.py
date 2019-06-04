#!/usr/bin/env python

from framework import VppTestCase


class TestLinearize(VppTestCase):
    """ Chained Buffer Linearization c-unittest """

    @classmethod
    def setUpClass(cls):
        super(TestLinearize, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestLinearize, cls).tearDownClass()

    def setUp(self):
        super(TestLinearize, self).setUp()

    def tearDown(self):
        super(TestLinearize, self).tearDown()

    def test_linearize(self):
        error = self.vapi.cli("test linearize")

        if error:
            self.logger.critical(error)
            self.assertNotIn('failed', error)
