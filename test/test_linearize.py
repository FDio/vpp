#!/usr/bin/env python

from framework import VppTestCase


class TestLinearize(VppTestCase):
    """ Buffer Linearization """

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
        self.vapi.cli("test linearize")
