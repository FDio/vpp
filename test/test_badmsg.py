#!/usr/bin/env python

import unittest

from framework import VppTestCase, VppTestRunner

class TestBadMsg(VppTestCase):
    """ Binary API negative tests """

    @classmethod
    def setUpClass(cls):
        super(TestBadMsg, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestBadMsg, cls).tearDownClass()

    def setUp(self):
        super(TestBadMsg, self).setUp()

    def tearDown(self):
        super(TestBadMsg, self).tearDown()

    def test_badmsg(self):
        """ Send bad message id """
        self.vapi.cli("test badmsg")

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
