#!/usr/bin/env python

import framework

from framework import VppTestCase, VppTestRunner
from framework import unittest


class TestFIB(VppTestCase):
    """ FIB Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestFIB, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestFIB, cls).tearDownClass()

    def test_fib(self):
        """ FIB Unit Tests """
        error = self.vapi.cli("test fib")

        if error:
            self.logger.critical(error)
        self.assertNotIn("Failed", error)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
