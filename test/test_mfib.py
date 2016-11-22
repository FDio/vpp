#!/usr/bin/env python

import unittest

from framework import VppTestCase, VppTestRunner


class TestMFIB(VppTestCase):
    """ MFIB Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestMFIB, cls).setUpClass()

    def setUp(self):
        super(TestMFIB, self).setUp()

    def tearDown(self):
        super(TestMFIB, self).tearDown()

    def test_mfib(self):
        """ MFIB Unit Tests """
        error = self.vapi.cli("test mfib")

        if error:
            self.logger.critical(error)
        self.assertEqual(error.find("Failed"), -1)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
