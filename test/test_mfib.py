#!/usr/bin/env python

import unittest

from framework import VppTestCase, VppTestRunner


class TestMFIB(VppTestCase):
    """ MFIB Test Case """

    def setUp(self):
        super(TestMFIB, self).setUp()

    def test_mfib(self):
        """ MFIB Unit Tests """
        error = self.vapi.cli("test mfib")

        if error:
            self.logger.critical(error)
        self.assertEqual(error.find("Failed"), -1)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
