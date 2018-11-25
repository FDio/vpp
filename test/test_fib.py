#!/usr/bin/env python

import unittest

from framework import VppTestCase, VppTestRunner


class TestFIB(VppTestCase):
    """ FIB Test Case """

    def test_fib(self):
        """ FIB Unit Tests """
        error = self.vapi.cli("test fib")

        if error:
            self.logger.critical(error)
        self.assertEqual(error.find("Failed"), -1)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
