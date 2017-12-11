#!/usr/bin/env python

import unittest

from framework import VppTestCase, VppTestRunner


class TestTCP(VppTestCase):
    """ TCP Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestTCP, cls).setUpClass()

    def setUp(self):
        super(TestTCP, self).setUp()
        self.vapi.session_enable_disable(is_enabled=1)

    def tearDown(self):
        super(TestTCP, self).tearDown()

    def test_tcp(self):
        """ TCP Unit Tests """
        error = self.vapi.cli("test tcp all")

        if error:
            self.logger.critical(error)
        self.assertEqual(error.find("Failed"), -1)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
