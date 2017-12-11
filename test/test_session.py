#!/usr/bin/env python

import unittest

from framework import VppTestCase, VppTestRunner


class TestSession(VppTestCase):
    """ Session Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestSession, cls).setUpClass()

    def setUp(self):
        super(TestSession, self).setUp()

    def tearDown(self):
        super(TestSession, self).tearDown()
        self.vapi.session_enable_disable(is_enabled=1)

    def test_session(self):
        """ Session Unit Tests """
        error = self.vapi.cli("test session all")

        if error:
            self.logger.critical(error)
        self.assertEqual(error.find("Failed"), -1)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
