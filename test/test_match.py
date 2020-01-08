#!/usr/bin/env python3

import unittest

from framework import VppTestCase, VppTestRunner


class TestMatch(VppTestCase):
    """ MATCH Test Case """

    vapi_response_timeout = 300

    @classmethod
    def setUpClass(cls):
        super(TestMatch, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestMatch, cls).tearDownClass()

    def test_match(self):
        """ MATCH Unit Tests """
        error = self.vapi.cli("test match")

        if error:
            self.logger.critical(error)
        self.assertNotIn("Failed", error)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
