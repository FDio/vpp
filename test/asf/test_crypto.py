#!/usr/bin/env python3

import unittest

from asfframework import VppAsfTestCase, VppTestRunner


class TestCrypto(VppAsfTestCase):
    """Crypto Test Case"""

    @classmethod
    def setUpClass(cls):
        super(TestCrypto, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestCrypto, cls).tearDownClass()

    def test_crypto(self):
        """Crypto Unit Tests"""
        error = self.vapi.cli("test crypto")

        if error:
            self.logger.critical(error)
        self.assertNotIn("FAIL", error)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
