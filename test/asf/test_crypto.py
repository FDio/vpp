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

    def test_crypto_perf(self):
        """Crypto+HMAC Performance Tests"""

        algorithms = [
            "aes-128-cbc-hmac-sha-1",
            "aes-128-ctr-hmac-sha-1",
        ]
        buffer_sizes = [64, 1024, 2048]

        for alg in algorithms:
            for buf_size in buffer_sizes:
                cmd = f"test crypto perf {alg} buffers 512 rounds 200 buffer-size {buf_size}"
                error = self.vapi.cli(cmd)
                if error:
                    self.logger.critical(error)
                self.assertNotIn("FAIL", error)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
