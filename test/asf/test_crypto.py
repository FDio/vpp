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
        error = self.vapi.cli("test crypto quiet")

        if error:
            self.logger.critical(error)
        self.assertEqual("OK", error.strip())

    def test_crypto_leak(self):
        """Crypto ctx key_data ADD/REMOVE accounting regression"""
        output = self.vapi.cli("test crypto leak")
        if output:
            self.logger.info(output)
        self.assertNotIn("FAIL", output)
        self.assertIn("OK", output)

    def test_crypto_perf(self):
        """Crypto+HMAC Performance Tests"""

        algorithms = [
            "aes-128-cbc-sha1-160",
            "aes-128-ctr-sha1-160",
        ]
        buffer_sizes = [64, 1024, 2048]

        for alg in algorithms:
            for buf_size in buffer_sizes:
                cmd = f"test crypto perf {alg} buffers 512 rounds 200 buffer-size {buf_size}"
                error = self.vapi.cli(cmd)
                if error:
                    self.logger.critical(error)
                self.assertNotIn("FAIL", error)


class TestCryptoWorker(TestCrypto):
    """Crypto Test Case (worker thread)"""

    vpp_worker_count = 1

    # Opt-in allowlist: only tests named here run under the worker variant.
    # New tests added to TestCrypto are skipped here by default; add them
    # explicitly if they should also run with workers.
    worker_tests = {"test_crypto_leak"}

    def setUp(self):
        if self._testMethodName not in self.worker_tests:
            self.skipTest("not in worker_tests allowlist")
        super().setUp()


class TestCryptoAsyncLifetime(VppAsfTestCase):
    """Crypto async context lifetime regression"""

    vpp_worker_count = 0
    extra_vpp_plugin_config = [
        "plugin crypto_sw_scheduler_plugin.so { enable }",
    ]

    def test_crypto_async_lifetime(self):
        """Pending async work keeps its crypto context alive"""
        output = self.vapi.cli("test crypto async lifetime")
        if output:
            self.logger.info(output)
        self.assertEqual("OK", output.strip())


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
