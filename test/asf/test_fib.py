#!/usr/bin/env python3

import unittest

from asfframework import VppAsfTestCase, VppTestRunner, tag_fixme_vpp_workers


@tag_fixme_vpp_workers
class TestFIB(VppAsfTestCase):
    """FIB Test Case"""

    @classmethod
    def setUpClass(cls):
        super(TestFIB, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestFIB, cls).tearDownClass()

    def test_fib(self):
        """FIB Unit Tests"""
        try:
            error = self.vapi.cli("test fib")
        except Exception as e:
            print(self.vapi.cli("sh ip fib 0.0.0.0/0"))
            print("--------------------")
            print(self.vapi.cli("sh ip fib 10.0.0.0/8"))
            print("--------------------")
            print(self.vapi.cli("sh ip fib 10.10.0.0/16"))
            print("--------------------")
            print(self.vapi.cli("sh ip fib 10.10.10.0/24"))
            print("--------------------")
            print(self.vapi.cli("sh ip fib 10.10.10.21/32"))
            raise

        # shameless test of CLIs to bump lcov results...
        # no i mean to ensure they don't crash
        self.logger.info(self.vapi.cli("sh fib source"))
        self.logger.info(self.vapi.cli("sh fib source prio"))
        self.logger.info(self.vapi.cli("sh fib memory"))
        self.logger.info(self.vapi.cli("sh fib entry"))
        self.logger.info(self.vapi.cli("sh fib entry 0"))
        self.logger.info(self.vapi.cli("sh fib entry 10000"))
        self.logger.info(self.vapi.cli("sh fib entry-delegate"))
        self.logger.info(self.vapi.cli("sh fib paths"))
        self.logger.info(self.vapi.cli("sh fib paths 0"))
        self.logger.info(self.vapi.cli("sh fib paths 10000"))
        self.logger.info(self.vapi.cli("sh fib path-list"))
        self.logger.info(self.vapi.cli("sh fib path-list 0"))
        self.logger.info(self.vapi.cli("sh fib path-list 10000"))
        self.logger.info(self.vapi.cli("sh fib walk"))
        self.logger.info(self.vapi.cli("sh fib uRPF"))

        if error:
            self.logger.critical(error)
        self.assertNotIn("Failed", error)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
