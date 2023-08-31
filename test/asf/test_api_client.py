#!/usr/bin/env python3

import unittest

from asfframework import VppAsfTestCase, VppTestRunner


class TestAPIClient(VppAsfTestCase):
    """API Internal client Test Cases"""

    def test_client_unittest(self):
        """Internal API client"""
        error = self.vapi.cli("test api internal")
        if error:
            self.logger.critical(error)
            self.assertNotIn("failed", error)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
