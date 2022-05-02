#!/usr/bin/env python3

import unittest

from framework import VppTestCase, VppTestRunner
from vpp_ip_route import VppIpTable, VppIpRoute, VppRoutePath


class TestAPIClient(VppTestCase):
    """API Internal client Test Cases"""

    def test_client_unittest(self):
        """Internal API client"""
        error = self.vapi.cli("test api internal")
        if error:
            self.logger.critical(error)
            self.assertNotIn("failed", error)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
