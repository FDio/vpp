#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2026 Cisco Systems, Inc.

import unittest

from asfframework import VppAsfTestCase, VppTestRunner
from config import config


@unittest.skipIf("tlspicotls" in config.excluded_plugins, "Exclude picotls tests")
class TestTlsPicotlsUnitTests(VppAsfTestCase):
    """Picotls Unit Tests"""

    @classmethod
    def setUpClass(cls):
        cls.extra_vpp_plugin_config = list(cls.extra_vpp_plugin_config) + [
            "plugin tlspicotls_unittest_plugin.so { enable }"
        ]
        super(TestTlsPicotlsUnitTests, cls).setUpClass()

    def test_tlspicotls_alpn(self):
        """Picotls ALPN Unit Tests"""
        output = self.vapi.cli("test tlspicotls alpn")

        if output:
            self.logger.info(output)
        self.assertNotIn("failed", output)
        self.assertNotIn("FAIL", output)
        self.assertIn("tlspicotls alpn tests passed", output)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
