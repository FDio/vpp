#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 FastNetMon

import unittest

from asfframework import VppAsfTestCase, VppTestRunner


class TestAclLoader(VppAsfTestCase):
    """ACL rule loader for plugins that reuse the lookup"""

    def test_acl_loader(self):
        """Create, replace and validate ACLs through the loader"""
        reply = self.vapi.cli("test acl-loader")
        self.logger.info(reply)
        self.assertNotIn("FAIL", reply)
        self.assertNotIn("failed", reply)
        self.assertIn("loader rejects a tag that does not fit", reply)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
