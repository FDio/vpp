#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 FastNetMon

import unittest

from asfframework import VppAsfTestCase, VppTestRunner


class TestAclLookupHook(VppAsfTestCase):
    """ACL lookup reuse: candidate callback"""

    def test_acl_lookup_hook(self):
        """Candidate callback on the hash and linear paths"""
        reply = self.vapi.cli("test acl-lookup-hook")
        self.logger.info(reply)
        self.assertNotIn("FAIL", reply)
        self.assertNotIn("failed", reply)
        self.assertIn("rejecting every rule gives no match", reply)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
