# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2026 Cisco Systems, Inc.

import subprocess
import unittest

from asfframework import CPUInterface, VppTestRunner
from config import config


@unittest.skipIf("vperf" in config.excluded_plugins, "Exclude vperf plugin tests")
class TestVperfStats(CPUInterface, unittest.TestCase):
    """vperf statistics tests"""

    @classmethod
    def is_tagged_run_solo(cls):
        return False

    @classmethod
    def has_tag(cls, tag):
        return False

    @classmethod
    def get_cores_required(cls):
        return 0

    def test_stats(self):
        """vperf statistics formatting"""
        result = subprocess.run(
            [f"{config.vpp_build_dir}/vpp/bin/test_vperf_stats"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
