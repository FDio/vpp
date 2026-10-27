# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2026 Cisco Systems, Inc.

import subprocess
import unittest

from asfframework import CPUInterface, VppTestRunner
from config import config


@unittest.skipIf("vperf" in config.excluded_plugins, "Exclude vperf plugin tests")
class TestVperfBuffers(CPUInterface, unittest.TestCase):
    """vperf buffer-size tests"""

    @classmethod
    def is_tagged_run_solo(cls):
        return False

    @classmethod
    def has_tag(cls, tag):
        return False

    @classmethod
    def get_cores_required(cls):
        return 0

    def run_buffer_test(self, binary):
        result = subprocess.run(
            [f"{config.vpp_build_dir}/vpp/bin/{binary}"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_client_buffers(self):
        """vperf client buffer input and allocation"""
        self.run_buffer_test("test_vperf_client")

    def test_server_buffers(self):
        """vperf server buffer configuration and allocation"""
        self.run_buffer_test("test_vperf_server")


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
