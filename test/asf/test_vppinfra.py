#!/usr/bin/env python3

import unittest

from asfframework import VppAsfTestCase, VppTestRunner


class TestVppinfra(VppAsfTestCase):
    """Vppinfra Unit Test Cases"""

    @classmethod
    def setUpClass(cls):
        super(TestVppinfra, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestVppinfra, cls).tearDownClass()

    def setUp(self):
        super(TestVppinfra, self).setUp()

    def tearDown(self):
        super(TestVppinfra, self).tearDown()

    def test_bitmap_unittest(self):
        """Bitmap unit tests"""

        cmds = ["test bitmap"]

        for cmd in cmds:
            error = self.vapi.cli(cmd)
            if error:
                self.logger.critical(error)
                self.assertNotIn("failed", error)

    def test_memory_trace(self):
        """Memory Trace Test"""
        # Enable memory tracing on main-heap
        r = self.vapi.cli_return_response("memory-trace on main-heap")
        self.assertEqual(r.retval, 0, "Failed to enable memory-trace")

        # Do some allocations by creating a loopback interface
        r = self.vapi.cli_return_response("loopback create")
        self.assertEqual(r.retval, 0, "Failed to create loopback")

        # Show memory trace (should have some allocations)
        r = self.vapi.cli_return_response("show memory main-heap")
        self.assertEqual(r.retval, 0, "Failed to show memory")

        # Disable memory tracing - this is where the bug would trigger
        # an assertion failure in clib_mem_trace_main_free()
        r = self.vapi.cli_return_response("memory-trace off")
        self.assertEqual(r.retval, 0, "Failed to disable memory-trace")

        # Verify we can still do operations after disabling
        r = self.vapi.cli_return_response("show memory main-heap")
        self.assertEqual(r.retval, 0, "Failed to show memory after trace off")

        # Test enable/disable on multiple heaps
        r = self.vapi.cli_return_response(
            "memory-trace on main-heap api-segment stats-segment"
        )
        self.assertEqual(r.retval, 0, "Failed to enable memory-trace on all heaps")

        r = self.vapi.cli_return_response("memory-trace off")
        self.assertEqual(r.retval, 0, "Failed to disable memory-trace on all heaps")


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
