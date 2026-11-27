#!/usr/bin/env python3

import json
import unittest
from pathlib import Path
from tempfile import NamedTemporaryFile

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


class TestMemoryTraceSnapshot(VppAsfTestCase):
    """Memory trace snapshots"""

    def test_save_memory_trace_filename(self):
        """Memory trace snapshots exclude their own parsed filename"""
        self.vapi.cli("memory-trace on main-heap")
        self.addCleanup(self.vapi.cli, "memory-trace off")
        loopback = self.vapi.create_loopback()
        self.addCleanup(self.vapi.delete_loopback, sw_if_index=loopback.sw_if_index)

        for prefix in ("vpp-", "vpp-" + "x" * 64):
            with NamedTemporaryFile(mode="r", dir="/tmp", prefix=prefix) as snapshot:
                self.vapi.cli(f"save memory-trace {Path(snapshot.name).name}")
                traces = json.load(snapshot)

            if not traces:
                self.skipTest("Heap stack traces are unavailable")
            self.assertFalse(
                any(
                    frame.partition(" + ")[0] == "parse_string"
                    for trace in traces
                    for frame in trace["traceback"]
                ),
                "snapshot contains its own parsed filename",
            )


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
