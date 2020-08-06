import unittest
import os

from framework import VppTestCase, VppTestRunner
from vpp_lo_interface import VppLoInterface
from vpp_api_trace import VppApiTrace


class ApiTraceTestCase(VppTestCase):
    """Api trace test case"""

    @classmethod
    def setUpClass(cls):
        """Set up class"""
        super(ApiTraceTestCase, cls).setUpClass()
        cls.api_trace = VppApiTrace(cls)

    def setUp(self):
        """Set up test case"""
        super(ApiTraceTestCase, self).setUp()
        self.api_trace.remove_vpp_config()
        self.api_trace.add_vpp_config()

    def tearDown(self):
        """Tear down test case"""
        super(ApiTraceTestCase, self).tearDown()
        self.api_trace.remove_vpp_config()
        self.api_trace.add_vpp_config()

    def test_api_trace_save(self):
        """Save api trace to a file"""
        self.api_trace.save()
        self.assertTrue(os.path.exists(f"/tmp/{self.api_trace.filename}"))

    def test_api_trace_free(self):
        """Free api trace"""
        # enabled, empty
        self.assertEqual(self.api_trace.traces, 0)
        self.assertTrue(self.api_trace.enabled)

        # trace some API calls
        self.vapi.sw_interface_dump()
        self.assertEqual(self.api_trace.traces, 2)

        # free the trace
        # the trace should be empty and disabled
        self.vapi.api_trace_free()
        self.assertEqual(self.api_trace.traces, 0)
        self.assertFalse(self.api_trace.enabled)

    def test_api_trace_replay(self):
        """Replay api trace"""
        # create interface
        lo = VppLoInterface(self)

        # save api trace
        self.api_trace.save()
        self.assertTrue(os.path.exists(f"/tmp/{self.api_trace.filename}"))

        # delete interfaces
        lo.remove_vpp_config()
        self.assertEqual(len(self.vapi.sw_interface_dump()), 1)

        # replay api
        self.api_trace.replay()

        # assert the interface exists
        self.assertEqual(len(self.vapi.sw_interface_dump()), 2)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
