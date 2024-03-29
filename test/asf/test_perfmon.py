from asfframework import VppAsfTestCase, VppTestRunner
from vpp_qemu_utils import can_create_namespaces
from config import config
import unittest


@unittest.skipIf(
    not can_create_namespaces("perfmon_chk"), "Test is not running with root privileges"
)
@unittest.skipIf("perfmon" in config.excluded_plugins, "Exclude Perfmon plugin tests")
class TestPerfmon(VppAsfTestCase):
    """Simple perfmon test"""

    @classmethod
    def setUpClass(cls):
        super(TestPerfmon, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestPerfmon, cls).tearDownClass()

    def test_perfmon(self):
        reply = self.vapi.cli("show perfmon active-bundle")
        self.assertNotIn("context-switches", reply)

        reply = self.vapi.cli("show perfmon bundle")
        self.assertIn("context-switches", reply)

        self.vapi.cli("perfmon start bundle context-switches type thread")
        reply = self.vapi.cli("show perfmon active-bundle")
        self.assertIn("name: context-switches", reply)

        reply = self.vapi.cli("show perfmon statistics")
        self.assertIn("per-thread context switches", reply)

        reply = self.vapi.cli("show perfmon source linux verbose")
        self.assertIn("description: Linux kernel performance counters", reply)
        self.vapi.cli("perfmon reset")

        reply = self.vapi.cli("show perfmon active-bundle")
        self.assertNotIn("context-switches", reply)

        self.vapi.cli("perfmon start bundle context-switches type thread")
        self.vapi.cli("perfmon stop")


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
