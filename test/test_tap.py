import unittest

from framework import VppTestCase, VppTestRunner
from vpp_devices import VppTAPInterface


class TestTAP(VppTestCase):
    """ TAP Test Case """

    def test_tap_add_del(self):
        """Create TAP interface"""
        tap0 = VppTAPInterface(self, tap_id=0)
        tap0.add_vpp_config()
        self.assertTrue(tap0.query_vpp_config())


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
