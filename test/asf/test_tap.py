import unittest
import os

from asfframework import VppAsfTestCase, VppTestRunner
from vpp_devices import VppTAPInterface


def check_tuntap_driver_access():
    return os.access("/dev/net/tun", os.R_OK and os.W_OK)


@unittest.skip("Requires root")
class TestTAP(VppAsfTestCase):
    """TAP Test Case"""

    def test_tap_add_del(self):
        """Create TAP interface"""
        tap0 = VppTAPInterface(self, tap_id=0)
        tap0.add_vpp_config()
        self.assertTrue(tap0.query_vpp_config())

    def test_tap_dump(self):
        """Test api dump w/ and w/o sw_if_index filtering"""
        MAX_INSTANCES = 10
        tap_instances = []
        for instance in range(MAX_INSTANCES):
            i = VppTAPInterface(self, tap_id=instance)
            i.add_vpp_config()
            tap_instances.append(i)
        details = self.vapi.sw_interface_tap_v2_dump()
        self.assertEqual(MAX_INSTANCES, len(details))
        details = self.vapi.sw_interface_tap_v2_dump(tap_instances[5].sw_if_index)
        self.assertEqual(1, len(details))


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
