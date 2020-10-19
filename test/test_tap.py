import unittest
import os

from framework import VppTestCase, VppTestRunner
from vpp_pom.vpp_devices import VppTAPInterface


def check_tuntap_driver_access():
    return os.access("/dev/net/tun", os.R_OK and os.W_OK)


@unittest.skip("Requires root")
class TestTAP(VppTestCase):
    """ TAP Test Case """

    def test_tap_add_del(self):
        """Create TAP interface"""
        tap0 = VppTAPInterface(self.vclient, tap_id=0)
        tap0.add_vpp_config()
        self.assertTrue(tap0.query_vpp_config())

    def test_tap_dump(self):
        """ Test api dump w/ and w/o sw_if_index filtering"""
        MAX_INSTANCES = 10
        tap_instances = []
        for instance in range(MAX_INSTANCES):
            i = VppTAPInterface(self.vclient, tap_id=instance)
            i.add_vpp_config()
            tap_instances.append(i)
        details = self.vclient.sw_interface_tap_v2_dump()
        self.assertEqual(MAX_INSTANCES, len(details))
        details = self.vclient.sw_interface_tap_v2_dump(
            tap_instances[5].sw_if_index)
        self.assertEqual(1, len(details))


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
