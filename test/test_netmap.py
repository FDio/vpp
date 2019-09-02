import unittest
import os

from framework import VppTestCase, VppTestRunner
from vpp_devices import VppNetmapInterface


def check_netmap_driver_access():
    return os.access("/dev/netmap", os.R_OK or os.W_OK)


@unittest.skipUnless(check_netmap_driver_access(), "Netmap driver missing")
class TestNetmap(VppTestCase):
    """ Netmap Test Case """

    host_if_name = 'netmap0'

    def test_tap_add_del(self):
        """Create netmap interface"""
        netmap0 = VppNetmapInterface(self, self.host_if_name)
        netmap0.add_vpp_config()
        self.assertTrue(netmap0.query_vpp_config())


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
