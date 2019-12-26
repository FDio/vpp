import unittest
import os

from framework import VppTestCase, VppTestRunner, capabilities
from vpp_devices import VppTAPInterface


def check_tuntap_driver_access():
    try:
        os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
        return True
    except PermissionError:
        return False
    except FileNotFoundError:
        return False


@unittest.skipUnless('cap_net_admin' in capabilities(),
                     "Missing capability: cap_net_admin.")
@unittest.skipUnless(check_tuntap_driver_access(), "Permission denied")
class TestTAP(VppTestCase):
    """ TAP Test Case """

    def test_tap_add_del(self):
        """Create TAP interface"""
        tap0 = VppTAPInterface(self, tap_id=0)
        tap0.add_vpp_config()
        self.assertTrue(tap0.query_vpp_config())


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
