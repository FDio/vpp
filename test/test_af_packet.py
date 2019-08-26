import unittest
import os
import psutil

from framework import VppTestCase, VppTestRunner
from vpp_devices import VppAFPacketInterface


class TestAFPacket(VppTestCase):
    """ Host interface Test Case """

    host_if_name = 'afp0'

    @classmethod
    def setUpClass(cls):
        super(TestAFPacket, cls).setUpClass()
        os.system('ip tuntap add dev ' + cls.host_if_name + ' mode tap')

    @classmethod
    def tearDownClass(cls):
        super(TestAFPacket, cls).tearDownClass()
        os.system('ip link delete ' + cls.host_if_name)

    def test_tap_add_del(self):
        """Create host interface"""
        # check if host interface exists
        self.assertTrue(psutil.net_if_addrs().get(self.host_if_name),
                        'Host interface ' + self.host_if_name + ' does not exist')
        afp0 = VppAFPacketInterface(self, self.host_if_name)
        afp0.add_vpp_config()
        self.assertTrue(afp0.query_vpp_config())


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
