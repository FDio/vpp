#!/usr/bin/env python

import unittest

from framework import VppTestCase, VppTestRunner

from vpp_vhost_interface import VppVhostInterface


class TesVhostInterface(VppTestCase):
    """Vhost User Test Case

    """

    def test_vhost(self):
        """ Vhost User add/delete interface test """
        self.logger.info("Vhost User add interfaces")

        # create interface 1 (VirtualEthernet0/0/0)
        vhost_if1 = VppVhostInterface(self, sock_filename='/tmp/sock1')
        vhost_if1.add_vpp_config()
        vhost_if1.admin_up()

        # create interface 2 (VirtualEthernet0/0/1)
        vhost_if2 = VppVhostInterface(self, sock_filename='/tmp/sock2')
        vhost_if2.add_vpp_config()
        vhost_if2.admin_up()

        # verify both interfaces in the show
        ifs = self.vapi.cli("show interface")
        self.assertNotEqual(ifs.find('VirtualEthernet0/0/0'), -1)
        self.assertNotEqual(ifs.find('VirtualEthernet0/0/1'), -1)

        # verify they are in the dump also
        if_dump = self.vapi.sw_interface_vhost_user_dump()
        self.assertTrue(vhost_if1.is_interface_config_in_dump(if_dump))
        self.assertTrue(vhost_if2.is_interface_config_in_dump(if_dump))

        # delete VirtualEthernet0/0/1
        self.logger.info("Deleting VirtualEthernet0/0/1")
        vhost_if2.remove_vpp_config()

        self.logger.info("Verifying VirtualEthernet0/0/1 is deleted")

        ifs = self.vapi.cli("show interface")
        # verify VirtualEthernet0/0/0 still in the show
        self.assertNotEqual(ifs.find('VirtualEthernet0/0/0'), -1)

        # verify VirtualEthernet0/0/1 not in the show
        self.assertEqual(ifs.find('VirtualEthernet0/0/1'), -1)

        # verify VirtualEthernet0/0/1 is not in the dump
        if_dump = self.vapi.sw_interface_vhost_user_dump()
        self.assertFalse(vhost_if2.is_interface_config_in_dump(if_dump))

        # verify VirtualEthernet0/0/0 is still in the dump
        self.assertTrue(vhost_if1.is_interface_config_in_dump(if_dump))

        # delete VirtualEthernet0/0/0
        self.logger.info("Deleting VirtualEthernet0/0/0")
        vhost_if1.remove_vpp_config()

        self.logger.info("Verifying VirtualEthernet0/0/0 is deleted")

        # verify VirtualEthernet0/0/0 not in the show
        ifs = self.vapi.cli("show interface")
        self.assertEqual(ifs.find('VirtualEthernet0/0/0'), -1)

        # verify VirtualEthernet0/0/0 is not in the dump
        if_dump = self.vapi.sw_interface_vhost_user_dump()
        self.assertFalse(vhost_if1.is_interface_config_in_dump(if_dump))

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
