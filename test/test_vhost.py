#!/usr/bin/env python3

import unittest

from framework import VppTestCase, VppTestRunner

from vpp_vhost_interface import VppVhostInterface


class TesVhostInterface(VppTestCase):
    """Vhost User Test Case

    """
    @classmethod
    def setUpClass(cls):
        super(TesVhostInterface, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TesVhostInterface, cls).tearDownClass()

    def tearDown(self):
        super(TesVhostInterface, self).tearDown()
        if not self.vpp_dead:
            if_dump = self.vapi.sw_interface_vhost_user_dump()
            for ifc in if_dump:
                self.vapi.delete_vhost_user_if(ifc.sw_if_index)

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
        self.assertIn('VirtualEthernet0/0/0', ifs)
        self.assertIn('VirtualEthernet0/0/1', ifs)

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
        self.assertIn('VirtualEthernet0/0/0', ifs)

        # verify VirtualEthernet0/0/1 not in the show
        self.assertNotIn('VirtualEthernet0/0/1', ifs)

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
        self.assertNotIn('VirtualEthernet0/0/0', ifs)

        # verify VirtualEthernet0/0/0 is not in the dump
        if_dump = self.vapi.sw_interface_vhost_user_dump()
        self.assertFalse(vhost_if1.is_interface_config_in_dump(if_dump))

    def test_vhost_interface_state(self):
        """ Vhost User interface states and events test """

        self.vapi.want_interface_events()

        # clear outstanding events
        # (like delete interface events from other tests)
        self.vapi.collect_events()

        vhost_if = VppVhostInterface(self, sock_filename='/tmp/sock1')

        # create vhost interface
        vhost_if.add_vpp_config()
        self.sleep(0.1)
        events = self.vapi.collect_events()
        # creating interface does now create events
        self.assert_equal(len(events), 1, "number of events")

        vhost_if.admin_up()
        vhost_if.assert_interface_state(1, 0, expect_event=True)

        vhost_if.admin_down()
        vhost_if.assert_interface_state(0, 0, expect_event=True)

        # delete vhost interface
        vhost_if.remove_vpp_config()
        event = self.vapi.wait_for_event(timeout=1)
        self.assert_equal(event.sw_if_index, vhost_if.sw_if_index,
                          "sw_if_index")
        self.assert_equal(event.deleted, 1, "deleted flag")

        # verify there are no more events
        events = self.vapi.collect_events()
        self.assert_equal(len(events), 0, "number of events")


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
