#!/usr/bin/env python

import unittest

from framework import VppTestCase, VppTestRunner

from vpp_bond_interface import VppBondInterface


class TesBondInterface(VppTestCase):
    """Bond Test Case

    """

    def test_bond(self):
        """ Bond add/delete interface test """
        self.logger.info("Bond add interfaces")

        # create interface 1 (BondEthernet0)
        bond_if1 = VppBondInterface(self, mode=5)
        bond_if1.add_vpp_config()
        bond_if1.admin_up()

        # create interface 2 (BondEthernet1)
        bond_if2 = VppBondInterface(self, mode=3)
        bond_if2.add_vpp_config()
        bond_if2.admin_up()

        # verify both interfaces in the show
        ifs = self.vapi.cli("show interface")
        self.assertNotEqual(ifs.find('BondEthernet0'), -1)
        self.assertNotEqual(ifs.find('BondEthernet1'), -1)

        # verify they are in the dump also
        if_dump = self.vapi.sw_interface_bond_dump()
        self.assertTrue(bond_if1.is_interface_config_in_dump(if_dump))
        self.assertTrue(bond_if2.is_interface_config_in_dump(if_dump))

        # delete BondEthernet1
        self.logger.info("Deleting BondEthernet1")
        bond_if2.remove_vpp_config()

        self.logger.info("Verifying BondEthernet1 is deleted")

        ifs = self.vapi.cli("show interface")
        # verify BondEthernet0 still in the show
        self.assertNotEqual(ifs.find('BondEthernet0'), -1)

        # verify BondEthernet1 not in the show
        self.assertEqual(ifs.find('BondEthernet1'), -1)

        # verify BondEthernet1 is not in the dump
        if_dump = self.vapi.sw_interface_bond_dump()
        self.assertFalse(bond_if2.is_interface_config_in_dump(if_dump))

        # verify BondEthernet0 is still in the dump
        self.assertTrue(bond_if1.is_interface_config_in_dump(if_dump))

        # delete BondEthernet0
        self.logger.info("Deleting BondEthernet0")
        bond_if1.remove_vpp_config()

        self.logger.info("Verifying BondEthernet0 is deleted")

        # verify BondEthernet0 not in the show
        ifs = self.vapi.cli("show interface")
        self.assertEqual(ifs.find('BondEthernet0'), -1)

        # verify BondEthernet0 is not in the dump
        if_dump = self.vapi.sw_interface_bond_dump()
        self.assertFalse(bond_if1.is_interface_config_in_dump(if_dump))

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
