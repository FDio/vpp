#!/usr/bin/env python3

import unittest

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP

from framework import VppTestCase, VppTestRunner
from vpp_bond_interface import VppBondInterface
from vpp_papi import MACAddress, VppEnum


class TestBondInterface(VppTestCase):
    """Bond Test Case

    """

    @classmethod
    def setUpClass(cls):
        super(TestBondInterface, cls).setUpClass()
        # Test variables
        cls.pkts_per_burst = 257    # Number of packets per burst
        # create 3 pg interfaces
        cls.create_pg_interfaces(range(4))

        # packet sizes
        cls.pg_if_packet_sizes = [64, 512, 1518]  # , 9018]

        # setup all interfaces
        for i in cls.pg_interfaces:
            i.admin_up()

    @classmethod
    def tearDownClass(cls):
        super(TestBondInterface, cls).tearDownClass()

    def setUp(self):
        super(TestBondInterface, self).setUp()

    def tearDown(self):
        super(TestBondInterface, self).tearDown()

    def show_commands_at_teardown(self):
        self.logger.info(self.vapi.ppcli("show interface"))

    def test_bond_traffic(self):
        """ Bond traffic test """

        # topology
        #
        # RX->              TX->
        #
        # pg2 ------+        +------pg0 (member)
        #           |        |
        #          BondEthernet0 (10.10.10.1)
        #           |        |
        # pg3 ------+        +------pg1 (memberx)
        #

        # create interface (BondEthernet0)
        #        self.logger.info("create bond")
        bond0_mac = "02:fe:38:30:59:3c"
        mac = MACAddress(bond0_mac).packed
        bond0 = VppBondInterface(
            self,
            mode=VppEnum.vl_api_bond_mode_t.BOND_API_MODE_XOR,
            lb=VppEnum.vl_api_bond_lb_algo_t.BOND_API_LB_ALGO_L34,
            numa_only=0,
            use_custom_mac=1,
            mac_address=mac)
        bond0.add_vpp_config()
        bond0.admin_up()
        self.vapi.sw_interface_add_del_address(
            sw_if_index=bond0.sw_if_index,
            prefix="10.10.10.1/24")

        self.pg2.config_ip4()
        self.pg2.resolve_arp()
        self.pg3.config_ip4()
        self.pg3.resolve_arp()

        self.logger.info(self.vapi.cli("show interface"))
        self.logger.info(self.vapi.cli("show interface address"))
        self.logger.info(self.vapi.cli("show ip neighbors"))

        # add member pg0 and pg1 to BondEthernet0
        self.logger.info("bond add member interface pg0 to BondEthernet0")
        bond0.add_member_vpp_bond_interface(sw_if_index=self.pg0.sw_if_index)
        self.logger.info("bond add_member interface pg1 to BondEthernet0")
        bond0.add_member_vpp_bond_interface(sw_if_index=self.pg1.sw_if_index)

        # verify both members in BondEthernet0
        if_dump = self.vapi.sw_member_interface_dump(bond0.sw_if_index)
        self.assertTrue(self.pg0.is_interface_config_in_dump(if_dump))
        self.assertTrue(self.pg1.is_interface_config_in_dump(if_dump))

        # generate a packet from pg2 -> BondEthernet0 -> pg1
        # BondEthernet0 TX hashes this packet to pg1
        p2 = (Ether(src=bond0_mac, dst=self.pg2.local_mac) /
              IP(src=self.pg2.local_ip4, dst="10.10.10.12") /
              UDP(sport=1235, dport=1235) /
              Raw(b'\xa5' * 100))
        self.pg2.add_stream(p2)

        # generate a packet from pg3 -> BondEthernet0 -> pg0
        # BondEthernet0 TX hashes this packet to pg0
        # notice the ip address and ports are different than p2 packet
        p3 = (Ether(src=bond0_mac, dst=self.pg3.local_mac) /
              IP(src=self.pg3.local_ip4, dst="10.10.10.11") /
              UDP(sport=1234, dport=1234) /
              Raw(b'\xa5' * 100))
        self.pg3.add_stream(p3)

        self.pg_enable_capture(self.pg_interfaces)

        # set up the static arp entries pointing to the BondEthernet0 interface
        # so that it does not try to resolve the ip address
        self.logger.info(self.vapi.cli(
            "set ip neighbor static BondEthernet0 10.10.10.12 abcd.abcd.0002"))
        self.logger.info(self.vapi.cli(
            "set ip neighbor static BondEthernet0 10.10.10.11 abcd.abcd.0004"))

        # clear the interface counters
        self.logger.info(self.vapi.cli("clear interfaces"))

        self.pg_start()

        self.logger.info("check the interface counters")

        # verify counters

        # BondEthernet0 tx bytes = 284
        intfs = self.vapi.cli("show interface BondEthernet0").split("\n")
        found = 0
        for intf in intfs:
            if "tx bytes" in intf and "284" in intf:
                found = 1
        self.assertEqual(found, 1)

        # BondEthernet0 tx bytes = 284
        intfs = self.vapi.cli("show interface BondEthernet0").split("\n")
        found = 0
        for intf in intfs:
            if "tx bytes" in intf and "284" in intf:
                found = 1
        self.assertEqual(found, 1)

        # pg2 rx bytes = 142
        intfs = self.vapi.cli("show interface pg2").split("\n")
        found = 0
        for intf in intfs:
            if "rx bytes" in intf and "142" in intf:
                found = 1
        self.assertEqual(found, 1)

        # pg3 rx bytes = 142
        intfs = self.vapi.cli("show interface pg3").split("\n")
        found = 0
        for intf in intfs:
            if "rx bytes" in intf and "142" in intf:
                found = 1
        self.assertEqual(found, 1)

        bond0.remove_vpp_config()

    def test_bond_add_member(self):
        """ Bond add_member/detach member test """

        # create interface (BondEthernet0) and set bond mode to LACP
        self.logger.info("create bond")
        bond0 = VppBondInterface(
            self,
            mode=VppEnum.vl_api_bond_mode_t.BOND_API_MODE_LACP,
            enable_gso=0)
        bond0.add_vpp_config()
        bond0.admin_up()

        # verify that interfaces can be added as_member and detached two times
        for i in range(2):
            # verify pg0 and pg1 not in BondEthernet0
            if_dump = self.vapi.sw_member_interface_dump(bond0.sw_if_index)
            self.assertFalse(self.pg0.is_interface_config_in_dump(if_dump))
            self.assertFalse(self.pg1.is_interface_config_in_dump(if_dump))

            # add_member pg0 and pg1 to BondEthernet0
            self.logger.info("bond add_member interface pg0 to BondEthernet0")
            bond0.add_member_vpp_bond_interface(
                sw_if_index=self.pg0.sw_if_index,
                is_passive=0,
                is_long_timeout=0)

            self.logger.info("bond add_member interface pg1 to BondEthernet0")
            bond0.add_member_vpp_bond_interface(
                sw_if_index=self.pg1.sw_if_index,
                is_passive=0,
                is_long_timeout=0)
            # verify both members in BondEthernet0
            if_dump = self.vapi.sw_member_interface_dump(bond0.sw_if_index)
            self.assertTrue(self.pg0.is_interface_config_in_dump(if_dump))
            self.assertTrue(self.pg1.is_interface_config_in_dump(if_dump))

            # detach interface pg0
            self.logger.info("detach interface pg0")
            bond0.detach_vpp_bond_interface(sw_if_index=self.pg0.sw_if_index)

            # verify pg0 is not in BondEthernet0, but pg1 is
            if_dump = self.vapi.sw_member_interface_dump(bond0.sw_if_index)
            self.assertFalse(self.pg0.is_interface_config_in_dump(if_dump))
            self.assertTrue(self.pg1.is_interface_config_in_dump(if_dump))

            # detach interface pg1
            self.logger.info("detach interface pg1")
            bond0.detach_vpp_bond_interface(sw_if_index=self.pg1.sw_if_index)

            # verify pg0 and pg1 not in BondEthernet0
            if_dump = self.vapi.sw_member_interface_dump(bond0.sw_if_index)
            self.assertFalse(self.pg0.is_interface_config_in_dump(if_dump))
            self.assertFalse(self.pg1.is_interface_config_in_dump(if_dump))

        bond0.remove_vpp_config()

    def test_bond(self):
        """ Bond add/delete interface test """
        self.logger.info("Bond add interfaces")

        # create interface 1 (BondEthernet0)
        bond0 = VppBondInterface(
            self, mode=VppEnum.vl_api_bond_mode_t.BOND_API_MODE_LACP)
        bond0.add_vpp_config()
        bond0.admin_up()

        # create interface 2 (BondEthernet1)
        bond1 = VppBondInterface(
            self, mode=VppEnum.vl_api_bond_mode_t.BOND_API_MODE_XOR)
        bond1.add_vpp_config()
        bond1.admin_up()

        # verify both interfaces in the show
        ifs = self.vapi.cli("show interface")
        self.assertIn('BondEthernet0', ifs)
        self.assertIn('BondEthernet1', ifs)

        # verify they are in the dump also
        if_dump = self.vapi.sw_bond_interface_dump(sw_if_index=0xFFFFFFFF)
        self.assertTrue(bond0.is_interface_config_in_dump(if_dump))
        self.assertTrue(bond1.is_interface_config_in_dump(if_dump))

        # delete BondEthernet1
        self.logger.info("Deleting BondEthernet1")
        bond1.remove_vpp_config()

        self.logger.info("Verifying BondEthernet1 is deleted")

        ifs = self.vapi.cli("show interface")
        # verify BondEthernet0 still in the show
        self.assertIn('BondEthernet0', ifs)

        # verify BondEthernet1 not in the show
        self.assertNotIn('BondEthernet1', ifs)

        # verify BondEthernet1 is not in the dump
        if_dump = self.vapi.sw_bond_interface_dump(sw_if_index=0xFFFFFFFF)
        self.assertFalse(bond1.is_interface_config_in_dump(if_dump))

        # verify BondEthernet0 is still in the dump
        self.assertTrue(bond0.is_interface_config_in_dump(if_dump))

        # delete BondEthernet0
        self.logger.info("Deleting BondEthernet0")
        bond0.remove_vpp_config()

        self.logger.info("Verifying BondEthernet0 is deleted")

        # verify BondEthernet0 not in the show
        ifs = self.vapi.cli("show interface")
        self.assertNotIn('BondEthernet0', ifs)

        # verify BondEthernet0 is not in the dump
        if_dump = self.vapi.sw_bond_interface_dump(
            sw_if_index=bond0.sw_if_index)
        self.assertFalse(bond0.is_interface_config_in_dump(if_dump))

    def test_bond_link(self):
        """ Bond hw interface link state test """

        # for convenience
        bond_modes = VppEnum.vl_api_bond_mode_t
        intf_flags = VppEnum.vl_api_if_status_flags_t

        # create interface 1 (BondEthernet0)
        self.logger.info("Create bond interface")
        # use round-robin mode to avoid negotiation required by LACP
        bond0 = VppBondInterface(self,
                                 mode=bond_modes.BOND_API_MODE_ROUND_ROBIN)
        bond0.add_vpp_config()

        # set bond admin up.
        self.logger.info("set interface BondEthernet0 admin up")
        bond0.admin_up()
        # confirm link up
        bond0.assert_interface_state(intf_flags.IF_STATUS_API_FLAG_ADMIN_UP,
                                     intf_flags.IF_STATUS_API_FLAG_LINK_UP)

        # toggle bond admin state
        self.logger.info("toggle interface BondEthernet0")
        bond0.admin_down()
        bond0.admin_up()

        # confirm link is still up
        bond0.assert_interface_state(intf_flags.IF_STATUS_API_FLAG_ADMIN_UP,
                                     intf_flags.IF_STATUS_API_FLAG_LINK_UP)

        # delete BondEthernet0
        self.logger.info("Deleting BondEthernet0")
        bond0.remove_vpp_config()


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
