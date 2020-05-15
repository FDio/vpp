#!/usr/bin/env python3

import time
import unittest

from framework import VppTestCase, VppTestRunner
from scapy.contrib.lacp import LACP, SlowProtocol, MarkerProtocol
from scapy.layers.l2 import Ether
from vpp_memif import remove_all_memif_vpp_config, VppSocketFilename, VppMemif
from vpp_bond_interface import VppBondInterface
from vpp_papi import VppEnum, MACAddress

bond_mac = "02:02:02:02:02:02"
lacp_dst_mac = '01:80:c2:00:00:02'
LACP_COLLECTION_AND_DISTRIBUTION_STATE = 63


class TestMarker(VppTestCase):
    """LACP Marker Protocol Test Case

    """

    @classmethod
    def setUpClass(cls):
        super(TestMarker, cls).setUpClass()
        # Test variables
        cls.pkts_per_burst = 257    # Number of packets per burst
        # create 3 pg interfaces
        cls.create_pg_interfaces(range(1))

        # packet sizes
        cls.pg_if_packet_sizes = [64, 512, 1518]  # , 9018]

        # setup all interfaces
        for i in cls.pg_interfaces:
            i.admin_up()

    @classmethod
    def tearDownClass(cls):
        super(TestMarker, cls).tearDownClass()

    def setUp(self):
        super(TestMarker, self).setUp()

    def tearDown(self):
        super(TestMarker, self).tearDown()

    def show_commands_at_teardown(self):
        self.logger.info(self.vapi.ppcli("show interface"))

    def test_marker_request(self):
        """ Marker Request test """

        # topology
        #
        #             +-+      +-+
        # memif1 -----|B|      |B|---- memif11
        #             |o|      |o|
        #             |n|------|n|
        #             |d|      |d|
        # pg0    -----|0|      |1|
        #             +-+      +-+

        socket1 = VppSocketFilename(
            self,
            socket_id=1,
            socket_filename="%s/memif.sock1" % self.tempdir)
        socket1.add_vpp_config()

        socket11 = VppSocketFilename(
            self,
            socket_id=2,
            socket_filename="%s/memif.sock1" % self.tempdir)
        socket11.add_vpp_config()

        memif1 = VppMemif(
            self,
            role=VppEnum.vl_api_memif_role_t.MEMIF_ROLE_API_MASTER,
            mode=VppEnum.vl_api_memif_mode_t.MEMIF_MODE_API_ETHERNET,
            socket_id=1)
        memif1.add_vpp_config()
        memif1.admin_up()

        memif11 = VppMemif(
            self,
            role=VppEnum.vl_api_memif_role_t.MEMIF_ROLE_API_SLAVE,
            mode=VppEnum.vl_api_memif_mode_t.MEMIF_MODE_API_ETHERNET,
            socket_id=2)
        memif11.add_vpp_config()
        memif11.admin_up()

        bond0 = VppBondInterface(
            self,
            mode=VppEnum.vl_api_bond_mode_t.BOND_API_MODE_LACP,
            use_custom_mac=1,
            mac_address=bond_mac)

        bond0.add_vpp_config()
        bond0.admin_up()

        bond1 = VppBondInterface(
            self,
            mode=VppEnum.vl_api_bond_mode_t.BOND_API_MODE_LACP)
        bond1.add_vpp_config()
        bond1.admin_up()

        bond0.enslave_vpp_bond_interface(sw_if_index=memif1.sw_if_index)
        bond1.enslave_vpp_bond_interface(sw_if_index=memif11.sw_if_index)

        # wait for memif protocol exchange and hardware carrier to come up
        self.assertTrue(memif1.wait_for_link_up(10))
        self.assertTrue(memif11.wait_for_link_up(10))

        # verify memif1 in bond0
        intfs = self.vapi.sw_interface_slave_dump(bond0.sw_if_index)
        for intf in intfs:
            self.assertTrue(intf.sw_if_index == memif1.sw_if_index)

        # verify memif11 in bond1
        intfs = self.vapi.sw_interface_slave_dump(bond1.sw_if_index)
        for intf in intfs:
            self.assertTrue(intf.sw_if_index == memif11.sw_if_index)

        self.vapi.ppcli("trace add memif-input 100")

        # create marker request
        marker = (Ether(src=bond_mac, dst=lacp_dst_mac) /
                  SlowProtocol() /
                  MarkerProtocol(marker_type=1,
                                 requester_port=1,
                                 requester_system=bond_mac,
                                 requester_transaction_id=1))

        bond1.enslave_vpp_bond_interface(sw_if_index=self.pg0.sw_if_index)
        self.pg0.add_stream(marker)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        lines = self.vapi.ppcli("show trace max 100").split("\n")
        found = 0
        for line in lines:
            if "Marker Information TLV:" in line:
                found = 1
        self.assertEqual(found, 1)

        bond0.remove_vpp_config()
        bond1.remove_vpp_config()


class TestLACP(VppTestCase):
    """LACP Test Case

    """

    @classmethod
    def setUpClass(cls):
        super(TestLACP, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestLACP, cls).tearDownClass()

    def setUp(self):
        super(TestLACP, self).setUp()

    def tearDown(self):
        super(TestLACP, self).tearDown()

    def show_commands_at_teardown(self):
        self.logger.info(self.vapi.ppcli("show interface"))

    def wait_for_lacp_connect(self, timeout, step=1):
        while 1:
            intfs = self.vapi.sw_interface_lacp_dump()
            all_good = 1
            for intf in intfs:
                if ((intf.actor_state !=
                     LACP_COLLECTION_AND_DISTRIBUTION_STATE) or
                    (intf.partner_state !=
                     LACP_COLLECTION_AND_DISTRIBUTION_STATE)):
                    all_good = 0
            if (all_good == 1):
                return 1
            self.sleep(step)
            timeout -= step
            if timeout <= 0:
                return 0

    def wait_for_slave_detach(self, bond, timeout, count, step=1):
        while 1:
            intfs = self.vapi.sw_interface_bond_dump()
            for intf in intfs:
                if (bond.sw_if_index == intf.sw_if_index):
                    if ((intf.slaves == count) and
                            (intf.active_slaves == count)):
                        return 1
                    else:
                        self.sleep(1)
                        timeout -= step
                        if (timeouut <= 0):
                            return 0

    def test_lacp_connect(self):
        """ LACP protocol connect test """

        # topology
        #
        #             +-+      +-+
        # memif1 -----|B|      |B|---- memif11
        #             |o|      |o|
        #             |n|------|n|
        #             |d|      |d|
        # memif2 -----|0|      |1|---- memif12
        #             +-+      +-+

        socket1 = VppSocketFilename(
            self,
            socket_id=1,
            socket_filename="%s/memif.sock1" % self.tempdir)
        socket1.add_vpp_config()

        socket11 = VppSocketFilename(
            self,
            socket_id=2,
            socket_filename="%s/memif.sock1" % self.tempdir)
        socket11.add_vpp_config()

        socket2 = VppSocketFilename(
            self,
            socket_id=3,
            socket_filename="%s/memif.sock2" % self.tempdir)
        socket2.add_vpp_config()

        socket22 = VppSocketFilename(
            self,
            socket_id=4,
            socket_filename="%s/memif.sock2" % self.tempdir)
        socket22.add_vpp_config()

        memif1 = VppMemif(
            self,
            role=VppEnum.vl_api_memif_role_t.MEMIF_ROLE_API_MASTER,
            mode=VppEnum.vl_api_memif_mode_t.MEMIF_MODE_API_ETHERNET,
            socket_id=1)
        memif1.add_vpp_config()
        memif1.admin_up()

        memif11 = VppMemif(
            self,
            role=VppEnum.vl_api_memif_role_t.MEMIF_ROLE_API_SLAVE,
            mode=VppEnum.vl_api_memif_mode_t.MEMIF_MODE_API_ETHERNET,
            socket_id=2)
        memif11.add_vpp_config()
        memif11.admin_up()

        memif2 = VppMemif(
            self,
            role=VppEnum.vl_api_memif_role_t.MEMIF_ROLE_API_MASTER,
            mode=VppEnum.vl_api_memif_mode_t.MEMIF_MODE_API_ETHERNET,
            socket_id=3)
        memif2.add_vpp_config()
        memif2.admin_up()

        memif12 = VppMemif(
            self,
            role=VppEnum.vl_api_memif_role_t.MEMIF_ROLE_API_SLAVE,
            mode=VppEnum.vl_api_memif_mode_t.MEMIF_MODE_API_ETHERNET,
            socket_id=4)
        memif12.add_vpp_config()
        memif12.admin_up()

        self.logger.info(self.vapi.ppcli("debug lacp on"))
        bond0 = VppBondInterface(
            self,
            mode=VppEnum.vl_api_bond_mode_t.BOND_API_MODE_LACP,
            use_custom_mac=1,
            mac_address=bond_mac)

        bond0.add_vpp_config()
        bond0.admin_up()

        bond1 = VppBondInterface(
            self,
            mode=VppEnum.vl_api_bond_mode_t.BOND_API_MODE_LACP)
        bond1.add_vpp_config()
        bond1.admin_up()

        # enslave memif1 and memif2 to bond0
        bond0.enslave_vpp_bond_interface(sw_if_index=memif1.sw_if_index)
        bond0.enslave_vpp_bond_interface(sw_if_index=memif2.sw_if_index)

        # enslave memif11 and memif12 to bond1
        bond1.enslave_vpp_bond_interface(sw_if_index=memif11.sw_if_index)
        bond1.enslave_vpp_bond_interface(sw_if_index=memif12.sw_if_index)

        # wait for memif protocol exchange and hardware carrier to come up
        self.assertTrue(memif1.wait_for_link_up(10))
        self.assertTrue(memif2.wait_for_link_up(10))
        self.assertTrue(memif11.wait_for_link_up(10))
        self.assertTrue(memif12.wait_for_link_up(10))

        # verify memif1 and memif2 in bond0
        intfs = self.vapi.sw_interface_slave_dump(bond0.sw_if_index)
        for intf in intfs:
            self.assertTrue(
                intf.sw_if_index == memif1.sw_if_index or
                intf.sw_if_index == memif2.sw_if_index)

        # verify memif11 and memif12 in bond1
        intfs = self.vapi.sw_interface_slave_dump(bond1.sw_if_index)
        for intf in intfs:
            self.assertTrue(
                intf.sw_if_index == memif11.sw_if_index or
                intf.sw_if_index == memif12.sw_if_index)
            self.assertTrue(intf.is_long_timeout == 0)
            self.assertTrue(intf.is_passive == 0)

        # Let LACP create the bundle
        self.wait_for_lacp_connect(30)

        intfs = self.vapi.sw_interface_lacp_dump()
        for intf in intfs:
            self.assertTrue(
                intf.actor_state == LACP_COLLECTION_AND_DISTRIBUTION_STATE)
            self.assertTrue(
                intf.partner_state == LACP_COLLECTION_AND_DISTRIBUTION_STATE)

        intfs = self.vapi.sw_interface_bond_dump()
        for intf in intfs:
            self.assertTrue(intf.slaves == 2)
            self.assertTrue(intf.active_slaves == 2)
            self.assertTrue(
                intf.mode == VppEnum.vl_api_bond_mode_t.BOND_API_MODE_LACP)

        self.logger.info(self.vapi.ppcli("show lacp"))
        self.logger.info(self.vapi.ppcli("show lacp details"))

        # detach slave memif1
        bond0.detach_vpp_bond_interface(sw_if_index=memif1.sw_if_index)

        self.wait_for_slave_detach(bond0, timeout=10, count=1)
        intfs = self.vapi.sw_interface_bond_dump()
        for intf in intfs:
            if (bond0.sw_if_index == intf.sw_if_index):
                self.assertTrue(intf.slaves == 1)
                self.assertTrue(intf.active_slaves == 1)
                self.assertTrue(
                    intf.mode == VppEnum.vl_api_bond_mode_t.BOND_API_MODE_LACP)

        # detach slave memif2
        bond0.detach_vpp_bond_interface(sw_if_index=memif2.sw_if_index)
        self.wait_for_slave_detach(bond0, timeout=10, count=0)

        intfs = self.vapi.sw_interface_bond_dump()
        for intf in intfs:
            if (bond0.sw_if_index == intf.sw_if_index):
                self.assertTrue(intf.slaves == 0)
                self.assertTrue(intf.active_slaves == 0)

        bond0.remove_vpp_config()
        bond1.remove_vpp_config()


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
