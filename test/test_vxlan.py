#!/usr/bin/env python

import unittest
from logging import *
from framework import vapi, VppTestCase, VppTestRunner
from util import Util
from template_bd import BridgeDomain

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy_handlers.vxlan import VXLAN


## TestVxlan is a subclass of BridgeDomain, Util, VppTestCase classes.
#
#  TestVxlan class defines VXLAN test cases for VXLAN encapsulation,
#  decapsulation and VXLAN tunnel termination in L2 bridge-domain.
class TestVxlan(BridgeDomain, Util, VppTestCase):
    """ VXLAN Test Case """

    ## Method to initialize all parent classes.
    #
    #  Initialize BridgeDomain objects, set documentation string for inherited
    #  tests and initialize VppTestCase object which must be called after
    #  doc strings are set.
    def __init__(self, *args):
        BridgeDomain.__init__(self)
        self.test_decap.__func__.__doc__ = ' VXLAN BD decapsulation '
        self.test_encap.__func__.__doc__ = ' VXLAN BD encapsulation '
        VppTestCase.__init__(self, *args)

    ## Method for VXLAN encapsulate function.
    #
    #  Encapsulate the original payload frame by adding VXLAN header with its
    #  UDP, IP and Ethernet fields.
    def encapsulate(self, pkt):
        return (Ether(src=self.pg0.my_mac, dst=self.pg0.vpp_mac) /
                IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) /
                UDP(sport=self.dport, dport=self.dport, chksum=0) /
                VXLAN(vni=self.vni) /
                pkt)

    ## Method for VXLAN decapsulate function.
    #
    #  Decapsulate the original payload frame by removing VXLAN header with
    #  its UDP, IP and Ethernet fields.
    def decapsulate(self, pkt):
        return pkt[VXLAN].payload

    ## Method for checking VXLAN encapsulation.
    #
    def check_encapsulation(self, pkt):
        # TODO: add error messages
        ## Verify source MAC is VPP_MAC and destination MAC is MY_MAC resolved
        #  by VPP using ARP.
        self.assertEqual(pkt[Ether].src, self.pg0.vpp_mac)
        self.assertEqual(pkt[Ether].dst, self.pg0.my_mac)
        ## Verify VXLAN tunnel source IP is VPP_IP and destination IP is MY_IP.
        self.assertEqual(pkt[IP].src, self.pg0.local_ip4)
        self.assertEqual(pkt[IP].dst, self.pg0.remote_ip4)
        ## Verify UDP destination port is VXLAN 4789, source UDP port could be
        #  arbitrary.
        self.assertEqual(pkt[UDP].dport, type(self).dport)
        # TODO: checksum check
        ## Verify VNI, based on configuration it must be 1.
        self.assertEqual(pkt[VXLAN].vni, type(self).vni)

    ## Class method to start the VXLAN test case.
    #  Overrides setUpClass method in VppTestCase class.
    #  Python try..except statement is used to ensure that the tear down of
    #  the class will be executed even if exception is raised.
    #  @param cls The class pointer.
    @classmethod
    def setUpClass(cls):
        super(TestVxlan, cls).setUpClass()

        cls.dport = 4789
        cls.vni = 1

        ## Create 2 pg interfaces.
        cls.create_pg_interfaces(range(2))
        cls.pg0.admin_up()
        cls.pg1.admin_up()

        ## Configure IPv4 addresses on VPP pg0.
        cls.pg0.config_ip4()

        ## Resolve MAC address for VPP's IP address on pg0.
        cls.pg0.resolve_arp()

        ## Create VXLAN VTEP on VPP pg0, and put vxlan_tunnel0 and pg1
        #  into BD.
        r = vapi.vxlan_add_del_tunnel(src_addr = cls.pg0.local_ip4n,  dst_addr = cls.pg0.remote_ip4n, vni = cls.vni)
        vapi.sw_interface_set_l2_bridge(r.sw_if_index, bd_id = 1)
        vapi.sw_interface_set_l2_bridge(cls.pg1.sw_if_index, bd_id = 1)

    ## Method to define VPP actions before tear down of the test case.
    #  Overrides tearDown method in VppTestCase class.
    #  @param self The object pointer.
    def tearDown(self):
        super(TestVxlan, self).tearDown()
        info(vapi.cli("show bridge-domain 1 detail"))

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
