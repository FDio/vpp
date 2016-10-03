#!/usr/bin/env python

import unittest
from framework import VppTestCase, VppTestRunner
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
        return (Ether(src=self.MY_MACS[0], dst=self.VPP_MACS[0]) /
                IP(src=self.MY_IP4S[0], dst=self.VPP_IP4S[0]) /
                UDP(sport=4789, dport=4789, chksum=0) /
                VXLAN(vni=1) /
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
        self.assertEqual(pkt[Ether].src, self.VPP_MACS[0])
        self.assertEqual(pkt[Ether].dst, self.MY_MACS[0])
        ## Verify VXLAN tunnel source IP is VPP_IP and destination IP is MY_IP.
        self.assertEqual(pkt[IP].src, self.VPP_IP4S[0])
        self.assertEqual(pkt[IP].dst, self.MY_IP4S[0])
        ## Verify UDP destination port is VXLAN 4789, source UDP port could be
        #  arbitrary.
        self.assertEqual(pkt[UDP].dport, 4789)
        # TODO: checksum check
        ## Verify VNI, based on configuration it must be 1.
        self.assertEqual(pkt[VXLAN].vni, 1)

    ## Class method to start the VXLAN test case.
    #  Overrides setUpClass method in VppTestCase class.
    #  Python try..except statement is used to ensure that the tear down of
    #  the class will be executed even if exception is raised.
    #  @param cls The class pointer.
    @classmethod
    def setUpClass(cls):
        super(TestVxlan, cls).setUpClass()
        try:
            ## Create 2 pg interfaces.
            cls.create_interfaces(range(2))
            ## Configure IPv4 addresses on VPP pg0.
            cls.config_ip4([0])
            ## Resolve MAC address for VPP's IP address on pg0.
            cls.resolve_arp([0])

            ## Create VXLAN VTEP on VPP pg0, and put vxlan_tunnel0 and pg1
            #  into BD.
            cls.api("vxlan_add_del_tunnel src %s dst %s vni 1" %
                    (cls.VPP_IP4S[0], cls.MY_IP4S[0]))
            cls.api("sw_interface_set_l2_bridge vxlan_tunnel0 bd_id 1")
            cls.api("sw_interface_set_l2_bridge pg1 bd_id 1")
        except:
            ## In case setUpClass fails run tear down.
            cls.tearDownClass()
            raise

    ## Method to define VPP actions before tear down of the test case.
    #  Overrides tearDown method in VppTestCase class.
    #  @param self The object pointer.
    def tearDown(self):
        super(TestVxlan, self).tearDown()
        self.cli(2, "show bridge-domain 1 detail")

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
