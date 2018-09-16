#!/usr/bin/env python

import socket
import unittest
from framework import VppTestCase, VppTestRunner
from vpp_ip_route import VppIpRoute, VppRoutePath
from util import ppp

from scapy.layers.l2 import Ether, Raw
from scapy.layers.inet import IP, UDP
from scapy.utils import atol

import StringIO


class TestFlowtable(VppTestCase):
    """ Flowtable Test Case """

    def __init__(self, *args):
        VppTestCase.__init__(self, *args)

    def generatePackets(self):
        """
        Encapsulate the original payload frame by adding IP and Ethernet fields
        """
        info = self.create_packet_info(self.pg0, self.pg1)
        payload = self.info_to_payload(info)
        return (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
                IP(src=self.pg0.remote_ip4, dst=self.dst_ip) /
                Raw(payload))

    def checkCapture(self):
        self.pg0.assert_nothing_captured()
        out = self.pg1.get_capture(len(self.packets))
        
        for pkt in out:
            try:        
                self.assertEqual(pkt[Ether].src, self.pg1.local_mac)
                self.assertEqual(pkt[Ether].dst, self.pg1.remote_mac)
                self.assertEqual(pkt[IP].src, self.pg0.remote_ip4)
                self.assertEqual(pkt[IP].dst, self.dst_ip)
            except:
                self.logger.error(ppp("Unexpected or invalid packet:", pkt))
                raise

    # Class method to start the Flowtable test case.
    #  Overrides setUpClass method in VppTestCase class.
    #  Python try..except statement is used to ensure that the tear down of
    #  the class will be executed even if exception is raised.
    #  @param cls The class pointer.
    @classmethod
    def setUpClass(cls):
        super(TestFlowtable, cls).setUpClass()
        cls.dst_ip = "192.168.1.2"
        
        cls.packets = range(1)

        try:
            # Create 2 pg interfaces.
            cls.create_pg_interfaces(range(2))
            cls.interfaces = list(cls.pg_interfaces)

            for i in cls.interfaces:
                i.admin_up()
                i.config_ip4()
                i.resolve_arp()
            
        except Exception:
            super(TestFlowtable, cls).tearDownClass()
            raise

    def test_flow_session(self):
        """ Create a flowtable session """

        #
        # Add a route that resolves the server's destination
        #
        route_sever_dst = VppIpRoute(self, self.dst_ip, 32,
                                     [VppRoutePath(self.pg1.remote_ip4,
                                                   self.pg1.sw_if_index)])
        route_sever_dst.add_vpp_config()

        # Setup flowtable and enable feature.
        r = self.vapi.flowtable_conf(
            flows_max=1024,
            sw_if_index=1,
            next_node_index=1,
            enable_disable=1)
            
        # Test the flowtable creation
        self.pg0.add_stream(self.generatePackets())
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.checkCapture()

        # Delete a route that resolves the server's destination
        route_sever_dst.remove_vpp_config()
            

    # Method to define VPP actions before tear down of the test case.
    #  Overrides tearDown method in VppTestCase class.
    #  @param self The object pointer.
    def tearDown(self):
        super(TestFlowtable, self).tearDown()

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
