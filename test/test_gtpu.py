#!/usr/bin/env python

import socket
from util import ip4n_range, ip4_range
import unittest
from framework import VppTestCase, VppTestRunner
from template_bd import BridgeDomain

from scapy.layers.l2 import Ether, Raw
from scapy.layers.inet import IP, UDP
from scapy.contrib.gtp import GTP_U_Header
from scapy.utils import atol
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_ip import *


class TestGtpu(BridgeDomain, VppTestCase):
    """ GTPU Test Case """

    def __init__(self, *args):
        BridgeDomain.__init__(self)
        VppTestCase.__init__(self, *args)

    def encapsulate(self, pkt, vni):
        """
        Encapsulate the original payload frame by adding GTPU header with its
        UDP, IP and Ethernet fields
        """
        return (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) /
                IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) /
                UDP(sport=self.dport, dport=self.dport, chksum=0) /
                GTP_U_Header(teid=vni, gtp_type=self.gtp_type, length=150) /
                pkt)

    def ip_range(self, start, end):
        """ range of remote ip's """
        return ip4_range(self.pg0.remote_ip4, start, end)

    def encap_mcast(self, pkt, src_ip, src_mac, vni):
        """
        Encapsulate the original payload frame by adding GTPU header with its
        UDP, IP and Ethernet fields
        """
        return (Ether(src=src_mac, dst=self.mcast_mac) /
                IP(src=src_ip, dst=self.mcast_ip4) /
                UDP(sport=self.dport, dport=self.dport, chksum=0) /
                GTP_U_Header(teid=vni, gtp_type=self.gtp_type, length=150) /
                pkt)

    def decapsulate(self, pkt):
        """
        Decapsulate the original payload frame by removing GTPU header
        """
        return pkt[GTP_U_Header].payload

    # Method for checking GTPU encapsulation.
    #
    def check_encapsulation(self, pkt, vni, local_only=False, mcast_pkt=False):
        # Verify source MAC is VPP_MAC and destination MAC is MY_MAC resolved
        #  by VPP using ARP.
        self.assertEqual(pkt[Ether].src, self.pg0.local_mac)
        if not local_only:
            if not mcast_pkt:
                self.assertEqual(pkt[Ether].dst, self.pg0.remote_mac)
            else:
                self.assertEqual(pkt[Ether].dst, type(self).mcast_mac)
        # Verify GTPU tunnel source IP is VPP_IP and destination IP is MY_IP.
        self.assertEqual(pkt[IP].src, self.pg0.local_ip4)
        if not local_only:
            if not mcast_pkt:
                self.assertEqual(pkt[IP].dst, self.pg0.remote_ip4)
            else:
                self.assertEqual(pkt[IP].dst, type(self).mcast_ip4)
        # Verify UDP destination port is GTPU 2152, source UDP port could be
        #  arbitrary.
        self.assertEqual(pkt[UDP].dport, type(self).dport)
        # Verify teid
        self.assertEqual(pkt[GTP_U_Header].teid, vni)

    def test_encap(self):
        """ Encapsulation test
        Send frames from pg1
        Verify receipt of encapsulated frames on pg0
        """
        self.pg1.add_stream([self.frame_reply])

        self.pg0.enable_capture()

        self.pg_start()

        # Pick first received frame and check if it's corectly encapsulated.
        out = self.pg0.get_capture(1)
        pkt = out[0]
        self.check_encapsulation(pkt, self.single_tunnel_bd)

        # payload = self.decapsulate(pkt)
        # self.assert_eq_pkts(payload, self.frame_reply)

    def test_ucast_flood(self):
        """ Unicast flood test
        Send frames from pg3
        Verify receipt of encapsulated frames on pg0
        """
        self.pg3.add_stream([self.frame_reply])

        self.pg0.enable_capture()

        self.pg_start()

        # Get packet from each tunnel and assert it's corectly encapsulated.
        out = self.pg0.get_capture(self.n_ucast_tunnels)
        for pkt in out:
            self.check_encapsulation(pkt, self.ucast_flood_bd, True)
            # payload = self.decapsulate(pkt)
            # self.assert_eq_pkts(payload, self.frame_reply)

    def test_mcast_flood(self):
        """ Multicast flood test
        Send frames from pg2
        Verify receipt of encapsulated frames on pg0
        """
        self.pg2.add_stream([self.frame_reply])

        self.pg0.enable_capture()

        self.pg_start()

        # Pick first received frame and check if it's corectly encapsulated.
        out = self.pg0.get_capture(1)
        pkt = out[0]
        self.check_encapsulation(pkt, self.mcast_flood_bd,
                                 local_only=False, mcast_pkt=True)

        # payload = self.decapsulate(pkt)
        # self.assert_eq_pkts(payload, self.frame_reply)

    @classmethod
    def create_gtpu_flood_test_bd(cls, teid, n_ucast_tunnels):
        # Create 10 ucast gtpu tunnels under bd
        ip_range_start = 10
        ip_range_end = ip_range_start + n_ucast_tunnels
        next_hop_address = cls.pg0.remote_ip4
        for dest_ip4 in ip4_range(next_hop_address, ip_range_start,
                                  ip_range_end):
            # add host route so dest_ip4n will not be resolved
            rip = VppIpRoute(cls, dest_ip4, 32,
                             [VppRoutePath(next_hop_address,
                                           INVALID_INDEX)],
                             register=False)
            rip.add_vpp_config()
            dest_ip4n = socket.inet_pton(socket.AF_INET, dest_ip4)
            r = cls.vapi.gtpu_add_del_tunnel(
                src_addr=cls.pg0.local_ip4n,
                dst_addr=dest_ip4n,
                teid=teid)
            cls.vapi.sw_interface_set_l2_bridge(r.sw_if_index, bd_id=teid)

    @classmethod
    def add_del_shared_mcast_dst_load(cls, is_add):
        """
        add or del tunnels sharing the same mcast dst
        to test gtpu ref_count mechanism
        """
        n_shared_dst_tunnels = 20
        teid_start = 1000
        teid_end = teid_start + n_shared_dst_tunnels
        for teid in range(teid_start, teid_end):
            r = cls.vapi.gtpu_add_del_tunnel(
                src_addr=cls.pg0.local_ip4n,
                dst_addr=cls.mcast_ip4n,
                mcast_sw_if_index=1,
                teid=teid,
                is_add=is_add)
            if r.sw_if_index == 0xffffffff:
                raise "bad sw_if_index"

    @classmethod
    def add_shared_mcast_dst_load(cls):
        cls.add_del_shared_mcast_dst_load(is_add=1)

    @classmethod
    def del_shared_mcast_dst_load(cls):
        cls.add_del_shared_mcast_dst_load(is_add=0)

    @classmethod
    def add_del_mcast_tunnels_load(cls, is_add):
        """
        add or del tunnels to test gtpu stability
        """
        n_distinct_dst_tunnels = 20
        ip_range_start = 10
        ip_range_end = ip_range_start + n_distinct_dst_tunnels
        for dest_ip4n in ip4n_range(cls.mcast_ip4n, ip_range_start,
                                    ip_range_end):
            teid = bytearray(dest_ip4n)[3]
            cls.vapi.gtpu_add_del_tunnel(
                src_addr=cls.pg0.local_ip4n,
                dst_addr=dest_ip4n,
                mcast_sw_if_index=1,
                teid=teid,
                is_add=is_add)

    @classmethod
    def add_mcast_tunnels_load(cls):
        cls.add_del_mcast_tunnels_load(is_add=1)

    @classmethod
    def del_mcast_tunnels_load(cls):
        cls.add_del_mcast_tunnels_load(is_add=0)

    # Class method to start the GTPU test case.
    #  Overrides setUpClass method in VppTestCase class.
    #  Python try..except statement is used to ensure that the tear down of
    #  the class will be executed even if exception is raised.
    #  @param cls The class pointer.
    @classmethod
    def setUpClass(cls):
        super(TestGtpu, cls).setUpClass()

        try:
            cls.dport = 2152
            cls.gtp_type = 0xff

            # Create 2 pg interfaces.
            cls.create_pg_interfaces(range(4))
            for pg in cls.pg_interfaces:
                pg.admin_up()

            # Configure IPv4 addresses on VPP pg0.
            cls.pg0.config_ip4()

            # Resolve MAC address for VPP's IP address on pg0.
            cls.pg0.resolve_arp()

            # Our Multicast address
            cls.mcast_ip4 = '239.1.1.1'
            cls.mcast_ip4n = socket.inet_pton(socket.AF_INET, cls.mcast_ip4)
            iplong = atol(cls.mcast_ip4)
            cls.mcast_mac = "01:00:5e:%02x:%02x:%02x" % (
                (iplong >> 16) & 0x7F, (iplong >> 8) & 0xFF, iplong & 0xFF)

            # Create GTPU VTEP on VPP pg0, and put gtpu_tunnel0 and pg1
            #  into BD.
            cls.single_tunnel_bd = 11
            r = cls.vapi.gtpu_add_del_tunnel(
                src_addr=cls.pg0.local_ip4n,
                dst_addr=cls.pg0.remote_ip4n,
                teid=cls.single_tunnel_bd)
            cls.vapi.sw_interface_set_l2_bridge(r.sw_if_index,
                                                bd_id=cls.single_tunnel_bd)
            cls.vapi.sw_interface_set_l2_bridge(cls.pg1.sw_if_index,
                                                bd_id=cls.single_tunnel_bd)

            # Setup teid 2 to test multicast flooding
            cls.n_ucast_tunnels = 10
            cls.mcast_flood_bd = 12
            cls.create_gtpu_flood_test_bd(cls.mcast_flood_bd,
                                          cls.n_ucast_tunnels)
            r = cls.vapi.gtpu_add_del_tunnel(
                src_addr=cls.pg0.local_ip4n,
                dst_addr=cls.mcast_ip4n,
                mcast_sw_if_index=1,
                teid=cls.mcast_flood_bd)
            cls.vapi.sw_interface_set_l2_bridge(r.sw_if_index,
                                                bd_id=cls.mcast_flood_bd)
            cls.vapi.sw_interface_set_l2_bridge(cls.pg2.sw_if_index,
                                                bd_id=cls.mcast_flood_bd)

            # Add and delete mcast tunnels to check stability
            cls.add_shared_mcast_dst_load()
            cls.add_mcast_tunnels_load()
            cls.del_shared_mcast_dst_load()
            cls.del_mcast_tunnels_load()

            # Setup teid 3 to test unicast flooding
            cls.ucast_flood_bd = 13
            cls.create_gtpu_flood_test_bd(cls.ucast_flood_bd,
                                          cls.n_ucast_tunnels)
            cls.vapi.sw_interface_set_l2_bridge(cls.pg3.sw_if_index,
                                                bd_id=cls.ucast_flood_bd)
        except Exception:
            super(TestGtpu, cls).tearDownClass()
            raise

    # Method to define VPP actions before tear down of the test case.
    #  Overrides tearDown method in VppTestCase class.
    #  @param self The object pointer.
    def tearDown(self):
        super(TestGtpu, self).tearDown()
        if not self.vpp_dead:
            self.logger.info(self.vapi.cli("show bridge-domain 11 detail"))
            self.logger.info(self.vapi.cli("show bridge-domain 12 detail"))
            self.logger.info(self.vapi.cli("show bridge-domain 13 detail"))
            self.logger.info(self.vapi.cli("show int"))
            self.logger.info(self.vapi.cli("show gtpu tunnel"))
            self.logger.info(self.vapi.cli("show trace"))


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
