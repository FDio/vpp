#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import unittest
from framework import VppTestCase, VppTestRunner
from util import Util

from scapy.packet import Raw
from scapy.layers.l2 import Ether, Dot1Q
from scapy.layers.inet6 import (IPv6, UDP,
    ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr,
    ICMPv6ND_NA, ICMPv6NDOptDstLLAddr)


@unittest.skip('Not finished yet.\n')
class TestIPv6(Util, VppTestCase):
    """ IPv6 Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestIPv6, cls).setUpClass()

        try:
            cls.create_interfaces_and_subinterfaces()

            # configure IPv6 on hardware interfaces
            cls.config_ip6(cls.interfaces)

            cls.config_ip6_on_software_interfaces(cls.interfaces)

            # resolve ICMPv6 ND using hardware interfaces
            cls.resolve_icmpv6_nd(cls.interfaces)

            # let VPP know MAC addresses of peer (sub)interfaces
            # cls.resolve_icmpv6_nd_on_software_interfaces(cls.interfaces)
            cls.send_neighbour_advertisement_on_software_interfaces(cls.interfaces)

            # config 2M FIB enries
            #cls.config_fib_entries(2000000)
            cls.config_fib_entries(1000000)

        except Exception as e:
            super(TestIPv6, cls).tearDownClass()
            raise

    def tearDown(self):
        self.cli(2, "show int")
        self.cli(2, "show trace")
        self.cli(2, "show hardware")
        self.cli(2, "show ip arp")
        # self.cli(2, "show ip fib")  # 2M entries
        self.cli(2, "show error")
        self.cli(2, "show run")

    @classmethod
    def create_vlan_subif(cls, pg_index, vlan):
        cls.api("create_vlan_subif pg%u vlan %u" % (pg_index, vlan))

    @classmethod
    def create_dot1ad_subif(cls, pg_index, sub_id, outer_vlan_id, inner_vlan_id):
        cls.api("create_subif pg%u sub_id %u outer_vlan_id %u inner_vlan_id %u dot1ad"
                 % (pg_index, sub_id, outer_vlan_id, inner_vlan_id))

    class SoftInt(object):
        pass

    class HardInt(SoftInt):
        pass

    class Subint(SoftInt):
        def __init__(self, sub_id):
            self.sub_id = sub_id

    class Dot1QSubint(Subint):
        def __init__(self, sub_id, vlan=None):
            if vlan is None:
                vlan = sub_id
            super(TestIPv6.Dot1QSubint, self).__init__(sub_id)
            self.vlan = vlan

    class Dot1ADSubint(Subint):
        def __init__(self, sub_id, outer_vlan, inner_vlan):
            super(TestIPv6.Dot1ADSubint, self).__init__(sub_id)
            self.outer_vlan = outer_vlan
            self.inner_vlan = inner_vlan

    @classmethod
    def create_interfaces_and_subinterfaces(cls):
        cls.interfaces = range(3)

        cls.create_interfaces(cls.interfaces)

        # Make vpp_api_test see interfaces created using debug CLI (in function create_interfaces)
        cls.api("sw_interface_dump")

        cls.INT_DETAILS = dict()

        cls.INT_DETAILS[0] = cls.HardInt()

        cls.INT_DETAILS[1] = cls.Dot1QSubint(100)
        cls.create_vlan_subif(1, cls.INT_DETAILS[1].vlan)

        # FIXME: Wrong packet format/wrong layer on output of interface 2
        #self.INT_DETAILS[2] = self.Dot1ADSubint(10, 200, 300)
        #self.create_dot1ad_subif(2, self.INT_DETAILS[2].sub_id, self.INT_DETAILS[2].outer_vlan, self.INT_DETAILS[2].inner_vlan)

        # Use dor1q for now
        cls.INT_DETAILS[2] = cls.Dot1QSubint(200)
        cls.create_vlan_subif(2, cls.INT_DETAILS[2].vlan)

        for i in cls.interfaces:
            det = cls.INT_DETAILS[i]
            if isinstance(det, cls.Subint):
                cls.api("sw_interface_set_flags pg%u.%u admin-up" % (i, det.sub_id))

    # IP adresses on subinterfaces
    MY_SOFT_IP6S = {}
    VPP_SOFT_IP6S = {}

    @classmethod
    def config_ip6_on_software_interfaces(cls, args):
        for i in args:
            cls.MY_SOFT_IP6S[i] = "fd01:%u::2" % i
            cls.VPP_SOFT_IP6S[i] = "fd01:%u::1" % i
            if isinstance(cls.INT_DETAILS[i], cls.Subint):
                interface = "pg%u.%u" % (i, cls.INT_DETAILS[i].sub_id)
            else:
                interface = "pg%u" % i
            cls.api("sw_interface_add_del_address %s %s/32" % (interface, cls.VPP_SOFT_IP6S[i]))
            cls.log("My subinterface IPv6 address is %s" % (cls.MY_SOFT_IP6S[i]))

    # let VPP know MAC addresses of peer (sub)interfaces
    @classmethod
    def resolve_icmpv6_nd_on_software_interfaces(cls, args):
        for i in args:
            ip = cls.VPP_SOFT_IP6S[i]
            cls.log("Sending ICMPv6ND_NS request for %s on port %u" % (ip, i))
            nd_req = (Ether(dst="ff:ff:ff:ff:ff:ff", src=cls.MY_MACS[i]) /
                      IPv6(src=cls.MY_SOFT_IP6S[i], dst=ip) /
                      ICMPv6ND_NS(tgt=ip) /
                      ICMPv6NDOptSrcLLAddr(lladdr=cls.MY_MACS[i]))
            cls.pg_add_stream(i, nd_req)
            cls.pg_enable_capture([i])

            cls.cli(2, "trace add pg-input 1")
            cls.pg_start()

            # We don't need to read output

    # let VPP know MAC addresses of peer (sub)interfaces
    @classmethod
    def send_neighbour_advertisement_on_software_interfaces(cls, args):
        for i in args:
            ip = cls.VPP_SOFT_IP6S[i]
            cls.log("Sending ICMPv6ND_NA message for %s on port %u" % (ip, i))
            pkt = (Ether(dst="ff:ff:ff:ff:ff:ff", src=cls.MY_MACS[i]) /
                   IPv6(src=cls.MY_SOFT_IP6S[i], dst=ip) /
                   ICMPv6ND_NA(tgt=ip, R=0, S=0) /
                   ICMPv6NDOptDstLLAddr(lladdr=cls.MY_MACS[i]))
            cls.pg_add_stream(i, pkt)
            cls.pg_enable_capture([i])

            cls.cli(2, "trace add pg-input 1")
            cls.pg_start()

    @classmethod
    def config_fib_entries(cls, count):
        n_int = len(cls.interfaces)
        for i in cls.interfaces:
            cls.api("ip_add_del_route fd02::1/128 via %s count %u" % (cls.VPP_SOFT_IP6S[i], count / n_int))

    @classmethod
    def add_dot1_layers(cls, i, packet):
        assert(type(packet) is Ether)
        payload = packet.payload
        det = cls.INT_DETAILS[i]
        if isinstance(det, cls.Dot1QSubint):
            packet.remove_payload()
            packet.add_payload(Dot1Q(vlan=det.sub_id) / payload)
        elif isinstance(det, cls.Dot1ADSubint):
            packet.remove_payload()
            packet.add_payload(Dot1Q(vlan=det.outer_vlan) / Dot1Q(vlan=det.inner_vlan) / payload)
            packet.type = 0x88A8

    def remove_dot1_layers(self, i, packet):
        self.assertEqual(type(packet), Ether)
        payload = packet.payload
        det = self.INT_DETAILS[i]
        if isinstance(det, self.Dot1QSubint):
            self.assertEqual(type(payload), Dot1Q)
            self.assertEqual(payload.vlan, self.INT_DETAILS[i].vlan)
            payload = payload.payload
        elif isinstance(det, self.Dot1ADSubint):  # TODO: change 88A8 type
            self.assertEqual(type(payload), Dot1Q)
            self.assertEqual(payload.vlan, self.INT_DETAILS[i].outer_vlan)
            payload = payload.payload
            self.assertEqual(type(payload), Dot1Q)
            self.assertEqual(payload.vlan, self.INT_DETAILS[i].inner_vlan)
            payload = payload.payload
        packet.remove_payload()
        packet.add_payload(payload)

    def create_stream(self, pg_id):
        pg_targets = [None] * 3
        pg_targets[0] = [1, 2]
        pg_targets[1] = [0, 2]
        pg_targets[2] = [0, 1]
        pkts = []
        for i in range(0, 257):
            target_pg_id = pg_targets[pg_id][i % 2]
            info = self.create_packet_info(pg_id, target_pg_id)
            payload = self.info_to_payload(info)
            p = (Ether(dst=self.VPP_MACS[pg_id], src=self.MY_MACS[pg_id]) /
                 IPv6(src=self.MY_SOFT_IP6S[pg_id], dst=self.MY_SOFT_IP6S[target_pg_id]) /
                 UDP(sport=1234, dport=1234) /
                 Raw(payload))
            info.data = p.copy()
            self.add_dot1_layers(pg_id, p)
            if not isinstance(self.INT_DETAILS[pg_id], self.Subint):
                packet_sizes = [76, 512, 1518, 9018]
            else:
                packet_sizes = [76, 512, 1518+4, 9018+4]
            size = packet_sizes[(i / 2) % len(packet_sizes)]
            self.extend_packet(p, size)
            pkts.append(p)
        return pkts

    def verify_capture(self, o, capture):
        last_info = {}
        for i in self.interfaces:
            last_info[i] = None
        for packet in capture:
            self.remove_dot1_layers(o, packet)  # Check VLAN tags and Ethernet header
            self.assertTrue(Dot1Q not in packet)
            try:
                ip = packet[IPv6]
                udp = packet[UDP]
                payload_info = self.payload_to_info(str(packet[Raw]))
                packet_index = payload_info.index
                src_pg = payload_info.src
                dst_pg = payload_info.dst
                self.assertEqual(dst_pg, o)
                self.log("Got packet on port %u: src=%u (id=%u)" % (o, src_pg, packet_index), 2)
                next_info = self.get_next_packet_info_for_interface2(src_pg, dst_pg, last_info[src_pg])
                last_info[src_pg] = next_info
                self.assertTrue(next_info is not None)
                self.assertEqual(packet_index, next_info.index)
                saved_packet = next_info.data
                # Check standard fields
                self.assertEqual(ip.src, saved_packet[IPv6].src)
                self.assertEqual(ip.dst, saved_packet[IPv6].dst)
                self.assertEqual(udp.sport, saved_packet[UDP].sport)
                self.assertEqual(udp.dport, saved_packet[UDP].dport)
            except:
                self.log("Unexpected or invalid packet:")
                packet.show()
                raise
        for i in self.interfaces:
            remaining_packet = self.get_next_packet_info_for_interface2(i, o, last_info[i])
            self.assertTrue(remaining_packet is None, "Port %u: Packet expected from source %u didn't arrive" % (o, i))

    def test_fib(self):
        """ IPv6 FIB test """

        for i in self.interfaces:
            pkts = self.create_stream(i)
            self.pg_add_stream(i, pkts)

        self.pg_enable_capture(self.interfaces)
        self.pg_start()

        for i in self.interfaces:
            out = self.pg_get_capture(i)
            self.log("Verifying capture %u" % i)
            self.verify_capture(i, out)


if __name__ == '__main__':
    unittest.main(testRunner = VppTestRunner)
