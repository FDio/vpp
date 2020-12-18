#!/usr/bin/env python3
import binascii
import random
import socket
import unittest

import scapy.compat
from scapy.contrib.mpls import MPLS
from scapy.layers.inet import IP, UDP, TCP, ICMP, icmptypes, icmpcodes
from scapy.layers.l2 import Ether, Dot1Q, ARP
from scapy.packet import Raw
from six import moves

from framework import tag_fixme_vpp_workers
from framework import VppTestCase, VppTestRunner
from util import ppp
from vpp_ip_route import VppIpRoute, VppRoutePath, VppIpMRoute, \
    VppMRoutePath, VppMplsIpBind, \
    VppMplsTable, VppIpTable, FibPathType, find_route, \
    VppIpInterfaceAddress, find_route_in_dump, find_mroute_in_dump
from vpp_ip import VppIpPuntPolicer, VppIpPuntRedirect, VppIpPathMtu
from vpp_sub_interface import VppSubInterface, VppDot1QSubint, VppDot1ADSubint
from vpp_papi import VppEnum
from vpp_neighbor import VppNeighbor
from vpp_lo_interface import VppLoInterface
from vpp_policer import VppPolicer, PolicerAction

NUM_PKTS = 67


class TestIPv4(VppTestCase):
    """ IPv4 Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestIPv4, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestIPv4, cls).tearDownClass()

    def setUp(self):
        """
        Perform test setup before test case.

        **Config:**
            - create 3 pg interfaces
                - untagged pg0 interface
                - Dot1Q subinterface on pg1
                - Dot1AD subinterface on pg2
            - setup interfaces:
                - put it into UP state
                - set IPv4 addresses
                - resolve neighbor address using ARP
            - configure 200 fib entries

        :ivar list interfaces: pg interfaces and subinterfaces.
        :ivar dict flows: IPv4 packet flows in test.
        """
        super(TestIPv4, self).setUp()

        # create 3 pg interfaces
        self.create_pg_interfaces(range(3))

        # create 2 subinterfaces for pg1 and pg2
        self.sub_interfaces = [
            VppDot1QSubint(self, self.pg1, 100),
            VppDot1ADSubint(self, self.pg2, 200, 300, 400)]

        # packet flows mapping pg0 -> pg1.sub, pg2.sub, etc.
        self.flows = dict()
        self.flows[self.pg0] = [self.pg1.sub_if, self.pg2.sub_if]
        self.flows[self.pg1.sub_if] = [self.pg0, self.pg2.sub_if]
        self.flows[self.pg2.sub_if] = [self.pg0, self.pg1.sub_if]

        # packet sizes
        self.pg_if_packet_sizes = [64, 1500, 9020]

        self.interfaces = list(self.pg_interfaces)
        self.interfaces.extend(self.sub_interfaces)

        # setup all interfaces
        for i in self.interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

        # config 2M FIB entries

    def tearDown(self):
        """Run standard test teardown and log ``show ip arp``."""
        super(TestIPv4, self).tearDown()

    def show_commands_at_teardown(self):
        self.logger.info(self.vapi.cli("show ip4 neighbors"))
        # info(self.vapi.cli("show ip fib"))  # many entries

    def modify_packet(self, src_if, packet_size, pkt):
        """Add load, set destination IP and extend packet to required packet
        size for defined interface.

        :param VppInterface src_if: Interface to create packet for.
        :param int packet_size: Required packet size.
        :param Scapy pkt: Packet to be modified.
        """
        dst_if_idx = int(packet_size / 10 % 2)
        dst_if = self.flows[src_if][dst_if_idx]
        info = self.create_packet_info(src_if, dst_if)
        payload = self.info_to_payload(info)
        p = pkt/Raw(payload)
        p[IP].dst = dst_if.remote_ip4
        info.data = p.copy()
        if isinstance(src_if, VppSubInterface):
            p = src_if.add_dot1_layer(p)
        self.extend_packet(p, packet_size)

        return p

    def create_stream(self, src_if):
        """Create input packet stream for defined interface.

        :param VppInterface src_if: Interface to create packet stream for.
        """
        hdr_ext = 4 if isinstance(src_if, VppSubInterface) else 0
        pkt_tmpl = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                    IP(src=src_if.remote_ip4) /
                    UDP(sport=1234, dport=1234))

        pkts = [self.modify_packet(src_if, i, pkt_tmpl)
                for i in moves.range(self.pg_if_packet_sizes[0],
                                     self.pg_if_packet_sizes[1], 10)]
        pkts_b = [self.modify_packet(src_if, i, pkt_tmpl)
                  for i in moves.range(self.pg_if_packet_sizes[1] + hdr_ext,
                                       self.pg_if_packet_sizes[2] + hdr_ext,
                                       50)]
        pkts.extend(pkts_b)

        return pkts

    def verify_capture(self, dst_if, capture):
        """Verify captured input packet stream for defined interface.

        :param VppInterface dst_if: Interface to verify captured packet stream
            for.
        :param list capture: Captured packet stream.
        """
        self.logger.info("Verifying capture on interface %s" % dst_if.name)
        last_info = dict()
        for i in self.interfaces:
            last_info[i.sw_if_index] = None
        is_sub_if = False
        dst_sw_if_index = dst_if.sw_if_index
        if hasattr(dst_if, 'parent'):
            is_sub_if = True
        for packet in capture:
            if is_sub_if:
                # Check VLAN tags and Ethernet header
                packet = dst_if.remove_dot1_layer(packet)
            self.assertTrue(Dot1Q not in packet)
            try:
                ip = packet[IP]
                udp = packet[UDP]
                payload_info = self.payload_to_info(packet[Raw])
                packet_index = payload_info.index
                self.assertEqual(payload_info.dst, dst_sw_if_index)
                self.logger.debug(
                    "Got packet on port %s: src=%u (id=%u)" %
                    (dst_if.name, payload_info.src, packet_index))
                next_info = self.get_next_packet_info_for_interface2(
                    payload_info.src, dst_sw_if_index,
                    last_info[payload_info.src])
                last_info[payload_info.src] = next_info
                self.assertTrue(next_info is not None)
                self.assertEqual(packet_index, next_info.index)
                saved_packet = next_info.data
                # Check standard fields
                self.assertEqual(ip.src, saved_packet[IP].src)
                self.assertEqual(ip.dst, saved_packet[IP].dst)
                self.assertEqual(udp.sport, saved_packet[UDP].sport)
                self.assertEqual(udp.dport, saved_packet[UDP].dport)
            except:
                self.logger.error(ppp("Unexpected or invalid packet:", packet))
                raise
        for i in self.interfaces:
            remaining_packet = self.get_next_packet_info_for_interface2(
                i.sw_if_index, dst_sw_if_index, last_info[i.sw_if_index])
            self.assertTrue(remaining_packet is None,
                            "Interface %s: Packet expected from interface %s "
                            "didn't arrive" % (dst_if.name, i.name))

    def test_fib(self):
        """ IPv4 FIB test

        Test scenario:

            - Create IPv4 stream for pg0 interface
            - Create IPv4 tagged streams for pg1's and pg2's sub-interface.
            - Send and verify received packets on each interface.
        """

        pkts = self.create_stream(self.pg0)
        self.pg0.add_stream(pkts)

        for i in self.sub_interfaces:
            pkts = self.create_stream(i)
            i.parent.add_stream(pkts)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        pkts = self.pg0.get_capture()
        self.verify_capture(self.pg0, pkts)

        for i in self.sub_interfaces:
            pkts = i.parent.get_capture()
            self.verify_capture(i, pkts)


class TestIPv4RouteLookup(VppTestCase):
    """ IPv4 Route Lookup Test Case """
    routes = []

    def route_lookup(self, prefix, exact):
        return self.vapi.api(self.vapi.papi.ip_route_lookup,
                             {
                                 'table_id': 0,
                                 'exact': exact,
                                 'prefix': prefix,
                             })

    @classmethod
    def setUpClass(cls):
        super(TestIPv4RouteLookup, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestIPv4RouteLookup, cls).tearDownClass()

    def setUp(self):
        super(TestIPv4RouteLookup, self).setUp()

        drop_nh = VppRoutePath("127.0.0.1", 0xffffffff,
                               type=FibPathType.FIB_PATH_TYPE_DROP)

        # Add 3 routes
        r = VppIpRoute(self, "1.1.0.0", 16, [drop_nh])
        r.add_vpp_config()
        self.routes.append(r)

        r = VppIpRoute(self, "1.1.1.0", 24, [drop_nh])
        r.add_vpp_config()
        self.routes.append(r)

        r = VppIpRoute(self, "1.1.1.1", 32, [drop_nh])
        r.add_vpp_config()
        self.routes.append(r)

    def tearDown(self):
        # Remove the routes we added
        for r in self.routes:
            r.remove_vpp_config()

        super(TestIPv4RouteLookup, self).tearDown()

    def test_exact_match(self):
        # Verify we find the host route
        prefix = "1.1.1.1/32"
        result = self.route_lookup(prefix, True)
        assert (prefix == str(result.route.prefix))

        # Verify we find a middle prefix route
        prefix = "1.1.1.0/24"
        result = self.route_lookup(prefix, True)
        assert (prefix == str(result.route.prefix))

        # Verify we do not find an available LPM.
        with self.vapi.assert_negative_api_retval():
            self.route_lookup("1.1.1.2/32", True)

    def test_longest_prefix_match(self):
        # verify we find lpm
        lpm_prefix = "1.1.1.0/24"
        result = self.route_lookup("1.1.1.2/32", False)
        assert (lpm_prefix == str(result.route.prefix))

        # Verify we find the exact when not requested
        result = self.route_lookup(lpm_prefix, False)
        assert (lpm_prefix == str(result.route.prefix))

        # Can't seem to delete the default route so no negative LPM test.


class TestIPv4IfAddrRoute(VppTestCase):
    """ IPv4 Interface Addr Route Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestIPv4IfAddrRoute, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestIPv4IfAddrRoute, cls).tearDownClass()

    def setUp(self):
        super(TestIPv4IfAddrRoute, self).setUp()

        # create 1 pg interface
        self.create_pg_interfaces(range(1))

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    def tearDown(self):
        super(TestIPv4IfAddrRoute, self).tearDown()
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.admin_down()

    def test_ipv4_ifaddrs_same_prefix(self):
        """ IPv4 Interface Addresses Same Prefix test

        Test scenario:

            - Verify no route in FIB for prefix 10.10.10.0/24
            - Configure IPv4 address 10.10.10.10/24 on an interface
            - Verify route in FIB for prefix 10.10.10.0/24
            - Configure IPv4 address 10.10.10.20/24 on an interface
            - Delete 10.10.10.10/24 from interface
            - Verify route in FIB for prefix 10.10.10.0/24
            - Delete 10.10.10.20/24 from interface
            - Verify no route in FIB for prefix 10.10.10.0/24
        """

        # create two addresses, verify route not present
        if_addr1 = VppIpInterfaceAddress(self, self.pg0, "10.10.10.10", 24)
        if_addr2 = VppIpInterfaceAddress(self, self.pg0, "10.10.10.20", 24)
        self.assertFalse(if_addr1.query_vpp_config())  # 10.10.10.10/24
        self.assertFalse(find_route(self, "10.10.10.10", 32))
        self.assertFalse(find_route(self, "10.10.10.20", 32))
        self.assertFalse(find_route(self, "10.10.10.255", 32))
        self.assertFalse(find_route(self, "10.10.10.0", 32))

        # configure first address, verify route present
        if_addr1.add_vpp_config()
        self.assertTrue(if_addr1.query_vpp_config())  # 10.10.10.10/24
        self.assertTrue(find_route(self, "10.10.10.10", 32))
        self.assertFalse(find_route(self, "10.10.10.20", 32))
        self.assertTrue(find_route(self, "10.10.10.255", 32))
        self.assertTrue(find_route(self, "10.10.10.0", 32))

        # configure second address, delete first, verify route not removed
        if_addr2.add_vpp_config()
        if_addr1.remove_vpp_config()
        self.assertFalse(if_addr1.query_vpp_config())  # 10.10.10.10/24
        self.assertTrue(if_addr2.query_vpp_config())  # 10.10.10.20/24
        self.assertFalse(find_route(self, "10.10.10.10", 32))
        self.assertTrue(find_route(self, "10.10.10.20", 32))
        self.assertTrue(find_route(self, "10.10.10.255", 32))
        self.assertTrue(find_route(self, "10.10.10.0", 32))

        # delete second address, verify route removed
        if_addr2.remove_vpp_config()
        self.assertFalse(if_addr2.query_vpp_config())  # 10.10.10.20/24
        self.assertFalse(find_route(self, "10.10.10.10", 32))
        self.assertFalse(find_route(self, "10.10.10.20", 32))
        self.assertFalse(find_route(self, "10.10.10.255", 32))
        self.assertFalse(find_route(self, "10.10.10.0", 32))

    def test_ipv4_ifaddr_route(self):
        """ IPv4 Interface Address Route test

        Test scenario:

            - Create loopback
            - Configure IPv4 address on loopback
            - Verify that address is not in the FIB
            - Bring loopback up
            - Verify that address is in the FIB now
            - Bring loopback down
            - Verify that address is not in the FIB anymore
            - Bring loopback up
            - Configure IPv4 address on loopback
            - Verify that address is in the FIB now
        """

        # create a loopback and configure IPv4
        loopbacks = self.create_loopback_interfaces(1)
        lo_if = self.lo_interfaces[0]

        lo_if.local_ip4_prefix_len = 32
        lo_if.config_ip4()

        # The intf was down when addr was added -> entry not in FIB
        fib4_dump = self.vapi.ip_route_dump(0)
        self.assertFalse(lo_if.is_ip4_entry_in_fib_dump(fib4_dump))

        # When intf is brought up, entry is added
        lo_if.admin_up()
        fib4_dump = self.vapi.ip_route_dump(0)
        self.assertTrue(lo_if.is_ip4_entry_in_fib_dump(fib4_dump))

        # When intf is brought down, entry is removed
        lo_if.admin_down()
        fib4_dump = self.vapi.ip_route_dump(0)
        self.assertFalse(lo_if.is_ip4_entry_in_fib_dump(fib4_dump))

        # Remove addr, bring up interface, re-add -> entry in FIB
        lo_if.unconfig_ip4()
        lo_if.admin_up()
        lo_if.config_ip4()
        fib4_dump = self.vapi.ip_route_dump(0)
        self.assertTrue(lo_if.is_ip4_entry_in_fib_dump(fib4_dump))

    def test_ipv4_ifaddr_del(self):
        """ Delete an interface address that does not exist """

        loopbacks = self.create_loopback_interfaces(1)
        lo = self.lo_interfaces[0]

        lo.config_ip4()
        lo.admin_up()

        #
        # try and remove pg0's subnet from lo
        #
        with self.vapi.assert_negative_api_retval():
            self.vapi.sw_interface_add_del_address(
                sw_if_index=lo.sw_if_index,
                prefix=self.pg0.local_ip4_prefix,
                is_add=0)


class TestICMPEcho(VppTestCase):
    """ ICMP Echo Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestICMPEcho, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestICMPEcho, cls).tearDownClass()

    def setUp(self):
        super(TestICMPEcho, self).setUp()

        # create 1 pg interface
        self.create_pg_interfaces(range(1))

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    def tearDown(self):
        super(TestICMPEcho, self).tearDown()
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.admin_down()

    def test_icmp_echo(self):
        """ VPP replies to ICMP Echo Request

        Test scenario:

            - Receive ICMP Echo Request message on pg0 interface.
            - Check outgoing ICMP Echo Reply message on pg0 interface.
        """

        icmp_id = 0xb
        icmp_seq = 5
        icmp_load = b'\x0a' * 18
        p_echo_request = (Ether(src=self.pg0.remote_mac,
                                dst=self.pg0.local_mac) /
                          IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) /
                          ICMP(id=icmp_id, seq=icmp_seq) /
                          Raw(load=icmp_load))

        self.pg0.add_stream(p_echo_request)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg0.get_capture(1)
        rx = rx[0]
        ether = rx[Ether]
        ipv4 = rx[IP]
        icmp = rx[ICMP]

        self.assertEqual(ether.src, self.pg0.local_mac)
        self.assertEqual(ether.dst, self.pg0.remote_mac)

        self.assertEqual(ipv4.src, self.pg0.local_ip4)
        self.assertEqual(ipv4.dst, self.pg0.remote_ip4)

        self.assertEqual(icmptypes[icmp.type], "echo-reply")
        self.assertEqual(icmp.id, icmp_id)
        self.assertEqual(icmp.seq, icmp_seq)
        self.assertEqual(icmp[Raw].load, icmp_load)


class TestIPv4FibCrud(VppTestCase):
    """ FIB - add/update/delete - ip4 routes

    Test scenario:
        - add 1k,
        - del 100,
        - add new 1k,
        - del 1.5k

    ..note:: Python API is too slow to add many routes, needs replacement.
    """

    def config_fib_many_to_one(self, start_dest_addr, next_hop_addr,
                               count, start=0):
        """

        :param start_dest_addr:
        :param next_hop_addr:
        :param count:
        :return list: added ips with 32 prefix
        """
        routes = []
        for i in range(count):
            r = VppIpRoute(self, start_dest_addr % (i + start), 32,
                           [VppRoutePath(next_hop_addr, 0xffffffff)])
            r.add_vpp_config()
            routes.append(r)
        return routes

    def unconfig_fib_many_to_one(self, start_dest_addr, next_hop_addr,
                                 count, start=0):

        routes = []
        for i in range(count):
            r = VppIpRoute(self, start_dest_addr % (i + start), 32,
                           [VppRoutePath(next_hop_addr, 0xffffffff)])
            r.remove_vpp_config()
            routes.append(r)
        return routes

    def create_stream(self, src_if, dst_if, routes, count):
        pkts = []

        for _ in range(count):
            dst_addr = random.choice(routes).prefix.network_address
            info = self.create_packet_info(src_if, dst_if)
            payload = self.info_to_payload(info)
            p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                 IP(src=src_if.remote_ip4, dst=str(dst_addr)) /
                 UDP(sport=1234, dport=1234) /
                 Raw(payload))
            info.data = p.copy()
            self.extend_packet(p, random.choice(self.pg_if_packet_sizes))
            pkts.append(p)

        return pkts

    def _find_ip_match(self, find_in, pkt):
        for p in find_in:
            if self.payload_to_info(p[Raw]) == \
                    self.payload_to_info(pkt[Raw]):
                if p[IP].src != pkt[IP].src:
                    break
                if p[IP].dst != pkt[IP].dst:
                    break
                if p[UDP].sport != pkt[UDP].sport:
                    break
                if p[UDP].dport != pkt[UDP].dport:
                    break
                return p
        return None

    def verify_capture(self, dst_interface, received_pkts, expected_pkts):
        self.assertEqual(len(received_pkts), len(expected_pkts))
        to_verify = list(expected_pkts)
        for p in received_pkts:
            self.assertEqual(p.src, dst_interface.local_mac)
            self.assertEqual(p.dst, dst_interface.remote_mac)
            x = self._find_ip_match(to_verify, p)
            to_verify.remove(x)
        self.assertListEqual(to_verify, [])

    def verify_route_dump(self, routes):
        for r in routes:
            self.assertTrue(find_route(self,
                                       r.prefix.network_address,
                                       r.prefix.prefixlen))

    def verify_not_in_route_dump(self, routes):
        for r in routes:
            self.assertFalse(find_route(self,
                                        r.prefix.network_address,
                                        r.prefix.prefixlen))

    @classmethod
    def setUpClass(cls):
        """
        #. Create and initialize 3 pg interfaces.
        #. initialize class attributes configured_routes and deleted_routes
           to store information between tests.
        """
        super(TestIPv4FibCrud, cls).setUpClass()

        try:
            # create 3 pg interfaces
            cls.create_pg_interfaces(range(3))

            cls.interfaces = list(cls.pg_interfaces)

            # setup all interfaces
            for i in cls.interfaces:
                i.admin_up()
                i.config_ip4()
                i.resolve_arp()

            cls.configured_routes = []
            cls.deleted_routes = []
            cls.pg_if_packet_sizes = [64, 512, 1518, 9018]

        except Exception:
            super(TestIPv4FibCrud, cls).tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        super(TestIPv4FibCrud, cls).tearDownClass()

    def setUp(self):
        super(TestIPv4FibCrud, self).setUp()
        self.reset_packet_infos()

        self.configured_routes = []
        self.deleted_routes = []

    def test_1_add_routes(self):
        """ Add 1k routes """

        # add 100 routes check with traffic script.
        self.configured_routes.extend(self.config_fib_many_to_one(
            "10.0.0.%d", self.pg0.remote_ip4, 100))

        self.verify_route_dump(self.configured_routes)

        self.stream_1 = self.create_stream(
            self.pg1, self.pg0, self.configured_routes, 100)
        self.stream_2 = self.create_stream(
            self.pg2, self.pg0, self.configured_routes, 100)
        self.pg1.add_stream(self.stream_1)
        self.pg2.add_stream(self.stream_2)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        pkts = self.pg0.get_capture(len(self.stream_1) + len(self.stream_2))
        self.verify_capture(self.pg0, pkts, self.stream_1 + self.stream_2)

    def test_2_del_routes(self):
        """ Delete 100 routes

        - delete 10 routes check with traffic script.
        """
        # config 1M FIB entries
        self.configured_routes.extend(self.config_fib_many_to_one(
            "10.0.0.%d", self.pg0.remote_ip4, 100))
        self.deleted_routes.extend(self.unconfig_fib_many_to_one(
            "10.0.0.%d", self.pg0.remote_ip4, 10, start=10))
        for x in self.deleted_routes:
            self.configured_routes.remove(x)

        self.verify_route_dump(self.configured_routes)

        self.stream_1 = self.create_stream(
            self.pg1, self.pg0, self.configured_routes, 100)
        self.stream_2 = self.create_stream(
            self.pg2, self.pg0, self.configured_routes, 100)
        self.stream_3 = self.create_stream(
            self.pg1, self.pg0, self.deleted_routes, 100)
        self.stream_4 = self.create_stream(
            self.pg2, self.pg0, self.deleted_routes, 100)
        self.pg1.add_stream(self.stream_1 + self.stream_3)
        self.pg2.add_stream(self.stream_2 + self.stream_4)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        pkts = self.pg0.get_capture(len(self.stream_1) + len(self.stream_2))
        self.verify_capture(self.pg0, pkts, self.stream_1 + self.stream_2)

    def test_3_add_new_routes(self):
        """ Add 1k routes

        - re-add 5 routes check with traffic script.
        - add 100 routes check with traffic script.
        """
        # config 1M FIB entries
        self.configured_routes.extend(self.config_fib_many_to_one(
            "10.0.0.%d", self.pg0.remote_ip4, 100))
        self.deleted_routes.extend(self.unconfig_fib_many_to_one(
            "10.0.0.%d", self.pg0.remote_ip4, 10, start=10))
        for x in self.deleted_routes:
            self.configured_routes.remove(x)

        tmp = self.config_fib_many_to_one(
            "10.0.0.%d", self.pg0.remote_ip4, 5, start=10)
        self.configured_routes.extend(tmp)
        for x in tmp:
            self.deleted_routes.remove(x)

        self.configured_routes.extend(self.config_fib_many_to_one(
            "10.0.1.%d", self.pg0.remote_ip4, 100))

        self.verify_route_dump(self.configured_routes)

        self.stream_1 = self.create_stream(
            self.pg1, self.pg0, self.configured_routes, 300)
        self.stream_2 = self.create_stream(
            self.pg2, self.pg0, self.configured_routes, 300)
        self.stream_3 = self.create_stream(
            self.pg1, self.pg0, self.deleted_routes, 100)
        self.stream_4 = self.create_stream(
            self.pg2, self.pg0, self.deleted_routes, 100)

        self.pg1.add_stream(self.stream_1 + self.stream_3)
        self.pg2.add_stream(self.stream_2 + self.stream_4)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        pkts = self.pg0.get_capture(len(self.stream_1) + len(self.stream_2))
        self.verify_capture(self.pg0, pkts, self.stream_1 + self.stream_2)

        # delete 5 routes check with traffic script.
        # add 100 routes check with traffic script.
        self.deleted_routes.extend(self.unconfig_fib_many_to_one(
            "10.0.0.%d", self.pg0.remote_ip4, 15))
        self.deleted_routes.extend(self.unconfig_fib_many_to_one(
            "10.0.0.%d", self.pg0.remote_ip4, 85))
        self.deleted_routes.extend(self.unconfig_fib_many_to_one(
            "10.0.1.%d", self.pg0.remote_ip4, 100))
        self.verify_not_in_route_dump(self.deleted_routes)


class TestIPNull(VppTestCase):
    """ IPv4 routes via NULL """

    @classmethod
    def setUpClass(cls):
        super(TestIPNull, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestIPNull, cls).tearDownClass()

    def setUp(self):
        super(TestIPNull, self).setUp()

        # create 2 pg interfaces
        self.create_pg_interfaces(range(2))

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    def tearDown(self):
        super(TestIPNull, self).tearDown()
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.admin_down()

    def test_ip_null(self):
        """ IP NULL route """

        #
        # A route via IP NULL that will reply with ICMP unreachables
        #
        ip_unreach = VppIpRoute(
            self, "10.0.0.1", 32,
            [VppRoutePath("0.0.0.0",
                          0xffffffff,
                          type=FibPathType.FIB_PATH_TYPE_ICMP_UNREACH)])
        ip_unreach.add_vpp_config()

        p_unreach = (Ether(src=self.pg0.remote_mac,
                           dst=self.pg0.local_mac) /
                     IP(src=self.pg0.remote_ip4, dst="10.0.0.1") /
                     UDP(sport=1234, dport=1234) /
                     Raw(b'\xa5' * 100))
        self.pg0.add_stream(p_unreach)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg0.get_capture(1)
        rx = rx[0]
        icmp = rx[ICMP]

        self.assertEqual(icmptypes[icmp.type], "dest-unreach")
        self.assertEqual(icmpcodes[icmp.type][icmp.code], "host-unreachable")
        self.assertEqual(icmp.src, self.pg0.remote_ip4)
        self.assertEqual(icmp.dst, "10.0.0.1")

        #
        # ICMP replies are rate limited. so sit and spin.
        #
        self.sleep(1)

        #
        # A route via IP NULL that will reply with ICMP prohibited
        #
        ip_prohibit = VppIpRoute(
            self, "10.0.0.2", 32,
            [VppRoutePath("0.0.0.0",
                          0xffffffff,
                          type=FibPathType.FIB_PATH_TYPE_ICMP_PROHIBIT)])
        ip_prohibit.add_vpp_config()

        p_prohibit = (Ether(src=self.pg0.remote_mac,
                            dst=self.pg0.local_mac) /
                      IP(src=self.pg0.remote_ip4, dst="10.0.0.2") /
                      UDP(sport=1234, dport=1234) /
                      Raw(b'\xa5' * 100))

        self.pg0.add_stream(p_prohibit)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rx = self.pg0.get_capture(1)

        rx = rx[0]
        icmp = rx[ICMP]

        self.assertEqual(icmptypes[icmp.type], "dest-unreach")
        self.assertEqual(icmpcodes[icmp.type][icmp.code], "host-prohibited")
        self.assertEqual(icmp.src, self.pg0.remote_ip4)
        self.assertEqual(icmp.dst, "10.0.0.2")

    def test_ip_drop(self):
        """ IP Drop Routes """

        p = (Ether(src=self.pg0.remote_mac,
                   dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst="1.1.1.1") /
             UDP(sport=1234, dport=1234) /
             Raw(b'\xa5' * 100))

        r1 = VppIpRoute(self, "1.1.1.0", 24,
                        [VppRoutePath(self.pg1.remote_ip4,
                                      self.pg1.sw_if_index)])
        r1.add_vpp_config()

        rx = self.send_and_expect(self.pg0, p * NUM_PKTS, self.pg1)

        #
        # insert a more specific as a drop
        #
        r2 = VppIpRoute(self, "1.1.1.1", 32,
                        [VppRoutePath("0.0.0.0",
                                      0xffffffff,
                                      type=FibPathType.FIB_PATH_TYPE_DROP)])
        r2.add_vpp_config()

        self.send_and_assert_no_replies(self.pg0, p * NUM_PKTS, "Drop Route")
        r2.remove_vpp_config()
        rx = self.send_and_expect(self.pg0, p * NUM_PKTS, self.pg1)


class TestIPDisabled(VppTestCase):
    """ IPv4 disabled """

    @classmethod
    def setUpClass(cls):
        super(TestIPDisabled, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestIPDisabled, cls).tearDownClass()

    def setUp(self):
        super(TestIPDisabled, self).setUp()

        # create 2 pg interfaces
        self.create_pg_interfaces(range(2))

        # PG0 is IP enalbed
        self.pg0.admin_up()
        self.pg0.config_ip4()
        self.pg0.resolve_arp()

        # PG 1 is not IP enabled
        self.pg1.admin_up()

    def tearDown(self):
        super(TestIPDisabled, self).tearDown()
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.admin_down()

    def test_ip_disabled(self):
        """ IP Disabled """

        MRouteItfFlags = VppEnum.vl_api_mfib_itf_flags_t
        MRouteEntryFlags = VppEnum.vl_api_mfib_entry_flags_t

        #
        # An (S,G).
        # one accepting interface, pg0, 2 forwarding interfaces
        #
        route_232_1_1_1 = VppIpMRoute(
            self,
            "0.0.0.0",
            "232.1.1.1", 32,
            MRouteEntryFlags.MFIB_API_ENTRY_FLAG_NONE,
            [VppMRoutePath(self.pg1.sw_if_index,
                           MRouteItfFlags.MFIB_API_ITF_FLAG_ACCEPT),
             VppMRoutePath(self.pg0.sw_if_index,
                           MRouteItfFlags.MFIB_API_ITF_FLAG_FORWARD)])
        route_232_1_1_1.add_vpp_config()

        pu = (Ether(src=self.pg1.remote_mac,
                    dst=self.pg1.local_mac) /
              IP(src="10.10.10.10", dst=self.pg0.remote_ip4) /
              UDP(sport=1234, dport=1234) /
              Raw(b'\xa5' * 100))
        pm = (Ether(src=self.pg1.remote_mac,
                    dst=self.pg1.local_mac) /
              IP(src="10.10.10.10", dst="232.1.1.1") /
              UDP(sport=1234, dport=1234) /
              Raw(b'\xa5' * 100))

        #
        # PG1 does not forward IP traffic
        #
        self.send_and_assert_no_replies(self.pg1, pu, "IP disabled")
        self.send_and_assert_no_replies(self.pg1, pm, "IP disabled")

        #
        # IP enable PG1
        #
        self.pg1.config_ip4()

        #
        # Now we get packets through
        #
        self.pg1.add_stream(pu)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = self.pg0.get_capture(1)

        self.pg1.add_stream(pm)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = self.pg0.get_capture(1)

        #
        # Disable PG1
        #
        self.pg1.unconfig_ip4()

        #
        # PG1 does not forward IP traffic
        #
        self.send_and_assert_no_replies(self.pg1, pu, "IP disabled")
        self.send_and_assert_no_replies(self.pg1, pm, "IP disabled")


class TestIPSubNets(VppTestCase):
    """ IPv4 Subnets """

    @classmethod
    def setUpClass(cls):
        super(TestIPSubNets, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestIPSubNets, cls).tearDownClass()

    def setUp(self):
        super(TestIPSubNets, self).setUp()

        # create a 2 pg interfaces
        self.create_pg_interfaces(range(2))

        # pg0 we will use to experiment
        self.pg0.admin_up()

        # pg1 is setup normally
        self.pg1.admin_up()
        self.pg1.config_ip4()
        self.pg1.resolve_arp()

    def tearDown(self):
        super(TestIPSubNets, self).tearDown()
        for i in self.pg_interfaces:
            i.admin_down()

    def test_ip_sub_nets(self):
        """ IP Sub Nets """

        #
        # Configure a covering route to forward so we know
        # when we are dropping
        #
        cover_route = VppIpRoute(self, "10.0.0.0", 8,
                                 [VppRoutePath(self.pg1.remote_ip4,
                                               self.pg1.sw_if_index)])
        cover_route.add_vpp_config()

        p = (Ether(src=self.pg1.remote_mac,
                   dst=self.pg1.local_mac) /
             IP(dst="10.10.10.10", src=self.pg0.local_ip4) /
             UDP(sport=1234, dport=1234) /
             Raw(b'\xa5' * 100))

        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = self.pg1.get_capture(1)

        #
        # Configure some non-/24 subnets on an IP interface
        #
        ip_addr_n = socket.inet_pton(socket.AF_INET, "10.10.10.10")

        self.vapi.sw_interface_add_del_address(
            sw_if_index=self.pg0.sw_if_index,
            prefix="10.10.10.10/16")

        pn = (Ether(src=self.pg1.remote_mac,
                    dst=self.pg1.local_mac) /
              IP(dst="10.10.0.0", src=self.pg0.local_ip4) /
              UDP(sport=1234, dport=1234) /
              Raw(b'\xa5' * 100))
        pb = (Ether(src=self.pg1.remote_mac,
                    dst=self.pg1.local_mac) /
              IP(dst="10.10.255.255", src=self.pg0.local_ip4) /
              UDP(sport=1234, dport=1234) /
              Raw(b'\xa5' * 100))

        self.send_and_assert_no_replies(self.pg1, pn, "IP Network address")
        self.send_and_assert_no_replies(self.pg1, pb, "IP Broadcast address")

        # remove the sub-net and we are forwarding via the cover again
        self.vapi.sw_interface_add_del_address(
            sw_if_index=self.pg0.sw_if_index,
            prefix="10.10.10.10/16",
            is_add=0)

        self.pg1.add_stream(pn)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = self.pg1.get_capture(1)
        self.pg1.add_stream(pb)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = self.pg1.get_capture(1)

        #
        # A /31 is a special case where the 'other-side' is an attached host
        # packets to that peer generate ARP requests
        #
        ip_addr_n = socket.inet_pton(socket.AF_INET, "10.10.10.10")

        self.vapi.sw_interface_add_del_address(
            sw_if_index=self.pg0.sw_if_index,
            prefix="10.10.10.10/31")

        pn = (Ether(src=self.pg1.remote_mac,
                    dst=self.pg1.local_mac) /
              IP(dst="10.10.10.11", src=self.pg0.local_ip4) /
              UDP(sport=1234, dport=1234) /
              Raw(b'\xa5' * 100))

        self.pg1.add_stream(pn)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = self.pg0.get_capture(1)
        rx[ARP]

        # remove the sub-net and we are forwarding via the cover again
        self.vapi.sw_interface_add_del_address(
            sw_if_index=self.pg0.sw_if_index,
            prefix="10.10.10.10/31", is_add=0)

        self.pg1.add_stream(pn)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = self.pg1.get_capture(1)


class TestIPLoadBalance(VppTestCase):
    """ IPv4 Load-Balancing """

    @classmethod
    def setUpClass(cls):
        super(TestIPLoadBalance, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestIPLoadBalance, cls).tearDownClass()

    def setUp(self):
        super(TestIPLoadBalance, self).setUp()

        self.create_pg_interfaces(range(5))
        mpls_tbl = VppMplsTable(self, 0)
        mpls_tbl.add_vpp_config()

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()
            i.enable_mpls()

    def tearDown(self):
        for i in self.pg_interfaces:
            i.disable_mpls()
            i.unconfig_ip4()
            i.admin_down()
        super(TestIPLoadBalance, self).tearDown()

    def send_and_expect_load_balancing(self, input, pkts, outputs):
        self.vapi.cli("clear trace")
        input.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rxs = []
        for oo in outputs:
            rx = oo._get_capture(1)
            self.assertNotEqual(0, len(rx))
            rxs.append(rx)
        return rxs

    def send_and_expect_one_itf(self, input, pkts, itf):
        input.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = itf.get_capture(len(pkts))

    def total_len(self, rxs):
        n = 0
        for rx in rxs:
            n += len(rx)
        return n

    def test_ip_load_balance(self):
        """ IP Load-Balancing """

        fhc = VppEnum.vl_api_ip_flow_hash_config_t
        af = VppEnum.vl_api_address_family_t

        #
        # An array of packets that differ only in the destination port
        #
        port_ip_pkts = []
        port_mpls_pkts = []

        #
        # An array of packets that differ only in the source address
        #
        src_ip_pkts = []
        src_mpls_pkts = []

        for ii in range(NUM_PKTS):
            port_ip_hdr = (IP(dst="10.0.0.1", src="20.0.0.1") /
                           UDP(sport=1234, dport=1234 + ii) /
                           Raw(b'\xa5' * 100))
            port_ip_pkts.append((Ether(src=self.pg0.remote_mac,
                                       dst=self.pg0.local_mac) /
                                 port_ip_hdr))
            port_mpls_pkts.append((Ether(src=self.pg0.remote_mac,
                                         dst=self.pg0.local_mac) /
                                   MPLS(label=66, ttl=2) /
                                   port_ip_hdr))

            src_ip_hdr = (IP(dst="10.0.0.1", src="20.0.0.%d" % ii) /
                          UDP(sport=1234, dport=1234) /
                          Raw(b'\xa5' * 100))
            src_ip_pkts.append((Ether(src=self.pg0.remote_mac,
                                      dst=self.pg0.local_mac) /
                                src_ip_hdr))
            src_mpls_pkts.append((Ether(src=self.pg0.remote_mac,
                                        dst=self.pg0.local_mac) /
                                  MPLS(label=66, ttl=2) /
                                  src_ip_hdr))

        route_10_0_0_1 = VppIpRoute(self, "10.0.0.1", 32,
                                    [VppRoutePath(self.pg1.remote_ip4,
                                                  self.pg1.sw_if_index),
                                     VppRoutePath(self.pg2.remote_ip4,
                                                  self.pg2.sw_if_index)])
        route_10_0_0_1.add_vpp_config()

        binding = VppMplsIpBind(self, 66, "10.0.0.1", 32)
        binding.add_vpp_config()

        #
        # inject the packet on pg0 - expect load-balancing across the 2 paths
        #  - since the default hash config is to use IP src,dst and port
        #    src,dst
        # We are not going to ensure equal amounts of packets across each link,
        # since the hash algorithm is statistical and therefore this can never
        # be guaranteed. But with 64 different packets we do expect some
        # balancing. So instead just ensure there is traffic on each link.
        #
        rx = self.send_and_expect_load_balancing(self.pg0, port_ip_pkts,
                                                 [self.pg1, self.pg2])
        n_ip_pg0 = len(rx[0])
        self.send_and_expect_load_balancing(self.pg0, src_ip_pkts,
                                            [self.pg1, self.pg2])
        self.send_and_expect_load_balancing(self.pg0, port_mpls_pkts,
                                            [self.pg1, self.pg2])
        rx = self.send_and_expect_load_balancing(self.pg0, src_mpls_pkts,
                                                 [self.pg1, self.pg2])
        n_mpls_pg0 = len(rx[0])

        #
        # change the router ID and expect the distribution changes
        #
        self.vapi.set_ip_flow_hash_router_id(router_id=0x11111111)

        rx = self.send_and_expect_load_balancing(self.pg0, port_ip_pkts,
                                                 [self.pg1, self.pg2])
        self.assertNotEqual(n_ip_pg0, len(rx[0]))

        rx = self.send_and_expect_load_balancing(self.pg0, src_mpls_pkts,
                                                 [self.pg1, self.pg2])
        self.assertNotEqual(n_mpls_pg0, len(rx[0]))

        #
        # change the flow hash config so it's only IP src,dst
        #  - now only the stream with differing source address will
        #    load-balance
        #
        self.vapi.set_ip_flow_hash_v2(
            af=af.ADDRESS_IP4,
            table_id=0,
            flow_hash_config=(fhc.IP_API_FLOW_HASH_SRC_IP |
                              fhc.IP_API_FLOW_HASH_DST_IP |
                              fhc.IP_API_FLOW_HASH_PROTO))

        self.send_and_expect_load_balancing(self.pg0, src_ip_pkts,
                                            [self.pg1, self.pg2])
        self.send_and_expect_load_balancing(self.pg0, src_mpls_pkts,
                                            [self.pg1, self.pg2])

        self.send_and_expect_one_itf(self.pg0, port_ip_pkts, self.pg2)

        #
        # change the flow hash config back to defaults
        #
        self.vapi.set_ip_flow_hash(vrf_id=0, src=1, dst=1,
                                   proto=1, sport=1, dport=1)

        #
        # Recursive prefixes
        #  - testing that 2 stages of load-balancing occurs and there is no
        #    polarisation (i.e. only 2 of 4 paths are used)
        #
        port_pkts = []
        src_pkts = []

        for ii in range(257):
            port_pkts.append((Ether(src=self.pg0.remote_mac,
                                    dst=self.pg0.local_mac) /
                              IP(dst="1.1.1.1", src="20.0.0.1") /
                              UDP(sport=1234, dport=1234 + ii) /
                              Raw(b'\xa5' * 100)))
            src_pkts.append((Ether(src=self.pg0.remote_mac,
                                   dst=self.pg0.local_mac) /
                             IP(dst="1.1.1.1", src="20.0.0.%d" % ii) /
                             UDP(sport=1234, dport=1234) /
                             Raw(b'\xa5' * 100)))

        route_10_0_0_2 = VppIpRoute(self, "10.0.0.2", 32,
                                    [VppRoutePath(self.pg3.remote_ip4,
                                                  self.pg3.sw_if_index),
                                     VppRoutePath(self.pg4.remote_ip4,
                                                  self.pg4.sw_if_index)])
        route_10_0_0_2.add_vpp_config()

        route_1_1_1_1 = VppIpRoute(self, "1.1.1.1", 32,
                                   [VppRoutePath("10.0.0.2", 0xffffffff),
                                    VppRoutePath("10.0.0.1", 0xffffffff)])
        route_1_1_1_1.add_vpp_config()

        #
        # inject the packet on pg0 - expect load-balancing across all 4 paths
        #
        self.vapi.cli("clear trace")
        self.send_and_expect_load_balancing(self.pg0, port_pkts,
                                            [self.pg1, self.pg2,
                                             self.pg3, self.pg4])
        self.send_and_expect_load_balancing(self.pg0, src_pkts,
                                            [self.pg1, self.pg2,
                                             self.pg3, self.pg4])

        #
        # bring down pg1 expect LB to adjust to use only those that are up
        #
        self.pg1.link_down()

        rx = self.send_and_expect_load_balancing(self.pg0, src_pkts,
                                                 [self.pg2, self.pg3,
                                                  self.pg4])
        self.assertEqual(len(src_pkts), self.total_len(rx))

        #
        # bring down pg2 expect LB to adjust to use only those that are up
        #
        self.pg2.link_down()

        rx = self.send_and_expect_load_balancing(self.pg0, src_pkts,
                                                 [self.pg3, self.pg4])
        self.assertEqual(len(src_pkts), self.total_len(rx))

        #
        # bring the links back up - expect LB over all again
        #
        self.pg1.link_up()
        self.pg2.link_up()

        rx = self.send_and_expect_load_balancing(self.pg0, src_pkts,
                                                 [self.pg1, self.pg2,
                                                  self.pg3, self.pg4])
        self.assertEqual(len(src_pkts), self.total_len(rx))

        #
        # The same link-up/down but this time admin state
        #
        self.pg1.admin_down()
        self.pg2.admin_down()
        rx = self.send_and_expect_load_balancing(self.pg0, src_pkts,
                                                 [self.pg3, self.pg4])
        self.assertEqual(len(src_pkts), self.total_len(rx))
        self.pg1.admin_up()
        self.pg2.admin_up()
        self.pg1.resolve_arp()
        self.pg2.resolve_arp()
        rx = self.send_and_expect_load_balancing(self.pg0, src_pkts,
                                                 [self.pg1, self.pg2,
                                                  self.pg3, self.pg4])
        self.assertEqual(len(src_pkts), self.total_len(rx))

        #
        # Recursive prefixes
        #  - testing that 2 stages of load-balancing, no choices
        #
        port_pkts = []

        for ii in range(257):
            port_pkts.append((Ether(src=self.pg0.remote_mac,
                                    dst=self.pg0.local_mac) /
                              IP(dst="1.1.1.2", src="20.0.0.2") /
                              UDP(sport=1234, dport=1234 + ii) /
                              Raw(b'\xa5' * 100)))

        route_10_0_0_3 = VppIpRoute(self, "10.0.0.3", 32,
                                    [VppRoutePath(self.pg3.remote_ip4,
                                                  self.pg3.sw_if_index)])
        route_10_0_0_3.add_vpp_config()

        route_1_1_1_2 = VppIpRoute(self, "1.1.1.2", 32,
                                   [VppRoutePath("10.0.0.3", 0xffffffff)])
        route_1_1_1_2.add_vpp_config()

        #
        # inject the packet on pg0 - rx only on via routes output interface
        #
        self.vapi.cli("clear trace")
        self.send_and_expect_one_itf(self.pg0, port_pkts, self.pg3)

        #
        # Add a LB route in the presence of a down link - expect no
        # packets over the down link
        #
        self.pg3.link_down()

        route_10_0_0_3 = VppIpRoute(self, "10.0.0.3", 32,
                                    [VppRoutePath(self.pg3.remote_ip4,
                                                  self.pg3.sw_if_index),
                                     VppRoutePath(self.pg4.remote_ip4,
                                                  self.pg4.sw_if_index)])
        route_10_0_0_3.add_vpp_config()

        port_pkts = []
        for ii in range(257):
            port_pkts.append(Ether(src=self.pg0.remote_mac,
                                   dst=self.pg0.local_mac) /
                             IP(dst="10.0.0.3", src="20.0.0.2") /
                             UDP(sport=1234, dport=1234 + ii) /
                             Raw(b'\xa5' * 100))

        self.send_and_expect_one_itf(self.pg0, port_pkts, self.pg4)

        # bring the link back up
        self.pg3.link_up()

        rx = self.send_and_expect_load_balancing(self.pg0, port_pkts,
                                                 [self.pg3, self.pg4])
        self.assertEqual(len(src_pkts), self.total_len(rx))


class TestIPVlan0(VppTestCase):
    """ IPv4 VLAN-0 """

    @classmethod
    def setUpClass(cls):
        super(TestIPVlan0, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestIPVlan0, cls).tearDownClass()

    def setUp(self):
        super(TestIPVlan0, self).setUp()

        self.create_pg_interfaces(range(2))
        mpls_tbl = VppMplsTable(self, 0)
        mpls_tbl.add_vpp_config()

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()
            i.enable_mpls()

    def tearDown(self):
        for i in self.pg_interfaces:
            i.disable_mpls()
            i.unconfig_ip4()
            i.admin_down()
        super(TestIPVlan0, self).tearDown()

    def test_ip_vlan_0(self):
        """ IP VLAN-0 """

        pkts = (Ether(src=self.pg0.remote_mac,
                      dst=self.pg0.local_mac) /
                Dot1Q(vlan=0) /
                IP(dst=self.pg1.remote_ip4,
                   src=self.pg0.remote_ip4) /
                UDP(sport=1234, dport=1234) /
                Raw(b'\xa5' * 100)) * NUM_PKTS

        #
        # Expect that packets sent on VLAN-0 are forwarded on the
        # main interface.
        #
        self.send_and_expect(self.pg0, pkts, self.pg1)


class IPPuntSetup(object):
    """ Setup for IPv4 Punt Police/Redirect """

    def punt_setup(self):
        self.create_pg_interfaces(range(4))

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

        # use UDP packet that have a port we need to explicitly
        # register to get punted.
        pt_l4 = VppEnum.vl_api_punt_type_t.PUNT_API_TYPE_L4
        af_ip4 = VppEnum.vl_api_address_family_t.ADDRESS_IP4
        udp_proto = VppEnum.vl_api_ip_proto_t.IP_API_PROTO_UDP
        punt_udp = {
            'type': pt_l4,
            'punt': {
                'l4': {
                    'af': af_ip4,
                    'protocol': udp_proto,
                    'port': 1234,
                }
            }
        }

        self.vapi.set_punt(is_add=1, punt=punt_udp)

        self.pkt = (Ether(src=self.pg0.remote_mac,
                          dst=self.pg0.local_mac) /
                    IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) /
                    UDP(sport=1234, dport=1234) /
                    Raw(b'\xa5' * 100))

    def punt_teardown(self):
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.admin_down()


class TestIPPunt(IPPuntSetup, VppTestCase):
    """ IPv4 Punt Police/Redirect """

    def setUp(self):
        super(TestIPPunt, self).setUp()
        super(TestIPPunt, self).punt_setup()

    def tearDown(self):
        super(TestIPPunt, self).punt_teardown()
        super(TestIPPunt, self).tearDown()

    def test_ip_punt(self):
        """ IP punt police and redirect """

        pkts = self.pkt * 1025

        #
        # Configure a punt redirect via pg1.
        #
        nh_addr = self.pg1.remote_ip4
        ip_punt_redirect = VppIpPuntRedirect(self, self.pg0.sw_if_index,
                                             self.pg1.sw_if_index, nh_addr)
        ip_punt_redirect.add_vpp_config()

        self.send_and_expect(self.pg0, pkts, self.pg1)

        #
        # add a policer
        #
        policer = VppPolicer(self, "ip4-punt", 400, 0, 10, 0, rate_type=1)
        policer.add_vpp_config()
        ip_punt_policer = VppIpPuntPolicer(self, policer.policer_index)
        ip_punt_policer.add_vpp_config()

        self.vapi.cli("clear trace")
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        #
        # the number of packet received should be greater than 0,
        # but not equal to the number sent, since some were policed
        #
        rx = self.pg1._get_capture(1)

        stats = policer.get_stats()

        # Single rate policer - expect conform, violate but no exceed
        self.assertGreater(stats['conform_packets'], 0)
        self.assertEqual(stats['exceed_packets'], 0)
        self.assertGreater(stats['violate_packets'], 0)

        self.assertGreater(len(rx), 0)
        self.assertLess(len(rx), len(pkts))

        #
        # remove the policer. back to full rx
        #
        ip_punt_policer.remove_vpp_config()
        policer.remove_vpp_config()
        self.send_and_expect(self.pg0, pkts, self.pg1)

        #
        # remove the redirect. expect full drop.
        #
        ip_punt_redirect.remove_vpp_config()
        self.send_and_assert_no_replies(self.pg0, pkts,
                                        "IP no punt config")

        #
        # Add a redirect that is not input port selective
        #
        ip_punt_redirect = VppIpPuntRedirect(self, 0xffffffff,
                                             self.pg1.sw_if_index, nh_addr)
        ip_punt_redirect.add_vpp_config()
        self.send_and_expect(self.pg0, pkts, self.pg1)
        ip_punt_redirect.remove_vpp_config()

    def test_ip_punt_dump(self):
        """ IP4 punt redirect dump"""

        #
        # Configure a punt redirects
        #
        nh_address = self.pg3.remote_ip4
        ipr_03 = VppIpPuntRedirect(self, self.pg0.sw_if_index,
                                   self.pg3.sw_if_index, nh_address)
        ipr_13 = VppIpPuntRedirect(self, self.pg1.sw_if_index,
                                   self.pg3.sw_if_index, nh_address)
        ipr_23 = VppIpPuntRedirect(self, self.pg2.sw_if_index,
                                   self.pg3.sw_if_index, "0.0.0.0")
        ipr_03.add_vpp_config()
        ipr_13.add_vpp_config()
        ipr_23.add_vpp_config()

        #
        # Dump pg0 punt redirects
        #
        self.assertTrue(ipr_03.query_vpp_config())
        self.assertTrue(ipr_13.query_vpp_config())
        self.assertTrue(ipr_23.query_vpp_config())

        #
        # Dump punt redirects for all interfaces
        #
        punts = self.vapi.ip_punt_redirect_dump(0xffffffff)
        self.assertEqual(len(punts), 3)
        for p in punts:
            self.assertEqual(p.punt.tx_sw_if_index, self.pg3.sw_if_index)
        self.assertNotEqual(punts[1].punt.nh, self.pg3.remote_ip4)
        self.assertEqual(str(punts[2].punt.nh), '0.0.0.0')


class TestIPPuntHandoff(IPPuntSetup, VppTestCase):
    """ IPv4 Punt Policer thread handoff """
    worker_config = "workers 2"

    def setUp(self):
        super(TestIPPuntHandoff, self).setUp()
        super(TestIPPuntHandoff, self).punt_setup()

    def tearDown(self):
        super(TestIPPuntHandoff, self).punt_teardown()
        super(TestIPPuntHandoff, self).tearDown()

    def test_ip_punt_policer_handoff(self):
        """ IP4 punt policer thread handoff """
        pkts = self.pkt * NUM_PKTS

        #
        # Configure a punt redirect via pg1.
        #
        nh_addr = self.pg1.remote_ip4
        ip_punt_redirect = VppIpPuntRedirect(self, self.pg0.sw_if_index,
                                             self.pg1.sw_if_index, nh_addr)
        ip_punt_redirect.add_vpp_config()

        action_tx = PolicerAction(
            VppEnum.vl_api_sse2_qos_action_type_t.SSE2_QOS_ACTION_API_TRANSMIT,
            0)
        #
        # This policer drops no packets, we are just
        # testing that they get to the right thread.
        #
        policer = VppPolicer(self, "ip4-punt", 400, 0, 10, 0, 1,
                             0, 0, False, action_tx, action_tx, action_tx)
        policer.add_vpp_config()
        ip_punt_policer = VppIpPuntPolicer(self, policer.policer_index)
        ip_punt_policer.add_vpp_config()

        for worker in [0, 1]:
            self.send_and_expect(self.pg0, pkts, self.pg1, worker=worker)
            self.logger.debug(self.vapi.cli("show trace max 100"))

        # Combined stats, all threads
        stats = policer.get_stats()

        # Single rate policer - expect conform, violate but no exceed
        self.assertGreater(stats['conform_packets'], 0)
        self.assertEqual(stats['exceed_packets'], 0)
        self.assertGreater(stats['violate_packets'], 0)

        # Worker 0, should have done all the policing
        stats0 = policer.get_stats(worker=0)
        self.assertEqual(stats, stats0)

        # Worker 1, should have handed everything off
        stats1 = policer.get_stats(worker=1)
        self.assertEqual(stats1['conform_packets'], 0)
        self.assertEqual(stats1['exceed_packets'], 0)
        self.assertEqual(stats1['violate_packets'], 0)

        # Bind the policer to worker 1 and repeat
        policer.bind_vpp_config(1, True)
        for worker in [0, 1]:
            self.send_and_expect(self.pg0, pkts, self.pg1, worker=worker)
            self.logger.debug(self.vapi.cli("show trace max 100"))

        # The 2 workers should now have policed the same amount
        stats = policer.get_stats()
        stats0 = policer.get_stats(worker=0)
        stats1 = policer.get_stats(worker=1)

        self.assertGreater(stats0['conform_packets'], 0)
        self.assertEqual(stats0['exceed_packets'], 0)
        self.assertGreater(stats0['violate_packets'], 0)

        self.assertGreater(stats1['conform_packets'], 0)
        self.assertEqual(stats1['exceed_packets'], 0)
        self.assertGreater(stats1['violate_packets'], 0)

        self.assertEqual(stats0['conform_packets'] + stats1['conform_packets'],
                         stats['conform_packets'])

        self.assertEqual(stats0['violate_packets'] + stats1['violate_packets'],
                         stats['violate_packets'])

        # Unbind the policer and repeat
        policer.bind_vpp_config(1, False)
        for worker in [0, 1]:
            self.send_and_expect(self.pg0, pkts, self.pg1, worker=worker)
            self.logger.debug(self.vapi.cli("show trace max 100"))

        # The policer should auto-bind to worker 0 when packets arrive
        stats = policer.get_stats()
        stats0new = policer.get_stats(worker=0)
        stats1new = policer.get_stats(worker=1)

        self.assertGreater(stats0new['conform_packets'],
                           stats0['conform_packets'])
        self.assertEqual(stats0new['exceed_packets'], 0)
        self.assertGreater(stats0new['violate_packets'],
                           stats0['violate_packets'])

        self.assertEqual(stats1, stats1new)

        #
        # Clean up
        #
        ip_punt_policer.remove_vpp_config()
        policer.remove_vpp_config()
        ip_punt_redirect.remove_vpp_config()


class TestIPDeag(VppTestCase):
    """ IPv4 Deaggregate Routes """

    @classmethod
    def setUpClass(cls):
        super(TestIPDeag, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestIPDeag, cls).tearDownClass()

    def setUp(self):
        super(TestIPDeag, self).setUp()

        self.create_pg_interfaces(range(3))

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    def tearDown(self):
        super(TestIPDeag, self).tearDown()
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.admin_down()

    def test_ip_deag(self):
        """ IP Deag Routes """

        #
        # Create a table to be used for:
        #  1 - another destination address lookup
        #  2 - a source address lookup
        #
        table_dst = VppIpTable(self, 1)
        table_src = VppIpTable(self, 2)
        table_dst.add_vpp_config()
        table_src.add_vpp_config()

        #
        # Add a route in the default table to point to a deag/
        # second lookup in each of these tables
        #
        route_to_dst = VppIpRoute(self, "1.1.1.1", 32,
                                  [VppRoutePath("0.0.0.0",
                                                0xffffffff,
                                                nh_table_id=1)])
        route_to_src = VppIpRoute(
            self, "1.1.1.2", 32,
            [VppRoutePath("0.0.0.0",
                          0xffffffff,
                          nh_table_id=2,
                          type=FibPathType.FIB_PATH_TYPE_SOURCE_LOOKUP)])
        route_to_dst.add_vpp_config()
        route_to_src.add_vpp_config()

        #
        # packets to these destination are dropped, since they'll
        # hit the respective default routes in the second table
        #
        p_dst = (Ether(src=self.pg0.remote_mac,
                       dst=self.pg0.local_mac) /
                 IP(src="5.5.5.5", dst="1.1.1.1") /
                 TCP(sport=1234, dport=1234) /
                 Raw(b'\xa5' * 100))
        p_src = (Ether(src=self.pg0.remote_mac,
                       dst=self.pg0.local_mac) /
                 IP(src="2.2.2.2", dst="1.1.1.2") /
                 TCP(sport=1234, dport=1234) /
                 Raw(b'\xa5' * 100))
        pkts_dst = p_dst * 257
        pkts_src = p_src * 257

        self.send_and_assert_no_replies(self.pg0, pkts_dst,
                                        "IP in dst table")
        self.send_and_assert_no_replies(self.pg0, pkts_src,
                                        "IP in src table")

        #
        # add a route in the dst table to forward via pg1
        #
        route_in_dst = VppIpRoute(self, "1.1.1.1", 32,
                                  [VppRoutePath(self.pg1.remote_ip4,
                                                self.pg1.sw_if_index)],
                                  table_id=1)
        route_in_dst.add_vpp_config()

        self.send_and_expect(self.pg0, pkts_dst, self.pg1)

        #
        # add a route in the src table to forward via pg2
        #
        route_in_src = VppIpRoute(self, "2.2.2.2", 32,
                                  [VppRoutePath(self.pg2.remote_ip4,
                                                self.pg2.sw_if_index)],
                                  table_id=2)
        route_in_src.add_vpp_config()
        self.send_and_expect(self.pg0, pkts_src, self.pg2)

        #
        # loop in the lookup DP
        #
        route_loop = VppIpRoute(self, "2.2.2.3", 32,
                                [VppRoutePath("0.0.0.0",
                                              0xffffffff,
                                              nh_table_id=0)])
        route_loop.add_vpp_config()

        p_l = (Ether(src=self.pg0.remote_mac,
                     dst=self.pg0.local_mac) /
               IP(src="2.2.2.4", dst="2.2.2.3") /
               TCP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 100))

        self.send_and_assert_no_replies(self.pg0, p_l * 257,
                                        "IP lookup loop")


class TestIPInput(VppTestCase):
    """ IPv4 Input Exceptions """

    @classmethod
    def setUpClass(cls):
        super(TestIPInput, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestIPInput, cls).tearDownClass()

    def setUp(self):
        super(TestIPInput, self).setUp()

        self.create_pg_interfaces(range(2))

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    def tearDown(self):
        super(TestIPInput, self).tearDown()
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.admin_down()

    def test_ip_input(self):
        """ IP Input Exceptions """

        # i can't find a way in scapy to construct an IP packet
        # with a length less than the IP header length

        #
        # Packet too short - this is forwarded
        #
        p_short = (Ether(src=self.pg0.remote_mac,
                         dst=self.pg0.local_mac) /
                   IP(src=self.pg0.remote_ip4,
                      dst=self.pg1.remote_ip4,
                      len=40) /
                   UDP(sport=1234, dport=1234) /
                   Raw(b'\xa5' * 100))

        rx = self.send_and_expect(self.pg0, p_short * NUM_PKTS, self.pg1)

        #
        # Packet too long - this is dropped
        #
        p_long = (Ether(src=self.pg0.remote_mac,
                        dst=self.pg0.local_mac) /
                  IP(src=self.pg0.remote_ip4,
                     dst=self.pg1.remote_ip4,
                     len=400) /
                  UDP(sport=1234, dport=1234) /
                  Raw(b'\xa5' * 100))

        rx = self.send_and_assert_no_replies(self.pg0, p_long * NUM_PKTS,
                                             "too long")

        #
        # bad chksum - this is dropped
        #
        p_chksum = (Ether(src=self.pg0.remote_mac,
                          dst=self.pg0.local_mac) /
                    IP(src=self.pg0.remote_ip4,
                       dst=self.pg1.remote_ip4,
                       chksum=400) /
                    UDP(sport=1234, dport=1234) /
                    Raw(b'\xa5' * 100))

        rx = self.send_and_assert_no_replies(self.pg0, p_chksum * NUM_PKTS,
                                             "bad checksum")

        #
        # bad version - this is dropped
        #
        p_ver = (Ether(src=self.pg0.remote_mac,
                       dst=self.pg0.local_mac) /
                 IP(src=self.pg0.remote_ip4,
                    dst=self.pg1.remote_ip4,
                    version=3) /
                 UDP(sport=1234, dport=1234) /
                 Raw(b'\xa5' * 100))

        rx = self.send_and_assert_no_replies(self.pg0, p_ver * NUM_PKTS,
                                             "funky version")

        #
        # fragment offset 1 - this is dropped
        #
        p_frag = (Ether(src=self.pg0.remote_mac,
                        dst=self.pg0.local_mac) /
                  IP(src=self.pg0.remote_ip4,
                     dst=self.pg1.remote_ip4,
                     frag=1) /
                  UDP(sport=1234, dport=1234) /
                  Raw(b'\xa5' * 100))

        rx = self.send_and_assert_no_replies(self.pg0, p_frag * NUM_PKTS,
                                             "frag offset")

        #
        # TTL expired packet
        #
        p_ttl = (Ether(src=self.pg0.remote_mac,
                       dst=self.pg0.local_mac) /
                 IP(src=self.pg0.remote_ip4,
                    dst=self.pg1.remote_ip4,
                    ttl=1) /
                 UDP(sport=1234, dport=1234) /
                 Raw(b'\xa5' * 100))

        rx = self.send_and_expect(self.pg0, p_ttl * NUM_PKTS, self.pg0)

        rx = rx[0]
        icmp = rx[ICMP]

        self.assertEqual(icmptypes[icmp.type], "time-exceeded")
        self.assertEqual(icmpcodes[icmp.type][icmp.code],
                         "ttl-zero-during-transit")
        self.assertEqual(icmp.src, self.pg0.remote_ip4)
        self.assertEqual(icmp.dst, self.pg1.remote_ip4)

        #
        # MTU exceeded
        #
        p_mtu = (Ether(src=self.pg0.remote_mac,
                       dst=self.pg0.local_mac) /
                 IP(src=self.pg0.remote_ip4,
                    dst=self.pg1.remote_ip4,
                    ttl=10, flags='DF') /
                 UDP(sport=1234, dport=1234) /
                 Raw(b'\xa5' * 2000))

        self.vapi.sw_interface_set_mtu(self.pg1.sw_if_index, [1500, 0, 0, 0])

        rx = self.send_and_expect(self.pg0, p_mtu * NUM_PKTS, self.pg0)
        rx = rx[0]
        icmp = rx[ICMP]

        self.assertEqual(icmptypes[icmp.type], "dest-unreach")
        self.assertEqual(icmpcodes[icmp.type][icmp.code],
                         "fragmentation-needed")
        self.assertEqual(icmp.src, self.pg0.remote_ip4)
        self.assertEqual(icmp.dst, self.pg1.remote_ip4)

        self.vapi.sw_interface_set_mtu(self.pg1.sw_if_index, [2500, 0, 0, 0])
        rx = self.send_and_expect(self.pg0, p_mtu * NUM_PKTS, self.pg1)

        # Reset MTU for subsequent tests
        self.vapi.sw_interface_set_mtu(self.pg1.sw_if_index, [9000, 0, 0, 0])

        #
        # source address 0.0.0.0 and 25.255.255.255 and for-us
        #
        p_s0 = (Ether(src=self.pg0.remote_mac,
                      dst=self.pg0.local_mac) /
                IP(src="0.0.0.0",
                   dst=self.pg0.local_ip4) /
                ICMP(id=4, seq=4) /
                Raw(load=b'\x0a' * 18))
        rx = self.send_and_assert_no_replies(self.pg0, p_s0 * 17)

        p_s0 = (Ether(src=self.pg0.remote_mac,
                      dst=self.pg0.local_mac) /
                IP(src="255.255.255.255",
                   dst=self.pg0.local_ip4) /
                ICMP(id=4, seq=4) /
                Raw(load=b'\x0a' * 18))
        rx = self.send_and_assert_no_replies(self.pg0, p_s0 * 17)


class TestIPDirectedBroadcast(VppTestCase):
    """ IPv4 Directed Broadcast """

    @classmethod
    def setUpClass(cls):
        super(TestIPDirectedBroadcast, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestIPDirectedBroadcast, cls).tearDownClass()

    def setUp(self):
        super(TestIPDirectedBroadcast, self).setUp()

        self.create_pg_interfaces(range(2))

        for i in self.pg_interfaces:
            i.admin_up()

    def tearDown(self):
        super(TestIPDirectedBroadcast, self).tearDown()
        for i in self.pg_interfaces:
            i.admin_down()

    def test_ip_input(self):
        """ IP Directed Broadcast """

        #
        # set the directed broadcast on pg0 first, then config IP4 addresses
        # for pg1 directed broadcast is always disabled
        self.vapi.sw_interface_set_ip_directed_broadcast(
            self.pg0.sw_if_index, 1)

        p0 = (Ether(src=self.pg1.remote_mac,
                    dst=self.pg1.local_mac) /
              IP(src="1.1.1.1",
                 dst=self.pg0._local_ip4_bcast) /
              UDP(sport=1234, dport=1234) /
              Raw(b'\xa5' * 2000))
        p1 = (Ether(src=self.pg0.remote_mac,
                    dst=self.pg0.local_mac) /
              IP(src="1.1.1.1",
                 dst=self.pg1._local_ip4_bcast) /
              UDP(sport=1234, dport=1234) /
              Raw(b'\xa5' * 2000))

        self.pg0.config_ip4()
        self.pg0.resolve_arp()
        self.pg1.config_ip4()
        self.pg1.resolve_arp()

        #
        # test packet is L2 broadcast
        #
        rx = self.send_and_expect(self.pg1, p0 * NUM_PKTS, self.pg0)
        self.assertTrue(rx[0][Ether].dst, "ff:ff:ff:ff:ff:ff")

        self.send_and_assert_no_replies(self.pg0, p1 * NUM_PKTS,
                                        "directed broadcast disabled")

        #
        # toggle directed broadcast on pg0
        #
        self.vapi.sw_interface_set_ip_directed_broadcast(
            self.pg0.sw_if_index, 0)
        self.send_and_assert_no_replies(self.pg1, p0 * NUM_PKTS,
                                        "directed broadcast disabled")

        self.vapi.sw_interface_set_ip_directed_broadcast(
            self.pg0.sw_if_index, 1)
        rx = self.send_and_expect(self.pg1, p0 * NUM_PKTS, self.pg0)

        self.pg0.unconfig_ip4()
        self.pg1.unconfig_ip4()


class TestIPLPM(VppTestCase):
    """ IPv4 longest Prefix Match """

    @classmethod
    def setUpClass(cls):
        super(TestIPLPM, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestIPLPM, cls).tearDownClass()

    def setUp(self):
        super(TestIPLPM, self).setUp()

        self.create_pg_interfaces(range(4))

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    def tearDown(self):
        super(TestIPLPM, self).tearDown()
        for i in self.pg_interfaces:
            i.admin_down()
            i.unconfig_ip4()

    def test_ip_lpm(self):
        """ IP longest Prefix Match """

        s_24 = VppIpRoute(self, "10.1.2.0", 24,
                          [VppRoutePath(self.pg1.remote_ip4,
                                        self.pg1.sw_if_index)])
        s_24.add_vpp_config()
        s_8 = VppIpRoute(self, "10.0.0.0", 8,
                         [VppRoutePath(self.pg2.remote_ip4,
                                       self.pg2.sw_if_index)])
        s_8.add_vpp_config()

        p_8 = (Ether(src=self.pg0.remote_mac,
                     dst=self.pg0.local_mac) /
               IP(src="1.1.1.1",
                  dst="10.1.1.1") /
               UDP(sport=1234, dport=1234) /
               Raw(b'\xa5' * 2000))
        p_24 = (Ether(src=self.pg0.remote_mac,
                      dst=self.pg0.local_mac) /
                IP(src="1.1.1.1",
                   dst="10.1.2.1") /
                UDP(sport=1234, dport=1234) /
                Raw(b'\xa5' * 2000))

        self.logger.info(self.vapi.cli("sh ip fib mtrie"))
        rx = self.send_and_expect(self.pg0, p_8 * NUM_PKTS, self.pg2)
        rx = self.send_and_expect(self.pg0, p_24 * NUM_PKTS, self.pg1)


@tag_fixme_vpp_workers
class TestIPv4Frag(VppTestCase):
    """ IPv4 fragmentation """

    @classmethod
    def setUpClass(cls):
        super(TestIPv4Frag, cls).setUpClass()

        cls.create_pg_interfaces([0, 1])
        cls.src_if = cls.pg0
        cls.dst_if = cls.pg1

        # setup all interfaces
        for i in cls.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    @classmethod
    def tearDownClass(cls):
        super(TestIPv4Frag, cls).tearDownClass()

    def test_frag_large_packets(self):
        """ Fragmentation of large packets """

        self.vapi.cli("adjacency counters enable")

        p = (Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac) /
             IP(src=self.src_if.remote_ip4, dst=self.dst_if.remote_ip4) /
             UDP(sport=1234, dport=5678) / Raw())
        self.extend_packet(p, 6000, "abcde")
        saved_payload = p[Raw].load

        nbr = VppNeighbor(self,
                          self.dst_if.sw_if_index,
                          self.dst_if.remote_mac,
                          self.dst_if.remote_ip4).add_vpp_config()

        # Force fragmentation by setting MTU of output interface
        # lower than packet size
        self.vapi.sw_interface_set_mtu(self.dst_if.sw_if_index,
                                       [5000, 0, 0, 0])

        self.pg_enable_capture()
        self.src_if.add_stream(p)
        self.pg_start()

        # Expecting 3 fragments because size of created fragments currently
        # cannot be larger then VPP buffer size (which is 2048)
        packets = self.dst_if.get_capture(3)

        # we should show 3 packets thru the neighbor
        self.assertEqual(3, nbr.get_stats()['packets'])

        # Assume VPP sends the fragments in order
        payload = b''
        for p in packets:
            payload_offset = p.frag * 8
            if payload_offset > 0:
                payload_offset -= 8  # UDP header is not in payload
            self.assert_equal(payload_offset, len(payload))
            payload += p[Raw].load
        self.assert_equal(payload, saved_payload, "payload")


class TestIPReplace(VppTestCase):
    """ IPv4 Table Replace """

    @classmethod
    def setUpClass(cls):
        super(TestIPReplace, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestIPReplace, cls).tearDownClass()

    def setUp(self):
        super(TestIPReplace, self).setUp()

        self.create_pg_interfaces(range(4))

        table_id = 1
        self.tables = []

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()
            i.generate_remote_hosts(2)
            self.tables.append(VppIpTable(self, table_id).add_vpp_config())
            table_id += 1

    def tearDown(self):
        super(TestIPReplace, self).tearDown()
        for i in self.pg_interfaces:
            i.admin_down()
            i.unconfig_ip4()

    def test_replace(self):
        """ IP Table Replace """

        MRouteItfFlags = VppEnum.vl_api_mfib_itf_flags_t
        MRouteEntryFlags = VppEnum.vl_api_mfib_entry_flags_t
        N_ROUTES = 20
        links = [self.pg0, self.pg1, self.pg2, self.pg3]
        routes = [[], [], [], []]

        # load up the tables with some routes
        for ii, t in enumerate(self.tables):
            for jj in range(N_ROUTES):
                uni = VppIpRoute(
                    self, "10.0.0.%d" % jj, 32,
                    [VppRoutePath(links[ii].remote_hosts[0].ip4,
                                  links[ii].sw_if_index),
                     VppRoutePath(links[ii].remote_hosts[1].ip4,
                                  links[ii].sw_if_index)],
                    table_id=t.table_id).add_vpp_config()
                multi = VppIpMRoute(
                    self, "0.0.0.0",
                    "239.0.0.%d" % jj, 32,
                    MRouteEntryFlags.MFIB_API_ENTRY_FLAG_NONE,
                    [VppMRoutePath(self.pg0.sw_if_index,
                                   MRouteItfFlags.MFIB_API_ITF_FLAG_ACCEPT),
                     VppMRoutePath(self.pg1.sw_if_index,
                                   MRouteItfFlags.MFIB_API_ITF_FLAG_FORWARD),
                     VppMRoutePath(self.pg2.sw_if_index,
                                   MRouteItfFlags.MFIB_API_ITF_FLAG_FORWARD),
                     VppMRoutePath(self.pg3.sw_if_index,
                                   MRouteItfFlags.MFIB_API_ITF_FLAG_FORWARD)],
                    table_id=t.table_id).add_vpp_config()
                routes[ii].append({'uni': uni,
                                   'multi': multi})

        #
        # replace the tables a few times
        #
        for kk in range(3):
            # replace_begin each table
            for t in self.tables:
                t.replace_begin()

            # all the routes are still there
            for ii, t in enumerate(self.tables):
                dump = t.dump()
                mdump = t.mdump()
                for r in routes[ii]:
                    self.assertTrue(find_route_in_dump(dump, r['uni'], t))
                    self.assertTrue(find_mroute_in_dump(mdump, r['multi'], t))

            # redownload the even numbered routes
            for ii, t in enumerate(self.tables):
                for jj in range(0, N_ROUTES, 2):
                    routes[ii][jj]['uni'].add_vpp_config()
                    routes[ii][jj]['multi'].add_vpp_config()

            # signal each table replace_end
            for t in self.tables:
                t.replace_end()

            # we should find the even routes, but not the odd
            for ii, t in enumerate(self.tables):
                dump = t.dump()
                mdump = t.mdump()
                for jj in range(0, N_ROUTES, 2):
                    self.assertTrue(find_route_in_dump(
                        dump, routes[ii][jj]['uni'], t))
                    self.assertTrue(find_mroute_in_dump(
                        mdump, routes[ii][jj]['multi'], t))
                for jj in range(1, N_ROUTES - 1, 2):
                    self.assertFalse(find_route_in_dump(
                        dump, routes[ii][jj]['uni'], t))
                    self.assertFalse(find_mroute_in_dump(
                        mdump, routes[ii][jj]['multi'], t))

            # reload all the routes
            for ii, t in enumerate(self.tables):
                for r in routes[ii]:
                    r['uni'].add_vpp_config()
                    r['multi'].add_vpp_config()

            # all the routes are still there
            for ii, t in enumerate(self.tables):
                dump = t.dump()
                mdump = t.mdump()
                for r in routes[ii]:
                    self.assertTrue(find_route_in_dump(dump, r['uni'], t))
                    self.assertTrue(find_mroute_in_dump(mdump, r['multi'], t))

        #
        # finally flush the tables for good measure
        #
        for t in self.tables:
            t.flush()
            self.assertEqual(len(t.dump()), 5)
            self.assertEqual(len(t.mdump()), 3)


class TestIPCover(VppTestCase):
    """ IPv4 Table Cover """

    @classmethod
    def setUpClass(cls):
        super(TestIPCover, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestIPCover, cls).tearDownClass()

    def setUp(self):
        super(TestIPCover, self).setUp()

        self.create_pg_interfaces(range(4))

        table_id = 1
        self.tables = []

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()
            i.generate_remote_hosts(2)
            self.tables.append(VppIpTable(self, table_id).add_vpp_config())
            table_id += 1

    def tearDown(self):
        super(TestIPCover, self).tearDown()
        for i in self.pg_interfaces:
            i.admin_down()
            i.unconfig_ip4()

    def test_cover(self):
        """ IP Table Cover """

        # add a loop back with a /32 prefix
        lo = VppLoInterface(self)
        lo.admin_up()
        a = VppIpInterfaceAddress(self, lo, "127.0.0.1", 32).add_vpp_config()

        # add a neighbour that matches the loopback's /32
        nbr = VppNeighbor(self,
                          lo.sw_if_index,
                          lo.remote_mac,
                          "127.0.0.1").add_vpp_config()

        # add the default route which will be the cover for /32
        r = VppIpRoute(self, "0.0.0.0", 0,
                       [VppRoutePath("127.0.0.1",
                                     lo.sw_if_index)],
                       register=False).add_vpp_config()

        # add/remove/add a longer mask cover
        r8 = VppIpRoute(self, "127.0.0.0", 8,
                        [VppRoutePath("127.0.0.1",
                                      lo.sw_if_index)]).add_vpp_config()
        r8.remove_vpp_config()
        r8.add_vpp_config()
        r8.remove_vpp_config()

        # remove the default route
        r.remove_vpp_config()

        # remove the interface prefix
        a.remove_vpp_config()


class TestIP4Replace(VppTestCase):
    """ IPv4 Interface Address Replace """

    @classmethod
    def setUpClass(cls):
        super(TestIP4Replace, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestIP4Replace, cls).tearDownClass()

    def setUp(self):
        super(TestIP4Replace, self).setUp()

        self.create_pg_interfaces(range(4))

        for i in self.pg_interfaces:
            i.admin_up()

    def tearDown(self):
        super(TestIP4Replace, self).tearDown()
        for i in self.pg_interfaces:
            i.admin_down()

    def get_n_pfxs(self, intf):
        return len(self.vapi.ip_address_dump(intf.sw_if_index))

    def test_replace(self):
        """ IP interface address replace """

        intf_pfxs = [[], [], [], []]

        # add prefixes to each of the interfaces
        for i in range(len(self.pg_interfaces)):
            intf = self.pg_interfaces[i]

            # 172.16.x.1/24
            addr = "172.16.%d.1" % intf.sw_if_index
            a = VppIpInterfaceAddress(self, intf, addr, 24).add_vpp_config()
            intf_pfxs[i].append(a)

            # 172.16.x.2/24 - a different address in the same subnet as above
            addr = "172.16.%d.2" % intf.sw_if_index
            a = VppIpInterfaceAddress(self, intf, addr, 24).add_vpp_config()
            intf_pfxs[i].append(a)

            # 172.15.x.2/24 - a different address and subnet
            addr = "172.15.%d.2" % intf.sw_if_index
            a = VppIpInterfaceAddress(self, intf, addr, 24).add_vpp_config()
            intf_pfxs[i].append(a)

        # a dump should n_address in it
        for intf in self.pg_interfaces:
            self.assertEqual(self.get_n_pfxs(intf), 3)

        #
        # remove all the address thru a replace
        #
        self.vapi.sw_interface_address_replace_begin()
        self.vapi.sw_interface_address_replace_end()
        for intf in self.pg_interfaces:
            self.assertEqual(self.get_n_pfxs(intf), 0)

        #
        # add all the interface addresses back
        #
        for p in intf_pfxs:
            for v in p:
                v.add_vpp_config()
        for intf in self.pg_interfaces:
            self.assertEqual(self.get_n_pfxs(intf), 3)

        #
        # replace again, but this time update/re-add the address on the first
        # two interfaces
        #
        self.vapi.sw_interface_address_replace_begin()

        for p in intf_pfxs[:2]:
            for v in p:
                v.add_vpp_config()

        self.vapi.sw_interface_address_replace_end()

        # on the first two the address still exist,
        # on the other two they do not
        for intf in self.pg_interfaces[:2]:
            self.assertEqual(self.get_n_pfxs(intf), 3)
        for p in intf_pfxs[:2]:
            for v in p:
                self.assertTrue(v.query_vpp_config())
        for intf in self.pg_interfaces[2:]:
            self.assertEqual(self.get_n_pfxs(intf), 0)

        #
        # add all the interface addresses back on the last two
        #
        for p in intf_pfxs[2:]:
            for v in p:
                v.add_vpp_config()
        for intf in self.pg_interfaces:
            self.assertEqual(self.get_n_pfxs(intf), 3)

        #
        # replace again, this time add different prefixes on all the interfaces
        #
        self.vapi.sw_interface_address_replace_begin()

        pfxs = []
        for intf in self.pg_interfaces:
            # 172.18.x.1/24
            addr = "172.18.%d.1" % intf.sw_if_index
            pfxs.append(VppIpInterfaceAddress(self, intf, addr,
                                              24).add_vpp_config())

        self.vapi.sw_interface_address_replace_end()

        # only .18 should exist on each interface
        for intf in self.pg_interfaces:
            self.assertEqual(self.get_n_pfxs(intf), 1)
        for pfx in pfxs:
            self.assertTrue(pfx.query_vpp_config())

        #
        # remove everything
        #
        self.vapi.sw_interface_address_replace_begin()
        self.vapi.sw_interface_address_replace_end()
        for intf in self.pg_interfaces:
            self.assertEqual(self.get_n_pfxs(intf), 0)

        #
        # add prefixes to each interface. post-begin add the prefix from
        # interface X onto interface Y. this would normally be an error
        # since it would generate a 'duplicate address' warning. but in
        # this case, since what is newly downloaded is sane, it's ok
        #
        for intf in self.pg_interfaces:
            # 172.18.x.1/24
            addr = "172.18.%d.1" % intf.sw_if_index
            VppIpInterfaceAddress(self, intf, addr, 24).add_vpp_config()

        self.vapi.sw_interface_address_replace_begin()

        pfxs = []
        for intf in self.pg_interfaces:
            # 172.18.x.1/24
            addr = "172.18.%d.1" % (intf.sw_if_index + 1)
            pfxs.append(VppIpInterfaceAddress(self, intf,
                                              addr, 24).add_vpp_config())

        self.vapi.sw_interface_address_replace_end()

        self.logger.info(self.vapi.cli("sh int addr"))

        for intf in self.pg_interfaces:
            self.assertEqual(self.get_n_pfxs(intf), 1)
        for pfx in pfxs:
            self.assertTrue(pfx.query_vpp_config())


class TestIPv4PathMTU(VppTestCase):
    """ IPv4 Path MTU """

    @classmethod
    def setUpClass(cls):
        super(TestIPv4PathMTU, cls).setUpClass()

        cls.create_pg_interfaces(range(2))

        # setup all interfaces
        for i in cls.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    @classmethod
    def tearDownClass(cls):
        super(TestIPv4PathMTU, cls).tearDownClass()

    def test_path_mtu(self):
        """ Path MTU """

        #
        # The goal here is not to test that fragmentation works correctly,
        # that's done elsewhere, the intent is to ensure that the Path MTU
        # settings are honoured.
        #
        self.vapi.cli("adjacency counters enable")

        # set the interface MTU to a reasonable value
        self.vapi.sw_interface_set_mtu(self.pg1.sw_if_index,
                                       [1800, 0, 0, 0])

        self.pg1.generate_remote_hosts(4)

        p_2k = (Ether(dst=self.pg0.local_mac,
                      src=self.pg0.remote_mac) /
                IP(src=self.pg0.remote_ip4,
                   dst=self.pg1.remote_ip4) /
                UDP(sport=1234, dport=5678) /
                Raw(b'0xa' * 640))
        p_1k = (Ether(dst=self.pg0.local_mac,
                      src=self.pg0.remote_mac) /
                IP(src=self.pg0.remote_ip4,
                   dst=self.pg1.remote_ip4) /
                UDP(sport=1234, dport=5678) /
                Raw(b'0xa' * 320))

        nbr = VppNeighbor(self,
                          self.pg1.sw_if_index,
                          self.pg1.remote_mac,
                          self.pg1.remote_ip4).add_vpp_config()

        # this is now the interface MTU frags
        self.send_and_expect(self.pg0, [p_2k], self.pg1, n_rx=2)
        self.send_and_expect(self.pg0, [p_1k], self.pg1)

        # drop the path MTU for this neighbour to below the interface MTU
        # expect more frags
        pmtu = VppIpPathMtu(self, self.pg1.remote_ip4, 900).add_vpp_config()

        self.send_and_expect(self.pg0, [p_2k], self.pg1, n_rx=3)
        self.send_and_expect(self.pg0, [p_1k], self.pg1, n_rx=2)

        # print/format the adj delegate
        self.logger.info(self.vapi.cli("sh adj 5"))

        # increase the path MTU to more than the interface
        # expect to use the interface MTU
        pmtu.modify(8192)

        self.send_and_expect(self.pg0, [p_2k], self.pg1, n_rx=2)
        self.send_and_expect(self.pg0, [p_1k], self.pg1)

        # go back to an MTU from the path
        # wrap the call around mark-n-sweep to enusre updates clear stale
        self.vapi.ip_path_mtu_replace_begin()
        pmtu.modify(900)
        self.vapi.ip_path_mtu_replace_end()

        self.send_and_expect(self.pg0, [p_2k], self.pg1, n_rx=3)
        self.send_and_expect(self.pg0, [p_1k], self.pg1, n_rx=2)

        # raise the interface's MTU
        # should still use that of the path
        self.vapi.sw_interface_set_mtu(self.pg1.sw_if_index,
                                       [2000, 0, 0, 0])
        self.send_and_expect(self.pg0, [p_2k], self.pg1, n_rx=3)
        self.send_and_expect(self.pg0, [p_1k], self.pg1, n_rx=2)

        # set path high and interface low
        pmtu.modify(2000)
        self.vapi.sw_interface_set_mtu(self.pg1.sw_if_index,
                                       [900, 0, 0, 0])
        self.send_and_expect(self.pg0, [p_2k], self.pg1, n_rx=3)
        self.send_and_expect(self.pg0, [p_1k], self.pg1, n_rx=2)

        # remove the path MTU using the mark-n-sweep semantics
        self.vapi.sw_interface_set_mtu(self.pg1.sw_if_index,
                                       [1800, 0, 0, 0])
        self.vapi.ip_path_mtu_replace_begin()
        self.vapi.ip_path_mtu_replace_end()

        self.send_and_expect(self.pg0, [p_2k], self.pg1, n_rx=2)
        self.send_and_expect(self.pg0, [p_1k], self.pg1)

        #
        # set path MTU for a neighbour that doesn't exist, yet
        #
        pmtu2 = VppIpPathMtu(self,
                             self.pg1.remote_hosts[2].ip4,
                             900).add_vpp_config()

        p_2k = (Ether(dst=self.pg0.local_mac,
                      src=self.pg0.remote_mac) /
                IP(src=self.pg0.remote_ip4,
                   dst=self.pg1.remote_hosts[2].ip4) /
                UDP(sport=1234, dport=5678) /
                Raw(b'0xa' * 640))
        p_1k = (Ether(dst=self.pg0.local_mac,
                      src=self.pg0.remote_mac) /
                IP(src=self.pg0.remote_ip4,
                   dst=self.pg1.remote_hosts[2].ip4) /
                UDP(sport=1234, dport=5678) /
                Raw(b'0xa' * 320))

        nbr2 = VppNeighbor(self,
                           self.pg1.sw_if_index,
                           self.pg1.remote_hosts[2].mac,
                           self.pg1.remote_hosts[2].ip4).add_vpp_config()

        # should frag to the path MTU
        self.send_and_expect(self.pg0, [p_2k], self.pg1, n_rx=3)
        self.send_and_expect(self.pg0, [p_1k], self.pg1, n_rx=2)

        # remove and re-add the neighbour
        nbr2.remove_vpp_config()
        nbr2.add_vpp_config()

        # should frag to the path MTU
        self.send_and_expect(self.pg0, [p_2k], self.pg1, n_rx=3)
        self.send_and_expect(self.pg0, [p_1k], self.pg1, n_rx=2)

        #
        # set PMTUs for many peers
        #
        N_HOSTS = 16
        self.pg1.generate_remote_hosts(16)
        self.pg1.configure_ipv4_neighbors()

        for h in range(N_HOSTS):
            pmtu = VppIpPathMtu(self, self.pg1.remote_hosts[h].ip4, 900)
            pmtu.add_vpp_config()
            self.assertTrue(pmtu.query_vpp_config())

        self.logger.info(self.vapi.cli("sh ip pmtu"))
        dump = list(self.vapi.vpp.details_iter(self.vapi.ip_path_mtu_get))
        self.assertEqual(N_HOSTS, len(dump))

        for h in range(N_HOSTS):
            p_2k[IP].dst = self.pg1.remote_hosts[h].ip4
            p_1k[IP].dst = self.pg1.remote_hosts[h].ip4

            # should frag to the path MTU
            self.send_and_expect(self.pg0, [p_2k], self.pg1, n_rx=3)
            self.send_and_expect(self.pg0, [p_1k], self.pg1, n_rx=2)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
