#!/usr/bin/env python
import random
import socket
import unittest

from framework import VppTestCase, VppTestRunner
from vpp_sub_interface import VppSubInterface, VppDot1QSubint, VppDot1ADSubint

from scapy.packet import Raw
from scapy.layers.l2 import Ether, Dot1Q
from scapy.layers.inet import IP, UDP
from util import ppp


class TestIPv4(VppTestCase):
    """ IPv4 Test Case """

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
        :ivar list pg_if_packet_sizes: packet sizes in test.
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
        self.pg_if_packet_sizes = [64, 512, 1518, 9018]
        self.sub_if_packet_sizes = [64, 512, 1518 + 4, 9018 + 4]

        self.interfaces = list(self.pg_interfaces)
        self.interfaces.extend(self.sub_interfaces)

        # setup all interfaces
        for i in self.interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

        # config 2M FIB entries
        self.config_fib_entries(200)

    def tearDown(self):
        """Run standard test teardown and log ``show ip arp``."""
        super(TestIPv4, self).tearDown()
        if not self.vpp_dead:
            self.logger.info(self.vapi.cli("show ip arp"))
            # info(self.vapi.cli("show ip fib"))  # many entries

    def config_fib_entries(self, count):
        """For each interface add to the FIB table *count* routes to
        "10.0.0.1/32" destination with interface's local address as next-hop
        address.

        :param int count: Number of FIB entries.

        - *TODO:* check if the next-hop address shouldn't be remote address
          instead of local address.
        """
        n_int = len(self.interfaces)
        percent = 0
        counter = 0.0
        dest_addr = socket.inet_pton(socket.AF_INET, "10.0.0.1")
        dest_addr_len = 32
        for i in self.interfaces:
            next_hop_address = i.local_ip4n
            for j in range(count / n_int):
                self.vapi.ip_add_del_route(
                    dest_addr, dest_addr_len, next_hop_address)
                counter += 1
                if counter / count * 100 > percent:
                    self.logger.info("Configure %d FIB entries .. %d%% done" %
                                     (count, percent))
                    percent += 1

    def create_stream(self, src_if, packet_sizes):
        """Create input packet stream for defined interface.

        :param VppInterface src_if: Interface to create packet stream for.
        :param list packet_sizes: Required packet sizes.
        """
        pkts = []
        for i in range(0, 257):
            dst_if = self.flows[src_if][i % 2]
            info = self.create_packet_info(
                src_if.sw_if_index, dst_if.sw_if_index)
            payload = self.info_to_payload(info)
            p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                 IP(src=src_if.remote_ip4, dst=dst_if.remote_ip4) /
                 UDP(sport=1234, dport=1234) /
                 Raw(payload))
            info.data = p.copy()
            if isinstance(src_if, VppSubInterface):
                p = src_if.add_dot1_layer(p)
            size = packet_sizes[(i // 2) % len(packet_sizes)]
            self.extend_packet(p, size)
            pkts.append(p)
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
                payload_info = self.payload_to_info(str(packet[Raw]))
                packet_index = payload_info.index
                self.assertEqual(payload_info.dst, dst_sw_if_index)
                self.logger.debug("Got packet on port %s: src=%u (id=%u)" %
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
            - Create IPv4 tagged streams for pg1's and pg2's subinterface.
            - Send and verify received packets on each interface.
        """

        pkts = self.create_stream(self.pg0, self.pg_if_packet_sizes)
        self.pg0.add_stream(pkts)

        for i in self.sub_interfaces:
            pkts = self.create_stream(i, self.sub_if_packet_sizes)
            i.parent.add_stream(pkts)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        pkts = self.pg0.get_capture()
        self.verify_capture(self.pg0, pkts)

        for i in self.sub_interfaces:
            pkts = i.parent.get_capture()
            self.verify_capture(i, pkts)


class TestIPv4FibCrud(VppTestCase):
    """ FIB - add/update/delete - ip4 routes

    Test scenario:
        - add 1k,
        - del 100,
        - add new 1k,
        - del 1.5k

    ..note:: Python API is to slow to add many routes, needs C code replacement.
    """

    def config_fib_many_to_one(self, start_dest_addr, next_hop_addr, count):
        """

        :param start_dest_addr:
        :param next_hop_addr:
        :param count:
        :return list: added ips with 32 prefix
        """
        added_ips = []
        dest_addr = int(
            socket.inet_pton(socket.AF_INET, start_dest_addr).encode('hex'), 16)
        dest_addr_len = 32
        n_next_hop_addr = socket.inet_pton(socket.AF_INET, next_hop_addr)
        for _ in range(count):
            n_dest_addr = '{:08x}'.format(dest_addr).decode('hex')
            self.vapi.ip_add_del_route(n_dest_addr, dest_addr_len,
                                       n_next_hop_addr)
            added_ips.append(socket.inet_ntoa(n_dest_addr))
            dest_addr += 1
        return added_ips

    def unconfig_fib_many_to_one(self, start_dest_addr, next_hop_addr, count):

        removed_ips = []
        dest_addr = int(
            socket.inet_pton(socket.AF_INET, start_dest_addr).encode('hex'), 16)
        dest_addr_len = 32
        n_next_hop_addr = socket.inet_pton(socket.AF_INET, next_hop_addr)
        for _ in range(count):
            n_dest_addr = '{:08x}'.format(dest_addr).decode('hex')
            self.vapi.ip_add_del_route(n_dest_addr, dest_addr_len,
                                       n_next_hop_addr, is_add=0)
            removed_ips.append(socket.inet_ntoa(n_dest_addr))
            dest_addr += 1
        return removed_ips

    def create_stream(self, src_if, dst_if, dst_ips, count):
        pkts = []

        for _ in range(count):
            dst_addr = random.choice(dst_ips)
            info = self.create_packet_info(
                src_if.sw_if_index, dst_if.sw_if_index)
            payload = self.info_to_payload(info)
            p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                 IP(src=src_if.remote_ip4, dst=dst_addr) /
                 UDP(sport=1234, dport=1234) /
                 Raw(payload))
            info.data = p.copy()
            size = random.choice(self.pg_if_packet_sizes)
            self.extend_packet(p, random.choice(self.pg_if_packet_sizes))
            pkts.append(p)

        return pkts

    def _find_ip_match(self, find_in, pkt):
        for p in find_in:
            if self.payload_to_info(str(p[Raw])) == self.payload_to_info(str(pkt[Raw])):
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

    @staticmethod
    def _match_route_detail(route_detail, ip, address_length=32, table_id=0):
        if route_detail.address == socket.inet_pton(socket.AF_INET, ip):
            if route_detail.table_id != table_id:
                return False
            elif route_detail.address_length != address_length:
                return False
            else:
                return True
        else:
            return False

    def verify_capture(self, dst_interface, received_pkts, expected_pkts):
        self.assertEqual(len(received_pkts), len(expected_pkts))
        to_verify = list(expected_pkts)
        for p in received_pkts:
            self.assertEqual(p.src, dst_interface.local_mac)
            self.assertEqual(p.dst, dst_interface.remote_mac)
            x = self._find_ip_match(to_verify, p)
            to_verify.remove(x)
        self.assertListEqual(to_verify, [])

    def verify_route_dump(self, fib_dump, ips):

        def _ip_in_route_dump(ip, fib_dump):
            return next((route for route in fib_dump
                         if self._match_route_detail(route, ip)),
                        False)

        for ip in ips:
            self.assertTrue(_ip_in_route_dump(ip, fib_dump),
                            'IP {} is not in fib dump.'.format(ip))

    def verify_not_in_route_dump(self, fib_dump, ips):

        def _ip_in_route_dump(ip, fib_dump):
            return next((route for route in fib_dump
                         if self._match_route_detail(route, ip)),
                        False)

        for ip in ips:
            self.assertFalse(_ip_in_route_dump(ip, fib_dump),
                             'IP {} is in fib dump.'.format(ip))

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

    def setUp(self):
        super(TestIPv4FibCrud, self).setUp()
        self.packet_infos = {}

    def test_1_add_routes(self):
        """ Add 1k routes

        - add 100 routes check with traffic script.
        """
        # config 1M FIB entries
        self.configured_routes.extend(self.config_fib_many_to_one(
            "10.0.0.0", self.pg0.remote_ip4, 100))

        fib_dump = self.vapi.ip_fib_dump()
        self.verify_route_dump(fib_dump, self.configured_routes)

        self.stream_1 = self.create_stream(
            self.pg1, self.pg0, self.configured_routes, 100)
        self.stream_2 = self.create_stream(
            self.pg2, self.pg0, self.configured_routes, 100)
        self.pg1.add_stream(self.stream_1)
        self.pg2.add_stream(self.stream_2)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        pkts = self.pg0.get_capture()
        self.verify_capture(self.pg0, pkts, self.stream_1 + self.stream_2)


    def test_2_del_routes(self):
        """ Delete 100 routes

        - delete 10 routes check with traffic script.
        """
        self.deleted_routes.extend(self.unconfig_fib_many_to_one(
            "10.0.0.10", self.pg0.remote_ip4, 10))
        for x in self.deleted_routes:
            self.configured_routes.remove(x)

        fib_dump = self.vapi.ip_fib_dump()
        self.verify_route_dump(fib_dump, self.configured_routes)

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

        pkts = self.pg0.get_capture()
        self.verify_capture(self.pg0, pkts, self.stream_1 + self.stream_2)

    def test_3_add_new_routes(self):
        """ Add 1k routes

        - re-add 5 routes check with traffic script.
        - add 100 routes check with traffic script.
        """
        tmp = self.config_fib_many_to_one(
            "10.0.0.10", self.pg0.remote_ip4, 5)
        self.configured_routes.extend(tmp)
        for x in tmp:
            self.deleted_routes.remove(x)

        self.configured_routes.extend(self.config_fib_many_to_one(
            "10.0.1.0", self.pg0.remote_ip4, 100))

        fib_dump = self.vapi.ip_fib_dump()
        self.verify_route_dump(fib_dump, self.configured_routes)

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

        pkts = self.pg0.get_capture()
        self.verify_capture(self.pg0, pkts, self.stream_1 + self.stream_2)

    def test_4_del_routes(self):
        """ Delete 1.5k routes

        - delete 5 routes check with traffic script.
        - add 100 routes check with traffic script.
        """
        self.deleted_routes.extend(self.unconfig_fib_many_to_one(
            "10.0.0.0", self.pg0.remote_ip4, 15))
        self.deleted_routes.extend(self.unconfig_fib_many_to_one(
            "10.0.0.20", self.pg0.remote_ip4, 85))
        self.deleted_routes.extend(self.unconfig_fib_many_to_one(
            "10.0.1.0", self.pg0.remote_ip4, 100))
        fib_dump = self.vapi.ip_fib_dump()
        self.verify_not_in_route_dump(fib_dump, self.deleted_routes)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
