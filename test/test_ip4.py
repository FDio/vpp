#!/usr/bin/env python
import binascii
import random
import socket
import unittest

from scapy.contrib.mpls import MPLS
from scapy.layers.inet import IP, UDP, TCP, ICMP, icmptypes, icmpcodes
from scapy.layers.l2 import Ether, Dot1Q, ARP
from scapy.packet import Raw
from six import moves

from framework import VppTestCase, VppTestRunner
from util import ppp
from vpp_ip_route import VppIpRoute, VppRoutePath, VppIpMRoute, \
    VppMRoutePath, MFIB_ITF_FLAG, MFIB_ENTRY_FLAG, VppMplsIpBind, \
    VppMplsTable, VppIpTable
from vpp_sub_interface import VppSubInterface, VppDot1QSubint, VppDot1ADSubint


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

    def modify_packet(self, src_if, packet_size, pkt):
        """Add load, set destination IP and extend packet to required packet
        size for defined interface.

        :param VppInterface src_if: Interface to create packet for.
        :param int packet_size: Required packet size.
        :param Scapy pkt: Packet to be modified.
        """
        dst_if_idx = packet_size / 10 % 2
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
                payload_info = self.payload_to_info(str(packet[Raw]))
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


class TestICMPEcho(VppTestCase):
    """ ICMP Echo Test Case """

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
        icmp_load = '\x0a' * 18
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

    def config_fib_many_to_one(self, start_dest_addr, next_hop_addr, count):
        """

        :param start_dest_addr:
        :param next_hop_addr:
        :param count:
        :return list: added ips with 32 prefix
        """
        added_ips = []
        dest_addr = int(binascii.hexlify(socket.inet_pton(socket.AF_INET,
                                         start_dest_addr)), 16)
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
        dest_addr = int(binascii.hexlify(socket.inet_pton(socket.AF_INET,
                                         start_dest_addr)), 16)
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
            info = self.create_packet_info(src_if, dst_if)
            payload = self.info_to_payload(info)
            p = (Ether(dst=src_if.local_mac, src=src_if.remote_mac) /
                 IP(src=src_if.remote_ip4, dst=dst_addr) /
                 UDP(sport=1234, dport=1234) /
                 Raw(payload))
            info.data = p.copy()
            self.extend_packet(p, random.choice(self.pg_if_packet_sizes))
            pkts.append(p)

        return pkts

    def _find_ip_match(self, find_in, pkt):
        for p in find_in:
            if self.payload_to_info(str(p[Raw])) == \
                    self.payload_to_info(str(pkt[Raw])):
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
        self.reset_packet_infos()

        self.configured_routes = []
        self.deleted_routes = []

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

        pkts = self.pg0.get_capture(len(self.stream_1) + len(self.stream_2))
        self.verify_capture(self.pg0, pkts, self.stream_1 + self.stream_2)

    def test_2_del_routes(self):
        """ Delete 100 routes

        - delete 10 routes check with traffic script.
        """
        # config 1M FIB entries
        self.configured_routes.extend(self.config_fib_many_to_one(
            "10.0.0.0", self.pg0.remote_ip4, 100))
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

        pkts = self.pg0.get_capture(len(self.stream_1) + len(self.stream_2))
        self.verify_capture(self.pg0, pkts, self.stream_1 + self.stream_2)

    def test_3_add_new_routes(self):
        """ Add 1k routes

        - re-add 5 routes check with traffic script.
        - add 100 routes check with traffic script.
        """
        # config 1M FIB entries
        self.configured_routes.extend(self.config_fib_many_to_one(
            "10.0.0.0", self.pg0.remote_ip4, 100))
        self.deleted_routes.extend(self.unconfig_fib_many_to_one(
            "10.0.0.10", self.pg0.remote_ip4, 10))
        for x in self.deleted_routes:
            self.configured_routes.remove(x)

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

        pkts = self.pg0.get_capture(len(self.stream_1) + len(self.stream_2))
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


class TestIPNull(VppTestCase):
    """ IPv4 routes via NULL """

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
        ip_unreach = VppIpRoute(self, "10.0.0.1", 32, [], is_unreach=1)
        ip_unreach.add_vpp_config()

        p_unreach = (Ether(src=self.pg0.remote_mac,
                           dst=self.pg0.local_mac) /
                     IP(src=self.pg0.remote_ip4, dst="10.0.0.1") /
                     UDP(sport=1234, dport=1234) /
                     Raw('\xa5' * 100))

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
        ip_prohibit = VppIpRoute(self, "10.0.0.2", 32, [], is_prohibit=1)
        ip_prohibit.add_vpp_config()

        p_prohibit = (Ether(src=self.pg0.remote_mac,
                            dst=self.pg0.local_mac) /
                      IP(src=self.pg0.remote_ip4, dst="10.0.0.2") /
                      UDP(sport=1234, dport=1234) /
                      Raw('\xa5' * 100))

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
             Raw('\xa5' * 100))

        r1 = VppIpRoute(self, "1.1.1.0", 24,
                        [VppRoutePath(self.pg1.remote_ip4,
                                      self.pg1.sw_if_index)])
        r1.add_vpp_config()

        rx = self.send_and_expect(self.pg0, p * 65, self.pg1)

        #
        # insert a more specific as a drop
        #
        r2 = VppIpRoute(self, "1.1.1.1", 32, [], is_drop=1)
        r2.add_vpp_config()

        self.send_and_assert_no_replies(self.pg0, p * 65, "Drop Route")
        r2.remove_vpp_config()
        rx = self.send_and_expect(self.pg0, p * 65, self.pg1)


class TestIPDisabled(VppTestCase):
    """ IPv4 disabled """

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

        #
        # An (S,G).
        # one accepting interface, pg0, 2 forwarding interfaces
        #
        route_232_1_1_1 = VppIpMRoute(
            self,
            "0.0.0.0",
            "232.1.1.1", 32,
            MFIB_ENTRY_FLAG.NONE,
            [VppMRoutePath(self.pg1.sw_if_index,
                           MFIB_ITF_FLAG.ACCEPT),
             VppMRoutePath(self.pg0.sw_if_index,
                           MFIB_ITF_FLAG.FORWARD)])
        route_232_1_1_1.add_vpp_config()

        pu = (Ether(src=self.pg1.remote_mac,
                    dst=self.pg1.local_mac) /
              IP(src="10.10.10.10", dst=self.pg0.remote_ip4) /
              UDP(sport=1234, dport=1234) /
              Raw('\xa5' * 100))
        pm = (Ether(src=self.pg1.remote_mac,
                    dst=self.pg1.local_mac) /
              IP(src="10.10.10.10", dst="232.1.1.1") /
              UDP(sport=1234, dport=1234) /
              Raw('\xa5' * 100))

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

    def setUp(self):
        super(TestIPSubNets, self).setUp()

        # create a 2 pg interfaces
        self.create_pg_interfaces(range(2))

        # pg0 we will use to experiemnt
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
             Raw('\xa5' * 100))

        self.pg1.add_stream(p)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = self.pg1.get_capture(1)

        #
        # Configure some non-/24 subnets on an IP interface
        #
        ip_addr_n = socket.inet_pton(socket.AF_INET, "10.10.10.10")

        self.vapi.sw_interface_add_del_address(self.pg0.sw_if_index,
                                               ip_addr_n,
                                               16)

        pn = (Ether(src=self.pg1.remote_mac,
                    dst=self.pg1.local_mac) /
              IP(dst="10.10.0.0", src=self.pg0.local_ip4) /
              UDP(sport=1234, dport=1234) /
              Raw('\xa5' * 100))
        pb = (Ether(src=self.pg1.remote_mac,
                    dst=self.pg1.local_mac) /
              IP(dst="10.10.255.255", src=self.pg0.local_ip4) /
              UDP(sport=1234, dport=1234) /
              Raw('\xa5' * 100))

        self.send_and_assert_no_replies(self.pg1, pn, "IP Network address")
        self.send_and_assert_no_replies(self.pg1, pb, "IP Broadcast address")

        # remove the sub-net and we are forwarding via the cover again
        self.vapi.sw_interface_add_del_address(self.pg0.sw_if_index,
                                               ip_addr_n,
                                               16,
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

        self.vapi.sw_interface_add_del_address(self.pg0.sw_if_index,
                                               ip_addr_n,
                                               31)

        pn = (Ether(src=self.pg1.remote_mac,
                    dst=self.pg1.local_mac) /
              IP(dst="10.10.10.11", src=self.pg0.local_ip4) /
              UDP(sport=1234, dport=1234) /
              Raw('\xa5' * 100))

        self.pg1.add_stream(pn)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = self.pg0.get_capture(1)
        rx[ARP]

        # remove the sub-net and we are forwarding via the cover again
        self.vapi.sw_interface_add_del_address(self.pg0.sw_if_index,
                                               ip_addr_n,
                                               31,
                                               is_add=0)
        self.pg1.add_stream(pn)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = self.pg1.get_capture(1)


class TestIPLoadBalance(VppTestCase):
    """ IPv4 Load-Balancing """

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
        input.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        for oo in outputs:
            rx = oo._get_capture(1)
            self.assertNotEqual(0, len(rx))

    def send_and_expect_one_itf(self, input, pkts, itf):
        input.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = itf.get_capture(len(pkts))

    def test_ip_load_balance(self):
        """ IP Load-Balancing """

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

        for ii in range(65):
            port_ip_hdr = (IP(dst="10.0.0.1", src="20.0.0.1") /
                           UDP(sport=1234, dport=1234 + ii) /
                           Raw('\xa5' * 100))
            port_ip_pkts.append((Ether(src=self.pg0.remote_mac,
                                       dst=self.pg0.local_mac) /
                                 port_ip_hdr))
            port_mpls_pkts.append((Ether(src=self.pg0.remote_mac,
                                         dst=self.pg0.local_mac) /
                                   MPLS(label=66, ttl=2) /
                                   port_ip_hdr))

            src_ip_hdr = (IP(dst="10.0.0.1", src="20.0.0.%d" % ii) /
                          UDP(sport=1234, dport=1234) /
                          Raw('\xa5' * 100))
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
        # be guaranteed. But wuth 64 different packets we do expect some
        # balancing. So instead just ensure there is traffic on each link.
        #
        self.send_and_expect_load_balancing(self.pg0, port_ip_pkts,
                                            [self.pg1, self.pg2])
        self.send_and_expect_load_balancing(self.pg0, src_ip_pkts,
                                            [self.pg1, self.pg2])
        self.send_and_expect_load_balancing(self.pg0, port_mpls_pkts,
                                            [self.pg1, self.pg2])
        self.send_and_expect_load_balancing(self.pg0, src_mpls_pkts,
                                            [self.pg1, self.pg2])

        #
        # change the flow hash config so it's only IP src,dst
        #  - now only the stream with differing source address will
        #    load-balance
        #
        self.vapi.set_ip_flow_hash(0, src=1, dst=1, sport=0, dport=0)

        self.send_and_expect_load_balancing(self.pg0, src_ip_pkts,
                                            [self.pg1, self.pg2])
        self.send_and_expect_load_balancing(self.pg0, src_mpls_pkts,
                                            [self.pg1, self.pg2])

        self.send_and_expect_one_itf(self.pg0, port_ip_pkts, self.pg2)

        #
        # change the flow hash config back to defaults
        #
        self.vapi.set_ip_flow_hash(0, src=1, dst=1, sport=1, dport=1)

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
                              Raw('\xa5' * 100)))
            src_pkts.append((Ether(src=self.pg0.remote_mac,
                                   dst=self.pg0.local_mac) /
                             IP(dst="1.1.1.1", src="20.0.0.%d" % ii) /
                             UDP(sport=1234, dport=1234) /
                             Raw('\xa5' * 100)))

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
        # Recursive prefixes
        #  - testing that 2 stages of load-balancing, no choices
        #
        port_pkts = []

        for ii in range(257):
            port_pkts.append((Ether(src=self.pg0.remote_mac,
                                    dst=self.pg0.local_mac) /
                              IP(dst="1.1.1.2", src="20.0.0.2") /
                              UDP(sport=1234, dport=1234 + ii) /
                              Raw('\xa5' * 100)))

        route_10_0_0_3 = VppIpRoute(self, "10.0.0.3", 32,
                                    [VppRoutePath(self.pg3.remote_ip4,
                                                  self.pg3.sw_if_index)])
        route_10_0_0_3.add_vpp_config()

        route_1_1_1_2 = VppIpRoute(self, "1.1.1.2", 32,
                                   [VppRoutePath("10.0.0.3", 0xffffffff)])
        route_1_1_1_2.add_vpp_config()

        #
        # inject the packet on pg0 - expect load-balancing across all 4 paths
        #
        self.vapi.cli("clear trace")
        self.send_and_expect_one_itf(self.pg0, port_pkts, self.pg3)


class TestIPVlan0(VppTestCase):
    """ IPv4 VLAN-0 """

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
                Raw('\xa5' * 100)) * 65

        #
        # Expect that packets sent on VLAN-0 are forwarded on the
        # main interface.
        #
        self.send_and_expect(self.pg0, pkts, self.pg1)


class TestIPPunt(VppTestCase):
    """ IPv4 Punt Police/Redirect """

    def setUp(self):
        super(TestIPPunt, self).setUp()

        self.create_pg_interfaces(range(4))

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    def tearDown(self):
        super(TestIPPunt, self).tearDown()
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.admin_down()

    def test_ip_punt(self):
        """ IP punt police and redirect """

        p = (Ether(src=self.pg0.remote_mac,
                   dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) /
             TCP(sport=1234, dport=1234) /
             Raw('\xa5' * 100))

        pkts = p * 1025

        #
        # Configure a punt redirect via pg1.
        #
        nh_addr = self.pg1.remote_ip4
        self.vapi.ip_punt_redirect(self.pg0.sw_if_index,
                                   self.pg1.sw_if_index,
                                   nh_addr)

        self.send_and_expect(self.pg0, pkts, self.pg1)

        #
        # add a policer
        #
        policer = self.vapi.policer_add_del("ip4-punt", 400, 0, 10, 0,
                                            rate_type=1)
        self.vapi.ip_punt_police(policer.policer_index)

        self.vapi.cli("clear trace")
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        #
        # the number of packet recieved should be greater than 0,
        # but not equal to the number sent, since some were policed
        #
        rx = self.pg1._get_capture(1)
        self.assertGreater(len(rx), 0)
        self.assertLess(len(rx), len(pkts))

        #
        # remove the poilcer. back to full rx
        #
        self.vapi.ip_punt_police(policer.policer_index, is_add=0)
        self.vapi.policer_add_del("ip4-punt", 400, 0, 10, 0,
                                  rate_type=1, is_add=0)
        self.send_and_expect(self.pg0, pkts, self.pg1)

        #
        # remove the redirect. expect full drop.
        #
        self.vapi.ip_punt_redirect(self.pg0.sw_if_index,
                                   self.pg1.sw_if_index,
                                   nh_addr,
                                   is_add=0)
        self.send_and_assert_no_replies(self.pg0, pkts,
                                        "IP no punt config")

        #
        # Add a redirect that is not input port selective
        #
        self.vapi.ip_punt_redirect(0xffffffff,
                                   self.pg1.sw_if_index,
                                   nh_addr)
        self.send_and_expect(self.pg0, pkts, self.pg1)

        self.vapi.ip_punt_redirect(0xffffffff,
                                   self.pg1.sw_if_index,
                                   nh_addr,
                                   is_add=0)

    def test_ip_punt_dump(self):
        """ IP4 punt redirect dump"""

        #
        # Configure a punt redirects
        #
        nh_address = self.pg3.remote_ip4
        self.vapi.ip_punt_redirect(self.pg0.sw_if_index,
                                   self.pg3.sw_if_index,
                                   nh_address)
        self.vapi.ip_punt_redirect(self.pg1.sw_if_index,
                                   self.pg3.sw_if_index,
                                   nh_address)
        self.vapi.ip_punt_redirect(self.pg2.sw_if_index,
                                   self.pg3.sw_if_index,
                                   '0.0.0.0')

        #
        # Dump pg0 punt redirects
        #
        punts = self.vapi.ip_punt_redirect_dump(self.pg0.sw_if_index)
        for p in punts:
            self.assertEqual(p.punt.rx_sw_if_index, self.pg0.sw_if_index)

        #
        # Dump punt redirects for all interfaces
        #
        punts = self.vapi.ip_punt_redirect_dump(0xffffffff)
        self.assertEqual(len(punts), 3)
        for p in punts:
            self.assertEqual(p.punt.tx_sw_if_index, self.pg3.sw_if_index)
        self.assertNotEqual(punts[1].punt.nh, self.pg3.remote_ip4)
        self.assertEqual(str(punts[2].punt.nh), '0.0.0.0')


class TestIPDeag(VppTestCase):
    """ IPv4 Deaggregate Routes """

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
        route_to_src = VppIpRoute(self, "1.1.1.2", 32,
                                  [VppRoutePath("0.0.0.0",
                                                0xffffffff,
                                                nh_table_id=2,
                                                is_source_lookup=1)])
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
                 Raw('\xa5' * 100))
        p_src = (Ether(src=self.pg0.remote_mac,
                       dst=self.pg0.local_mac) /
                 IP(src="2.2.2.2", dst="1.1.1.2") /
                 TCP(sport=1234, dport=1234) /
                 Raw('\xa5' * 100))
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
               Raw('\xa5' * 100))

        self.send_and_assert_no_replies(self.pg0, p_l * 257,
                                        "IP lookup loop")


class TestIPInput(VppTestCase):
    """ IPv4 Input Exceptions """

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
                   Raw('\xa5' * 100))

        rx = self.send_and_expect(self.pg0, p_short * 65, self.pg1)

        #
        # Packet too long - this is dropped
        #
        p_long = (Ether(src=self.pg0.remote_mac,
                        dst=self.pg0.local_mac) /
                  IP(src=self.pg0.remote_ip4,
                     dst=self.pg1.remote_ip4,
                     len=400) /
                  UDP(sport=1234, dport=1234) /
                  Raw('\xa5' * 100))

        rx = self.send_and_assert_no_replies(self.pg0, p_long * 65,
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
                    Raw('\xa5' * 100))

        rx = self.send_and_assert_no_replies(self.pg0, p_chksum * 65,
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
                 Raw('\xa5' * 100))

        rx = self.send_and_assert_no_replies(self.pg0, p_ver * 65,
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
                  Raw('\xa5' * 100))

        rx = self.send_and_assert_no_replies(self.pg0, p_frag * 65,
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
                 Raw('\xa5' * 100))

        rx = self.send_and_expect(self.pg0, p_ttl * 65, self.pg0)

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
                 Raw('\xa5' * 2000))

        self.vapi.sw_interface_set_mtu(self.pg1.sw_if_index, [1500, 0, 0, 0])

        rx = self.send_and_expect(self.pg0, p_mtu * 65, self.pg0)
        rx = rx[0]
        icmp = rx[ICMP]

        self.assertEqual(icmptypes[icmp.type], "dest-unreach")
        self.assertEqual(icmpcodes[icmp.type][icmp.code],
                         "fragmentation-needed")
        self.assertEqual(icmp.src, self.pg0.remote_ip4)
        self.assertEqual(icmp.dst, self.pg1.remote_ip4)

        self.vapi.sw_interface_set_mtu(self.pg1.sw_if_index, [2500, 0, 0, 0])
        rx = self.send_and_expect(self.pg0, p_mtu * 65, self.pg1)

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
                Raw(load='\x0a' * 18))
        rx = self.send_and_assert_no_replies(self.pg0, p_s0 * 17)

        p_s0 = (Ether(src=self.pg0.remote_mac,
                      dst=self.pg0.local_mac) /
                IP(src="255.255.255.255",
                   dst=self.pg0.local_ip4) /
                ICMP(id=4, seq=4) /
                Raw(load='\x0a' * 18))
        rx = self.send_and_assert_no_replies(self.pg0, p_s0 * 17)


class TestIPDirectedBroadcast(VppTestCase):
    """ IPv4 Directed Broadcast """

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
              Raw('\xa5' * 2000))
        p1 = (Ether(src=self.pg0.remote_mac,
                    dst=self.pg0.local_mac) /
              IP(src="1.1.1.1",
                 dst=self.pg1._local_ip4_bcast) /
              UDP(sport=1234, dport=1234) /
              Raw('\xa5' * 2000))

        self.pg0.config_ip4()
        self.pg0.resolve_arp()
        self.pg1.config_ip4()
        self.pg1.resolve_arp()

        #
        # test packet is L2 broadcast
        #
        rx = self.send_and_expect(self.pg1, p0 * 65, self.pg0)
        self.assertTrue(rx[0][Ether].dst, "ff:ff:ff:ff:ff:ff")

        self.send_and_assert_no_replies(self.pg0, p1 * 65,
                                        "directed broadcast disabled")

        #
        # toggle directed broadcast on pg0
        #
        self.vapi.sw_interface_set_ip_directed_broadcast(
            self.pg0.sw_if_index, 0)
        self.send_and_assert_no_replies(self.pg1, p0 * 65,
                                        "directed broadcast disabled")

        self.vapi.sw_interface_set_ip_directed_broadcast(
            self.pg0.sw_if_index, 1)
        rx = self.send_and_expect(self.pg1, p0 * 65, self.pg0)

        self.pg0.unconfig_ip4()
        self.pg1.unconfig_ip4()


class TestIPLPM(VppTestCase):
    """ IPv4 longest Prefix Match """

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
               Raw('\xa5' * 2000))
        p_24 = (Ether(src=self.pg0.remote_mac,
                      dst=self.pg0.local_mac) /
                IP(src="1.1.1.1",
                   dst="10.1.2.1") /
                UDP(sport=1234, dport=1234) /
                Raw('\xa5' * 2000))

        self.logger.info(self.vapi.cli("sh ip fib mtrie"))
        rx = self.send_and_expect(self.pg0, p_8 * 65, self.pg2)
        rx = self.send_and_expect(self.pg0, p_24 * 65, self.pg1)


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

    def test_frag_large_packets(self):
        """ Fragmentation of large packets """

        p = (Ether(dst=self.src_if.local_mac, src=self.src_if.remote_mac) /
             IP(src=self.src_if.remote_ip4, dst=self.dst_if.remote_ip4) /
             UDP(sport=1234, dport=5678) / Raw())
        self.extend_packet(p, 6000, "abcde")
        saved_payload = p[Raw].load

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

        # Assume VPP sends the fragments in order
        payload = ''
        for p in packets:
            payload_offset = p.frag * 8
            if payload_offset > 0:
                payload_offset -= 8  # UDP header is not in payload
            self.assert_equal(payload_offset, len(payload))
            payload += p[Raw].load
        self.assert_equal(payload, saved_payload, "payload")


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
