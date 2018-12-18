#!/usr/bin/env python
import binascii
import random
import socket
import unittest
import os
import scapy.layers.inet6 as inet6
import threading
import struct

from struct import unpack, unpack_from
from util import ppp, ppc
from re import compile
from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6DestUnreach
from framework import VppTestCase, VppTestRunner


# Format MAC Address
def get_mac_addr(bytes_addr):
    return ':'.join('%02x' % ord(b) for b in bytes_addr)


# Format IP Address
def ipv4(bytes_addr):
    return '.'.join('%d' % ord(b) for b in bytes_addr)


# Unpack Ethernet Frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return dest_mac, src_mac, socket.htons(proto), data[14:]


# Unpack IPv4 Packets
def ipv4_packet(data):
    proto, src, target = struct.unpack('! 8x 1x B 2x 4s 4s', data[:20])
    return proto, src, target, data[20:]


# Unpack IPv6 Packets
def ipv6_packet(data):
    nh, src, target = struct.unpack('! 6x B 1x 16s 16s', data[:40])
    return nh, src, target, data[40:]


# Unpacks any UDP Packet
def udp_seg(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]


# Unpacks any TCP Packet
def tcp_seg(data):
    src_port, dest_port, seq, flag = struct.unpack('! H H L 4x H', data[:14])
    return src_port, dest_port, seq, data[((flag >> 12) * 4):]


def receivePackets(sock, counters):
    # Wait for some packets on socket
    while True:
        data = sock.recv(65536)

        # punt socket metadata
        # packet_desc = data[0:8]

        # Ethernet
        _, _, eth_proto, data = ethernet_frame(data[8:])
        # Ipv4
        if eth_proto == 8:
            proto, _, _, data = ipv4_packet(data)
            # TCP
            if proto == 6:
                _, dst_port, _, data = udp_seg(data)
            # UDP
            elif proto == 17:
                _, dst_port, _, data = udp_seg(data)
                counters[dst_port] = 0
        # Ipv6
        elif eth_proto == 0xdd86:
            nh, _, _, data = ipv6_packet(data)
            # TCP
            if nh == 6:
                _, dst_port, _, data = udp_seg(data)
            # UDP
            elif nh == 17:
                _, dst_port, _, data = udp_seg(data)
                counters[dst_port] = 0


class serverSocketThread(threading.Thread):
    """ Socket server thread"""

    def __init__(self, threadID, sockName, counters):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.sockName = sockName
        self.sock = None
        self.counters = counters

    def run(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            os.unlink(self.sockName)
        except:
            pass
        self.sock.bind(self.sockName)

        receivePackets(self.sock, self.counters)


class TestPuntSocket(VppTestCase):
    """ Punt Socket """

    ports = [1111, 2222, 3333, 4444]
    sock_servers = list()
    portsCheck = dict()
    nr_packets = 256

    @classmethod
    def setUpConstants(cls):
        tempdir = cls.tempdir
        cls.config.add('punt', 'socket', '%s/socket_punt' % cls.tempdir)
        super(TestPuntSocket, cls).setUpConstants()

    def setUp(self):
        super(TestPuntSocket, self).setUp()
        random.seed()

        self.create_pg_interfaces(range(2))
        for i in self.pg_interfaces:
            i.admin_up()

    def tearDown(self):
        del self.sock_servers[:]

    def socket_client_create(self, sock_name, id=None):
        thread = serverSocketThread(id, sock_name, self.portsCheck)
        self.sock_servers.append(thread)
        thread.start()

    def socket_client_close(self):
        for thread in self.sock_servers:
            thread.sock.close()


class TestIP4PuntSocket(TestPuntSocket):
    """ Punt Socket for IPv4 """

    def setUp(self):
        super(TestIP4PuntSocket, self).setUp()

        for i in self.pg_interfaces:
            i.config_ip4()
            i.resolve_arp()

    def tearDown(self):
        super(TestIP4PuntSocket, self).tearDown()
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.admin_down()

    def test_punt_socket_dump(self):
        """ Punt socket registration/deregistration"""

        punts = self.vapi.punt_socket_dump(is_ip6=0)
        self.assertEqual(len(punts), 0)

        #
        # configure a punt socket
        #
        self.vapi.punt_socket_register(1111, self.tempdir+"/socket_punt_1111")
        self.vapi.punt_socket_register(2222, self.tempdir+"/socket_punt_2222")
        punts = self.vapi.punt_socket_dump(is_ip6=0)
        self.assertEqual(len(punts), 2)
        self.assertEqual(punts[0].punt.l4_port, 1111)
        self.assertEqual(punts[1].punt.l4_port, 2222)

        #
        # deregister a punt socket
        #
        self.vapi.punt_socket_deregister(1111)
        punts = self.vapi.punt_socket_dump(is_ip6=0)
        self.assertEqual(len(punts), 1)

        #
        # configure a punt socket again
        #
        self.vapi.punt_socket_register(1111, self.tempdir+"/socket_punt_1111")
        self.vapi.punt_socket_register(3333, self.tempdir+"/socket_punt_3333")
        punts = self.vapi.punt_socket_dump(is_ip6=0)
        self.assertEqual(len(punts), 3)

        #
        # deregister all punt socket
        #
        self.vapi.punt_socket_deregister(1111)
        self.vapi.punt_socket_deregister(2222)
        self.vapi.punt_socket_deregister(3333)
        punts = self.vapi.punt_socket_dump(is_ip6=0)
        self.assertEqual(len(punts), 0)

    def test_punt_socket_traffic_single_port_single_socket(self):
        """ Punt socket traffic single port single socket"""

        port = self.ports[0]

        p = (Ether(src=self.pg0.remote_mac,
                   dst=self.pg0.local_mac) /
             IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) /
             UDP(sport=9876, dport=port) /
             Raw('\xa5' * 100))

        pkts = p * self.nr_packets
        self.portsCheck[port] = self.nr_packets

        punts = self.vapi.punt_socket_dump(is_ip6=0)
        self.assertEqual(len(punts), 0)

        #
        # expect ICMP - port unreachable for all packets
        #
        self.vapi.cli("clear trace")
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        # FIXME - when punt socket deregister is implemented
        # rx = self.pg0.get_capture(self.nr_packets)
        # for p in rx:
        #     self.assertEqual(int(p[IP].proto), 1)   # ICMP
        #     self.assertEqual(int(p[ICMP].code), 3)  # unreachable

        #
        # configure a punt socket
        #
        self.socket_client_create(self.tempdir+"/socket_" + str(port))
        self.vapi.punt_socket_register(port, self.tempdir+"/socket_" +
                                       str(port))
        punts = self.vapi.punt_socket_dump(is_ip6=0)
        self.assertEqual(len(punts), 1)

        self.logger.debug("Sending %s packets to port %d",
                          str(self.portsCheck[port]), port)
        #
        # expect punt socket and no packets on pg0
        #
        self.vapi.cli("clear errors")
        self.vapi.cli("clear trace")
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg0.get_capture(0)
        self.logger.info(self.vapi.cli("show trace"))
        self.socket_client_close()
        self.assertEqual(self.portsCheck[port], 0)

        #
        # remove punt socket. expect ICMP - port unreachable for all packets
        #
        self.vapi.punt_socket_deregister(port)
        punts = self.vapi.punt_socket_dump(is_ip6=0)
        self.assertEqual(len(punts), 0)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        # FIXME - when punt socket deregister is implemented
        # self.pg0.get_capture(nr_packets)

    def test_punt_socket_traffic_multi_port_multi_sockets(self):
        """ Punt socket traffic multi ports and multi sockets"""

        for p in self.ports:
            self.portsCheck[p] = 0

        #
        # create stream with random pakets count per given ports
        #
        pkts = list()
        for _ in range(0, self.nr_packets):
            # choose port from port list
            p = random.choice(self.ports)
            pkts.append((
                Ether(src=self.pg0.remote_mac,
                      dst=self.pg0.local_mac) /
                IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) /
                UDP(sport=9876, dport=p) /
                Raw('\xa5' * 100)))
            self.portsCheck[p] += 1
        #
        # no punt socket
        #
        punts = self.vapi.punt_socket_dump(is_ip6=0)
        self.assertEqual(len(punts), 0)

        #
        # configure a punt socket
        #
        for p in self.ports:
            self.socket_client_create(self.tempdir+"/socket_" + str(p))
            self.vapi.punt_socket_register(p, self.tempdir+"/socket_" + str(p))
        punts = self.vapi.punt_socket_dump(is_ip6=0)
        self.assertEqual(len(punts), len(self.ports))

        for p in self.ports:
            self.logger.debug("Sending %s packets to port %d",
                              str(self.portsCheck[p]), p)

        #
        # expect punt socket and no packets on pg0
        #
        self.vapi.cli("clear errors")
        self.vapi.cli("clear trace")
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg0.get_capture(0)
        self.logger.info(self.vapi.cli("show trace"))
        self.socket_client_close()

        for p in self.ports:
            self.assertEqual(self.portsCheck[p], 0)
            self.vapi.punt_socket_deregister(p)
        punts = self.vapi.punt_socket_dump(is_ip6=0)
        self.assertEqual(len(punts), 0)

    def test_punt_socket_traffic_multi_ports_single_socket(self):
        """ Punt socket traffic multi ports and single socket"""

        for p in self.ports:
            self.portsCheck[p] = 0

        #
        # create stream with random pakets count per given ports
        #
        pkts = list()
        for _ in range(0, self.nr_packets):
            # choose port from port list
            p = random.choice(self.ports)
            pkts.append((
                Ether(src=self.pg0.remote_mac,
                      dst=self.pg0.local_mac) /
                IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) /
                UDP(sport=9876, dport=p) /
                Raw('\xa5' * 100)))
            self.portsCheck[p] += 1

        #
        # no punt socket
        #
        punts = self.vapi.punt_socket_dump(is_ip6=0)
        self.assertEqual(len(punts), 0)

        # configure a punt socket
        #
        self.socket_client_create(self.tempdir+"/socket_multi")
        for p in self.ports:
            self.vapi.punt_socket_register(p, self.tempdir+"/socket_multi")
        punts = self.vapi.punt_socket_dump(is_ip6=0)
        self.assertEqual(len(punts), len(self.ports))

        for p in self.ports:
            self.logger.debug("Sending %s packets to port %d",
                              str(self.portsCheck[p]), p)
        #
        # expect punt socket and no packets on pg0
        #
        self.vapi.cli("clear errors")
        self.vapi.cli("clear trace")
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg0.get_capture(0)
        self.logger.info(self.vapi.cli("show trace"))
        self.socket_client_close()

        for p in self.ports:
            self.assertEqual(self.portsCheck[p], 0)
            self.vapi.punt_socket_deregister(p)
        punts = self.vapi.punt_socket_dump(is_ip6=0)
        self.assertEqual(len(punts), 0)


class TestIP6PuntSocket(TestPuntSocket):
    """ Punt Socket for IPv6"""

    def setUp(self):
        super(TestIP6PuntSocket, self).setUp()

        for i in self.pg_interfaces:
            i.config_ip6()
            i.resolve_ndp()

    def tearDown(self):
        super(TestIP6PuntSocket, self).tearDown()
        for i in self.pg_interfaces:
            i.unconfig_ip6()
            i.admin_down()

    def test_punt_socket_dump(self):
        """ Punt socket registration """

        punts = self.vapi.punt_socket_dump(is_ip6=1)
        self.assertEqual(len(punts), 0)

        #
        # configure a punt socket
        #
        self.vapi.punt_socket_register(1111, self.tempdir+"/socket_1111",
                                       is_ip4=0)
        self.vapi.punt_socket_register(2222, self.tempdir+"/socket_2222",
                                       is_ip4=0)
        punts = self.vapi.punt_socket_dump(is_ip6=1)
        self.assertEqual(len(punts), 2)
        self.assertEqual(punts[0].punt.l4_port, 1111)
        self.assertEqual(punts[1].punt.l4_port, 2222)

        #
        # deregister a punt socket
        #
        self.vapi.punt_socket_deregister(1111, is_ip4=0)
        punts = self.vapi.punt_socket_dump(is_ip6=1)
        self.assertEqual(len(punts), 1)

        #
        # configure a punt socket again
        #
        self.vapi.punt_socket_register(1111, self.tempdir+"/socket_1111",
                                       is_ip4=0)
        punts = self.vapi.punt_socket_dump(is_ip6=1)
        self.assertEqual(len(punts), 2)

        #
        # deregister all punt socket
        #
        self.vapi.punt_socket_deregister(1111, is_ip4=0)
        self.vapi.punt_socket_deregister(2222, is_ip4=0)
        self.vapi.punt_socket_deregister(3333, is_ip4=0)
        punts = self.vapi.punt_socket_dump(is_ip6=1)
        self.assertEqual(len(punts), 0)

    def test_punt_socket_traffic_single_port_single_socket(self):
        """ Punt socket traffic single port single socket"""

        port = self.ports[0]

        p = (Ether(src=self.pg0.remote_mac,
                   dst=self.pg0.local_mac) /
             IPv6(src=self.pg0.remote_ip6, dst=self.pg0.local_ip6) /
             inet6.UDP(sport=9876, dport=port) /
             Raw('\xa5' * 100))

        pkts = p * self.nr_packets
        self.portsCheck[port] = self.nr_packets

        punts = self.vapi.punt_socket_dump(is_ip6=1)
        self.assertEqual(len(punts), 0)

        #
        # expect ICMPv6 - destination unreachable for all packets
        #
        self.vapi.cli("clear trace")
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        # FIXME - when punt socket deregister is implemented
        # rx = self.pg0.get_capture(self.nr_packets)
        # for p in rx:
        #     self.assertEqual(int(p[IPv6].nh), 58)                # ICMPv6
        #     self.assertEqual(int(p[ICMPv6DestUnreach].code),4)  # unreachable

        #
        # configure a punt socket
        #
        self.socket_client_create(self.tempdir+"/socket_" + str(port))
        self.vapi.punt_socket_register(port, self.tempdir+"/socket_" +
                                       str(port), is_ip4=0)
        punts = self.vapi.punt_socket_dump(is_ip6=1)
        self.assertEqual(len(punts), 1)

        self.logger.debug("Sending %s packets to port %d",
                          str(self.portsCheck[port]), port)
        #
        # expect punt socket and no packets on pg0
        #
        self.vapi.cli("clear errors")
        self.vapi.cli("clear trace")
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg0.get_capture(0)
        self.logger.info(self.vapi.cli("show trace"))
        self.socket_client_close()
        self.assertEqual(self.portsCheck[port], 0)

        #
        # remove punt socket. expect ICMP - dest. unreachable for all packets
        #
        self.vapi.punt_socket_deregister(port, is_ip4=0)
        punts = self.vapi.punt_socket_dump(is_ip6=1)
        self.assertEqual(len(punts), 0)
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        # FIXME - when punt socket deregister is implemented
        # self.pg0.get_capture(nr_packets)

    def test_punt_socket_traffic_multi_port_multi_sockets(self):
        """ Punt socket traffic multi ports and multi sockets"""

        for p in self.ports:
            self.portsCheck[p] = 0

        #
        # create stream with random pakets count per given ports
        #
        pkts = list()
        for _ in range(0, self.nr_packets):
            # choose port from port list
            p = random.choice(self.ports)
            pkts.append((
                Ether(src=self.pg0.remote_mac,
                      dst=self.pg0.local_mac) /
                IPv6(src=self.pg0.remote_ip6, dst=self.pg0.local_ip6) /
                inet6.UDP(sport=9876, dport=p) /
                Raw('\xa5' * 100)))
            self.portsCheck[p] += 1
        #
        # no punt socket
        #
        punts = self.vapi.punt_socket_dump(is_ip6=1)
        self.assertEqual(len(punts), 0)

        #
        # configure a punt socket
        #
        for p in self.ports:
            self.socket_client_create(self.tempdir+"/socket_" + str(p))
            self.vapi.punt_socket_register(p, self.tempdir+"/socket_" + str(p),
                                           is_ip4=0)
        punts = self.vapi.punt_socket_dump(is_ip6=1)
        self.assertEqual(len(punts), len(self.ports))

        for p in self.ports:
            self.logger.debug("Sending %s packets to port %d",
                              str(self.portsCheck[p]), p)

        #
        # expect punt socket and no packets on pg0
        #
        self.vapi.cli("clear errors")
        self.vapi.cli("clear trace")
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg0.get_capture(0)
        self.logger.info(self.vapi.cli("show trace"))
        self.socket_client_close()

        for p in self.ports:
            self.assertEqual(self.portsCheck[p], 0)
            self.vapi.punt_socket_deregister(p, is_ip4=0)
        punts = self.vapi.punt_socket_dump(is_ip6=1)
        self.assertEqual(len(punts), 0)

    def test_punt_socket_traffic_multi_ports_single_socket(self):
        """ Punt socket traffic multi ports and single socket"""

        for p in self.ports:
            self.portsCheck[p] = 0

        #
        # create stream with random pakets count per given ports
        #
        pkts = list()
        for _ in range(0, self.nr_packets):
            # choose port from port list
            p = random.choice(self.ports)
            pkts.append((
                Ether(src=self.pg0.remote_mac,
                      dst=self.pg0.local_mac) /
                IPv6(src=self.pg0.remote_ip6, dst=self.pg0.local_ip6) /
                inet6.UDP(sport=9876, dport=p) /
                Raw('\xa5' * 100)))
            self.portsCheck[p] += 1

        #
        # no punt socket
        #
        punts = self.vapi.punt_socket_dump(is_ip6=1)
        self.assertEqual(len(punts), 0)

        #
        # configure a punt socket
        #
        self.socket_client_create(self.tempdir+"/socket_multi")
        for p in self.ports:
            self.vapi.punt_socket_register(p, self.tempdir+"/socket_multi",
                                           is_ip4=0)
        punts = self.vapi.punt_socket_dump(is_ip6=1)
        self.assertEqual(len(punts), len(self.ports))

        for p in self.ports:
            self.logger.debug("Send %s packets to port %d",
                              str(self.portsCheck[p]), p)
        #
        # expect punt socket and no packets on pg0
        #
        self.vapi.cli("clear errors")
        self.vapi.cli("clear trace")
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.pg0.get_capture(0)
        self.logger.info(self.vapi.cli("show trace"))
        self.socket_client_close()

        for p in self.ports:
            self.assertEqual(self.portsCheck[p], 0)
            self.vapi.punt_socket_deregister(p, is_ip4=0)
        punts = self.vapi.punt_socket_dump(is_ip6=1)
        self.assertEqual(len(punts), 0)

if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
