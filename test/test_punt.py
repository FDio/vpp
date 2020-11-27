#!/usr/bin/env python3
import binascii
import random
import socket
import os
import threading
import struct
import copy
import fcntl
import time

from struct import unpack, unpack_from

try:
    import unittest2 as unittest
except ImportError:
    import unittest

from util import ppp, ppc
from re import compile
import scapy.compat
from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, ICMP
from scapy.layers.ipsec import ESP
import scapy.layers.inet6 as inet6
from scapy.layers.inet6 import IPv6, ICMPv6DestUnreach
from scapy.contrib.ospf import OSPF_Hdr, OSPFv3_Hello
from framework import VppTestCase, VppTestRunner

from vpp_ip import DpoProto
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_papi import VppEnum
from vpp_ipsec_tun_interface import VppIpsecTunInterface
from vpp_punt import PuntIpProto, PuntL4, PuntException, VppPuntSocket, \
    Punt

NUM_PKTS = 67


class serverSocketThread(threading.Thread):
    """ Socket server thread"""

    def __init__(self, threadID, sockName):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.sockName = sockName
        self.sock = None
        self.rx_pkts = []
        self.keep_running = True

    def rx_packets(self):
        # Wait for some packets on socket
        while self.keep_running:
            try:
                data = self.sock.recv(65536)

                # punt socket metadata
                # packet_desc = data[0:8]

                # Ethernet
                self.rx_pkts.append(Ether(data[8:]))
            except IOError as e:
                if e.errno == 11:
                    # nothing to receive, sleep a little
                    time.sleep(0.1)
                    pass
                else:
                    raise

    def run(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            os.unlink(self.sockName)
        except:
            pass
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
        fcntl.fcntl(self.sock, fcntl.F_SETFL, os.O_NONBLOCK)
        self.sock.bind(self.sockName)

        self.rx_packets()

    def close(self):
        self.sock.close()
        self.keep_running = False
        return self.rx_pkts


class TestPuntSocket(VppTestCase):
    """ Punt Socket """

    ports = [1111, 2222, 3333, 4444]
    sock_servers = list()
    # FIXME: nr_packets > 3 results in failure
    # nr_packets = 3 makes the test unstable
    nr_packets = 2

    @classmethod
    def setUpClass(cls):
        super(TestPuntSocket, cls).setUpClass()
        Punt.init_feature_class(cls.vapi)

    @classmethod
    def tearDownClass(cls):
        super(TestPuntSocket, cls).tearDownClass()

    @classmethod
    def setUpConstants(cls):
        cls.extra_vpp_punt_config = [
            "punt", "{", "socket", cls.tempdir+"/socket_punt", "}"]
        super(TestPuntSocket, cls).setUpConstants()

    def setUp(self):
        super(TestPuntSocket, self).setUp()
        random.seed()

        self.create_pg_interfaces(range(2))
        for i in self.pg_interfaces:
            i.admin_up()

    def tearDown(self):
        del self.sock_servers[:]
        super(TestPuntSocket, self).tearDown()

    def socket_client_create(self, sock_name, id=None):
        thread = serverSocketThread(id, sock_name)
        self.sock_servers.append(thread)
        thread.start()
        return thread

    def socket_client_close(self):
        rx_pkts = []
        for thread in self.sock_servers:
            rx_pkts += thread.close()
            thread.join()
        return rx_pkts

    def verify_udp_pkts(self, rxs, n_rx, port):
        n_match = 0
        for rx in rxs:
            self.assertTrue(rx.haslayer(UDP))
            if rx[UDP].dport == port:
                n_match += 1
        self.assertEqual(n_match, n_rx)

    def _test_punt_socket_dump(self, punt_sockets):
        if len(punt_sockets) < 2:
            raise ValueError("Requires minimum of 2 punt sockets")
        punt_type = punt_sockets[0].punt.type

        #
        # Verify no punt sockets are present
        #
        punts = Punt.dump(punt_type)
        self.assertEqual(len(punts), 0)

        #
        # Configure punt sockets
        #
        for ps in punt_sockets[:2]:
            ps.add_vpp_config()

        #
        # Verify configuration
        #
        punts = Punt.dump_to_punt(Punt.dump(punt_type))
        self.assertEqual(len(punts), 2)
        for idx in range(2):
            self.assertEqual(punts[idx], punt_sockets[idx].punt)

        #
        # Remove punt socket
        #
        punt_sockets[1].remove_vpp_config()
        punts = Punt.dump_to_punt(Punt.dump(punt_type))
        self.assertEqual(len(punts), 1)
        self.assertEqual(punt_sockets[0].punt, punts[0])

        #
        # Add more punt sockets
        #
        for ps in punt_sockets[1:]:
            ps.add_vpp_config()
        punts = Punt.dump(punt_type)
        self.assertEqual(len(punts), len(punt_sockets))
        #
        # Verify configuration
        #
        punts = Punt.dump_to_punt(punts)
        for ps in punt_sockets:
            self.assertTrue(ps.punt in punts)

        #
        # Remove all punt sockets
        #
        for ps in punt_sockets:
            ps.remove_vpp_config()
        punts = Punt.dump(punt_type)
        self.assertEqual(len(punts), 0)

    def _test_traffic_sport_ssocket(
            self, punt_socket, pkt, test_ports):
        """ Punt socket traffic single port single socket"""

        pkts = pkt * self.nr_packets

        punts = Punt.dump(punt_socket.punt.type)
        self.assertEqual(len(punts), 0)

        #
        # expect ICMP - port unreachable for all packets
        #
        rx = self.send_and_expect(self.pg0, pkts, self.pg0)
        test_ports(rx)

        #
        # configure a punt socket
        #
        self.socket_client_create(punt_socket.pathname)
        punt_socket.add_vpp_config()
        punts = Punt.dump(punt_socket.punt.type)
        self.assertEqual(len(punts), 1)

        #
        # expect punt socket and no packets on pg0
        #
        self.send_and_assert_no_replies(self.pg0, pkts)
        rx = self.socket_client_close()
        self.verify_udp_pkts(rx, len(pkts), punt_socket.punt.port)

        #
        # remove punt socket. expect ICMP - port unreachable for all packets
        #
        punt_socket.remove_vpp_config()
        punts = Punt.dump(punt_socket.punt.type)
        self.assertEqual(len(punts), 0)

        rx = self.send_and_expect(self.pg0, pkts, self.pg0)
        test_ports(rx)


class TestIP4PuntSocket(TestPuntSocket):
    """ Punt Socket for IPv4 UDP """

    @classmethod
    def setUpClass(cls):
        super(TestIP4PuntSocket, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestIP4PuntSocket, cls).tearDownClass()

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

        af_ip4 = VppEnum.vl_api_address_family_t.ADDRESS_IP4
        udp_proto = VppEnum.vl_api_ip_proto_t.IP_API_PROTO_UDP

        #
        # configure a punt socket
        #
        punt_socket_1 = VppPuntSocket(self, PuntL4(
            af_ip4, udp_proto, 1111), "%s/socket_punt_1111" % self.tempdir)
        punt_socket_2 = VppPuntSocket(self, PuntL4(
            af_ip4, udp_proto, 2222), "%s/socket_punt_2222" % self.tempdir)
        punt_socket_3 = VppPuntSocket(self, PuntL4(
            af_ip4, udp_proto, 3333), "%s/socket_punt_3333" % self.tempdir)

        super(TestIP4PuntSocket, self)._test_punt_socket_dump([punt_socket_1,
                                                               punt_socket_2,
                                                               punt_socket_3])

    def _test_ports(self, rx):
        for p in rx:
            self.assertEqual(int(p[IP].proto), 1)   # ICMP
            self.assertEqual(int(p[ICMP].code), 3)  # unreachable

    def test_punt_socket_traffic_single_port_single_socket(self):
        """ Punt socket traffic single port single socket"""

        port = self.ports[0]
        af_ip4 = VppEnum.vl_api_address_family_t.ADDRESS_IP4
        udp_proto = VppEnum.vl_api_ip_proto_t.IP_API_PROTO_UDP

        punt_socket = VppPuntSocket(self, PuntL4(af_ip4, udp_proto, port),
                                    "%s/socket_%d" % (self.tempdir, port))

        pkt = (Ether(src=self.pg0.remote_mac,
                     dst=self.pg0.local_mac) /
               IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) /
               UDP(sport=9876, dport=port) /
               Raw(b'\xa5' * 100))

        super(TestIP4PuntSocket, self)._test_traffic_sport_ssocket(
            punt_socket, pkt, self._test_ports)

    def test_punt_socket_traffic_multi_ports_multi_sockets(self):
        """ Punt socket traffic multi ports and multi sockets"""

        af_ip4 = VppEnum.vl_api_address_family_t.ADDRESS_IP4
        udp_proto = VppEnum.vl_api_ip_proto_t.IP_API_PROTO_UDP

        punt_l4 = PuntL4(af_ip4, udp_proto, 0)
        punt_socket = VppPuntSocket(self, punt_l4, None)

        # configuration for each UDP port
        cfgs = dict()

        #
        # create stream of packets for each port
        #
        for port in self.ports:
            # choose port from port list
            cfgs[port] = {}

            pkt = (Ether(src=self.pg0.remote_mac,
                         dst=self.pg0.local_mac) /
                   IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) /
                   UDP(sport=9876, dport=port) /
                   Raw(b'\xa5' * 100))
            cfgs[port]['pkts'] = pkt * self.nr_packets
            cfgs[port]['port'] = port

            # configure punt sockets
            cfgs[port]['sock'] = self.socket_client_create(
                "%s/socket_%d" % (self.tempdir, port))
            cfgs[port]['vpp'] = VppPuntSocket(
                self, PuntL4(af_ip4, udp_proto, port), "%s/socket_%d" %
                (self.tempdir, port))
            cfgs[port]['vpp'].add_vpp_config()

        #
        # send the packets that get punted
        #
        for cfg in cfgs.values():
            self.send_and_assert_no_replies(self.pg0, cfg['pkts'])

        #
        # test that we got the excepted packets on the expected socket
        #
        for cfg in cfgs.values():
            rx = cfg['sock'].close()
            self.verify_udp_pkts(rx, len(cfg['pkts']), cfg['port'])
            cfg['vpp'].remove_vpp_config()

    def test_punt_socket_traffic_multi_ports_single_socket(self):
        """ Punt socket traffic multi ports and single socket"""

        af_ip4 = VppEnum.vl_api_address_family_t.ADDRESS_IP4
        udp_proto = VppEnum.vl_api_ip_proto_t.IP_API_PROTO_UDP

        #
        # create stream of packets with each port
        #
        pkts = []
        for port in self.ports:
            # choose port from port list
            pkt = (Ether(src=self.pg0.remote_mac,
                         dst=self.pg0.local_mac) /
                   IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) /
                   UDP(sport=9876, dport=port) /
                   Raw(b'\xa5' * 100))
            pkts += pkt * self.nr_packets

        #
        # configure a punt socket
        #
        self.socket_client_create("%s/socket_multi" % self.tempdir)
        punt_sockets = []
        for p in self.ports:
            sock = VppPuntSocket(self, PuntL4(af_ip4, udp_proto, p),
                                 "%s/socket_multi" % self.tempdir)
            sock.add_vpp_config()
            punt_sockets.append(sock)
        punts = Punt.dump(punt_type=Punt.type_l4)
        self.assertEqual(len(punts), len(self.ports))

        #
        # expect punt socket and no packets on pg0
        #
        self.send_and_assert_no_replies(self.pg0, pkts)
        self.logger.info(self.vapi.cli("show trace"))
        rx = self.socket_client_close()

        for p in self.ports:
            self.verify_udp_pkts(rx, self.nr_packets, p)
        for s in punt_sockets:
            s.remove_vpp_config()
        punts = Punt.dump(punt_type=Punt.type_l4)
        self.assertEqual(len(punts), 0)


class TestIP6PuntSocket(TestPuntSocket):
    """ Punt Socket for IPv6 UDP """

    @classmethod
    def setUpClass(cls):
        super(TestIP6PuntSocket, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestIP6PuntSocket, cls).tearDownClass()

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

        af_ip6 = VppEnum.vl_api_address_family_t.ADDRESS_IP6
        udp_proto = VppEnum.vl_api_ip_proto_t.IP_API_PROTO_UDP
        #
        # configure a punt socket
        #
        punt_socket_1 = VppPuntSocket(self, PuntL4(af_ip6, udp_proto, 1111),
                                      "%s/socket_1111" % self.tempdir)
        punt_socket_2 = VppPuntSocket(self, PuntL4(af_ip6, udp_proto, 2222),
                                      "%s/socket_2222" % self.tempdir)
        punt_socket_3 = VppPuntSocket(self, PuntL4(af_ip6, udp_proto, 3333),
                                      "%s/socket_3333" % self.tempdir)

        super(TestIP6PuntSocket, self)._test_punt_socket_dump([punt_socket_1,
                                                               punt_socket_2,
                                                               punt_socket_3])

    def _test_ports(self, rx):
        # FIXME - when punt socket deregister is implemented
        # rx = self.pg0.get_capture(self.nr_packets)
        # for p in rx:
        #     self.assertEqual(int(p[IPv6].nh), 58)                # ICMPv6
        #     self.assertEqual(int(p[ICMPv6DestUnreach].code),4)  # unreachable
        pass

    def test_punt_socket_traffic_single_port_single_socket(self):
        """ Punt socket traffic single port single socket"""

        port = self.ports[0]
        af_ip6 = VppEnum.vl_api_address_family_t.ADDRESS_IP6
        udp_proto = VppEnum.vl_api_ip_proto_t.IP_API_PROTO_UDP

        punt_socket = VppPuntSocket(self, PuntL4(af_ip6, udp_proto, port),
                                    "%s/socket_%d" % (self.tempdir, port))

        pkt = (Ether(src=self.pg0.remote_mac,
                     dst=self.pg0.local_mac) /
               IPv6(src=self.pg0.remote_ip6, dst=self.pg0.local_ip6) /
               inet6.UDP(sport=9876, dport=port) /
               Raw(b'\xa5' * 100))

        super(TestIP6PuntSocket, self)._test_traffic_sport_ssocket(
            punt_socket, pkt, self._test_ports)

    def test_punt_socket_traffic_multi_ports_multi_sockets(self):
        """ Punt socket traffic multi ports and multi sockets"""

        af_ip6 = VppEnum.vl_api_address_family_t.ADDRESS_IP6
        udp_proto = VppEnum.vl_api_ip_proto_t.IP_API_PROTO_UDP

        # configuration for each UDP port
        cfgs = dict()

        #
        # create stream of packets for each port
        #
        for port in self.ports:
            # choose port from port list
            cfgs[port] = {}

            pkt = (Ether(src=self.pg0.remote_mac,
                         dst=self.pg0.local_mac) /
                   IPv6(src=self.pg0.remote_ip6, dst=self.pg0.local_ip6) /
                   UDP(sport=9876, dport=port) /
                   Raw(b'\xa5' * 100))
            cfgs[port]['pkts'] = pkt * self.nr_packets
            cfgs[port]['port'] = port

            # configure punt sockets
            cfgs[port]['sock'] = self.socket_client_create(
                "%s/socket_%d" % (self.tempdir, port))
            cfgs[port]['vpp'] = VppPuntSocket(
                self, PuntL4(af_ip6, udp_proto, port), "%s/socket_%d" %
                (self.tempdir, port))
            cfgs[port]['vpp'].add_vpp_config()

        #
        # send the packets that get punted
        #
        for cfg in cfgs.values():
            self.send_and_assert_no_replies(self.pg0, cfg['pkts'])

        #
        # test that we got the excepted packets on the expected socket
        #
        for cfg in cfgs.values():
            rx = cfg['sock'].close()
            self.verify_udp_pkts(rx, len(cfg['pkts']), cfg['port'])
            cfg['vpp'].remove_vpp_config()

    def test_punt_socket_traffic_multi_ports_single_socket(self):
        """ Punt socket traffic multi ports and single socket"""

        af_ip6 = VppEnum.vl_api_address_family_t.ADDRESS_IP6
        udp_proto = VppEnum.vl_api_ip_proto_t.IP_API_PROTO_UDP

        #
        # create stream of packets with each port
        #
        pkts = []
        for port in self.ports:
            # choose port from port list
            pkt = (Ether(src=self.pg0.remote_mac,
                         dst=self.pg0.local_mac) /
                   IPv6(src=self.pg0.remote_ip6, dst=self.pg0.local_ip6) /
                   UDP(sport=9876, dport=port) /
                   Raw(b'\xa5' * 100))
            pkts += pkt * self.nr_packets

        #
        # no punt socket
        #
        punts = Punt.dump(Punt.type_l4)
        self.assertEqual(len(punts), 0)

        #
        # configure a punt socket
        #
        self.socket_client_create("%s/socket_multi" % self.tempdir)
        punt_sockets = []
        for p in self.ports:
            sock = VppPuntSocket(self, PuntL4(af_ip6, udp_proto, p),
                                 "%s/socket_multi" % self.tempdir)
            sock.add_vpp_config()
            punt_sockets.append(sock)
        punts = Punt.dump(Punt.type_l4)
        self.assertEqual(len(punts), len(self.ports))

        #
        # expect punt socket and no packets on pg0
        #
        self.vapi.cli("clear errors")
        self.vapi.cli("clear trace")
        self.pg0.add_stream(pkts)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        # give a chance to punt socket to collect all packets
        self.sleep(1)
        self.pg0.get_capture(0)
        rx = self.socket_client_close()

        for p in self.ports:
            self.verify_udp_pkts(rx, self.nr_packets, p)
        for sock in punt_sockets:
            sock.remove_vpp_config()
        punts = Punt.dump(Punt.type_l4)
        self.assertEqual(len(punts), 0)


class TestExceptionPuntSocket(TestPuntSocket):
    """ Punt Socket for Exceptions """

    @classmethod
    def setUpClass(cls):
        super(TestExceptionPuntSocket, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestExceptionPuntSocket, cls).tearDownClass()

    def setUp(self):
        super(TestExceptionPuntSocket, self).setUp()

        self.create_pg_interfaces(range(2))
        for i in self.pg_interfaces:
            i.config_ip4()
            i.resolve_arp()

    def tearDown(self):
        super(TestExceptionPuntSocket, self).tearDown()
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.admin_down()

    def test_registration(self):
        """ Punt socket registration/deregistration"""

        punts = Punt.dump(Punt.type_exception)
        self.assertEqual(len(punts), 0)

        #
        # configure a punt socket
        #
        punt_socket_1 = VppPuntSocket(self, PuntException(1),
                                      "%s/socket_punt_1" % self.tempdir)
        punt_socket_2 = VppPuntSocket(self, PuntException(2),
                                      "%s/socket_punt_2" % self.tempdir)
        punt_socket_3 = VppPuntSocket(self, PuntException(3),
                                      "%s/socket_punt_3" % self.tempdir)

        super(TestExceptionPuntSocket, self)._test_punt_socket_dump(
            [punt_socket_1, punt_socket_2, punt_socket_3])

    def verify_esp_pkts(self, rxs, n_sent, spi, has_udp):
        self.assertEqual(len(rxs), n_sent)
        for rx in rxs:
            self.assertTrue(rx.haslayer(IP))
            self.assertTrue(rx.haslayer(ESP))
            self.assertEqual(rx[ESP].spi, spi)
            if has_udp:
                self.assertTrue(rx.haslayer(UDP))

    def test_traffic(self):
        """ Punt socket traffic """

        #
        # we're dealing with IPSec tunnels punting for no-such-tunnel
        # (SPI=0 goes to ikev2)
        #
        cfgs = dict()
        cfgs['ipsec4-no-such-tunnel'] = {'spi': 99,
                                         'udp': False,
                                         'itf': self.pg0}

        #
        # find the VPP ID for these punt exception reasin
        #
        rs = Punt.dump_reason()
        for key in cfgs:
            for r in rs:
                print(r.reason.name)
                print(key)
                if r.reason.name == key:
                    cfgs[key]['id'] = r.reason.id
                    cfgs[key]['vpp'] = VppPuntSocket(
                        self, PuntException(r.reason.id), "%s/socket_%d" %
                        (self.tempdir, r.reason.id))
                    break

        #
        # configure punt sockets
        #
        for cfg in cfgs.values():
            cfg['sock'] = self.socket_client_create("%s/socket_%d" %
                                                    (self.tempdir, cfg['id']))
            cfg['vpp'].add_vpp_config()

        #
        # create packet streams for 'no-such-tunnel' exception
        #
        for cfg in cfgs.values():
            pkt = (Ether(src=cfg['itf'].remote_mac,
                         dst=cfg['itf'].local_mac) /
                   IP(src=cfg['itf'].remote_ip4,
                      dst=cfg['itf'].local_ip4))
            if (cfg['udp']):
                pkt = pkt / UDP(sport=666, dport=4500)
            pkt = (pkt / ESP(spi=cfg['spi'], seq=3) /
                   Raw(b'\xa5' * 100))
            cfg['pkts'] = [pkt]

        #
        # send packets for each SPI we expect to be punted
        #
        for cfg in cfgs.values():
            self.send_and_assert_no_replies(cfg['itf'], cfg['pkts'])

        #
        # verify the punted packets arrived on the associated socket
        #
        for cfg in cfgs.values():
            rx = cfg['sock'].close()
            self.verify_esp_pkts(rx, len(cfg['pkts']),
                                 cfg['spi'], cfg['udp'])

        #
        # add some tunnels, make sure it still punts
        #
        VppIpsecTunInterface(self, self.pg0, 1000, 1000,
                             (VppEnum.vl_api_ipsec_crypto_alg_t.
                              IPSEC_API_CRYPTO_ALG_AES_CBC_128),
                             b"0123456701234567",
                             b"0123456701234567",
                             (VppEnum.vl_api_ipsec_integ_alg_t.
                              IPSEC_API_INTEG_ALG_SHA1_96),
                             b"0123456701234567",
                             b"0123456701234567").add_vpp_config()
        VppIpsecTunInterface(self, self.pg1, 1000, 1000,
                             (VppEnum.vl_api_ipsec_crypto_alg_t.
                              IPSEC_API_CRYPTO_ALG_AES_CBC_128),
                             b"0123456701234567",
                             b"0123456701234567",
                             (VppEnum.vl_api_ipsec_integ_alg_t.
                              IPSEC_API_INTEG_ALG_SHA1_96),
                             b"0123456701234567",
                             b"0123456701234567",
                             udp_encap=True).add_vpp_config()

        #
        # send packets for each SPI we expect to be punted
        #
        for cfg in cfgs.values():
            self.send_and_assert_no_replies(cfg['itf'], cfg['pkts'])

        #
        # verify the punted packets arrived on the associated socket
        #
        for cfg in cfgs.values():
            rx = cfg['sock'].close()
            self.verify_esp_pkts(rx, len(cfg['pkts']),
                                 cfg['spi'], cfg['udp'])


class TestIpProtoPuntSocket(TestPuntSocket):
    """ Punt Socket for IP packets """

    @classmethod
    def setUpClass(cls):
        super(TestIpProtoPuntSocket, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestIpProtoPuntSocket, cls).tearDownClass()

    def setUp(self):
        super(TestIpProtoPuntSocket, self).setUp()

        for i in self.pg_interfaces:
            i.config_ip4()
            i.resolve_arp()

    def tearDown(self):
        super(TestIpProtoPuntSocket, self).tearDown()
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.admin_down()

    def test_registration(self):
        """ Punt socket registration/deregistration"""

        af_ip4 = VppEnum.vl_api_address_family_t.ADDRESS_IP4
        proto_ospf = VppEnum.vl_api_ip_proto_t.IP_API_PROTO_OSPF
        proto_eigrp = VppEnum.vl_api_ip_proto_t.IP_API_PROTO_EIGRP

        #
        # configure a punt socket
        #
        punt_socket_1 = VppPuntSocket(self, PuntIpProto(af_ip4, proto_ospf),
                                      "%s/socket_punt_1" % self.tempdir)
        punt_socket_2 = VppPuntSocket(self, PuntIpProto(af_ip4, proto_eigrp),
                                      "%s/socket_punt_2" % self.tempdir)

        super(TestIpProtoPuntSocket, self)._test_punt_socket_dump(
            [punt_socket_1, punt_socket_2])

    def verify_ospf_pkts(self, rxs, n_sent):
        self.assertEqual(len(rxs), n_sent)
        for rx in rxs:
            self.assertTrue(rx.haslayer(OSPF_Hdr))

    def test_traffic(self):
        """ Punt socket traffic """

        af_ip4 = VppEnum.vl_api_address_family_t.ADDRESS_IP4
        proto_ospf = VppEnum.vl_api_ip_proto_t.IP_API_PROTO_OSPF

        #
        # create packet streams and configure a punt sockets
        #
        pkt = (Ether(src=self.pg0.remote_mac,
                     dst=self.pg0.local_mac) /
               IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4) /
               OSPF_Hdr() /
               OSPFv3_Hello())
        pkts = pkt * 7

        #
        # configure a punt socket to capture OSPF packets
        #
        sock = self.socket_client_create("%s/socket_1" % self.tempdir)
        punt_socket = VppPuntSocket(self, PuntIpProto(af_ip4, proto_ospf),
                                    "%s/socket_1" % self.tempdir)
        punt_socket.add_vpp_config()

        #
        # send packets for each SPI we expect to be punted
        #
        self.send_and_assert_no_replies(self.pg0, pkts)

        #
        # verify the punted packets arrived on the associated socket
        #
        rx = sock.close()
        self.verify_ospf_pkts(rx, len(pkts))


class TestPunt(VppTestCase):
    """ Exception Punt Test Case """

    @classmethod
    def setUpClass(cls):
        super(TestPunt, cls).setUpClass()
        Punt.init_feature_class(cls.vapi)

    @classmethod
    def tearDownClass(cls):
        super(TestPunt, cls).tearDownClass()

    def setUp(self):
        super(TestPunt, self).setUp()

        self.create_pg_interfaces(range(4))

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()
            i.config_ip6()
            i.resolve_ndp()

    def tearDown(self):
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.admin_down()
        super(TestPunt, self).tearDown()

    def test_punt(self):
        """ Exception Path testing """

        #
        # dump the punt registered reasons
        #  search for a few we know should be there
        #
        rs = Punt.dump_reason()

        reasons = ["ipsec6-no-such-tunnel",
                   "ipsec4-no-such-tunnel",
                   "ipsec4-spi-o-udp-0"]

        for reason in reasons:
            found = False
            for r in rs:
                if r.reason.name == reason:
                    found = True
                    break
            self.assertTrue(found)

        #
        # Using the test CLI we will hook in a exception path to
        # send ACL deny packets out of pg0 and pg1.
        # the ACL is src,dst = 1.1.1.1,1.1.1.2
        #
        ip_1_1_1_2 = VppIpRoute(self, "1.1.1.2", 32,
                                [VppRoutePath(self.pg3.remote_ip4,
                                              self.pg3.sw_if_index)])
        ip_1_1_1_2.add_vpp_config()
        ip_1_2 = VppIpRoute(self, "1::2", 128,
                            [VppRoutePath(self.pg3.remote_ip6,
                                          self.pg3.sw_if_index,
                                          proto=DpoProto.DPO_PROTO_IP6)])
        ip_1_2.add_vpp_config()

        p4 = (Ether(src=self.pg2.remote_mac,
                    dst=self.pg2.local_mac) /
              IP(src="1.1.1.1", dst="1.1.1.2") /
              UDP(sport=1234, dport=1234) /
              Raw(b'\xa5' * 100))
        p6 = (Ether(src=self.pg2.remote_mac,
                    dst=self.pg2.local_mac) /
              IPv6(src="1::1", dst="1::2") /
              UDP(sport=1234, dport=1234) /
              Raw(b'\xa5' * 100))
        self.send_and_expect(self.pg2, p4*1, self.pg3)
        self.send_and_expect(self.pg2, p6*1, self.pg3)

        #
        # apply the punting features
        #
        self.vapi.cli("test punt pg2")

        #
        # dump the punt reasons to learn the IDs assigned
        #
        rs = Punt.dump_reason(reason={'name': "reason-v4"})
        r4 = rs[0].reason.id
        rs = Punt.dump_reason(reason={'name': "reason-v6"})
        r6 = rs[0].reason.id

        #
        # pkts now dropped
        #
        self.send_and_assert_no_replies(self.pg2, p4*NUM_PKTS)
        self.send_and_assert_no_replies(self.pg2, p6*NUM_PKTS)

        #
        # Check state:
        #  1 - node error counters
        #  2 - per-reason counters
        #    2, 3 are the index of the assigned punt reason
        #
        stats = self.statistics.get_err_counter(
            "/err/punt-dispatch/No registrations")
        self.assertEqual(stats, 2*NUM_PKTS)

        stats = self.statistics.get_counter("/net/punt")
        self.assertEqual(stats[0][r4]['packets'], NUM_PKTS)
        self.assertEqual(stats[0][r6]['packets'], NUM_PKTS)

        #
        # use the test CLI to test a client that punts exception
        # packets out of pg0
        #
        self.vapi.cli("test punt pg0 %s" % self.pg0.remote_ip4)
        self.vapi.cli("test punt pg0 %s" % self.pg0.remote_ip6)

        rx4s = self.send_and_expect(self.pg2, p4*NUM_PKTS, self.pg0)
        rx6s = self.send_and_expect(self.pg2, p6*NUM_PKTS, self.pg0)

        #
        # check the packets come out IP unmodified but destined to pg0 host
        #
        for rx in rx4s:
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(p4[IP].dst, rx[IP].dst)
            self.assertEqual(p4[IP].ttl, rx[IP].ttl)
        for rx in rx6s:
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(p6[IPv6].dst, rx[IPv6].dst)
            self.assertEqual(p6[IPv6].hlim, rx[IPv6].hlim)

        stats = self.statistics.get_counter("/net/punt")
        self.assertEqual(stats[0][r4]['packets'], 2*NUM_PKTS)
        self.assertEqual(stats[0][r6]['packets'], 2*NUM_PKTS)

        #
        # add another registration for the same reason to send packets
        # out of pg1
        #
        self.vapi.cli("test punt pg1 %s" % self.pg1.remote_ip4)
        self.vapi.cli("test punt pg1 %s" % self.pg1.remote_ip6)

        self.vapi.cli("clear trace")
        self.pg2.add_stream(p4 * NUM_PKTS)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rxd = self.pg0.get_capture(NUM_PKTS)
        for rx in rxd:
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(p4[IP].dst, rx[IP].dst)
            self.assertEqual(p4[IP].ttl, rx[IP].ttl)
        rxd = self.pg1.get_capture(NUM_PKTS)
        for rx in rxd:
            self.assertEqual(rx[Ether].dst, self.pg1.remote_mac)
            self.assertEqual(rx[Ether].src, self.pg1.local_mac)
            self.assertEqual(p4[IP].dst, rx[IP].dst)
            self.assertEqual(p4[IP].ttl, rx[IP].ttl)

        self.vapi.cli("clear trace")
        self.pg2.add_stream(p6 * NUM_PKTS)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        rxd = self.pg0.get_capture(NUM_PKTS)
        for rx in rxd:
            self.assertEqual(rx[Ether].dst, self.pg0.remote_mac)
            self.assertEqual(rx[Ether].src, self.pg0.local_mac)
            self.assertEqual(p6[IPv6].dst, rx[IPv6].dst)
            self.assertEqual(p6[IPv6].hlim, rx[IPv6].hlim)
        rxd = self.pg1.get_capture(NUM_PKTS)
        for rx in rxd:
            self.assertEqual(rx[Ether].dst, self.pg1.remote_mac)
            self.assertEqual(rx[Ether].src, self.pg1.local_mac)
            self.assertEqual(p6[IPv6].dst, rx[IPv6].dst)
            self.assertEqual(p6[IPv6].hlim, rx[IPv6].hlim)

        stats = self.statistics.get_counter("/net/punt")
        self.assertEqual(stats[0][r4]['packets'], 3*NUM_PKTS)
        self.assertEqual(stats[0][r6]['packets'], 3*NUM_PKTS)

        self.logger.info(self.vapi.cli("show vlib graph punt-dispatch"))
        self.logger.info(self.vapi.cli("show punt client"))
        self.logger.info(self.vapi.cli("show punt reason"))
        self.logger.info(self.vapi.cli("show punt stats"))
        self.logger.info(self.vapi.cli("show punt db"))


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
