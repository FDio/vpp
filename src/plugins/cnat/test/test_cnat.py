#!/usr/bin/env python3

import unittest

from framework import VppTestCase, VppTestRunner
from vpp_ip import DpoProto, INVALID_INDEX
from itertools import product

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.layers.inet import IPerror, TCPerror, UDPerror, ICMPerror
from scapy.layers.inet6 import IPv6, IPerror6, ICMPv6DestUnreach
from scapy.layers.inet6 import ICMPv6EchoRequest, ICMPv6EchoReply

import struct

from ipaddress import ip_address, ip_network, \
    IPv4Address, IPv6Address, IPv4Network, IPv6Network

from vpp_object import VppObject
from vpp_papi import VppEnum

N_PKTS = 15


class Ep(object):
    """ CNat endpoint """

    def __init__(self, ip=None, port=0, l4p=TCP,
                 sw_if_index=INVALID_INDEX, is_v6=False):
        self.ip = ip
        if ip is None:
            self.ip = "::" if is_v6 else "0.0.0.0"
        self.port = port
        self.l4p = l4p
        self.sw_if_index = sw_if_index
        if is_v6:
            self.if_af = VppEnum.vl_api_address_family_t.ADDRESS_IP6
        else:
            self.if_af = VppEnum.vl_api_address_family_t.ADDRESS_IP4

    def encode(self):
        return {'addr': self.ip,
                'port': self.port,
                'sw_if_index': self.sw_if_index,
                'if_af': self.if_af}

    @classmethod
    def from_pg(cls, pg, is_v6=False):
        if pg is None:
            return cls(is_v6=is_v6)
        else:
            return cls(sw_if_index=pg.sw_if_index, is_v6=is_v6)

    @property
    def isV6(self):
        return ":" in self.ip

    def __str__(self):
        return ("%s:%d" % (self.ip, self.port))


class EpTuple(object):
    """ CNat endpoint """

    def __init__(self, src, dst):
        self.src = src
        self.dst = dst

    def encode(self):
        return {'src_ep': self.src.encode(),
                'dst_ep': self.dst.encode()}

    def __str__(self):
        return ("%s->%s" % (self.src, self.dst))


class VppCNatTranslation(VppObject):

    def __init__(self, test, iproto, vip, paths):
        self._test = test
        self.vip = vip
        self.iproto = iproto
        self.paths = paths
        self.encoded_paths = []
        for path in self.paths:
            self.encoded_paths.append(path.encode())

    def __str__(self):
        return ("%s %s %s" % (self.vip, self.iproto, self.paths))

    @property
    def vl4_proto(self):
        ip_proto = VppEnum.vl_api_ip_proto_t
        return {
            UDP: ip_proto.IP_API_PROTO_UDP,
            TCP: ip_proto.IP_API_PROTO_TCP,
        }[self.iproto]

    def add_vpp_config(self):
        r = self._test.vapi.cnat_translation_update(
            {'vip': self.vip.encode(),
             'ip_proto': self.vl4_proto,
             'n_paths': len(self.paths),
             'paths': self.encoded_paths})
        self._test.registry.register(self, self._test.logger)
        self.id = r.id

    def modify_vpp_config(self, paths):
        self.paths = paths
        self.encoded_paths = []
        for path in self.paths:
            self.encoded_paths.append(path.encode())

        r = self._test.vapi.cnat_translation_update(
            {'vip': self.vip.encode(),
             'ip_proto': self.vl4_proto,
             'n_paths': len(self.paths),
             'paths': self.encoded_paths})
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.cnat_translation_del(id=self.id)

    def query_vpp_config(self):
        for t in self._test.vapi.cnat_translation_dump():
            if self.id == t.translation.id:
                return t.translation
        return None

    def object_id(self):
        return ("cnat-translation-%s" % (self.vip))

    def get_stats(self):
        c = self._test.statistics.get_counter("/net/cnat-translation")
        return c[0][self.id]


class TestCNatTranslation(VppTestCase):
    """ CNat Translation """
    extra_vpp_punt_config = ["cnat", "{",
                             "session-db-buckets", "64",
                             "session-cleanup-timeout", "0.1",
                             "session-max-age", "1",
                             "tcp-max-age", "1",
                             "scanner", "off", "}"]

    @classmethod
    def setUpClass(cls):
        super(TestCNatTranslation, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestCNatTranslation, cls).tearDownClass()

    def setUp(self):
        super(TestCNatTranslation, self).setUp()

        self.create_pg_interfaces(range(3))

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
        super(TestCNatTranslation, self).tearDown()

    def cnat_create_translation(self, vip, nbr):
        ip_v = "ip6" if vip.isV6 else "ip4"
        dep = Ep(getattr(self.pg1.remote_hosts[nbr], ip_v), 4000 + nbr)
        sep = Ep("::", 0) if vip.isV6 else Ep("0.0.0.0", 0)
        t1 = VppCNatTranslation(
            self, vip.l4p, vip,
            [EpTuple(sep, dep), EpTuple(sep, dep)])
        t1.add_vpp_config()
        return t1

    def cnat_test_translation(self, t1, nbr, sports, isV6=False):
        ip_v = "ip6" if isV6 else "ip4"
        ip_class = IPv6 if isV6 else IP
        vip = t1.vip

        #
        # Flows
        #
        for src in self.pg0.remote_hosts:
            for sport in sports:
                # from client to vip
                p1 = (Ether(dst=self.pg0.local_mac,
                            src=src.mac) /
                      ip_class(src=getattr(src, ip_v), dst=vip.ip) /
                      vip.l4p(sport=sport, dport=vip.port) /
                      Raw())

                self.vapi.cli("trace add pg-input 1")
                rxs = self.send_and_expect(self.pg0,
                                           p1 * N_PKTS,
                                           self.pg1)
                self.logger.info(self.vapi.cli("show trace max 1"))

                for rx in rxs:
                    self.assert_packet_checksums_valid(rx)
                    self.assertEqual(
                        rx[ip_class].dst,
                        getattr(self.pg1.remote_hosts[nbr], ip_v))
                    self.assertEqual(rx[vip.l4p].dport, 4000 + nbr)
                    self.assertEqual(
                        rx[ip_class].src,
                        getattr(src, ip_v))
                    self.assertEqual(rx[vip.l4p].sport, sport)

                # from vip to client
                p1 = (Ether(dst=self.pg1.local_mac,
                            src=self.pg1.remote_mac) /
                      ip_class(src=getattr(
                          self.pg1.remote_hosts[nbr],
                          ip_v),
                          dst=getattr(src, ip_v)) /
                      vip.l4p(sport=4000 + nbr, dport=sport) /
                      Raw())

                rxs = self.send_and_expect(self.pg1,
                                           p1 * N_PKTS,
                                           self.pg0)

                for rx in rxs:
                    self.assert_packet_checksums_valid(rx)
                    self.assertEqual(
                        rx[ip_class].dst,
                        getattr(src, ip_v))
                    self.assertEqual(rx[vip.l4p].dport, sport)
                    self.assertEqual(rx[ip_class].src, vip.ip)
                    self.assertEqual(rx[vip.l4p].sport, vip.port)

                #
                # packets to the VIP that do not match a
                # translation are dropped
                #
                p1 = (Ether(dst=self.pg0.local_mac,
                            src=src.mac) /
                      ip_class(src=getattr(src, ip_v), dst=vip.ip) /
                      vip.l4p(sport=sport, dport=6666) /
                      Raw())

                self.send_and_assert_no_replies(self.pg0,
                                                p1 * N_PKTS,
                                                self.pg1)

                #
                # packets from the VIP that do not match a
                # session are forwarded
                #
                p1 = (Ether(dst=self.pg1.local_mac,
                            src=self.pg1.remote_mac) /
                      ip_class(src=getattr(
                          self.pg1.remote_hosts[nbr],
                          ip_v),
                          dst=getattr(src, ip_v)) /
                      vip.l4p(sport=6666, dport=sport) /
                      Raw())

                rxs = self.send_and_expect(self.pg1,
                                           p1 * N_PKTS,
                                           self.pg0)

        self.assertEqual(t1.get_stats()['packets'],
                         N_PKTS *
                         len(sports) *
                         len(self.pg0.remote_hosts))

    def cnat_test_translation_update(self, t1, sports, isV6=False):
        ip_v = "ip6" if isV6 else "ip4"
        ip_class = IPv6 if isV6 else IP
        vip = t1.vip

        #
        # modify the translation to use a different backend
        #
        dep = Ep(getattr(self.pg2, 'remote_' + ip_v), 5000)
        sep = Ep("::", 0) if isV6 else Ep("0.0.0.0", 0)
        t1.modify_vpp_config([EpTuple(sep, dep)])

        #
        # existing flows follow the old path
        #
        for src in self.pg0.remote_hosts:
            for sport in sports:
                # from client to vip
                p1 = (Ether(dst=self.pg0.local_mac,
                            src=src.mac) /
                      ip_class(src=getattr(src, ip_v), dst=vip.ip) /
                      vip.l4p(sport=sport, dport=vip.port) /
                      Raw())

                rxs = self.send_and_expect(self.pg0,
                                           p1 * N_PKTS,
                                           self.pg1)

        #
        # new flows go to the new backend
        #
        for src in self.pg0.remote_hosts:
            p1 = (Ether(dst=self.pg0.local_mac,
                        src=src.mac) /
                  ip_class(src=getattr(src, ip_v), dst=vip.ip) /
                  vip.l4p(sport=9999, dport=vip.port) /
                  Raw())

            rxs = self.send_and_expect(self.pg0,
                                       p1 * N_PKTS,
                                       self.pg2)

    def cnat_translation(self, vips, isV6=False):
        """ CNat Translation """

        ip_class = IPv6 if isV6 else IP
        ip_v = "ip6" if isV6 else "ip4"
        sports = [1234, 1233]

        #
        # turn the scanner off whilst testing otherwise sessions
        # will time out
        #
        self.vapi.cli("test cnat scanner off")

        sessions = self.vapi.cnat_session_dump()

        trs = []
        for nbr, vip in enumerate(vips):
            trs.append(self.cnat_create_translation(vip, nbr))

        self.logger.info(self.vapi.cli("sh cnat client"))
        self.logger.info(self.vapi.cli("sh cnat translation"))

        #
        # translations
        #
        for nbr, vip in enumerate(vips):
            self.cnat_test_translation(trs[nbr], nbr, sports, isV6=isV6)
            self.cnat_test_translation_update(trs[nbr], sports, isV6=isV6)
            if isV6:
                self.logger.info(self.vapi.cli(
                    "sh ip6 fib %s" % self.pg0.remote_ip6))
            else:
                self.logger.info(self.vapi.cli(
                    "sh ip fib %s" % self.pg0.remote_ip4))
            self.logger.info(self.vapi.cli("sh cnat session verbose"))

        #
        # turn the scanner back on and wait until the sessions
        # all disapper
        #
        self.vapi.cli("test cnat scanner on")

        n_tries = 0
        sessions = self.vapi.cnat_session_dump()
        while (len(sessions) and n_tries < 100):
            n_tries += 1
            sessions = self.vapi.cnat_session_dump()
            self.sleep(2)
            self.logger.info(self.vapi.cli("show cnat session verbose"))

        self.assertTrue(n_tries < 100)
        self.vapi.cli("test cnat scanner off")

        #
        # load some flows again and purge
        #
        for vip in vips:
            for src in self.pg0.remote_hosts:
                for sport in sports:
                    # from client to vip
                    p1 = (Ether(dst=self.pg0.local_mac,
                                src=src.mac) /
                          ip_class(src=getattr(src, ip_v), dst=vip.ip) /
                          vip.l4p(sport=sport, dport=vip.port) /
                          Raw())
                    self.send_and_expect(self.pg0,
                                         p1 * N_PKTS,
                                         self.pg2)

        for tr in trs:
            tr.remove_vpp_config()

        self.assertTrue(self.vapi.cnat_session_dump())
        self.vapi.cnat_session_purge()
        self.assertFalse(self.vapi.cnat_session_dump())

    def test_icmp(self):
        vips = [
            Ep("30.0.0.1", 5555),
            Ep("30.0.0.2", 5554),
            Ep("30.0.0.2", 5553, UDP),
            Ep("30::1", 6666),
            Ep("30::2", 5553, UDP),
        ]
        sport = 1234

        self.pg0.generate_remote_hosts(len(vips))
        self.pg0.configure_ipv6_neighbors()
        self.pg0.configure_ipv4_neighbors()

        self.pg1.generate_remote_hosts(len(vips))
        self.pg1.configure_ipv6_neighbors()
        self.pg1.configure_ipv4_neighbors()

        self.vapi.cli("test cnat scanner off")
        trs = []
        for nbr, vip in enumerate(vips):
            trs.append(self.cnat_create_translation(vip, nbr))

        self.logger.info(self.vapi.cli("sh cnat client"))
        self.logger.info(self.vapi.cli("sh cnat translation"))

        for nbr, vip in enumerate(vips):
            if vip.isV6:
                client_addr = self.pg0.remote_hosts[0].ip6
                remote_addr = self.pg1.remote_hosts[nbr].ip6
                remote2_addr = self.pg2.remote_hosts[0].ip6
            else:
                client_addr = self.pg0.remote_hosts[0].ip4
                remote_addr = self.pg1.remote_hosts[nbr].ip4
                remote2_addr = self.pg2.remote_hosts[0].ip4
            IP46 = IPv6 if vip.isV6 else IP
            # from client to vip
            p1 = (Ether(dst=self.pg0.local_mac,
                        src=self.pg0.remote_hosts[0].mac) /
                  IP46(src=client_addr, dst=vip.ip) /
                  vip.l4p(sport=sport, dport=vip.port) /
                  Raw())

            rxs = self.send_and_expect(self.pg0,
                                       p1 * N_PKTS,
                                       self.pg1)

            for rx in rxs:
                self.assert_packet_checksums_valid(rx)
                self.assertEqual(rx[IP46].dst, remote_addr)
                self.assertEqual(rx[vip.l4p].dport, 4000 + nbr)
                self.assertEqual(rx[IP46].src, client_addr)
                self.assertEqual(rx[vip.l4p].sport, sport)

            InnerIP = rxs[0][IP46]

            ICMP46 = ICMPv6DestUnreach if vip.isV6 else ICMP
            ICMPelem = ICMPv6DestUnreach(code=1) if vip.isV6 else ICMP(type=11)
            # from vip to client, ICMP error
            p1 = (Ether(dst=self.pg1.local_mac, src=self.pg1.remote_mac) /
                  IP46(src=remote_addr, dst=client_addr) /
                  ICMPelem / InnerIP)

            rxs = self.send_and_expect(self.pg1,
                                       p1 * N_PKTS,
                                       self.pg0)

            TCPUDPError = TCPerror if vip.l4p == TCP else UDPerror
            IP46error = IPerror6 if vip.isV6 else IPerror
            for rx in rxs:
                self.assert_packet_checksums_valid(rx)
                self.assertEqual(rx[IP46].src, vip.ip)
                self.assertEqual(rx[ICMP46][IP46error].src, client_addr)
                self.assertEqual(rx[ICMP46][IP46error].dst, vip.ip)
                self.assertEqual(rx[ICMP46][IP46error]
                                 [TCPUDPError].sport, sport)
                self.assertEqual(rx[ICMP46][IP46error]
                                 [TCPUDPError].dport, vip.port)

            # from other remote to client, ICMP error
            # outside shouldn't be NAT-ed
            p1 = (Ether(dst=self.pg2.local_mac, src=self.pg2.remote_mac) /
                  IP46(src=remote2_addr, dst=client_addr) /
                  ICMPelem / InnerIP)

            rxs = self.send_and_expect(self.pg1,
                                       p1 * N_PKTS,
                                       self.pg0)

            TCPUDPError = TCPerror if vip.l4p == TCP else UDPerror
            IP46error = IPerror6 if vip.isV6 else IPerror
            for rx in rxs:
                self.assert_packet_checksums_valid(rx)
                self.assertEqual(rx[IP46].src, remote2_addr)
                self.assertEqual(rx[ICMP46][IP46error].src, client_addr)
                self.assertEqual(rx[ICMP46][IP46error].dst, vip.ip)
                self.assertEqual(rx[ICMP46][IP46error]
                                 [TCPUDPError].sport, sport)
                self.assertEqual(rx[ICMP46][IP46error]
                                 [TCPUDPError].dport, vip.port)

        self.vapi.cnat_session_purge()

    def test_cnat6(self):
        # """ CNat Translation ipv6 """
        vips = [
            Ep("30::1", 5555),
            Ep("30::2", 5554),
            Ep("30::2", 5553, UDP),
        ]

        self.pg0.generate_remote_hosts(len(vips))
        self.pg0.configure_ipv6_neighbors()
        self.pg1.generate_remote_hosts(len(vips))
        self.pg1.configure_ipv6_neighbors()

        self.cnat_translation(vips, isV6=True)

    def test_cnat4(self):
        # """ CNat Translation ipv4 """

        vips = [
            Ep("30.0.0.1", 5555),
            Ep("30.0.0.2", 5554),
            Ep("30.0.0.2", 5553, UDP),
        ]

        self.pg0.generate_remote_hosts(len(vips))
        self.pg0.configure_ipv4_neighbors()
        self.pg1.generate_remote_hosts(len(vips))
        self.pg1.configure_ipv4_neighbors()

        self.cnat_translation(vips)


class TestCNatSourceNAT(VppTestCase):
    """ CNat Source NAT """
    extra_vpp_punt_config = ["cnat", "{",
                             "session-max-age", "1",
                             "tcp-max-age", "1", "}"]

    @classmethod
    def setUpClass(cls):
        super(TestCNatSourceNAT, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestCNatSourceNAT, cls).tearDownClass()

    def setUp(self):
        super(TestCNatSourceNAT, self).setUp()

        self.create_pg_interfaces(range(3))

        for i in self.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()
            i.config_ip6()
            i.resolve_ndp()

        self.pg0.configure_ipv6_neighbors()
        self.pg0.configure_ipv4_neighbors()
        self.pg1.generate_remote_hosts(2)
        self.pg1.configure_ipv4_neighbors()
        self.pg1.configure_ipv6_neighbors()

        self.vapi.cli("test cnat scanner off")
        self.vapi.cnat_set_snat_addresses(
            snat_ip4=self.pg2.remote_hosts[0].ip4,
            snat_ip6=self.pg2.remote_hosts[0].ip6)
        self.vapi.feature_enable_disable(
            enable=1,
            arc_name="ip6-unicast",
            feature_name="ip6-cnat-snat",
            sw_if_index=self.pg0.sw_if_index)
        self.vapi.feature_enable_disable(
            enable=1,
            arc_name="ip4-unicast",
            feature_name="ip4-cnat-snat",
            sw_if_index=self.pg0.sw_if_index)

    def tearDown(self):
        self.vapi.cnat_session_purge()
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.admin_down()
        super(TestCNatSourceNAT, self).tearDown()

    def test_snat_v6(self):
        # """ CNat Source Nat v6 """
        self.sourcenat_test_tcp_udp_conf(TCP, isV6=True)
        self.sourcenat_test_tcp_udp_conf(UDP, isV6=True)
        self.sourcenat_test_icmp_err_conf(isV6=True)
        self.sourcenat_test_icmp_echo6_conf()

    def test_snat_v4(self):
        # """ CNat Source Nat v4 """
        self.sourcenat_test_tcp_udp_conf(TCP)
        self.sourcenat_test_tcp_udp_conf(UDP)
        self.sourcenat_test_icmp_err_conf()
        self.sourcenat_test_icmp_echo4_conf()

    def sourcenat_test_icmp_echo6_conf(self):
        sports = [1234, 1235]
        dports = [6661, 6662]

        for nbr, remote_host in enumerate(self.pg1.remote_hosts):
            client_addr = self.pg0.remote_hosts[0].ip6
            remote_addr = self.pg1.remote_hosts[nbr].ip6
            src_nat_addr = self.pg2.remote_hosts[0].ip6

            # ping from pods to outside network
            p1 = (
                Ether(dst=self.pg0.local_mac,
                      src=self.pg0.remote_hosts[0].mac) /
                IPv6(src=client_addr, dst=remote_addr) /
                ICMPv6EchoRequest(id=0xfeed) /
                Raw())

            rxs = self.send_and_expect(
                self.pg0,
                p1 * N_PKTS,
                self.pg1)

            for rx in rxs:
                self.assertEqual(rx[IPv6].src, src_nat_addr)
                self.assert_packet_checksums_valid(rx)

            received_id = rx[0][ICMPv6EchoRequest].id
            # ping reply from outside to pods
            p2 = (
                Ether(dst=self.pg1.local_mac,
                      src=self.pg1.remote_hosts[nbr].mac) /
                IPv6(src=remote_addr, dst=src_nat_addr) /
                ICMPv6EchoReply(id=received_id))
            rxs = self.send_and_expect(
                self.pg1,
                p2 * N_PKTS,
                self.pg0)

            for rx in rxs:
                self.assert_packet_checksums_valid(rx)
                self.assertEqual(rx[IPv6].src, remote_addr)
                self.assertEqual(rx[ICMPv6EchoReply].id, 0xfeed)

    def sourcenat_test_icmp_echo4_conf(self):
        sports = [1234, 1235]
        dports = [6661, 6662]

        for nbr, remote_host in enumerate(self.pg1.remote_hosts):
            IP46 = IP
            client_addr = self.pg0.remote_hosts[0].ip4
            remote_addr = self.pg1.remote_hosts[nbr].ip4
            src_nat_addr = self.pg2.remote_hosts[0].ip4

            # ping from pods to outside network
            p1 = (
                Ether(dst=self.pg0.local_mac,
                      src=self.pg0.remote_hosts[0].mac) /
                IP46(src=client_addr, dst=remote_addr) /
                ICMP(type=8, id=0xfeed) /
                Raw())

            rxs = self.send_and_expect(
                self.pg0,
                p1 * N_PKTS,
                self.pg1)

            for rx in rxs:
                self.assertEqual(rx[IP46].src, src_nat_addr)
                self.assert_packet_checksums_valid(rx)

            received_id = rx[0][ICMP].id
            # ping reply from outside to pods
            p2 = (
                Ether(dst=self.pg1.local_mac,
                      src=self.pg1.remote_hosts[nbr].mac) /
                IP46(src=remote_addr, dst=src_nat_addr) /
                ICMP(type=0, id=received_id))
            rxs = self.send_and_expect(
                self.pg1,
                p2 * N_PKTS,
                self.pg0)

            for rx in rxs:
                self.assert_packet_checksums_valid(rx)
                self.assertEqual(rx[IP46].src, remote_addr)
                self.assertEqual(rx[ICMP].id, 0xfeed)

    def sourcenat_test_icmp_err_conf(self, isV6=False):
        sports = [1234, 1235]
        dports = [6661, 6662]

        for nbr, remote_host in enumerate(self.pg1.remote_hosts):
            if isV6:
                IP46 = IPv6
                client_addr = self.pg0.remote_hosts[0].ip6
                remote_addr = self.pg1.remote_hosts[nbr].ip6
                src_nat_addr = self.pg2.remote_hosts[0].ip6
                ICMP46 = ICMPv6DestUnreach
                ICMPelem = ICMPv6DestUnreach(code=1)
                IP46error = IPerror6
            else:
                IP46 = IP
                client_addr = self.pg0.remote_hosts[0].ip4
                remote_addr = self.pg1.remote_hosts[nbr].ip4
                src_nat_addr = self.pg2.remote_hosts[0].ip4
                IP46error = IPerror
                ICMP46 = ICMP
                ICMPelem = ICMP(type=11)

            # from pods to outside network
            p1 = (
                Ether(dst=self.pg0.local_mac,
                      src=self.pg0.remote_hosts[0].mac) /
                IP46(src=client_addr, dst=remote_addr) /
                TCP(sport=sports[nbr], dport=dports[nbr]) /
                Raw())

            rxs = self.send_and_expect(
                self.pg0,
                p1 * N_PKTS,
                self.pg1)
            for rx in rxs:
                self.assert_packet_checksums_valid(rx)
                self.assertEqual(rx[IP46].dst, remote_addr)
                self.assertEqual(rx[TCP].dport, dports[nbr])
                self.assertEqual(rx[IP46].src, src_nat_addr)
                sport = rx[TCP].sport

            InnerIP = rxs[0][IP46]
            # from outside to pods, ICMP error
            p2 = (
                Ether(dst=self.pg1.local_mac,
                      src=self.pg1.remote_hosts[nbr].mac) /
                IP46(src=remote_addr, dst=src_nat_addr) /
                ICMPelem / InnerIP)

            rxs = self.send_and_expect(
                self.pg1,
                p2 * N_PKTS,
                self.pg0)

            for rx in rxs:
                self.assert_packet_checksums_valid(rx)
                self.assertEqual(rx[IP46].src, remote_addr)
                self.assertEqual(rx[ICMP46][IP46error].src, client_addr)
                self.assertEqual(rx[ICMP46][IP46error].dst, remote_addr)
                self.assertEqual(rx[ICMP46][IP46error]
                                 [TCPerror].sport, sports[nbr])
                self.assertEqual(rx[ICMP46][IP46error]
                                 [TCPerror].dport, dports[nbr])

    def sourcenat_test_tcp_udp_conf(self, l4p, isV6=False):
        sports = [1234, 1235]
        dports = [6661, 6662]

        for nbr, remote_host in enumerate(self.pg1.remote_hosts):
            if isV6:
                IP46 = IPv6
                client_addr = self.pg0.remote_hosts[0].ip6
                remote_addr = self.pg1.remote_hosts[nbr].ip6
                src_nat_addr = self.pg2.remote_hosts[0].ip6
                exclude_prefix = ip_network(
                    "%s/100" % remote_addr, strict=False)
            else:
                IP46 = IP
                client_addr = self.pg0.remote_hosts[0].ip4
                remote_addr = self.pg1.remote_hosts[nbr].ip4
                src_nat_addr = self.pg2.remote_hosts[0].ip4
                exclude_prefix = ip_network(
                    "%s/16" % remote_addr, strict=False)
            # from pods to outside network
            p1 = (
                Ether(dst=self.pg0.local_mac,
                      src=self.pg0.remote_hosts[0].mac) /
                IP46(src=client_addr, dst=remote_addr) /
                l4p(sport=sports[nbr], dport=dports[nbr]) /
                Raw())

            self.vapi.cli("trace add pg-input 1")
            rxs = self.send_and_expect(
                self.pg0,
                p1 * N_PKTS,
                self.pg1)
            self.logger.info(self.vapi.cli("show trace max 1"))

            for rx in rxs:
                self.assert_packet_checksums_valid(rx)
                self.assertEqual(rx[IP46].dst, remote_addr)
                self.assertEqual(rx[l4p].dport, dports[nbr])
                self.assertEqual(rx[IP46].src, src_nat_addr)
                sport = rx[l4p].sport

            # from outside to pods
            p2 = (
                Ether(dst=self.pg1.local_mac,
                      src=self.pg1.remote_hosts[nbr].mac) /
                IP46(src=remote_addr, dst=src_nat_addr) /
                l4p(sport=dports[nbr], dport=sport) /
                Raw())

            rxs = self.send_and_expect(
                self.pg1,
                p2 * N_PKTS,
                self.pg0)

            for rx in rxs:
                self.assert_packet_checksums_valid(rx)
                self.assertEqual(rx[IP46].dst, client_addr)
                self.assertEqual(rx[l4p].dport, sports[nbr])
                self.assertEqual(rx[l4p].sport, dports[nbr])
                self.assertEqual(rx[IP46].src, remote_addr)

            # add remote host to exclude list
            self.vapi.cnat_add_del_snat_prefix(prefix=exclude_prefix, is_add=1)
            self.vapi.cnat_session_purge()

            rxs = self.send_and_expect(
                self.pg0,
                p1 * N_PKTS,
                self.pg1)
            for rx in rxs:
                self.assert_packet_checksums_valid(rx)
                self.assertEqual(rx[IP46].dst, remote_addr)
                self.assertEqual(rx[l4p].dport, dports[nbr])
                self.assertEqual(rx[IP46].src, client_addr)

            # remove remote host from exclude list
            self.vapi.cnat_add_del_snat_prefix(prefix=exclude_prefix, is_add=0)
            self.vapi.cnat_session_purge()

            rxs = self.send_and_expect(
                self.pg0,
                p1 * N_PKTS,
                self.pg1)

            for rx in rxs:
                self.assert_packet_checksums_valid(rx)
                self.assertEqual(rx[IP46].dst, remote_addr)
                self.assertEqual(rx[l4p].dport, dports[nbr])
                self.assertEqual(rx[IP46].src, src_nat_addr)

            self.vapi.cnat_session_purge()


class TestCNatDHCP(VppTestCase):
    """ CNat Translation """
    extra_vpp_punt_config = ["cnat", "{",
                             "session-db-buckets", "64",
                             "session-cleanup-timeout", "0.1",
                             "session-max-age", "1",
                             "tcp-max-age", "1",
                             "scanner", "off", "}"]

    @classmethod
    def setUpClass(cls):
        super(TestCNatDHCP, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestCNatDHCP, cls).tearDownClass()

    def tearDown(self):
        for i in self.pg_interfaces:
            i.admin_down()
        super(TestCNatDHCP, self).tearDown()

    def create_translation(self, vip_pg, *args, is_v6=False):
        vip = Ep(sw_if_index=vip_pg.sw_if_index, is_v6=is_v6)
        paths = []
        for (src_pg, dst_pg) in args:
            paths.append(EpTuple(
                Ep.from_pg(src_pg, is_v6=is_v6),
                Ep.from_pg(dst_pg, is_v6=is_v6)
            ))
        t1 = VppCNatTranslation(self, TCP, vip, paths)
        t1.add_vpp_config()
        return t1

    def make_addr(self, sw_if_index, i, is_v6):
        if is_v6:
            return "fd01:%x::%u" % (sw_if_index, i + 1)
        else:
            return "172.16.%u.%u" % (sw_if_index, i)

    def make_prefix(self, sw_if_index, i, is_v6):
        if is_v6:
            return "%s/128" % self.make_addr(sw_if_index, i, is_v6)
        else:
            return "%s/32" % self.make_addr(sw_if_index, i, is_v6)

    def check_resolved(self, tr, vip_pg, *args, i=0, is_v6=False):
        qt1 = tr.query_vpp_config()
        self.assertEqual(str(qt1.vip.addr), self.make_addr(
            vip_pg.sw_if_index, i, is_v6))
        for (src_pg, dst_pg), path in zip(args, qt1.paths):
            if src_pg:
                self.assertEqual(str(path.src_ep.addr), self.make_addr(
                    src_pg.sw_if_index, i, is_v6))
            if dst_pg:
                self.assertEqual(str(path.dst_ep.addr), self.make_addr(
                    dst_pg.sw_if_index, i, is_v6))

    def config_ips(self, rng, is_add=1, is_v6=False):
        for pg, i in product(self.pg_interfaces, rng):
            self.vapi.sw_interface_add_del_address(
                sw_if_index=pg.sw_if_index,
                prefix=self.make_prefix(pg.sw_if_index, i, is_v6),
                is_add=is_add)

    def test_dhcp_v4(self):
        self.create_pg_interfaces(range(5))
        for i in self.pg_interfaces:
            i.admin_up()
        pglist = (self.pg0, (self.pg1, self.pg2), (self.pg1, self.pg4))
        t1 = self.create_translation(*pglist)
        self.config_ips([0])
        self.check_resolved(t1, *pglist)
        self.config_ips([1])
        self.config_ips([0], is_add=0)
        self.check_resolved(t1, *pglist, i=1)
        self.config_ips([1], is_add=0)
        t1.remove_vpp_config()

    def test_dhcp_v6(self):
        self.create_pg_interfaces(range(5))
        for i in self.pg_interfaces:
            i.admin_up()
        pglist = (self.pg0, (self.pg1, self.pg2), (self.pg1, self.pg4))
        t1 = self.create_translation(*pglist, is_v6=True)
        self.config_ips([0], is_v6=True)
        self.check_resolved(t1, *pglist, is_v6=True)
        self.config_ips([1], is_v6=True)
        self.config_ips([0], is_add=0, is_v6=True)
        self.check_resolved(t1, *pglist, i=1, is_v6=True)
        self.config_ips([1], is_add=0, is_v6=True)
        t1.remove_vpp_config()

    def test_dhcp_snat(self):
        self.create_pg_interfaces(range(1))
        for i in self.pg_interfaces:
            i.admin_up()
        self.vapi.cnat_set_snat_addresses(sw_if_index=self.pg0.sw_if_index)
        self.config_ips([0], is_v6=False)
        self.config_ips([0], is_v6=True)
        r = self.vapi.cnat_get_snat_addresses()
        self.assertEqual(str(r.snat_ip4), self.make_addr(
            self.pg0.sw_if_index, 0, False))
        self.assertEqual(str(r.snat_ip6), self.make_addr(
            self.pg0.sw_if_index, 0, True))
        self.config_ips([1], is_v6=False)
        self.config_ips([1], is_v6=True)
        self.config_ips([0], is_add=0, is_v6=False)
        self.config_ips([0], is_add=0, is_v6=True)
        r = self.vapi.cnat_get_snat_addresses()
        self.assertEqual(str(r.snat_ip4), self.make_addr(
            self.pg0.sw_if_index, 1, False))
        self.assertEqual(str(r.snat_ip6), self.make_addr(
            self.pg0.sw_if_index, 1, True))
        self.config_ips([1], is_add=0, is_v6=False)
        self.config_ips([1], is_add=0, is_v6=True)


if __name__ == '__main__':
    unittest.main(testRunner