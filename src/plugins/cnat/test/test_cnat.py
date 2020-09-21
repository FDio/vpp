#!/usr/bin/env python3

import unittest

from framework import VppTestCase, VppTestRunner
from vpp_ip import DpoProto, INVALID_INDEX

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.inet6 import IPv6

from ipaddress import ip_address, ip_network, \
    IPv4Address, IPv6Address, IPv4Network, IPv6Network

from vpp_object import VppObject
from vpp_papi import VppEnum

N_PKTS = 15


def find_cnat_translation(test, id):
    ts = test.vapi.cnat_translation_dump()
    for t in ts:
        if id == t.translation.id:
            return True
    return False


class Ep(object):
    """ CNat endpoint """

    def __init__(self, ip, port, l4p=TCP,
                 sw_if_index=INVALID_INDEX, is_v6=False):
        self.ip = ip
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

    @property
    def vl4_proto(self):
        ip_proto = VppEnum.vl_api_ip_proto_t
        return {
            UDP: ip_proto.IP_API_PROTO_UDP,
            TCP: ip_proto.IP_API_PROTO_TCP,
        }[self.iproto]

    def delete(self):
        r = self._test.vapi.cnat_translation_del(id=self.id)

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
        self._test.vapi.cnat_translation_del(self.id)

    def query_vpp_config(self):
        return find_cnat_translation(self._test, self.id)

    def object_id(self):
        return ("cnat-translation-%s" % (self.vip))

    def get_stats(self):
        c = self._test.statistics.get_counter("/net/cnat-translation")
        return c[0][self.id]


class VppCNATSourceNat(VppObject):

    def __init__(self, test, address, exclude_subnets=[]):
        self._test = test
        self.address = address
        self.exclude_subnets = exclude_subnets

    def add_vpp_config(self):
        a = ip_address(self.address)
        if 4 == a.version:
            self._test.vapi.cnat_set_snat_addresses(snat_ip4=self.address)
        else:
            self._test.vapi.cnat_set_snat_addresses(snat_ip6=self.address)
        for subnet in self.exclude_subnets:
            self.cnat_exclude_subnet(subnet, True)

    def cnat_exclude_subnet(self, exclude_subnet, isAdd=True):
        add = 1 if isAdd else 0
        self._test.vapi.cnat_add_del_snat_prefix(
            prefix=exclude_subnet, is_add=add)

    def query_vpp_config(self):
        return False

    def remove_vpp_config(self):
        return False


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

    def cnat_create_translation(self, vip, nbr, isV6=False):
        ip_v = "ip6" if isV6 else "ip4"
        dep = Ep(getattr(self.pg1.remote_hosts[nbr], ip_v), 4000 + nbr)
        sep = Ep("::", 0) if isV6 else Ep("0.0.0.0", 0)
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
            trs.append(self.cnat_create_translation(vip, nbr, isV6=isV6))

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

        self.assertTrue(n_tries < 100)

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
            tr.delete()

        self.assertTrue(self.vapi.cnat_session_dump())
        self.vapi.cnat_session_purge()
        self.assertFalse(self.vapi.cnat_session_dump())

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

    def tearDown(self):
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.admin_down()
        super(TestCNatSourceNAT, self).tearDown()

    def cnat_set_snat_address(self, srcNatAddr, interface, isV6=False):
        t1 = VppCNATSourceNat(self, srcNatAddr)
        t1.add_vpp_config()
        cnat_arc_name = "ip6-unicast" if isV6 else "ip4-unicast"
        cnat_feature_name = "ip6-cnat-snat" if isV6 else "ip4-cnat-snat"
        self.vapi.feature_enable_disable(
            enable=1,
            arc_name=cnat_arc_name,
            feature_name=cnat_feature_name,
            sw_if_index=interface.sw_if_index)

        return t1

    def cnat_test_sourcenat(self, srcNatAddr, l4p=TCP, isV6=False):
        ip_v = "ip6" if isV6 else "ip4"
        ip_class = IPv6 if isV6 else IP
        sports = [1234, 1235, 1236]
        dports = [6661, 6662, 6663]

        self.pg0.generate_remote_hosts(1)
        self.pg0.configure_ipv4_neighbors()
        self.pg0.configure_ipv6_neighbors()
        self.pg1.generate_remote_hosts(len(sports))
        self.pg1.configure_ipv4_neighbors()
        self.pg1.configure_ipv6_neighbors()

        self.vapi.cli("test cnat scanner on")
        t1 = self.cnat_set_snat_address(srcNatAddr, self.pg0, isV6)

        for nbr, remote_host in enumerate(self.pg1.remote_hosts):
            # from pods to outside network
            p1 = (
                Ether(
                    dst=self.pg0.local_mac,
                    src=self.pg0.remote_hosts[0].mac) /
                ip_class(
                    src=getattr(self.pg0.remote_hosts[0], ip_v),
                    dst=getattr(remote_host, ip_v)) /
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
                self.assertEqual(
                    rx[ip_class].dst,
                    getattr(remote_host, ip_v))
                self.assertEqual(rx[l4p].dport, dports[nbr])
                self.assertEqual(
                    rx[ip_class].src,
                    srcNatAddr)
                sport = rx[l4p].sport

            # from outside to pods
            p2 = (
                Ether(
                    dst=self.pg1.local_mac,
                    src=self.pg1.remote_hosts[nbr].mac) /
                ip_class(src=getattr(remote_host, ip_v), dst=srcNatAddr) /
                l4p(sport=dports[nbr], dport=sport) /
                Raw())

            rxs = self.send_and_expect(
                self.pg1,
                p2 * N_PKTS,
                self.pg0)

            for rx in rxs:
                self.assert_packet_checksums_valid(rx)
                self.assertEqual(
                    rx[ip_class].dst,
                    getattr(self.pg0.remote_hosts[0], ip_v))
                self.assertEqual(rx[l4p].dport, sports[nbr])
                self.assertEqual(rx[l4p].sport, dports[nbr])
                self.assertEqual(
                    rx[ip_class].src,
                    getattr(remote_host, ip_v))

            # add remote host to exclude list
            subnet_mask = 100 if isV6 else 16
            subnet = getattr(remote_host, ip_v) + "/" + str(subnet_mask)
            exclude_subnet = ip_network(subnet, strict=False)

            t1.cnat_exclude_subnet(exclude_subnet)
            self.vapi.cnat_session_purge()

            rxs = self.send_and_expect(
                self.pg0,
                p1 * N_PKTS,
                self.pg1)
            for rx in rxs:
                self.assert_packet_checksums_valid(rx)
                self.assertEqual(
                    rx[ip_class].dst,
                    getattr(remote_host, ip_v))
                self.assertEqual(rx[l4p].dport, dports[nbr])
                self.assertEqual(
                    rx[ip_class].src,
                    getattr(self.pg0.remote_hosts[0], ip_v))

            # remove remote host from exclude list
            t1.cnat_exclude_subnet(exclude_subnet, isAdd=False)
            self.vapi.cnat_session_purge()

            rxs = self.send_and_expect(
                self.pg0,
                p1 * N_PKTS,
                self.pg1)

            for rx in rxs:
                self.assert_packet_checksums_valid(rx)
                self.assertEqual(
                    rx[ip_class].dst,
                    getattr(remote_host, ip_v))
                self.assertEqual(rx[l4p].dport, dports[nbr])
                self.assertEqual(
                    rx[ip_class].src,
                    srcNatAddr)

    def test_cnat6_sourcenat(self):
        # """ CNat Source Nat ipv6 """
        self.cnat_test_sourcenat(self.pg2.remote_hosts[0].ip6, TCP, True)
        self.cnat_test_sourcenat(self.pg2.remote_hosts[0].ip6, UDP, True)

    def test_cnat4_sourcenat(self):
        # """ CNat Source Nat ipv4 """
        self.cnat_test_sourcenat(self.pg2.remote_hosts[0].ip4, TCP)
        self.cnat_test_sourcenat(self.pg2.remote_hosts[0].ip4, UDP)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
