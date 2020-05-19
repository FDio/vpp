#!/usr/bin/env python3

import unittest

from framework import VppTestCase, VppTestRunner
from vpp_ip import DpoProto

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.inet6 import IPv6

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

    def __init__(self, ip, port, l4p=TCP):
        self.ip = ip
        self.port = port
        self.l4p = l4p

    def encode(self):
        return {'addr': self.ip,
                'port': self.port}

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


class TestCNatTranslation(VppTestCase):
    """ CNat Translation """
    extra_vpp_punt_config = ["cnat", "{",
                             "session-max-age", "1",
                             "tcp-max-age", "1", "}"]

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
        # turn the scanner back on and wait untill the sessions
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


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
