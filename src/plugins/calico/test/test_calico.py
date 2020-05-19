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

N_PKTS = 63


def find_calico_translate(test, id):
    ts = test.vapi.calico_translate_dump()
    for t in ts:
        if id == p.translate.id:
            return True
    return False


class VppCalicoEndpoint(object):
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

    def encode(self):
        return {'addr': self.ip,
                'port': self.port}

    def __str__(self):
        return ("%s:%d" % (self.ip, self.port))


class VppCalicoTranslate(VppObject):

    def __init__(self, test, vip, iproto, paths):
        self._test = test
        self.vip = vip
        self.iproto = iproto,
        self.paths = paths
        self.encoded_paths = []
        for path in self.paths:
            self.encoded_paths.append(path.encode())

    def add_vpp_config(self):
        r = self._test.vapi.calico_translate_update(
            {'vip': self.vip.encode(),
             'ip_proto': self.iproto[0],
             'n_paths': len(self.paths),
             'paths': self.encoded_paths})
        self._test.registry.register(self, self._test.logger)
        self.id = r.id

    def modify_vpp_config(self, paths):
        self.paths = paths
        self.encoded_paths = []
        for path in self.paths:
            self.encoded_paths.append(path.encode())

        r = self._test.vapi.calico_translate_update(
            {'vip': self.vip.encode(),
             'ip_proto': self.iproto[0],
             'n_paths': len(self.paths),
             'paths': self.encoded_paths})
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.calico_translate_del(self.id)

    def query_vpp_config(self):
        return find_calico_translate(self._test, self.id)

    def object_id(self):
        return ("calico-translate-%s" % (self.vip))

    def get_stats(self):
        c = self._test.statistics.get_counter("/net/calico-translation")
        return c[0][self.id]


class TestCalicoTranslate(VppTestCase):
    """ Calico Translate """

    @classmethod
    def setUpClass(cls):
        super(TestCalicoTranslate, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestCalicoTranslate, cls).tearDownClass()

    def setUp(self):
        super(TestCalicoTranslate, self).setUp()

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
        super(TestCalicoTranslate, self).tearDown()

    def test_calico4(self):
        """ Calico Translate 4 """

        self.pg0.generate_remote_hosts(4)
        self.pg0.configure_ipv4_neighbors()
        self.pg1.generate_remote_hosts(4)
        self.pg1.configure_ipv4_neighbors()

        ip_proto = VppEnum.vl_api_ip_proto_t
        vips = ["30.0.0.1", "30.0.0.2"]
        vports = [3000, 3001]
        sports = [1234, 1235, 1236]
        l4_protos = [UDP, TCP]
        vl4_protos = [ip_proto.IP_API_PROTO_UDP,
                      ip_proto.IP_API_PROTO_TCP]

        #
        # translations
        #
        nbr = 0
        for vip in vips:
            for vport in vports:
                for l4p, vl4 in zip(l4_protos, vl4_protos):
                    t1 = VppCalicoTranslate(
                        self,
                        VppCalicoEndpoint(vip, vport),
                        vl4,
                        [VppCalicoEndpoint(self.pg1.remote_hosts[nbr].ip4,
                                           4000 + nbr),
                         VppCalicoEndpoint(self.pg1.remote_hosts[nbr].ip4,
                                           4000 + nbr)])
                    t1.add_vpp_config()

                    print(self.vapi.cli("sh ip fib %s" % vip))

                    # print(self.vapi.cli("sh calico vip"))

                    #
                    # Flows
                    #
                    for src in self.pg0.remote_hosts:
                        for sport in sports:
                            # from client to vip
                            p1 = (Ether(dst=self.pg0.local_mac,
                                        src=src.mac) /
                                  IP(src=src.ip4, dst=vip) /
                                  l4p(sport=sport, dport=vport) /
                                  Raw())

                            rxs = self.send_and_expect(self.pg0,
                                                       p1 * N_PKTS,
                                                       self.pg1)

                            for rx in rxs:
                                self.assert_packet_checksums_valid(rx)
                                self.assertEqual(
                                    rx[IP].dst,
                                    self.pg1.remote_hosts[nbr].ip4)
                                self.assertEqual(rx[l4p].dport, 4000 + nbr)
                                self.assertEqual(rx[IP].src, src.ip4)
                                self.assertEqual(rx[l4p].sport, sport)

                            # from vip to client
                            p1 = (Ether(dst=self.pg1.local_mac,
                                        src=self.pg1.remote_mac) /
                                  IP(src=self.pg1.remote_hosts[nbr].ip4,
                                     dst=src.ip4) /
                                  l4p(sport=4000 + nbr, dport=sport) /
                                  Raw())

                            rxs = self.send_and_expect(self.pg1,
                                                       p1 * N_PKTS,
                                                       self.pg0)

                            for rx in rxs:
                                self.assert_packet_checksums_valid(rx)
                                self.assertEqual(rx[IP].dst, src.ip4)
                                self.assertEqual(rx[l4p].dport, sport)
                                self.assertEqual(rx[IP].src, vip)
                                self.assertEqual(rx[l4p].sport, vport)

                            #
                            # packets to the VIP that do not match a
                            # translation are dropped
                            #
                            p1 = (Ether(dst=self.pg0.local_mac,
                                        src=src.mac) /
                                  IP(src=src.ip4, dst=vip) /
                                  l4p(sport=sport, dport=6666) /
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
                                  IP(src=self.pg1.remote_hosts[nbr].ip4,
                                     dst=src.ip4) /
                                  l4p(sport=6666, dport=sport) /
                                  Raw())

                            rxs = self.send_and_expect(self.pg1,
                                                       p1 * N_PKTS,
                                                       self.pg0)

                    self.assertEqual(t1.get_stats()['packets'],
                                     N_PKTS *
                                     len(sports) *
                                     len(self.pg0.remote_hosts))

                    #
                    # modify the translation to use a different backend
                    #
                    t1.modify_vpp_config(
                        [VppCalicoEndpoint(self.pg2.remote_ip4, 5000)])

                    #
                    # existing flows follow the old path
                    #
                    for src in self.pg0.remote_hosts:
                        for sport in sports:
                            # from client to vip
                            p1 = (Ether(dst=self.pg0.local_mac,
                                        src=src.mac) /
                                  IP(src=src.ip4, dst=vip) /
                                  UDP(sport=sport, dport=vport) /
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
                              IP(src=src.ip4, dst=vip) /
                              UDP(sport=9999, dport=vport) /
                              Raw())

                        rxs = self.send_and_expect(self.pg0,
                                                   p1 * N_PKTS,
                                                   self.pg2)
            nbr += 1

            print(self.vapi.cli("sh ip fib %s" %
                                self.pg0.remote_ip4))
            print(self.vapi.cli("sh calico session"))

        print(self.vapi.cli("sh calico client"))
        print(self.vapi.cli("sh calico vip"))
        print(self.vapi.cli("sh ip fib"))
        print("FINISHED")


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
