#!/usr/bin/env python3

import unittest

from framework import VppTestCase, VppTestRunner
from vpp_ip import DpoProto
from vpp_ip_route import VppIpRoute, VppRoutePath, VppMplsLabel, \
    VppIpTable, FibPathProto
from vpp_acl import AclRule, VppAcl

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
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

        self.create_pg_interfaces(range(2))

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

        self.pg1.generate_remote_hosts(4)
        self.pg1.configure_ipv4_neighbors()

        ip_proto = VppEnum.vl_api_ip_proto_t
        vip = "30.0.0.1"
        vport1 = 3000
        vport2 = 3001

        t1 = VppCalicoTranslate(
            self,
            VppCalicoEndpoint(vip, vport1),
            ip_proto.IP_API_PROTO_UDP,
            [VppCalicoEndpoint(self.pg1.remote_hosts[0].ip4, 4000),
             VppCalicoEndpoint(self.pg1.remote_hosts[1].ip4, 4001)])
        t1.add_vpp_config()
        t2 = VppCalicoTranslate(
            self,
            VppCalicoEndpoint(vip, vport2),
            ip_proto.IP_API_PROTO_UDP,
            [VppCalicoEndpoint(self.pg1.remote_hosts[2].ip4, 4000),
             VppCalicoEndpoint(self.pg1.remote_hosts[3].ip4, 4001)])
        t2.add_vpp_config()

        print(self.vapi.cli("sh ip fib 30.0.0.1"))
        print(self.vapi.cli("sh calico vip"))

        print(self.vapi.cli("sh vlib graph ip4-calico-translate"))

        p1 = (Ether(dst=self.pg0.local_mac,
                    src=self.pg0.remote_mac) /
              IP(src=self.pg0.remote_ip4,
                 dst=vip) /
              UDP(sport=1234, dport=vport1) /
              Raw())
        p2 = (Ether(dst=self.pg0.local_mac,
                    src=self.pg0.remote_mac) /
              IP(src=self.pg0.remote_ip4,
                 dst=vip) /
              UDP(sport=1234, dport=vport2) /
              Raw())

        try:
            rxs = self.send_and_expect(self.pg0, p1 * N_PKTS, self.pg1)
        except:
            print(self.vapi.cli("sh trace"))
        for rx in rxs:
            self.assert_packet_checksums_valid(rx)
            self.assertEqual(rx[IP].dst, self.pg1.remote_hosts[1].ip4)
            self.assertEqual(rx[UDP].dport, 4001)

        try:
            rxs = self.send_and_expect(self.pg0, p2 * N_PKTS, self.pg1)
        except:
            print(self.vapi.cli("sh trace"))
            
        for rx in rxs:
            self.assert_packet_checksums_valid(rx)
            self.assertEqual(rx[IP].dst, self.pg1.remote_hosts[3].ip4)
            self.assertEqual(rx[UDP].dport, 4001)

        print(self.vapi.cli("sh calico session"))
        # print(self.vapi.cli("sh trace"))

        self.assertEqual(t1.get_stats()['packets'], N_PKTS)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
