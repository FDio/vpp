#!/usr/bin/env python
""" L2BD ARP term Test """

import unittest
import random
import copy

from scapy.packet import Raw
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP

from framework import VppTestCase, VppTestRunner
from util import Host, ppp, mactobinary


class TestL2bdArpTerm(VppTestCase):
    """ L2BD arp termination Test Case """

    @classmethod
    def setUpClass(cls):
        """
        Perform standard class setup (defined by class method setUpClass in
        class VppTestCase) before running the test case, set test case related
        variables and configure VPP.
        """
        super(TestL2bdArpTerm, cls).setUpClass()

        try:
            # Create pg interfaces
            n_bd = 1
            cls.ifs_per_bd = ifs_per_bd = 3
            n_ifs = n_bd * ifs_per_bd
            cls.create_pg_interfaces(range(n_ifs))

            # Set up all interfaces
            for i in cls.pg_interfaces:
                i.admin_up()

            cls.hosts = set()

        except Exception:
            super(TestL2bdArpTerm, cls).tearDownClass()
            raise

    def setUp(self):
        """
        Clear trace and packet infos before running each test.
        """
        self.reset_packet_infos()
        super(TestL2bdArpTerm, self).setUp()

    def tearDown(self):
        """
        Show various debug prints after each test.
        """
        super(TestL2bdArpTerm, self).tearDown()
        if not self.vpp_dead:
            self.logger.info(self.vapi.ppcli("show l2fib verbose"))
            self.logger.info(self.vapi.ppcli("show bridge-domain 1 detail"))

    def add_del_arp_term_hosts(self, entries, bd_id=1, is_add=1):
        for e in entries:
            self.vapi.bd_ip_mac_add_del(bd_id=bd_id,
                                        mac=e.bin_mac,
                                        ip=e.ip4n,
                                        is_ipv6=0,
                                        is_add=is_add)

    @classmethod
    def mac_list(cls, b6_range):
        return ["00:00:ca:fe:00:%02x" % b6 for b6 in b6_range]

    @classmethod
    def ip4_host(cls, subnet, host, mac):
        return Host(mac=mac,
                    ip4="172.17.1%02u.%u" % (subnet, host))

    @classmethod
    def ip4_hosts(cls, subnet, start, mac_list):
        return {cls.ip4_host(subnet, start + j, mac_list[j])
                for j in range(len(mac_list))}

    @classmethod
    def bd_swifs(cls, b):
        n = cls.ifs_per_bd
        start = (b - 1) * n
        return [cls.pg_interfaces[j] for j in range(start, start + n)]

    def bd_add_del(self, bd_id=1, is_add=1):
        if is_add:
            self.vapi.bridge_domain_add_del(bd_id=bd_id, is_add=is_add)
        for swif in self.bd_swifs(bd_id):
            swif_idx = swif.sw_if_index
            self.vapi.sw_interface_set_l2_bridge(
                swif_idx, bd_id=bd_id, enable=is_add)
        if not is_add:
            self.vapi.bridge_domain_add_del(bd_id=bd_id, is_add=is_add)

    @classmethod
    def arp(cls, src_host, host):
        return (Ether(dst="ff:ff:ff:ff:ff:ff", src=src_host.mac) /
                ARP(op="who-has",
                    hwsrc=src_host.bin_mac,
                    pdst=host.ip4,
                    psrc=src_host.ip4))

    @classmethod
    def arp_reqs(cls, src_host, entries):
        return [cls.arp(src_host, e) for e in entries]

    def response_host(self, src_host, arp_resp):
        ether = arp_resp[Ether]
        self.assertEqual(ether.dst, src_host.mac)

        arp = arp_resp[ARP]
        self.assertEqual(arp.hwtype, 1)
        self.assertEqual(arp.ptype, 0x800)
        self.assertEqual(arp.hwlen, 6)
        self.assertEqual(arp.plen, 4)
        arp_opts = {"who-has": 1, "is-at": 2}
        self.assertEqual(arp.op, arp_opts["is-at"])
        self.assertEqual(arp.hwdst, src_host.mac)
        self.assertEqual(arp.pdst, src_host.ip4)
        return Host(arp.hwsrc, arp.psrc)

    def arp_resp_hosts(self, src_host, pkts):
        return {self.response_host(src_host, p) for p in pkts}

    def set_bd_flags(self, bd_id, **args):
        """
        Enable/disable defined feature(s) of the bridge domain.

        :param int bd_id: Bridge domain ID.
        :param list args: List of feature/status pairs. Allowed features: \
        learn, forward, flood, uu_flood and arp_term. Status False means \
        disable, status True means enable the feature.
        :raise: ValueError in case of unknown feature in the input.
        """
        for flag in args:
            if flag == "learn":
                feature_bitmap = 1 << 0
            elif flag == "forward":
                feature_bitmap = 1 << 1
            elif flag == "flood":
                feature_bitmap = 1 << 2
            elif flag == "uu_flood":
                feature_bitmap = 1 << 3
            elif flag == "arp_term":
                feature_bitmap = 1 << 4
            else:
                raise ValueError("Unknown feature used: %s" % flag)
            is_set = 1 if args[flag] else 0
            self.vapi.bridge_flags(bd_id, is_set, feature_bitmap)
        self.logger.info("Bridge domain ID %d updated" % bd_id)

    def verify_arp(self, src_host, req_hosts, resp_hosts, bd_id=1):
        reqs = self.arp_reqs(src_host, req_hosts)

        for swif in self.bd_swifs(bd_id):
            swif.add_stream(reqs)

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        for swif in self.bd_swifs(bd_id):
            resp_pkts = swif.get_capture(len(resp_hosts))
            resps = self.arp_resp_hosts(src_host, resp_pkts)
            self.assertEqual(len(resps ^ resp_hosts), 0)

    def test_l2bd_arp_term_01(self):
        """ L2BD arp term - add 5 hosts, verify arp responses
        """
        src_host = self.ip4_host(50, 50, "00:00:11:22:33:44")
        self.bd_add_del(1, is_add=1)
        self.set_bd_flags(1, arp_term=True, flood=False,
                          uu_flood=False, learn=False)
        macs = self.mac_list(range(1, 5))
        hosts = self.ip4_hosts(4, 1, macs)
        self.add_del_arp_term_hosts(hosts, is_add=1)
        self.verify_arp(src_host, hosts, hosts)
        type(self).hosts = hosts

    def test_l2bd_arp_term_02(self):
        """ L2BD arp term - delete 3 hosts, verify arp responses
        """
        src_host = self.ip4_host(50, 50, "00:00:11:22:33:44")
        macs = self.mac_list(range(1, 3))
        deleted = self.ip4_hosts(4, 1, macs)
        self.add_del_arp_term_hosts(deleted, is_add=0)
        remaining = self.hosts - deleted
        self.verify_arp(src_host, self.hosts, remaining)
        type(self).hosts = remaining
        self.bd_add_del(1, is_add=0)

    def test_l2bd_arp_term_03(self):
        """ L2BD arp term - recreate BD1, readd 3 hosts, verify arp responses
        """
        src_host = self.ip4_host(50, 50, "00:00:11:22:33:44")
        self.bd_add_del(1, is_add=1)
        self.set_bd_flags(1, arp_term=True, flood=False,
                          uu_flood=False, learn=False)
        macs = self.mac_list(range(1, 3))
        readded = self.ip4_hosts(4, 1, macs)
        self.add_del_arp_term_hosts(readded, is_add=1)
        self.verify_arp(src_host, self.hosts | readded, readded)
        type(self).hosts = readded

    def test_l2bd_arp_term_04(self):
        """ L2BD arp term - 2 IP4 addrs per host
        """
        src_host = self.ip4_host(50, 50, "00:00:11:22:33:44")
        macs = self.mac_list(range(1, 3))
        sub5_hosts = self.ip4_hosts(5, 1, macs)
        self.add_del_arp_term_hosts(sub5_hosts, is_add=1)
        hosts = self.hosts | sub5_hosts
        self.verify_arp(src_host, hosts, hosts)
        type(self).hosts = hosts
        self.bd_add_del(1, is_add=0)

    def test_l2bd_arp_term_05(self):
        """ L2BD arp term - create and update 10 IP4-mac pairs
        """
        src_host = self.ip4_host(50, 50, "00:00:11:22:33:44")
        self.bd_add_del(1, is_add=1)
        self.set_bd_flags(1, arp_term=True, flood=False,
                          uu_flood=False, learn=False)
        macs1 = self.mac_list(range(10, 20))
        hosts1 = self.ip4_hosts(5, 1, macs1)
        self.add_del_arp_term_hosts(hosts1, is_add=1)
        self.verify_arp(src_host, hosts1, hosts1)
        macs2 = self.mac_list(range(20, 30))
        hosts2 = self.ip4_hosts(5, 1, macs2)
        self.add_del_arp_term_hosts(hosts2, is_add=1)
        self.verify_arp(src_host, hosts1, hosts2)
        self.bd_add_del(1, is_add=0)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
