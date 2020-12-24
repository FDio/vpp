#!/usr/bin/env python3

import unittest

from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6, Raw
from scapy.layers.l2 import Ether, ARP, Dot1Q

from vpp_object import VppObject
from framework import VppTestCase, VppTestRunner


class VppLcpPair(VppObject):
    def __init__(self, test, phy, host):
        self._test = test
        self.phy = phy
        self.host = host

    def add_vpp_config(self):
        self._test.vapi.cli("test lcp add phy %s host %s" %
                            (self.phy, self.host))
        self._test.registry.register(self, self._test.logger)
        return self

    def remove_vpp_config(self):
        self._test.vapi.cli("test lcp del phy %s host %s" %
                            (self.phy, self.host))

    def object_id(self):
        return "lcp:%d:%d" % (self.phy.sw_if_index,
                              self.host.sw_if_index)

    def query_vpp_config(self):
        pairs = self._test.vapi.lcp_itf_pair_dump()

        for p in pairs:
            if p.phy_sw_if_index == self.phy.sw_if_index and \
               p.host_sw_if_index == self.host.sw_if_index:
                return True
        return False


class TestLinuxCP(VppTestCase):
    """ Linux Control Plane """

    extra_vpp_plugin_config = ["plugin",
                               "linux_cp_plugin.so",
                               "{", "enable", "}",
                               "plugin",
                               "linux_cp_unittest_plugin.so",
                               "{", "enable", "}"]

    @classmethod
    def setUpClass(cls):
        super(TestLinuxCP, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestLinuxCP, cls).tearDownClass()

    def setUp(self):
        super(TestLinuxCP, self).setUp()

        # create 4 pg interfaces so there are a few addresses
        # in the FIB
        self.create_pg_interfaces(range(4))

        for i in self.pg_interfaces:
            i.admin_up()

    def tearDown(self):
        for i in self.pg_interfaces:
            i.admin_down()
        super(TestLinuxCP, self).tearDown()

    def test_linux_cp_tap(self):
        """ Linux CP TAP """

        #
        # Setup
        #

        arp_opts = {"who-has": 1, "is-at": 2}

        # create two pairs, wihch a bunch of hots on the phys
        hosts = [self.pg0, self.pg1]
        phys = [self.pg2, self.pg3]
        N_HOSTS = 4

        for phy in phys:
            phy.config_ip4()
            phy.generate_remote_hosts(4)
            phy.configure_ipv4_neighbors()

        pair1 = VppLcpPair(self, phys[0], hosts[0]).add_vpp_config()
        pair2 = VppLcpPair(self, phys[1], hosts[1]).add_vpp_config()

        self.logger.info(self.vapi.cli("sh lcp adj verbose"))
        self.logger.info(self.vapi.cli("sh lcp"))

        #
        # Traffic Tests
        #

        # hosts to phys
        for phy, host in zip(phys, hosts):
            for j in range(N_HOSTS):
                p = (Ether(src=phy.local_mac,
                           dst=phy.remote_hosts[j].mac) /
                     IP(src=phy.local_ip4,
                        dst=phy.remote_hosts[j].ip4) /
                     UDP(sport=1234, dport=1234) /
                     Raw())

                rxs = self.send_and_expect(host, [p], phy)

                # verify packet is unchanged
                for rx in rxs:
                    self.assertEqual(p.show2(True), rx.show2(True))

                # ARPs x-connect to phy
                p = (Ether(dst="ff:ff:ff:ff:ff:ff",
                           src=phy.remote_hosts[j].mac) /
                     ARP(op="who-has",
                         hwdst=phy.remote_hosts[j].mac,
                         hwsrc=phy.local_mac,
                         psrc=phy.local_ip4,
                         pdst=phy.remote_hosts[j].ip4))

                rxs = self.send_and_expect(host, [p], phy)

                # verify packet is unchanged
                for rx in rxs:
                    self.assertEqual(p.show2(True), rx.show2(True))

        # phy to host
        for phy, host in zip(phys, hosts):
            for j in range(N_HOSTS):
                p = (Ether(dst=phy.local_mac,
                           src=phy.remote_hosts[j].mac) /
                     IP(dst=phy.local_ip4,
                        src=phy.remote_hosts[j].ip4) /
                     UDP(sport=1234, dport=1234) /
                     Raw())

                rxs = self.send_and_expect(phy, [p], host)

                # verify packet is unchanged
                for rx in rxs:
                    self.assertEqual(p.show2(True), rx.show2(True))

                # ARPs rx'd on the phy are sent to the host
                p = (Ether(dst="ff:ff:ff:ff:ff:ff",
                           src=phy.remote_hosts[j].mac) /
                     ARP(op="is-at",
                         hwsrc=phy.remote_hosts[j].mac,
                         hwdst=phy.local_mac,
                         pdst=phy.local_ip4,
                         psrc=phy.remote_hosts[j].ip4))

                rxs = self.send_and_expect(phy, [p], host)

                # verify packet is unchanged
                for rx in rxs:
                    self.assertEqual(p.show2(True), rx.show2(True))

        # cleanup
        for phy in phys:
            phy.unconfig_ip4()


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
