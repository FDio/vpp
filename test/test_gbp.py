#!/usr/bin/env python

import unittest
import socket
import struct

from framework import VppTestCase, VppTestRunner
from vpp_object import VppObject

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6

from socket import AF_INET, AF_INET6
from scapy.utils import inet_pton


class VppGbpEndpoint(VppObject):
    """
    GDB Endpoint
    """

    def __init__(self, test, sw_if_index, addr, epg, is_ip6=0):
        self._test = test
        self.sw_if_index = sw_if_index
        self.epg = epg
        self.addr_p = addr
        self.is_ip6 = is_ip6
        if is_ip6:
            self.addr = inet_pton(AF_INET6, addr)
        else:
            self.addr = inet_pton(AF_INET, addr)

    def add_vpp_config(self):
        self._test.vapi.gbp_endpoint_add_del(
            1,
            self.sw_if_index,
            self.addr,
            self.is_ip6,
            self.epg)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.gbp_endpoint_add_del(
            0,
            self.sw_if_index,
            self.addr,
            self.is_ip6,
            self.epg)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "gbp-endpoint;[%d:%s:%d]" % (self.sw_if_index,
                                            self.addr_p,
                                            self.epg)

    def query_vpp_config(self):
        eps = self._test.vapi.gbp_endpoint_dump()
        for ep in eps:
            if ep.endpoint.address == self.addr \
               and ep.endpoint.sw_if_index == self.sw_if_index:
                return True
        return False


class VppGbpContract(VppObject):
    """
    GDB Contract
    """

    def __init__(self, test, src_epg, dst_epg, acl_index):
        self._test = test
        self.acl_index = acl_index
        self.src_epg = src_epg
        self.dst_epg = dst_epg

    def add_vpp_config(self):
        self._test.vapi.gbp_contract_add_del(
            1,
            self.src_epg,
            self.dst_epg,
            self.acl_index)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.gbp_contract_add_del(
            0,
            self.src_epg,
            self.dst_epg,
            self.acl_index)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "gbp-contract;[%d:%s:%d]" % (self.src_epg,
                                            self.dst_epg,
                                            self.acl_index)

    def query_vpp_config(self):
        eps = self._test.vapi.gbp_contract_dump()
        for ep in eps:
            if ep.contract.src_epg == self.src_epg \
               and ep.contract.dst_epg == self.dst_epg:
                return True
        return False


class TestGBP(VppTestCase):
    """ GBP Test Case """

    def setUp(self):
        super(TestGBP, self).setUp()

        # create 6 pg interfaces for pg0 to pg5
        self.create_pg_interfaces(range(6))

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

        super(TestGBP, self).tearDown()

    def test_gbp4(self):
        """ Group Based Policy v4 """

        ep1 = VppGbpEndpoint(self,
                             self.pg0.sw_if_index,
                             self.pg0.remote_ip4,
                             220)
        ep1.add_vpp_config()
        ep2 = VppGbpEndpoint(self,
                             self.pg1.sw_if_index,
                             self.pg1.remote_ip4,
                             220)
        ep2.add_vpp_config()

        ep3 = VppGbpEndpoint(self,
                             self.pg2.sw_if_index,
                             self.pg2.remote_ip4,
                             221)
        ep3.add_vpp_config()
        ep4 = VppGbpEndpoint(self,
                             self.pg3.sw_if_index,
                             self.pg3.remote_ip4,
                             222)
        ep4.add_vpp_config()

        self.logger.info(self.vapi.cli("sh gbp endpoint"))

        #
        # in the abscense of policy, endpoints in the same EPG
        # can communicate
        #
        pkt_intra_epg = (Ether(src=self.pg0.remote_mac,
                               dst=self.pg0.local_mac) /
                         IP(src=self.pg0.remote_ip4,
                            dst=self.pg1.remote_ip4) /
                         UDP(sport=1234, dport=1234) /
                         Raw('\xa5' * 100))

        self.send_and_expect(self.pg0, pkt_intra_epg * 65, self.pg1)

        #
        # in the abscense of policy, endpoints in the different EPG
        # cannot communicate
        #
        pkt_inter_epg_220_to_221 = (Ether(src=self.pg0.remote_mac,
                                          dst=self.pg0.local_mac) /
                                    IP(src=self.pg0.remote_ip4,
                                       dst=self.pg2.remote_ip4) /
                                    UDP(sport=1234, dport=1234) /
                                    Raw('\xa5' * 100))
        pkt_inter_epg_220_to_222 = (Ether(src=self.pg0.remote_mac,
                                          dst=self.pg0.local_mac) /
                                    IP(src=self.pg0.remote_ip4,
                                       dst=self.pg3.remote_ip4) /
                                    UDP(sport=1234, dport=1234) /
                                    Raw('\xa5' * 100))
        pkt_inter_epg_221_to_220 = (Ether(src=self.pg2.remote_mac,
                                          dst=self.pg2.local_mac) /
                                    IP(src=self.pg2.remote_ip4,
                                       dst=self.pg0.remote_ip4) /
                                    UDP(sport=1234, dport=1234) /
                                    Raw('\xa5' * 100))

        self.send_and_assert_no_replies(self.pg0,
                                        pkt_inter_epg_220_to_221 * 65)
        self.send_and_assert_no_replies(self.pg0,
                                        pkt_inter_epg_221_to_220 * 65)

        #
        # A uni-directional contract from EPG 220 -> 221
        #
        c1 = VppGbpContract(self, 220, 221, 0xffffffff)
        c1.add_vpp_config()

        self.send_and_expect(self.pg0,
                             pkt_inter_epg_220_to_221 * 65,
                             self.pg2)
        self.send_and_assert_no_replies(self.pg2,
                                        pkt_inter_epg_221_to_220 * 65)

        #
        # contract for the return direction
        #
        c2 = VppGbpContract(self, 221, 220, 0xffffffff)
        c2.add_vpp_config()

        self.send_and_expect(self.pg0,
                             pkt_inter_epg_220_to_221 * 65,
                             self.pg2)
        self.send_and_expect(self.pg2,
                             pkt_inter_epg_221_to_220 * 65,
                             self.pg0)

        #
        # check that inter group is still disabled for the groups
        # not in the contract.
        #
        self.send_and_assert_no_replies(self.pg0,
                                        pkt_inter_epg_220_to_222 * 65)

        self.logger.info(self.vapi.cli("sh gbp contract"))

        #
        # remove both contracts, traffic stops in both directions
        #
        c2.remove_vpp_config()
        c1.remove_vpp_config()

        self.send_and_assert_no_replies(self.pg2,
                                        pkt_inter_epg_221_to_220 * 65)
        self.send_and_assert_no_replies(self.pg0,
                                        pkt_inter_epg_220_to_221 * 65)
        self.send_and_expect(self.pg0, pkt_intra_epg * 65, self.pg1)

    def test_gbp6(self):
        """ Group Based Policy v6 """

        ep1 = VppGbpEndpoint(self,
                             self.pg0.sw_if_index,
                             self.pg0.remote_ip6,
                             220,
                             is_ip6=1)
        ep1.add_vpp_config()
        ep2 = VppGbpEndpoint(self,
                             self.pg1.sw_if_index,
                             self.pg1.remote_ip6,
                             220,
                             is_ip6=1)
        ep2.add_vpp_config()

        ep3 = VppGbpEndpoint(self,
                             self.pg2.sw_if_index,
                             self.pg2.remote_ip6,
                             221,
                             is_ip6=1)
        ep3.add_vpp_config()
        ep4 = VppGbpEndpoint(self,
                             self.pg3.sw_if_index,
                             self.pg3.remote_ip6,
                             222,
                             is_ip6=1)
        ep4.add_vpp_config()

        self.logger.info(self.vapi.cli("sh gbp endpoint"))

        #
        # in the abscense of policy, endpoints in the same EPG
        # can communicate
        #
        pkt_intra_epg = (Ether(src=self.pg0.remote_mac,
                               dst=self.pg0.local_mac) /
                         IPv6(src=self.pg0.remote_ip6,
                              dst=self.pg1.remote_ip6) /
                         UDP(sport=1234, dport=1234) /
                         Raw('\xa5' * 100))

        self.send_and_expect(self.pg0, pkt_intra_epg * 65, self.pg1)

        #
        # in the abscense of policy, endpoints in the different EPG
        # cannot communicate
        #
        pkt_inter_epg_220_to_221 = (Ether(src=self.pg0.remote_mac,
                                          dst=self.pg0.local_mac) /
                                    IPv6(src=self.pg0.remote_ip6,
                                         dst=self.pg2.remote_ip6) /
                                    UDP(sport=1234, dport=1234) /
                                    Raw('\xa5' * 100))
        pkt_inter_epg_220_to_222 = (Ether(src=self.pg0.remote_mac,
                                          dst=self.pg0.local_mac) /
                                    IPv6(src=self.pg0.remote_ip6,
                                         dst=self.pg3.remote_ip6) /
                                    UDP(sport=1234, dport=1234) /
                                    Raw('\xa5' * 100))
        pkt_inter_epg_221_to_220 = (Ether(src=self.pg2.remote_mac,
                                          dst=self.pg2.local_mac) /
                                    IPv6(src=self.pg2.remote_ip6,
                                         dst=self.pg0.remote_ip6) /
                                    UDP(sport=1234, dport=1234) /
                                    Raw('\xa5' * 100))

        self.send_and_assert_no_replies(self.pg0,
                                        pkt_inter_epg_220_to_221 * 65)
        self.send_and_assert_no_replies(self.pg0,
                                        pkt_inter_epg_221_to_220 * 65)

        #
        # A uni-directional contract from EPG 220 -> 221
        #
        c1 = VppGbpContract(self, 220, 221, 0xffffffff)
        c1.add_vpp_config()

        self.send_and_expect(self.pg0,
                             pkt_inter_epg_220_to_221 * 65,
                             self.pg2)
        self.send_and_assert_no_replies(self.pg2,
                                        pkt_inter_epg_221_to_220 * 65)

        #
        # contract for the return direction
        #
        c2 = VppGbpContract(self, 221, 220, 0xffffffff)
        c2.add_vpp_config()

        self.send_and_expect(self.pg0,
                             pkt_inter_epg_220_to_221 * 65,
                             self.pg2)
        self.send_and_expect(self.pg2,
                             pkt_inter_epg_221_to_220 * 65,
                             self.pg0)

        #
        # check that inter group is still disabled for the groups
        # not in the contract.
        #
        self.send_and_assert_no_replies(self.pg0,
                                        pkt_inter_epg_220_to_222 * 65)

        self.logger.info(self.vapi.cli("sh gbp contract"))

        #
        # remove both contracts, traffic stops in both directions
        #
        c2.remove_vpp_config()
        c1.remove_vpp_config()

        self.send_and_assert_no_replies(self.pg2,
                                        pkt_inter_epg_221_to_220 * 65)
        self.send_and_assert_no_replies(self.pg0,
                                        pkt_inter_epg_220_to_221 * 65)
        self.send_and_expect(self.pg0, pkt_intra_epg * 65, self.pg1)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
