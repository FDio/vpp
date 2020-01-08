#!/usr/bin/env python3

"""ACL Test Cases """

import unittest
import random

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.layers.inet6 import IPv6ExtHdrFragment
from framework import VppTestCase, VppTestRunner
from util import Host, ppp

from vpp_object import VppObject
from vpp_papi import VppEnum, MACAddress
from vpp_l2 import VppBridgeDomain, VppBridgeDomainPort, VppL2FibEntry
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_match import VppMatchRuleMaskIpMac, VppMatchRuleNTuple, \
    VppMatchRuleExactIpL4, VppMatchSet, VppMatchRuleSets

N_PKTS = 63
INDEX_INVALID = 0xffffffff


class VppAce():
    """
    Access Control Entry that describes a n-tuple match
    """

    def __init__(self, test, action, rule):
        self._test = test
        self.action = action
        self.rule = rule
        self.index = INDEX_INVALID

    def encode(self):
        return ({'action': self.action,
                 'rule': self.rule.encode()})

    def get_stats(self):
        c = self._test.statistics.get_counter("/net/ace2")
        return c[0][self.index]

    def get_pkts(self):
        return self.get_stats()['packets']


class VppACL(VppObject):
    """
    Access Control List
    """

    def __init__(self, test, aces, tag=b""):
        self._test = test
        self.aces = aces
        self.tag = tag

    def add_vpp_config(self):
        rules = []
        for a in self.aces:
            rules.append(a.encode())
        r = self._test.vapi.acl2_update(acl_index=4294967295,
                                        aces=rules,
                                        n_aces=len(rules),
                                        tag=self.tag)
        self.acl_index = r.acl_index

        self._test.assertEqual(len(self.aces), r.n_aces)
        for a, i in zip(self.aces, r.ace_indices):
            a.index = i
        self._test.registry.register(self, self._test.logger)
        return self

    def modify_vpp_config(self, aces):
        self.aces = aces
        rules = []
        for a in self.aces:
            rules.append(a.encode())
        r = self._test.vapi.acl2_update(acl_index=self.acl_index,
                                        aces=rules,
                                        n_aces=len(rules),
                                        tag=self.tag)
        for a, i in zip(self.aces, r.ace_indices):
            a.index = i

    def remove_vpp_config(self):
        self._test.vapi.acl2_del(acl_index=self.acl_index)

    def query_vpp_config(self):
        return self._test.vapi.acl2_dump(self.acl_index)

    def object_id(self):
        return ("acl-%d-%s" % (self.acl_index, self.tag))


class VppAclBind(VppObject):
    """
    ACL Binding to an interfaces
    """

    def __init__(self, test, acls, itf, dir):
        self._test = test
        self.acls = acls
        self.itf = itf
        self.dir = dir

    def add_vpp_config(self):
        ais = []
        for a in self.acls:
            ais.append(a.acl_index)
        self._test.vapi.acl2_bind(sw_if_index=self.itf.sw_if_index,
                                  dir=self.dir,
                                  count=len(self.acls),
                                  acls=ais)
        self._test.registry.register(self, self._test.logger)
        return self

    def modify_vpp_config(self, acls):
        self.acls = acls
        ais = []
        for a in self.acls:
            ais.append(a.acl_index)
        self._test.vapi.acl2_bind(sw_if_index=self.itf.sw_if_index,
                                  dir=self.dir,
                                  count=len(self.acls),
                                  acls=ais)

    def remove_vpp_config(self):
        self._test.vapi.acl2_bind(sw_if_index=self.itf.sw_if_index,
                                  dir=self.dir,
                                  count=0,
                                  acls=[])

    def query_vpp_config(self):
        return self._test.vapi.acl2_bind_dump(self.itf.sw_if_index)

    def object_id(self):
        return ("acl-bind-%d-%s" % (self.dir, self.itf))


class ACL2TestCase(VppTestCase):
    """ ACL-2 Test Case """

    extra_vpp_punt_config = ["acl2", "{", "heap-size 1M", "}"]

    @classmethod
    def setUpClass(cls):
        super(ACL2TestCase, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(ACL2TestCase, cls).tearDownClass()

    def setUp(self):
        super(ACL2TestCase, self).setUp()

        # create 3 pg interfaces
        self.create_pg_interfaces(range(4))

        # pg0 & pg1 L3 interfaces with ip4 and ip6 addresss
        # pg2 & pg3 in L2 bridge
        for i in self.pg_interfaces:
            i.admin_up()

        self.pg0.config_ip4()
        self.pg0.config_ip6()
        self.pg0.resolve_arp()
        self.pg0.resolve_ndp()

        self.pg1.config_ip4()
        self.pg1.config_ip6()
        self.pg1.resolve_arp()
        self.pg1.resolve_ndp()

        # setup the BD connectivity, including the L2FIB entries
        # so we don't flood
        bd = VppBridgeDomain(self, 1).add_vpp_config()
        bp1 = VppBridgeDomainPort(self, bd, self.pg2).add_vpp_config()
        bp2 = VppBridgeDomainPort(self, bd, self.pg3).add_vpp_config()
        VppL2FibEntry(self, bd, self.pg3.remote_mac, self.pg3).add_vpp_config()
        VppL2FibEntry(self, bd, self.pg2.remote_mac, self.pg2).add_vpp_config()

        # short cuts, mainly to defeat PEP
        self.ANY = 0
        self.UDP = VppEnum.vl_api_ip_proto_t.IP_API_PROTO_UDP
        self.TCP = VppEnum.vl_api_ip_proto_t.IP_API_PROTO_TCP
        self.ICMP4 = VppEnum.vl_api_ip_proto_t.IP_API_PROTO_ICMP
        self.ICMP6 = VppEnum.vl_api_ip_proto_t.IP_API_PROTO_ICMP6
        self.DENY = VppEnum.vl_api_acl2_action_t.ACL2_API_ACTION_DENY
        self.PERMIT = VppEnum.vl_api_acl2_action_t.ACL2_API_ACTION_PERMIT
        self.RX = VppEnum.vl_api_direction_t.RX
        self.TX = VppEnum.vl_api_direction_t.TX

        self.vapi.acl2_stats_enable(enable=True)

        self.logger.info(self.vapi.cli("sh acl2 config"))

    def tearDown(self):
        super(ACL2TestCase, self).tearDown()

        self.pg0.unconfig_ip4()
        self.pg0.unconfig_ip6()

        self.pg1.unconfig_ip4()
        self.pg1.unconfig_ip6()

        for i in self.pg_interfaces:
            i.admin_down()

    def test_n_tuple(self):
        """ n-tuple ACEs """

        # route for sent packets
        VppIpRoute(self, "1.1.1.1", 32,
                   [VppRoutePath(self.pg1.remote_ip4,
                                 self.pg1.sw_if_index)]).add_vpp_config()

        permit_port1 = 1111
        permit_port2 = 1112
        deny_port1 = 2222
        deny_port2 = 2223

        p_permit1 = (Ether(dst=self.pg0.local_mac,
                           src=self.pg0.remote_mac) /
                     IP(src="1.1.1.2",
                        dst="1.1.1.1") /
                     UDP(sport=permit_port1, dport=5) /
                     Raw())
        p_permit2 = (Ether(dst=self.pg0.local_mac,
                           src=self.pg0.remote_mac) /
                     IP(src="1.1.1.2",
                        dst="1.1.1.1") /
                     UDP(sport=permit_port2, dport=5) /
                     Raw())
        p_deny1 = (Ether(dst=self.pg0.local_mac,
                         src=self.pg0.remote_mac) /
                   IP(src="1.1.1.2",
                      dst="1.1.1.1") /
                   UDP(sport=deny_port1, dport=5) /
                   Raw())
        p_deny2 = (Ether(dst=self.pg0.local_mac,
                         src=self.pg0.remote_mac) /
                   IP(src="1.1.1.2",
                      dst="1.1.1.1") /
                   UDP(sport=deny_port2, dport=5) /
                   Raw())
        p_miss = (Ether(dst=self.pg0.local_mac,
                        src=self.pg0.remote_mac) /
                  IP(src="1.1.1.2",
                     dst="1.1.1.1") /
                  UDP(sport=5, dport=5) /
                  Raw())

        #
        # The ACL's initial list of ACEs
        #
        aces1 = [VppAce(self, self.PERMIT,
                        VppMatchRuleNTuple("1.1.1.2/32",
                                           "1.1.1.1/32",
                                           self.UDP,
                                           src_ports=[permit_port1,
                                                      permit_port1])),
                 VppAce(self, self.DENY,
                        VppMatchRuleNTuple("1.1.1.2/32",
                                           "1.1.1.1/32", self.UDP,
                                           src_ports=[deny_port1,
                                                      deny_port1]))]

        acl1 = VppACL(self, aces1, b'one').add_vpp_config()

        b_pg0 = VppAclBind(self, [acl1], self.pg0, self.RX).add_vpp_config()

        self.logger.info(self.vapi.cli("sh acl2 acl"))
        self.logger.info(self.vapi.cli("sh acl2 bind detail"))
        self.logger.info(self.vapi.cli("sh int feat pg0"))

        self.send_and_expect(self.pg0, p_permit1 * N_PKTS, self.pg1)
        self.send_and_assert_no_replies(self.pg0, p_deny1 * N_PKTS)
        self.send_and_assert_no_replies(self.pg0, p_miss * N_PKTS)

        #
        # Modify the ACL's list of ACEs
        #
        aces2 = [VppAce(self, self.PERMIT,
                        VppMatchRuleNTuple("1.1.1.2/32",
                                           "1.1.1.1/32", self.UDP,
                                           src_ports=[permit_port2,
                                                      permit_port2])),
                 VppAce(self, self.DENY,
                        VppMatchRuleNTuple("1.1.1.2/32",
                                           "1.1.1.1/32", self.UDP,
                                           src_ports=[deny_port2,
                                                      deny_port2]))]
        acl1.modify_vpp_config(aces2)

        self.send_and_expect(self.pg0, p_permit2 * N_PKTS, self.pg1)
        self.send_and_assert_no_replies(self.pg0, p_permit1 * N_PKTS)
        self.send_and_assert_no_replies(self.pg0, p_deny2 * N_PKTS)
        self.send_and_assert_no_replies(self.pg0, p_miss * N_PKTS)

        #
        # unbind the ACL and test all packets now pass
        #
        b_pg0.remove_vpp_config()

        self.send_and_expect(self.pg0, p_permit2 * N_PKTS, self.pg1)
        self.send_and_expect(self.pg0, p_deny2 * N_PKTS, self.pg1)
        self.send_and_expect(self.pg0, p_miss * N_PKTS, self.pg1)

        # swap the aces back
        acl1.modify_vpp_config(aces1)

        #
        # bind the same ACL on egress
        #
        b_pg1 = VppAclBind(self, [acl1], self.pg1, self.TX).add_vpp_config()

        self.send_and_expect(self.pg0, p_permit1 * N_PKTS, self.pg1)
        self.send_and_assert_no_replies(self.pg0, p_deny1 * N_PKTS)
        self.send_and_assert_no_replies(self.pg0, p_miss * N_PKTS)

        #
        # replace the binding with a different ACL
        #
        acl2 = VppACL(self, aces2, b'one').add_vpp_config()

        b_pg1.modify_vpp_config([acl2])

        # we should now drop what we used to pass
        self.send_and_assert_no_replies(self.pg0, p_permit1 * N_PKTS)

        # and match against the new ACL/ACEs
        self.send_and_expect(self.pg0, p_permit2 * N_PKTS, self.pg1)
        self.send_and_assert_no_replies(self.pg0, p_deny2 * N_PKTS)
        self.send_and_assert_no_replies(self.pg0, p_miss * N_PKTS)

        #
        # bind both ACLs
        #
        b_pg1.modify_vpp_config([acl1, acl2])

        self.logger.info(self.vapi.cli("sh acl2 acl"))
        self.logger.info(self.vapi.cli("sh acl2 bind detail"))

        self.send_and_expect(self.pg0, p_permit1 * N_PKTS, self.pg1)
        self.send_and_assert_no_replies(self.pg0, p_deny1 * N_PKTS)
        self.send_and_expect(self.pg0, p_permit2 * N_PKTS, self.pg1)
        self.send_and_assert_no_replies(self.pg0, p_deny2 * N_PKTS)

        # unbind acl1
        b_pg1.modify_vpp_config([acl2])

        self.send_and_assert_no_replies(self.pg0, p_permit1 * N_PKTS)
        self.send_and_expect(self.pg0, p_permit2 * N_PKTS, self.pg1)

        # unbind all
        b_pg1.remove_vpp_config()

    def test_mask_ip_mac(self):
        """ mask-ip-mac ACEs """

        N_HOSTS = 127

        #
        # Test Rules of type mask-ip-mac
        #  we're not testing whether matching this type of rule for all
        #  paramters wroks, that's done else where. What we're testing is
        #  is that we can decode them correctly and apply them to the correct
        #  place in the switch path.
        # We've also tested the bind/unbind replace etc with the n-tuples above
        # so this is rather simple
        #
        ETH_IP4 = VppEnum.vl_api_ether_type_t.ETHERTYPE_API_IP4
        ETH_IP6 = VppEnum.vl_api_ether_type_t.ETHERTYPE_API_IP6
        SRC = VppEnum.vl_api_match_orientation_t.MATCH_API_SRC
        DST = VppEnum.vl_api_match_orientation_t.MATCH_API_DST

        self.pg2.generate_remote_hosts(N_HOSTS)
        aces = []

        #
        # a permit ACE for each remote host on pg0
        #
        for i in range(N_HOSTS):
            aces.append(VppAce(
                self, self.PERMIT,
                VppMatchRuleMaskIpMac(ETH_IP6,
                                      SRC,
                                      "%s/128" % self.pg2.remote_hosts[i].ip6,
                                      self.pg2.remote_hosts[i].mac)))
            aces.append(VppAce(
                self, self.PERMIT,
                VppMatchRuleMaskIpMac(ETH_IP4,
                                      SRC,
                                      "%s/32" % self.pg2.remote_hosts[i].ip4,
                                      self.pg2.remote_hosts[i].mac)))

        acl = VppACL(self, aces, b'one').add_vpp_config()

        b_pg0 = VppAclBind(self, [acl], self.pg2, self.RX).add_vpp_config()

        # a packet from each remote host
        for i in range(N_HOSTS):
            p4 = (Ether(dst=self.pg3.local_mac,
                        src=self.pg2.remote_hosts[i].mac) /
                  IP(src=self.pg2.remote_hosts[i].ip4,
                     dst=self.pg3.remote_ip4) /
                  UDP(sport=5, dport=5) /
                  Raw())
            p6 = (Ether(dst=self.pg3.local_mac,
                        src=self.pg2.remote_hosts[i].mac) /
                  IPv6(src=self.pg2.remote_hosts[i].ip6,
                       dst=self.pg3.remote_ip6) /
                  UDP(sport=5, dport=5) /
                  Raw())

            self.send_and_expect(self.pg2, p6 * N_PKTS, self.pg3)
            self.send_and_expect(self.pg2, p4 * N_PKTS, self.pg3)

        #
        # try the same ACLs in the TX path
        #
        b_pg0.remove_vpp_config()

        b_pg0 = VppAclBind(self, [acl], self.pg2, self.TX).add_vpp_config()

        self.logger.info(self.vapi.cli("sh acl2 acl"))
        self.logger.info(self.vapi.cli("sh acl2 bind detail"))

        # a packet from each remote host
        for i in range(N_HOSTS):
            p4 = (Ether(dst=self.pg3.local_mac,
                        src=self.pg2.remote_hosts[i].mac) /
                  IP(src=self.pg2.remote_hosts[i].ip4,
                     dst=self.pg3.remote_ip4) /
                  UDP(sport=5, dport=5) /
                  Raw())
            p6 = (Ether(dst=self.pg3.local_mac,
                        src=self.pg2.remote_hosts[i].mac) /
                  IPv6(src=self.pg2.remote_hosts[i].ip6,
                       dst=self.pg3.remote_ip6) /
                  UDP(sport=5, dport=5) /
                  Raw())

            self.send_and_expect(self.pg2, p6 * N_PKTS, self.pg3)
            self.send_and_expect(self.pg2, p4 * N_PKTS, self.pg3)

    def test_sets(self):
        """ Match Set ACEs """

        N_HOSTS = 64

        self.pg0.generate_remote_hosts(N_HOSTS)
        self.pg1.generate_remote_hosts(N_HOSTS)

        self.pg0.configure_ipv4_neighbors()
        self.pg1.configure_ipv4_neighbors()

        EXACT_IP_L4 = VppEnum.vl_api_match_type_t.MATCH_API_TYPE_EXACT_IP_L4
        ETH_IP4 = VppEnum.vl_api_ether_type_t.ETHERTYPE_API_IP4
        ETH_IP6 = VppEnum.vl_api_ether_type_t.ETHERTYPE_API_IP6
        SRC = VppEnum.vl_api_match_orientation_t.MATCH_API_SRC
        DST = VppEnum.vl_api_match_orientation_t.MATCH_API_DST
        self.UDP = VppEnum.vl_api_ip_proto_t.IP_API_PROTO_UDP

        #
        # create 8 sets
        #   4 each with 1/4 of pg0's hosts
        #   4 each with 1/4 of pg1's hosts
        #
        all_pg0 = []
        all_pg1 = []
        for i in range(N_HOSTS):
            all_pg0.append(
                VppMatchRuleExactIpL4(SRC,
                                      self.pg0.remote_hosts[i].ip4,
                                      self.UDP, 80))
            all_pg1.append(
                VppMatchRuleExactIpL4(DST,
                                      self.pg1.remote_hosts[i].ip4,
                                      self.UDP, 80))

        sets_pg0 = []
        sets_pg1 = []
        lists_pg0 = []
        lists_pg1 = []
        handles_pg0 = []
        handles_pg1 = []

        q = int(N_HOSTS / 4)

        for i in range(4):
            s = VppMatchSet(self, EXACT_IP_L4,
                            SRC, ETH_IP4).add_vpp_config()
            sets_pg0.append(s)

            l = all_pg0[i*q:(i+1)*q]
            lists_pg0.append(l)

            h = s.vpp_list_update(l)
            handles_pg0.append(h)

            s = VppMatchSet(self, EXACT_IP_L4,
                            DST, ETH_IP4).add_vpp_config()
            sets_pg1.append(s)

            l = all_pg1[i*q:(i+1)*q]
            lists_pg1.append(l)

            h = s.vpp_list_update(l)
            handles_pg1.append(h)

        self.logger.info(self.vapi.cli("sh match set"))

        #
        # add an ACL that uses one set for source
        #
        ace = VppAce(self, self.PERMIT,
                     VppMatchRuleSets(src=sets_pg0[0]))

        acl = VppACL(self, [ace], b'one').add_vpp_config()

        b_pg0 = VppAclBind(self, [acl], self.pg0, self.RX).add_vpp_config()

        self.logger.info(self.vapi.cli("sh acl2 acl"))

        # only packets sourced from within that set should be allowed
        pkts = []
        for r1, r2 in zip(lists_pg0[0], lists_pg1[0]):
            p = (Ether(dst=self.pg0.local_mac,
                       src=self.pg0.remote_mac) /
                 IP(src=r1.ip, dst=r2.ip) /
                 UDP(sport=80, dport=80) /
                 Raw())
            pkts.append(p)

        self.send_and_expect(self.pg0, pkts, self.pg1)

        self.assertEqual(len(pkts), ace.get_pkts())

        p_drop = (Ether(dst=self.pg0.local_mac,
                        src=self.pg0.remote_mac) /
                  IP(src=self.pg0.remote_ip4,
                     dst=self.pg1.remote_ip4) /
                  UDP(sport=79, dport=5) /
                  Raw())

        self.send_and_assert_no_replies(self.pg0, [p_drop], self.pg1)

        #
        # change the bound ACL to match on both a src and dst set
        #
        ace = VppAce(self, self.PERMIT,
                     VppMatchRuleSets(src=sets_pg0[0],
                                      dst=sets_pg1[0]))
        acl.modify_vpp_config([ace])

        self.send_and_expect(self.pg0, pkts, self.pg1)
        self.send_and_assert_no_replies(self.pg0, [p_drop], self.pg1)

        #
        # change to search all sets
        #
        aces = [VppAce(self, self.PERMIT,
                       VppMatchRuleSets(src=sets_pg0[0],
                                        dst=sets_pg1[0])),
                VppAce(self, self.PERMIT,
                       VppMatchRuleSets(src=sets_pg0[1],
                                        dst=sets_pg1[1])),
                VppAce(self, self.PERMIT,
                       VppMatchRuleSets(src=sets_pg0[2],
                                        dst=sets_pg1[2])),
                VppAce(self, self.PERMIT,
                       VppMatchRuleSets(src=sets_pg0[3],
                                        dst=sets_pg1[3]))]
        acl.modify_vpp_config(aces)

        pkts = []
        for r1, r2 in zip(all_pg0, all_pg1):
            p = (Ether(dst=self.pg0.local_mac,
                       src=self.pg0.remote_mac) /
                 IP(src=r1.ip, dst=r2.ip) /
                 UDP(sport=80, dport=80) /
                 Raw())
            pkts.append(p)

        self.vapi.cli("clear ace")
        self.send_and_expect(self.pg0, pkts, self.pg1)
        for a in aces:
            self.assertEqual(a.get_pkts(), N_HOSTS / 4)
        self.vapi.cli("clear ace")
        self.send_and_expect(self.pg0, pkts, self.pg1)
        for a in aces:
            self.assertEqual(a.get_pkts(), N_HOSTS / 4)

        self.send_and_assert_no_replies(self.pg0, [p_drop], self.pg1)

        # cleanup the lists
        for i in range(4):
            sets_pg0[i].vpp_list_delete(handles_pg0[i])
            sets_pg1[i].vpp_list_delete(handles_pg1[i])


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
