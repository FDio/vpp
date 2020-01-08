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


PORT_RANGE_BEGIN = 0x0
PORT_RANGE_END = 0xffff
ICMP_RANGE_BEGIN = 0x0
ICMP_RANGE_END = 0xff
N_PKTS = 63


class VppAceNTuple():
    """
    Access Control Entry that describes a n-tuple match
    """

    def __init__(self, action, src_ip, dst_ip, proto,
                 src_ports=[PORT_RANGE_BEGIN, PORT_RANGE_END],
                 dst_ports=[PORT_RANGE_BEGIN, PORT_RANGE_END],
                 icmp_types=[ICMP_RANGE_BEGIN, ICMP_RANGE_END],
                 icmp_codes=[ICMP_RANGE_BEGIN, ICMP_RANGE_END],
                 tcp_flags=[0, 0]):
        self.action = action
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.proto = proto
        self.src_ports = {
            'mpr_begin': src_ports[0],
            'mpr_end': src_ports[1],
        }
        self.dst_ports = {
            'mpr_begin': dst_ports[0],
            'mpr_end': dst_ports[1],
        }
        self.icmp_types = {
            'mitr_begin': icmp_types[0],
            'mitr_end': icmp_types[1],
        },
        self.icmp_codes = {
            'micr_begin': icmp_codes[0],
            'micr_end': icmp_codes[1],
        },
        self.tcp_flags = {
            'mtf_flags': tcp_flags[0],
            'mtf_mask': tcp_flags[1],
        }
        self.ETH_IP4 = VppEnum.vl_api_ether_type_t.ETHERTYPE_API_IP4
        self.UDP = VppEnum.vl_api_ip_proto_t.IP_API_PROTO_UDP
        self.TCP = VppEnum.vl_api_ip_proto_t.IP_API_PROTO_TCP
        self.ICMP4 = VppEnum.vl_api_ip_proto_t.IP_API_PROTO_ICMP
        self.ICMP6 = VppEnum.vl_api_ip_proto_t.IP_API_PROTO_ICMP6
        self.MASK_N_TUPLE = VppEnum.vl_api_match_type_t.MATCH_API_TYPE_MASK_N_TUPLE

    def encode(self):
        if self.proto == self.TCP or self.proto == self.UDP:
            rule = ({'action': self.action,
                     'rule': {
                         'mr_type': self.MASK_N_TUPLE,
                         'mr_proto': self.ETH_IP4,
                         'mr_union': {
                             'mask_n_tuple': {
                                 'mnt_src_ip': self.src_ip,
                                 'mnt_dst_ip': self.dst_ip,
                                 'mnt_proto': self.proto,
                                 'mnt_l4': {
                                     'mlu_l4': {
                                         'ml4_src_port': self.src_ports,
                                         'ml4_dst_port': self.dst_ports,
                                         'ml4_tcp': self.tcp_flags,
                                     }}}
                         }}})
        elif self.proto == self.ICMP4 or self.proto == self.ICMP6:
            rule = ({'action': self.action,
                     'rule': {
                         'mr_type': self.MASK_N_TUPLE,
                         'mr_proto': self.ETH_IP4,
                         'mr_union': {
                             'mask_n_tuple': {
                                 'mnt_src_ip': self.src_ip,
                                 'mnt_dst_ip': self.dst_ip,
                                 'mnt_proto': self.proto,
                                 'mnt_l4': {
                                     'mlu_icmp': {
                                         'mir_codes': self.icmp_codes,
                                         'mir_types': self.icmp_types,
                                     }}}
                         }}})
        else:
            rule = ({'action': self.action,
                     'rule': {
                         'mr_type': self.MASK_N_TUPLE,
                         'mr_proto': self.ETH_IP4,
                         'mr_union': {
                             'mask_n_tuple': {
                                 'mnt_src_ip': self.src_ip,
                                 'mnt_dst_ip': self.dst_ip,
                                 'mnt_proto': 0,
                             }}}})
        return rule


class VppAceMaskIpMac():
    """
    Access Control Entry that describes a mask-ip-mac match
    """

    def __init__(self, action, ether_type, orientation,
                 ip, mac,
                 mac_mask=MACAddress("ff:ff:ff:ff:ff:ff")):
        self.action = action
        self.ether_type = ether_type
        self.orientation = orientation
        self.ip = ip
        self.mac = mac
        self.mask = mac_mask
        self.MASK_IP_MAC = VppEnum.vl_api_match_type_t.MATCH_API_TYPE_MASK_IP_MAC

    def encode(self):
        rule = ({'action': self.action,
                 'rule': {
                     'mr_type': self.MASK_IP_MAC,
                     'mr_proto': self.ether_type,
                     'mr_orientation': self.orientation,
                     'mr_union': {
                         'mask_ip_mac': {
                             'mmim_ip': self.ip,
                             'mmim_mac': {
                                 'mmm_mac': self.mac,
                                 'mmm_mask': self.mask,
                             }}}}})
        return rule


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
                                        count=len(rules),
                                        tag=self.tag)
        self.acl_index = r.acl_index
        self._test.registry.register(self, self._test.logger)
        return self

    def modify_vpp_config(self, aces):
        self.aces = aces
        rules = []
        for a in self.aces:
            rules.append(a.encode())
        r = self._test.vapi.acl2_update(acl_index=self.acl_index,
                                        aces=rules,
                                        count=len(rules),
                                        tag=self.tag)

    def remove_vpp_config(self):
        self._test.vapi.acl2_del(acl_index=self.acl_index)

    def query_vpp_config(self):
        return self._test.vapi.acl2_dump(self.acl_index)

    def object_id(self):
        return ("acl-%d-%s" % (self.acl_index, self.tag))

    def get_stats(self):
        c = self._test.statistics.get_counter("/acl2/%d/matches" %
                                              self.acl_index)


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
        aces1 = [VppAceNTuple(self.PERMIT, "1.1.1.2/32",
                              "1.1.1.1/32", self.UDP,
                              src_ports=[permit_port1,
                                         permit_port1]),
                 VppAceNTuple(self.DENY, "1.1.1.2/32",
                              "1.1.1.1/32", self.UDP,
                              src_ports=[deny_port1,
                                         deny_port1])]

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
        aces2 = [VppAceNTuple(self.PERMIT, "1.1.1.2/32",
                              "1.1.1.1/32", self.UDP,
                              src_ports=[permit_port2,
                                         permit_port2]),
                 VppAceNTuple(self.DENY, "1.1.1.2/32",
                              "1.1.1.1/32", self.UDP,
                              src_ports=[deny_port2,
                                         deny_port2])]
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
            aces.append(VppAceMaskIpMac(self.PERMIT, ETH_IP6, SRC,
                                        "%s/128" % self.pg2.remote_hosts[i].ip6,
                                        self.pg2.remote_hosts[i].mac))
            aces.append(VppAceMaskIpMac(self.PERMIT, ETH_IP4, SRC,
                                        "%s/32" % self.pg2.remote_hosts[i].ip4,
                                        self.pg2.remote_hosts[i].mac))

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


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
