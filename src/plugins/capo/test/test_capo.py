#!/usr/bin/env python3

import random
import unittest
from ipaddress import (IPv4Address, IPv4Network, IPv6Address, IPv6Network,
                       ip_address, ip_network)
from itertools import product

from framework import VppTestCase, VppTestRunner
from scapy.layers.inet import (ICMP, IP, TCP, UDP, ICMPerror, IPerror,
                               TCPerror, UDPerror)
from scapy.layers.inet6 import (ICMPv6DestUnreach, ICMPv6EchoReply,
                                ICMPv6EchoRequest, IPerror6, IPv6)
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from vpp_ip import INVALID_INDEX, DpoProto
from vpp_object import VppObject
from vpp_papi import VppEnum

icmp4_type = 8  # echo request
icmp4_code = 3
icmp6_type = 128  # echo request
icmp6_code = 3
tcp_protocol = 6
icmp_protocol = 1
icmp6_protocol = 58
udp_protocol = 17
src_l4 = 1234
dst_l4 = 4321


def random_payload():
    return Raw(load=bytearray(random.getrandbits(8) for _ in range(20)))


class VppCapoPolicyItem():
    def __init__(self, is_inbound, rule_id):
        self._is_inbound = is_inbound
        self._rule_id = rule_id

    def encode(self):
        return {'rule_id': self._rule_id, 'is_inbound': self._is_inbound}


class VppCapoPolicy(VppObject):
    def __init__(self, test, rules):
        self._test = test
        self._rules = rules
        self.encoded_rules = []
        self.init_rules()

    def init_rules(self):
        self.encoded_rules = []
        for rule in self._rules:
            self.encoded_rules.append(rule.encode())

    def add_vpp_config(self):
        r = self._test.vapi.capo_policy_create(
            len(self.encoded_rules),
            self.encoded_rules)
        self._test.assertEqual(0, r.retval)
        self._test.registry.register(self, self._test.logger)
        self._test.logger.info("capo_policy_create retval=" + str(r.retval))
        self._policy_id = r.policy_id
        self._test.logger.info(self._test.vapi.cli("show capo policies verbose"))

    def capo_policy_update(self, rules):
        self._rules = rules
        self.init_rules()
        r = self._test.vapi.capo_policy_update(
            self._policy_id,
            len(self.encoded_rules),
            self.encoded_rules)
        self._test.assertEqual(0, r.retval)

    def capo_policy_delete(self):
        r = self._test.vapi.capo_policy_delete(self._policy_id)
        self._test.assertEqual(0, r.retval)
        self._test.logger.info(self._test.vapi.cli("show capo policies"))

    def remove_vpp_config(self):
        self.capo_policy_delete()

    def query_vpp_config(self):
        self._test.logger.info("query vpp config")
        self._test.logger.info(self._test.vapi.cli("show capo policies verbose"))


class VppCapoFilter:
    def __init__(self, type=None, value=0, should_match=0):
        self._filter_type = type if type != None else FILTER_TYPE_NONE
        self._filter_value = value
        self._should_match = should_match

    def encode(self):
        return {'type': self._filter_type,
            'value': self._filter_value,
            'should_match': self._should_match}


class VppCapoRule(VppObject):
    def __init__(self, test, is_v6, action, filters=[], matches=[]):
        self._test = test
        # This is actually unused
        self._af = 255
        self.init_rule(action, filters, matches)

    def vpp_id(self):
        return self._rule_id

    def init_rule(self, action, filters=[], matches=[]):
        self._action = action
        self._filters = filters
        self._matches = matches
        self.encoded_filters = []
        for filter in self._filters:
            self.encoded_filters.append(filter.encode())
        while len(self.encoded_filters) < 3:
            self.encoded_filters.append(VppCapoFilter().encode())
        self._test.assertEqual(len(self.encoded_filters), 3)

    def add_vpp_config(self):
        r = self._test.vapi.capo_rule_create(
            {'af': self._af,
             'action': self._action,
             'filters': self.encoded_filters,
             'num_entries': len(self._matches),
             'matches': self._matches
            })
        self._test.assertEqual(0, r.retval)
        self._test.registry.register(self, self._test.logger)
        self._test.logger.info("capo_rule_create retval=" + str(r.retval))
        self._rule_id = r.rule_id
        self._test.logger.info("rules id : " + str(self._rule_id))
        self._test.logger.info(self._test.vapi.cli("show capo rules"))

    def capo_rule_update(self, filters, matches):
        self.init_rule(self._action, filters, matches)
        r = self._test.vapi.capo_rule_update(
            self._rule_id,
            {'af': self._af,
             'action': self._action,
             'filters': self.encoded_filters,
             'num_entries': len(self._matches),
             'matches': self._matches
            })
        self._test.assertEqual(0, r.retval)
        self._test.registry.register(self, self._test.logger)
        self._test.logger.info("capo rule update")
        self._test.logger.info(self._test.vapi.cli("show capo rules"))

    def capo_rule_delete(self):
        r = self._test.vapi.capo_rule_delete(self._rule_id)
        self._test.assertEqual(0, r.retval)
        self._test.logger.info(self._test.vapi.cli("show capo rules"))

    def remove_vpp_config(self):
        self.capo_rule_delete()

    def query_vpp_config(self):
        self._test.logger.info("query vpp config")
        self._test.logger.info(self._test.vapi.cli("show capo rules"))


class VppCapoIpset(VppObject):
    def __init__(self, test, type, members):
        self.test = test
        self.type = type
        self.members = members

    def add_vpp_config(self):
        r = self.test.vapi.capo_ipset_create(self.type)
        self.test.assertEqual(0, r.retval)
        self.vpp_id = r.set_id
        encoded_members = []
        for m in self.members:
            if self.type == IPSET_TYPE_IP:
                encoded_members.append({"val":{"address": m}})
            elif self.type == IPSET_TYPE_IP_PORT:
                encoded_members.append({"val":{"tuple": m}})
            elif self.type == IPSET_TYPE_NET:
                encoded_members.append({"val":{"prefix": m}})
        r = self.test.vapi.capo_ipset_add_del_members(
            set_id=self.vpp_id,
            is_add=True,
            len=len(encoded_members),
            members=encoded_members,
        )
        self.test.assertEqual(0, r.retval)

    def query_vpp_config(self):
        pass

    def remove_vpp_config(self):
        r = self.test.vapi.capo_ipset_delete(set_id=self.vpp_id)
        self.test.assertEqual(0, r.retval)



class BaseCapoTest(VppTestCase):
    @classmethod
    def setUpClass(self):
        super(BaseCapoTest, self).setUpClass()
        # We can't define these before the API is loaded, so here they are...
        global ACTION_ALLOW, ACTION_DENY, ACTION_PASS, ACTION_LOG
        ACTION_ALLOW = VppEnum.vl_api_capo_rule_action_t.CAPO_ALLOW
        ACTION_DENY = VppEnum.vl_api_capo_rule_action_t.CAPO_DENY
        ACTION_PASS = VppEnum.vl_api_capo_rule_action_t.CAPO_PASS
        ACTION_LOG = VppEnum.vl_api_capo_rule_action_t.CAPO_LOG
        global FILTER_TYPE_NONE, FILTER_TYPE_L4_PROTO, FILTER_TYPE_ICMP_CODE, FILTER_TYPE_ICMP_TYPE
        FILTER_TYPE_NONE = VppEnum.vl_api_capo_rule_filter_type_t.CAPO_RULE_FILTER_NONE_TYPE
        FILTER_TYPE_L4_PROTO = VppEnum.vl_api_capo_rule_filter_type_t.CAPO_RULE_FILTER_L4_PROTO
        FILTER_TYPE_ICMP_CODE = VppEnum.vl_api_capo_rule_filter_type_t.CAPO_RULE_FILTER_ICMP_CODE
        FILTER_TYPE_ICMP_TYPE = VppEnum.vl_api_capo_rule_filter_type_t.CAPO_RULE_FILTER_ICMP_TYPE
        global ENTRY_CIDR, ENTRY_PORT_RANGE, ENTRY_PORT_IP_SET, ENTRY_IP_SET
        ENTRY_CIDR = VppEnum.vl_api_capo_entry_type_t.CAPO_CIDR
        ENTRY_PORT_RANGE = VppEnum.vl_api_capo_entry_type_t.CAPO_PORT_RANGE
        ENTRY_PORT_IP_SET = VppEnum.vl_api_capo_entry_type_t.CAPO_PORT_IP_SET
        ENTRY_IP_SET = VppEnum.vl_api_capo_entry_type_t.CAPO_IP_SET
        global IPSET_TYPE_IP, IPSET_TYPE_IP_PORT, IPSET_TYPE_NET
        IPSET_TYPE_IP = VppEnum.vl_api_capo_ipset_type_t.CAPO_IP
        IPSET_TYPE_IP_PORT = VppEnum.vl_api_capo_ipset_type_t.CAPO_IP_AND_PORT
        IPSET_TYPE_NET = VppEnum.vl_api_capo_ipset_type_t.CAPO_NET

        self.create_pg_interfaces(range(2))
        for i in self.pg_interfaces:
            i.admin_up()
            # Add one additional neighbor on each side for tests with different addresses
            i.generate_remote_hosts(2)
            i.config_ip4()
            i.configure_ipv4_neighbors()
            i.config_ip6()
            i.configure_ipv6_neighbors()

    @classmethod
    def tearDownClass(self):
        for i in self.pg_interfaces:
            i.unconfig_ip4()
            i.unconfig_ip6()
            i.admin_down()
        super(BaseCapoTest, self).tearDownClass()


    def setUp(self):
        super(BaseCapoTest, self).setUp()

    def tearDown(self):
        super(BaseCapoTest, self).tearDown()

    def configure_policies(self, interface, ingress, egress, profiles):
        id_list = []
        for policy in ingress + egress + profiles:
            id_list.append(policy._policy_id)

        r = self.vapi.capo_configure_policies(
             interface.sw_if_index,
             len(ingress),
             len(egress),
             len(ingress) + len(egress) + len(profiles),
             id_list)
        self.assertEqual(0, r.retval)

    def base_ip_packet(self, is_v6=False, second_src_ip=False, second_dst_ip=False):
        IP46 = IPv6 if is_v6 else IP
        src_host = self.pg0.remote_hosts[1 if second_src_ip else 0]
        dst_host = self.pg1.remote_hosts[1 if second_dst_ip else 0]
        src_addr = src_host.ip6 if is_v6 else src_host.ip4
        dst_addr = dst_host.ip6 if is_v6 else dst_host.ip4
        return Ether(src=src_host.mac, dst=self.pg0.local_mac) / IP46(src=src_addr,
                dst=dst_addr)

    def do_test_one_rule(self, filters, matches, matching_packets, not_matching_packets):
        # Caution: because of how vpp works, packets may be reordered (v4 first, v6 next)
        # which may break the check on received packets
        # Therefore, in matching packets, all v4 packets must be before all v6 packets
        self.rule.capo_rule_update(filters, matches)
        self.send_test_packets(self.pg0, self.pg1, matching_packets, not_matching_packets)

    def send_test_packets(self, from_if, to_if, passing_packets, dropped_packets):
        if len(passing_packets) > 0:
            rxl = self.send_and_expect(from_if, passing_packets, to_if)
            self.assertEqual(len(rxl), len(passing_packets))
            for i in range(len(passing_packets)):
                rx = rxl[i].payload
                tx = passing_packets[i].payload
                tx = tx.__class__(bytes(tx)) # Compute all fields
                # Remove IP[v6] TTL / checksum that are changed on forwarding
                if IP in tx:
                    del tx.chksum, tx.ttl, rx.chksum, rx.ttl
                elif IPv6 in tx:
                    del tx.hlim, rx.hlim
                self.assertEqual(rx, tx)
        if len(dropped_packets) > 0:
            self.send_and_assert_no_replies(from_if, dropped_packets, to_if, timeout=0.1)
        self.vapi.cli("clear acl-plugin sessions")


class TestCapoMatches(BaseCapoTest):
    """ Calico Policies rule matching tests  """
    @classmethod
    def setUpClass(self):
        super(TestCapoMatches, self).setUpClass()

    @classmethod
    def tearDownClass(self):
        super(TestCapoMatches, self).tearDownClass()

    def setUp(self):
        super(TestCapoMatches, self).setUp()
        self.rule = VppCapoRule(self, is_v6=False, action=ACTION_ALLOW)
        self.rule.add_vpp_config()
        self.policy = VppCapoPolicy(self, [VppCapoPolicyItem(is_inbound=1, rule_id=self.rule.vpp_id())])
        self.policy.add_vpp_config()
        self.configure_policies(self.pg1, [self.policy], [], [])
        self.src_ip_ipset = VppCapoIpset(self, IPSET_TYPE_IP, [self.pg0.remote_ip4, self.pg0.remote_ip6])
        self.src_ip_ipset.add_vpp_config()
        self.dst_ip_ipset = VppCapoIpset(self, IPSET_TYPE_IP, [self.pg1.remote_ip4, self.pg1.remote_ip6])
        self.dst_ip_ipset.add_vpp_config()
        self.src_net_ipset = VppCapoIpset(self, IPSET_TYPE_NET, [self.pg0.remote_ip4+"/32", self.pg0.remote_ip6+"/128"])
        self.src_net_ipset.add_vpp_config()
        self.dst_net_ipset = VppCapoIpset(self, IPSET_TYPE_NET, [self.pg1.remote_ip4+"/32", self.pg1.remote_ip6+"/128"])
        self.dst_net_ipset.add_vpp_config()
        self.src_ipport_ipset = VppCapoIpset(self, IPSET_TYPE_IP_PORT, [
            {"address":self.pg0.remote_ip4, "l4_proto": tcp_protocol, "port": src_l4},
            {"address":self.pg0.remote_ip6, "l4_proto": tcp_protocol, "port": src_l4}
        ])
        self.src_ipport_ipset.add_vpp_config()
        self.dst_ipport_ipset = VppCapoIpset(self, IPSET_TYPE_IP_PORT, [
            {"address":self.pg1.remote_ip4, "l4_proto": tcp_protocol, "port": dst_l4},
            {"address":self.pg1.remote_ip6, "l4_proto": tcp_protocol, "port": dst_l4}
        ])
        self.dst_ipport_ipset.add_vpp_config()

    def tearDown(self):
        self.vapi.cli("clear acl-plugin sessions")
        self.configure_policies(self.pg1, [], [], [])
        self.policy.capo_policy_delete()
        self.rule.capo_rule_delete()
        super(TestCapoMatches, self).tearDown()

    def test_empty_rule(self):
        # Empty rule matches everything
        valid = [
            self.base_ip_packet(False) / TCP(sport=src_l4, dport=dst_l4) / random_payload(),
            self.base_ip_packet(False) / UDP(sport=src_l4, dport=dst_l4) / random_payload(),
            self.base_ip_packet(False) / ICMP(type=icmp4_type, code=icmp4_code) / random_payload(),
            self.base_ip_packet(True) / TCP(sport=src_l4, dport=dst_l4) / random_payload(),
            self.base_ip_packet(True) / UDP(sport=src_l4, dport=dst_l4) / random_payload(),
            self.base_ip_packet(True) / ICMPv6EchoRequest(type=icmp6_type, code=icmp6_code) / random_payload(),
        ]
        self.do_test_one_rule([], [], valid, [])

    def capo_test_icmp(self, is_v6):
        ICMP46 = ICMPv6EchoRequest if is_v6 else ICMP
        icmp_type = icmp6_type if is_v6 else icmp4_type
        icmp_code = icmp6_code if is_v6 else icmp4_code

        # Define filter on ICMP type
        filters = [VppCapoFilter(FILTER_TYPE_ICMP_TYPE, value=icmp_type, should_match=1)]
        valid = self.base_ip_packet(is_v6) / ICMP46(type=icmp_type, code=icmp_code) / random_payload()
        invalid = self.base_ip_packet(is_v6) / ICMP46(type=11, code=22) / random_payload()
        self.do_test_one_rule(filters, [], [valid], [invalid])

        # Define filter on ICMP type  / should match = 0
        filters = [VppCapoFilter(FILTER_TYPE_ICMP_TYPE, value=11, should_match=0)]
        invalid = self.base_ip_packet(is_v6) / ICMP46(type=11, code=icmp_code) / random_payload()
        valid = self.base_ip_packet(is_v6) / ICMP46(type=icmp_type, code=icmp_code) / random_payload()
        self.do_test_one_rule(filters, [], [valid], [invalid])

    def test_icmp4_type(self):
        self.capo_test_icmp(is_v6=False)

    def test_icmp6_type(self):
        self.capo_test_icmp(is_v6=True)

    def capo_test_icmp_code(self, is_v6):
        ICMP46 = ICMPv6EchoRequest if is_v6 else ICMP
        icmp_type = 1 if is_v6 else 3   # Destination unreachable
        icmp_code = 9 # admin prohibited

        # Define filter on ICMP type
        filters = [VppCapoFilter(FILTER_TYPE_ICMP_CODE, value=icmp_code, should_match=1)]
        valid = self.base_ip_packet(is_v6) / ICMP46(type=icmp_type, code=icmp_code) / random_payload()
        invalid = self.base_ip_packet(is_v6) / ICMP46(type=icmp_type, code=icmp_code-1) / random_payload()
        self.do_test_one_rule(filters, [], [valid], [invalid])

        # Define filter on ICMP type  / should match = 0
        filters = [VppCapoFilter(FILTER_TYPE_ICMP_CODE, value=icmp_code, should_match=0)]
        valid = self.base_ip_packet(is_v6) / ICMP46(type=icmp_type, code=icmp_code+1) / random_payload()
        invalid = self.base_ip_packet(is_v6) / ICMP46(type=icmp_type, code=icmp_code) / random_payload()
        self.do_test_one_rule(filters, [], [valid], [invalid])

    def test_icmp4_code(self):
        self.capo_test_icmp(is_v6=False)

    def test_icmp6_code(self):
        self.capo_test_icmp(is_v6=True)

    def capo_test_l4proto(self, is_v6, l4proto):
        filter_value = 0
        if l4proto == TCP:
            filter_value = tcp_protocol
        elif l4proto == UDP:
            filter_value = udp_protocol

        # Define filter on l4proto type
        filters = [VppCapoFilter(FILTER_TYPE_L4_PROTO, value=filter_value, should_match=1)]

        # Send tcp pg0 -> pg1
        valid = self.base_ip_packet(is_v6) / l4proto(sport=src_l4, dport=dst_l4) / random_payload()
        # send icmp packet (different l4proto) and expect packet is filtered
        invalid = self.base_ip_packet(is_v6) / ICMP(type=8, code=3) / random_payload()
        self.do_test_one_rule(filters, [], [valid], [invalid])

        # Define filter on l4proto / should match = 0
        filters = [VppCapoFilter(FILTER_TYPE_L4_PROTO, value=filter_value, should_match=0)]
        # send l4proto packet and expect it is filtered
        invalid = self.base_ip_packet(is_v6) / l4proto(sport=src_l4, dport=dst_l4) / random_payload()
        # send icmp packet (different l4proto) and expect it is not filtered
        valid = self.base_ip_packet(is_v6) / ICMP(type=8, code=3) / random_payload()
        self.do_test_one_rule(filters, [], [valid], [invalid])

    def test_l4proto_tcp4(self):
        self.capo_test_l4proto(False, TCP)

    def test_l4proto_tcp6(self):
        self.capo_test_l4proto(True, TCP)

    def test_l4proto_udp4(self):
        self.capo_test_l4proto(False, UDP)

    def test_l4proto_udp6(self):
        self.capo_test_l4proto(True, UDP)

    def test_prefixes_ip6(self):
        self.test_prefixes(True)

    def test_prefixes(self, is_ip6=False):
        pload = lambda : TCP(sport=src_l4, dport=dst_l4) / random_payload()
        dst_ip_match = self.pg1.remote_ip6 + "/128" if is_ip6 else self.pg1.remote_ip4 + "/32"
        match = {"is_src": False, "is_not": False, "type": ENTRY_CIDR, "data": {"cidr": dst_ip_match}}
        valid = self.base_ip_packet(is_ip6) / pload()
        invalid = self.base_ip_packet(is_ip6, second_dst_ip=True) / pload()
        self.do_test_one_rule([], [match], [valid], [invalid])

        match['is_not'] = True
        self.do_test_one_rule([], [match], [invalid], [valid])

        src_ip_match = self.pg0.remote_ip6 + "/128" if is_ip6 else self.pg0.remote_ip4 + "/32"
        match = {"is_src": True, "is_not": False, "type": ENTRY_CIDR, "data": {"cidr": src_ip_match}}
        valid = self.base_ip_packet(is_ip6) / pload()
        invalid = self.base_ip_packet(is_ip6, second_src_ip=True) / pload()
        self.do_test_one_rule([], [match], [valid], [invalid])

        match['is_not'] = True
        self.do_test_one_rule([], [match], [invalid], [valid])

    def test_port_ranges_ip6(self):
        self.test_prefixes(True)

    def test_port_ranges(self, is_ip6=False):
        base = self.base_ip_packet(is_ip6)
        test_port = 5123
        # Test all match kinds
        match = {"is_src": False, "is_not": False, "type": ENTRY_PORT_RANGE,
                 "data": {"port_range": {"start": test_port, "end": test_port}}}
        valid = base / TCP(sport=test_port, dport=test_port) / random_payload()
        invalid = [
            base / TCP(sport=test_port, dport=test_port+1) / random_payload(),
            base / TCP(sport=test_port, dport=test_port-1) / random_payload(),
        ]
        self.do_test_one_rule([], [match], [valid], invalid)

        match['is_not'] = True
        self.do_test_one_rule([], [match], invalid, [valid])

        match = {"is_src": True, "is_not": False, "type": ENTRY_PORT_RANGE,
                 "data": {"port_range": {"start": test_port, "end": test_port}}}
        valid = base / TCP(sport=test_port, dport=test_port) / random_payload()
        invalid = [
            base / TCP(sport=test_port+1, dport=test_port) / random_payload(),
            base / TCP(sport=test_port-1, dport=test_port) / random_payload(),
        ]
        self.do_test_one_rule([], [match], [valid], invalid)

        match['is_not'] = True
        self.do_test_one_rule([], [match], invalid, [valid])

        # Test port ranges with several ports & UDP
        match = {"is_src": False, "is_not": False, "type": ENTRY_PORT_RANGE,
                 "data": {"port_range": {"start": test_port, "end": test_port+10}}}
        valid = [
            base / TCP(sport=test_port, dport=test_port) / random_payload(),
            base / TCP(sport=test_port, dport=test_port+5) / random_payload(),
            base / TCP(sport=test_port, dport=test_port+10) / random_payload(),
            base / UDP(sport=test_port, dport=test_port) / random_payload(),
            base / UDP(sport=test_port, dport=test_port+5) / random_payload(),
            base / UDP(sport=test_port, dport=test_port+10) / random_payload(),
        ]
        invalid = [
            base / TCP(sport=test_port, dport=test_port-1) / random_payload(),
            base / TCP(sport=test_port, dport=test_port+11) / random_payload(),
        ]
        self.do_test_one_rule([], [match], valid, invalid)


    def test_ip_ipset_ip6(self):
        self.test_ip_ipset(True)

    def test_ip_ipset(self, is_ip6=False):
        pload = lambda : TCP(sport=src_l4, dport=dst_l4) / random_payload()
        dst_ip_match = self.pg1.remote_ip6 + "/128" if is_ip6 else self.pg1.remote_ip4 + "/32"
        match = {"is_src": False, "is_not": False, "type": ENTRY_IP_SET,
                 "data": {"set_id": {"set_id": self.dst_ip_ipset.vpp_id}}}
        valid = self.base_ip_packet(is_ip6) / pload()
        invalid = self.base_ip_packet(is_ip6, second_dst_ip=True) / pload()
        self.do_test_one_rule([], [match], [valid], [invalid])

        match['is_not'] = True
        self.do_test_one_rule([], [match], [invalid], [valid])

        src_ip_match = self.pg0.remote_ip6 + "/128" if is_ip6 else self.pg0.remote_ip4 + "/32"
        match = {"is_src": True, "is_not": False, "type": ENTRY_IP_SET,
                 "data": {"set_id": {"set_id": self.src_ip_ipset.vpp_id}}}
        valid = self.base_ip_packet(is_ip6) / pload()
        invalid = self.base_ip_packet(is_ip6, second_src_ip=True) / pload()
        self.do_test_one_rule([], [match], [valid], [invalid])

        match['is_not'] = True
        self.do_test_one_rule([], [match], [invalid], [valid])

    def test_net_ipset_ip6(self):
        self.test_net_ipset(True)

    def test_net_ipset(self, is_ip6=False):
        pload = lambda : TCP(sport=src_l4, dport=dst_l4) / random_payload()
        dst_ip_match = self.pg1.remote_ip6 + "/128" if is_ip6 else self.pg1.remote_ip4 + "/32"
        match = {"is_src": False, "is_not": False, "type": ENTRY_IP_SET,
                 "data": {"set_id": {"set_id": self.dst_net_ipset.vpp_id}}}
        valid = self.base_ip_packet(is_ip6) / pload()
        invalid = self.base_ip_packet(is_ip6, second_dst_ip=True) / pload()
        self.do_test_one_rule([], [match], [valid], [invalid])

        match['is_not'] = True
        self.do_test_one_rule([], [match], [invalid], [valid])

        src_ip_match = self.pg0.remote_ip6 + "/128" if is_ip6 else self.pg0.remote_ip4 + "/32"
        match = {"is_src": True, "is_not": False, "type": ENTRY_IP_SET,
                 "data": {"set_id": {"set_id": self.src_net_ipset.vpp_id}}}
        valid = self.base_ip_packet(is_ip6) / pload()
        invalid = self.base_ip_packet(is_ip6, second_src_ip=True) / pload()
        self.do_test_one_rule([], [match], [valid], [invalid])

        match['is_not'] = True
        self.do_test_one_rule([], [match], [invalid], [valid])

    def test_ipport_ipset_ip6(self):
        self.test_ipport_ipset(True)

    def test_ipport_ipset(self, is_ip6=False):
        match = {"is_src": False, "is_not": False, "type": ENTRY_PORT_IP_SET,
                 "data": {"set_id": {"set_id": self.dst_ipport_ipset.vpp_id}}}
        valid = self.base_ip_packet(is_ip6) / TCP(sport=src_l4, dport=dst_l4) / random_payload()
        invalid = [ # Change all criteria: address, proto, port
            self.base_ip_packet(is_ip6, second_dst_ip=True) / TCP(sport=src_l4, dport=dst_l4) / random_payload(),
            self.base_ip_packet(is_ip6) / UDP(sport=src_l4, dport=dst_l4) / random_payload(),
            self.base_ip_packet(is_ip6) / TCP(sport=src_l4, dport=dst_l4+1) / random_payload(),
        ]
        self.do_test_one_rule([], [match], [valid], invalid)

        match['is_not'] = True
        self.do_test_one_rule([], [match], invalid, [valid])

        match = {"is_src": True, "is_not": False, "type": ENTRY_PORT_IP_SET,
                 "data": {"set_id": {"set_id": self.src_ipport_ipset.vpp_id}}}
        valid = self.base_ip_packet(is_ip6) / TCP(sport=src_l4, dport=dst_l4) / random_payload()
        invalid = [ # Change all criteria: address, proto, port
            self.base_ip_packet(is_ip6, second_src_ip=True) / TCP(sport=src_l4, dport=dst_l4) / random_payload(),
            self.base_ip_packet(is_ip6) / UDP(sport=src_l4, dport=dst_l4) / random_payload(),
            self.base_ip_packet(is_ip6) / TCP(sport=src_l4+1, dport=dst_l4) / random_payload(),
        ]
        self.do_test_one_rule([], [match], [valid], invalid)

        match['is_not'] = True
        self.do_test_one_rule([], [match], invalid, [valid])

    # Calico specificity: if a rule has port ranges and ipport ipsets, a packet matches
    # the rule if it matches either category
    def test_port_range_and_ipport_ipset_ip6(self):
            self.test_port_range_and_ipport_ipset(True)

    def test_port_range_and_ipport_ipset(self, is_ip6=False):
        # Test all match types to exercies all code (but not all combinations)
        test_port=4569
        matches = [
            {"is_src": False, "is_not": False, "type": ENTRY_PORT_IP_SET,
                "data": {"set_id": {"set_id": self.dst_ipport_ipset.vpp_id}}},
            {"is_src": False, "is_not": False, "type": ENTRY_PORT_RANGE,
                "data": {"port_range": {"start": test_port, "end": test_port}}},
        ]
        valid = [
            self.base_ip_packet(is_ip6) / TCP(sport=src_l4, dport=dst_l4) / random_payload(),
            self.base_ip_packet(is_ip6) / TCP(sport=src_l4, dport=test_port) / random_payload(),
            self.base_ip_packet(is_ip6) / UDP(sport=src_l4, dport=test_port) / random_payload(),
            self.base_ip_packet(is_ip6, second_src_ip=True) / TCP(sport=src_l4, dport=test_port) / random_payload(),
            self.base_ip_packet(is_ip6, second_dst_ip=True) / TCP(sport=src_l4, dport=test_port) / random_payload(),
        ]
        invalid = [
            self.base_ip_packet(is_ip6, second_dst_ip=True) / TCP(sport=src_l4, dport=dst_l4) / random_payload(),
            self.base_ip_packet(is_ip6) / UDP(sport=src_l4, dport=dst_l4) / random_payload(),
            self.base_ip_packet(is_ip6) / TCP(sport=src_l4, dport=(dst_l4+test_port)//2) / random_payload(),
        ]
        self.do_test_one_rule([], matches, valid, invalid)

        for match in matches:
            match['is_not'] = True
        self.do_test_one_rule([], matches, invalid, valid)

        matches = [
            {"is_src": True, "is_not": False, "type": ENTRY_PORT_IP_SET,
                "data": {"set_id": {"set_id": self.src_ipport_ipset.vpp_id}}},
            {"is_src": True, "is_not": False, "type": ENTRY_PORT_RANGE,
                "data": {"port_range": {"start": test_port, "end": test_port}}},
        ]
        valid = [
            self.base_ip_packet(is_ip6) / TCP(sport=src_l4, dport=dst_l4) / random_payload(),
            self.base_ip_packet(is_ip6) / TCP(sport=test_port, dport=dst_l4) / random_payload(),
            self.base_ip_packet(is_ip6) / UDP(sport=test_port, dport=dst_l4) / random_payload(),
            self.base_ip_packet(is_ip6, second_src_ip=True) / TCP(sport=test_port, dport=dst_l4) / random_payload(),
            self.base_ip_packet(is_ip6, second_dst_ip=True) / TCP(sport=test_port, dport=dst_l4) / random_payload(),
        ]
        invalid = [
            self.base_ip_packet(is_ip6, second_src_ip=True) / TCP(sport=src_l4, dport=dst_l4) / random_payload(),
            self.base_ip_packet(is_ip6) / UDP(sport=src_l4, dport=dst_l4) / random_payload(),
            self.base_ip_packet(is_ip6) / TCP(sport=(src_l4+test_port)//2, dport=dst_l4) / random_payload(),
        ]
        self.do_test_one_rule([], matches, valid, invalid)

        for match in matches:
            match['is_not'] = True
        self.do_test_one_rule([], matches, invalid, valid)


class TestCapoPolicies(BaseCapoTest):
    """ Calico Policies tests """
    @classmethod
    def setUpClass(self):
        super(TestCapoPolicies, self).setUpClass()

    @classmethod
    def tearDownClass(self):
        super(TestCapoPolicies, self).tearDownClass()

    def setUp(self):
        super(TestCapoPolicies, self).setUp()

    def tearDown(self):
        super(TestCapoPolicies, self).tearDown()

    def tcp_dport_rule(self, port, action):
        return VppCapoRule(self, is_v6=False, action=action,
            filters=[VppCapoFilter(FILTER_TYPE_L4_PROTO, tcp_protocol, True)],
            matches=[{"is_src": False, "is_not": False, "type": ENTRY_PORT_RANGE,
                        "data": {"port_range": {"start": port, "end": port}}}]
        )

    def test_inbound_outbound(self):
        r = self.tcp_dport_rule(1000, ACTION_ALLOW)
        r.add_vpp_config()
        pin = VppCapoPolicy(self, [VppCapoPolicyItem(is_inbound=1, rule_id=r.vpp_id())])
        pout = VppCapoPolicy(self, [VppCapoPolicyItem(is_inbound=0, rule_id=r.vpp_id())])
        pin.add_vpp_config()
        pout.add_vpp_config()

        matching = self.base_ip_packet() / TCP(sport=1, dport=1000) / random_payload()
        not_matching = self.base_ip_packet() / TCP(sport=1, dport=2000) / random_payload()

        # out policy at src
        self.configure_policies(self.pg0, [], [pout], [])
        self.send_test_packets(self.pg0, self.pg1, [matching], [not_matching])

        # policies configured at src + dst
        self.configure_policies(self.pg1, [pin], [], [])
        self.send_test_packets(self.pg0, self.pg1, [matching], [not_matching])

        # policies configured at dst
        self.configure_policies(self.pg0, [], [], [])
        self.send_test_packets(self.pg0, self.pg1, [matching], [not_matching])

        # no policies
        self.configure_policies(self.pg1, [], [], [])
        self.send_test_packets(self.pg0, self.pg1, [matching, not_matching], [])

    def test_default_verdict(self):
        # If profiles only are configured (pass_id = 0), default is deny
        # If there are policies + profiles (pass_id > 0), then default is to deny before
        # evaluating profiles, unless a rule with a PASS target matches
        rule1 = self.tcp_dport_rule(1000, ACTION_ALLOW)
        rule2 = self.tcp_dport_rule(2000, ACTION_ALLOW)
        rule3 = self.tcp_dport_rule(1000, ACTION_DENY)
        rule4 = self.tcp_dport_rule(1000, ACTION_PASS)
        rule1.add_vpp_config()
        rule2.add_vpp_config()
        rule3.add_vpp_config()
        rule4.add_vpp_config()
        policy1 = VppCapoPolicy(self, [VppCapoPolicyItem(is_inbound=1, rule_id=rule1.vpp_id())])
        policy2 = VppCapoPolicy(self, [VppCapoPolicyItem(is_inbound=1, rule_id=rule2.vpp_id())])
        policy3 = VppCapoPolicy(self, [VppCapoPolicyItem(is_inbound=1, rule_id=rule3.vpp_id())])
        policy4 = VppCapoPolicy(self, [VppCapoPolicyItem(is_inbound=1, rule_id=rule4.vpp_id())])
        policy5 = VppCapoPolicy(self, [
            VppCapoPolicyItem(is_inbound=1, rule_id=rule4.vpp_id()),
            VppCapoPolicyItem(is_inbound=1, rule_id=rule3.vpp_id()),
        ])
        policy1.add_vpp_config()
        policy2.add_vpp_config()
        policy3.add_vpp_config()
        policy4.add_vpp_config()
        policy5.add_vpp_config()

        # Test profile default deny: 1 allow rule, pass_id=0
        self.configure_policies(self.pg1, [], [], [policy1])
        passing = [self.base_ip_packet() / TCP(sport=1, dport=1000) / random_payload()]
        dropped = [self.base_ip_packet() / TCP(sport=1, dport=2000) / random_payload()]
        self.send_test_packets(self.pg0, self.pg1, passing, dropped)

        # Test policy default deny: 1 allow rule, pass_id=1
        self.configure_policies(self.pg1, [policy1], [], [])
        self.send_test_packets(self.pg0, self.pg1, passing, dropped)

        # Test that profiles are not executed when policies are configured
        # 1 allow policy, 1 allow profile, pass_id=1
        self.configure_policies(self.pg1, [policy1], [], [policy2])
        self.send_test_packets(self.pg0, self.pg1, passing, dropped)

        # Test that pass target does not evaluate further policies and jumps to profiles
        # 1 pass policy, 1 deny policy, 1 allow profile, pass_id=2
        self.configure_policies(self.pg1, [policy4, policy3], [], [policy1])
        self.send_test_packets(self.pg0, self.pg1, passing, dropped)

        # Test that pass target does not evaluate further rules in the policy and jumps to profiles
        # 1 policy w/ 1 pass rule & 1 deny rule, 1 deny profile, pass_id=1
        self.configure_policies(self.pg1, [policy5], [], [policy1])
        self.send_test_packets(self.pg0, self.pg1, passing, dropped)

        policy1.remove_vpp_config()
        policy2.remove_vpp_config()
        policy3.remove_vpp_config()
        policy4.remove_vpp_config()
        policy5.remove_vpp_config()
        rule1.remove_vpp_config()
        rule2.remove_vpp_config()
        rule3.remove_vpp_config()
        rule4.remove_vpp_config()

    def test_realistic_policy(self):
        # Rule 1 allows ping from everywhere
        rule1 = VppCapoRule(self, is_v6=False, action=ACTION_ALLOW,
            filters = [
                VppCapoFilter(FILTER_TYPE_L4_PROTO, icmp_protocol, True),
                VppCapoFilter(FILTER_TYPE_ICMP_TYPE, 8, True),
                VppCapoFilter(FILTER_TYPE_ICMP_CODE, 0, True),
            ],
            matches = [],
        )
        rule1.add_vpp_config()
        # Rule 2 allows tcp dport 8080 from a single container
        src_ipset = VppCapoIpset(self, IPSET_TYPE_NET,
                [self.pg0.remote_ip4 + "/32", self.pg0.remote_ip6 + "/128"])
        src_ipset.add_vpp_config()
        rule2 = VppCapoRule(self, is_v6=False, action=ACTION_ALLOW,
            filters=[
                VppCapoFilter(FILTER_TYPE_L4_PROTO, tcp_protocol, True),
            ],
            matches = [
                {"is_src": True, "is_not": False, "type": ENTRY_IP_SET,
                        "data": {"set_id": {"set_id": src_ipset.vpp_id}}},
                {"is_src": False, "is_not": False, "type": ENTRY_PORT_RANGE,
                        "data": {"port_range": {"start": 8080, "end": 8080}}},
            ],
        )
        rule2.add_vpp_config()
        policy = VppCapoPolicy(self, [
            VppCapoPolicyItem(is_inbound=1, rule_id=rule1.vpp_id()),
            VppCapoPolicyItem(is_inbound=1, rule_id=rule2.vpp_id()),
        ])
        policy.add_vpp_config()
        self.configure_policies(self.pg1, [policy], [], [])

        passing = [
            self.base_ip_packet() / ICMP(type=8),
            self.base_ip_packet(second_src_ip=True) / ICMP(type=8),
            self.base_ip_packet() / TCP(sport=1, dport=8080) / random_payload(),
        ]
        dropped = [
            self.base_ip_packet() / ICMP(type=3),
            self.base_ip_packet(second_src_ip=True) / TCP(sport=1, dport=8080) / random_payload(),
            self.base_ip_packet() / UDP(sport=1, dport=8080) / random_payload(),
            self.base_ip_packet() / TCP(sport=1, dport=8081) / random_payload(),
        ]
        self.send_test_packets(self.pg0, self.pg1, passing, dropped)
        # Cleanup
        self.configure_policies(self.pg1, [], [], [])
        policy.remove_vpp_config()
        rule1.remove_vpp_config()
        rule2.remove_vpp_config()
        src_ipset.remove_vpp_config()
