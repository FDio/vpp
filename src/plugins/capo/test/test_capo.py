#!/usr/bin/env python3

import unittest

from framework import VppTestCase, VppTestRunner
from vpp_ip import DpoProto, INVALID_INDEX
from itertools import product

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.layers.inet import IPerror, TCPerror, UDPerror, ICMPerror
from scapy.layers.inet6 import IPv6, IPerror6, ICMPv6DestUnreach
from scapy.layers.inet6 import ICMPv6EchoRequest, ICMPv6EchoReply

from ipaddress import ip_address, ip_network, \
    IPv4Address, IPv6Address, IPv4Network, IPv6Network

from vpp_object import VppObject
from vpp_papi import VppEnum

icmp4_type = 8  # echo request
icmp4_code = 3
icmp6_type = 128  # echo request
icmp6_code = 3
icmp4_type_2 = 8
icmp4_code_from_2 = 5
icmp4_code_to_2 = 20
icmp6_type_2 = 128
icmp6_code_from_2 = 8
icmp6_code_to_2 = 42
tcp_protocol = 6
icmp_protocol = 1
icmp6_protocol = 58
udp_protocol = 17
src_l4 = 1234
dst_l4 = 4321


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
        self._test.registry.register(self, self._test.logger)
        self._test.logger.info("capo_policy_create retval=" + str(r.retval))
        self._policy_id = r.policy_id
        self._test.logger.info(self._test.vapi.cli("show capo policies"))

    def capo_policy_update(self, rules):
        self._rules = rules
        self.init_rules()
        self._test.vapi.capo_policy_update(
            self._policy_id,
            len(self.encoded_rules),
            self.encoded_rules)

    def capo_policy_delete(self):
        self._test.vapi.capo_policy_delete(self._policy_id)
        self._test.logger.info(self._test.vapi.cli("show capo policies"))

    def remove_vpp_config(self):
        self._test.logger.info("remove vpp config")
        self.capo_policy_delete()

    def query_vpp_config(self):
        self._test.logger.info("query vpp config")
        self._test.logger.info(self._test.vapi.cli("show capo policies"))

class VppCapoFilter:
    def __init__(self, type=None, value=0, should_match=0):
        self._filter_type = type if type != None else VppEnum.vl_api_capo_rule_filter_type_t.CAPO_RULE_FILTER_NONE_TYPE
        self._filter_value = value
        self._should_match = should_match

    def encode(self):
        return {'type': self._filter_type,
            'value': self._filter_value,
            'should_match': self._should_match}

class VppCapoRule(VppObject):
    def __init__(self, test, is_v6, action, filters):
        self._test = test
        self._af = VppEnum.vl_api_address_family_t.ADDRESS_IP6 if is_v6 else VppEnum.vl_api_address_family_t.ADDRESS_IP4
        self.init_rule(action, filters)

    def init_rule(self, action, filters):
        self._action = action
        self._filters = filters
        self.encoded_filters = []
        for filter in self._filters:
            self.encoded_filters.append(filter.encode())

    def add_vpp_config(self):
        r = self._test.vapi.capo_rule_create(
            {'af': self._af,
             'action': self._action,
             'filters': self.encoded_filters,
             'num_entries': 0,
             'matches': []
            })
        self._test.registry.register(self, self._test.logger)
        self._test.logger.info("capo_rule_create retval=" + str(r.retval))
        self._rule_id = r.rule_id
        self._test.logger.info("rules id : " + str(self._rule_id))
        self._test.logger.info(self._test.vapi.cli("show capo rules"))

    def capo_rule_update(self, action, filters):
        self.init_rule(action, filters)
        self._test.vapi.capo_rule_update(
            self._rule_id,
            {'af': self._af,
             'action': self._action,
             'filters': self.encoded_filters,
             'num_entries': 0,
             'matches': []
            })
        self._test.registry.register(self, self._test.logger)

        self._test.logger.info("capo rule update")
        self._test.logger.info(self._test.vapi.cli("show capo rules"))
    
    def capo_rule_delete(self):
        self._test.vapi.capo_rule_delete(
            self._rule_id)
        self._test.logger.info(self._test.vapi.cli("show capo rules"))

    def remove_vpp_config(self):
        self._test.logger.info("remove vpp config")
        self.capo_rule_delete()

    def query_vpp_config(self):
        self._test.logger.info("query vpp config")
        self._test.logger.info(self._test.vapi.cli("show capo rules"))

class TestCapo(VppTestCase):
    """ CAPO  """
    @classmethod
    def setUpClass(cls):
        super(TestCapo, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestCapo, cls).tearDownClass()

    def setUp(self):
        super(TestCapo, self).setUp()

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
        super(TestCapo, self).tearDown()

    def configure_policies(self, policies, interface, pass_policy_id):
        id_list = []
        for policy in policies:
            id_list.append(policy._policy_id)

        self.vapi.capo_configure_policies(
             interface.sw_if_index,
             len(id_list),
             pass_policy_id,
             id_list)

    def capo_test_icmp(self, is_v6):
        IP46 = IPv6 if is_v6 else IP
        ICMP46 = ICMPv6EchoRequest if is_v6 else ICMP
        ip_v = "ip6" if is_v6 else "ip4"
        icmp_load = b'\x0a' * 18
        icmp_type = icmp6_type if is_v6 else icmp4_type
        icmp_code = icmp6_code if is_v6 else icmp4_code

        # Define filter on ICMP type
        filters = [
            VppCapoFilter(VppEnum.vl_api_capo_rule_filter_type_t.CAPO_RULE_FILTER_ICMP_TYPE,
                          value=icmp6_type if is_v6 else icmp4_type, 
                          should_match=1),
            VppCapoFilter(), 
            VppCapoFilter()]

        # Create rule with action=CAPO_ALLOW
        rule_icmp_type = VppCapoRule(self, 
                            is_v6=is_v6, 
                            action=VppEnum.vl_api_capo_rule_action_t.CAPO_ALLOW, 
                            filters=filters)
        rule_icmp_type.add_vpp_config()
        rules = [VppCapoPolicyItem(is_inbound=1, rule_id=rule_icmp_type._rule_id)]

        # Create policy
        policy0 = VppCapoPolicy(self, rules)
        policy0.add_vpp_config()

        # Configure policy
        self.configure_policies( [ policy0 ], interface=self.pg1, pass_policy_id=0)

        # Send icmp pg0 -> pg1 
        client_addr = getattr(self.pg0, "remote_" + ip_v)
        remote_addr = getattr(self.pg1, "remote_" + ip_v)
        icmp_echo_request = (Ether(src=self.pg0.remote_mac,
                                dst=self.pg0.local_mac) /
                          IP46(src=client_addr, dst=remote_addr) /
                          ICMP46(type=icmp_type, code=icmp_code) /
                          Raw(load=icmp_load))
        rx = self.send_and_expect(self.pg0, icmp_echo_request * 1, self.pg1)
        rx = rx[0]

        self.assertEqual(rx[IP46].dst, remote_addr)
        self.assertEqual(rx[IP46].src, client_addr)
        self.assertEqual(rx[ICMP46].type, icmp_type)
        self.assertEqual(rx[ICMP46].code, icmp_code)

        # send icmp packet with random type/code
        icmp_echo_request = (Ether(src=self.pg0.remote_mac,
                                dst=self.pg0.local_mac) /
                          IP46(src=client_addr, dst=remote_addr) /
                          ICMP46(type=11, code=22) /
                          Raw(load=icmp_load))

        rx = self.send_and_assert_no_replies(self.pg0, icmp_echo_request * 1, self.pg1)
        
        # TODO : not pass
        # update rule with action=CAPO_DENY
        rule_icmp_type.capo_rule_update(action=VppEnum.vl_api_capo_rule_action_t.CAPO_DENY, 
                            filters=filters)
        
        icmp_echo_request = (Ether(src=self.pg0.remote_mac,
                                dst=self.pg0.local_mac) /
                          IP46(src=client_addr, dst=remote_addr) /
                          ICMP46(type=icmp_type, code=icmp_code ) /
                          Raw(load=icmp_load))
        # send icmp packet with echo request type/code and expect no packet
        rx = self.send_and_assert_no_replies(self.pg0, icmp_echo_request * 1, self.pg1)

        # Define filter on ICMP type  / should match = 0
        filters = [
            VppCapoFilter(VppEnum.vl_api_capo_rule_filter_type_t.CAPO_RULE_FILTER_ICMP_TYPE,
                          value=icmp_type, should_match=0),
            VppCapoFilter(), 
            VppCapoFilter()]
        
        rule_icmp_type.capo_rule_update(action=VppEnum.vl_api_capo_rule_action_t.CAPO_DENY, 
                        filters=filters)
        # send icmp echo request and expect the packet is not filtered
        icmp_echo_request = (Ether(src=self.pg0.remote_mac,
                                dst=self.pg0.local_mac) /
                          IP46(src=client_addr, dst=remote_addr) /
                          ICMP46(type=icmp_type, code=icmp_code) /
                          Raw(load=icmp_load))
        rx = self.send_and_expect(self.pg0, icmp_echo_request * 1, self.pg1)
        rx = rx[0]

        # TODO : not pass
        # Remove rule and policy
        rule_icmp_type.remove_vpp_config()
        policy0.remove_vpp_config() 
        # send icmp packet with random type/code and assert replie
        icmp_echo_request = (Ether(src=self.pg0.remote_mac,
                                dst=self.pg0.local_mac) /
                          IP46(src=client_addr, dst=remote_addr) /
                          ICMP46(type=11, code=22) /
                          Raw(load=icmp_load))
        rx = self.send_and_expect(self.pg0, icmp_echo_request * 1, self.pg1)
        rx = rx[0]

    def test_icmp4(self):
        self.capo_test_icmp(is_v6 = False)

    def test_icmp6(self):
        self.capo_test_icmp(is_v6 = True)

    def capo_test_l4proto(self, is_v6, l4proto):
        IP46 = IPv6 if is_v6 else IP
        ip_v = "ip6" if is_v6 else "ip4"

        filter_value = 0
        if l4proto == TCP:
            filter_value = tcp_protocol
        elif l4proto == UDP:
            filter_value = udp_protocol

        # Define filter on l4proto type
        filters = [
            VppCapoFilter(VppEnum.vl_api_capo_rule_filter_type_t.CAPO_RULE_FILTER_L4_PROTO,
                          value=filter_value, 
                          should_match=1),
            VppCapoFilter(), 
            VppCapoFilter()]

        # Create rule with action=CAPO_ALLOW
        rule_l4_proto = VppCapoRule(self, 
                            is_v6=is_v6, 
                            action=VppEnum.vl_api_capo_rule_action_t.CAPO_ALLOW, 
                            filters=filters)
        rule_l4_proto.add_vpp_config()
        rules = [VppCapoPolicyItem(is_inbound=1, rule_id=rule_l4_proto._rule_id)]

        # Create policy
        policy0 = VppCapoPolicy(self, rules)
        policy0.add_vpp_config()

        # Configure policy
        self.configure_policies( [ policy0 ], self.pg1, 0)

        # Send tcp pg0 -> pg1 
        client_addr = getattr(self.pg0, "remote_" + ip_v)
        remote_addr = getattr(self.pg1, "remote_" + ip_v)

        pkt = (Ether(src=self.pg0.remote_mac,
                          dst=self.pg0.local_mac) /
                          IP46(src=client_addr, dst=remote_addr) /
                          l4proto(sport=src_l4, dport=dst_l4))

        rx = self.send_and_expect(self.pg0, pkt * 1, self.pg1)
        rx = rx[0]

        self.assertEqual(rx[IP46].dst, remote_addr)
        self.assertEqual(rx[IP46].src, client_addr)
        self.assertEqual(rx[IP46].sport, src_l4)
        self.assertEqual(rx[IP46].dport, dst_l4)

        ## TODO : not pass
        # send icmp packet and expect packet is filtered
        pkt = (Ether(src=self.pg0.remote_mac,
                                dst=self.pg0.local_mac) /
                          IP46(src=client_addr, dst=remote_addr) /
                          ICMP(type=8, code=3) /
                          Raw(load=b'\x0a' * 18))
        rx = self.send_and_assert_no_replies(self.pg0, pkt * 1, self.pg1)

        # update rule with action=CAPO_DENY 
        rule_l4_proto.capo_rule_update(action=VppEnum.vl_api_capo_rule_action_t.CAPO_DENY, 
                            filters=filters)
        
        pkt = (Ether(src=self.pg0.remote_mac,
                          dst=self.pg0.local_mac) /
                          IP46(src=client_addr, dst=remote_addr) /
                          l4proto(sport=src_l4, dport=dst_l4))
        # send packet and expect packet is filtered
        rx = self.send_and_assert_no_replies(self.pg0, pkt * 1, self.pg1)

        # Define filter on l4proto / should match = 0
        filters = [
            VppCapoFilter(VppEnum.vl_api_capo_rule_filter_type_t.CAPO_RULE_FILTER_L4_PROTO,
                          value=filter_value, should_match=0),
            VppCapoFilter(), 
            VppCapoFilter()]
        # update rule with ACTION=CAPO_DENY
        rule_l4_proto.capo_rule_update(action=VppEnum.vl_api_capo_rule_action_t.CAPO_DENY, 
                        filters=filters)

        # send l4proto packet and expect it is not filtered
        pkt = (Ether(src=self.pg0.remote_mac,
                          dst=self.pg0.local_mac) /
                          IP46(src=client_addr, dst=remote_addr) /
                          l4proto(sport=src_l4, dport=dst_l4))
        rx = self.send_and_expect(self.pg0, pkt * 1, self.pg1)
        rx = rx[0]

        ## TODO : not pass 
        # send icmp packet and expect it is filtered
        pkt = (Ether(src=self.pg0.remote_mac,
                                dst=self.pg0.local_mac) /
                          IP46(src=client_addr, dst=remote_addr) /
                          ICMP(type=8, code=3) /
                          Raw(load=b'\x0a' * 18))
        rx = self.send_and_assert_no_replies(self.pg0, pkt * 1, self.pg1)

        ## TODO : not pass    
        # Remove rule and policy
        rule_l4_proto.remove_vpp_config()
        policy0.remove_vpp_config() 
        # send icmp packet and expect it is not filtered
        pkt = (Ether(src=self.pg0.remote_mac,
                                dst=self.pg0.local_mac) /
                          IP46(src=client_addr, dst=remote_addr) /
                          ICMP(type=8, code=3) /
                          Raw(load=b'\x0a' * 18))
        rx = self.send_and_expect(self.pg0, pkt * 1, self.pg1)
        
    def test_tcp4(self):
        self.capo_test_l4proto(False, TCP)

    def test_tcp6(self):
        self.capo_test_l4proto(True, TCP)

    def test_udp4(self):
        self.capo_test_l4proto(False, UDP)

    def test_udp6(self):
        self.capo_test_l4proto(True, UDP)