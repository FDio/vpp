#!/usr/bin/env python3

""" Match Types """

import unittest

from vpp_object import VppObject
from vpp_papi import VppEnum, MACAddress


PORT_RANGE_BEGIN = 0x0
PORT_RANGE_END = 0xffff
ICMP_RANGE_BEGIN = 0x0
ICMP_RANGE_END = 0xff


class VppMatchRuleNTuple():
    """
    Match Rule that describes a n-tuple match
    """

    def __init__(self, src_ip, dst_ip, proto,
                 src_ports=[PORT_RANGE_BEGIN, PORT_RANGE_END],
                 dst_ports=[PORT_RANGE_BEGIN, PORT_RANGE_END],
                 icmp_types=[ICMP_RANGE_BEGIN, ICMP_RANGE_END],
                 icmp_codes=[ICMP_RANGE_BEGIN, ICMP_RANGE_END],
                 tcp_flags=[0, 0]):
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

    def encode(self):
        ETH_IP4 = VppEnum.vl_api_ether_type_t.ETHERTYPE_API_IP4
        UDP = VppEnum.vl_api_ip_proto_t.IP_API_PROTO_UDP
        TCP = VppEnum.vl_api_ip_proto_t.IP_API_PROTO_TCP
        ICMP4 = VppEnum.vl_api_ip_proto_t.IP_API_PROTO_ICMP
        ICMP6 = VppEnum.vl_api_ip_proto_t.IP_API_PROTO_ICMP6
        MASK_N_TUPLE = VppEnum.vl_api_match_type_t.MATCH_API_TYPE_MASK_N_TUPLE

        if self.proto == TCP or self.proto == UDP:
            rule = ({'mr_type': MASK_N_TUPLE,
                     'mr_proto': ETH_IP4,
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
                     }})
        elif self.proto == ICMP4 or self.proto == ICMP6:
            rule = ({'mr_type': MASK_N_TUPLE,
                     'mr_proto': ETH_IP4,
                     'mr_union': {
                         'mask_n_tuple': {
                             'mnt_src_ip': self.src_ip,
                             'mnt_dst_ip': self.dst_ip,
                             'mnt_proto': self.proto,
                             'mnt_l4': {
                                 'mlu_icmp': {
                                     'mir_codes': self.icmp_codes,
                                     'mir_types': self.icmp_types,
                                 }}}}})
        else:
            rule = ({'mr_type': MASK_N_TUPLE,
                     'mr_proto': ETH_IP4,
                     'mr_union': {
                         'mask_n_tuple': {
                             'mnt_src_ip': self.src_ip,
                             'mnt_dst_ip': self.dst_ip,
                             'mnt_proto': 0,
                         }}})
        return rule


class VppMatchRuleMaskIpMac():
    """
    Match Rule that describes a mask-ip-mac
    """

    def __init__(self, ether_type, orientation,
                 ip, mac,
                 mac_mask=MACAddress("ff:ff:ff:ff:ff:ff")):
        self.ether_type = ether_type
        self.orientation = orientation
        self.ip = ip
        self.mac = mac
        self.mask = mac_mask

    def encode(self):
        MASK_IP_MAC = VppEnum.vl_api_match_type_t.MATCH_API_TYPE_MASK_IP_MAC
        rule = ({'mr_type': MASK_IP_MAC,
                 'mr_proto': self.ether_type,
                 'mr_orientation': self.orientation,
                 'mr_union': {
                     'mask_ip_mac': {
                         'mmim_ip': self.ip,
                         'mmim_mac': {
                             'mmm_mac': self.mac,
                             'mmm_mask': self.mask,
                         }}}})
        return rule


class VppMatchRuleExactIpL4():
    """
    Match Rule that describes a exact-ip-port
    """

    def __init__(self, orientation,
                 ip, proto, port):
        self.orientation = orientation
        self.ip = ip
        self.proto = proto
        self.port = port

    def encode(self):
        EXACT_IP_L4 = VppEnum.vl_api_match_type_t.MATCH_API_TYPE_EXACT_IP_L4
        ETH_IP4 = VppEnum.vl_api_ether_type_t.ETHERTYPE_API_IP4
        ETH_IP6 = VppEnum.vl_api_ether_type_t.ETHERTYPE_API_IP6

        rule = ({'mr_type': EXACT_IP_L4,
                 'mr_proto': ETH_IP4,
                 'mr_orientation': self.orientation,
                 'mr_union': {
                     'exact_ip_l4': {
                         'meil_ip': self.ip,
                         'meil_proto': self.proto,
                         'meil_l4': {
                             'mel4_port': self.port,
                         }}}})
        return rule


class VppMatchRuleSets():
    """
    Match Rule that matches on other sets
    """

    def __init__(self, src=None, dst=None):
        self.src = src
        self.dst = dst

    def encode(self):
        SETS = VppEnum.vl_api_match_type_t.MATCH_API_TYPE_SETS
        ETH_IP4 = VppEnum.vl_api_ether_type_t.ETHERTYPE_API_IP4
        SRC = VppEnum.vl_api_match_orientation_t.MATCH_API_SRC
        NV = 0xffffffff

        rule = ({'mr_type': SETS,
                 'mr_proto': ETH_IP4,
                 'mr_orientation': SRC,
                 'mr_union': {
                     'sets': {
                         'mss_src': self.src.index if self.src else NV,
                         'mss_dst': self.dst.index if self.dst else NV,
                     }}})
        return rule


class VppMatchSet(VppObject):
    """
    Match Set
    """

    def __init__(self, test, mtype, mo, etype, tag=b'wallabies'):
        self._test = test
        self.mtype = mtype
        self.mo = mo
        self.etype = etype
        self.tag = tag

    def encode(self):
        return ({'ms_type': self.mtype,
                 'ms_orientation': self.mo,
                 'ms_ether_type': self.etype,
                 'ms_tag': str(self.tag)})

    def add_vpp_config(self):
        r = self._test.vapi.match_set_add(set=self.encode())
        self.index = r.match_set_index
        self._test.registry.register(self, self._test.logger)
        return self

    def remove_vpp_config(self):
        self._test.vapi.match_set_delete(match_set_index=self.index)

    def query_vpp_config(self):
        sets = self._test.vapi.match_set_dump()

        for s in sets:
            if s.set.ms_index == self.index:
                return True
        return False

    def object_id(self):
        return ("match-set-%d-%s" % (self.index, self.tag))

    def vpp_list_update(self, rules, mlist=0xffffffff, prio=0):
        es = []
        for r in rules:
            es.append(r.encode())
        r = self._test.vapi.match_set_list_update(
            match_set_index=self.index,
            match_list_index=mlist,
            priority=prio,
            list=({
                'ml_n_rules': len(es),
                'ml_rules': es}))
        return r.match_list_index

    def vpp_list_delete(self, mlist):
        self._test.vapi.match_set_list_delete(match_set_index=self.index,
                                              match_list_index=mlist)
