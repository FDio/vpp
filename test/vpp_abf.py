#!/usr/bin/env python
"""
  ACL Based Forwarding objects
"""

from vpp_object import *
from vpp_ip_route import VppRoutePath
from socket import inet_pton, inet_ntop, AF_INET, AF_INET6


def find_abf_policy(test, id):
    policies = test.vapi.abf_policy_dump()
    for p in policies:
        if id == p.policy.policy_id:
            return True
    return False


def find_abf_itf_attach(test, id, sw_if_index):
    attachs = test.vapi.abf_itf_attach_dump()
    for a in attachs:
        if id == a.attach.policy_id and \
           sw_if_index == a.attach.sw_if_index:
            return True
    return False


class VppAbfPolicy(VppObject):

    def __init__(self,
                 test,
                 policy_id,
                 acl,
                 paths):
        self._test = test
        self.policy_id = policy_id
        self.acl = acl
        self.paths = paths

    def paths_encode(self):
        vpaths = []
        for p in self.paths:
            vpaths.append({'next_hop': p.nh_addr,
                           'next_hop_sw_if_index': p.nh_itf,
                           'next_hop_weight': 1,
                           'next_hop_afi': p.proto,
                           'next_hop_preference': 0,
                           'next_hop_table_id': p.nh_table_id,
                           'next_hop_id': p.next_hop_id,
                           'is_udp_encap': p.is_udp_encap,
                           'next_hop_n_out_labels': len(p.nh_labels),
                           'next_hop_out_label_stack': p.nh_labels})
        return vpaths

    def add_vpp_config(self):
        self._test.vapi.abf_policy_add_del(
            1,
            {'policy_id': self.policy_id,
             'acl_index': self.acl.acl_index,
             'n_paths': len(self.paths),
             'paths': self.paths_encode()})
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.abf_policy_add_del(
            0,
            {'policy_id': self.policy_id,
             'acl_index': self.acl.acl_index,
             'n_paths': len(self.paths),
             'paths': self.paths_encode()})

    def query_vpp_config(self):
        return find_abf_policy(self._test, self.policy_id)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return ("abf-policy-%d" % self.policy_id)


class VppAbfAttach(VppObject):

    def __init__(self,
                 test,
                 policy_id,
                 sw_if_index,
                 priority,
                 is_ipv6=0):
        self._test = test
        self.policy_id = policy_id
        self.sw_if_index = sw_if_index
        self.priority = priority
        self.is_ipv6 = is_ipv6

    def add_vpp_config(self):
        self._test.vapi.abf_itf_attach_add_del(
            1,
            {'policy_id': self.policy_id,
             'sw_if_index': self.sw_if_index,
             'priority': self.priority,
             'is_ipv6': self.is_ipv6})
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.abf_itf_attach_add_del(
            0,
            {'policy_id': self.policy_id,
             'sw_if_index': self.sw_if_index,
             'priority': self.priority,
             'is_ipv6': self.is_ipv6})

    def query_vpp_config(self):
        return find_abf_itf_attach(self._test,
                                   self.policy_id,
                                   self.sw_if_index)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return ("abf-attach-%d-%d" % (self.policy_id, self.sw_if_index))
