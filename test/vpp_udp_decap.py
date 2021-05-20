#!/usr/bin/env python3
"""
  UDP decap objects
"""

from vpp_object import VppObject
from socket import inet_pton, inet_ntop, AF_INET, AF_INET6


class VppUdpDecap(VppObject):

    def __init__(self,
                 test,
                 is_ip4,
                 dst_port,
                 next_node):
        self._test = test
        self.is_ip4 = is_ip4
        self.dst_port = dst_port
        self.next_node = next_node
        self.active = False

    def add_vpp_config(self):
        r = self._test.vapi.get_node_index(self.next_node)
        self._test.vapi.udp_decap_add_del(1, self.is_ip4,
                                          self.dst_port, r.node_index)
        self._test.registry.register(self, self._test.logger)
        self.active = True

    def query_vpp_config(self):
        return self.active

    def remove_vpp_config(self):
        self._test.vapi.udp_decap_add_del(False, self.is_ip4, self.dst_port, 0)
        self.active = False
