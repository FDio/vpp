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
                 next_proto):
        self._test = test
        self.active = False
        self.udp_decap = {
            'is_ip4': is_ip4,
            'port': dst_port,
            'next_proto': next_proto
        }

    def add_vpp_config(self):
        self._test.vapi.udp_decap_add_del(True, self.udp_decap)
        self._test.registry.register(self, self._test.logger)
        self.active = True

    def query_vpp_config(self):
        return self.active

    def remove_vpp_config(self):
        self._test.vapi.udp_decap_add_del(False, self.udp_decap)
        self.active = False
