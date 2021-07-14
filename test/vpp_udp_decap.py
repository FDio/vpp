#!/usr/bin/env python3
"""
  UDP decap objects
"""

from vpp_object import VppObject
from socket import inet_pton, inet_ntop, AF_INET, AF_INET6


def find_udp_decap(test, ud):
    decaps = test.vapi.udp_decap_dump()
    for d in decaps:
        if ud.udp_decap["is_ip4"] == d.udp_decap.is_ip4 \
           and ud.udp_decap["port"] == d.udp_decap.port:
            return True
    return False


class VppUdpDecap(VppObject):

    def __init__(self,
                 test,
                 is_ip4,
                 dst_port,
                 next_proto):
        self._test = test
        self.udp_decap = {
            'is_ip4': is_ip4,
            'port': dst_port,
            'next_proto': next_proto
        }

    def add_vpp_config(self):
        self._test.vapi.udp_decap_add_del(True, self.udp_decap)
        self._test.registry.register(self, self._test.logger)

    def query_vpp_config(self):
        return find_udp_decap(self._test, self)

    def remove_vpp_config(self):
        self._test.vapi.udp_decap_add_del(False, self.udp_decap)
