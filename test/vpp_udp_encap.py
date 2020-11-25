#!/usr/bin/env python3
"""
  UDP encap objects
"""

from vpp_object import VppObject
from socket import inet_pton, inet_ntop, AF_INET, AF_INET6
from vpp_papi.vpp_stats import combined_counter_sum


def find_udp_encap(test, ue):
    encaps = test.vapi.udp_encap_dump()
    for e in encaps:
        if ue.id == e.udp_encap.id \
           and ue.src_ip == str(e.udp_encap.src_ip) \
           and ue.dst_ip == str(e.udp_encap.dst_ip) \
           and e.udp_encap.dst_port == ue.dst_port \
           and e.udp_encap.src_port == ue.src_port:
            return True

    return False


class VppUdpEncap(VppObject):

    def __init__(self,
                 test,
                 src_ip,
                 dst_ip,
                 src_port,
                 dst_port,
                 table_id=0):
        self._test = test
        self.table_id = table_id
        self.src_ip_s = src_ip
        self.dst_ip_s = dst_ip
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port

    def add_vpp_config(self):
        r = self._test.vapi.udp_encap_add(
            self.src_ip,
            self.dst_ip,
            self.src_port,
            self.dst_port,
            self.table_id)
        self.id = r.id
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.udp_encap_del(self.id)

    def query_vpp_config(self):
        return find_udp_encap(self._test, self)

    def object_id(self):
        return ("udp-encap-%d" % self.id)

    def get_stats(self):
        return combined_counter_sum(
            self._test.statistics.get_counter("/net/udp-encap"),
            self.id)
