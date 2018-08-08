#!/usr/bin/env python
"""
  UDP encap objects
"""

from vpp_object import *
from socket import inet_pton, inet_ntop, AF_INET, AF_INET6
from vpp_ip import *


def find_udp_encap(test, ue):
    encaps = test.vapi.udp_encap_dump()
    for e in encaps:
        if ue.id == e.udp_encap.id \
           and compare_ip_address(e.udp_encap.src_ip.un,
                                  ue.src_ip.addr.ip_addr) \
           and compare_ip_address(e.udp_encap.dst_ip.un,
                                  ue.dst_ip.addr.ip_addr) \
           and e.udp_encap.dst_port == ue.dst_port \
           and e.udp_encap.src_port == ue.src_port:
            return True

    return False


class VppUdpEncap(VppObject):

    def __init__(self,
                 test,
                 id,
                 src_ip,
                 dst_ip,
                 src_port,
                 dst_port,
                 table_id=0):
        self._test = test
        self.id = id
        self.table_id = table_id
        self.src_ip_s = src_ip
        self.dst_ip_s = dst_ip
        self.src_ip = VppIpAddress(src_ip)
        self.dst_ip = VppIpAddress(dst_ip)
        self.src_port = src_port
        self.dst_port = dst_port

    def add_vpp_config(self):
        self._test.vapi.udp_encap_add(
            self.id,
            self.src_ip.encode(),
            self.dst_ip.encode(),
            self.src_port,
            self.dst_port,
            self.table_id)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.udp_encap_del(self.id)

    def query_vpp_config(self):
        return find_udp_encap(self._test, self)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return ("udp-encap-%d" % self.id)
