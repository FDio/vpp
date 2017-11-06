"""
  UDP encap objects
"""

from vpp_object import *
from socket import inet_pton, inet_ntop, AF_INET, AF_INET6


def find_udp_encap(test, id):
    encaps = test.vapi.udp_encap_dump()
    for e in encaps:
        if id == e.id:
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
                 table_id=0,
                 is_ip6=0):
        self._test = test
        self.id = id
        self.table_id = table_id
        self.is_ip6 = is_ip6
        self.src_ip_s = src_ip
        self.dst_ip_s = dst_ip
        if is_ip6:
            self.src_ip = inet_pton(AF_INET6, src_ip)
            self.dst_ip = inet_pton(AF_INET6, dst_ip)
        else:
            self.src_ip = inet_pton(AF_INET, src_ip)
            self.dst_ip = inet_pton(AF_INET, dst_ip)
        self.src_port = src_port
        self.dst_port = dst_port

    def add_vpp_config(self):
        self._test.vapi.udp_encap_add_del(
            self.id,
            self.src_ip,
            self.dst_ip,
            self.src_port,
            self.dst_port,
            self.table_id,
            is_ip6=self.is_ip6,
            is_add=1)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.udp_encap_add_del(
            self.id,
            self.src_ip,
            self.dst_ip,
            self.src_port,
            self.dst_port,
            self.table_id,
            is_ip6=self.is_ip6,
            is_add=0)

    def query_vpp_config(self):
        return find_udp_encap(self._test, self.id)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return ("udp-encap-%d" % self.id)
