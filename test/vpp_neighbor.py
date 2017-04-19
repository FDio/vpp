"""
  Neighbour Entries

  object abstractions for ARP and ND
"""

from socket import inet_pton, inet_ntop, AF_INET, AF_INET6
from vpp_object import *
from util import mactobinary


def find_nbr(test, sw_if_index, ip_addr, is_static=0, inet=AF_INET):
    nbrs = test.vapi.ip_neighbor_dump(sw_if_index,
                                      is_ipv6=1 if AF_INET6 == inet else 0)
    if inet == AF_INET:
        s = 4
    else:
        s = 16
    nbr_addr = inet_pton(inet, ip_addr)

    for n in nbrs:
        if nbr_addr == n.ip_address[:s] \
           and is_static == n.is_static:
            return True
    return False


class VppNeighbor(VppObject):
    """
    ARP Entry
    """

    def __init__(self, test, sw_if_index, mac_addr, nbr_addr,
                 af=AF_INET, is_static=False, is_no_fib_entry=0):
        self._test = test
        self.sw_if_index = sw_if_index
        self.mac_addr = mactobinary(mac_addr)
        self.af = af
        self.is_static = is_static
        self.is_no_fib_entry = is_no_fib_entry
        self.nbr_addr = inet_pton(af, nbr_addr)

    def add_vpp_config(self):
        self._test.vapi.ip_neighbor_add_del(
            self.sw_if_index,
            self.mac_addr,
            self.nbr_addr,
            is_add=1,
            is_ipv6=1 if AF_INET6 == self.af else 0,
            is_static=self.is_static,
            is_no_adj_fib=self.is_no_fib_entry)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.ip_neighbor_add_del(
            self.sw_if_index,
            self.mac_addr,
            self.nbr_addr,
            is_ipv6=1 if AF_INET6 == self.af else 0,
            is_add=0,
            is_static=self.is_static)

    def query_vpp_config(self):
        dump = self._test.vapi.ip_neighbor_dump(
            self.sw_if_index,
            is_ipv6=1 if AF_INET6 == self.af else 0)
        for n in dump:
            if self.nbr_addr == n.ip_address \
               and self.is_static == n.is_static:
                return True
        return False

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return ("%d:%s"
                % (self.sw_if_index,
                   inet_ntop(self.af, self.nbr_addr)))
