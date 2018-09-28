"""
  Neighbour Entries

  object abstractions for ARP and ND
"""

from socket import inet_pton, inet_ntop, AF_INET, AF_INET6
from vpp_object import *
from util import mactobinary


def find_nbr(test, sw_if_index, ip_addr, is_static=0, inet=AF_INET, mac=None):
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
            if mac:
                if n.mac_address == mactobinary(mac):
                    return True
            else:
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
        self.nbr_addr = nbr_addr
        self.nbr_addr_n = inet_pton(af, nbr_addr)

    def add_vpp_config(self):
        r = self._test.vapi.ip_neighbor_add_del(
            self.sw_if_index,
            self.mac_addr,
            self.nbr_addr_n,
            is_add=1,
            is_ipv6=1 if AF_INET6 == self.af else 0,
            is_static=self.is_static,
            is_no_adj_fib=self.is_no_fib_entry)
        self.stats_index = r.stats_index
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.ip_neighbor_add_del(
            self.sw_if_index,
            self.mac_addr,
            self.nbr_addr_n,
            is_ipv6=1 if AF_INET6 == self.af else 0,
            is_add=0,
            is_static=self.is_static)

    def query_vpp_config(self):
        return find_nbr(self._test,
                        self.sw_if_index,
                        self.nbr_addr,
                        self.is_static,
                        self.af)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return ("%d:%s" % (self.sw_if_index, self.nbr_addr))

    def get_stats(self):
        c = self._test.statistics.get_counter("/net/adjacency")
        return c[0][self.stats_index]
