"""
  Neighbour Entries

  object abstractions for ARP and ND
"""

from socket import inet_pton, inet_ntop, AF_INET, AF_INET6
from vpp_object import *
from util import mactobinary
from ipaddress import ip_address
from vpp_ip import *


def find_nbr(test, sw_if_index, nbr_addr, is_static=0, mac=None):
    ip_addr = VppIpAddress(unicode(nbr_addr))

    if 4 is ip_addr.version:
        nbrs = test.vapi.ip_neighbor_dump(sw_if_index, is_ipv6=0)
    else:
        nbrs = test.vapi.ip_neighbor_dump(sw_if_index, is_ipv6=1)

    for n in nbrs:
        if ip_addr == n.neighbor.ip_address and \
           is_static == n.neighbor.is_static:
            if mac:
                if n.neighbor.mac_address == mactobinary(mac):
                    return True
            else:
                return True
    return False


class VppNeighbor(VppObject):
    """
    ARP Entry
    """

    def __init__(self, test, sw_if_index, mac_addr, nbr_addr,
                 is_static=False, is_no_fib_entry=0):
        self._test = test
        self.sw_if_index = sw_if_index
        self.mac_addr = mactobinary(mac_addr)
        self.is_static = is_static
        self.is_no_fib_entry = is_no_fib_entry
        self.nbr_addr = VppIpAddress(nbr_addr)

    def add_vpp_config(self):
        r = self._test.vapi.ip_neighbor_add_del(
            self.sw_if_index,
            self.mac_addr,
            self.nbr_addr.encode(),
            is_add=1,
            is_static=self.is_static,
            is_no_adj_fib=self.is_no_fib_entry)
        self.stats_index = r.stats_index
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.ip_neighbor_add_del(
            self.sw_if_index,
            self.mac_addr,
            self.nbr_addr.encode(),
            is_add=0,
            is_static=self.is_static)

    def query_vpp_config(self):
        return find_nbr(self._test,
                        self.sw_if_index,
                        self.nbr_addr.address,
                        self.is_static)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return ("%d:%s" % (self.sw_if_index, self.nbr_addr))

    def get_stats(self):
        c = self._test.statistics.get_counter("/net/adjacency")
        return c[0][self.stats_index]
