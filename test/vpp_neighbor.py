"""
  Neighbour Entries

  object abstractions for ARP and ND
"""

from socket import inet_pton, inet_ntop, AF_INET, AF_INET6
from vpp_object import *
from util import mactobinary
from ipaddress import ip_address
from vpp_ip import *
from vpp_mac import *


def find_nbr(test, sw_if_index, nbr_addr, is_static=0, mac=None):
    ip_addr = VppIpAddress(nbr_addr)
    e = VppEnum.vl_api_ip_neighbor_flags_t
    nbrs = test.vapi.ip_neighbor_dump(sw_if_index,
                                      is_ipv6=(6 is ip_addr.version))

    for n in nbrs:
        if ip_addr == n.neighbor.ip_address and \
           is_static == (n.neighbor.flags & e.IP_API_NEIGHBOR_FLAG_STATIC):
            if mac:
                if n.neighbor.mac_address.bytes == mactobinary(mac):
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
        self.mac_addr = VppMacAddress(mac_addr)

        e = VppEnum.vl_api_ip_neighbor_flags_t
        self.flags = e.IP_API_NEIGHBOR_FLAG_NONE
        if is_static:
            self.flags |= e.IP_API_NEIGHBOR_FLAG_STATIC
        if is_no_fib_entry:
            self.flags |= e.IP_API_NEIGHBOR_FLAG_NO_FIB_ENTRY
        self.nbr_addr = VppIpAddress(nbr_addr)

    def add_vpp_config(self):
        r = self._test.vapi.ip_neighbor_add_del(
            self.sw_if_index,
            self.mac_addr.encode(),
            self.nbr_addr.encode(),
            is_add=1,
            flags=self.flags)
        self.stats_index = r.stats_index
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.ip_neighbor_add_del(
            self.sw_if_index,
            self.mac_addr.encode(),
            self.nbr_addr.encode(),
            is_add=0,
            flags=self.flags)

    def is_static(self):
        e = VppEnum.vl_api_ip_neighbor_flags_t
        return (self.flags & e.IP_API_NEIGHBOR_FLAG_STATIC)

    def query_vpp_config(self):
        return find_nbr(self._test,
                        self.sw_if_index,
                        self.nbr_addr.address,
                        self.is_static())

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return ("%d:%s" % (self.sw_if_index, self.nbr_addr.address))

    def get_stats(self):
        c = self._test.statistics.get_counter("/net/adjacency")
        return c[0][self.stats_index]
