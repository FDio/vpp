"""
  Neighbour Entries

  object abstractions for ARP and ND
"""

from ipaddress import ip_address
from vpp_object import VppObject
from vpp_papi import mac_pton, VppEnum


def find_nbr(test, sw_if_index, nbr_addr, is_static=0, mac=None):
    ip_addr = ip_address(str(nbr_addr))
    e = VppEnum.vl_api_ip_neighbor_flags_t
    nbrs = test.vapi.ip_neighbor_dump(sw_if_index=sw_if_index,
                                      af=ip_addr.vapi_af)

    for n in nbrs:
        if sw_if_index == n.neighbor.sw_if_index and \
           ip_addr == n.neighbor.ip_address and \
           is_static == (n.neighbor.flags & e.IP_API_NEIGHBOR_FLAG_STATIC):
            if mac:
                if mac == str(n.neighbor.mac_address):
                    return True
            else:
                return True
    return False


class VppNeighbor(VppObject):
    """
    ARP Entry
    """

    def __init__(self, test, sw_if_index, mac_addr, nbr_addr,
                 is_static=False, is_no_fib_entry=False):
        self._test = test
        self.sw_if_index = sw_if_index
        self.mac_addr = mac_addr
        self.nbr_addr = nbr_addr

        e = VppEnum.vl_api_ip_neighbor_flags_t
        self.flags = e.IP_API_NEIGHBOR_FLAG_NONE
        if is_static:
            self.flags |= e.IP_API_NEIGHBOR_FLAG_STATIC
        if is_no_fib_entry:
            self.flags |= e.IP_API_NEIGHBOR_FLAG_NO_FIB_ENTRY

    def encode(self):
        return {
            'sw_if_index': self.sw_if_index,
            'flags': self.flags,
            'mac_address': self.mac_addr,
            'ip_address': self.nbr_addr,
        }

    def add_vpp_config(self):
        r = self._test.vapi.ip_neighbor_add_del(
            is_add=True,
            neighbor=self.encode(),
        )
        self.stats_index = r.stats_index
        self._test.registry.register(self, self._test.logger)
        return self

    def remove_vpp_config(self):
        self._test.vapi.ip_neighbor_add_del(
            is_add=False,
            neighbor=self.encode(),
        )

    def is_static(self):
        e = VppEnum.vl_api_ip_neighbor_flags_t
        return (self.flags & e.IP_API_NEIGHBOR_FLAG_STATIC)

    def query_vpp_config(self):
        return find_nbr(self._test,
                        self.sw_if_index,
                        self.nbr_addr,
                        self.is_static())

    def object_id(self):
        return ("%d:%s" % (self.sw_if_index, self.nbr_addr))

    def get_stats(self):
        c = self._test.statistics["/net/adjacency"]
        return c[0][self.stats_index]
