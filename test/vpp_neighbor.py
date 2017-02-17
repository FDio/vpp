"""
  Neighbour Entries

  object abstractions for ARP and ND
"""

import socket
from vpp_object import *


def mactobinary(mac):
    """ Conver the : separated format into binary packet data for the API """
    return mac.replace(':', '').decode('hex')


class VppNeighbor(VppObject):
    """
    ARP Entry
    """

    def __init__(self, test, sw_if_index, mac_addr, nbr_addr,
                 is_ip6=0, is_static=0):
        self._test = test
        self.sw_if_index = sw_if_index
        self.mac_addr = mactobinary(mac_addr)
        self.is_ip6 = is_ip6
        self.is_static = is_static
        if is_ip6:
            self.nbr_addr = socket.inet_pton(socket.AF_INET6, nbr_addr)
        else:
            self.nbr_addr = socket.inet_pton(socket.AF_INET, nbr_addr)

    def add_vpp_config(self):
        self._test.vapi.ip_neighbor_add_del(
            self.sw_if_index,
            self.mac_addr,
            self.nbr_addr,
            is_add=1,
            is_ipv6=self.is_ip6,
            is_static=self.is_static)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.ip_neighbor_add_del(
            self.sw_if_index,
            self.mac_addr,
            self.nbr_addr,
            is_add=0,
            is_static=self.is_static)

    def query_vpp_config(self):
        dump = self._test.vapi.ip_neighbor_dump(self.sw_if_index,
                                                is_ipv6=self.is_ip6)
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
                   socket.inet_ntop(socket.AF_INET, self.nbr_addr)))
