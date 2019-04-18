#!/usr/bin/env python
"""
  NHRP objects
"""

from vpp_object import VppObject


def find_nhrp(test, ne):
    ns = test.vapi.nhrp_dump()
    for n in ns:
        if ne.peer == str(n.entry.peer) \
           and ne.itf._sw_if_index == n.entry.sw_if_index:
            return True
    return False


class VppNhrp(VppObject):

    def __init__(self, test, itf, peer, nh, table_id=0):
        self._test = test
        self.table_id = table_id
        self.peer = peer
        self.itf = itf
        self.nh = nh

    def add_vpp_config(self):
        r = self._test.vapi.nhrp_add_del(
            self.itf._sw_if_index,
            self.peer,
            self.nh,
            self.table_id)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        r = self._test.vapi.nhrp_add_del(
            self.itf._sw_if_index,
            self.peer,
            is_add=0)

    def query_vpp_config(self):
        return find_nhrp(self._test, self)

    def object_id(self):
        return ("nhrp-%s-%s" % (self.itf, self.peer))
