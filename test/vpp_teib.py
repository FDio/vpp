#!/usr/bin/env python3
"""
  Tunnel Endpoint Information Base (TEIB) objects
"""

from vpp_object import VppObject


def find_teib(test, ne):
    ns = test.vapi.teib_dump()
    for n in ns:
        if ne.peer == str(n.entry.peer) \
           and ne.itf._sw_if_index == n.entry.sw_if_index:
            return True
    return False


class VppTeib(VppObject):

    def __init__(self, test, itf, peer, nh, table_id=0):
        self._test = test
        self.table_id = table_id
        self.peer = peer
        self.itf = itf
        self.nh = nh

    def add_vpp_config(self):
        self._test.vapi.teib_entry_add_del(
            is_add=1,
            entry={
                'nh_table_id': self.table_id,
                'sw_if_index': self.itf.sw_if_index,
                'peer': self.peer,
                'nh': self.nh,
            })
        self._test.registry.register(self, self._test.logger)
        return self

    def remove_vpp_config(self):
        self._test.vapi.teib_entry_add_del(
            is_add=0,
            entry={
                'nh_table_id': self.table_id,
                'sw_if_index': self.itf.sw_if_index,
                'peer': self.peer,
            })

    def query_vpp_config(self):
        return find_teib(self._test, self)

    def object_id(self):
        return ("teib-%s-%s" % (self.itf, self.peer))

    def __repr__(self):
        return f"{self.__class__.__name__}({repr(self._test)}, " \
               f"{repr(self.itf)}, {repr(self.peer)}, {repr(self.nh)}, " \
               f"table_id={repr(self.table_id)})"
