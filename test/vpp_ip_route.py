"""
  IP Routes

  object abstractions for representing IP routes in VPP
"""

import socket


class IpPath:

    def __init__(self, nh_addr, nh_sw_if_index, nh_table_id=0):
        self.nh_addr = socket.inet_pton(socket.AF_INET, nh_addr)
        self.nh_itf = nh_sw_if_index
        self.nh_table_id = nh_table_id


class IpRoute:
    """
    IP Route
    """

    def __init__(self, test, dest_addr,
                 dest_addr_len, paths, table_id=0):
        self._test = test
        self.paths = paths
        self.dest_addr = socket.inet_pton(socket.AF_INET, dest_addr)
        self.dest_addr_len = dest_addr_len
        self.table_id = table_id

    def add_vpp_config(self):
        for path in self.paths:
            self._test.vapi.ip_add_del_route(self.dest_addr,
                                             self.dest_addr_len,
                                             path.nh_addr,
                                             path.nh_itf,
                                             table_id=self.table_id)

    def remove_vpp_config(self):
        for path in self.paths:
            self._test.vapi.ip_add_del_route(self.dest_addr,
                                             self.dest_addr_len,
                                             path.nh_addr,
                                             path.nh_itf,
                                             table_id=self.table_id,
                                             is_add=0)
