"""
  IP Routes

  object abstractions for representing IP routes in VPP
"""

import socket

# from vnet/vnet/mpls/mpls_types.h
MPLS_IETF_MAX_LABEL = 0xfffff
MPLS_LABEL_INVALID = MPLS_IETF_MAX_LABEL + 1


class RoutePath:

    def __init__(self, nh_addr, nh_sw_if_index, nh_table_id=0, labels=[], nh_via_label=MPLS_LABEL_INVALID):
        self.nh_addr = socket.inet_pton(socket.AF_INET, nh_addr)
        self.nh_itf = nh_sw_if_index
        self.nh_table_id = nh_table_id
        self.nh_via_label = nh_via_label
        self.nh_labels = labels


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
                                             table_id=self.table_id,
                                             next_hop_out_label_stack=path.nh_labels,
                                             next_hop_n_out_labels=len(
                                                 path.nh_labels),
                                             next_hop_via_label=path.nh_via_label)

    def remove_vpp_config(self):
        for path in self.paths:
            self._test.vapi.ip_add_del_route(self.dest_addr,
                                             self.dest_addr_len,
                                             path.nh_addr,
                                             path.nh_itf,
                                             table_id=self.table_id,
                                             is_add=0)


class MplsIpBind:
    """
    MPLS to IP Binding
    """

    def __init__(self, test, local_label,  dest_addr, dest_addr_len):
        self._test = test
        self.dest_addr = socket.inet_pton(socket.AF_INET, dest_addr)
        self.dest_addr_len = dest_addr_len
        self.local_label = local_label

    def add_vpp_config(self):
        self._test.vapi.mpls_ip_bind_unbind(self.local_label,
                                            self.dest_addr,
                                            self.dest_addr_len)

    def remove_vpp_config(self):
        self._test.vapi.mpls_ip_bind_unbind(self.local_label,
                                            self.dest_addr,
                                            self.dest_addr_len,
                                            is_bind=0)


class MplsRoute:
    """
    MPLS Route
    """

    def __init__(self, test, local_label, eos_bit, paths, table_id=0):
        self._test = test
        self.paths = paths
        self.local_label = local_label
        self.eos_bit = eos_bit
        self.table_id = table_id

    def add_vpp_config(self):
        for path in self.paths:
            self._test.vapi.mpls_route_add_del(self.local_label,
                                               self.eos_bit,
                                               1,
                                               path.nh_addr,
                                               path.nh_itf,
                                               table_id=self.table_id,
                                               next_hop_out_label_stack=path.nh_labels,
                                               next_hop_n_out_labels=len(
                                                   path.nh_labels),
                                               next_hop_via_label=path.nh_via_label)

    def remove_vpp_config(self):
        for path in self.paths:
            self._test.vapi.mpls_route_add_del(self.local_label,
                                               self.eos_bit,
                                               1,
                                               path.nh_addr,
                                               path.nh_itf,
                                               table_id=self.table_id,
                                               is_add=0)
