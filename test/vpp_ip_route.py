"""
  IP Routes

  object abstractions for representing IP routes in VPP
"""

import socket

# from vnet/vnet/mpls/mpls_types.h
MPLS_IETF_MAX_LABEL = 0xfffff
MPLS_LABEL_INVALID = MPLS_IETF_MAX_LABEL + 1


class RoutePath(object):

    def __init__(
            self,
            nh_addr,
            nh_sw_if_index,
            nh_table_id=0,
            labels=[],
            nh_via_label=MPLS_LABEL_INVALID,
            is_ip6=0):
        self.nh_itf = nh_sw_if_index
        self.nh_table_id = nh_table_id
        self.nh_via_label = nh_via_label
        self.nh_labels = labels
        if is_ip6:
            self.nh_addr = socket.inet_pton(socket.AF_INET6, nh_addr)
        else:
            self.nh_addr = socket.inet_pton(socket.AF_INET, nh_addr)


class MRoutePath(RoutePath):

    def __init__(self, nh_sw_if_index, flags):
        super(MRoutePath, self).__init__("0.0.0.0",
                                         nh_sw_if_index)
        self.nh_i_flags = flags


class IpRoute:
    """
    IP Route
    """

    def __init__(self, test, dest_addr,
                 dest_addr_len, paths, table_id=0, is_ip6=0, is_local=0):
        self._test = test
        self.paths = paths
        self.dest_addr_len = dest_addr_len
        self.table_id = table_id
        self.is_ip6 = is_ip6
        self.is_local = is_local
        if is_ip6:
            self.dest_addr = socket.inet_pton(socket.AF_INET6, dest_addr)
        else:
            self.dest_addr = socket.inet_pton(socket.AF_INET, dest_addr)

    def add_vpp_config(self):
        if self.is_local:
            self._test.vapi.ip_add_del_route(
                self.dest_addr,
                self.dest_addr_len,
                socket.inet_pton(socket.AF_INET6, "::"),
                0xffffffff,
                is_local=1,
                table_id=self.table_id,
                is_ipv6=self.is_ip6)
        else:
            for path in self.paths:
                self._test.vapi.ip_add_del_route(
                    self.dest_addr,
                    self.dest_addr_len,
                    path.nh_addr,
                    path.nh_itf,
                    table_id=self.table_id,
                    next_hop_out_label_stack=path.nh_labels,
                    next_hop_n_out_labels=len(
                        path.nh_labels),
                    next_hop_via_label=path.nh_via_label,
                    is_ipv6=self.is_ip6)

    def remove_vpp_config(self):
        if self.is_local:
            self._test.vapi.ip_add_del_route(
                self.dest_addr,
                self.dest_addr_len,
                socket.inet_pton(socket.AF_INET6, "::"),
                0xffffffff,
                is_local=1,
                is_add=0,
                table_id=self.table_id,
                is_ipv6=self.is_ip6)
        else:
            for path in self.paths:
                self._test.vapi.ip_add_del_route(self.dest_addr,
                                                 self.dest_addr_len,
                                                 path.nh_addr,
                                                 path.nh_itf,
                                                 table_id=self.table_id,
                                                 is_add=0)


class IpMRoute:
    """
    IP Multicast Route
    """

    def __init__(self, test, src_addr, grp_addr,
                 grp_addr_len, e_flags, paths, table_id=0, is_ip6=0):
        self._test = test
        self.paths = paths
        self.grp_addr_len = grp_addr_len
        self.table_id = table_id
        self.e_flags = e_flags
        self.is_ip6 = is_ip6

        if is_ip6:
            self.grp_addr = socket.inet_pton(socket.AF_INET6, grp_addr)
            self.src_addr = socket.inet_pton(socket.AF_INET6, src_addr)
        else:
            self.grp_addr = socket.inet_pton(socket.AF_INET, grp_addr)
            self.src_addr = socket.inet_pton(socket.AF_INET, src_addr)

    def add_vpp_config(self):
        for path in self.paths:
            self._test.vapi.ip_mroute_add_del(self.src_addr,
                                              self.grp_addr,
                                              self.grp_addr_len,
                                              self.e_flags,
                                              path.nh_itf,
                                              path.nh_i_flags,
                                              table_id=self.table_id,
                                              is_ipv6=self.is_ip6)

    def remove_vpp_config(self):
        for path in self.paths:
            self._test.vapi.ip_mroute_add_del(self.src_addr,
                                              self.grp_addr,
                                              self.grp_addr_len,
                                              self.e_flags,
                                              path.nh_itf,
                                              path.nh_i_flags,
                                              table_id=self.table_id,
                                              is_add=0,
                                              is_ipv6=self.is_ip6)

    def update_entry_flags(self, flags):
        self.e_flags = flags
        self._test.vapi.ip_mroute_add_del(self.src_addr,
                                          self.grp_addr,
                                          self.grp_addr_len,
                                          self.e_flags,
                                          0xffffffff,
                                          0,
                                          table_id=self.table_id,
                                          is_ipv6=self.is_ip6)

    def update_path_flags(self, itf, flags):
        for path in self.paths:
            if path.nh_itf == itf:
                path.nh_i_flags = flags
                break
        self._test.vapi.ip_mroute_add_del(self.src_addr,
                                          self.grp_addr,
                                          self.grp_addr_len,
                                          self.e_flags,
                                          path.nh_itf,
                                          path.nh_i_flags,
                                          table_id=self.table_id,
                                          is_ipv6=self.is_ip6)


class MFibSignal:
    def __init__(self, test, route, interface, packet):
        self.route = route
        self.interface = interface
        self.packet = packet
        self.test = test

    def compare(self, signal):
        self.test.assertEqual(self.interface, signal.sw_if_index)
        self.test.assertEqual(self.route.table_id, signal.table_id)
        self.test.assertEqual(self.route.grp_addr_len,
                              signal.grp_address_len)
        for i in range(self.route.grp_addr_len / 8):
            self.test.assertEqual(self.route.grp_addr[i],
                                  signal.grp_address[i])
        if (self.route.grp_addr_len > 32):
            for i in range(4):
                self.test.assertEqual(self.route.src_addr[i],
                                      signal.src_address[i])


class MplsIpBind:
    """
    MPLS to IP Binding
    """

    def __init__(self, test, local_label, dest_addr, dest_addr_len):
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
            self._test.vapi.mpls_route_add_del(
                self.local_label,
                self.eos_bit,
                1,
                path.nh_addr,
                path.nh_itf,
                table_id=self.table_id,
                next_hop_out_label_stack=path.nh_labels,
                next_hop_n_out_labels=len(
                    path.nh_labels),
                next_hop_via_label=path.nh_via_label,
                next_hop_table_id=path.nh_table_id)

    def remove_vpp_config(self):
        for path in self.paths:
            self._test.vapi.mpls_route_add_del(self.local_label,
                                               self.eos_bit,
                                               1,
                                               path.nh_addr,
                                               path.nh_itf,
                                               table_id=self.table_id,
                                               is_add=0)
