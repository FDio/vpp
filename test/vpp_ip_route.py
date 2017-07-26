"""
  IP Routes

  object abstractions for representing IP routes in VPP
"""

from vpp_object import *
from socket import inet_pton, inet_ntop, AF_INET, AF_INET6

# from vnet/vnet/mpls/mpls_types.h
MPLS_IETF_MAX_LABEL = 0xfffff
MPLS_LABEL_INVALID = MPLS_IETF_MAX_LABEL + 1


class MRouteItfFlags:
    MFIB_ITF_FLAG_NONE = 0
    MFIB_ITF_FLAG_NEGATE_SIGNAL = 1
    MFIB_ITF_FLAG_ACCEPT = 2
    MFIB_ITF_FLAG_FORWARD = 4
    MFIB_ITF_FLAG_SIGNAL_PRESENT = 8
    MFIB_ITF_FLAG_INTERNAL_COPY = 16


class MRouteEntryFlags:
    MFIB_ENTRY_FLAG_NONE = 0
    MFIB_ENTRY_FLAG_SIGNAL = 1
    MFIB_ENTRY_FLAG_DROP = 2
    MFIB_ENTRY_FLAG_CONNECTED = 4
    MFIB_ENTRY_FLAG_INHERIT_ACCEPT = 8


class DpoProto:
    DPO_PROTO_IP4 = 0
    DPO_PROTO_IP6 = 1
    DPO_PROTO_MPLS = 2
    DPO_PROTO_ETHERNET = 3
    DPO_PROTO_NSH = 4


def find_route(test, ip_addr, len, table_id=0, inet=AF_INET):
    if inet == AF_INET:
        s = 4
        routes = test.vapi.ip_fib_dump()
    else:
        s = 16
        routes = test.vapi.ip6_fib_dump()

    route_addr = inet_pton(inet, ip_addr)
    for e in routes:
        if route_addr == e.address[:s] \
           and len == e.address_length \
           and table_id == e.table_id:
            return True
    return False


class VppIpTable(VppObject):

    def __init__(self,
                 test,
                 table_id,
                 is_ip6=0):
        self._test = test
        self.table_id = table_id
        self.is_ip6 = is_ip6

    def add_vpp_config(self):
        self._test.vapi.ip_table_add_del(
            self.table_id,
            is_ipv6=self.is_ip6,
            is_add=1)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.ip_table_add_del(
            self.table_id,
            is_ipv6=self.is_ip6,
            is_add=0)

    def query_vpp_config(self):
        # find the default route
        return find_route(self._test,
                          "::" if self.is_ip6 else "0.0.0.0",
                          0,
                          self.table_id,
                          inet=AF_INET6 if self.is_ip6 == 1 else AF_INET)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return ("table-%s-%d" %
                ("v6" if self.is_ip6 == 1 else "v4",
                 self.table_id))


class VppRoutePath(object):

    def __init__(
            self,
            nh_addr,
            nh_sw_if_index,
            nh_table_id=0,
            labels=[],
            nh_via_label=MPLS_LABEL_INVALID,
            rpf_id=0,
            is_interface_rx=0,
            is_resolve_host=0,
            is_resolve_attached=0,
            proto=DpoProto.DPO_PROTO_IP4):
        self.nh_itf = nh_sw_if_index
        self.nh_table_id = nh_table_id
        self.nh_via_label = nh_via_label
        self.nh_labels = labels
        self.weight = 1
        self.rpf_id = rpf_id
        self.proto = proto
        if self.proto is DpoProto.DPO_PROTO_IP6:
            self.nh_addr = inet_pton(AF_INET6, nh_addr)
        elif self.proto is DpoProto.DPO_PROTO_IP4:
            self.nh_addr = inet_pton(AF_INET, nh_addr)
        else:
            self.nh_addr = inet_pton(AF_INET6, "::")
        self.is_resolve_host = is_resolve_host
        self.is_resolve_attached = is_resolve_attached
        self.is_interface_rx = is_interface_rx
        self.is_rpf_id = 0
        if rpf_id != 0:
            self.is_rpf_id = 1
            self.nh_itf = rpf_id


class VppMRoutePath(VppRoutePath):

    def __init__(self, nh_sw_if_index, flags):
        super(VppMRoutePath, self).__init__("0.0.0.0",
                                            nh_sw_if_index)
        self.nh_i_flags = flags


class VppIpRoute(VppObject):
    """
    IP Route
    """

    def __init__(self, test, dest_addr,
                 dest_addr_len, paths, table_id=0, is_ip6=0, is_local=0,
                 is_unreach=0, is_prohibit=0):
        self._test = test
        self.paths = paths
        self.dest_addr_len = dest_addr_len
        self.table_id = table_id
        self.is_ip6 = is_ip6
        self.is_local = is_local
        self.is_unreach = is_unreach
        self.is_prohibit = is_prohibit
        self.dest_addr_p = dest_addr
        if is_ip6:
            self.dest_addr = inet_pton(AF_INET6, dest_addr)
        else:
            self.dest_addr = inet_pton(AF_INET, dest_addr)

    def modify(self, paths, is_local=0,
               is_unreach=0, is_prohibit=0):
        self.paths = paths
        self.is_local = is_local
        self.is_unreach = is_unreach
        self.is_prohibit = is_prohibit

    def add_vpp_config(self):
        if self.is_local or self.is_unreach or self.is_prohibit:
            self._test.vapi.ip_add_del_route(
                self.dest_addr,
                self.dest_addr_len,
                inet_pton(AF_INET6, "::"),
                0xffffffff,
                is_local=self.is_local,
                is_unreach=self.is_unreach,
                is_prohibit=self.is_prohibit,
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
                    next_hop_table_id=path.nh_table_id,
                    is_ipv6=self.is_ip6,
                    is_resolve_host=path.is_resolve_host,
                    is_resolve_attached=path.is_resolve_attached,
                    is_multipath=1 if len(self.paths) > 1 else 0)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        if self.is_local or self.is_unreach or self.is_prohibit:
            self._test.vapi.ip_add_del_route(
                self.dest_addr,
                self.dest_addr_len,
                inet_pton(AF_INET6, "::"),
                0xffffffff,
                is_local=self.is_local,
                is_unreach=self.is_unreach,
                is_prohibit=self.is_prohibit,
                is_add=0,
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
                    next_hop_table_id=path.nh_table_id,
                    next_hop_via_label=path.nh_via_label,
                    is_add=0,
                    is_ipv6=self.is_ip6)

    def query_vpp_config(self):
        return find_route(self._test,
                          self.dest_addr_p,
                          self.dest_addr_len,
                          self.table_id,
                          inet=AF_INET6 if self.is_ip6 == 1 else AF_INET)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return ("%d:%s/%d"
                % (self.table_id,
                   self.dest_addr_p,
                   self.dest_addr_len))


class VppIpMRoute(VppObject):
    """
    IP Multicast Route
    """

    def __init__(self, test, src_addr, grp_addr,
                 grp_addr_len, e_flags, paths, table_id=0,
                 rpf_id=0, is_ip6=0):
        self._test = test
        self.paths = paths
        self.grp_addr_len = grp_addr_len
        self.table_id = table_id
        self.e_flags = e_flags
        self.is_ip6 = is_ip6
        self.rpf_id = rpf_id

        if is_ip6:
            self.grp_addr = inet_pton(AF_INET6, grp_addr)
            self.src_addr = inet_pton(AF_INET6, src_addr)
        else:
            self.grp_addr = inet_pton(AF_INET, grp_addr)
            self.src_addr = inet_pton(AF_INET, src_addr)

    def add_vpp_config(self):
        for path in self.paths:
            self._test.vapi.ip_mroute_add_del(self.src_addr,
                                              self.grp_addr,
                                              self.grp_addr_len,
                                              self.e_flags,
                                              path.nh_itf,
                                              path.nh_i_flags,
                                              rpf_id=self.rpf_id,
                                              table_id=self.table_id,
                                              is_ipv6=self.is_ip6)
        self._test.registry.register(self, self._test.logger)

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

    def update_rpf_id(self, rpf_id):
        self.rpf_id = rpf_id
        self._test.vapi.ip_mroute_add_del(self.src_addr,
                                          self.grp_addr,
                                          self.grp_addr_len,
                                          self.e_flags,
                                          0xffffffff,
                                          0,
                                          rpf_id=self.rpf_id,
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

    def query_vpp_config(self):
        dump = self._test.vapi.ip_fib_dump()
        for e in dump:
            if self.grp_addr == e.address \
               and self.grp_addr_len == e.address_length \
               and self.table_id == e.table_id:
                return True
        return False

    def __str__(self):
        return self.object_id()

    def object_id(self):
        if self.is_ip6:
            return ("%d:(%s,%s/%d)"
                    % (self.table_id,
                       inet_ntop(AF_INET6, self.src_addr),
                       inet_ntop(AF_INET6, self.grp_addr),
                       self.grp_addr_len))
        else:
            return ("%d:(%s,%s/%d)"
                    % (self.table_id,
                       inet_ntop(AF_INET, self.src_addr),
                       inet_ntop(AF_INET, self.grp_addr),
                       self.grp_addr_len))


class VppMFibSignal(object):
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


class VppMplsIpBind(VppObject):
    """
    MPLS to IP Binding
    """

    def __init__(self, test, local_label, dest_addr, dest_addr_len,
                 table_id=0, ip_table_id=0, is_ip6=0):
        self._test = test
        self.dest_addr_len = dest_addr_len
        self.dest_addr = dest_addr
        self.local_label = local_label
        self.table_id = table_id
        self.ip_table_id = ip_table_id
        self.is_ip6 = is_ip6
        if is_ip6:
            self.dest_addrn = inet_pton(AF_INET6, dest_addr)
        else:
            self.dest_addrn = inet_pton(AF_INET, dest_addr)

    def add_vpp_config(self):
        self._test.vapi.mpls_ip_bind_unbind(self.local_label,
                                            self.dest_addrn,
                                            self.dest_addr_len,
                                            table_id=self.table_id,
                                            ip_table_id=self.ip_table_id,
                                            is_ip4=(self.is_ip6 == 0))
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.mpls_ip_bind_unbind(self.local_label,
                                            self.dest_addrn,
                                            self.dest_addr_len,
                                            table_id=self.table_id,
                                            ip_table_id=self.ip_table_id,
                                            is_bind=0,
                                            is_ip4=(self.is_ip6 == 0))

    def query_vpp_config(self):
        dump = self._test.vapi.mpls_fib_dump()
        for e in dump:
            if self.local_label == e.label \
               and self.table_id == e.table_id:
                return True
        return False

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return ("%d:%s binds %d:%s/%d"
                % (self.table_id,
                   self.local_label,
                   self.ip_table_id,
                   self.dest_addr,
                   self.dest_addr_len))


class VppMplsTable(VppObject):

    def __init__(self,
                 test,
                 table_id):
        self._test = test
        self.table_id = table_id

    def add_vpp_config(self):
        self._test.vapi.mpls_table_add_del(
            self.table_id,
            is_add=1)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.mpls_table_add_del(
            self.table_id,
            is_add=0)

    def query_vpp_config(self):
        # find the default route
        dump = self._test.vapi.mpls_fib_dump()
        if len(dump):
            return True
        return False

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return ("table-mpls-%d" % (self.table_id))


class VppMplsRoute(VppObject):
    """
    MPLS Route/LSP
    """

    def __init__(self, test, local_label, eos_bit, paths, table_id=0,
                 is_multicast=0):
        self._test = test
        self.paths = paths
        self.local_label = local_label
        self.eos_bit = eos_bit
        self.table_id = table_id
        self.is_multicast = is_multicast

    def add_vpp_config(self):
        is_multipath = len(self.paths) > 1
        for path in self.paths:
            self._test.vapi.mpls_route_add_del(
                self.local_label,
                self.eos_bit,
                path.proto,
                path.nh_addr,
                path.nh_itf,
                is_multicast=self.is_multicast,
                is_multipath=is_multipath,
                table_id=self.table_id,
                is_interface_rx=path.is_interface_rx,
                is_rpf_id=path.is_rpf_id,
                next_hop_out_label_stack=path.nh_labels,
                next_hop_n_out_labels=len(
                    path.nh_labels),
                next_hop_via_label=path.nh_via_label,
                next_hop_table_id=path.nh_table_id)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        for path in self.paths:
            self._test.vapi.mpls_route_add_del(self.local_label,
                                               self.eos_bit,
                                               path.proto,
                                               path.nh_addr,
                                               path.nh_itf,
                                               is_rpf_id=path.is_rpf_id,
                                               table_id=self.table_id,
                                               is_add=0)

    def query_vpp_config(self):
        dump = self._test.vapi.mpls_fib_dump()
        for e in dump:
            if self.local_label == e.label \
               and self.eos_bit == e.eos_bit \
               and self.table_id == e.table_id:
                return True
        return False

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return ("%d:%s/%d"
                % (self.table_id,
                   self.local_label,
                   20+self.eos_bit))
