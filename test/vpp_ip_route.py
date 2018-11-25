"""
  IP Routes

  object abstractions for representing IP routes in VPP
"""

import enum
from socket import inet_pton, inet_ntop, AF_INET, AF_INET6
from vpp_ip import *
from vpp_object import *

# from vnet/vnet/mpls/mpls_types.h
MPLS_IETF_MAX_LABEL = 0xfffff
MPLS_LABEL_INVALID = MPLS_IETF_MAX_LABEL + 1


class MFIB_ITF_FLAG(enum.IntEnum):  # noqa
    NONE = 0
    NEGATE_SIGNAL = 1
    ACCEPT = 2
    FORWARD = 4
    SIGNAL_PRESENT = 8
    INTERNAL_COPY = 16


class MFIB_ENTRY_FLAG(enum.IntEnum):  # noqa
    NONE = 0
    SIGNAL = 1
    DROP = 2
    CONNECTED = 4
    INHERIT_ACCEPT = 8


class MPLS_LSP_MODE(enum.IntEnum):  # noqa
    PIPE = 0
    UNIFORM = 1


def ip_to_dpo_proto(addr):
    if addr.version is 6:
        return DPO_PROTO.IP6
    else:
        return DPO_PROTO.IP4


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


def find_mroute(test, grp_addr, src_addr, grp_addr_len,
                table_id=0, inet=AF_INET):
    if inet == AF_INET:
        s = 4
        routes = test.vapi.ip_mfib_dump()
    else:
        s = 16
        routes = test.vapi.ip6_mfib_dump()
    gaddr = inet_pton(inet, grp_addr)
    saddr = inet_pton(inet, src_addr)
    for e in routes:
        if gaddr == e.grp_address[:s] \
           and grp_addr_len == e.address_length \
           and saddr == e.src_address[:s] \
           and table_id == e.table_id:
            return True
    return False


def find_mpls_route(test, table_id, label, eos_bit, paths=None):
    dump = test.vapi.mpls_fib_dump()
    for e in dump:
        if label == e.label \
           and eos_bit == e.eos_bit \
           and table_id == e.table_id:
            if not paths:
                return True
            else:
                if (len(paths) != len(e.path)):
                    return False
                for i in range(len(paths)):
                    if (paths[i] != e.path[i]):
                        return False
                return True
    return False


def fib_interface_ip_prefix(test, address, length, sw_if_index):
    vp = VppIpPrefix(address, length)
    addrs = test.vapi.ip_address_dump(sw_if_index, is_ipv6=vp.is_ip6)

    if vp.is_ip6:
        n = 16
    else:
        n = 4

    for a in addrs:
        if a.prefix_length == length and \
           a.sw_if_index == sw_if_index and \
           a.ip[:n] == vp.bytes:
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
        if self.table_id == 0:
            # the default table always exists
            return False
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


class VppIpInterfaceAddress(VppObject):

    def __init__(self, test, intf, addr, len):
        self._test = test
        self.intf = intf
        self.prefix = VppIpPrefix(addr, len)

    def add_vpp_config(self):
        self._test.vapi.sw_interface_add_del_address(
            self.intf.sw_if_index,
            self.prefix.bytes,
            self.prefix.length,
            is_add=1,
            is_ipv6=self.prefix.is_ip6)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.sw_interface_add_del_address(
            self.intf.sw_if_index,
            self.prefix.bytes,
            self.prefix.length,
            is_add=0,
            is_ipv6=self.prefix.is_ip6)

    def query_vpp_config(self):
        return fib_interface_ip_prefix(self._test,
                                       self.prefix.address,
                                       self.prefix.length,
                                       self.intf.sw_if_index)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "interface-ip-%s-%s" % (self.intf, self.prefix)


class VppIpInterfaceBind(VppObject):

    def __init__(self, test, intf, table):
        self._test = test
        self.intf = intf
        self.table = table

    def add_vpp_config(self):
        if self.table.is_ip6:
            self.intf.set_table_ip6(self.table.table_id)
        else:
            self.intf.set_table_ip4(self.table.table_id)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        if 0 == self.table.table_id:
            return
        if self.table.is_ip6:
            self.intf.set_table_ip6(0)
        else:
            self.intf.set_table_ip4(0)

    def query_vpp_config(self):
        if 0 == self.table.table_id:
            return False
        return self._test.vapi.sw_interface_get_table(
            self.intf.sw_if_index,
            self.table.is_ip6).vrf_id == self.table.table_id

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "interface-bind-%s-%s" % (self.intf, self.table)


class VppMplsLabel(object):
    def __init__(self, value, mode=MPLS_LSP_MODE.PIPE, ttl=64, exp=0):
        self.value = value
        self.mode = mode
        self.ttl = ttl
        self.exp = exp

    def encode(self):
        is_uniform = 0 if self.mode is MPLS_LSP_MODE.PIPE else 1
        return {'label': self.value,
                'ttl': self.ttl,
                'exp': self.exp,
                'is_uniform': is_uniform}

    def _key(self):
        return (self.value, self.mode, self.ttl, self.exp),

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        elif hasattr(other, 'label'):
            return (self._key == other._key) and \
                (self.mode == MPLS_LSP_MODE.UNIFORM)
        else:
            return self._key == other._key

    def __ne__(self, other):
        return not (self == other)

    def __hash__(self):
        return hash(self._key())


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
            is_source_lookup=0,
            is_udp_encap=0,
            is_dvr=0,
            next_hop_id=0xffffffff,
            proto=DPO_PROTO.IP4):
        self.nh_itf = nh_sw_if_index
        self.nh_table_id = nh_table_id
        self.nh_via_label = nh_via_label
        self.nh_labels = labels
        self.weight = 1
        self.rpf_id = rpf_id
        self.proto = proto
        if self.proto is DPO_PROTO.IP6:
            self.nh_addr = inet_pton(AF_INET6, nh_addr)
        elif self.proto is DPO_PROTO.IP4:
            self.nh_addr = inet_pton(AF_INET, nh_addr)
        else:
            self.nh_addr = inet_pton(AF_INET6, "::")
        self.is_resolve_host = is_resolve_host
        self.is_resolve_attached = is_resolve_attached
        self.is_interface_rx = is_interface_rx
        self.is_source_lookup = is_source_lookup
        self.is_rpf_id = 0
        if rpf_id != 0:
            self.is_rpf_id = 1
            self.nh_itf = rpf_id
        self.is_udp_encap = is_udp_encap
        self.next_hop_id = next_hop_id
        self.is_dvr = is_dvr

    def encode_labels(self):
        lstack = []
        for l in self.nh_labels:
            if type(l) == VppMplsLabel:
                lstack.append(l.encode())
            else:
                lstack.append({'label': l,
                               'ttl': 255})
        return lstack

    def encode(self):
        return {'next_hop': self.nh_addr,
                'weight': 1,
                'afi': 0,
                'preference': 0,
                'table_id': self.nh_table_id,
                'next_hop_id': self.next_hop_id,
                'sw_if_index': self.nh_itf,
                'afi': self.proto,
                'is_udp_encap': self.is_udp_encap,
                'n_labels': len(self.nh_labels),
                'label_stack': self.encode_labels()}

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.nh_addr == other.nh_addr
        elif hasattr(other, 'sw_if_index'):
            # vl_api_fib_path_t
            if (len(self.nh_labels) != other.n_labels):
                return False
            for i in range(len(self.nh_labels)):
                if (self.nh_labels[i] != other.label_stack[i]):
                    return False
            return self.nh_itf == other.sw_if_index
        else:
            return False

    def __ne__(self, other):
        return not (self == other)


class VppMRoutePath(VppRoutePath):

    def __init__(self, nh_sw_if_index, flags,
                 nh=None,
                 proto=DPO_PROTO.IP4,
                 bier_imp=0):
        if not nh:
            nh = "::" if proto is DPO_PROTO.IP6 else "0.0.0.0"
        super(VppMRoutePath, self).__init__(nh,
                                            nh_sw_if_index,
                                            proto=proto)
        self.nh_i_flags = flags
        self.bier_imp = bier_imp


class VppIpRoute(VppObject):
    """
    IP Route
    """

    def __init__(self, test, dest_addr,
                 dest_addr_len, paths, table_id=0, is_ip6=0, is_local=0,
                 is_unreach=0, is_prohibit=0, is_drop=0):
        self._test = test
        self.paths = paths
        self.dest_addr_len = dest_addr_len
        self.table_id = table_id
        self.is_ip6 = is_ip6
        self.is_local = is_local
        self.is_unreach = is_unreach
        self.is_prohibit = is_prohibit
        self.is_drop = is_drop
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
        if self.is_local or self.is_unreach or \
           self.is_prohibit or self.is_drop:
            r = self._test.vapi.ip_add_del_route(
                self.dest_addr,
                self.dest_addr_len,
                inet_pton(AF_INET6, "::"),
                0xffffffff,
                is_local=self.is_local,
                is_unreach=self.is_unreach,
                is_prohibit=self.is_prohibit,
                is_drop=self.is_drop,
                table_id=self.table_id,
                is_ipv6=self.is_ip6)
        else:
            for path in self.paths:
                lstack = path.encode_labels()

                r = self._test.vapi.ip_add_del_route(
                    self.dest_addr,
                    self.dest_addr_len,
                    path.nh_addr,
                    path.nh_itf,
                    table_id=self.table_id,
                    next_hop_out_label_stack=lstack,
                    next_hop_n_out_labels=len(lstack),
                    next_hop_via_label=path.nh_via_label,
                    next_hop_table_id=path.nh_table_id,
                    next_hop_id=path.next_hop_id,
                    is_ipv6=self.is_ip6,
                    is_dvr=path.is_dvr,
                    is_resolve_host=path.is_resolve_host,
                    is_resolve_attached=path.is_resolve_attached,
                    is_source_lookup=path.is_source_lookup,
                    is_udp_encap=path.is_udp_encap,
                    is_multipath=1 if len(self.paths) > 1 else 0)
        self.stats_index = r.stats_index
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        if self.is_local or self.is_unreach or \
           self.is_prohibit or self.is_drop:
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
                    next_hop_id=path.next_hop_id,
                    is_add=0,
                    is_udp_encap=path.is_udp_encap,
                    is_ipv6=self.is_ip6,
                    is_dvr=path.is_dvr)

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

    def get_stats_to(self):
        c = self._test.statistics.get_counter("/net/route/to")
        return c[0][self.stats_index]

    def get_stats_via(self):
        c = self._test.statistics.get_counter("/net/route/via")
        return c[0][self.stats_index]


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

        self.grp_addr_p = grp_addr
        self.src_addr_p = src_addr
        if is_ip6:
            self.grp_addr = inet_pton(AF_INET6, grp_addr)
            self.src_addr = inet_pton(AF_INET6, src_addr)
        else:
            self.grp_addr = inet_pton(AF_INET, grp_addr)
            self.src_addr = inet_pton(AF_INET, src_addr)

    def add_vpp_config(self):
        for path in self.paths:
            r = self._test.vapi.ip_mroute_add_del(self.src_addr,
                                                  self.grp_addr,
                                                  self.grp_addr_len,
                                                  self.e_flags,
                                                  path.proto,
                                                  path.nh_itf,
                                                  path.nh_addr,
                                                  path.nh_i_flags,
                                                  bier_imp=path.bier_imp,
                                                  rpf_id=self.rpf_id,
                                                  table_id=self.table_id,
                                                  is_ipv6=self.is_ip6)
            self.stats_index = r.stats_index
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        for path in self.paths:
            self._test.vapi.ip_mroute_add_del(self.src_addr,
                                              self.grp_addr,
                                              self.grp_addr_len,
                                              self.e_flags,
                                              path.proto,
                                              path.nh_itf,
                                              path.nh_addr,
                                              path.nh_i_flags,
                                              table_id=self.table_id,
                                              bier_imp=path.bier_imp,
                                              is_add=0,
                                              is_ipv6=self.is_ip6)

    def update_entry_flags(self, flags):
        self.e_flags = flags
        self._test.vapi.ip_mroute_add_del(self.src_addr,
                                          self.grp_addr,
                                          self.grp_addr_len,
                                          self.e_flags,
                                          0,
                                          0xffffffff,
                                          "",
                                          0,
                                          table_id=self.table_id,
                                          is_ipv6=self.is_ip6)

    def update_rpf_id(self, rpf_id):
        self.rpf_id = rpf_id
        self._test.vapi.ip_mroute_add_del(self.src_addr,
                                          self.grp_addr,
                                          self.grp_addr_len,
                                          self.e_flags,
                                          0,
                                          0xffffffff,
                                          "",
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
                                          path.proto,
                                          path.nh_itf,
                                          path.nh_addr,
                                          path.nh_i_flags,
                                          table_id=self.table_id,
                                          is_ipv6=self.is_ip6)

    def query_vpp_config(self):
        return find_mroute(self._test,
                           self.grp_addr_p,
                           self.src_addr_p,
                           self.grp_addr_len,
                           self.table_id,
                           inet=AF_INET6 if self.is_ip6 == 1 else AF_INET)

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

    def get_stats(self):
        c = self._test.statistics.get_counter("/net/mroute")
        return c[0][self.stats_index]


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
            lstack = path.encode_labels()

            r = self._test.vapi.mpls_route_add_del(
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
                next_hop_out_label_stack=lstack,
                next_hop_n_out_labels=len(lstack),
                next_hop_via_label=path.nh_via_label,
                next_hop_table_id=path.nh_table_id)
        self.stats_index = r.stats_index
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
        return find_mpls_route(self._test, self.table_id,
                               self.local_label, self.eos_bit)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return ("%d:%s/%d"
                % (self.table_id,
                   self.local_label,
                   20+self.eos_bit))

    def get_stats_to(self):
        c = self._test.statistics.get_counter("/net/route/to")
        return c[0][self.stats_index]

    def get_stats_via(self):
        c = self._test.statistics.get_counter("/net/route/via")
        return c[0][self.stats_index]
