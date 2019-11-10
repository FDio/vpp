"""
  IP Routes

  object abstractions for representing IP routes in VPP
"""

from ipaddress import IPv4Network, IPv6Network, ip_address
from socket import AF_INET, AF_INET6, inet_ntop, inet_pton

from vpp_ip import (
    INVALID_INDEX,
    DpoProto,
    VppIpAddressUnion,
    VppIpMPrefix,
    VppIpPrefix,
)
from vpp_object import VppObject

# from vnet/vnet/mpls/mpls_types.h
MPLS_IETF_MAX_LABEL = 0xfffff
MPLS_LABEL_INVALID = MPLS_IETF_MAX_LABEL + 1

try:
    text_type = unicode
except NameError:
    text_type = str


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


class FibPathProto:
    FIB_PATH_NH_PROTO_IP4 = 0
    FIB_PATH_NH_PROTO_IP6 = 1
    FIB_PATH_NH_PROTO_MPLS = 2
    FIB_PATH_NH_PROTO_ETHERNET = 3
    FIB_PATH_NH_PROTO_BIER = 4
    FIB_PATH_NH_PROTO_NSH = 5


class FibPathType:
    FIB_PATH_TYPE_NORMAL = 0
    FIB_PATH_TYPE_LOCAL = 1
    FIB_PATH_TYPE_DROP = 2
    FIB_PATH_TYPE_UDP_ENCAP = 3
    FIB_PATH_TYPE_BIER_IMP = 4
    FIB_PATH_TYPE_ICMP_UNREACH = 5
    FIB_PATH_TYPE_ICMP_PROHIBIT = 6
    FIB_PATH_TYPE_SOURCE_LOOKUP = 7
    FIB_PATH_TYPE_DVR = 8
    FIB_PATH_TYPE_INTERFACE_RX = 9
    FIB_PATH_TYPE_CLASSIFY = 10


class FibPathFlags:
    FIB_PATH_FLAG_NONE = 0
    FIB_PATH_FLAG_RESOLVE_VIA_ATTACHED = 1
    FIB_PATH_FLAG_RESOLVE_VIA_HOST = 2
    FIB_PATH_FLAG_POP_PW_CW = 4


class MplsLspMode:
    PIPE = 0
    UNIFORM = 1


def ip_to_dpo_proto(addr):
    if addr.version == 6:
        return DpoProto.DPO_PROTO_IP6
    else:
        return DpoProto.DPO_PROTO_IP4


def address_proto(ip_addr):
    if ip_addr.ip_addr.version is 4:
        return FibPathProto.FIB_PATH_NH_PROTO_IP4
    else:
        return FibPathProto.FIB_PATH_NH_PROTO_IP6


def find_route(test, addr, len, table_id=0):
    ip_addr = ip_address(text_type(addr))

    if 4 is ip_addr.version:
        routes = test.vapi.ip_route_dump(table_id, False)
        prefix = IPv4Network("%s/%d" % (text_type(addr), len), strict=False)
    else:
        routes = test.vapi.ip_route_dump(table_id, True)
        prefix = IPv6Network("%s/%d" % (text_type(addr), len), strict=False)

    for e in routes:
        if table_id == e.route.table_id \
           and prefix == e.route.prefix:
            return True
    return False


def find_mroute(test, grp_addr, src_addr, grp_addr_len,
                table_id=0):
    ip_mprefix = VppIpMPrefix(text_type(src_addr),
                              text_type(grp_addr),
                              grp_addr_len)

    if 4 is ip_mprefix.version:
        routes = test.vapi.ip_mroute_dump(table_id, False)
    else:
        routes = test.vapi.ip_mroute_dump(table_id, True)

    for e in routes:
        if table_id == e.route.table_id and ip_mprefix == e.route.prefix:
            return True
    return False


def find_mpls_route(test, table_id, label, eos_bit, paths=None):
    dump = test.vapi.mpls_route_dump(table_id)
    for e in dump:
        if label == e.mr_route.mr_label \
           and eos_bit == e.mr_route.mr_eos \
           and table_id == e.mr_route.mr_table_id:
            if not paths:
                return True
            else:
                if (len(paths) != len(e.mr_route.mr_paths)):
                    return False
                for i in range(len(paths)):
                    if (paths[i] != e.mr_route.mr_paths[i]):
                        return False
                return True
    return False


def fib_interface_ip_prefix(test, address, length, sw_if_index):
    ip_addr = ip_address(text_type(address))

    if 4 is ip_addr.version:
        addrs = test.vapi.ip_address_dump(sw_if_index)
        prefix = IPv4Network("%s/%d" % (text_type(address), length),
                             strict=False)
    else:
        addrs = test.vapi.ip_address_dump(sw_if_index, is_ipv6=1)
        prefix = IPv6Network("%s/%d" % (text_type(address), length),
                             strict=False)

    # TODO: refactor this to VppIpPrefix.__eq__
    for a in addrs:
        if a.sw_if_index == sw_if_index and \
           a.prefix.network == prefix:
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
        self._test.vapi.ip_table_add_del(is_ipv6=self.is_ip6, is_add=1,
                                         table_id=self.table_id)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.ip_table_add_del(is_ipv6=self.is_ip6, is_add=0,
                                         table_id=self.table_id)

    def query_vpp_config(self):
        if self.table_id == 0:
            # the default table always exists
            return False
        # find the default route
        return find_route(self._test,
                          "::" if self.is_ip6 else "0.0.0.0",
                          0,
                          self.table_id)

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
            sw_if_index=self.intf.sw_if_index, prefix=self.prefix.encode(),
            is_add=1)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.sw_interface_add_del_address(
            sw_if_index=self.intf.sw_if_index, prefix=self.prefix.encode(),
            is_add=0)

    def query_vpp_config(self):
        return fib_interface_ip_prefix(self._test,
                                       self.prefix.address,
                                       self.prefix.length,
                                       self.intf.sw_if_index)

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

    def object_id(self):
        return "interface-bind-%s-%s" % (self.intf, self.table)


class VppMplsLabel(object):
    def __init__(self, value, mode=MplsLspMode.PIPE, ttl=64, exp=0):
        self.value = value
        self.mode = mode
        self.ttl = ttl
        self.exp = exp

    def encode(self):
        is_uniform = 0 if self.mode is MplsLspMode.PIPE else 1
        return {'label': self.value,
                'ttl': self.ttl,
                'exp': self.exp,
                'is_uniform': is_uniform}

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return (self.value == other.value and
                    self.ttl == other.ttl and
                    self.exp == other.exp and
                    self.mode == other.mode)
        elif hasattr(other, 'label'):
            return (self.value == other.label and
                    self.ttl == other.ttl and
                    self.exp == other.exp and
                    (self.mode == MplsLspMode.UNIFORM) == other.is_uniform)
        else:
            return False

    def __ne__(self, other):
        return not (self == other)


class VppFibPathNextHop(object):
    def __init__(self, addr,
                 via_label=MPLS_LABEL_INVALID,
                 next_hop_id=INVALID_INDEX):
        self.addr = VppIpAddressUnion(addr)
        self.via_label = via_label
        self.obj_id = next_hop_id

    def encode(self):
        if self.via_label is not MPLS_LABEL_INVALID:
            return {'via_label': self.via_label}
        if self.obj_id is not INVALID_INDEX:
            return {'obj_id': self.obj_id}
        else:
            return {'address': self.addr.encode()}

    def proto(self):
        if self.via_label is MPLS_LABEL_INVALID:
            return address_proto(self.addr)
        else:
            return FibPathProto.FIB_PATH_NH_PROTO_MPLS

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            # try the other instance's __eq__.
            return NotImplemented
        return (self.addr == other.addr and
                self.via_label == other.via_label and
                self.obj_id == other.obj_id)


class VppRoutePath(object):

    def __init__(
            self,
            nh_addr,
            nh_sw_if_index,
            nh_table_id=0,
            labels=[],
            nh_via_label=MPLS_LABEL_INVALID,
            rpf_id=0,
            next_hop_id=INVALID_INDEX,
            proto=None,
            flags=FibPathFlags.FIB_PATH_FLAG_NONE,
            type=FibPathType.FIB_PATH_TYPE_NORMAL):
        self.nh_itf = nh_sw_if_index
        self.nh_table_id = nh_table_id
        self.nh_labels = labels
        self.weight = 1
        self.rpf_id = rpf_id
        self.proto = proto
        self.flags = flags
        self.type = type
        self.nh = VppFibPathNextHop(nh_addr, nh_via_label, next_hop_id)
        if proto is None:
            self.proto = self.nh.proto()
        else:
            self.proto = proto
        self.next_hop_id = next_hop_id

    def encode_labels(self):
        lstack = []
        for l in self.nh_labels:
            if type(l) == VppMplsLabel:
                lstack.append(l.encode())
            else:
                lstack.append({'label': l,
                               'ttl': 255})
        while (len(lstack) < 16):
            lstack.append({})

        return lstack

    def encode(self):
        return {'weight': 1,
                'preference': 0,
                'table_id': self.nh_table_id,
                'nh': self.nh.encode(),
                'next_hop_id': self.next_hop_id,
                'sw_if_index': self.nh_itf,
                'rpf_id': self.rpf_id,
                'proto': self.proto,
                'type': self.type,
                'flags': self.flags,
                'n_labels': len(self.nh_labels),
                'label_stack': self.encode_labels()}

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.nh == other.nh
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
                 proto=FibPathProto.FIB_PATH_NH_PROTO_IP4,
                 type=FibPathType.FIB_PATH_TYPE_NORMAL,
                 bier_imp=INVALID_INDEX):
        if not nh:
            nh = "::" if proto is FibPathProto.FIB_PATH_NH_PROTO_IP6 \
                 else "0.0.0.0"
        super(VppMRoutePath, self).__init__(nh,
                                            nh_sw_if_index,
                                            proto=proto,
                                            type=type,
                                            next_hop_id=bier_imp)
        self.nh_i_flags = flags
        self.bier_imp = bier_imp

    def encode(self):
        return {'path': super(VppMRoutePath, self).encode(),
                'itf_flags': self.nh_i_flags}


class VppIpRoute(VppObject):
    """
    IP Route
    """

    def __init__(self, test, dest_addr,
                 dest_addr_len, paths, table_id=0, register=True):
        self._test = test
        self.paths = paths
        self.table_id = table_id
        self.prefix = VppIpPrefix(dest_addr, dest_addr_len)
        self.register = register
        self.stats_index = None
        self.modified = False

        self.encoded_paths = []
        for path in self.paths:
            self.encoded_paths.append(path.encode())

    def __eq__(self, other):
        if self.table_id == other.table_id and \
           self.prefix == other.prefix:
            return True
        return False

    def modify(self, paths):
        self.paths = paths
        self.encoded_paths = []
        for path in self.paths:
            self.encoded_paths.append(path.encode())
        self.modified = True

        self._test.vapi.ip_route_add_del(route={'table_id': self.table_id,
                                                'prefix': self.prefix.encode(),
                                                'n_paths': len(
                                                    self.encoded_paths),
                                                'paths': self.encoded_paths,
                                                },
                                         is_add=1,
                                         is_multipath=0)

    def add_vpp_config(self):
        r = self._test.vapi.ip_route_add_del(
            route={'table_id': self.table_id,
                   'prefix': self.prefix.encode(),
                   'n_paths': len(self.encoded_paths),
                   'paths': self.encoded_paths,
                   },
            is_add=1,
            is_multipath=0)
        self.stats_index = r.stats_index
        if self.register:
            self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        # there's no need to issue different deletes for modified routes
        # we do this only to test the two different ways to delete routes
        # eiter by passing all the paths to remove and mutlipath=1 or
        # passing no paths and multipath=0
        if self.modified:
            self._test.vapi.ip_route_add_del(
                route={'table_id': self.table_id,
                       'prefix': self.prefix.encode(),
                       'n_paths': len(
                           self.encoded_paths),
                       'paths': self.encoded_paths},
                is_add=0,
                is_multipath=1)
        else:
            self._test.vapi.ip_route_add_del(
                route={'table_id': self.table_id,
                       'prefix': self.prefix.encode(),
                       'n_paths': 0},
                is_add=0,
                is_multipath=0)

    def query_vpp_config(self):
        return find_route(self._test,
                          self.prefix.address,
                          self.prefix.len,
                          self.table_id)

    def object_id(self):
        return ("%s:table-%d-%s/%d" % (
            'ip6-route' if self.prefix.addr.version == 6 else 'ip-route',
                self.table_id,
                self.prefix.address,
                self.prefix.len))

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
                 rpf_id=0):
        self._test = test
        self.paths = paths
        self.table_id = table_id
        self.e_flags = e_flags
        self.rpf_id = rpf_id

        self.prefix = VppIpMPrefix(src_addr, grp_addr, grp_addr_len)
        self.encoded_paths = []
        for path in self.paths:
            self.encoded_paths.append(path.encode())

    def add_vpp_config(self):
        r = self._test.vapi.ip_mroute_add_del(self.table_id,
                                              self.prefix.encode(),
                                              self.e_flags,
                                              self.rpf_id,
                                              self.encoded_paths,
                                              is_add=1)
        self.stats_index = r.stats_index
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.ip_mroute_add_del(self.table_id,
                                          self.prefix.encode(),
                                          self.e_flags,
                                          self.rpf_id,
                                          self.encoded_paths,
                                          is_add=0)

    def update_entry_flags(self, flags):
        self.e_flags = flags
        self._test.vapi.ip_mroute_add_del(self.table_id,
                                          self.prefix.encode(),
                                          self.e_flags,
                                          self.rpf_id,
                                          [],
                                          is_add=1)

    def update_rpf_id(self, rpf_id):
        self.rpf_id = rpf_id
        self._test.vapi.ip_mroute_add_del(self.table_id,
                                          self.prefix.encode(),
                                          self.e_flags,
                                          self.rpf_id,
                                          [],
                                          is_add=1)

    def update_path_flags(self, itf, flags):
        for p in range(len(self.paths)):
            if self.paths[p].nh_itf == itf:
                self.paths[p].nh_i_flags = flags
            self.encoded_paths[p] = self.paths[p].encode()
            break

        self._test.vapi.ip_mroute_add_del(self.table_id,
                                          self.prefix.encode(),
                                          self.e_flags,
                                          self.rpf_id,
                                          [self.encoded_paths[p]],
                                          is_add=1,
                                          is_multipath=0)

    def query_vpp_config(self):
        return find_mroute(self._test,
                           self.prefix.gaddr,
                           self.prefix.saddr,
                           self.prefix.length,
                           self.table_id)

    def object_id(self):
        return ("%d:(%s,%s/%d)" % (self.table_id,
                                   self.prefix.saddr,
                                   self.prefix.gaddr,
                                   self.prefix.length))

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
        self.test.assertEqual(self.route.prefix, signal.prefix)


class VppMplsIpBind(VppObject):
    """
    MPLS to IP Binding
    """

    def __init__(self, test, local_label, dest_addr, dest_addr_len,
                 table_id=0, ip_table_id=0, is_ip6=0):
        self._test = test
        self.dest_addr_len = dest_addr_len
        self.dest_addr = dest_addr
        self.ip_addr = ip_address(text_type(dest_addr))
        self.local_label = local_label
        self.table_id = table_id
        self.ip_table_id = ip_table_id
        self.prefix = VppIpPrefix(dest_addr, dest_addr_len)

    def add_vpp_config(self):
        self._test.vapi.mpls_ip_bind_unbind(self.local_label,
                                            self.prefix.encode(),
                                            table_id=self.table_id,
                                            ip_table_id=self.ip_table_id)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.mpls_ip_bind_unbind(self.local_label,
                                            self.prefix.encode(),
                                            table_id=self.table_id,
                                            ip_table_id=self.ip_table_id,
                                            is_bind=0)

    def query_vpp_config(self):
        dump = self._test.vapi.mpls_route_dump(self.table_id)
        for e in dump:
            if self.local_label == e.mr_route.mr_label \
               and self.table_id == e.mr_route.mr_table_id:
                return True
        return False

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
        dump = self._test.vapi.mpls_table_dump()
        for d in dump:
            if d.mt_table.mt_table_id == self.table_id:
                return True
        return False

    def object_id(self):
        return ("table-mpls-%d" % (self.table_id))


class VppMplsRoute(VppObject):
    """
    MPLS Route/LSP
    """

    def __init__(self, test, local_label, eos_bit, paths, table_id=0,
                 is_multicast=0,
                 eos_proto=FibPathProto.FIB_PATH_NH_PROTO_IP4):
        self._test = test
        self.paths = paths
        self.local_label = local_label
        self.eos_bit = eos_bit
        self.eos_proto = eos_proto
        self.table_id = table_id
        self.is_multicast = is_multicast

    def add_vpp_config(self):
        paths = []
        for path in self.paths:
            paths.append(path.encode())

        r = self._test.vapi.mpls_route_add_del(self.table_id,
                                               self.local_label,
                                               self.eos_bit,
                                               self.eos_proto,
                                               self.is_multicast,
                                               paths, 1, 0)
        self.stats_index = r.stats_index
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        paths = []
        for path in self.paths:
            paths.append(path.encode())

        self._test.vapi.mpls_route_add_del(self.table_id,
                                           self.local_label,
                                           self.eos_bit,
                                           self.eos_proto,
                                           self.is_multicast,
                                           paths, 0, 0)

    def query_vpp_config(self):
        return find_mpls_route(self._test, self.table_id,
                               self.local_label, self.eos_bit)

    def object_id(self):
        return ("mpls-route-%d:%s/%d"
                % (self.table_id,
                   self.local_label,
                   20 + self.eos_bit))

    def get_stats_to(self):
        c = self._test.statistics.get_counter("/net/route/to")
        return c[0][self.stats_index]

    def get_stats_via(self):
        c = self._test.statistics.get_counter("/net/route/via")
        return c[0][self.stats_index]
