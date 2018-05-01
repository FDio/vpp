"""
  IP Routes

  object abstractions for representing IP routes in VPP
"""

from vpp_object import *
from socket import inet_pton, inet_ntop, AF_INET, AF_INET6
from ipaddress import IPv4Address, IPv6Address, AddressValueError, ip_address

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


class FibPathProto:
    FIB_PATH_NH_PROTO_IP4 = 0
    FIB_PATH_NH_PROTO_IP6 = 1
    FIB_PATH_NH_PROTO_MPLS = 2
    FIB_PATH_NH_PROTO_ETHERNET = 3
    FIB_PATH_NH_PROTO_BIER = 4
    FIB_PATH_NH_PROTO_NSH = 5


class IpAddressFamily:
    ADDRESS_IP4 = 0
    ADDRESS_IP6 = 1
    

class MplsLspMode:
    PIPE = 0
    UNIFORM = 1


def find_route(test, ip_addr, len, table_id=0, inet=AF_INET):
    ip_addr = ip_address(unicode(ip_addr))
    if 4 is ip_addr.version:
        s = 4
        routes = test.vapi.ip_route_dump(table_id, False)
    else:
        s = 16
        routes = test.vapi.ip_route_dump(table_id, True)

    for e in routes:
        if ip_addr.packed == e.route.prefix.address[:s] \
           and len == e.route.prefix.address_length \
           and table_id == e.route.table_id:
            return True
    return False


def find_mroute(test, grp_addr, src_addr, grp_addr_len,
                table_id=0, inet=AF_INET):
    ip_saddr = ip_address(unicode(src_addr))
    ip_gaddr = ip_address(unicode(grp_addr))
    if 4 is ip_saddr.version:
        s = 4
        routes = test.vapi.ip_mroute_dump(table_id, False)
    else:
        s = 16
        routes = test.vapi.ip_mroute_dump(table_id, True)

    for e in routes:
        if ip_gaddr.packed == e.route.prefix.grp_address[:s] \
           and grp_addr_len == e.route.prefix.address_length \
           and ip_saddr.packed == e.route.prefix.src_address[:s] \
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

class VppIpAddress():
        def __init__(self, addr):
            self.addr = addr
            self.ip_addr = ip_address(unicode(self.addr))

        def proto(self):
            if self.ip_addr.version is 4:
                return FibPathProto.FIB_PATH_NH_PROTO_IP4
            else:
                return FibPathProto.FIB_PATH_NH_PROTO_IP6

        def encode(self):
            if self.proto() is FibPathProto.FIB_PATH_NH_PROTO_IP6:
                return {
                    'ip6': {
                        'address': self.ip_addr.packed
                    },
                }
            else:
                return {
                    'ip4': {
                        'address': self.ip_addr.packed
                    },
                }


class VppFibPathNextHop:
    def __init__(self, addr, via_label=MPLS_LABEL_INVALID):
        self.addr = VppIpAddress(addr)
        self.via_label = via_label

    def encode(self):
        if self.via_label is MPLS_LABEL_INVALID:
            return {'address': self.addr.encode()}
        else:
            return {'via_label': self.via_label}

    def proto(self):
        if self.via_label is MPLS_LABEL_INVALID:
            return self.addr.proto()
        else:
            return FibPathProto.FIB_PATH_NH_PROTO_MPLS


class VppRoutePath(object):

    def __init__(
            self,
            nh_addr,
            nh_sw_if_index,
            nh_table_id=0,
            labels=[],
            nh_via_label=MPLS_LABEL_INVALID,
            rpf_id=0,
            next_hop_id=0xffffffff,
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
        self.nh = VppFibPathNextHop(nh_addr, nh_via_label)
        self.proto = self.nh.proto()
        self.next_hop_id = next_hop_id

    def encode_labels(self):
        lstack = []
        for l in self.nh_labels:
            if type(l) == VppMplsLabel:
                lstack.append(l.encode())
            else:
                lstack.append({'label': l,
                               'ttl': 255})
        n_labels = len(lstack)
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


class VppMRoutePath(VppRoutePath):

    def __init__(self, nh_sw_if_index, flags,
                 nh=None,
                 proto=FibPathProto.FIB_PATH_NH_PROTO_IP4,
                 bier_imp=0):
        if not nh:
            nh = "::" if proto is FibPathProto.FIB_PATH_NH_PROTO_IP6 else "0.0.0.0"
        super(VppMRoutePath, self).__init__(nh,
                                            nh_sw_if_index,
                                            proto=proto)
        self.nh_i_flags = flags
        self.bier_imp = bier_imp

    def encode(self):
        return {'path': super(VppMRoutePath, self).encode(),
                'itf_flags': self.nh_i_flags}

class VppIpPrefix():
    def __init__(self, addr, len):
        self.addr = addr
        self.len = len

    def encode(self):
        ip_addr = ip_address(unicode(self.addr))

        if 6 is ip_addr.version:
            prefix = {
                'address': {
                    'af': IpAddressFamily.ADDRESS_IP6,
                    'un': {
                        'ip6': {
                            'address': ip_addr.packed
                            },
                        },
                    },
                'address_length': self.len,
                }
        else:
            prefix = {
                'address': {
                    'af': IpAddressFamily.ADDRESS_IP4,
                    'un': {
                        'ip4': {
                            'address': ip_addr.packed
                            },
                        },
                    },
                'address_length': self.len,
                }
        return prefix


class VppIpRoute(VppObject):
    """
    IP Route
    """

    def __init__(self, test, dest_addr,
                 dest_addr_len, paths, table_id=0):
        self._test = test
        self.paths = paths
        self.table_id = table_id
        self.dest_addr_p = dest_addr
        self.prefix = VppIpPrefix(dest_addr, dest_addr_len)

        self.encoded_paths = []
        for path in self.paths:
            self.encoded_paths.append(path.encode())

    def modify(self, paths, is_local=0,
               is_unreach=0, is_prohibit=0):
        self.paths = paths
        self.is_local = is_local
        self.is_unreach = is_unreach
        self.is_prohibit = is_prohibit

    def add_vpp_config(self):
        self._test.vapi.ip_route_add_del(
            self.table_id,
            self.prefix.encode(),
            self.encoded_paths,
            1, 0)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.ip_route_add_del(
            self.table_id,
            self.prefix.encode(),
            self.encoded_paths,
            0, 0)

    def query_vpp_config(self):
        return find_route(self._test,
                          self.prefix.addr,
                          self.prefix.len,
                          self.table_id)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return ("%d:%s/%d"
                % (self.table_id,
                   self.prefix.addr,
                   self.prefix.len))


class VppIpMPrefix():
    def __init__(self, saddr, gaddr, len):
        self.saddr = saddr
        self.gaddr = gaddr
        self.len = len

    def encode(self):
        ip_saddr = ip_address(unicode(self.saddr))
        ip_gaddr = ip_address(unicode(self.gaddr))

        if 6 is ip_saddr.version:
            prefix = {
                'af': IpAddressFamily.ADDRESS_IP6,
                'grp_address': {
                    'ip6': {
                        'address': ip_gaddr.packed
                    },
                },
                'src_address': {
                    'ip6': {
                        'address': ip_saddr.packed
                    },
                },
                'grp_address_length': self.len,
            }
        else:
            prefix = {
                'af': IpAddressFamily.ADDRESS_IP4,
                'grp_address': {
                    'ip4': {
                        'address': ip_gaddr.packed
                    },
                },
                'src_address': {
                    'ip4': {
                        'address': ip_saddr.packed
                    },
                },
                'grp_address_length': self.len,
            }
        return prefix


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
        self._test.vapi.ip_mroute_add_del(self.table_id,
                                          self.prefix.encode(),
                                          self.e_flags,
                                          self.rpf_id,
                                          self.encoded_paths,
                                          is_add=1)
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
        for path in self.paths:
            if path.nh_itf == itf:
                path.nh_i_flags = flags
                break
        self.encoded_paths = []
        for path in self.paths:
            self.encoded_paths.append(path.encode())

        self._test.vapi.ip_mroute_add_del(self.table_id,
                                          self.prefix.encode(),
                                          self.e_flags,
                                          self.rpf_id,
                                          self.encoded_paths,
                                          is_add=1)

    def query_vpp_config(self):
        return find_mroute(self._test,
                           self.prefix.gaddr,
                           self.prefix.saddr,
                           self.prefix.len,
                           self.table_id)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return ("%d:(%s,%s/%d)" % (self.table_id,
                                   self.prefix.saddr,
                                   self.prefix.gaddr,
                                   self.prefix.len))


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
        self.ip_addr = ip_address(unicode(dest_addr))
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
        dump = self._test.vapi.mpls_table_dump()
        for d in dump:
            if d.mt_table.mt_table_id == self.table_id:
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

        self._test.vapi.mpls_route_add_del(self.table_id,
                                           self.local_label,
                                           self.eos_bit,
                                           self.eos_proto,
                                           self.is_multicast,
                                           paths, 1, 0)
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
        dump = self._test.vapi.mpls_route_dump(self.table_id)
        for e in dump:
            if self.local_label == e.mr_route.mr_label \
               and self.eos_bit == e.mr_route.mr_eos \
               and self.table_id == e.mr_route.mr_table_id:
                return True
        return False

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return ("%d:%s/%d"
                % (self.table_id,
                   self.local_label,
                   20+self.eos_bit))
