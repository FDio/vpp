"""
  BIER Tables and Routes
"""

import enum
import socket
from vpp_object import VppObject
from vpp_ip_route import MPLS_LABEL_INVALID, VppRoutePath, VppMplsLabel


class BIER_HDR_PROTO(enum.IntEnum):  # noqa
    MPLS_DOWN_STREAM = 1
    MPLS_UP_STREAM = 2
    ETHERNET = 3
    IPV4 = 4
    IPV6 = 5
    VXLAN = 6
    CTRL = 7
    OAM = 8


class VppBierTableID(object):
    def __init__(self, sub_domain_id, set_id, hdr_len_id):
        self.set_id = set_id
        self.sub_domain_id = sub_domain_id
        self.hdr_len_id = hdr_len_id


def find_bier_table(test, bti):
    tables = test.vapi.bier_table_dump()
    for t in tables:
        if bti.set_id == t.bt_tbl_id.bt_set \
           and bti.sub_domain_id == t.bt_tbl_id.bt_sub_domain \
           and bti.hdr_len_id == t.bt_tbl_id.bt_hdr_len_id:
            return True
    return False


def find_bier_route(test, bti, bp):
    routes = test.vapi.bier_route_dump(bti)
    for r in routes:
        if bti.set_id == r.br_tbl_id.bt_set \
           and bti.sub_domain_id == r.br_tbl_id.bt_sub_domain \
           and bti.hdr_len_id == r.br_tbl_id.bt_hdr_len_id \
           and bp == r.br_bp:
            return True
    return False


def find_bier_disp_table(test, bdti):
    tables = test.vapi.bier_disp_table_dump()
    for t in tables:
        if bdti == t.bdt_tbl_id:
            return True
    return False


def find_bier_disp_entry(test, bdti, bp):
    entries = test.vapi.bier_disp_entry_dump(bdti)
    for e in entries:
        if bp == e.bde_bp \
           and bdti == e.bde_tbl_id:
            return True
    return False


def find_bier_imp(test, bti, bp):
    imps = test.vapi.bier_imp_dump()
    for i in imps:
        if bti.set_id == i.bi_tbl_id.bt_set \
           and bti.sub_domain_id == i.bi_tbl_id.bt_sub_domain \
           and bti.hdr_len_id == i.bi_tbl_id.bt_hdr_len_id \
           and bp == i.bi_src:
            return True
    return False


class VppBierTable(VppObject):
    """
    BIER Table
    """

    def __init__(self, test, id, mpls_label):
        self._test = test
        self.id = id
        self.mpls_label = mpls_label

    def add_vpp_config(self):
        self._test.vapi.bier_table_add_del(
            self.id,
            self.mpls_label,
            is_add=1)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.bier_table_add_del(
            self.id,
            self.mpls_label,
            is_add=0)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "bier-table;[%d:%d:%d]" % (self.id.set_id,
                                          self.id.sub_domain_id,
                                          self.id.hdr_len_id)

    def query_vpp_config(self):
        return find_bier_table(self._test, self.id)


class VppBierRoute(VppObject):
    """
    BIER route
    """

    def __init__(self, test, tbl_id, bp, paths):
        self._test = test
        self.tbl_id = tbl_id
        self.bp = bp
        self.paths = paths

    def encode_path(self, p):
        lstack = []
        for l in p.nh_labels:
            if type(l) == VppMplsLabel:
                lstack.append(l.encode())
            else:
                lstack.append({'label': l, 'ttl': 255})
        n_labels = len(lstack)
        while (len(lstack) < 16):
            lstack.append({})
        return {'next_hop': p.nh_addr,
                'weight': 1,
                'afi': p.proto,
                'sw_if_index': 0xffffffff,
                'preference': 0,
                'table_id': p.nh_table_id,
                'next_hop_id': p.next_hop_id,
                'is_udp_encap': p.is_udp_encap,
                'n_labels': n_labels,
                'label_stack': lstack}

    def encode_paths(self):
        br_paths = []
        for p in self.paths:
            br_paths.append(self.encode_path(p))
        return br_paths

    def add_vpp_config(self):
        self._test.vapi.bier_route_add_del(
            self.tbl_id,
            self.bp,
            self.encode_paths(),
            is_add=1)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.bier_route_add_del(
            self.tbl_id,
            self.bp,
            self.encode_paths(),
            is_add=0)

    def update_paths(self, paths):
        self.paths = paths
        self._test.vapi.bier_route_add_del(
            self.tbl_id,
            self.bp,
            self.encode_paths(),
            is_replace=1)

    def add_path(self, path):
        self._test.vapi.bier_route_add_del(
            self.tbl_id,
            self.bp,
            [self.encode_path(path)],
            is_add=1,
            is_replace=0)
        self.paths.append(path)
        self._test.registry.register(self, self._test.logger)

    def remove_path(self, path):
        self._test.vapi.bier_route_add_del(
            self.tbl_id,
            self.bp,
            [self.encode_path(path)],
            is_add=0,
            is_replace=0)
        self.paths.remove(path)

    def remove_all_paths(self):
        self._test.vapi.bier_route_add_del(
            self.tbl_id,
            self.bp,
            [],
            is_add=0,
            is_replace=1)
        self.paths = []

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "bier-route;[%d:%d:%d:%d]" % (self.tbl_id.set_id,
                                             self.tbl_id.sub_domain_id,
                                             self.tbl_id.hdr_len_id,
                                             self.bp)

    def query_vpp_config(self):
        return find_bier_route(self._test, self.tbl_id, self.bp)


class VppBierImp(VppObject):
    """
    BIER route
    """

    def __init__(self, test, tbl_id, src, ibytes):
        self._test = test
        self.tbl_id = tbl_id
        self.ibytes = ibytes
        self.src = src

    def add_vpp_config(self):
        res = self._test.vapi.bier_imp_add(
            self.tbl_id,
            self.src,
            self.ibytes)
        self.bi_index = res.bi_index
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.bier_imp_del(
            self.bi_index)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "bier-imp;[%d:%d:%d:%d]" % (self.tbl_id.set_id,
                                           self.tbl_id.sub_domain_id,
                                           self.tbl_id.hdr_len_id,
                                           self.src)

    def query_vpp_config(self):
        return find_bier_imp(self._test, self.tbl_id, self.src)


class VppBierDispTable(VppObject):
    """
    BIER Disposition Table
    """

    def __init__(self, test, id):
        self._test = test
        self.id = id

    def add_vpp_config(self):
        self._test.vapi.bier_disp_table_add_del(
            self.id,
            is_add=1)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.bier_disp_table_add_del(
            self.id,
            is_add=0)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "bier-disp-table;[%d]" % (self.id)

    def query_vpp_config(self):
        return find_bier_disp_table(self._test, self.id)


class VppBierDispEntry(VppObject):
    """
    BIER Disposition Entry
    """

    def __init__(self, test, tbl_id, bp, payload_proto, nh_proto,
                 nh, nh_tbl, rpf_id=~0):
        self._test = test
        self.tbl_id = tbl_id
        self.nh_tbl = nh_tbl
        self.nh_proto = nh_proto
        self.bp = bp
        self.payload_proto = payload_proto
        self.rpf_id = rpf_id
        self.nh = socket.inet_pton(socket.AF_INET, nh)

    def add_vpp_config(self):
        self._test.vapi.bier_disp_entry_add_del(
            self.tbl_id,
            self.bp,
            self.payload_proto,
            self.nh_proto,
            self.nh,
            self.nh_tbl,
            self.rpf_id,
            is_add=1)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.bier_disp_entry_add_del(
            self.tbl_id,
            self.bp,
            self.payload_proto,
            self.nh_proto,
            self.nh,
            self.nh_tbl,
            self.rpf_id,
            is_add=0)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "bier-disp-entry;[%d:%d]" % (self.tbl_id,
                                            self.bp)

    def query_vpp_config(self):
        return find_bier_disp_entry(self._test, self.tbl_id, self.bp)
