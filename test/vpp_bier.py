"""
  BIER Tables and Routes
"""

import socket
from vpp_object import VppObject

class VppBierTableID():
    def __init__(self, set_id, sub_domain_id, hdr_len_id):
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
        if bp == r.br_bp:
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
        return find_bier_table(self._test,self.id)


class VppBierRoute(VppObject):
    """
    BIER route
    """

    def __init__(self, test, tbl_id, bp, nh, out_label):
        self._test = test
        self.tbl_id = tbl_id
        self.out_label = out_label
        self.bp = bp
        self.nh = socket.inet_pton(socket.AF_INET, nh)

    def add_vpp_config(self):
        self._test.vapi.bier_route_add_del(
            self.tbl_id,
            self.bp,
            self.nh,
            self.out_label,
            is_add=1)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.bier_route_add_del(
            self.tbl_id,
            self.bp,
            self.nh,
            self.out_label,
            is_add=0)

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "bier-route;[%d:%d:%d:%d]" % (self.tbl_id.set_id,
                                             self.tbl_id.sub_domain_id,
                                             self.tbl_id.hdr_len_id,
                                             self.bp)

    def query_vpp_config(self):
        return find_bier_route(self._test,self.tbl_id, self.bp)


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
        return False
