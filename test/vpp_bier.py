"""
  BIER Tables and Routes
"""

import socket
from vpp_object import VppObject

class VppBIERTableID():
    def __init__(self, set_id, sub_domain_id, hdr_len_id):
        self.set_id = set_id
        self.sub_domain_id = sub_domain_id
        self.hdr_len_id = hdr_len_id


class VppBIERTable(VppObject):
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

    def remove_vpp_config(self):
        self._test.vapi.bier_table_add_del(
            self.id,
            self.mpls_label,
            is_add=0)

    def object_id(self):
        return "bier-table;[%d:%d:%d]" % (self.set_id,
                                          self.sub_domain_id,
                                          self.hdr_len_id)

    def query_vpp_config(self):
        return False


class VppBIERRoute(VppObject):
    """
    BIER route
    """

    def __init__(self, test, set_id, sub_domain_id, hdr_len_id,
                 bp, nh, out_label):
        self._test = test
        self.set_id = set_id
        self.sub_domain_id = sub_domain_id
        self.hdr_len_id = hdr_len_id
        self.out_label = out_label
        self.bp = bp
        self.nh = socket.inet_pton(socket.AF_INET, nh)

    def add_vpp_config(self):
        self._test.vapi.bier_route_add_del(
            self.set_id,
            self.sub_domain_id,
            self.hdr_len_id,
            self.bp,
            self.nh,
            self.out_label,
            is_add=1)

    def remove_vpp_config(self):
        self._test.vapi.bier_route_add_del(
            self.set_id,
            self.sub_domain_id,
            self.hdr_len_id,
            self.bp,
            self.nh,
            self.out_label,
            is_add=0)

    def object_id(self):
        return "bier-route;[%d:%d:%d:%d]" % (self.set_id,
                                             self.sub_domain_id,
                                             self.hdr_len_id,
                                             self.pb)

    def query_vpp_config(self):
        return False
