# Copyright (c) 2021 Cisco and/or its affiliates.
#
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#
# Licensed under the Apache License 2.0 or
# GNU General Public License v2.0 or later;  you may not use this file
# except in compliance with one of these Licenses. You
# may obtain a copy of the Licenses at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#     https://www.gnu.org/licenses/old-licenses/gpl-2.0-standalone.html
#
# Note: If this file is linked with Scapy, which is GPLv2+, your use of it
# must be under GPLv2+.  If at any point in the future it is no longer linked
# with Scapy (or other GPLv2+ licensed software), you are free to choose
# Apache 2.
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
  BIER Tables and Routes
"""

import socket
from vpp_object import VppObject
from vpp_ip_route import MPLS_LABEL_INVALID, VppRoutePath, VppMplsLabel


class BIER_HDR_PAYLOAD:
    BIER_HDR_PROTO_MPLS_DOWN_STREAM = 1
    BIER_HDR_PROTO_MPLS_UP_STREAM = 2
    BIER_HDR_PROTO_ETHERNET = 3
    BIER_HDR_PROTO_IPV4 = 4
    BIER_HDR_PROTO_IPV6 = 5
    BIER_HDR_PROTO_VXLAN = 6
    BIER_HDR_PROTO_CTRL = 7
    BIER_HDR_PROTO_OAM = 8


class VppBierTableID():
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
        if bti.set_id == r.br_route.br_tbl_id.bt_set \
           and bti.sub_domain_id == r.br_route.br_tbl_id.bt_sub_domain \
           and bti.hdr_len_id == r.br_route.br_tbl_id.bt_hdr_len_id \
           and bp == r.br_route.br_bp:
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
        self.encoded_paths = []
        for path in self.paths:
            self.encoded_paths.append(path.encode())

    def add_vpp_config(self):
        self._test.vapi.bier_route_add_del(
            self.tbl_id,
            self.bp,
            self.encoded_paths,
            is_add=1)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.bier_route_add_del(
            self.tbl_id,
            self.bp,
            self.encoded_paths,
            is_add=0)

    def update_paths(self, paths):
        self.paths = paths
        self.encoded_paths = []
        for path in self.paths:
            self.encoded_paths.append(path.encode())
        self._test.vapi.bier_route_add_del(
            self.tbl_id,
            self.bp,
            self.encoded_paths,
            is_replace=1)

    def add_path(self, path):
        self.encoded_paths.append(path.encode())
        self._test.vapi.bier_route_add_del(
            self.tbl_id,
            self.bp,
            [path.encode()],
            is_add=1,
            is_replace=0)
        self.paths.append(path)
        self._test.registry.register(self, self._test.logger)

    def remove_path(self, path):
        self.encoded_paths.remove(path.encode())
        self._test.vapi.bier_route_add_del(
            self.tbl_id,
            self.bp,
            [path.encode()],
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

    def object_id(self):
        return "bier-disp-entry;[%d:%d]" % (self.tbl_id,
                                            self.bp)

    def query_vpp_config(self):
        return find_bier_disp_entry(self._test, self.tbl_id, self.bp)
