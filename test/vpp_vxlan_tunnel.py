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
from vpp_interface import VppInterface
from vpp_papi import VppEnum


INDEX_INVALID = 0xffffffff
DEFAULT_PORT = 4789
UNDEFINED_PORT = 0


def find_vxlan_tunnel(test, src, dst, s_port, d_port, vni):
    ts = test.vapi.vxlan_tunnel_v2_dump(INDEX_INVALID)

    src_port = DEFAULT_PORT
    if s_port != UNDEFINED_PORT:
        src_port = s_port

    dst_port = DEFAULT_PORT
    if d_port != UNDEFINED_PORT:
        dst_port = d_port

    for t in ts:
        if src == str(t.src_address) and \
           dst == str(t.dst_address) and \
           src_port == t.src_port and \
           dst_port == t.dst_port and \
           t.vni == vni:
            return t.sw_if_index
    return INDEX_INVALID


class VppVxlanTunnel(VppInterface):
    """
    VPP VXLAN interface
    """

    def __init__(self, test, src, dst, vni,
                 src_port=UNDEFINED_PORT, dst_port=UNDEFINED_PORT,
                 mcast_itf=None,
                 mcast_sw_if_index=INDEX_INVALID,
                 decap_next_index=INDEX_INVALID,
                 encap_vrf_id=None, instance=0xffffffff, is_l3=False):
        """ Create VXLAN Tunnel interface """
        super(VppVxlanTunnel, self).__init__(test)
        self.src = src
        self.dst = dst
        self.vni = vni
        self.src_port = src_port
        self.dst_port = dst_port
        self.mcast_itf = mcast_itf
        self.mcast_sw_if_index = mcast_sw_if_index
        self.encap_vrf_id = encap_vrf_id
        self.decap_next_index = decap_next_index
        self.instance = instance
        self.is_l3 = is_l3

        if (self.mcast_itf):
            self.mcast_sw_if_index = self.mcast_itf.sw_if_index

    def add_vpp_config(self):
        reply = self.test.vapi.vxlan_add_del_tunnel_v3(
            is_add=1, src_address=self.src, dst_address=self.dst, vni=self.vni,
            src_port=self.src_port, dst_port=self.dst_port,
            mcast_sw_if_index=self.mcast_sw_if_index,
            encap_vrf_id=self.encap_vrf_id, is_l3=self.is_l3,
            instance=self.instance, decap_next_index=self.decap_next_index)
        self.set_sw_if_index(reply.sw_if_index)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self.test.vapi.vxlan_add_del_tunnel_v2(
            is_add=0, src_address=self.src, dst_address=self.dst, vni=self.vni,
            src_port=self.src_port, dst_port=self.dst_port,
            mcast_sw_if_index=self.mcast_sw_if_index,
            encap_vrf_id=self.encap_vrf_id, instance=self.instance,
            decap_next_index=self.decap_next_index)

    def query_vpp_config(self):
        return (INDEX_INVALID != find_vxlan_tunnel(self._test,
                                                   self.src,
                                                   self.dst,
                                                   self.src_port,
                                                   self.dst_port,
                                                   self.vni))

    def object_id(self):
        return "vxlan-%d-%d-%s-%s" % (self.sw_if_index, self.vni,
                                      self.src, self.dst)
