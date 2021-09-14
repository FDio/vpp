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
import socket
from vpp_papi import VppEnum


class VppGreInterface(VppInterface):
    """
    VPP GRE interface
    """

    def __init__(self, test, src_ip, dst_ip, outer_table_id=0,
                 type=None, mode=None, flags=0,
                 session=0):
        """ Create VPP GRE interface """
        super(VppGreInterface, self).__init__(test)
        self.t_src = src_ip
        self.t_dst = dst_ip
        self.t_outer_table = outer_table_id
        self.t_session = session
        self.t_flags = flags
        self.t_type = type
        if not self.t_type:
            self.t_type = (VppEnum.vl_api_gre_tunnel_type_t.
                           GRE_API_TUNNEL_TYPE_L3)
        self.t_mode = mode
        if not self.t_mode:
            self.t_mode = (VppEnum.vl_api_tunnel_mode_t.
                           TUNNEL_API_MODE_P2P)

    def add_vpp_config(self):
        r = self.test.vapi.gre_tunnel_add_del(
            is_add=1,
            tunnel={
                'src': self.t_src,
                'dst': self.t_dst,
                'outer_table_id': self.t_outer_table,
                'instance': 0xffffffff,
                'type': self.t_type,
                'mode': self.t_mode,
                'flags': self.t_flags,
                'session_id': self.t_session})
        self.set_sw_if_index(r.sw_if_index)
        self.generate_remote_hosts()
        self.test.registry.register(self, self.test.logger)
        return self

    def remove_vpp_config(self):
        self.unconfig()
        self.test.vapi.gre_tunnel_add_del(
            is_add=0,
            tunnel={
                'src': self.t_src,
                'dst': self.t_dst,
                'outer_table_id': self.t_outer_table,
                'instance': 0xffffffff,
                'type': self.t_type,
                'mode': self.t_mode,
                'flags': self.t_flags,
                'session_id': self.t_session})

    def object_id(self):
        return "gre-%d" % self.sw_if_index

    def query_vpp_config(self):
        return (self.test.vapi.gre_tunnel_dump(
            sw_if_index=self._sw_if_index))

    @property
    def remote_ip(self):
        return self.t_dst

    @property
    def local_ip(self):
        return self.t_src
