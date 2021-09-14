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
from vpp_tunnel_interface import VppTunnelInterface
from ipaddress import ip_address
from vpp_papi import VppEnum


class VppIpIpTunInterface(VppTunnelInterface):
    """
    VPP IP-IP Tunnel interface
    """

    def __init__(self, test, parent_if, src, dst,
                 table_id=0, dscp=0x0,
                 flags=0, mode=None):
        super(VppIpIpTunInterface, self).__init__(test, parent_if)
        self.src = src
        self.dst = dst
        self.table_id = table_id
        self.dscp = dscp
        self.flags = flags
        self.mode = mode
        if not self.mode:
            self.mode = (VppEnum.vl_api_tunnel_mode_t.
                         TUNNEL_API_MODE_P2P)

    def add_vpp_config(self):
        r = self.test.vapi.ipip_add_tunnel(
            tunnel={
                'src': self.src,
                'dst': self.dst,
                'table_id': self.table_id,
                'flags': self.flags,
                'dscp': self.dscp,
                'instance': 0xffffffff,
                'mode': self.mode,
            })
        self.set_sw_if_index(r.sw_if_index)
        r = self.test.vapi.ipip_tunnel_dump(
            sw_if_index=self.sw_if_index)
        self.instance = r[0].tunnel.instance
        self.test.registry.register(self, self.test.logger)
        return self

    def remove_vpp_config(self):
        self.test.vapi.ipip_del_tunnel(sw_if_index=self._sw_if_index)

    def query_vpp_config(self):
        ts = self.test.vapi.ipip_tunnel_dump(sw_if_index=0xffffffff)
        for t in ts:
            if t.tunnel.sw_if_index == self._sw_if_index:
                return True
        return False

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "ipip%d" % self.instance

    @property
    def remote_ip(self):
        return self.dst

    @property
    def local_ip(self):
        return self.src
