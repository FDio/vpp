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
from vpp_object import VppObject


class VppDHCPProxy(VppObject):

    def __init__(
        self,
        test,
        dhcp_server,
        dhcp_src_address,
        rx_vrf_id=0,
        server_vrf_id=0,
    ):
        self._test = test
        self._rx_vrf_id = rx_vrf_id
        self._server_vrf_id = server_vrf_id
        self._dhcp_server = dhcp_server
        self._dhcp_src_address = dhcp_src_address

    def set_proxy(
            self,
            dhcp_server,
            dhcp_src_address,
            rx_vrf_id=0,
            server_vrf_id=0):
        if self.query_vpp_config():
            raise Exception('Vpp config present')
        self._rx_vrf_id = rx_vrf_id
        self._server_vrf_id = server_vrf_id
        self._dhcp_server = dhcp_server
        self._dhcp_src_address = dhcp_src_address

    def add_vpp_config(self):
        self._test.vapi.dhcp_proxy_config(
            is_add=1,
            rx_vrf_id=self._rx_vrf_id,
            server_vrf_id=self._server_vrf_id,
            dhcp_server=self._dhcp_server,
            dhcp_src_address=self._dhcp_src_address)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.dhcp_proxy_config(
            rx_vrf_id=self._rx_vrf_id,
            server_vrf_id=self._server_vrf_id,
            dhcp_server=self._dhcp_server,
            dhcp_src_address=self._dhcp_src_address,
            is_add=0)

    def get_vpp_dump(self):
        dump = self._test.vapi.dhcp_proxy_dump()
        for entry in dump:
            if entry.rx_vrf_id == self._rx_vrf_id:
                return entry

    def query_vpp_config(self):
        dump = self.get_vpp_dump()
        return True if dump else False

    def object_id(self):
        return "dhcp-proxy-%d" % self._rx_vrf_id


class VppDHCPClient(VppObject):

    def __init__(
            self,
            test,
            sw_if_index,
            hostname,
            id=None,
            want_dhcp_event=False,
            set_broadcast_flag=True,
            dscp=None,
            pid=None):
        self._test = test
        self._sw_if_index = sw_if_index
        self._hostname = hostname
        self._id = id
        self._want_dhcp_event = want_dhcp_event
        self._set_broadcast_flag = set_broadcast_flag
        self._dscp = dscp
        self._pid = pid

    def set_client(
            self,
            sw_if_index,
            hostname,
            id=None,
            want_dhcp_event=False,
            set_broadcast_flag=True,
            dscp=None,
            pid=None):
        if self.query_vpp_config():
            raise Exception('Vpp config present')
        self._sw_if_index = sw_if_index
        self._hostname = hostname
        self._id = id
        self._want_dhcp_event = want_dhcp_event
        self._set_broadcast_flag = set_broadcast_flag
        self._dscp = dscp
        self._pid = pid

    def add_vpp_config(self):
        id = self._id.encode('ascii') if self._id else None
        client = {'sw_if_index': self._sw_if_index, 'hostname': self._hostname,
                  'id': id,
                  'want_dhcp_event': self._want_dhcp_event,
                  'set_broadcast_flag': self._set_broadcast_flag,
                  'dscp': self._dscp, 'pid': self._pid}
        self._test.vapi.dhcp_client_config(is_add=1, client=client)
        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        client = client = {
            'sw_if_index': self._sw_if_index,
            'hostname': self._hostname}
        self._test.vapi.dhcp_client_config(client=client, is_add=0)

    def get_vpp_dump(self):
        dump = self._test.vapi.dhcp_client_dump()
        for entry in dump:
            if entry.client.sw_if_index == self._sw_if_index:
                return entry

    def query_vpp_config(self):
        dump = self.get_vpp_dump()
        return True if dump else False

    def object_id(self):
        return "dhcp-client-%s/%d" % (self._hostname, self._sw_if_index)
