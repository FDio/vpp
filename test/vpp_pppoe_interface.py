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
from vpp_papi import mac_pton


class VppPppoeInterface(VppInterface):
    """
    VPP Pppoe interface
    """

    def __init__(self, test, client_ip, client_mac,
                 session_id, decap_vrf_id=0):
        """ Create VPP PPPoE4 interface """
        super(VppPppoeInterface, self).__init__(test)
        self.client_ip = client_ip
        self.client_mac = client_mac
        self.session_id = session_id
        self.decap_vrf_id = decap_vrf_id
        self.vpp_sw_if_index = -1

    def add_vpp_config(self):
        r = self.test.vapi.pppoe_add_del_session(
                self.client_ip, self.client_mac,
                session_id=self.session_id,
                decap_vrf_id=self.decap_vrf_id)
        self.set_sw_if_index(r.sw_if_index)
        self.vpp_sw_if_index = r.sw_if_index
        self.generate_remote_hosts()

    def remove_vpp_config(self):
        self.unconfig()
        self.test.vapi.pppoe_add_del_session(
                self.client_ip, self.client_mac,
                session_id=self.session_id,
                decap_vrf_id=self.decap_vrf_id,
                is_add=0)

    def set_unnumbered(self, swif_iface):
        self.test.vapi.sw_interface_set_unnumbered(
            swif_iface,
            self.vpp_sw_if_index)
