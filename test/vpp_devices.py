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


class VppTAPInterface(VppInterface):

    @property
    def tap_id(self):
        """TAP id"""
        return self._tap_id

    def __init__(self, test, tap_id=0xffffffff, mac_addr=None):
        self._test = test
        self._tap_id = tap_id
        self._mac_addr = mac_addr

    def get_vpp_dump(self):
        dump = self._test.vapi.sw_interface_tap_v2_dump(
            sw_if_index=self.sw_if_index)
        return dump

    def add_vpp_config(self):
        reply = self._test.vapi.tap_create_v2(
            id=self._tap_id,
            use_random_mac=bool(self._mac_addr),
            mac_address=self._mac_addr)
        self.set_sw_if_index(reply.sw_if_index)
        self._test.registry.register(self, self.test.logger)

    def remove_vpp_config(self):
        self._test.vapi.tap_delete_v2(sw_if_index=self.sw_if_index)

    def query_vpp_config(self):
        dump = self.get_vpp_dump()
        return bool(dump)

    def object_id(self):
        return "tap-%s" % self._tap_id
