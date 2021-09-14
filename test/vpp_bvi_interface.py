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
from vpp_interface import VppInterface


class VppBviInterface(VppInterface, VppObject):
    """VPP bvi interface."""

    def __init__(self, test):
        """ Create VPP BVI interface """
        super(VppBviInterface, self).__init__(test)
        self.add_vpp_config()

    def add_vpp_config(self):
        r = self.test.vapi.bvi_create(user_instance=0xffffffff,
                                      mac="00:00:00:00:00:00")
        self.set_sw_if_index(r.sw_if_index)

    def remove_vpp_config(self):
        self.test.vapi.bvi_delete(sw_if_index=self.sw_if_index)

    def object_id(self):
        return "bvi-%d" % self._sw_if_index
