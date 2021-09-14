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
import abc
from vpp_pg_interface import is_ipv6_misc
from vpp_interface import VppInterface


class VppTunnelInterface(VppInterface, metaclass=abc.ABCMeta):
    """ VPP tunnel interface abstraction """

    def __init__(self, test, parent_if):
        super(VppTunnelInterface, self).__init__(test)
        self.parent_if = parent_if

    @property
    def local_mac(self):
        return self.parent_if.local_mac

    @property
    def remote_mac(self):
        return self.parent_if.remote_mac

    def enable_capture(self):
        return self.parent_if.enable_capture()

    def add_stream(self, pkts):
        return self.parent_if.add_stream(pkts)

    def get_capture(self, expected_count=None, remark=None, timeout=1,
                    filter_out_fn=is_ipv6_misc):
        return self.parent_if.get_capture(expected_count, remark, timeout,
                                          filter_out_fn)
