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

from trex_stl_lib.api import *

class STLS1:

    def create_stream (self):
        base_pkt = Ether()/IP(dst="2.2.0.1")/UDP(dport=12)

        pad = Padding()
        if len(base_pkt) < 64:
            pad_len = 64 - len(base_pkt)
            pad.load = '\x00' * pad_len

        vm = STLVM()

        vm.tuple_var(name="tuple", ip_min="10.0.0.3", ip_max="10.1.134.162", port_min=1025, port_max=1124, limit_flows=10000000)

        vm.write(fv_name="tuple.ip", pkt_offset="IP.src")
        vm.fix_chksum()

        vm.write(fv_name="tuple.port", pkt_offset="UDP.sport")

        pkt = STLPktBuilder(pkt=base_pkt/pad, vm=vm)

        return STLStream(packet=pkt, mode=STLTXCont())

    def get_streams (self, direction = 0, **kwargs):
        return [self.create_stream()]


# dynamic load - used for trex console or simulator
def register():
    return STLS1()



