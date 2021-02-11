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
import socket


class IGMP_MODE:
    ROUTER = 0
    HOST = 1


class IGMP_FILTER:
    INCLUDE = 1
    EXCLUDE = 0


def find_igmp_state(states, itf, gaddr, saddr):
    for s in states:
        if s.sw_if_index == itf.sw_if_index and \
           str(s.gaddr) == gaddr and str(s.saddr) == saddr:
            return True
    return False


def wait_for_igmp_event(test, timeout, itf, gaddr, saddr, ff):
    ev = test.vapi.wait_for_event(timeout, "igmp_event")
    if ev.sw_if_index == itf.sw_if_index and \
       str(ev.gaddr) == gaddr and str(ev.saddr) == saddr and \
       ev.filter == ff:
        return True
    return False


class IgmpSG():
    def __init__(self, gaddr, saddrs):
        self.gaddr = gaddr
        self.gaddr_p = socket.inet_pton(socket.AF_INET, gaddr)
        self.saddrs = saddrs
        self.saddrs_p = []
        self.saddrs_encoded = []
        for s in saddrs:
            ss = socket.inet_pton(socket.AF_INET, s)
            self.saddrs_p.append(ss)
            self.saddrs_encoded.append(ss)


class IgmpRecord():
    def __init__(self, sg, type):
        self.sg = sg
        self.type = type


class VppHostState(VppObject):
    def __init__(self, test, filter, sw_if_index, sg):
        self._test = test
        self.sw_if_index = sw_if_index
        self.filter = filter
        self.sg = sg

    def add_vpp_config(self):
        self._test.vapi.igmp_listen(
            self.filter, self.sw_if_index,
            self.sg.saddrs_encoded, self.sg.gaddr_p)

    def remove_vpp_config(self):
        self._test.vapi.igmp_listen(
            self.filter,
            self.sw_if_index,
            [],
            self.sg.gaddr_p)

    def object_id(self):
        return "%s:%d" % (self.sg, self.sw_if_index)

    def query_vpp_config(self):
        return self._test.vapi.igmp_dump()
