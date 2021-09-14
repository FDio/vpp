#!/usr/bin/env python3
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
"""
  TEIB objects
"""

from vpp_object import VppObject


def find_teib(test, ne):
    ns = test.vapi.teib_dump()
    for n in ns:
        if ne.peer == str(n.entry.peer) \
           and ne.itf._sw_if_index == n.entry.sw_if_index:
            return True
    return False


class VppTeib(VppObject):

    def __init__(self, test, itf, peer, nh, table_id=0):
        self._test = test
        self.table_id = table_id
        self.peer = peer
        self.itf = itf
        self.nh = nh

    def add_vpp_config(self):
        r = self._test.vapi.teib_entry_add_del(
            is_add=1,
            entry={
                'nh_table_id': self.table_id,
                'sw_if_index': self.itf.sw_if_index,
                'peer': self.peer,
                'nh': self.nh,
            })
        self._test.registry.register(self, self._test.logger)
        return self

    def remove_vpp_config(self):
        r = self._test.vapi.teib_entry_add_del(
            is_add=0,
            entry={
                'nh_table_id': self.table_id,
                'sw_if_index': self.itf.sw_if_index,
                'peer': self.peer,
            })

    def query_vpp_config(self):
        return find_teib(self._test, self)

    def object_id(self):
        return ("teib-%s-%s" % (self.itf, self.peer))
