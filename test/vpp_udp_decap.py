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
  UDP decap objects
"""

from vpp_object import VppObject
from socket import inet_pton, inet_ntop, AF_INET, AF_INET6


class VppUdpDecap(VppObject):

    def __init__(self,
                 test,
                 is_ip4,
                 dst_port,
                 next_proto):
        self._test = test
        self.active = False
        self.udp_decap = {
            'is_ip4': is_ip4,
            'port': dst_port,
            'next_proto': next_proto
        }

    def add_vpp_config(self):
        self._test.vapi.udp_decap_add_del(True, self.udp_decap)
        self._test.registry.register(self, self._test.logger)
        self.active = True

    def query_vpp_config(self):
        return self.active

    def remove_vpp_config(self):
        self._test.vapi.udp_decap_add_del(False, self.udp_decap)
        self.active = False
