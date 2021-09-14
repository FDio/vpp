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
  SRv6 LocalSIDs

  object abstractions for representing SRv6 localSIDs in VPP
"""

from vpp_object import VppObject
from socket import inet_pton, inet_ntop, AF_INET, AF_INET6


class SRv6LocalSIDBehaviors():
    # from src/vnet/srv6/sr.h
    SR_BEHAVIOR_END = 1
    SR_BEHAVIOR_X = 2
    SR_BEHAVIOR_T = 3
    SR_BEHAVIOR_D_FIRST = 4   # Unused. Separator in between regular and D
    SR_BEHAVIOR_DX2 = 5
    SR_BEHAVIOR_DX6 = 6
    SR_BEHAVIOR_DX4 = 7
    SR_BEHAVIOR_DT6 = 8
    SR_BEHAVIOR_DT4 = 9
    SR_BEHAVIOR_END_UN_PERF = 10
    SR_BEHAVIOR_END_UN = 11
    SR_BEHAVIOR_LAST = 12      # Must always be the last one


class SRv6PolicyType():
    # from src/vnet/srv6/sr.h
    SR_POLICY_TYPE_DEFAULT = 0
    SR_POLICY_TYPE_SPRAY = 1


class SRv6PolicySteeringTypes():
    # from src/vnet/srv6/sr.h
    SR_STEER_L2 = 2
    SR_STEER_IPV4 = 4
    SR_STEER_IPV6 = 6


class VppSRv6LocalSID(VppObject):
    """
    SRv6 LocalSID
    """

    def __init__(self, test, localsid, behavior, nh_addr,
                 end_psp, sw_if_index, vlan_index, fib_table):
        self._test = test
        self.localsid = localsid
        self.behavior = behavior
        self.nh_addr = nh_addr
        self.end_psp = end_psp
        self.sw_if_index = sw_if_index
        self.vlan_index = vlan_index
        self.fib_table = fib_table
        self._configured = False

    def add_vpp_config(self):
        self._test.vapi.sr_localsid_add_del(
            localsid=self.localsid,
            behavior=self.behavior,
            nh_addr=self.nh_addr,
            is_del=0,
            end_psp=self.end_psp,
            sw_if_index=self.sw_if_index,
            vlan_index=self.vlan_index,
            fib_table=self.fib_table)
        self._configured = True

    def remove_vpp_config(self):
        self._test.vapi.sr_localsid_add_del(
            localsid=self.localsid,
            behavior=self.behavior,
            nh_addr=self.nh_addr,
            is_del=1,
            end_psp=self.end_psp,
            sw_if_index=self.sw_if_index,
            vlan_index=self.vlan_index,
            fib_table=self.fib_table)
        self._configured = False

    def query_vpp_config(self):
        # sr_localsids_dump API is disabled
        # use _configured flag for now
        return self._configured

    def object_id(self):
        return ("%d;%s,%d"
                % (self.fib_table,
                   self.localsid,
                   self.behavior))


class VppSRv6Policy(VppObject):
    """
    SRv6 Policy
    """

    def __init__(self, test, bsid,
                 is_encap, sr_type, weight, fib_table,
                 segments, source):
        self._test = test
        self.bsid = bsid
        self.is_encap = is_encap
        self.sr_type = sr_type
        self.weight = weight
        self.fib_table = fib_table
        self.segments = segments
        self.n_segments = len(segments)
        # source not passed to API
        # self.source = inet_pton(AF_INET6, source)
        self.source = source
        self._configured = False

    def add_vpp_config(self):
        self._test.vapi.sr_policy_add(
                     bsid=self.bsid,
                     weight=self.weight,
                     is_encap=self.is_encap,
                     is_spray=self.sr_type,
                     fib_table=self.fib_table,
                     sids={'num_sids': self.n_segments, 'sids': self.segments})
        self._configured = True

    def remove_vpp_config(self):
        self._test.vapi.sr_policy_del(
                     self.bsid)
        self._configured = False

    def query_vpp_config(self):
        # no API to query SR Policies
        # use _configured flag for now
        return self._configured

    def object_id(self):
        return ("%d;%s-><%s>;%d"
                % (self.sr_type,
                   self.bsid,
                   ','.join(self.segments),
                   self.is_encap))


class VppSRv6Steering(VppObject):
    """
    SRv6 Steering
    """

    def __init__(self, test,
                 bsid,
                 prefix,
                 mask_width,
                 traffic_type,
                 sr_policy_index,
                 table_id,
                 sw_if_index):
        self._test = test
        self.bsid = bsid
        self.prefix = prefix
        self.mask_width = mask_width
        self.traffic_type = traffic_type
        self.sr_policy_index = sr_policy_index
        self.sw_if_index = sw_if_index
        self.table_id = table_id
        self._configured = False

    def add_vpp_config(self):
        self._test.vapi.sr_steering_add_del(
                     is_del=0,
                     bsid=self.bsid,
                     sr_policy_index=self.sr_policy_index,
                     table_id=self.table_id,
                     prefix={'address': self.prefix, 'len':  self.mask_width},
                     sw_if_index=self.sw_if_index,
                     traffic_type=self.traffic_type)
        self._configured = True

    def remove_vpp_config(self):
        self._test.vapi.sr_steering_add_del(
                     is_del=1,
                     bsid=self.bsid,
                     sr_policy_index=self.sr_policy_index,
                     table_id=self.table_id,
                     prefix={'address': self.prefix, 'len':  self.mask_width},
                     sw_if_index=self.sw_if_index,
                     traffic_type=self.traffic_type)
        self._configured = False

    def query_vpp_config(self):
        # no API to query steering entries
        # use _configured flag for now
        return self._configured

    def object_id(self):
        return ("%d;%d;%s/%d->%s"
                % (self.table_id,
                   self.traffic_type,
                   self.prefix,
                   self.mask_width,
                   self.bsid))
