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
  QoS

  object abstractions for representing QoS config VPP
"""

from vpp_object import VppObject


class VppQosRecord(VppObject):
    """ QoS Record(ing) configuration """

    def __init__(self, test, intf, source):
        self._test = test
        self.intf = intf
        self.source = source

    def add_vpp_config(self):
        self._test.vapi.qos_record_enable_disable(
            enable=1,
            record={'sw_if_index': self.intf.sw_if_index,
                    'input_source': self.source})
        self._test.registry.register(self, self._test.logger)
        return self

    def remove_vpp_config(self):
        self._test.vapi.qos_record_enable_disable(
            enable=0,
            record={'sw_if_index': self.intf.sw_if_index,
                    'input_source': self.source})

    def query_vpp_config(self):
        rs = self._test.vapi.qos_record_dump()

        for r in rs:
            if self.intf.sw_if_index == r.record.sw_if_index and \
               self.source == r.record.input_source:
                return True
        return False

    def object_id(self):
        return ("qos-record-%s-%d" % (self.intf, self.source))


class VppQosStore(VppObject):
    """ QoS Store(ing) configuration """

    def __init__(self, test, intf, source, value):
        self._test = test
        self.intf = intf
        self.source = source
        self.value = value

    def add_vpp_config(self):
        self._test.vapi.qos_store_enable_disable(
            enable=1,
            store={'sw_if_index': self.intf.sw_if_index,
                   'input_source': self.source,
                   'value': self.value})
        self._test.registry.register(self, self._test.logger)
        return self

    def remove_vpp_config(self):
        self._test.vapi.qos_store_enable_disable(
            enable=0,
            store={'sw_if_index': self.intf.sw_if_index,
                   'input_source': self.source})

    def query_vpp_config(self):
        rs = self._test.vapi.qos_store_dump()

        for r in rs:
            if self.intf.sw_if_index == r.store.sw_if_index and \
               self.source == r.store.input_source and \
               self.value == r.store.value:
                return True
        return False

    def object_id(self):
        return ("qos-store-%s-%d" % (self.intf, self.source))


class VppQosEgressMap(VppObject):
    """ QoS Egress Map(ping) configuration """

    def __init__(self, test, id, rows):
        self._test = test
        self.id = id
        self.rows = rows

    def add_vpp_config(self):
        self._test.vapi.qos_egress_map_update(
            map={'id': self.id,
                 'rows': self.rows})
        self._test.registry.register(self, self._test.logger)
        return self

    def remove_vpp_config(self):
        self._test.vapi.qos_egress_map_delete(id=self.id)

    def query_vpp_config(self):
        rs = self._test.vapi.qos_egress_map_dump()

        for r in rs:
            if self.id == r.map.id:
                return True
        return False

    def object_id(self):
        return ("qos-map-%d" % (self.id))


class VppQosMark(VppObject):
    """ QoS Mark(ing) configuration """

    def __init__(self, test, intf, map, source):
        self._test = test
        self.intf = intf
        self.source = source
        self.map = map

    def add_vpp_config(self):
        self._test.vapi.qos_mark_enable_disable(
            enable=1,
            mark={'sw_if_index': self.intf.sw_if_index,
                  'map_id': self.map.id,
                  'output_source': self.source})
        self._test.registry.register(self, self._test.logger)
        return self

    def remove_vpp_config(self):
        self._test.vapi.qos_mark_enable_disable(
            enable=0,
            mark={'sw_if_index': self.intf.sw_if_index,
                  'output_source': self.source})

    def query_vpp_config(self):
        ms = self._test.vapi.qos_mark_dump()

        for m in ms:
            if self.intf.sw_if_index == m.mark.sw_if_index and \
               self.source == m.mark.output_source and \
               self.map.id == m.mark.map_id:
                return True
        return False

    def object_id(self):
        return ("qos-mark-%s-%d" % (self.intf, self.source))
