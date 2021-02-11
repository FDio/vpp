# Copyright (c) 2021 Cisco and/or its affiliates.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This is a standalone library not depending on any GPL-licensed code.

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
