# Copyright (c) 2019. Vinci Consulting Corp. All Rights Reserved.
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

import vpp_object


class VppLbVip(vpp_object.VppObject):

    def __init__(self, test, pfx, sfx, port, protocol):
        self._test = test
        self.pfx = pfx
        self.sfx = sfx
        self.port = port
        self.protocol = protocol

    def add_vpp_config(self):
        self._test_vapi.lb_add_del_vip(pfx=self.pfx,
                                       sfx=self.pfx,
                                       port=self.port,
                                       protocol=self.protocol)

        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.lb_add_del_vip(pfx=self.pfx,
                                       sfx=self.pfx,
                                       port=self.port,
                                       protocol=self.protocol,
                                       is_del=1)

    def query_vpp_config(self):
        details = self._test.vapi.lb_add_del_vip(fx=self.pfx,
                                                 sfx=self.pfx,
                                                 port=self.port,
                                                 protocol=self.protocol)
        return True if self == details else False


class VppLbAs(vpp_object.VppObject):
    def __init__(self, test, pfx, port, protocol, app_srv, is_del, is_flush):
        self._test = test
        # this is the vip
        self.pfx = pfx
        self.port = port
        self.protocol = protocol

        self.app_srv = app_srv
        self.is_del = is_del
        self.is_flush = is_flush

    def add_vpp_config(self):
        self._test_vapi.lb_add_del_as(pfx=self.pfx,
                                      port=self.port,
                                      protocol=self.protocol,
                                      app_srv=self.app_srv,
                                      is_flush=self.is_flush,
                                      )

        self._test.registry.register(self, self._test.logger)

    def remove_vpp_config(self):
        self._test.vapi.lb_add_del_as(pfx=self.pfx,
                                      port=self.port,
                                      protocol=self.protocol,
                                      app_srv=self.app_srv,
                                      is_flush=self.is_flush,
                                      is_del=1)

    def query_vpp_config(self):
        details = self._test.vapi.lb_as_dump(pfx=self.pfx,
                                             port=self.port,
                                             protocol=self.protocol)
        return True if self == details else False
