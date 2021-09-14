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
from ipaddress import IPv4Address, AddressValueError
from vpp_object import VppObject
from vpp_papi import VppEnum


class AuthMethod:
    v = {'rsa-sig': 1,
         'shared-key': 2}

    @staticmethod
    def value(key): return AuthMethod.v[key]


class IDType:
    v = {'ip4-addr': 1,
         'fqdn': 2,
         'ip6-addr': 5}

    @staticmethod
    def value(key): return IDType.v[key]


class Profile(VppObject):
    """ IKEv2 profile """
    def __init__(self, test, profile_name):
        self.test = test
        self.vapi = test.vapi
        self.profile_name = profile_name
        self.udp_encap = False
        self.natt = True

    def disable_natt(self):
        self.natt = False

    def add_auth(self, method, data, is_hex=False):
        if isinstance(method, int):
            m = method
        elif isinstance(method, str):
            m = AuthMethod.value(method)
        else:
            raise Exception('unsupported type {}'.format(method))
        self.auth = {'auth_method': m,
                     'data': data,
                     'is_hex': is_hex}

    def add_local_id(self, id_type, data):
        if isinstance(id_type, str):
            t = IDType.value(id_type)
        self.local_id = {'id_type': t,
                         'data': data,
                         'is_local': True}

    def add_remote_id(self, id_type, data):
        if isinstance(id_type, str):
            t = IDType.value(id_type)
        self.remote_id = {'id_type': t,
                          'data': data,
                          'is_local': False}

    def add_local_ts(self, start_addr, end_addr, start_port=0, end_port=0xffff,
                     proto=0, is_ip4=True):
        self.ts_is_ip4 = is_ip4
        self.local_ts = {'is_local': True,
                         'protocol_id': proto,
                         'start_port': start_port,
                         'end_port': end_port,
                         'start_addr': start_addr,
                         'end_addr': end_addr}

    def add_remote_ts(self, start_addr, end_addr, start_port=0,
                      end_port=0xffff, proto=0):
        try:
            IPv4Address(start_addr)
            is_ip4 = True
        except AddressValueError:
            is_ip4 = False
        self.ts_is_ip4 = is_ip4
        self.remote_ts = {'is_local': False,
                          'protocol_id': proto,
                          'start_port': start_port,
                          'end_port': end_port,
                          'start_addr': start_addr,
                          'end_addr': end_addr}

    def add_responder_hostname(self, hn):
        self.responder_hostname = hn

    def add_responder(self, responder):
        self.responder = responder

    def add_ike_transforms(self, tr):
        self.ike_transforms = tr

    def add_esp_transforms(self, tr):
        self.esp_transforms = tr

    def set_udp_encap(self, udp_encap):
        self.udp_encap = udp_encap

    def set_lifetime_data(self, data):
        self.lifetime_data = data

    def set_ipsec_over_udp_port(self, port):
        self.ipsec_udp_port = {'is_set': 1,
                               'port': port}

    def set_tunnel_interface(self, sw_if_index):
        self.tun_itf = sw_if_index

    def object_id(self):
        return 'ikev2-profile-%s' % self.profile_name

    def remove_vpp_config(self):
        self.vapi.ikev2_profile_add_del(name=self.profile_name, is_add=False)

    def add_vpp_config(self):
        self.vapi.ikev2_profile_add_del(name=self.profile_name, is_add=True)
        if hasattr(self, 'auth'):
            self.vapi.ikev2_profile_set_auth(name=self.profile_name,
                                             data_len=len(self.auth['data']),
                                             **self.auth)
        if hasattr(self, 'local_id'):
            self.vapi.ikev2_profile_set_id(name=self.profile_name,
                                           data_len=len(self.local_id
                                                        ['data']),
                                           **self.local_id)
        if hasattr(self, 'remote_id'):
            self.vapi.ikev2_profile_set_id(name=self.profile_name,
                                           data_len=len(self.remote_id
                                                        ['data']),
                                           **self.remote_id)
        if hasattr(self, 'local_ts'):
            self.vapi.ikev2_profile_set_ts(name=self.profile_name,
                                           ts=self.local_ts)

        if hasattr(self, 'remote_ts'):
            self.vapi.ikev2_profile_set_ts(name=self.profile_name,
                                           ts=self.remote_ts)

        if hasattr(self, 'responder'):
            self.vapi.ikev2_set_responder(name=self.profile_name,
                                          responder=self.responder)

        if hasattr(self, 'responder_hostname'):
            print(self.responder_hostname)
            self.vapi.ikev2_set_responder_hostname(name=self.profile_name,
                                                   **self.responder_hostname)

        if hasattr(self, 'ike_transforms'):
            self.vapi.ikev2_set_ike_transforms(name=self.profile_name,
                                               tr=self.ike_transforms)

        if hasattr(self, 'esp_transforms'):
            self.vapi.ikev2_set_esp_transforms(name=self.profile_name,
                                               tr=self.esp_transforms)

        if self.udp_encap:
            self.vapi.ikev2_profile_set_udp_encap(name=self.profile_name)

        if hasattr(self, 'lifetime_data'):
            self.vapi.ikev2_set_sa_lifetime(name=self.profile_name,
                                            **self.lifetime_data)

        if hasattr(self, 'ipsec_udp_port'):
            self.vapi.ikev2_profile_set_ipsec_udp_port(name=self.profile_name,
                                                       **self.ipsec_udp_port)
        if hasattr(self, 'tun_itf'):
            self.vapi.ikev2_set_tunnel_interface(name=self.profile_name,
                                                 sw_if_index=self.tun_itf)

        if not self.natt:
            self.vapi.ikev2_profile_disable_natt(name=self.profile_name)

    def query_vpp_config(self):
        res = self.vapi.ikev2_profile_dump()
        for r in res:
            if r.profile.name == self.profile_name:
                return r.profile
        return None
