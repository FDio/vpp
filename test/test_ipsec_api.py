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
import unittest

from framework import VppTestCase, VppTestRunner
from template_ipsec import TemplateIpsec, IPsecIPv4Params
from vpp_papi import VppEnum


class IpsecApiTestCase(VppTestCase):
    """ IPSec API tests """

    @classmethod
    def setUpClass(cls):
        super(IpsecApiTestCase, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(IpsecApiTestCase, cls).tearDownClass()

    def setUp(self):
        super(IpsecApiTestCase, self).setUp()
        self.create_pg_interfaces([0])
        self.pg0.config_ip4()
        self.pg0.admin_up()

        self.vpp_esp_protocol = (VppEnum.vl_api_ipsec_proto_t.
                                 IPSEC_API_PROTO_ESP)
        self.vpp_ah_protocol = (VppEnum.vl_api_ipsec_proto_t.
                                IPSEC_API_PROTO_AH)
        self.ipv4_params = IPsecIPv4Params()

    def tearDown(self):
        self.pg0.unconfig_ip4()
        self.pg0.admin_down()
        super(IpsecApiTestCase, self).tearDown()

    def test_backend_dump(self):
        """ backend dump """
        d = self.vapi.ipsec_backend_dump()
        self.assert_equal(len(d), 2, "number of ipsec backends in dump")
        self.assert_equal(d[0].protocol, self.vpp_ah_protocol,
                          "ipsec protocol in dump entry")
        self.assert_equal(d[0].index, 0, "index in dump entry")
        self.assert_equal(d[0].active, 1, "active flag in dump entry")
        self.assert_equal(d[1].protocol, self.vpp_esp_protocol,
                          "ipsec protocol in dump entry")
        self.assert_equal(d[1].index, 0, "index in dump entry")
        self.assert_equal(d[1].active, 1, "active flag in dump entry")

    def test_select_valid_backend(self):
        """ select valid backend """
        self.vapi.ipsec_select_backend(self.vpp_ah_protocol, 0)
        self.vapi.ipsec_select_backend(self.vpp_esp_protocol, 0)

    def test_select_invalid_backend(self):
        """ select invalid backend """
        with self.vapi.assert_negative_api_retval():
            self.vapi.ipsec_select_backend(self.vpp_ah_protocol, 200)
        with self.vapi.assert_negative_api_retval():
            self.vapi.ipsec_select_backend(self.vpp_esp_protocol, 200)

    def test_select_backend_in_use(self):
        """ attempt to change backend while sad configured """
        params = self.ipv4_params
        addr_type = params.addr_type
        is_ipv6 = params.is_ipv6
        scapy_tun_sa_id = params.scapy_tun_sa_id
        scapy_tun_spi = params.scapy_tun_spi
        auth_algo_vpp_id = params.auth_algo_vpp_id
        auth_key = params.auth_key
        crypt_algo_vpp_id = params.crypt_algo_vpp_id
        crypt_key = params.crypt_key

        self.vapi.ipsec_sad_entry_add_del(
            is_add=1,
            entry={
                'sad_id': scapy_tun_sa_id,
                'spi': scapy_tun_spi,
                'integrity_algorithm': auth_algo_vpp_id,
                'integrity_key': {
                    'data': auth_key,
                    'length': len(auth_key),
                },
                'crypto_algorithm': crypt_algo_vpp_id,
                'crypto_key': {
                    'data': crypt_key,
                    'length': len(crypt_key),
                },
                'protocol': self.vpp_ah_protocol,
                'tunnel_src': self.pg0.local_addr[addr_type],
                'tunnel_dst': self.pg0.remote_addr[addr_type]
            })
        with self.vapi.assert_negative_api_retval():
            self.vapi.ipsec_select_backend(
                protocol=self.vpp_ah_protocol, index=0)

        self.vapi.ipsec_sad_entry_add_del(
            is_add=0,
            entry={
                'sad_id': scapy_tun_sa_id,
                'spi': scapy_tun_spi,
                'integrity_algorithm': auth_algo_vpp_id,
                'integrity_key': {
                    'data': auth_key,
                    'length': len(auth_key),
                },
                'crypto_algorithm': crypt_algo_vpp_id,
                'crypto_key': {
                    'data': crypt_key,
                    'length': len(crypt_key),
                },
                'protocol': self.vpp_ah_protocol,
                'tunnel_src': self.pg0.local_addr[addr_type],
                'tunnel_dst': self.pg0.remote_addr[addr_type]
            })
        self.vapi.ipsec_select_backend(
            protocol=self.vpp_ah_protocol, index=0)


if __name__ == '__main__':
    unittest.main(testRunner=VppTestRunner)
