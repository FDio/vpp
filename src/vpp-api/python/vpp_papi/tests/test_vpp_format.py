#  Copyright (c) 2019. Vinci Consulting Corp. All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import ipaddress
import socket
import unittest

from parameterized import parameterized

from vpp_papi import vpp_format

try:
    text_type = unicode
except NameError:
    text_type = str



ip4_addr = '1.2.3.4'
ip4_addrn = b'\x01\x02\x03\x04'
ip4_prefix_len = 32
ip4_prefix = '%s/%s' % (ip4_addr, ip4_prefix_len)
ipv4_network = ipaddress.IPv4Network(text_type(ip4_prefix))
ip4_addr_format_vl_api_address_t = {'un': {'ip4': b'\x01\x02\x03\x04'},
                                    'af': 0}
ip4_addr_format_vl_api_prefix_t = {'address':                                # noqa: E127,E501
                                       {'un': {'ip4': b'\x01\x02\x03\x04'},
                                        'af': 0},
                                   'len': ip4_prefix_len}
ip4_addr_format_vl_api_prefix_packed_t = {'address': b'\x01\x02\x03\x04',
                                          'len': ip4_prefix_len}

ip6_addr = 'dead::'
ip6_addrn = b'\xde\xad\x00\x00\x00\x00\x00\x00' \
            b'\x00\x00\x00\x00\x00\x00\x00\x00'
ip6_prefix_len = 127
ip6_prefix = '%s/%s' % (ip6_addr, ip6_prefix_len)
ipv6_network = ipaddress.IPv6Network(text_type(ip6_prefix))
ip6_addr_format_vl_api_address_t = {'un': {'ip6': b'\xde\xad\x00\x00'
                                                  b'\x00\x00\x00\x00'
                                                  b'\x00\x00\x00\x00'
                                                  b'\x00\x00\x00\x00'},
                                    'af': 1}
ip6_addr_format_vl_api_prefix_t = {'address':       # noqa: E127
                                       {'af': 1,
                                        'un': {
                                            'ip6': b'\xde\xad\x00\x00'
                                                   b'\x00\x00\x00\x00'
                                                   b'\x00\x00\x00\x00'
                                                   b'\x00\x00\x00\x00'}},
                                   'len': ip6_prefix_len}
ip6_addr_format_vl_api_prefix_packed_t = {'address': b'\xde\xad\x00\x00'   # noqa: E127,E501
                                                     b'\x00\x00\x00\x00'
                                                     b'\x00\x00\x00\x00'
                                                     b'\x00\x00\x00\x00',
                                          'len': ip6_prefix_len}


class TestVppFormat(unittest.TestCase):

    def test_format_vl_api_address_t(self):
        res = vpp_format.format_vl_api_address_t(ip4_addr)
        self.assertEqual(res, ip4_addr_format_vl_api_address_t)

        # PY2: raises socket.error
        # PY3: raises OSError
        with self.assertRaises((TypeError,
                                socket.error,
                                OSError)):
            res = vpp_format.format_vl_api_address_t(ip4_addrn)

        res = vpp_format.format_vl_api_address_t(ip6_addr)
        self.assertEqual(res, ip6_addr_format_vl_api_address_t)

        with self.assertRaises(TypeError):
            es = vpp_format.format_vl_api_address_t(ip6_addrn)

    @parameterized.expand([('ip4 prefix',
                            ip4_prefix,
                            ip4_addr_format_vl_api_prefix_t),
                           ('ip6 prefix',
                            ip6_prefix,
                            ip6_addr_format_vl_api_prefix_t),
                           ('IPv4Network',
                            ipv4_network,
                            ip4_addr_format_vl_api_prefix_t),
                           ('IPv6Network',
                            ipv6_network,
                            ip6_addr_format_vl_api_prefix_t),
                           ])
    def test_format_vl_api_prefix_t(self, _, arg, expected):
        res = vpp_format.format_vl_api_prefix_t(arg)
        self.assertEqual(res, expected)

    def test_format_vl_api_ip6_prefix_t(self):
        res = vpp_format.format_vl_api_ip6_prefix_t(ip6_prefix)
        self.assertEqual(res, ip6_addr_format_vl_api_prefix_packed_t)

        res = vpp_format.format_vl_api_ip6_prefix_t(ipv6_network)
        self.assertEqual(res, ip6_addr_format_vl_api_prefix_packed_t)

    def test_format_vl_api_ip4_prefix_t(self):
        res = vpp_format.format_vl_api_ip4_prefix_t(ip4_prefix)
        self.assertEqual(res, ip4_addr_format_vl_api_prefix_packed_t)

        res = vpp_format.format_vl_api_ip4_prefix_t(ipv4_network)
        self.assertEqual(res, ip4_addr_format_vl_api_prefix_packed_t)

    def test_format_vl_api_ip6_prefix_t_raises(self):
        # PY2: raises socket.error
        # PY3: raises OSError
        with self.assertRaises((socket.error, OSError)):
            res = vpp_format.format_vl_api_ip6_prefix_t(ip4_prefix)

    def test_format_vl_api_ip4_prefix_t_raises(self):
        # PY2: raises socket.error
        # PY3: raises OSError
        with self.assertRaises((socket.error, OSError)):
            res = vpp_format.format_vl_api_ip4_prefix_t(ip6_prefix)
