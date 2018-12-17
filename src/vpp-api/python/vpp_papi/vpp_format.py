#
# Copyright (c) 2018 Cisco and/or its affiliates.
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
#

from socket import inet_pton, inet_ntop, AF_INET6, AF_INET
import socket
import ipaddress
from . import macaddress

# Copies from vl_api_address_t definition
ADDRESS_IP4 = 0
ADDRESS_IP6 = 1

#
# Type conversion for input arguments and return values
#


def format_vl_api_address_t(args):
    try:
        return {'un': {'ip6': inet_pton(AF_INET6, args)},
                'af': ADDRESS_IP6}
    except socket.error as e:
        return {'un': {'ip4': inet_pton(AF_INET, args)},
                'af': ADDRESS_IP4}


def format_vl_api_prefix_t(args):
    p, length = args.split('/')
    return {'address': format_vl_api_address_t(p),
            'address_length': int(length)}


def format_vl_api_ip6_prefix_t(args):
    p, length = args.split('/')
    return {'prefix': inet_pton(AF_INET6, p),
            'len': int(length)}


def format_vl_api_ip4_prefix_t(args):
    p, length = args.split('/')
    return {'prefix': inet_pton(AF_INET, p),
            'len': int(length)}


conversion_table = {
    'vl_api_ip6_address_t':
    {
        'IPv6Address': lambda o: o.packed,
        'str': lambda s: inet_pton(AF_INET6, s)
    },
    'vl_api_ip4_address_t':
    {
        'IPv4Address': lambda o: o.packed,
        'str': lambda s: inet_pton(AF_INET, s)
    },
    'vl_api_ip6_prefix_t':
    {
        'IPv6Network': lambda o: {'prefix': o.network_address.packed,
                                  'len': o.prefixlen},
        'str': lambda s: format_vl_api_ip6_prefix_t(s)
    },
    'vl_api_ip4_prefix_t':
    {
        'IPv4Network': lambda o: {'prefix': o.network_address.packed,
                                  'len': o.prefixlen},
        'str': lambda s: format_vl_api_ip4_prefix_t(s)
    },
    'vl_api_address_t':
    {
        'IPv4Address': lambda o: {'af': ADDRESS_IP4, 'un': {'ip4': o.packed}},
        'IPv6Address': lambda o: {'af': ADDRESS_IP6, 'un': {'ip6': o.packed}},
        'str': lambda s: format_vl_api_address_t(s)
    },
    'vl_api_prefix_t':
    {
        'IPv4Network': lambda o: {'prefix':
                                  {'af': ADDRESS_IP4, 'un':
                                   {'ip4': o.network_address.packed}},
                                  'len': o.prefixlen},
        'IPv6Network': lambda o: {'prefix':
                                  {'af': ADDRESS_IP6, 'un':
                                   {'ip6': o.network_address.packed}},
                                  'len': o.prefixlen},
        'str': lambda s: format_vl_api_prefix_t(s)
    },
    'vl_api_mac_address_t':
    {
        'MACAddress': lambda o: o.packed,
        'str': lambda s: macaddress.mac_pton(s)
    },
}


def unformat_api_address_t(o):
    if o.af == 1:
        return ipaddress.IPv6Address(o.un.ip6)
    if o.af == 0:
        return ipaddress.IPv4Address(o.un.ip4)


def unformat_api_prefix_t(o):
    if isinstance(o.address, ipaddress.IPv4Address):
        return ipaddress.IPv4Network((o.address, o.address_length), False)
    if isinstance(o.address, ipaddress.IPv6Address):
        return ipaddress.IPv6Network((o.address, o.address_length), False)


conversion_unpacker_table = {
    'vl_api_ip6_address_t': lambda o: ipaddress.IPv6Address(o),
    'vl_api_ip6_prefix_t': lambda o: ipaddress.IPv6Network((o.prefix, o.len)),
    'vl_api_ip4_address_t': lambda o: ipaddress.IPv4Address(o),
    'vl_api_ip4_prefix_t': lambda o: ipaddress.IPv4Network((o.prefix, o.len)),
    'vl_api_address_t': lambda o: unformat_api_address_t(o),
    'vl_api_prefix_t': lambda o: unformat_api_prefix_t(o),
    'vl_api_mac_address_t': lambda o: macaddress.MACAddress(o),
}
